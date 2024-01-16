use orion::hash::digest;
use orion::{aead, aead::SecretKey};
use rsa::pkcs1v15::Signature;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{date_now, get_state, EnigmatickState, Method, Profile};

pub struct KeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

pub fn get_key_pair() -> KeyPair {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed");
    let public_key = RsaPublicKey::from(&private_key);

    KeyPair {
        private_key,
        public_key,
    }
}

#[wasm_bindgen]
pub fn get_hash(data: Vec<u8>) -> Option<String> {
    if let Ok(hash) = digest(&data) {
        base64::encode(hash).into()
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub struct SignParams {
    pub host: String,
    pub request_target: String,
    pub body: Option<String>,
    pub data: Option<Vec<u8>>,
    pub method: Method,
}

#[derive(Default, Debug)]
pub struct SignResponse {
    pub signature: String,
    pub date: String,
    pub digest: Option<String>,
}

fn compute_hash(params: &SignParams) -> Option<String> {
    let mut hasher = Sha256::new();

    match params {
        SignParams {
            body: Some(body), ..
        } => {
            hasher.update(body.as_bytes());
        }
        SignParams {
            data: Some(data), ..
        } => {
            hasher.update(data);
        }
        _ => return None,
    }
    let hashed = base64::encode(hasher.finalize());
    Some(format!("sha-256={hashed}"))
}

fn format_http_date_now() -> String {
    // This seems unnecessarily complex, but the complexity is necessary
    // because it is relying on a browser (date_now) exported in lib.rs
    fn perf_to_system(amt: f64) -> std::time::SystemTime {
        let secs = (amt as u64) / 1_000;
        let nanos = ((amt as u32) % 1_000) * 1_000_000;
        std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos)
    }

    httpdate::fmt_http_date(perf_to_system(date_now()))
}

fn create_signature(
    signing_key: &SigningKey<Sha256>,
    request_target: &str,
    host: &str,
    date: &str,
    hash: &Option<String>,
) -> Signature {
    let signed_string = if let Some(hash) = hash {
        format!("(request-target): {request_target}\nhost: {host}\ndate: {date}\ndigest: {hash}")
    } else {
        format!("(request-target): {request_target}\nhost: {host}\ndate: {date}")
    };

    let mut rng = rand::thread_rng();
    signing_key.sign_with_rng(&mut rng, signed_string.as_bytes())
}

fn build_sign_response(
    signature: Signature,
    state: &EnigmatickState,
    profile: &Profile,
    date: &str,
    hash: Option<String>,
) -> SignResponse {
    let signature_base64 = base64::encode(signature.to_bytes());
    let key_id = format!(
        "{}/user/{}#client-key",
        state.server_url.clone().unwrap(),
        profile.username
    );
    let headers = if hash.is_some() {
        "\"(request-target) host date digest\""
    } else {
        "\"(request-target) host date\""
    };

    SignResponse {
        signature: format!("keyId=\"{key_id}\",headers={headers},signature=\"{signature_base64}\""),
        date: date.to_string(),
        digest: hash,
    }
}

pub fn sign(params: SignParams) -> Option<SignResponse> {
    let hash = compute_hash(&params);
    let request_target = format!(
        "{} {}",
        params.method.to_string().to_lowercase(),
        params.request_target
    );
    let date = format_http_date_now();

    let state = get_state();
    if let (Some(private_key_pem), Some(profile)) = (&state.client_private_key_pem, &state.profile)
    {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).unwrap();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = create_signature(&signing_key, &request_target, &params.host, &date, &hash);

        return Some(build_sign_response(signature, &state, profile, &date, hash));
    }

    None
}

#[wasm_bindgen]
pub fn decrypt(encoded_data: String) -> Option<String> {
    let state = get_state();
    let derived_key = state.derived_key.clone()?;
    let decoded_key = base64::decode(derived_key).ok()?;
    let secret_key = SecretKey::from_slice(&decoded_key).ok()?;
    let decrypted = aead::open(&secret_key, &base64::decode(encoded_data).unwrap()).ok()?;
    let decrypted_str = String::from_utf8(decrypted).ok()?;

    Some(decrypted_str)
}

pub fn encrypt(data: String) -> Option<String> {
    let state = get_state();
    let derived_key = state.derived_key.clone()?;
    let decoded_key = base64::decode(derived_key).ok()?;
    let secret_key = SecretKey::from_slice(&decoded_key).ok()?;
    let encrypted = aead::seal(&secret_key, data.as_bytes()).ok()?;

    Some(base64::encode(encrypted))
}
