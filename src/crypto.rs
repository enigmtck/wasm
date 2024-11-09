use base64::{engine::general_purpose, engine::Engine as _};
use orion::hash::digest;
use orion::kdf;
use orion::{aead, aead::SecretKey};
use rsa::pkcs1v15::Signature;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::error::Error;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, date_now, get_one_time_keys, get_state, send_get, ApCollection, EnigmatickState, Method, Profile
};

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
    digest(&data)
        .ok()
        .map(|x| general_purpose::STANDARD.encode(x))
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
    let hashed = general_purpose::STANDARD.encode(hasher.finalize());
    Some(format!("sha-256={hashed}"))
}

fn format_http_date_now() -> String {
    // This seems unnecessarily complex, but the complexity is necessary
    // because it is relying on a browser function (date_now) exported in lib.rs
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
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());
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

pub fn encode_derived_key(derived_key: &SecretKey) -> String {
    general_purpose::STANDARD.encode(derived_key.unprotected_as_bytes())
}

pub fn derive_key(password_str: String, encoded_salt: String) -> Result<SecretKey, Box<dyn Error>> {
    let salt = kdf::Salt::from_slice(&general_purpose::STANDARD.decode(encoded_salt)?)?;
    let password = kdf::Password::from_slice(password_str.as_bytes())?;

    Ok(kdf::derive_key(&password, &salt, 3, 1 << 4, 32)?)
}

pub fn decrypt(
    derived_key: Option<String>,
    encoded_data: String,
) -> Result<String, Box<dyn Error>> {
    let derived_key = derived_key.unwrap_or(
        get_state()
            .derived_key
            .clone()
            .ok_or("derived_key missing")?,
    );
    let decoded_key = general_purpose::STANDARD.decode(derived_key)?;
    let secret_key = SecretKey::from_slice(&decoded_key)?;
    let decrypted = aead::open(
        &secret_key,
        &general_purpose::STANDARD.decode(encoded_data).unwrap(),
    )?;
    let decrypted_str = String::from_utf8(decrypted)?;

    Ok(decrypted_str)
}

pub fn encrypt(derived_key: Option<String>, data: String) -> Result<String, Box<dyn Error>> {
    let derived_key = derived_key.unwrap_or(
        get_state()
            .derived_key
            .clone()
            .ok_or("derived_key missing")?,
    );
    let decoded_key = general_purpose::STANDARD.decode(derived_key)?;
    let secret_key = SecretKey::from_slice(&decoded_key)?;
    let encrypted = aead::seal(&secret_key, data.as_bytes())?;

    Ok(general_purpose::STANDARD.encode(encrypted))
}

