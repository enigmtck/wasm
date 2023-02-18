use orion::hash::digest;
use rsa::signature::{RandomizedSigner, Signature};
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{date_now, Method, ENIGMATICK_STATE};

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
pub fn get_hash(data: String) -> Option<String> {
    if let Ok(hash) = digest(data.as_bytes()) {
        base64::encode(hash).into()
    } else {
        Option::None
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

pub fn sign(params: SignParams) -> SignResponse {
    // (request-target): post /users/justin/inbox
    // host: ser.endipito.us
    // date: Tue, 20 Dec 2022 22:02:48 GMT
    // digest: sha-256=uus37v4gf3z6ze+jtuyk+8xsT01FhYOi/rOoDfFV1u4=

    let digest = {
        if let Some(body) = params.body {
            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            let hashed = base64::encode(hasher.finalize());
            Option::from(format!("sha-256={hashed}"))
        } else if let Some(data) = params.data {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let hashed = base64::encode(hasher.finalize());
            Option::from(format!("sha-256={hashed}"))
        } else {
            Option::None
        }
    };

    // let url = Url::parse(&params.url).unwrap();
    // let host = url.host().unwrap().to_string();
    let request_target = format!(
        "{} {}",
        params.method.to_string().to_lowercase(),
        params.request_target
    );

    let host = params.host;

    fn perf_to_system(amt: f64) -> std::time::SystemTime {
        let secs = (amt as u64) / 1_000;
        let nanos = ((amt as u32) % 1_000) * 1_000_000;
        std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos)
    }

    let date = httpdate::fmt_http_date(perf_to_system(date_now()));

    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.try_lock() {
        if let (Some(y), Some(profile)) = (&x.client_private_key_pem, &x.profile) {
            let private_key = RsaPrivateKey::from_pkcs8_pem(y).unwrap();
            let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);

            let structured_data = {
                if let Some(digest) = digest.clone() {
                    let signed_string = format!(
                        "(request-target): {request_target}\nhost: {host}\ndate: {date}\ndigest: {digest}"
                    );

                    Option::from(signed_string)
                } else {
                    let signed_string =
                        format!("(request-target): {request_target}\nhost: {host}\ndate: {date}");

                    Option::from(signed_string)
                }
            };

            if let Some(structured_data) = structured_data {
                let mut rng = rand::thread_rng();
                let signature = signing_key.sign_with_rng(&mut rng, structured_data.as_bytes());

                if let Some(digest) = digest {
                    SignResponse {
                        signature: format!(
                            "keyId=\"{}/user/{}#client-key\",headers=\"(request-target) host date digest\",signature=\"{}\"",
                            x.server_url.clone().unwrap(),
                            profile.username,
                            base64::encode(signature.as_bytes())),
                        date,
                        digest: Option::from(digest)
                    }
                } else {
                    SignResponse {
                        signature: format!(
                            "keyId=\"{}/user/{}#client-key\",headers=\"(request-target) host date\",signature=\"{}\"",
                            x.server_url.clone().unwrap(),
                            profile.username,
                            base64::encode(signature.as_bytes())),
                        date,
                        digest: Option::None
                    }
                }
            } else {
                SignResponse::default()
            }
        } else {
            SignResponse::default()
        }
    } else {
        SignResponse::default()
    }
}
