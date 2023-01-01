#![allow(non_upper_case_globals)]

use gloo_net::http::Request;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use lazy_static::lazy_static;

use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, Signature, Verifier};
use rsa::{pkcs8::DecodePrivateKey, pkcs8::EncodePublicKey, pkcs8::EncodePrivateKey, pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use orion::{aead, kdf};
use base64::{encode, decode};
use std::sync::{Arc, Mutex};

#[wasm_bindgen(getter_with_clone)]
#[derive(Default, Clone)]
pub struct EnigmatickState {
    // this is stored in state because derivation is expensive
    derived_key: Option<String>,

    // the keystore is in the profile, but it's stringified
    profile: Option<UserResponse>,

    // this is the un-stringified version of the keystore from the profile
    // it includes the encrypted data stored on the server accessible via
    // object getters
    keystore: Option<KeyStore>,

    // this is the decrypted, PEM encoded client key from the keystore
    client_private_key_pem: Option<String>,
}

#[wasm_bindgen]
impl EnigmatickState {
    pub fn new() -> EnigmatickState {
        EnigmatickState::default()
    }

    pub fn set_derived_key(&mut self, key: String) -> Self {
        self.derived_key = Option::from(key);
        self.clone()
    }

    pub fn get_derived_key(&self) -> Option<String> {
        self.derived_key.clone()
    }

    pub fn set_profile(&mut self, profile: UserResponse) -> Self {
        self.profile = Option::from(profile);
        self.clone()
    }

    pub fn get_profile(&self) -> Option<UserResponse> {
        self.profile.clone()
    }

    pub fn set_keystore(&mut self, keystore: KeyStore) -> Self {
        self.keystore = Option::from(keystore);
        self.clone()
    }

    pub fn get_keystore(&self) -> Option<KeyStore> {
        self.keystore.clone()
    }

    pub fn set_client_private_key_pem(&mut self, pem: String) -> Self {
        self.client_private_key_pem = Option::from(pem);
        self.clone()
    }

    pub fn get_client_private_key_pem(&self) -> Option<String> {
        self.client_private_key_pem.clone()
    }
}

lazy_static! {
    pub static ref ENIGMATICK_STATE: Arc<Mutex<EnigmatickState>> = {
        Arc::new(Mutex::new(EnigmatickState::new()))
    };
}

struct KeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

fn get_key_pair() -> KeyPair {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed");
    let public_key = RsaPublicKey::from(&private_key);

    KeyPair {
        private_key,
        public_key,
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyStore {
    // salt is base64 encoded and is used for the KDF that generates the
    // key for the AEAD encryption used in this struct
    pub salt: String,
    // client_private_key is pem encoded, encrypted, and then base64 encoded
    pub client_private_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub display_name: String,
    pub client_public_key: String,
    pub keystore: String,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct UserResponse {
    pub client_public_key: String,
    pub created_at: String,
    pub display_name: String,
    pub keystore: String,
    pub public_key: String,
    #[wasm_bindgen(skip)]
    pub summary: Option<String>,
    pub updated_at: String,
    pub username: String,
    pub uuid: String
}

#[wasm_bindgen]
pub async fn get_state() -> EnigmatickState {
    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.lock() {
        x.clone()
    } else {
        EnigmatickState::default()
    }
}

#[wasm_bindgen]
pub async fn authenticate(username: String,
                          password: String,
                          passphrase: String) -> Option<UserResponse> {

    #[derive(Serialize, Debug, Clone)]
    struct AuthenticationData {
        username: String,
        password: String,
    }
    
    let req = AuthenticationData {
        username,
        password,
    };

    if let Ok(passphrase) = kdf::Password::from_slice(passphrase.as_bytes()) {
        if let Ok(x) = Request::post("http://localhost:8010/api/user/authenticate").json(&req) {   
            if let Ok(y) = x.send().await {
                let state = &*ENIGMATICK_STATE.clone();
                let user = y.json().await.ok();
                
                if let Ok(mut x) = state.try_lock() {
                    let user: UserResponse = user.clone().unwrap();
                    x.set_profile(user.clone());

                    let keystore: KeyStore = serde_json::from_str(&user.keystore).unwrap();
                    x.set_keystore(keystore.clone());

                    let salt = kdf::Salt::from_slice(&decode(keystore.salt).unwrap()).unwrap();

                    if let Ok(derived_key) = kdf::derive_key(&passphrase, &salt, 3, 1<<4, 32) {
                        let encoded_derived_key = encode(derived_key.unprotected_as_bytes());
                        x.set_derived_key(encoded_derived_key);

                        if let Ok(decrypted_client_key_pem) = aead::open(&derived_key, &decode(keystore.client_private_key).unwrap()) {
                            x.set_client_private_key_pem(String::from_utf8(decrypted_client_key_pem).unwrap());
                        }
                    }
                };

                user
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub async fn create_user(username: String,
                         display_name: String,
                         password: String,
                         passphrase: String) -> Option<UserResponse> {
    let key = get_key_pair();

    if let (Ok(client_public_key),
            Ok(client_private_key),
            Ok(passphrase)) =
        (key.public_key.to_public_key_pem(LineEnding::default()),
         key.private_key.to_pkcs8_pem(LineEnding::default()),
         kdf::Password::from_slice(passphrase.as_bytes()))
    {

        let client_private_key = client_private_key.to_string();
        let encoded_client_private_key = client_private_key.clone();
        
        let salt = kdf::Salt::default();
        
        // the example uses 1<<16 (64MiB) for the memory; I'm using 1<<4 (16KiB) for my test machine
        // this should be increased to what is tolerable
        if let Ok(derived_key) = kdf::derive_key(&passphrase, &salt, 3, 1<<4, 32) {
            let salt = encode(&salt);
            let encoded_derived_key = encode(derived_key.unprotected_as_bytes());

            if let Ok(ciphertext) = aead::seal(&derived_key, client_private_key.as_bytes()) {
                let client_private_key = encode(ciphertext);
                
                if let Ok(keystore) = serde_json::to_string(&KeyStore {
                    client_private_key,
                    salt
                }) {
                    
                    let req = NewUser {
                        username,
                        password,
                        display_name,
                        client_public_key,
                        keystore
                    };
                    
                    if let Ok(x) = Request::post("http://localhost:8010/api/user/create").json(&req) {   
                        if let Ok(y) = x.send().await {
                            let state = &*ENIGMATICK_STATE.clone();
                            let user = y.json().await.ok();
                            
                            if let Ok(mut x) = state.try_lock() {
                                let user: UserResponse = user.clone().unwrap();
                                x.set_profile(user.clone());
                                x.set_derived_key(encoded_derived_key);
                                x.set_keystore(serde_json::from_str(&user.keystore).unwrap());
                                x.set_client_private_key_pem(encoded_client_private_key);
                            };

                            user
                        } else {
                            Option::None
                        }
                    } else {
                        Option::None
                    }
                } else {
                    Option::None
                }
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}
