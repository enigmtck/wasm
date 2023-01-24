use std::collections::HashMap;

use base64::{decode, encode};
use gloo_net::http::Request;
use orion::{aead, kdf};
use rsa::pkcs8::{EncodePublicKey, LineEnding, EncodePrivateKey};
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, upload_file, KeyStore, log, ENIGMATICK_STATE, get_key_pair, send_post};

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
pub struct Profile {
    pub created_at: String,
    pub updated_at: String,
    pub uuid: String,
    pub username: String,
    pub display_name: String,
    #[wasm_bindgen(skip)]
    pub summary: Option<String>,
    pub public_key: String,
    #[wasm_bindgen(skip)]
    pub keystore: KeyStore,
    pub client_public_key: String,
}

#[wasm_bindgen]
pub async fn authenticate(username: String,
                          password: String,
                          passphrase: String) -> Option<Profile> {

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
        log("in passphrase");
        if let Ok(x) = Request::post("/api/user/authenticate").json(&req) {   
            if let Ok(y) = x.send().await {
                log("in request");
                let state = &*ENIGMATICK_STATE.clone();
                //log(&format!("y\n{:#?}", y.text().await));
                let user = y.json().await.ok();
                
                if let Ok(mut x) = state.try_lock() {
                    log("in lock");
                    x.authenticated = true;

                    log(&format!("user\n{user:#?}"));
                    let user: Profile = user.clone().unwrap();
                    x.set_profile(user.clone());
                    log("after profile");
                    x.keystore = Option::from(user.keystore.clone());
                    log("after keystore");
                    let salt = kdf::Salt::from_slice(&decode(user.keystore.salt).unwrap()).unwrap();

                    if let Ok(derived_key) = kdf::derive_key(&passphrase, &salt, 3, 1<<4, 32) {
                        log("in derive");
                        let encoded_derived_key = encode(derived_key.unprotected_as_bytes());
                        x.set_derived_key(encoded_derived_key);

                        if let Ok(decrypted_client_key_pem) =
                            aead::open(&derived_key,
                                       &decode(user.keystore.client_private_key)
                                       .unwrap())
                        {
                            log("in decrypted pem");
                            x.set_client_private_key_pem(
                                String::from_utf8(decrypted_client_key_pem).unwrap()
                            );
                        }

                        if let Ok(decrypted_olm_pickled_account) =
                            aead::open(&derived_key,
                                       &decode(user.keystore.olm_pickled_account)
                                       .unwrap())
                        {
                            log("in decrypted pickle");
                            x.set_olm_pickled_account(String::from_utf8(decrypted_olm_pickled_account)
                                                      .unwrap());
                        }

                        if let Ok(decrypted_olm_sessions) =
                            aead::open(&derived_key,
                                       &decode(user.keystore.olm_sessions)
                                       .unwrap())
                        {
                            log("in decrypted olm_sessions");
                            match String::from_utf8(decrypted_olm_sessions) {
                                Ok(y) => {
                                    log(&format!("olm_sessions: {y:#?}"));
                                    x.set_olm_sessions(y);
                                },
                                Err(e) => log(&format!("olm_sessions error: {e:#?}"))
                            }           
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
                         passphrase: String,
                         olm_identity_public_key: String,
                         olm_one_time_keys: String,
                         olm_pickled_account: String
) -> Option<Profile> {
    
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

            let olm_sessions = serde_json::to_string(&HashMap::<String, String>::new()).unwrap();
            
            if let (Ok(cpk_ciphertext), Ok(olm_ciphertext), Ok(sessions_ciphertext)) =
                (aead::seal(&derived_key, client_private_key.as_bytes()),
                 aead::seal(&derived_key, olm_pickled_account.as_bytes()),
                 aead::seal(&derived_key, olm_sessions.as_bytes())) {
                    
                    let client_private_key = encode(cpk_ciphertext);
                    let olm_pickled_account = encode(olm_ciphertext);
                    let olm_sessions = encode(sessions_ciphertext);
                    let olm_one_time_keys: HashMap<String, Vec<u8>> =
                        serde_json::from_str(&olm_one_time_keys).unwrap();
                    let olm_external_identity_keys: HashMap<String, String> = HashMap::new();
                    let olm_external_one_time_keys: HashMap<String, String> = HashMap::new();
                    
                    if let Ok(keystore) = serde_json::to_string(&KeyStore {
                        client_private_key,
                        salt,
                        olm_identity_public_key,
                        olm_one_time_keys,
                        olm_pickled_account,
                        olm_external_identity_keys,
                        olm_external_one_time_keys,
                        olm_sessions,
                    }) {

                        log(&format!("serialized keystore\n{keystore:#?}"));
                        let req = NewUser {
                            username,
                            password,
                            display_name,
                            client_public_key,
                            keystore
                        };
                        
                        if let Ok(x) =
                            Request::post("/api/user/create").json(&req) {   
                            if let Ok(y) = x.send().await {
                                let state = &*ENIGMATICK_STATE.clone();
                                let user = y.json().await.ok();
                                
                                if let Ok(mut x) = state.try_lock() {
                                    let user: Profile = user.clone().unwrap();
                                    x.set_profile(user.clone());
                                    x.set_derived_key(encoded_derived_key);
                                    x.keystore = Option::from(user.keystore);
                                    x.set_client_private_key_pem(encoded_client_private_key);
                                };
                                //let user = y.text().await.ok();

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

#[wasm_bindgen]
pub async fn upload_avatar(data: &[u8], length: u32, extension: String) {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!("/api/user/{}/avatar?extension={}",
                             profile.username.clone(),
                             extension);

        upload_file(state.server_name.unwrap(), upload, data, length).await;

        Option::None
    }).await;
}

#[wasm_bindgen]
pub async fn upload_banner(data: &[u8], length: u32, extension: String) {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!("/api/user/{}/banner?extension={}",
                             profile.username.clone(),
                             extension);

        upload_file(state.server_name.unwrap(), upload, data, length).await;

        Option::None
    }).await;
}

#[wasm_bindgen]
pub async fn update_password(current: String, updated: String) -> bool {
    authenticated(move |_state: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/password",
                          profile.username);

        #[derive(Serialize)]
        struct UpdatePassword {
            current: String,
            updated: String,
        }
        
        let data = serde_json::to_string(&UpdatePassword { current, updated }).unwrap();
        send_post(url, data, "application/json".to_string()).await
    }).await.is_some()
}


#[wasm_bindgen]
pub async fn update_summary(summary: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        #[derive(Serialize, Deserialize)]
        struct SummaryUpdate {
            content: String
        }

        let data = SummaryUpdate { content: summary };

        log("{data\ndata:#?}");
        
        let url = format!("/api/user/{}/update/summary",
                          profile.username);

        log("url\n{url:#?}");
        let data = serde_json::to_string(&data).unwrap();
        log("data\n{data:#?}");
        send_post(url, data, "application/json".to_string()).await
    }).await
}
