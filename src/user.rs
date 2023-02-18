use std::collections::HashMap;

use base64::{decode, encode};
use gloo_net::http::Request;
use orion::{aead, kdf};
use rsa::pkcs8::{EncodePublicKey, LineEnding, EncodePrivateKey};
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, upload_file, log, ENIGMATICK_STATE, get_key_pair, send_post, encrypt, get_hash};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub display_name: String,
    pub client_public_key: Option<String>,
    pub client_private_key: Option<String>,
    pub olm_pickled_account: Option<String>,
    pub olm_pickled_account_hash: Option<String>,
    pub olm_identity_key: Option<String>,
    pub salt: Option<String>,
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
    pub client_public_key: Option<String>,
    pub avatar_filename: String,
    pub banner_filename: Option<String>,
    pub salt: Option<String>,
    pub client_private_key: Option<String>,
    pub olm_pickled_account: Option<String>,
    pub olm_identity_key: Option<String>,
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
                    //x.keystore = Option::from(user.keystore.clone());
                    log("after keystore");
                    if let (Some(salt), Some(client_private_key), Some(pickled_account)) = (user.salt, user.client_private_key, user.olm_pickled_account) {
                        let salt = kdf::Salt::from_slice(&decode(salt).unwrap()).unwrap();

                        if let Ok(derived_key) = kdf::derive_key(&passphrase, &salt, 3, 1<<4, 32) {
                            log("in derive");
                            let encoded_derived_key = encode(derived_key.unprotected_as_bytes());
                            x.set_derived_key(encoded_derived_key);

                            if let Ok(decrypted_client_key_pem) =
                                aead::open(&derived_key,
                                           &decode(client_private_key)
                                           .unwrap())
                            {
                                log("in decrypted pem");
                                x.set_client_private_key_pem(
                                    String::from_utf8(decrypted_client_key_pem).unwrap()
                                );
                            }

                            if let Ok(decrypted_olm_pickled_account) =
                                aead::open(&derived_key,
                                           &decode(pickled_account)
                                           .unwrap())
                            {
                                log("in decrypted pickle");
                                x.set_olm_pickled_account(String::from_utf8(decrypted_olm_pickled_account)
                                                          .unwrap());
                            }

                            // if let Ok(decrypted_olm_sessions) =
                            //     aead::open(&derived_key,
                            //                &decode(user.keystore.olm_sessions)
                            //                .unwrap())
                            // {
                            //     log("in decrypted olm_sessions");
                            //     match String::from_utf8(decrypted_olm_sessions) {
                            //         Ok(y) => {
                            //             log(&format!("olm_sessions: {y:#?}"));
                            //             x.set_olm_sessions(y);
                            //         },
                            //         Err(e) => log(&format!("olm_sessions error: {e:#?}"))
                            //     }           
                            // }
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
        let olm_identity_key = Some(olm_identity_public_key);
        let client_public_key = Some(client_public_key);
        let client_private_key = client_private_key.to_string();
        let encoded_client_private_key = client_private_key.clone();
        
        let salt = kdf::Salt::default();
        
        // the example uses 1<<16 (64MiB) for the memory; I'm using 1<<4 (16KiB) for my test machine
        // this should be increased to what is tolerable
        if let Ok(derived_key) = kdf::derive_key(&passphrase, &salt, 3, 1<<4, 32) {
            let salt = Some(encode(&salt));
            let encoded_derived_key = encode(derived_key.unprotected_as_bytes());

            let olm_pickled_account_hash = get_hash(olm_pickled_account.clone());
            
            if let (Ok(cpk_ciphertext), Ok(olm_ciphertext)) =
                (aead::seal(&derived_key, client_private_key.as_bytes()),
                 aead::seal(&derived_key, olm_pickled_account.as_bytes())) {
                    
                    let client_private_key = Some(encode(cpk_ciphertext));
                    let olm_pickled_account = Some(encode(olm_ciphertext));
                    
                    let req = NewUser {
                        username,
                        password,
                        display_name,
                        client_public_key,
                        client_private_key,
                        olm_pickled_account,
                        olm_pickled_account_hash,
                        olm_identity_key,
                        salt,
                    };
                    
                    if let Ok(x) =
                        Request::post("/api/user/create").json(&req) {   
                            if let Ok(y) = x.send().await {
                                let state = &*ENIGMATICK_STATE.clone();
                                let user = y.json().await.ok();
                                
                                if let Ok(mut x) = state.try_lock() {
                                    let user: Profile = user.clone().unwrap();
                                    x.set_profile(user);
                                    x.set_derived_key(encoded_derived_key);
                                    // x.keystore = Option::from(user.keystore);
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
        
        let url = format!("/api/user/{}/update/summary",
                          profile.username);

        let data = serde_json::to_string(&data).unwrap();
        send_post(url, data, "application/json".to_string()).await
    }).await
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct OtkUpdateParams {
    keys: HashMap<String, String>,
    account: String,
    mutation_of: String,
    account_hash: String,
}

#[wasm_bindgen]
impl OtkUpdateParams {
    pub fn new() -> Self {
        OtkUpdateParams::default()
    }

    pub fn set_account(&mut self, account: String) -> Self {
        self.account = encrypt(account).expect("ACCOUNT ENCRYPTION FAILED");
        
        self.clone()
    }

    pub fn set_mutation(&mut self, hash: String) -> Self {
        self.mutation_of = hash;
        
        self.clone()
    }

    pub fn set_account_hash(&mut self, hash: String) -> Self {
        self.account_hash = hash;
        
        self.clone()
    }
    
    pub fn set_keys(&mut self, key_map: String) -> Self {
        if let Ok(m) = serde_json::from_str::<HashMap<String, String>>(&key_map) {
            self.keys = m;
        }

        self.clone()
    }
}

#[wasm_bindgen]
pub async fn add_one_time_keys(params: OtkUpdateParams) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let username = profile.username;
        let url = format!("/api/user/{username}/otk");

        let data = serde_json::to_string(&params).unwrap();
        log(&format!("{data:#?}"));
        send_post(url, data, "application/json".to_string()).await
        //Option::None
    }).await
}
