use std::collections::HashMap;

use base64::{decode, encode};
use gloo_net::http::Request;
use orion::{aead, kdf};
use rsa::pkcs8::{EncodePublicKey, LineEnding, EncodePrivateKey};
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, upload_file, log, ENIGMATICK_STATE, get_key_pair, send_post, encrypt, get_hash, send_get, ApObject, error, ApActor};

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
pub async fn authenticate(username: String, password_str: String) -> Option<Profile> {
    #[derive(Serialize, Debug, Clone)]
    struct AuthenticationData {
        username: String,
        password: String,
    }

    let password_hash = get_hash(password_str.clone().into_bytes())?;
    let req = AuthenticationData {
        username,
        password: encode(password_hash),
    };

    let password = kdf::Password::from_slice(password_str.as_bytes()).ok()?;
    
    let user = Request::post("/api/user/authenticate")
        .json(&req)
        .ok()?
        .send()
        .await
        .ok()?
        .json::<Profile>()
        .await
        .ok()?;

    let state = &*ENIGMATICK_STATE.clone();
    
    if let Ok(mut x) = state.try_lock() {
        x.authenticated = true;
        x.set_profile(user.clone());

        if let (Some(salt), Some(client_private_key), Some(pickled_account)) =
            (user.salt.clone(), user.client_private_key.clone(), user.olm_pickled_account.clone())
        {
            let salt = kdf::Salt::from_slice(&decode(salt).ok()?).ok()?;

            if let Ok(derived_key) = kdf::derive_key(&password, &salt, 3, 1 << 4, 32) {
                let encoded_derived_key = encode(derived_key.unprotected_as_bytes());
                x.set_derived_key(encoded_derived_key);

                if let Ok(decrypted_client_key_pem) =
                    aead::open(&derived_key, &decode(client_private_key).ok()?)
                {
                    x.set_client_private_key_pem(
                        String::from_utf8(decrypted_client_key_pem).ok()?,
                    );
                }

                if let Ok(decrypted_olm_pickled_account) =
                    aead::open(&derived_key, &decode(pickled_account).ok()?)
                {
                    x.set_olm_pickled_account(
                        String::from_utf8(decrypted_olm_pickled_account).ok()?,
                    );
                }
            }
        }
    }

    Some(user)
}

#[wasm_bindgen]
pub async fn create_user(
    username: String,
    display_name: String,
    password_str: String,
    olm_identity_public_key: String,
    olm_pickled_account: String,
) -> Option<Profile> {
    let key = get_key_pair();

    let client_public_key = key.public_key.to_public_key_pem(LineEnding::default()).ok()?;
    let client_private_key = key.private_key.to_pkcs8_pem(LineEnding::default()).ok()?;
    let password = kdf::Password::from_slice(password_str.as_bytes()).ok()?;
    let olm_identity_key = Some(olm_identity_public_key);

    let salt = kdf::Salt::default();

    let derived_key = kdf::derive_key(&password, &salt, 3, 1 << 4, 32).ok()?;
    let password_hash = get_hash(password_str.clone().into_bytes())?;
    let salt = Some(encode(&salt));
    let encoded_derived_key = encode(derived_key.unprotected_as_bytes());

    let cpk_ciphertext = aead::seal(&derived_key, client_private_key.as_bytes()).ok()?;
    let olm_ciphertext = aead::seal(&derived_key, olm_pickled_account.as_bytes()).ok()?;

    let client_private_key = encode(cpk_ciphertext);
    let olm_pickled_account = encode(olm_ciphertext);

    let olm_pickled_account_hash = get_hash(olm_pickled_account.clone().into_bytes());

    let req = NewUser {
        username,
        password: encode(password_hash),
        display_name,
        client_public_key: Some(client_public_key),
        client_private_key: Some(client_private_key.clone()),
        olm_pickled_account: Some(olm_pickled_account),
        olm_pickled_account_hash,
        olm_identity_key,
        salt,
    };

    async {
        let x = Request::post("/api/user/create").json(&req).ok()?;
        let y = x.send().await.ok()?;
        let state = &*ENIGMATICK_STATE.clone();
        let user: Option<Profile> = y.json().await.ok()?;

        if let Some(user) = user.clone() {
            if let Ok(mut x) = state.try_lock() {
                x.set_profile(user.clone());
                x.set_derived_key(encoded_derived_key);
                x.set_client_private_key_pem(client_private_key.clone());
            }
        }

        user
    }
    .await
}

#[wasm_bindgen]
pub async fn upload_image(data: &[u8], length: u32) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!("/api/user/{}/image",
                             profile.username.clone());

        upload_file(state.server_name.unwrap(), upload, data, length).await
    }).await
}

#[wasm_bindgen]
pub async fn upload_avatar(data: &[u8], length: u32, extension: String) {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!("/api/user/{}/avatar?extension={}",
                             profile.username.clone(),
                             extension);

        upload_file(state.server_name.unwrap(), upload, data, length).await;

        None
    }).await;
}

#[wasm_bindgen]
pub async fn upload_banner(data: &[u8], length: u32, extension: String) {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!("/api/user/{}/banner?extension={}",
                             profile.username.clone(),
                             extension);

        upload_file(state.server_name.unwrap(), upload, data, length).await;

        None
    }).await;
}

#[wasm_bindgen]
pub async fn update_password(current: String, updated: String) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/password",
                          profile.username);

        #[derive(Serialize)]
        struct UpdatePassword {
            current: String,
            updated: String,
            encrypted_client_private_key: String,
            encrypted_olm_pickled_account: String,
        }
        
        let encrypted_client_private_key = encrypt(state.client_private_key_pem.clone()?)?;
        let encrypted_olm_pickled_account = encrypt(state.get_olm_pickled_account()?)?;
        
        let data = serde_json::to_string(&UpdatePassword { current, updated, encrypted_client_private_key, encrypted_olm_pickled_account }).unwrap();
        send_post(url, data, "application/json".to_string()).await
    }).await.is_some()
}


#[wasm_bindgen]
pub async fn update_summary(summary: String, markdown: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        #[derive(Serialize, Deserialize)]
        struct SummaryUpdate {
            content: String,
            markdown: String,
        }

        let data = SummaryUpdate { content: summary, markdown };
        
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
    }).await
}

#[wasm_bindgen]
pub async fn get_ap_id() -> Option<String> {
   authenticated(move |state: EnigmatickState, profile: Profile| async move {
       let username = profile.username;
       let server = state.get_server_url();

       server.map(|server| format!("{server}/user/{username}"))
   }).await
}

#[wasm_bindgen]
pub async fn get_followers() -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let username = profile.username;
        let url = format!("/user/{username}/followers");
        
        if let Some(text) = send_get(None, url, "application/activity+json".to_string()).await {
            if let Ok(ApObject::Collection(object)) = serde_json::from_str(&text) {
                object.ordered_items.map(|items| serde_json::to_string(&items).unwrap())
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        } else {
            error("FAILED TO RETRIEVE FOLLOWERS");
            None
        }
    }).await 
}

#[wasm_bindgen]
pub async fn get_following() -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let username = profile.username;
        let url = format!("/user/{username}/following");
        
        if let Some(text) = send_get(None, url, "application/activity+json".to_string()).await {
            if let Ok(ApObject::Collection(object)) = serde_json::from_str(&text) {
                object.ordered_items.map(|items| serde_json::to_string(&items).unwrap())
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        } else {
            error("FAILED TO RETRIEVE FOLLOWING");
            None
        }
    }).await 
}

// because of CORS, this should only work for id values that correspond to local URLs
#[wasm_bindgen]
pub async fn get_profile(id: String) -> Option<String> {
    if let Ok(resp) = Request::get(&id.to_string())
        .header("Content-Type", "application/activity+json")
        .header("Accept", "application/activity+json")
        .send().await
    {
        if let Ok(text) = resp.text().await {
            if let Ok(actor) = serde_json::from_str::<ApActor>(&text) {
                Some(serde_json::to_string(&actor).unwrap())
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO ACTOR\n{text:#}"));
                None
            }
        } else {
            error("FAILED TO DECODE RESPONSE TO TEXT");
            None
        }
    } else {
        None
    }
}

#[wasm_bindgen]
pub async fn get_profile_by_username(username: String) -> Option<String> {
    let server_url = {
        if let Ok(state) = (*ENIGMATICK_STATE).try_lock() {
            state.server_url.clone()
        } else {
            None
        }
    };

    if let Some(server_url) = server_url {
        get_profile(format!("{server_url}/user/{username}")).await
    } else {
        None
    }
}
