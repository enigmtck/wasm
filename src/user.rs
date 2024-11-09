use std::collections::HashMap;

use base64::{engine::general_purpose, engine::Engine as _};
use gloo_net::http::Request;
use orion::{aead, kdf};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use vodozemac::olm::Account;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, decrypt, derive_key, encode_derived_key, encrypt, error, get_hash, get_key_pair,
    get_state, log, send_get, send_post, update_state, update_state_password, upload_file, ApActor,
    ApObject, EnigmatickState,
};

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
    pub avatar_filename: Option<String>,
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
        password: general_purpose::STANDARD.encode(password_hash),
    };

    let user = Request::post("/api/user/authenticate")
        .json(&req)
        .ok()?
        .send()
        .await
        .ok()?
        .json::<Profile>()
        .await
        .ok()?;

    log(&format!("PROFILE\n{user:#?}"));

    update_state(|state| {
        state.authenticated = true;
        state.set_profile(user.clone());
        Ok(())
    })
    .ok()?;

    if let (Some(salt), Some(client_private_key), Some(pickled_account)) = (
        user.salt.clone(),
        user.client_private_key.clone(),
        user.olm_pickled_account.clone(),
    ) {
        let derived_key = derive_key(password_str, salt).ok()?;
        let encoded_derived_key = encode_derived_key(&derived_key);

        update_state(|state| {
            state.set_derived_key(encoded_derived_key.clone());
            Ok(())
        })
        .ok()?;

        let client_private_key =
            decrypt(Some(encoded_derived_key.clone()), client_private_key).ok()?;
        update_state(|state| {
            state.set_client_private_key_pem(client_private_key);
            Ok(())
        })
        .ok()?;

        let pickled_account = decrypt(Some(encoded_derived_key), pickled_account).ok()?;
        update_state(|state| {
            state.set_olm_pickled_account(pickled_account);
            Ok(())
        })
        .ok()?;
    }

    Some(user)
}

#[wasm_bindgen]
pub async fn create_user(
    username: String,
    display_name: String,
    password_str: String,
) -> Option<Profile> {
    let key = get_key_pair();

    let client_public_key = key
        .public_key
        .to_public_key_pem(LineEnding::default())
        .ok()?;
    let client_private_key = key.private_key.to_pkcs8_pem(LineEnding::default()).ok()?;
    let password = kdf::Password::from_slice(password_str.as_bytes()).ok()?;

    let account = Account::new();
    let olm_identity_key = Some(account.curve25519_key().to_base64());
    let olm_pickled_account = serde_json::to_string(&account.pickle()).unwrap();

    let salt = kdf::Salt::default();

    let derived_key = kdf::derive_key(&password, &salt, 3, 1 << 4, 32).ok()?;
    let password_hash = get_hash(password_str.clone().into_bytes())?;
    let salt = Some(general_purpose::STANDARD.encode(&salt));
    let encoded_derived_key = general_purpose::STANDARD.encode(derived_key.unprotected_as_bytes());

    let cpk_ciphertext = aead::seal(&derived_key, client_private_key.as_bytes()).ok()?;
    let olm_ciphertext = aead::seal(&derived_key, olm_pickled_account.as_bytes()).ok()?;

    let encrypted_client_private_key = general_purpose::STANDARD.encode(cpk_ciphertext);
    let encrypted_olm_pickled_account = general_purpose::STANDARD.encode(olm_ciphertext);

    let olm_pickled_account_hash = get_hash(olm_pickled_account.clone().into_bytes());

    let req = NewUser {
        username,
        password: general_purpose::STANDARD.encode(password_hash),
        display_name,
        client_public_key: Some(client_public_key),
        client_private_key: Some(encrypted_client_private_key.clone()),
        olm_pickled_account: Some(encrypted_olm_pickled_account),
        olm_pickled_account_hash,
        olm_identity_key,
        salt,
    };

    async {
        let x = Request::post("/api/user/create").json(&req).ok()?;
        let y = x.send().await.ok()?;
        let user: Option<Profile> = y.json().await.ok()?;

        if let Some(user) = user.clone() {
            update_state(|state| {
                state.set_profile(user.clone());
                state.set_derived_key(encoded_derived_key);
                state.set_client_private_key_pem(client_private_key.clone().to_string());
                Ok(())
            })
            .ok();
        }

        user
    }
    .await
}

#[wasm_bindgen]
pub async fn upload_image(data: &[u8], length: u32) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!("/api/user/{}/image", profile.username.clone());

        upload_file(state.server_name.unwrap(), upload, data, length).await
    })
    .await
}

#[wasm_bindgen]
pub async fn upload_avatar(data: &[u8], length: u32, extension: String) {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!(
            "/api/user/{}/avatar?extension={}",
            profile.username.clone(),
            extension
        );

        upload_file(state.server_name.unwrap(), upload, data, length).await;

        None
    })
    .await;
}

#[wasm_bindgen]
pub async fn upload_banner(data: &[u8], length: u32, extension: String) {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let upload = format!(
            "/api/user/{}/banner?extension={}",
            profile.username.clone(),
            extension
        );

        upload_file(state.server_name.unwrap(), upload, data, length).await;

        None
    })
    .await;
}

#[wasm_bindgen]
pub async fn update_password(current_str: String, updated_str: String) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/password", profile.username);

        let current_hash = get_hash(current_str.clone().into_bytes())?;
        let updated_hash = get_hash(updated_str.clone().into_bytes())?;

        let current = general_purpose::STANDARD.encode(current_hash);
        let updated = general_purpose::STANDARD.encode(updated_hash);

        #[derive(Serialize)]
        struct UpdatePassword {
            current: String,
            updated: String,
            encrypted_client_private_key: String,
            encrypted_olm_pickled_account: String,
        }

        let encoded_derived_key = encode_derived_key(
            &derive_key(updated_str.clone(), state.profile.clone()?.salt?).ok()?,
        );
        let encrypted_client_private_key = encrypt(
            Some(encoded_derived_key.clone()),
            state.client_private_key_pem.clone()?,
        )
        .ok()?;
        let encrypted_olm_pickled_account = encrypt(
            Some(encoded_derived_key.clone()),
            state.get_olm_pickled_account()?,
        )
        .ok()?;

        let data = serde_json::to_string(&UpdatePassword {
            current,
            updated,
            encrypted_client_private_key,
            encrypted_olm_pickled_account,
        })
        .unwrap();

        send_post(url, data, "application/json".to_string())
            .await
            .and_then(|resp| {
                if resp == "200" {
                    update_state_password(updated_str.clone()).ok()
                } else {
                    None
                }
            })
    })
    .await
    .is_some()
}

#[wasm_bindgen]
pub async fn update_summary(summary: String, markdown: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        #[derive(Serialize, Deserialize)]
        struct SummaryUpdate {
            content: String,
            markdown: String,
        }

        let data = SummaryUpdate {
            content: summary,
            markdown,
        };

        let url = format!("/api/user/{}/update/summary", profile.username);

        let data = serde_json::to_string(&data).unwrap();
        send_post(url, data, "application/json".to_string()).await
    })
    .await
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
        self.account_hash = get_hash(account.clone().into_bytes()).expect("get_hash shouldn't fail");
        self.account = encrypt(None, account).expect("ACCOUNT ENCRYPTION FAILED");

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
    })
    .await
}

#[wasm_bindgen]
pub async fn get_ap_id() -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let username = profile.username;
        let server = state.get_server_url();

        server.map(|server| format!("{server}/user/{username}"))
    })
    .await
}

#[wasm_bindgen]
pub async fn get_webfinger() -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let username = profile.username;
        let server = state.get_server_name();

        server.map(|server| format!("@{username}@{server}"))
    })
    .await
}

#[wasm_bindgen]
pub async fn get_followers(username: String, page: Option<u32>) -> Option<String> {
    authenticated(move |_: EnigmatickState, _: Profile| async move {
        let url = {
            if let Some(page) = page {
                format!("/user/{username}/followers?page={page}")
            } else {
                format!("/user/{username}/followers")
            }
        };

        send_get(None, url, "application/activity+json".to_string()).await
    })
    .await
}

#[wasm_bindgen]
pub async fn get_following(username: String, page: Option<u32>) -> Option<String> {
    authenticated(move |_: EnigmatickState, _: Profile| async move {
        let url = {
            if let Some(page) = page {
                format!("/user/{username}/following?page={page}")
            } else {
                format!("/user/{username}/following")
            }
        };

        send_get(None, url, "application/activity+json".to_string()).await
    })
    .await
}

#[wasm_bindgen]
pub async fn get_profile_by_username(username: String) -> Option<String> {
    let server_url = get_state().server_url.clone()?;

    let resp = Request::get(&format!("{server_url}/api/user/{username}"))
        .header("Content-Type", "application/activity+json")
        .header("Accept", "application/activity+json")
        .send()
        .await
        .ok()?;

    let text = resp.text().await.ok()?;

    let actor = serde_json::from_str::<ApActor>(&text).ok()?;

    Some(serde_json::to_string(&actor).unwrap())
}
