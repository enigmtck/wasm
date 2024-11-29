extern crate console_error_panic_hook;

use std::collections::HashMap;
use std::error::Error;

use base64::{engine::general_purpose, engine::Engine as _};
use lazy_static::lazy_static;
use orion::kdf;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::Profile;

lazy_static! {
    static ref ENIGMATICK_STATE: Arc<Mutex<EnigmatickState>> =
        Arc::new(Mutex::new(EnigmatickState::new()));
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EnigmatickState {
    // e.g., enigmatick.jdt.dev or 192.168.1.1:8080
    // pulled from /api/v2/instance
    pub server_name: Option<String>,

    // e.g., https://enigmatick.jdt.dev or http://192.168.1.1:8080
    // pulled from /api/v2/instance
    pub server_url: Option<String>,

    // self-explanatory
    pub authenticated: bool,

    // this is stored in state because derivation is expensive
    pub derived_key: Option<String>,

    // the keystore is in the profile, but it's stringified
    pub profile: Option<Profile>,

    // this is the un-stringified version of the keystore from the profile
    // it includes the encrypted data stored on the server accessible via
    // object getters
    // #[wasm_bindgen(skip)]
    // pub keystore: Option<KeyStore>,

    // this is the decrypted, PEM encoded client key from the keystore
    pub client_private_key_pem: Option<String>,

    // this is the decrypted, pickled olm account from the keystore
    olm_pickled_account: Option<String>,

    // this is the decrypted map of user identities to pickled sessions decrypted
    // and decoded from the keystore
    olm_sessions: Option<HashMap<String, String>>,
}

impl Default for EnigmatickState {
    fn default() -> Self {
        EnigmatickState {
            server_name: None,
            server_url: None,
            authenticated: false,
            derived_key: None,
            profile: None,
            client_private_key_pem: None,
            olm_pickled_account: None,
            olm_sessions: None,
        }
    }
}

#[wasm_bindgen]
impl EnigmatickState {
    pub fn new() -> EnigmatickState {
        console_error_panic_hook::set_once();
        
        EnigmatickState::default()
    }

    pub fn set_server_name(&mut self, server_name: String) -> Self {
        self.server_name = Some(server_name);
        self.clone()
    }

    pub fn get_server_name(&self) -> Option<String> {
        self.server_name.clone()
    }

    pub fn set_server_url(&mut self, server_url: String) -> Self {
        self.server_url = Some(server_url);
        self.clone()
    }

    pub fn get_server_url(&self) -> Option<String> {
        self.server_url.clone()
    }

    pub fn set_derived_key(&mut self, key: String) -> Self {
        self.derived_key = Some(key);
        self.clone()
    }

    pub fn get_derived_key(&self) -> Option<String> {
        self.derived_key.clone()
    }

    pub fn set_profile(&mut self, profile: Profile) -> Self {
        self.profile = Some(profile);
        self.clone()
    }

    pub fn get_profile(&self) -> Option<Profile> {
        self.profile.clone()
    }

    pub fn set_client_private_key_pem(&mut self, pem: String) -> Self {
        self.client_private_key_pem = Some(pem);
        self.clone()
    }

    pub fn get_client_private_key_pem(&self) -> Option<String> {
        self.client_private_key_pem.clone()
    }

    pub fn set_olm_pickled_account(&mut self, olm_pickled_account: String) -> Self {
        self.olm_pickled_account = Some(olm_pickled_account);
        self.clone()
    }

    pub fn get_olm_pickled_account(&self) -> Option<String> {
        self.olm_pickled_account.clone()
    }

    pub fn set_olm_sessions(&mut self, olm_sessions: String) -> Self {
        self.olm_sessions =
            Some(serde_json::from_str::<HashMap<String, String>>(&olm_sessions).unwrap());
        self.clone()
    }

    pub fn get_olm_sessions(&self) -> String {
        serde_json::to_string(&self.olm_sessions).unwrap()
    }

    pub fn set_olm_session(&mut self, ap_id: String, session: String) -> Self {
        if let Some(olm_sessions) = self.olm_sessions.clone() {
            let mut olm_sessions = olm_sessions;
            olm_sessions.insert(ap_id, session);
            self.olm_sessions = Some(olm_sessions);
        }
        self.clone()
    }

    pub fn get_olm_session(&self, ap_id: String) -> Option<String> {
        self.olm_sessions.clone()?.get(&ap_id).cloned()
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn export(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[wasm_bindgen]
pub fn import_state(data: String) {
    let imported_state: EnigmatickState = serde_json::from_str(&data).unwrap();

    let state = &*ENIGMATICK_STATE.clone();

    if let Ok(mut x) = state.try_lock() {
        x.set_derived_key(imported_state.derived_key.unwrap());
        x.authenticated = imported_state.authenticated;
        x.set_client_private_key_pem(imported_state.client_private_key_pem.unwrap());
        x.set_profile(imported_state.profile.unwrap());
        x.set_olm_pickled_account(imported_state.olm_pickled_account.unwrap());
        // x.set_keystore(imported_state.keystore.unwrap());
    };
}

#[wasm_bindgen]
pub fn get_state() -> EnigmatickState {
    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.lock() {
        x.clone()
    } else {
        EnigmatickState::default()
    }
}

pub fn update_state<F>(update_fn: F) -> Result<String, Box<dyn Error>>
where
    F: FnOnce(&mut EnigmatickState) -> Result<(), Box<dyn Error>>,
{
    let state = &*ENIGMATICK_STATE;

    let mut state = state.lock().map_err(|e| e.to_string())?;
    update_fn(&mut state)?;

    Ok(true.to_string())
}

pub fn update_state_password(password: String) -> Result<String, Box<dyn Error>> {
    update_state(|state| {
        let salt = kdf::Salt::from_slice(
            &general_purpose::STANDARD.decode(
                state
                    .profile
                    .as_ref()
                    .ok_or("Missing profile")?
                    .salt
                    .as_ref()
                    .ok_or("Missing salt")?,
            )?,
        )?;
        let password = kdf::Password::from_slice(password.as_bytes())?;

        if let Ok(derived_key) = kdf::derive_key(&password, &salt, 3, 1 << 4, 32) {
            let encoded_derived_key =
                general_purpose::STANDARD.encode(derived_key.unprotected_as_bytes());
            state.set_derived_key(encoded_derived_key);
        }

        Ok(())
    })
}
