use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ENIGMATICK_STATE, KeyStore, Profile, log};

#[wasm_bindgen(getter_with_clone)]
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
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
    olm_sessions: Option<HashMap<String, String>>
}

#[wasm_bindgen]
impl EnigmatickState {
    pub fn new() -> EnigmatickState {
        EnigmatickState::default()
    }

    pub fn set_server_name(&mut self, server_name: String) -> Self {
        self.server_name = Option::from(server_name);
        self.clone()
    }

    pub fn get_server_name(&self) -> Option<String> {
        self.server_name.clone()
    }

    pub fn set_server_url(&mut self, server_url: String) -> Self {
        self.server_url = Option::from(server_url);
        self.clone()
    }

    pub fn get_server_url(&self) -> Option<String> {
        self.server_url.clone()
    }
    
    pub fn cache_external_identity_key(&mut self, ap_id: String, identity_key: String) -> Self {
        // if let Some(keystore) = &self.keystore {
        //     let mut keystore = keystore.clone();
        //     keystore.olm_external_identity_keys.insert(ap_id, identity_key);
        //     self.keystore = Option::from(keystore);
        // }
        self.clone()
    }

    pub fn get_external_identity_key(&self, ap_id: String) -> Option<String> {
        // if let Some(keystore) = &self.keystore {
        //     keystore.olm_external_identity_keys.get(&ap_id).cloned()
        // } else {
            Option::None
        // }
    }

    pub fn get_external_one_time_key(&self, ap_id: String) -> Option<String> {
        // if let Some(keystore) = &self.keystore {
        //     keystore.olm_external_one_time_keys.get(&ap_id).cloned()
        // } else {
            Option::None
        // }
    }
    
    pub fn set_derived_key(&mut self, key: String) -> Self {
        self.derived_key = Option::from(key);
        self.clone()
    }

    pub fn get_derived_key(&self) -> Option<String> {
        self.derived_key.clone()
    }

    pub fn set_profile(&mut self, profile: Profile) -> Self {
        self.profile = Option::from(profile);
        self.clone()
    }

    pub fn get_profile(&self) -> Option<Profile> {
        self.profile.clone()
    }

    // fn set_keystore(&mut self, keystore: KeyStore) -> Self {
    //     self.keystore = Option::from(keystore);
    //     self.clone()
    // }

    // fn get_keystore(&self) -> Option<KeyStore> {
    //     self.keystore.clone()
    // }

    pub fn set_client_private_key_pem(&mut self, pem: String) -> Self {
        self.client_private_key_pem = Option::from(pem);
        self.clone()
    }

    pub fn get_client_private_key_pem(&self) -> Option<String> {
        self.client_private_key_pem.clone()
    }

    pub fn set_olm_pickled_account(&mut self, olm_pickled_account: String) -> Self {
        self.olm_pickled_account = Option::from(olm_pickled_account);
        self.clone()
    }

    pub fn get_olm_pickled_account(&self) -> Option<String> {
        self.olm_pickled_account.clone()
    }

    pub fn set_olm_sessions(&mut self, olm_sessions: String) -> Self {
        self.olm_sessions = Option::<HashMap<String, String>>::from(
            serde_json::from_str::<HashMap<String, String>>(&olm_sessions).unwrap());
        self.clone()
    }

    pub fn get_olm_sessions(&self) -> String {
        serde_json::to_string(&self.olm_sessions).unwrap()
    }

    pub fn set_olm_session(&mut self, ap_id: String, session: String) -> Self {
        if let Some(olm_sessions) = self.olm_sessions.clone() {
            let mut olm_sessions = olm_sessions;
            olm_sessions.insert(ap_id, session);
            self.olm_sessions = Option::from(olm_sessions);
        } 
        self.clone()
    }
    
    pub fn get_olm_session(&self, ap_id: String) -> Option<String> {
        if let Some(olm_sessions) = self.olm_sessions.clone() {
            olm_sessions.get(&ap_id).cloned()
        } else {
            Option::None
        }
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
    log("entering wasm import_state");
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

    log("exiting import_state");
}

#[wasm_bindgen]
pub async fn get_state() -> EnigmatickState {
    log("entering wasm get_state");
    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.lock() {
        log("exiting get_state lock");
        x.clone()
    } else {
        log("exiting get_state no lock");
        EnigmatickState::default()
    }
}
