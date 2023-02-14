use std::collections::HashMap;

use orion::aead::SecretKey;
use orion::aead;

use base64::{encode, decode};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, send_post, get_webfinger, ENIGMATICK_STATE, ApObject, ApBasicContent, ApBasicContentType};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApInstrument {
    Single(Box<ApObject>),
    Multiple(Vec<ApObject>),
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApSession {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    context: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
    to: String,
    pub attributed_to: String,
    pub instrument: ApInstrument,
    reference: Option<String>,
}

impl From<KexInitParams> for ApSession {
    fn from(params: KexInitParams) -> Self {
        ApSession {
            context: Option::from("https://www.w3.org/ns/activitystreams".to_string()),
            kind: "EncryptedSession".to_string(),
            to: params.recipient,
            instrument: ApInstrument::Single(Box::new(ApObject::Basic(ApBasicContent {
                kind: ApBasicContentType::IdentityKey,
                content: params.identity_key
            }))),
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct KeyStore {
    // salt is base64 encoded and is used for the KDF that generates the
    // key for the AEAD encryption used in this struct
    pub salt: String,

    // client_private_key is pem encoded, encrypted, and then base64 encoded
    pub client_private_key: String,

    // olm_identity_public_key is a Curve25519PublicKey that has been base64
    // encoded without padding by the vodozemac library (which will also import
    // it using native functions)
    pub olm_identity_public_key: String,

    // olm_one_time_keys is a JSON object in the form of {"u8": [u8,u8,u8..], "u8": [...]}
    // these are public keys to be distributed to parties who want to initiate Olm sessions
    pub olm_one_time_keys: HashMap<String, Vec<u8>>,

    // olm_pickled_account is converted from an Account to an AccountPickle and then serialized
    // via serde_json by the Olm component; it is then encrypted and base64 encoded here
    pub olm_pickled_account: String,

    // olm_external_identity_keys is a cache of keys to use for decrypting messages with
    // other parties; the format is https://server/user/username -> base64-encoded-identitykey
    pub olm_external_identity_keys: HashMap<String, String>,

    // olm_external_one_time_keys is a cache of keys to use for decrypting messages with
    // other parties; the format is https://server/user/username -> base64-encoded-onetimekey
    pub olm_external_one_time_keys: HashMap<String, String>,

    // olm_sessions is a HashMap<String, String> that maps user identities to pickled Olm
    // sessions; the HashMap is stored via serde_json::to_string -> AEAD encrypt -> base64
    pub olm_sessions: String,
}


pub async fn send_updated_identity_cache() -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        // if let Some(keystore) = state.keystore {
        //     let url = format!("/api/user/{}/update_identity_cache",
        //                       profile.username);

        //     let data = serde_json::to_string(&keystore).unwrap();
        //     send_post(url, data, "application/json".to_string()).await
        // } else {
            Option::None
        // }
    }).await.is_some()
}

pub async fn send_updated_olm_sessions() -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        // if let Some(keystore) = state.keystore {
        //     let url = format!("/api/user/{}/update_olm_sessions",
        //                       profile.username);

        //     let data = serde_json::to_string(&keystore).unwrap();
        //     send_post(url, data, "application/json".to_string()).await
        // } else {
            Option::None
        // }
    }).await.is_some()
}

#[wasm_bindgen]
pub fn update_keystore_olm_sessions(olm_sessions: String) -> bool {
    if let Ok(mut x) = (*ENIGMATICK_STATE).try_lock() {
        if let Some(derived_key) = &x.derived_key {
            let derived_key = SecretKey::from_slice(&decode(derived_key).unwrap()).unwrap();
            
            if let Ok(ciphertext) = aead::seal(&derived_key, olm_sessions.as_bytes()) {
                // let mut keystore = x.keystore.clone().unwrap();
                // keystore.olm_sessions = encode(ciphertext);
                // x.keystore = Option::from(keystore);
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

#[wasm_bindgen]
pub fn get_olm_session(ap_id: String) -> Option<String> {
    if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
        x.get_olm_session(ap_id)
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn get_external_identity_key(ap_id: String) -> Option<String> {
    if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
        x.get_external_identity_key(ap_id)
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn get_external_one_time_key(ap_id: String) -> Option<String> {
    if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
        x.get_external_one_time_key(ap_id)
    } else {
        Option::None
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Default)]
pub struct KexInitParams {
    pub recipient: String,
    pub identity_key: String
}

#[wasm_bindgen]
impl KexInitParams {
    pub fn new() -> KexInitParams {
        KexInitParams::default()
    }

    pub fn set_recipient_id(&mut self, id: String) -> Self {
        self.recipient = id;
        self.clone()
    }
    
    pub async fn set_recipient_webfinger(&mut self, address: String) -> Self {
        self.recipient = get_webfinger(address).await.unwrap_or_default();
        self.clone()
    }

    pub fn set_identity_key(&mut self, key: String) -> Self {
        self.identity_key = key;
        self.clone()
    }
}

#[wasm_bindgen]
pub async fn send_kex_init(params: KexInitParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let id = format!("{}/user/{}",
                         state.server_url.unwrap(),
                         profile.username.clone());
        let mut encrypted_session = ApSession::from(params);
        encrypted_session.attributed_to = id;

        send_post(outbox,
                  serde_json::to_string(&encrypted_session).unwrap(),
                  "application/activity+json".to_string()).await
    }).await.is_some()
}
