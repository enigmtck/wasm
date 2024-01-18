use base64::encode;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, send_post, encrypt, resolve_processed_item, get_hash, log, send_get, ApCollection, error};


#[wasm_bindgen]
pub async fn store_to_vault(data: String, remote_actor: String, resolves: String, session_uuid: String, session: String, mutation_of: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        #[derive(Serialize, Debug, Clone)]
        pub struct SessionUpdate {
            pub session_uuid: String,
            pub encrypted_session: String,
            pub session_hash: String,
            pub mutation_of: String,
        }
        
        #[derive(Serialize, Debug, Clone)]
        pub struct VaultStorageRequest {
            pub data: String,
            pub remote_actor: String,
            pub session: SessionUpdate
        }

        if let (Ok(encrypted_session), Some(session_hash)) = (encrypt(None, session.clone()), get_hash(session.into_bytes())) {
            let session = SessionUpdate {
                session_uuid,
                encrypted_session,
                session_hash,
                mutation_of
            };
        
            let url = format!("/api/user/{}/vault",
                              profile.username.clone());

            if let Ok(data) = encrypt(None, data) {
                if send_post(url,
                             serde_json::to_string(&VaultStorageRequest {
                                 data,
                                 remote_actor,
                                 session
                             }).unwrap(),
                             "application/json".to_string()).await.is_some() {
                    resolve_processed_item(resolves).await
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }).await
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VaultRetrievalItem {
    pub created_at: String,
    pub updated_at: String,
    pub uuid: String,
    pub remote_actor: String,
    pub data: String,
}

#[wasm_bindgen]
pub async fn get_vault(offset: i32, limit: i32, actor: String) -> Option<String> {
    log("IN get vault");
    
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let username = profile.username.clone();

        let actor = encode(actor);
        let url = format!("/api/user/{username}/vault?offset={offset}&limit={limit}&actor={actor}");
        
        if let Some(data) = send_get(None, url, "application/json".to_string()).await {
            error(&format!("VAULT RESPONSE\n{:#?}", data));
            // if let Ok(items) = serde_json::from_str::<Vec<VaultRetrievalItem>>(&data) {
            //     Option::from(serde_json::to_string(&items).unwrap())
            // } else {
            //     Option::None
            // }

            if let Ok(object) = serde_json::from_str::<ApCollection>(&data) {
                Option::from(serde_json::to_string(&object).unwrap())
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    }).await
}

