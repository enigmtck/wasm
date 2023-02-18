use serde::Serialize;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, send_post, encrypt, resolve_processed_item, get_hash};


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

        if let (Some(encrypted_session), Some(session_hash)) = (encrypt(session.clone()), get_hash(session)) {
            let session = SessionUpdate {
                session_uuid,
                encrypted_session,
                session_hash,
                mutation_of
            };
        
            let url = format!("/api/user/{}/vault",
                              profile.username.clone());

            if let Some(data) = encrypt(data) {
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
