use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, log, send_post};

#[wasm_bindgen]
pub async fn store_to_vault(data: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        log("in authenticated");

        #[derive(Deserialize, Serialize, Debug, Clone)]
        pub struct VaultStorageRequest {
            pub data: String,
        }
        
        let url = format!("/api/user/{}/vault",
                          profile.username.clone());

        log(&format!("{url:#?}"));
        
        send_post(url,
                  serde_json::to_string(&VaultStorageRequest {
                      data
                  }).unwrap(),
                  "application/json".to_string()).await
    }).await
}
