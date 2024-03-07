use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, send_post, log};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StreamAuthorization {
    uuid: String,
}

#[wasm_bindgen]
pub async fn send_authorization(uuid: String) -> bool {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let endpoint = format!("/api/user/{}/events/authorize",
                               profile.username.clone());

        let authorization = StreamAuthorization { uuid: uuid.clone() };
        
        send_post(endpoint,
                  serde_json::to_string(&authorization).unwrap(),
                  "application/activity+json".to_string()).await
    }).await.is_some()
}
