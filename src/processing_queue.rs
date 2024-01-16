use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{log, authenticated, EnigmatickState, Profile, ApObject, send_post, send_get};

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub enum QueueTask {
    Resolve,
    #[default]
    Unknown,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct QueueAction {
    id: String,
    action: QueueTask,
}

#[wasm_bindgen]
pub async fn resolve_processed_item(id: String) -> Option<String> {
    log("IN resolve_processed_item");

    authenticated(move |_state: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/queue",
                          profile.username.clone());
        
        let data = QueueAction {
            id,
            action: QueueTask::Resolve
        };
        
        send_post(url,
                  serde_json::to_string(&data).unwrap(),
                  "application/json".to_string()).await
    }).await
}

#[wasm_bindgen]
pub async fn get_processing_queue() -> Option<String> {
    log("IN get processing_queue");
    
    authenticated(move |_state: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/queue",
                            profile.username.clone());

        let data = send_get(None, url, "application/activity+json".to_string()).await?;

        if let ApObject::Collection(object) = serde_json::from_str::<ApObject>(&data).ok()? {
            Some(serde_json::to_string(&object).ok()?)
        } else {
            None
        }
    }).await
}
