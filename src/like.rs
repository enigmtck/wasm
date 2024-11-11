use std::fmt::{self, Debug};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, get_state, log, send_post, ApContext,
    EnigmatickState, Profile, ApUndo,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
pub enum ApLikeType {
    #[default]
    Like,
}

impl fmt::Display for ApLikeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApLike {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApLikeType,
    pub actor: String,
    pub to: String,
    pub id: Option<String>,
    pub object: String,
}

impl ApLike {
    pub async fn new(to: String, object: String, id: Option<String>) -> Self {
        let state = get_state();
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            ApLike {
                context: None,
                kind: ApLikeType::default(),
                actor: format!("{server_url}/user/{}",
                               profile.username),
                id,
                object,
                to
            }
        } else {
            ApLike::default()
        }
    }
}

#[wasm_bindgen]
pub async fn send_like(to: String, object: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let like = ApLike::new(to, object, None).await;

        log(&format!("LIKE\n{like:#?}"));
        send_post(outbox,
                  serde_json::to_string(&like).unwrap(),
                  "application/activity+json".to_string()).await
    }).await
}

#[wasm_bindgen]
pub async fn send_unlike(to: String, object: String, id: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let like = ApLike::new(to, object, Some(id)).await;
        let undo: ApUndo = like.into();

        log(&format!("UNLIKE\n{undo:#?}"));
        send_post(outbox,
                  serde_json::to_string(&undo).unwrap(),
                  "application/activity+json".to_string()).await
    }).await
}
