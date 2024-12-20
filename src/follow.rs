use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, send_post, ApUndo, ApContext, ApObject, get_state};

#[derive(Serialize, Deserialize, Default, Debug, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum ApFollowType {
    #[default]
    Follow,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApFollow {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApFollowType,
    pub actor: String,
    pub id: Option<String>,
    pub object: ApObject,
}

impl ApFollow {
    fn new(object: String, id: Option<String>) -> Self {
        let state = get_state();

        if let (Some(server_url), Some(profile)) = (state.server_url, state.profile) {
            let actor = format!("{}/user/{}", server_url, profile.username);

            ApFollow {
                id,
                context: Some(ApContext::default()),
                kind: ApFollowType::Follow,
                actor,
                object: ApObject::Plain(object),
            }
        } else {
            ApFollow::default()
        }
    }
}

#[wasm_bindgen]
pub async fn send_follow(address: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let follow = ApFollow::new(address, None);

        send_post(outbox,
                  serde_json::to_string(&follow).unwrap(),
                  "application/activity+json".to_string()).await
    }).await
}

#[wasm_bindgen]
pub async fn send_unfollow(address: String, id: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let follow = ApFollow::new(address, Some(id));
        let undo: ApUndo = follow.into();

        send_post(outbox,
                  serde_json::to_string(&undo).unwrap(),
                  "application/activity+json".to_string()).await
    }).await
}
