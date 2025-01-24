use jdt_activity_pub::{ApFollow, ApUndo};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, send_post, EnigmatickState, Profile};

#[wasm_bindgen]
pub async fn send_follow(address: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let follow = ApFollow::new(address, state.profile?.id, None);

        send_post(
            outbox,
            serde_json::to_string(&follow).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_unfollow(address: String, id: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let follow = ApFollow::new(address, state.profile?.id, Some(id));
        let undo: ApUndo = follow.into();

        send_post(
            outbox,
            serde_json::to_string(&undo).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}
