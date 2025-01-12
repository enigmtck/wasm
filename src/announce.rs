use jdt_activity_pub::{ApAnnounce, ApUndo};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, log, send_post, EnigmatickState,
    Profile,
};

#[wasm_bindgen]
pub async fn send_announce(object: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let announce = ApAnnounce::new(object, state.profile?.id, None);

        log(&format!("ANNOUNCE\n{announce:#?}"));
        send_post(
            outbox,
            serde_json::to_string(&announce).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_unannounce(object: String, id: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let undo: ApUndo = ApAnnounce::new(object, state.profile?.id, Some(id)).into();

        log(&format!("UNANNOUNCE\n{undo:#?}"));
        send_post(
            outbox,
            serde_json::to_string(&undo).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}
