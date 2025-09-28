use jdt_activity_pub::{ApAddress, ApLike, ApUndo};
use jdt_activity_pub::MaybeMultiple;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, log, send_post, EnigmatickState, Profile};

#[wasm_bindgen]
pub async fn send_like(to: String, object: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let like = ApLike::new(
            state.profile?.id,
            MaybeMultiple::Single(ApAddress::from(to)),
            object.into(),
            None,
        );

        //log(&format!("LIKE\n{like:#?}"));
        send_post(
            outbox,
            serde_json::to_string(&like).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_unlike(to: String, object: String, id: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let like = ApLike::new(
            state.profile?.id,
            MaybeMultiple::Single(ApAddress::from(to)),
            object.into(),
            Some(id),
        );
        let undo: ApUndo = like.into();

        //log(&format!("UNLIKE\n{undo:#?}"));
        send_post(
            outbox,
            serde_json::to_string(&undo).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}
