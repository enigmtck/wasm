use jdt_activity_pub::ApDelete;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, log, send_post, EnigmatickState, Profile};

#[wasm_bindgen]
pub async fn send_delete(object: String) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let delete = ApDelete::new(object, state.profile?.id);

        log(&format!("DELETE\n{delete:#?}"));
        send_post(
            outbox,
            serde_json::to_string(&delete).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
        //Some("".to_string())
    })
    .await
    .is_some()
}
