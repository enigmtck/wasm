use jdt_activity_pub::{ApObject, Collectible};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, get_string, EnigmatickState, Method, Profile, SignParams};

#[wasm_bindgen]
pub async fn get_inbox(offset: i32, limit: i32) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let username = profile.username.clone();

        let inbox = format!("/user/{username}/inbox?offset={offset}&limit={limit}");

        let signature = crate::crypto::sign(SignParams {
            host: state.server_name.unwrap(),
            request_target: inbox.clone(),
            body: None,
            data: None,
            method: Method::Get,
        })?;

        let response = get_string(inbox, Some(signature), "application/activity+json")
            .await
            .ok()??;

        if let ApObject::Collection(object) = serde_json::from_str(&response).ok()? {
            Some(serde_json::to_string(&object.items()?).unwrap())
        } else {
            None
        }
    })
    .await
}
