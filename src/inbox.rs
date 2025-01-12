use gloo_net::http::Request;
use jdt_activity_pub::{ApObject, Collectible};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, SignParams, Method};

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
            method: Method::Get
        })?;

        let resp = Request::get(&inbox)
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature)
            .header("Content-Type", "application/activity+json")
            .send().await.ok()?;

        if let ApObject::Collection(object) = resp.json().await.ok()? {
            Some(serde_json::to_string(&object.items()?).unwrap())
        } else {
            None
        }
    }).await
}
