use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, SignParams, Method, ApObject};

#[wasm_bindgen]
pub async fn get_inbox(offset: i32, limit: i32) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let username = profile.username.clone();
        
        let inbox = format!("/user/{username}/inbox?offset={offset}&limit={limit}");
        
        let signature = crate::crypto::sign(SignParams {
            host: state.server_name.unwrap(),
            request_target: inbox.clone(),
            body: Option::None,
            data: Option::None,
            method: Method::Get
        });

        if let Ok(resp) = Request::get(&inbox)
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature)
            .header("Content-Type", "application/activity+json")
            .send().await
        {
            if let Ok(ApObject::Collection(object)) = resp.json().await {
                if let Some(items) = object.items {
                    Option::from(serde_json::to_string(&items).unwrap())
                } else {
                    Option::None
                }
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    }).await
}
