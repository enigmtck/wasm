use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{log, authenticated, EnigmatickState, Profile, SignParams, sign, Method, ApObject};

#[wasm_bindgen]
pub async fn get_inbox() -> Option<String> {
    log("in get inbox");

    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let inbox = format!("/user/{}/inbox",
                            profile.username.clone());
        
        let signature = sign(SignParams {
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
                Option::from(serde_json::to_string(&object).unwrap())
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    }).await
}
