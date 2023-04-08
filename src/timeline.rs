use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, SignParams, Method, ApObject, error, ENIGMATICK_STATE, send_get};

#[wasm_bindgen]
pub async fn get_timeline(offset: i32, limit: i32) -> Option<String> {
    let authentication: Option<String> = {
        if let Ok(state) = (*ENIGMATICK_STATE).try_lock() {
            if let Some(profile) = state.profile.clone() {
                if state.is_authenticated() {
                    Some(profile.username)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(username) = authentication {
        authenticated(move |_state: EnigmatickState, _profile: Profile| async move {
            let url = format!("/user/{username}/inbox?offset={offset}&limit={limit}");
            
            if let Some(text) = send_get(url, "application/activity+json".to_string()).await {
                if let Ok(ApObject::Collection(object)) = serde_json::from_str(&text) {
                    if let Some(items) = object.items {
                        Option::from(serde_json::to_string(&items).unwrap())
                    } else {
                        None
                    }
                } else {
                    error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                    None
                }
            } else {
                Option::None
            }
        }).await
    } else if let Ok(resp) = Request::get(&format!("/api/timeline?offset={offset}&limit={limit}"))
        .header("Content-Type", "application/activity+json")
        .send().await
    {
        if let Ok(text) = resp.text().await {
            if let Ok(ApObject::Collection(object)) = serde_json::from_str(&text) {
                if let Some(items) = object.items {
                    Option::from(serde_json::to_string(&items).unwrap())
                } else {
                    None
                }
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        } else {
            error("FAILED TO DECODE RESPONSE TO TEXT");
            None
        }
    } else {
        None
    }
}

#[wasm_bindgen]
pub async fn get_conversation(conversation: String, offset: i32, limit: i32) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let username = profile.username.clone();
        
        let inbox = format!("/api/user/{username}/conversation?conversation={conversation}&offset={offset}&limit={limit}");
        
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
            // log(&resp.text().await.unwrap());
            // Option::None
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
