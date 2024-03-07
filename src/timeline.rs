use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;
use crate::{authenticated, EnigmatickState, Profile, SignParams, Method, ApObject, error, send_get, get_state};

#[wasm_bindgen]
pub async fn get_timeline(offset: i32, limit: i32, view: String) -> Option<String> {
    let state = get_state();
    
    if state.authenticated {
        authenticated(move |_: EnigmatickState, profile: Profile| async move {
            let username = profile.username;
            let url = format!("/user/{username}/inbox?offset={offset}&limit={limit}&view={view}");
            
            let text = send_get(None, url, "application/activity+json".to_string()).await?;
            if let ApObject::Collection(object) = serde_json::from_str(&text).ok()? {
                object.items.map(|items| serde_json::to_string(&items).unwrap())
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        }).await
    } else {
        let resp = Request::get(&format!("/api/timeline?offset={offset}&limit={limit}&view=global"))
            .header("Content-Type", "application/activity+json")
            .send().await.ok()?;

        let text = resp.text().await.ok()?;
        if let ApObject::Collection(object) = serde_json::from_str(&text).ok()? {
            object.items.map(|items| serde_json::to_string(&items).unwrap())
        } else {
            error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
            None
        }
    }
}

#[wasm_bindgen]
pub async fn get_conversation(conversation: String, offset: i32, limit: i32) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let username = profile.username.clone();
        
        let conversation = urlencoding::encode(&conversation).to_string();
        let inbox = format!("/api/user/{username}/conversation?conversation={conversation}&offset={offset}&limit={limit}");
        
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
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        
        if let ApObject::Collection(object) = resp {
            object.items.map(|items| {
                serde_json::to_string(&items).unwrap()
            })
        } else {
            None
        }
    }).await
}
