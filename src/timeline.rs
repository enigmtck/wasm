use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;
use crate::{authenticated, EnigmatickState, Profile, SignParams, Method, ApObject, error, send_get, get_state, log};

#[wasm_bindgen]
pub async fn get_timeline(max: Option<String>, min: Option<String>, limit: i32, view: String) -> Option<String> {
    let state = get_state();
    
    let position = {
        if let Some(max) = max {
            format!("&max={max}")
        } else if let Some(min) = min {
            format!("&min={min}")
        } else { String::new() }
    };

    if state.authenticated {
        authenticated(move |_: EnigmatickState, profile: Profile| async move {
            let username = profile.username;
            let url = format!("/user/{username}/inbox?limit={limit}{position}&view={view}");
            
            let text = send_get(None, url, "application/activity+json".to_string()).await?;
            if let ApObject::Collection(object) = serde_json::from_str(&text).ok()? {
                //object.ordered_items.map(|items| serde_json::to_string(&items).unwrap())
                serde_json::to_string(&object).ok()
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        }).await
    } else {
        let resp = Request::get(&format!("/inbox?limit={limit}{position}&view=global"))
            .header("Content-Type", "application/activity+json")
            .send().await.ok()?;

        let text = resp.text().await.ok()?;
        log(&text);
        if let ApObject::Collection(object) = serde_json::from_str(&text).ok()? {
            //object.ordered_items.map(|items| serde_json::to_string(&items).unwrap())
            serde_json::to_string(&object).ok()
        } else {
            error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
            None
        }
    }
}

#[wasm_bindgen]
pub async fn get_conversation(conversation: String, limit: i32) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let username = profile.username.clone();
        
        let conversation = urlencoding::encode(&conversation).to_string();
        let inbox = format!("/api/conversation?id={conversation}&limit={limit}");
        
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
            serde_json::to_string(&object).ok()
            //object.items.map(|items| {
            //    serde_json::to_string(&items).unwrap()    
            //})
        } else {
            None
        }
    }).await
}
