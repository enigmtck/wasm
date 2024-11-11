use gloo_net::http::Request;
use urlencoding::encode;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
use serde_wasm_bindgen;
use crate::{authenticated, EnigmatickState, Profile, ApObject, error, send_get, get_state, log};

pub fn convert_hashtags_to_query_string(hashtags: &[String]) -> String {
    hashtags
        .iter()
        .map(|tag| format!("&hashtags[]={}", encode(tag)))
        .collect::<Vec<String>>()
        .join("")
}

#[wasm_bindgen]
pub async fn get_timeline(max: Option<String>, min: Option<String>, limit: i32, view: String, hashtags: JsValue) -> Option<String> {
    let state = get_state();
    
    let hashtags: Vec<String> = serde_wasm_bindgen::from_value(hashtags).unwrap_or_default();
    let hashtags = convert_hashtags_to_query_string(&hashtags);
    log(&hashtags);

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
            let url = format!("/user/{username}/inbox?limit={limit}{position}&view={view}{hashtags}");
            
            let text = send_get(None, url, "application/activity+json".to_string()).await?;
            if let ApObject::CollectionPage(object) = serde_json::from_str(&text).ok()? {
                //object.ordered_items.map(|items| serde_json::to_string(&items).unwrap())
                serde_json::to_string(&object).ok()
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        }).await
    } else {
        let resp = Request::get(&format!("/inbox?limit={limit}{position}&view=global{hashtags}"))
            .header("Content-Type", "application/activity+json")
            .send().await.ok()?;

        let text = resp.text().await.ok()?;
        log(&text);
        if let ApObject::CollectionPage(object) = serde_json::from_str(&text).ok()? {
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
    authenticated(move |_state: EnigmatickState, _profile: Profile| async move {
        let conversation = urlencoding::encode(&conversation).to_string();
        let inbox = format!("/api/conversation?id={conversation}&limit={limit}");
        
        send_get(None, inbox, "application/activity+json".to_string()).await
    }).await
}
