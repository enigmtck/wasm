use crate::{get_state, log, send_get};
use gloo_net::http::Request;
use jdt_activity_pub::ApObject;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub async fn get_outbox(
    username: String,
    kind: Option<String>,
    timestamp: Option<String>,
) -> Option<String> {
    //log(&format!("REQUEST {username}"));
    //let (username, limit, kind, timestamp) = extract_outbox_elements(url);

    log(&format!(
        "USERNAME {username:#?} KIND {kind:#?} TIMESTAMP {timestamp:#?}"
    ));

    let outbox = match (kind, timestamp) {
        (Some(kind), Some(timestamp)) => Some(format!(
            "/user/{username}/outbox?page=true&{kind}={timestamp}"
        )),
        (None, None) => Some(format!("/user/{username}/outbox?page=true")),
        _ => None,
    };

    log(&format!("OUTBOX {outbox:#?}"));

    if get_state().authenticated {
        send_get(None, outbox?, "application/activity+json".to_string()).await
    } else {
        let resp = Request::get(&outbox?)
            .header("Content-Type", "application/activity+json")
            .send()
            .await
            .ok()?;

        if let Ok(ApObject::Collection(object)) = resp.json().await {
            serde_json::to_string(&object).ok()
        } else {
            None
        }
    }
}
