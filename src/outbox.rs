use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;

use crate:: ApObject;

#[wasm_bindgen]
pub async fn get_outbox(username: String, offset: i32, limit: i32) -> Option<String> {
    let outbox = format!("/user/{username}/outbox?offset={offset}&limit={limit}");

    if let Ok(resp) = Request::get(&outbox)
        .header("Content-Type", "application/activity+json")
        .send().await
    {
        if let Ok(ApObject::Collection(object)) = resp.json().await {
            object.items.map(|items| serde_json::to_string(&items).unwrap())
        } else {
            None
        }
    } else {
        None
    }
}
