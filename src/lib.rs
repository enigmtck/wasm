#![allow(non_upper_case_globals)]

use anyhow::Result;
use base64::{engine::general_purpose, engine::Engine as _};
use futures::Future;
use gloo_net::http::Request;
use jdt_activity_pub::ApAttachment;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cmp::Ordering,
    fmt::{self, Debug},
};
use wasm_bindgen::prelude::*;

pub mod actor;
pub mod announce;
pub mod cache;
pub mod crypto;
pub mod delete;
pub mod follow;
pub mod inbox;
pub mod instance;
pub mod keystore;
pub mod like;
pub mod mls;
pub mod note;
pub mod olm;
pub mod outbox;
pub mod processing_queue;
pub mod session;
pub mod state;
pub mod stream;
pub mod timeline;
pub mod user;
pub mod vault;

pub use actor::*;
pub use announce::*;
pub use cache::*;
pub use crypto::*;
pub use delete::*;
pub use follow::*;
pub use inbox::*;
pub use instance::*;
pub use keystore::*;
pub use like::*;
pub use note::*;
pub use olm::*;
pub use outbox::*;
pub use processing_queue::*;
pub use session::*;
pub use state::*;
pub use stream::*;
pub use timeline::*;
pub use user::*;
pub use vault::*;

lazy_static! {
    pub static ref HANDLE_RE: Regex =
        Regex::new(r#"@[a-zA-Z0-9\-_]+@(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+"#)
            .expect("invalid handle regex");
    pub static ref URL_RE: Regex =
        Regex::new(r#"https://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+/[a-zA-Z0-9\-/]+"#)
            .expect("invalid url regex");
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct OrdValue(Value);

impl PartialOrd for OrdValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdValue {
    fn cmp(&self, other: &Self) -> Ordering {
        let a_str = serde_json::to_string(&self.0).unwrap();
        let b_str = serde_json::to_string(&other.0).unwrap();
        a_str.cmp(&b_str)
    }
}

pub async fn authenticated<F, Fut>(f: F) -> Option<String>
where
    F: FnOnce(EnigmatickState, Profile) -> Fut,
    Fut: Future<Output = Option<String>>,
{
    let state = get_state();
    let profile = state.profile.clone()?;

    if state.is_authenticated() {
        f(state, profile.clone()).await
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub enum Method {
    Get,
    Post,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

pub async fn send_post(url: String, body: String, content_type: String) -> Option<String> {
    let signature = {
        let state = get_state();

        let url = url.split('?').collect::<Vec<&str>>()[0];

        sign(SignParams {
            host: state.server_name.clone()?,
            request_target: url.to_string(),
            body: Some(body.clone()),
            data: None,
            method: Method::Post,
        })?
    };

    Some(
        Request::post(&url)
            .header("Enigmatick-Date", &signature.date)
            .header("Digest", &signature.digest.unwrap())
            .header("Signature", &signature.signature)
            .header("Content-Type", &content_type)
            .body(body)
            .send()
            .await
            .ok()?
            .text()
            .await
            .ok()?
            .to_string(),
    )
}

pub async fn send_get_promise(
    server_name: Option<String>,
    url: String,
    content_type: String,
) -> Result<JsValue, JsValue> {
    let signature = {
        let state = get_state();

        let url = url.split('?').collect::<Vec<&str>>()[0];

        sign(SignParams {
            host: server_name.unwrap_or(state.server_name.unwrap()),
            request_target: url.to_string(),
            body: None,
            data: None,
            method: Method::Get,
        })
    };

    let mut request = Request::get(&url);

    if let Some(signature) = signature {
        request = request
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature);
    }

    let response = request
        .header("Content-Type", &content_type)
        .send()
        .await
        .map_err(|x| JsValue::from(x.to_string()))?;

    // The ? above unwraps the Result. The ok() below checks that the Response
    // is 200ish
    if !response.ok() {
        return Err(JsValue::UNDEFINED);
    }

    let response_text = response
        .text()
        .await
        .map_err(|x| JsValue::from(x.to_string()))?;

    match response_text.as_str() {
        "" => Err(JsValue::UNDEFINED),
        _ => Ok(JsValue::from(response_text)),
    }
}

pub async fn send_get(
    server_name: Option<String>,
    url: String,
    content_type: String,
) -> Option<String> {
    let signature = {
        let state = get_state();

        let url = url.split('?').collect::<Vec<&str>>()[0];

        sign(SignParams {
            host: server_name.unwrap_or(state.server_name?),
            request_target: url.to_string(),
            body: None,
            data: None,
            method: Method::Get,
        })
    };

    let mut request = Request::get(&url);

    if let Some(signature) = signature {
        request = request
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature);
    }

    let response = request
        .header("Content-Type", &content_type)
        .send()
        .await
        .ok()?;

    // The ok()? above unwraps the Result. The ok() below checks that the Response
    // is 200ish
    if response.ok() {
        response.text().await.ok()
    } else {
        None
    }
}

pub async fn upload_file(
    server_name: String,
    upload: String,
    data: &[u8],
    length: u32,
) -> Option<String> {
    let j = js_sys::Uint8Array::new_with_length(length);
    j.copy_from(data);

    let signature = sign(SignParams {
        host: server_name,
        request_target: upload.clone(),
        body: None,
        data: Some(Vec::from(data)),
        method: Method::Post,
    })?;

    if let Ok(resp) = Request::post(&upload)
        .header("Enigmatick-Date", &signature.date)
        .header("Digest", &signature.digest.unwrap())
        .header("Signature", &signature.signature)
        .header("Content-Type", "application/octet-stream")
        .body(j)
        .send()
        .await
    {
        if let Ok(attachment) = resp.json::<ApAttachment>().await {
            log(&format!("upload completed\n{attachment:#?}"));
            Some(serde_json::to_string(&attachment).unwrap())
        } else {
            None
        }
    } else {
        None
    }
}

#[wasm_bindgen]
pub fn get_activity_ap_id_from_uuid(uuid: String) -> Option<String> {
    let state = get_state();
    let server_name = state.server_name.clone()?;

    Some(format!("https://{}/activities/{}", server_name, uuid))
}

#[wasm_bindgen]
pub fn get_url_safe_base64(text: String) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(text)
}
