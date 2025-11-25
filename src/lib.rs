#![allow(non_upper_case_globals)]

use anyhow::Result;
use base64::{engine::general_purpose, engine::Engine as _};
use futures::Future;
use jdt_activity_pub::ApAttachment;
use lazy_static::lazy_static;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cmp::Ordering,
    fmt::{self, Debug},
};
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use gloo_net::http::Request;

pub mod actor;
pub mod announce;
pub mod chess;
pub mod crypto;
pub mod delete;
pub mod follow;
pub mod inbox;
pub mod instance;
pub mod keystore;
pub mod like;
pub mod mls;
pub mod note;
pub mod outbox;
pub mod processing_queue;
pub mod session;
pub mod state;
pub mod stream;
pub mod timeline;
pub mod update;
pub mod user;
pub mod vault;

#[cfg(target_arch = "wasm32")]
pub mod cache;

pub use actor::*;
pub use announce::*;
pub use chess::*;
pub use crypto::*;
pub use delete::*;
pub use follow::*;
pub use inbox::*;
pub use instance::*;
pub use keystore::*;
pub use like::*;
pub use note::*;
pub use outbox::*;
pub use processing_queue::*;
pub use session::*;
pub use state::*;
pub use stream::*;
pub use timeline::*;
pub use update::*;
pub use user::*;
pub use vault::*;

#[cfg(target_arch = "wasm32")]
pub use cache::*;

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

#[cfg(target_arch = "wasm32")]
pub async fn get_object<T: DeserializeOwned>(
    url: String,
    signature: Option<SignResponse>,
    content_type: &str,
) -> Result<T> {
    let mut request = Request::get(&url);

    if let Some(signature) = signature {
        request = request
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature);
    }

    let resp = request.header("Content-Type", content_type).send().await?;
    resp.json::<T>().await.map_err(anyhow::Error::msg)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn get_object<T: DeserializeOwned>(
    url: String,
    signature: Option<SignResponse>,
    content_type: &str,
) -> Result<T> {
    let client = reqwest::Client::new();
    let mut client = client.get(&url);

    if let Some(signature) = signature {
        client = client.header("Enigmatick-Date", &signature.date);
        client = client.header("Signature", &signature.signature);
    }

    let resp = client.header("Content-Type", content_type).send().await?;
    resp.json::<T>().await.map_err(anyhow::Error::msg)
}

#[cfg(target_arch = "wasm32")]
pub async fn get_string(
    url: String,
    signature: Option<SignResponse>,
    content_type: &str,
) -> Result<Option<String>> {
    let mut request = Request::get(&url);

    if let Some(signature) = signature {
        request = request
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature);
    }

    let response = request.header("Content-Type", content_type).send().await?;

    if response.ok() {
        Ok(response.text().await.ok())
    } else {
        Ok(None)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn get_string(
    url: String,
    signature: Option<SignResponse>,
    content_type: &str,
) -> Result<Option<String>> {
    let client = reqwest::Client::new();
    let mut client = client.get(url);

    if let Some(signature) = signature {
        client = client
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature);
    }

    let response = client.header("Content-Type", content_type).send().await?;

    if response.status().is_success() {
        Ok(response.text().await.ok())
    } else {
        Ok(None)
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn post_string(
    url: String,
    body: String,
    content_type: &str,
    signature: Option<SignResponse>,
) -> Option<String> {
    let mut client = Request::post(&url);
    if let Some(signature) = signature {
        client = client
            .header("Enigmatick-Date", &signature.date)
            .header("Digest", &signature.digest.unwrap())
            .header("Signature", &signature.signature);
    }

    Some(
        client
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

#[cfg(not(target_arch = "wasm32"))]
pub async fn post_string(
    url: String,
    body: String,
    content_type: &str,
    signature: Option<SignResponse>,
) -> Option<String> {
    let client = reqwest::Client::new();
    let mut client = client.post(url);

    if let Some(signature) = signature {
        client = client
            .header("Enigmatick-Date", &signature.date)
            .header("Digest", &signature.digest.unwrap())
            .header("Signature", &signature.signature);
    }

    Some(
        client
            .header("Content-Type", content_type)
            .body(body.clone())
            .send()
            .await
            .ok()?
            .text()
            .await
            .ok()?
            .to_string(),
    )
}

pub async fn post_object<T: Serialize>(
    url: String,
    object: T,
    content_type: &str,
    signature: Option<SignResponse>,
) -> Option<String> {
    let body = serde_json::to_string(&object).ok()?;
    post_string(url, body, content_type, signature).await
}

#[cfg(target_arch = "wasm32")]
pub async fn post_bytes(
    url: &String,
    bytes: &[u8],
    length: u32,
    content_type: &String,
    signature: Option<SignResponse>,
) -> Option<String> {
    let j_bytes = js_sys::Uint8Array::new_with_length(length);
    j_bytes.copy_from(bytes);

    let mut client = Request::post(url);

    if let Some(signature) = signature {
        client = client
            .header("Enigmatick-Date", &signature.date)
            .header("Digest", &signature.digest.unwrap())
            .header("Signature", &signature.signature);
    }

    client
        .header("Content-Type", content_type)
        .body(j_bytes)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn post_bytes(
    url: &String,
    bytes: &[u8],
    _length: u32,
    content_type: &String,
    signature: Option<SignResponse>,
) -> Option<String> {
    let client = reqwest::Client::new();
    let mut client = client.post(url);

    if let Some(signature) = signature {
        client = client
            .header("Enigmatick-Date", &signature.date)
            .header("Digest", &signature.digest.unwrap())
            .header("Signature", &signature.signature);
    }

    client
        .header("Content-Type", content_type)
        .body(bytes.to_vec())
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()
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

    post_string(url, body, &content_type, Some(signature)).await
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

    let response = get_string(url, signature, &content_type)
        .await
        .map_err(|x| JsValue::from(x.to_string()))?
        .ok_or(JsValue::UNDEFINED)?;

    match response.as_str() {
        "" => Err(JsValue::UNDEFINED),
        _ => Ok(JsValue::from(response)),
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

    get_string(url, signature, &content_type).await.ok()?
}

pub async fn upload_file(
    server_name: Option<String>,
    url: String,
    data: &[u8],
    length: u32,
) -> Option<String> {
    let signature = {
        let state = get_state();

        let url = url.split('?').collect::<Vec<&str>>()[0];
        sign(SignParams {
            host: server_name.unwrap_or(state.server_name?),
            request_target: url.to_string(),
            body: None,
            data: Some(Vec::from(data)),
            method: Method::Post,
        })?
    };

    if let Some(resp) = post_bytes(
        &url,
        data,
        length,
        &"application/octet-stream".to_string(),
        Some(signature),
    )
    .await
    {
        if let Ok(attachment) = serde_json::from_str::<ApAttachment>(&resp) {
            //log(&format!("upload completed\n{attachment:#?}"));
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
