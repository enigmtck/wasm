#![allow(non_upper_case_globals)]

use base64::{engine::general_purpose, engine::Engine as _};
use futures::Future;
use gloo_net::http::Request;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};
use wasm_bindgen::prelude::*;

pub mod accept;
pub mod activitypub;
pub mod actor;
pub mod add;
pub mod announce;
pub mod attachment;
pub mod block;
pub mod collection;
pub mod create;
pub mod crypto;
pub mod delete;
pub mod follow;
pub mod inbox;
pub mod instance;
pub mod invite;
pub mod join;
pub mod keystore;
pub mod like;
pub mod note;
pub mod olm;
pub mod outbox;
pub mod processing_queue;
pub mod question;
pub mod remove;
pub mod session;
pub mod signature;
pub mod state;
pub mod stream;
pub mod timeline;
pub mod undo;
pub mod update;
pub mod user;
pub mod vault;

pub use accept::*;
pub use activitypub::*;
pub use actor::*;
pub use add::*;
pub use announce::*;
pub use attachment::*;
pub use block::*;
pub use collection::*;
pub use create::*;
pub use crypto::*;
pub use delete::*;
pub use follow::*;
pub use inbox::*;
pub use instance::*;
pub use invite::*;
pub use join::*;
pub use keystore::*;
pub use like::*;
pub use note::*;
pub use olm::*;
pub use outbox::*;
pub use processing_queue::*;
pub use question::*;
pub use remove::*;
pub use session::*;
pub use signature::*;
pub use state::*;
pub use stream::*;
pub use timeline::*;
pub use undo::*;
pub use update::*;
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ActivityPub {
    Activity(ApActivity),
    Actor(ApActor),
    Object(ApObject),
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum MaybeMultiple<T> {
    Single(T),
    Multiple(Vec<T>),
    #[default]
    None,
}

impl From<String> for MaybeMultiple<String> {
    fn from(data: String) -> Self {
        MaybeMultiple::Single(data)
    }
}

impl<T> From<Vec<T>> for MaybeMultiple<T> {
    fn from(data: Vec<T>) -> Self {
        MaybeMultiple::Multiple(data)
    }
}

impl<T: Clone> MaybeMultiple<T> {
    pub fn single(&self) -> Option<T> {
        match self {
            MaybeMultiple::Multiple(s) => {
                if s.len() == 1 {
                    Some(s[0].clone())
                } else {
                    None
                }
            }
            MaybeMultiple::Single(s) => Some(s.clone()),
            MaybeMultiple::None => None,
        }
    }

    pub fn multiple(&self) -> Vec<T> {
        match self {
            MaybeMultiple::Multiple(data) => data.clone(),
            MaybeMultiple::Single(data) => {
                vec![data.clone()]
            }
            MaybeMultiple::None => vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Identifier {
    id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum MaybeReference<T> {
    Reference(String),
    Actual(T),
    Identifier(Identifier),
    #[default]
    None,
}

impl<T> fmt::Display for MaybeReference<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaybeReference::Reference(reference) => f.write_str(reference),
            MaybeReference::Identifier(identifier) => f.write_str(&identifier.id),
            _ => f.write_str("UNDEFINED"),
        }
    }
}

impl From<ApObject> for MaybeReference<ApObject> {
    fn from(object: ApObject) -> Self {
        MaybeReference::Actual(object)
    }
}

impl From<String> for MaybeReference<ApObject> {
    fn from(reference: String) -> Self {
        MaybeReference::Reference(reference)
    }
}

impl From<ApActivity> for MaybeReference<ApActivity> {
    fn from(activity: ApActivity) -> Self {
        MaybeReference::Actual(activity)
    }
}

impl From<String> for MaybeReference<String> {
    fn from(reference: String) -> Self {
        MaybeReference::Reference(reference)
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

        sign(SignParams {
            host: state.server_name.clone()?,
            request_target: url.clone(),
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
            .status()
            .to_string(),
    )
}

pub async fn send_get(
    server_name: Option<String>,
    url: String,
    content_type: String,
) -> Option<String> {
    let signature = {
        let state = get_state();

        sign(SignParams {
            host: server_name.unwrap_or(state.server_name?),
            request_target: url.clone(),
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

    request
        .header("Content-Type", &content_type)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()
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
