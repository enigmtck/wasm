#![allow(non_upper_case_globals)]

use base64::{engine::general_purpose, engine::Engine as _};
use chrono::{DateTime, Utc};
use futures::Future;
use gloo_net::http::Request;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    fmt::{self, Debug},
};
use wasm_bindgen::prelude::*;
use anyhow::{anyhow, Result};

pub mod accept;
pub mod activitypub;
pub mod actor;
pub mod add;
pub mod announce;
pub mod attachment;
pub mod block;
pub mod cache;
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
pub use cache::*;
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

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct Ephemeral {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followers: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaders: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub following: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader_as_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_activity_as_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_markdown: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<ApActorTerse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announces: Option<Vec<ApActorTerse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announced: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targeted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<Metadata>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub likes: Option<Vec<ApActorTerse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributed_to: Option<Vec<ApActorTerse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruments_to_update: Option<Vec<ApInstrument>>,
}

impl From<Option<Vec<ApActorTerse>>> for Ephemeral {
    fn from(actors: Option<Vec<ApActorTerse>>) -> Self {
        Self {
            actors,
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(untagged)]
pub enum ActivityPub {
    Activity(ApActivity),
    Actor(ApActor),
    Object(ApObject),
}

impl From<ApObject> for ActivityPub {
    fn from(object: ApObject) -> Self {
        ActivityPub::Object(object)
    }
}

impl FromIterator<ApObject> for Vec<ActivityPub> {
    fn from_iter<I: IntoIterator<Item = ApObject>>(iter: I) -> Self {
        iter.into_iter().map(ActivityPub::from).collect()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(untagged)]
pub enum MaybeMultiple<T> {
    Single(T),
    Multiple(Vec<T>),
    #[default]
    None,
}

impl<T: PartialEq> MaybeMultiple<T> {
    fn is_none(&self) -> bool {
        *self == MaybeMultiple::None
    }
}

impl<T> From<Option<Vec<T>>> for MaybeMultiple<T> {
    fn from(data: Option<Vec<T>>) -> Self {
        match data {
            Some(x) => MaybeMultiple::Multiple(x),
            None => MaybeMultiple::None,
        }
    }
}

impl<T: DeserializeOwned> From<Option<Value>> for MaybeMultiple<T> {
    fn from(data: Option<Value>) -> Self {
        match data {
            Some(value) => value.into(),
            None => MaybeMultiple::None,
        }
    }
}

impl<T: DeserializeOwned> From<Value> for MaybeMultiple<T> {
    fn from(data: Value) -> Self {
        // First, try to convert to Vec<T>
        if let Ok(vec_result) = serde_json::from_value::<Vec<T>>(data.clone()) {
            MaybeMultiple::Multiple(vec_result)
        }
        // If Vec conversion fails, try single T
        else if let Ok(single_result) = serde_json::from_value::<T>(data) {
            MaybeMultiple::Single(single_result)
        }
        // If both conversions fail, return None
        else {
            MaybeMultiple::None
        }
    }
}

impl<T: Serialize> From<&MaybeMultiple<T>> for Option<Value> {
    fn from(object: &MaybeMultiple<T>) -> Self {
        match object {
            MaybeMultiple::None => None,
            _ => Some(json!(object)),
        }
    }
}

impl<T: Serialize> From<MaybeMultiple<T>> for Option<Value> {
    fn from(object: MaybeMultiple<T>) -> Self {
        match object {
            MaybeMultiple::None => None,
            _ => Some(json!(object)),
        }
    }
}

impl<T: Serialize> From<&MaybeMultiple<T>> for Value {
    fn from(object: &MaybeMultiple<T>) -> Self {
        json!(object)
    }
}

impl<T: Serialize> From<MaybeMultiple<T>> for Value {
    fn from(object: MaybeMultiple<T>) -> Self {
        json!(object)
    }
}

impl From<ApObject> for MaybeMultiple<ApObject> {
    fn from(data: ApObject) -> Self {
        MaybeMultiple::Single(data)
    }
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
    pub fn map<U, F>(self, mut f: F) -> MaybeMultiple<U>
    where
        F: FnMut(T) -> U,
    {
        match self {
            MaybeMultiple::Multiple(vec) => {
                MaybeMultiple::Multiple(vec.into_iter().map(f).collect())
            }
            MaybeMultiple::Single(val) => MaybeMultiple::Single(f(val)),
            MaybeMultiple::None => MaybeMultiple::None,
        }
    }

    pub fn single(&self) -> Result<T> {
        match self {
            MaybeMultiple::Multiple(s) => {
                if s.len() == 1 {
                    Ok(s[0].clone())
                } else {
                    Err(anyhow!("MaybeMultiple is Multiple"))
                }
            }
            MaybeMultiple::Single(s) => Ok(s.clone()),
            MaybeMultiple::None => Err(anyhow!("MaybeMultiple is None")),
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

    pub fn extend(mut self, mut additional: Vec<T>) -> Self {
        match self {
            MaybeMultiple::Multiple(ref mut data) => {
                data.append(&mut additional);
                data.clone().into()
            }
            MaybeMultiple::Single(data) => {
                additional.push(data.clone());
                additional.clone().into()
            }
            MaybeMultiple::None => additional.clone().into(),
        }
    }

    pub fn option(&self) -> Option<Vec<T>> {
        match self {
            MaybeMultiple::Multiple(v) => Some(v.clone()),
            MaybeMultiple::Single(s) => Some(vec![s.clone()]),
            MaybeMultiple::None => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Identifier {
    id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
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
