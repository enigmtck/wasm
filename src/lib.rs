#![allow(non_upper_case_globals)]

use gloo_net::http::Request;
use futures::Future;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::*;
use lazy_static::lazy_static;
use orion::{aead, aead::SecretKey};

use std::sync::{Arc, Mutex};
use std::fmt::{self, Debug};

pub mod announce;
pub mod accept;
pub mod attachment;
pub mod create;
pub mod user;
pub mod collection;
pub mod crypto;
pub mod activitypub;
pub mod actor;
pub mod delete;
pub mod follow;
pub mod keystore;
pub mod instance;
pub mod inbox;
pub mod outbox;
pub mod note;
pub mod processing_queue;
pub mod state;
pub mod timeline;
pub mod session;
pub mod signature;
pub mod stream;
pub mod vault;
pub mod like;
pub mod invite;
pub mod join;
pub mod update;
pub mod block;
pub mod add;
pub mod remove;
pub mod undo;
pub mod olm;

pub use announce::*;
pub use accept::*;
pub use attachment::*;
pub use create::*;
pub use user::*;
pub use collection::*;
pub use crypto::*;
pub use activitypub::*;
pub use actor::*;
pub use delete::*;
pub use follow::*;
pub use keystore::*;
pub use instance::*;
pub use inbox::*;
pub use outbox::*;
pub use note::*;
pub use processing_queue::*;
pub use session::*;
pub use state::*;
pub use timeline::*;
pub use stream::*;
pub use signature::*;
pub use vault::*;
pub use like::*;
pub use invite::*;
pub use join::*;
pub use update::*;
pub use block::*;
pub use add::*;
pub use remove::*;
pub use undo::*;
pub use olm::*;

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

lazy_static! {
    pub static ref ENIGMATICK_STATE: Arc<Mutex<EnigmatickState>> = {
        Arc::new(Mutex::new(EnigmatickState::new()))
    };
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
    None
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
            MaybeMultiple::None => None
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

#[wasm_bindgen]
pub fn decrypt(encoded_data: String) -> Option<String> {
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};

    if let Some(state) = state {
        if let Some(derived_key) = state.derived_key {
            if let Ok(derived_key) = base64::decode(derived_key) {
                if let Ok(derived_key) = SecretKey::from_slice(&derived_key) {
                    if let Ok(decrypted) = aead::open(&derived_key, &base64::decode(encoded_data).unwrap()) {
                        if let Ok(decrypted) = String::from_utf8(decrypted) {
                            Some(decrypted)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub fn encrypt(data: String) -> Option<String> {
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};

    if let Some(state) = state {
        if let Some(derived_key) = state.derived_key {
            if let Ok(derived_key) = base64::decode(derived_key) {
                if let Ok(derived_key) = SecretKey::from_slice(&derived_key) {
                    if let Ok(encrypted) = aead::seal(&derived_key, data.as_bytes()) {
                        base64::encode(encrypted).into()
                    } else {
                        Option::None
                    }
                } else {
                    Option::None
                }
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

pub async fn authenticated<F, Fut>(f: F) -> Option<String> where F: FnOnce(EnigmatickState, Profile) -> Fut, Fut: Future<Output = Option<String>> {
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};
    
    if let Some(state) = state {
        if state.is_authenticated() {
            if let Some(profile) = &state.profile.clone() {

                f(state, profile.clone()).await
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[derive(Debug, Clone)]
pub enum Method {
    Get,
    Post
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

pub async fn send_post(url: String, body: String, content_type: String) -> Option<String> {
    let state = {
        if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
            Option::from(x.clone()) } else { Option::None }
    };
    
    if let Some(state) = state {
        let signature = sign(SignParams {
            host: state.server_name.unwrap(),
            request_target: url.clone(),
            body: Option::from(body.clone()),
            data: Option::None,
            method: Method::Post
        });

        match Request::post(&url)
            .header("Enigmatick-Date", &signature.date)
            .header("Digest", &signature.digest.unwrap())
            .header("Signature", &signature.signature)
            .header("Content-Type", &content_type)
            .body(body)
            .send()
            .await {
                Ok(x) => match x.text().await {
                    Ok(x) => Option::from(x),
                    Err(_) => {
                        error("UNABLE TO DECODE RESPONSE");
                        Option::None
                    }
                },
                Err(_) => {
                    error("UNABLE TO SEND POST");
                    Option::None
                }
            }
    } else {
        error("UNABLE TO RETRIEVE STATE");
        Option::None
    }
}

pub async fn send_get(url: String, content_type: String) -> Option<String> {
    let state = {
        if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
            Option::from(x.clone()) } else { Option::None }
    };
    
    if let Some(state) = state {
        let signature = sign(SignParams {
            host: state.server_name.unwrap(),
            request_target: url.clone(),
            body: Option::None,
            data: Option::None,
            method: Method::Get
        });

        match Request::get(&url)
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature)
            .header("Content-Type", &content_type)
            .send().await
        {
            Ok(x) if x.status() == 200 => match x.text().await {
                Ok(x) => Option::from(x),
                Err(e) => {
                    error(&format!("ERROR PERFORMING GET\n{e:#?}"));
                    Option::None
                }
            },
            Ok(x) => {
                error(&format!("ERROR PERFORMING GET\n{x:#?}"));
                Option::None
            },
            Err(e) => {
                error(&format!("ERROR PERFORMING GET\n{e:#?}"));
                Option::None
            }
        }
    } else {
        error("UNABLE TO RETRIEVE STATE");
        Option::None
    }
}

pub async fn upload_file(server_name: String, upload: String, data: &[u8], length: u32) -> Option<String> {
    let j = js_sys::Uint8Array::new_with_length(length);
    j.copy_from(data);

    let signature = sign(SignParams {
        host: server_name,
        request_target: upload.clone(),
        body: None,
        data: Some(Vec::from(data)),
        method: Method::Post
    });

    if let Ok(resp) = Request::post(&upload)
        .header("Enigmatick-Date", &signature.date)
        .header("Digest", &signature.digest.unwrap())
        .header("Signature", &signature.signature)
        .header("Content-Type", "application/octet-stream")
        .body(j)
        .send().await
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
    let server_name: Option<String> = {
        if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
            x.clone().server_name } else { Option::None }
    };

    server_name.map(|x| format!("https://{}/activities/{}", x, uuid))
}
