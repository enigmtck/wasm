#![allow(non_upper_case_globals)]

use gloo_net::http::Request;
use futures::Future;
use wasm_bindgen::prelude::*;
use lazy_static::lazy_static;

use std::sync::{Arc, Mutex};
use std::fmt::{self, Debug};

pub mod user;
pub mod crypto;
pub mod activitypub;
pub mod webfinger;
pub mod keystore;
pub mod instance;
pub mod inbox;
pub mod processing_queue;
pub mod state;

pub use user::*;
pub use crypto::*;
pub use activitypub::*;
pub use webfinger::*;
pub use keystore::*;
pub use instance::*;
pub use inbox::*;
pub use processing_queue::*;
pub use state::*;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
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

pub async fn authenticated<F, Fut>(f: F) -> Option<String> where F: FnOnce(EnigmatickState, Profile) -> Fut, Fut: Future<Output = Option<String>> {
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};
    
    if let Some(state) = state {
        log("in state");
        if state.is_authenticated() {
            log("in authenticated");
            if let Some(profile) = &state.profile.clone() {
                log("in profile");

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

    log("in send_post");
    
    if let Some(state) = state {
        log(&format!("in state\n{state:#?}"));
        let signature = sign(SignParams {
            host: state.server_name.unwrap(),
            request_target: url.clone(),
            body: Option::from(body.clone()),
            data: Option::None,
            method: Method::Post
        });

        log("pre send");
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
                    Err(e) => {
                        log(&format!("{e:#?}"));
                        Option::None
                    }
                },
                Err(e) => {
                    log(&format!("{e:#?}"));
                    Option::None
                }
            }
    } else {
        log("in no state");
        Option::None
    }
}

pub async fn upload_file(server_name: String, upload: String, data: &[u8], length: u32) -> Option<String> {
    let j = js_sys::Uint8Array::new_with_length(length);
    j.copy_from(data);

    let signature = sign(SignParams {
        host: server_name,
        request_target: upload.clone(),
        body: Option::None,
        data: Option::from(Vec::from(data)),
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
        log(&format!("upload completed\n{resp:#?}"));
        Option::from("{\"success\":true}".to_string())
    } else {
        Option::None
    }
}
