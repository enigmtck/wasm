#![allow(non_upper_case_globals)]

use gloo_net::http::Request;
use futures::Future;
use wasm_bindgen::prelude::*;
use lazy_static::lazy_static;
use orion::{aead, aead::SecretKey};

use std::sync::{Arc, Mutex};
use std::fmt::{self, Debug};

pub mod user;
pub mod crypto;
pub mod activitypub;
pub mod webfinger;
pub mod keystore;
pub mod instance;
pub mod inbox;
pub mod note;
pub mod processing_queue;
pub mod state;
pub mod timeline;
pub mod session;
pub mod stream;
pub mod vault;

pub use user::*;
pub use crypto::*;
pub use activitypub::*;
pub use webfinger::*;
pub use keystore::*;
pub use instance::*;
pub use inbox::*;
pub use note::*;
pub use processing_queue::*;
pub use session::*;
pub use state::*;
pub use timeline::*;
pub use stream::*;
pub use vault::*;

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
                    Err(e) => {
                        error("UNABLE TO DECODE RESPONSE");
                        Option::None
                    }
                },
                Err(e) => {
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
            Ok(x) => match x.text().await {
                Ok(x) => Option::from(x),
                Err(e) => {
                    error(&format!("ERROR PERFORMING GET\n{e:#?}"));
                    Option::None
                }
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
