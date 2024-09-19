use js_sys::Promise;
use std::collections::HashMap;
use std::sync::{Mutex, Arc};
use wasm_bindgen_futures::{future_to_promise, JsFuture};
use futures::{Future, FutureExt};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug)]
pub struct EnigmatickCache {
    store: Mutex<HashMap<String, Promise>>,
}

#[wasm_bindgen]
impl EnigmatickCache {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        EnigmatickCache {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, key: &str) -> Option<Promise> {
        self.store.lock().unwrap().get(key).cloned()
    }

    pub fn set(&self, key: &str, value: Promise) {
        self.store.lock().unwrap().insert(key.to_string(), value);
    }
}

#[wasm_bindgen]
pub async fn fetch_with_cache(cache: &EnigmatickCache, url: String) -> Promise {
    if let Some(promise) = cache.get(&url.clone()) {
        return promise;
    }

    let url_clone = url.clone();
    let promise = future_to_promise(async move {
        let url = url.clone();
        let window = web_sys::window().unwrap();
        let resp = JsFuture::from(window.fetch_with_str(&url)).await?;
        let resp: web_sys::Response = resp.dyn_into().unwrap();
        let text = JsFuture::from(resp.text()?).await?;
        Ok(text)
    });

    let url = url_clone.clone();
    cache.set(&url, promise.clone());
    promise
}