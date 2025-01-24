use crate::{authenticated, log, EnigmatickState, Profile};
use jdt_activity_pub::{ApActor, ApCollection};
use js_sys::Promise;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::future_to_promise;

use crate::{get_state, send_get, send_get_promise, HANDLE_RE, URL_RE};

#[cfg(target_arch = "wasm32")]
use crate::EnigmatickCache;

#[wasm_bindgen]
pub async fn get_remote_resource(
    resource: String,
    webfinger: String,
    page: Option<String>,
) -> Option<String> {
    let state = get_state();
    let profile = format!("user/{}/", state.profile.clone()?.username);
    let server_name = state.server_name.clone()?;

    let url = match page {
        Some(page) => format!(
            "/api/{profile}remote/{resource}?webfinger={webfinger}&page={}",
            urlencoding::encode(&page)
        ),
        None => format!("/api/{profile}remote/{resource}?webfinger={webfinger}"),
    };

    send_get(Some(server_name), url, "application/json".to_string()).await
}

pub async fn get_remote_keys(webfinger: String) -> Option<ApCollection> {
    let state = get_state();
    let profile = format!("user/{}/", state.profile.clone()?.username);
    let server_name = state.server_name.clone()?;

    let url = format!("/api/{profile}remote/keys?webfinger={webfinger}");

    send_get(Some(server_name), url, "application/json".to_string())
        .await
        .and_then(|x| serde_json::from_str(&x).ok())
}

#[wasm_bindgen]
pub async fn get_remote_following(webfinger: String, page: Option<String>) -> Option<String> {
    get_remote_resource("following".to_string(), webfinger, page).await
}

#[wasm_bindgen]
pub async fn get_remote_followers(webfinger: String, page: Option<String>) -> Option<String> {
    get_remote_resource("followers".to_string(), webfinger, page).await
}

#[wasm_bindgen]
pub async fn get_remote_outbox(webfinger: String, page: Option<String>) -> Option<String> {
    get_remote_resource("outbox".to_string(), webfinger, page).await
}

#[wasm_bindgen]
pub fn get_actor_from_webfinger_promise(webfinger: String) -> Promise {
    let state = get_state();
    let authenticated = state.is_authenticated();

    let url = {
        if authenticated {
            let username = state.profile.clone().unwrap().username;
            format!("/api/user/{username}/remote/actor?webfinger={webfinger}")
        } else {
            format!("/api/remote/actor?webfinger={webfinger}")
        }
    };

    future_to_promise(send_get_promise(None, url, "application/json".to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn get_actor_cached(cache: &EnigmatickCache, id: String) -> Option<Promise> {
    if let Some(promise) = cache.get(&id.clone()) {
        log(&format!("SHORT CIRCUITING GET_ACTOR_CACHED: {id}"));
        return Some(promise);
    }

    if URL_RE.is_match(&id) {
        log(&format!("GETTING ID: {id}"));
        let webfinger = get_webfinger_from_id(id.clone()).await?;

        let p = get_actor_from_webfinger_promise(webfinger);
        cache.set(&id, p.clone());
    } else if HANDLE_RE.is_match(&id) {
        log(&format!("GETTING WEBFINGER: {id}"));

        let p = get_actor_from_webfinger_promise(id.clone());
        cache.set(&id, p.clone());
    }

    cache.get(&id.clone())
}

#[wasm_bindgen]
pub async fn get_actor(id: String) -> Option<String> {
    if URL_RE.is_match(&id) {
        let webfinger = get_webfinger_from_id(id).await?;

        get_actor_from_webfinger(webfinger)
            .await
            .and_then(|x| serde_json::to_string(&x).ok())
    } else if HANDLE_RE.is_match(&id) {
        get_actor_from_webfinger(id)
            .await
            .and_then(|x| serde_json::to_string(&x).ok())
    } else {
        None
    }
}

pub async fn get_actor_from_webfinger(webfinger: String) -> Option<ApActor> {
    let state = get_state();
    let authenticated = state.is_authenticated();

    let url = {
        if authenticated {
            let username = state.profile.clone()?.username;
            format!("/api/user/{username}/remote/actor?webfinger={webfinger}")
        } else {
            format!("/api/remote/actor?webfinger={webfinger}")
        }
    };

    send_get(None, url, "application/json".to_string())
        .await
        .and_then(|x| serde_json::from_str(&x).ok())
}

#[wasm_bindgen]
pub async fn get_webfinger_from_id(id: String) -> Option<String> {
    let id = urlencoding::encode(&id);

    let state = get_state();
    let authenticated = state.is_authenticated();

    let url = {
        if authenticated {
            let username = state.profile.clone()?.username;
            format!("/api/user/{username}/remote/webfinger?id={id}")
        } else {
            format!("/api/remote/webfinger?id={id}")
        }
    };

    send_get(None, url, "application/json".to_string()).await
}

#[wasm_bindgen]
pub async fn get_webfinger_from_handle(handle: String) -> Option<String> {
    authenticated(
        move |state: EnigmatickState, _profile: Profile| async move {
            let server = state.get_server_name();

            server.map(|server| format!("@{handle}@{server}"))
        },
    )
    .await
}
