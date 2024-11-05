use js_sys::{Promise};
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::future_to_promise;
use std::fmt::{self, Debug};
use wasm_bindgen::prelude::wasm_bindgen;
use crate::{authenticated, log, EnigmatickState, Ephemeral, Profile};

use crate::{
    get_state, send_get, send_get_promise, ApAttachment, ApContext, ApImage, ApTag, EnigmatickCache, MaybeMultiple, HANDLE_RE, URL_RE
};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApPublicKey {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApCapabilities {
    pub accepts_chat_messages: Option<bool>,
    pub enigmatick_encryption: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default, Hash)]
#[serde(untagged)]
pub enum ApAddress {
    Address(String),
    #[default]
    None,
}

impl fmt::Display for ApAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let ApAddress::Address(x) = self {
            write!(f, "{}", x.clone())
        } else {
            write!(f, "https://localhost")
        }
    }
}

impl From<String> for ApAddress {
    fn from(address: String) -> Self {
        ApAddress::Address(address)
    }
}

impl TryFrom<serde_json::Value> for ApAddress {
    type Error = String;

    fn try_from(address: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(address).map_err(|_| "failed to convert to ApAddress")?
    }
}

impl ApAddress {
    pub fn is_public(&self) -> bool {
        if let ApAddress::Address(x) = self {
            x.to_lowercase() == *"https://www.w3.org/ns/activitystreams#public"
        } else {
            false
        }
    }

    pub fn get_public() -> Self {
        ApAddress::Address("https://www.w3.org/ns/activitystreams#Public".to_string())
    }
}

#[derive(Serialize, PartialEq, Eq, Deserialize, Clone, Debug, Default, Ord, PartialOrd)]
pub enum ApActorType {
    Application,
    Group,
    Organization,
    Person,
    Service,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApEndpoint {
    pub shared_inbox: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApActor {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApActorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub preferred_username: String,
    pub inbox: String,
    pub outbox: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub following: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liked: Option<String>,
    pub public_key: ApPublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub featured: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub featured_tags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<MaybeMultiple<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manually_approves_followers: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Vec<ApTag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Vec<ApAttachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<ApEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<ApImage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ApImage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<MaybeMultiple<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<bool>,

    // perhaps SoapBox/Pleroma-specific
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<ApCapabilities>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ApActorTerse {
    pub id: String,
    pub url: String,
    pub name: Option<String>,
    pub preferred_username: String,
    pub tag: Vec<ApTag>,
    pub icon: Option<ApImage>,
}

#[derive(Serialize, Deserialize)]
pub struct WebfingerLink {
    rel: String,
    #[serde(rename = "type")]
    kind: Option<String>,
    href: Option<String>,
    template: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct WebfingerResponse {
    pub subject: String,
    pub aliases: Vec<String>,
    pub links: Vec<WebfingerLink>,
}

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

        get_actor_from_webfinger(webfinger).await
    } else if HANDLE_RE.is_match(&id) {
        get_actor_from_webfinger(id).await
    } else {
        None
    }
}

#[wasm_bindgen]
pub async fn get_actor_from_webfinger(webfinger: String) -> Option<String> {
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

    send_get(None, url, "application/json".to_string()).await
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
    authenticated(move |state: EnigmatickState, _profile: Profile| async move {
        let server = state.get_server_name();

        server.map(|server| format!("@{handle}@{server}"))
    })
    .await
}