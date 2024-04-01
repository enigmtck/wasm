use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    get_state, send_get, ApAttachment, ApContext, ApImage, ApTag, MaybeMultiple, HANDLE_RE, URL_RE,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApPublicKey {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
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

#[derive(Serialize, PartialEq, Eq, Deserialize, Clone, Debug, Default)]
pub enum ApActorType {
    Application,
    Group,
    Organization,
    Person,
    Service,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApEndpoint {
    pub shared_inbox: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
    pub url: Option<String>,
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

    // These facilitate consolidation of joined tables in to this object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_followers: Option<Vec<ApActor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_leaders: Option<Vec<ApActor>>,

    // These are ephemeral attributes to facilitate client operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_following: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_leader_ap_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_follow_activity_ap_id: Option<String>,

    // These are used for user operations on their own profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_summary_markdown: Option<String>,
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
