use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;
use std::fmt::{self, Debug};

use crate::{send_get, ApContext, ApTag, ApAttachment, ApImage, authenticated, EnigmatickState, Profile, ENIGMATICK_STATE, log};

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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApAddress {
    Address(String),
}

impl ApAddress {
    pub fn is_public(&self) -> bool {
        let ApAddress::Address(x) = self;
        x.to_lowercase() == *"https://www.w3.org/ns/activitystreams#public"
    }

    pub fn get_public() -> Self {
        ApAddress::Address("https://www.w3.org/ns/activitystreams#Public".to_string())
    }
}

impl fmt::Display for ApAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ApAddress::Address(x) = self;
        write!(f, "{}", x.clone())
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
    pub also_known_as: Option<Vec<String>>,
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
    template: Option<String>
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
    let path = match page {
        Some(page) => format!(
            "/api/remote/{resource}?webfinger={webfinger}&page={}",
            urlencoding::encode(&page)
        ),
        None => format!("/api/remote/{resource}?webfinger={webfinger}"),
    };
    send_get(path, "application/json".to_string()).await
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
    let authentication: Option<String> = {
        if let Ok(state) = (*ENIGMATICK_STATE).try_lock() {
            if let Some(profile) = state.profile.clone() {
                if state.is_authenticated() {
                    Some(profile.username)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    let url = {
        if let Some(username) = authentication {
            log("AUTHENTICATED ACTOR RETRIEVAL");
            format!("/api/user/{username}/remote/actor?webfinger={webfinger}")
        } else {
            format!("/api/remote/actor?webfinger={webfinger}")
        }
    };
    
    send_get(url, "application/json".to_string()).await
}

#[wasm_bindgen]
pub async fn get_actor(id: String) -> Option<String> {
    if let Some(webfinger) = get_webfinger_from_id(id).await {
        get_actor_from_webfinger(webfinger).await
    } else {
        None
    }
}

#[wasm_bindgen]
pub async fn get_webfinger_from_id(id: String) -> Option<String> {
    let id = urlencoding::encode(&id);

    let authentication: Option<String> = {
        if let Ok(state) = (*ENIGMATICK_STATE).try_lock() {
            if let Some(profile) = state.profile.clone() {
                if state.is_authenticated() {
                    Some(profile.username)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    let url = {
        if let Some(username) = authentication {
            log("AUTHENTICATED WEBFINGER RETRIEVAL");
            format!("/api/user/{username}/remote/webfinger?id={id}")
        } else {
            format!("/api/remote/webfinger?id={id}")
        }
    };

    send_get(url, "application/json".to_string()).await
}

