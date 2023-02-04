use std::{collections::HashMap, fmt::{self, Debug}, str::FromStr};

use serde::{Serialize, Deserialize};
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;
use strum_macros::{EnumString, Display};

use crate::{get_webfinger, KexInitParams, authenticated, EnigmatickState, Profile, send_post, send_updated_olm_sessions, ENIGMATICK_STATE, SendParams, ApNote, ApSession};


#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApFlexible {
    Single(Value),
    Multiple(Vec<Value>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApTagType {
    Mention,
    Hashtag,
    Emoji,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApHashtag {
    #[serde(rename = "type")]
    kind: ApTagType,
    name: String,
    href: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApMention {
    #[serde(rename = "type")]
    pub kind: ApTagType,
    pub name: String,
    pub href: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApImageType {
    Image,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApImage {
    #[serde(rename = "type")]
    pub kind: ApImageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApEmoji {
    #[serde(rename = "type")]
    kind: ApTagType,
    id: Option<String>,
    name: Option<String>,
    updated: Option<String>,
    icon: Option<ApImage>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum ApTag {
    Mention(ApMention),
    Emoji(ApEmoji),
    HashTag(ApHashtag),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApAttachmentType {
    PropertyValue,
    Document,
    IdentityProof,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApAttachment {
    #[serde(rename = "type")]
    pub kind: ApAttachmentType,
    pub name: Option<String>,
    pub value: Option<String>,
    pub media_type: Option<String>,
    pub url: Option<String>,
    pub blurhash: Option<String>,
    pub width: Option<i32>,
    pub height: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApContext {
    Plain(String),
    Complex(Vec<Value>),
}

impl Default for ApContext {
    fn default() -> Self {
        ApContext::Plain("https://www.w3.org/ns/activitystreams".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, EnumString, Display, Default)]
pub enum ApObjectType {
    Article,
    Audio,
    Document,
    Event,
    Image,
    Note,
    Page,
    Place,
    Profile,
    Relationship,
    Tombstone,
    Video,
    EncryptedSession,
    EncryptedNote,
    IdentityKey,
    SessionKey,
    #[default]
    Unknown
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApBaseObjectType {
    Object,
    Link,
    Activity,
    IntransitiveActivity,
    Collection,
    OrderedCollection,
    CollectionPage,
    OrderedCollectionPage,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApCollection {
    #[serde(rename = "@context")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApBaseObjectType,
    pub id: Option<String>,
    pub total_items: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<ApObject>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    part_of: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApObject {
    Plain(String),
    Collection(ApCollection),
    Session(ApSession),
    Note(ApNote),
    Basic(ApBasicContent),
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub enum ApFollowType {
    Follow,
    Undo,
    #[default]
    Unknown
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApFollow {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    context: Option<String>,
    #[serde(rename = "type")]
    kind: ApFollowType,
    actor: String,
    object: String,
}

type FollowAction = (String, ApFollowType);

impl From<FollowAction> for ApFollow {
    fn from(action: FollowAction) -> Self {
        // I'm probably doing this badly; I'm trying to appease the compiler
        // warning me about holding the lock across the await further down
        let state = &*ENIGMATICK_STATE;
        let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};

        if let Some(state) = state {
            if let (Some(server_url), Some(profile)) = (state.server_url, state.profile) {
                let actor = format!("{}/user/{}", server_url, profile.username);
        
                ApFollow {
                    context: Option::from("https://www.w3.org/ns/activitystreams".to_string()),
                    kind: action.1,
                    actor,
                    object: action.0            
                }
            } else {
                ApFollow::default()
            }
        } else {
            ApFollow::default()
        }
    }
}

#[wasm_bindgen]
pub async fn send_follow(address: String) -> bool {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let follow: ApFollow = (address, ApFollowType::Follow).into();

        send_post(outbox,
                  serde_json::to_string(&follow).unwrap(),
                  "application/activity+json".to_string()).await
    }).await.is_some()
}

#[wasm_bindgen]
pub async fn send_unfollow(address: String) -> bool {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let follow: ApFollow = (address, ApFollowType::Undo).into();

        send_post(outbox,
                  serde_json::to_string(&follow).unwrap(),
                  "application/activity+json".to_string()).await
    }).await.is_some()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ApBasicContentType {
    IdentityKey,
    SessionKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApBasicContent {
    #[serde(rename = "type")]
    pub kind: ApBasicContentType,
    pub content: String,
}
