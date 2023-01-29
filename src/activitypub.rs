use std::{collections::HashMap, fmt::{self, Debug}, str::FromStr};

use serde::{Serialize, Deserialize};
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;
use strum_macros::EnumString;

use crate::{get_webfinger, KexInitParams, authenticated, EnigmatickState, Profile, send_post, send_updated_olm_sessions, ENIGMATICK_STATE};


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
    kind: ApTagType,
    name: String,
    href: String,
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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApNote {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    pub tag: Option<Vec<ApTag>>,
    pub attributed_to: String,
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub kind: ApObjectType,
    pub to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replies: Option<ApFlexible>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Vec<ApAttachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atom_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to_atom_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_map: Option<Value>,
}

impl From<SendParams> for ApNote {
    fn from(params: SendParams) -> Self {
        let tag = Option::from(params.recipients.iter().map(|(x, y)| ApTag::Mention ( ApMention { kind: ApTagType::Mention, name: x.to_string(), href: y.to_string()})).collect::<Vec<ApTag>>());

        let mut recipients: Vec<String> = params.recipients.into_values().collect();
        recipients.extend(params.recipient_ids);

        if recipients.is_empty() {
            recipients.push("https://www.w3.org/ns/activitystreams#Public".to_string());
        }
        
        ApNote {
            context: Option::from(ApContext::default()),
            kind: ApObjectType::from_str(&params.kind).unwrap(),
            to: recipients,
            tag,
            content: params.content,
            in_reply_to: params.in_reply_to,
            ..Default::default()
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Default)]
pub struct SendParams {
    // @name@example.com -> https://example.com/user/name
    recipients: HashMap<String, String>,

    // https://server/user/username - used for EncryptedNotes where tags
    // are undesirable
    recipient_ids: Vec<String>,
    content: String,
    kind: String,
    in_reply_to: Option<String>,
}

#[wasm_bindgen]
impl SendParams {
    pub fn new() -> SendParams {
        SendParams::default()
    }

    pub fn set_kind(&mut self, kind: String) -> Self {
        self.kind = kind;
        self.clone()
    }
    
    pub fn add_recipient_id(&mut self, recipient_id: String) -> Self {
        self.recipient_ids.push(recipient_id);
        self.clone()
    }
    
    pub async fn add_address(&mut self, address: String) -> Self {
        self.recipients.insert(address.clone(), get_webfinger(address).await.unwrap_or_default());
        self.clone()
    }

    pub fn set_content(&mut self, content: String) -> Self {
        self.content = content;
        self.clone()
    }

    pub fn get_recipients(&self) -> String {
        serde_json::to_string(&self.recipients).unwrap()
    }

    pub fn get_content(&self) -> String {
        self.content.clone()
    }

    pub fn set_in_reply_to(&mut self, in_reply_to: String) -> Self {
        self.in_reply_to = Some(in_reply_to);
        self.clone()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, EnumString, Default)]
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
    IdentityKey,
    SessionKey,
    #[default]
    Unknown
}

impl fmt::Display for ApObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
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

#[wasm_bindgen]
pub async fn send_note(params: SendParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let id = format!("{}/user/{}",
                         state.server_url.unwrap(),
                         profile.username.clone());
        let mut note = ApNote::from(params);
        note.attributed_to = id;

        send_post(outbox,
                  serde_json::to_string(&note).unwrap(),
                  "application/activity+json".to_string()).await
    }).await.is_some()
}

#[wasm_bindgen]
pub async fn send_encrypted_note(params: SendParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let id = format!("{}/user/{}",
                         state.server_url.unwrap(),
                         profile.username.clone());
        let mut encrypted_message = ApNote::from(params);
        encrypted_message.attributed_to = id;

        
        if send_post(outbox,
                     serde_json::to_string(&encrypted_message).unwrap(),
                     "application/activity+json".to_string()).await.is_some() {
            if send_updated_olm_sessions().await {
                Option::from("{\"success\":true}".to_string())
            } else {
                Option::None
            }
        } else {
            Option::None
        }
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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApInstrument {
    Single(Box<ApObject>),
    Multiple(Vec<ApObject>),
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApSession {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    context: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
    to: String,
    pub attributed_to: String,
    pub instrument: ApInstrument,
    reference: Option<String>,
}

impl From<KexInitParams> for ApSession {
    fn from(params: KexInitParams) -> Self {
        ApSession {
            context: Option::from("https://www.w3.org/ns/activitystreams".to_string()),
            kind: "EncryptedSession".to_string(),
            to: params.recipient,
            instrument: ApInstrument::Single(Box::new(ApObject::Basic(ApBasicContent {
                kind: ApBasicContentType::IdentityKey,
                content: params.identity_key
            }))),
            ..Default::default()
        }
    }
}
