use std::fmt::Debug;

use serde::{Serialize, Deserialize};
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, send_post, ENIGMATICK_STATE, ApNote, ApSession, ApInstrument, MaybeReference, ApActor, ApCollection, ApCollectionPage, ApDelete, ApLike, ApAnnounce, ApAccept, ApCreate, ApInvite, ApJoin, ApUpdate, ApBlock, ApAdd, ApRemove};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApFlexible {
    Single(Value),
    Multiple(Vec<Value>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApMentionType {
    Mention,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApHashtagType {
    Hashtag,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApEmojiType {
    Emoji,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApHashtag {
    #[serde(rename = "type")]
    kind: ApHashtagType,
    name: String,
    href: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApMention {
    #[serde(rename = "type")]
    pub kind: ApMentionType,
    pub name: String,
    pub href: Option<String>,
    pub value: Option<String>,
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
    kind: ApEmojiType,
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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApAttachmentType {
    OlmSession,
    PropertyValue,
    Document,
    IdentityProof,
    Link,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApAttachment {
    #[serde(rename = "type")]
    pub kind: ApAttachmentType,
    pub name: Option<String>,
    pub value: Option<String>,
    pub hash: Option<String>,
    pub mutation_of: Option<String>,
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
pub enum ApUndoType {
    #[default]
    Undo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApUndo {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApUndoType,
    pub actor: String,
    pub id: Option<String>,
    pub object: MaybeReference<ApObject>,
}

impl From<ApFollow> for ApUndo {
    fn from(follow: ApFollow) -> Self {
        ApUndo {
            context: Some(ApContext::default()),
            kind: ApUndoType::default(),
            actor: follow.actor.clone(),
            id: follow.id.clone().map(|follow| format!("{}#undo", follow)),
            object: MaybeReference::Actual(ApObject::Follow(Box::new(follow))),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub enum ApFollowType {
    #[default]
    Follow
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApFollow {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApFollowType,
    pub actor: String,
    pub id: Option<String>,
    pub object: ApObject,
}

impl From<String> for ApFollow {
    fn from(object: String) -> Self {
        // I'm probably doing this badly; I'm trying to appease the compiler
        // warning me about holding the lock across the await further down
        let state = &*ENIGMATICK_STATE;
        let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};

        if let Some(state) = state {
            if let (Some(server_url), Some(profile)) = (state.server_url, state.profile) {
                let actor = format!("{}/user/{}", server_url, profile.username);
        
                ApFollow {
                    id: None,
                    context: Some(ApContext::default()),
                    kind: ApFollowType::Follow,
                    actor,
                    object: ApObject::Plain(object), 
                }
            } else {
                ApFollow::default()
            }
        } else {
            ApFollow::default()
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApObject {
    Plain(String),
    Collection(ApCollection),
    CollectionPage(ApCollectionPage),
    Session(ApSession),
    Instrument(ApInstrument),
    Note(ApNote),
    Actor(ApActor),
    Follow(Box<ApFollow>),
    Undo(Box<ApUndo>),
    #[default]
    Unknown,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApActivity {
    Delete(Box<ApDelete>),
    Like(Box<ApLike>),
    Undo(Box<ApUndo>),
    Accept(Box<ApAccept>),
    Follow(ApFollow),
    Announce(ApAnnounce),
    Create(ApCreate),
    Invite(ApInvite),
    Join(ApJoin),
    Update(ApUpdate),
    Block(ApBlock),
    Add(ApAdd),
    Remove(ApRemove),
}


#[wasm_bindgen]
pub async fn send_follow(address: String) -> bool {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let follow: ApFollow = address.into();

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
        
        let follow: ApFollow = address.into();
        let undo: ApUndo = follow.into();

        send_post(outbox,
                  serde_json::to_string(&undo).unwrap(),
                  "application/activity+json".to_string()).await
    }).await.is_some()
}


