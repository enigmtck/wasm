use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    ApAccept, ApActor, ApAdd, ApAnnounce, ApBlock, ApCollection, ApCollectionPage, ApCreate, ApDelete, ApFollow, ApInstrument, ApInvite, ApJoin, ApLike, ApNote, ApQuestion, ApRemove, ApSession, ApUndo, ApUpdate, OrdValue
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApFlexible {
    Single(Value),
    Multiple(Vec<Value>),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApMentionType {
    Mention,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApHashtagType {
    Hashtag,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApEmojiType {
    Emoji,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApHashtag {
    #[serde(rename = "type")]
    kind: ApHashtagType,
    name: String,
    href: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApMention {
    #[serde(rename = "type")]
    pub kind: ApMentionType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApImageType {
    Image,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ApImage {
    #[serde(rename = "type")]
    pub kind: ApImageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApEmoji {
    #[serde(rename = "type")]
    kind: ApEmojiType,
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<String>,
    icon: ApImage,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum ApTag {
    Mention(ApMention),
    Emoji(ApEmoji),
    HashTag(ApHashtag),
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(untagged)]
pub enum ApContext {
    Plain(String),
    Complex(Vec<OrdValue>),
}

impl Default for ApContext {
    fn default() -> Self {
        ApContext::Plain("https://www.w3.org/ns/activitystreams".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApObject {
    Session(ApSession),
    Instrument(ApInstrument),
    Note(ApNote),
    Question(ApQuestion),
    Actor(ApActor),
    Collection(ApCollection),
    CollectionPage(ApCollectionPage),

    // These members exist to catch unknown object types
    Plain(String),
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
