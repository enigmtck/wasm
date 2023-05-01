use core::fmt;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::{ActivityPub, ApContext, MaybeReference};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApCollectionType {
    Collection,
    OrderedCollection,
    #[default]
    Unknown,
}

impl fmt::Display for ApCollectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApCollectionPageType {
    #[default]
    CollectionPage,
    OrderedCollectionPage,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApCollectionPage {
    #[serde(rename = "type")]
    pub kind: ApCollectionPageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_of: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<ActivityPub>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordered_items: Option<Vec<ActivityPub>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApCollection {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApCollectionType,
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<ActivityPub>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordered_items: Option<Vec<ActivityPub>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<MaybeReference<ApCollectionPage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<MaybeReference<ApCollectionPage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<MaybeReference<ApCollectionPage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<MaybeReference<ApCollectionPage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<MaybeReference<ApCollectionPage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_of: Option<String>,
}
