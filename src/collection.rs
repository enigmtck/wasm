use core::fmt;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ActivityPub, ApContext, ApInstrument, ApObject, Ephemeral, MaybeReference};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApCollectionAmbiguated {
    Collection(ApCollection),
    Page(ApCollectionPage),
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApCollectionType {
    #[default]
    Collection,
    OrderedCollection,
}

impl fmt::Display for ApCollectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApCollectionPageType {
    #[default]
    CollectionPage,
    OrderedCollectionPage,
}

impl fmt::Display for ApCollectionPageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApCollectionPage {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApCollectionPageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_of: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<ActivityPub>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordered_items: Option<Vec<ActivityPub>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApCollection {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApCollectionType,
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<i64>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}

impl From<Vec<ApInstrument>> for ApCollection {
    fn from(instruments: Vec<ApInstrument>) -> Self {
        Self {
            kind: ApCollectionType::Collection,
            total_items: Some(instruments.len() as i64),
            items: Some(instruments.into_iter().map(ApObject::from).collect()),
            ..Default::default()
        }
    }
}

impl Default for ApCollection {
    fn default() -> ApCollection {
        ApCollection {
            context: Some(ApContext::default()),
            kind: ApCollectionType::Collection,
            id: None,
            total_items: None,
            items: None,
            ordered_items: None,
            first: None,
            last: None,
            next: None,
            prev: None,
            current: None,
            part_of: None,
            ephemeral: None,
        }
    }
}