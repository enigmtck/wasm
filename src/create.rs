use core::fmt;
use std::fmt::Debug;
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};

use crate::{ApAddress, ApContext, ApObject, Ephemeral, MaybeMultiple, MaybeReference};

use super::signature::ApSignature;

#[derive(Serialize, Deserialize, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
pub enum ApCreateType {
    #[default]
    Create,
}

impl fmt::Display for ApCreateType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApCreate {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApCreateType,
    pub actor: ApAddress,
    pub to: MaybeMultiple<ApAddress>,
    pub cc: Option<MaybeMultiple<ApAddress>>,
    pub id: Option<String>,
    pub object: MaybeReference<ApObject>,
    pub published: Option<String>,
    pub signature: Option<ApSignature>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}