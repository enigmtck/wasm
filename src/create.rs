use core::fmt;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{ApAddress, ApContext, ApInstrument, ApObject, Ephemeral, MaybeMultiple, MaybeReference};

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

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApCreate {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApCreateType,
    pub actor: ApAddress,
    pub to: MaybeMultiple<ApAddress>,
    #[serde(skip_serializing_if = "MaybeMultiple::is_none")]
    #[serde(default)]
    pub cc: MaybeMultiple<ApAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub object: MaybeReference<ApObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ApSignature>,
    #[serde(skip_serializing_if = "MaybeMultiple::is_none")]
    #[serde(default)]
    pub instrument: MaybeMultiple<ApInstrument>,

    // These are ephemeral attributes to facilitate client operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}
