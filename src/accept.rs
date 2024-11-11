use core::fmt;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{ApActivity, ApAddress, ApContext, MaybeReference};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
pub enum ApAcceptType {
    #[default]
    Accept,
}

impl fmt::Display for ApAcceptType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApAccept {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApAcceptType,
    pub actor: ApAddress,
    pub id: Option<String>,
    pub object: MaybeReference<ApActivity>,
}
