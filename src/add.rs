use core::fmt;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{ApAddress, ApContext};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
pub enum ApAddType {
    #[default]
    Add,
}

impl fmt::Display for ApAddType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApAdd {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApAddType,
    pub actor: ApAddress,
    pub target: Option<String>,
    pub object: String,
}
