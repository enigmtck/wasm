use core::fmt;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{ApAddress, ApContext};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApBlockType {
    #[default]
    Block,
}

impl fmt::Display for ApBlockType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApBlock {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApBlockType,
    pub actor: ApAddress,
    pub id: Option<String>,
    pub object: String,
}
