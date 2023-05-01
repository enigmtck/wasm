use core::fmt;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{ApAddress, ApContext, ApObject, MaybeMultiple, MaybeReference};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApJoinType {
    #[default]
    Join,
}

impl fmt::Display for ApJoinType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApJoin {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApJoinType,
    pub actor: ApAddress,
    pub id: Option<String>,
    pub to: MaybeMultiple<ApAddress>,
    pub object: MaybeReference<ApObject>,
}
