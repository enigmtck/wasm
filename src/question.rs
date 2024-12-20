
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::{ApAddress, ApAttachment, ApCollectionType, ApContext, ApNoteType, ApTag, Ephemeral, MaybeMultiple, OrdValue};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApQuestionType {
    #[default]
    #[serde(alias = "question")]
    Question,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct QuestionCollection {
    total_items: i32,
    #[serde(rename = "type")]
    kind: ApCollectionType,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct QuestionNote {
    id: Option<String>,
    attributed_to: Option<String>,
    to: Option<MaybeMultiple<String>>,
    name: String,
    replies: Option<QuestionCollection>,
    #[serde(rename = "type")]
    kind: ApNoteType,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApQuestion {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApQuestionType,
    pub id: String,

    pub attributed_to: ApAddress,
    pub to: MaybeMultiple<ApAddress>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<MaybeMultiple<ApAddress>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<QuestionNote>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_of: Option<Vec<QuestionNote>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_map: Option<OrdValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voters_count: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Vec<ApTag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Vec<ApAttachment>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}
