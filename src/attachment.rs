use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum ApAttachment {
    Document(ApDocument),
    PropertyValue(ApPropertyValue),
    Link(ApLink),
    Proof(ApProof),
    VerifiableIdentityStatement(ApVerifiableIdentityStatement),
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApDocumentType {
    Document,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApDocument {
    #[serde(rename = "type")]
    pub kind: ApDocumentType,
    pub media_type: Option<String>,
    pub url: Option<String>,
    pub blurhash: Option<String>,
    pub width: Option<i32>,
    pub height: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApPropertyValueType {
    PropertyValue,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApPropertyValue {
    #[serde(rename = "type")]
    pub kind: ApPropertyValueType,
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApLinkType {
    Link,
}

impl fmt::Display for ApLinkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApLink {
    #[serde(rename = "type")]
    pub kind: ApLinkType,
    pub href: Option<String>,
    pub media_type: Option<String>,
    pub name: Option<String>,
    pub rel: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApProof {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub created: Option<String>,
    pub proof_purpose: Option<String>,
    pub proof_value: Option<String>,
    pub verification_method: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApVerifiableIdentityStatementType {
    VerifiableIdentityStatement,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApVerifiableIdentityStatement {
    #[serde(rename = "type")]
    pub kind: ApVerifiableIdentityStatementType,
    pub subject: Option<String>,
    pub proof: Option<ApProof>,
    pub also_known_as: Option<String>,
}
