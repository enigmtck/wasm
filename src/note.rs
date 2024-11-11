use std::{
    collections::HashMap,
    fmt::{self, Debug},
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vodozemac::{olm::{Account, AccountPickle, SessionConfig}, Curve25519PublicKey};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, encrypt, error, get_actor_from_webfinger, get_hash, get_remote_keys, get_state,
    get_webfinger_from_id, log, resolve_processed_item, send_get, send_post, ActivityPub, ApActor,
    ApActorTerse, ApAddress, ApAttachment, ApContext, ApFlexible, ApInstrument, ApInstrumentType,
    ApInstruments, ApMention, ApMentionType, ApObject, ApTag, EnigmatickState, Ephemeral,
    MaybeMultiple, OrdValue, Profile,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApNoteType {
    Note,
    EncryptedNote,
    VaultNote,
    #[default]
    Unknown,
}

impl fmt::Display for ApNoteType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub url: Option<String>,
    pub twitter_title: Option<String>,
    pub description: Option<String>,
    pub og_description: Option<String>,
    pub og_title: Option<String>,
    pub og_image: Option<String>,
    pub og_site_name: Option<String>,
    pub twitter_image: Option<String>,
    pub og_url: Option<String>,
    pub twitter_description: Option<String>,
    pub published: Option<String>,
    pub twitter_site: Option<String>,
    pub og_type: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct ApNote {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    pub tag: Option<Vec<ApTag>>,
    pub attributed_to: String,
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub kind: ApNoteType,
    pub to: MaybeMultiple<ApAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub published: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replies: Option<ApFlexible>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Vec<ApAttachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atom_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to_atom_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_map: Option<OrdValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument: Option<MaybeMultiple<ApInstrument>>,

    // These are ephemeral attributes to facilitate client operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}

impl Default for ApNote {
    fn default() -> ApNote {
        ApNote {
            context: Some(ApContext::default()),
            tag: None,
            attributed_to: String::new(),
            id: None,
            kind: ApNoteType::Note,
            to: MaybeMultiple::Multiple(vec![]),
            url: None,
            published: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            cc: None,
            replies: None,
            attachment: None,
            in_reply_to: None,
            content: String::new(),
            summary: None,
            sensitive: None,
            atom_uri: None,
            in_reply_to_atom_uri: None,
            conversation: None,
            content_map: None,
            instrument: None,
            ephemeral: None,
        }
    }
}

impl From<SendParams> for ApNote {
    fn from(params: SendParams) -> Self {
        log(&format!("params\n{params:#?}"));

        let mut tag = params
            .recipients
            .iter()
            .map(|(x, y)| {
                ApTag::Mention(ApMention {
                    kind: ApMentionType::Mention,
                    name: x.to_string(),
                    href: Some(y.to_string()),
                    value: None,
                })
            })
            .collect::<Vec<ApTag>>();

        if let Some(idk) = params.identity_key {
            tag.push(ApTag::Mention(ApMention {
                kind: ApMentionType::Mention,
                name: params.attributed_to,
                href: None,
                value: Some(idk),
            }));
        }

        let mut to: Vec<String> = vec![];
        let mut cc: Vec<String> = vec![];

        if params.is_public {
            to.push("https://www.w3.org/ns/activitystreams#Public".to_string());
            cc.extend(params.recipients.into_values().collect::<Vec<String>>());
            cc.extend(params.recipient_ids);
        } else {
            to.extend(params.recipients.into_values().collect::<Vec<String>>());
            to.extend(params.recipient_ids);
        }

        let mut instrument: Option<MaybeMultiple<ApInstrument>> = None;
        if let (Some(session), Some(hash)) = (params.session_data, params.session_hash) {
            instrument = Some(MaybeMultiple::Single(ApInstrument {
                kind: ApInstrumentType::OlmSession,
                content: Some(session),
                hash: hash.into(),
                uuid: params.session_uuid,
                ..Default::default()
            }))
        }

        ApNote {
            context: Some(ApContext::default()),
            kind: {
                if params.is_encrypted {
                    ApNoteType::EncryptedNote
                } else {
                    ApNoteType::Note
                }
            },
            to: MaybeMultiple::Multiple(to.iter().map(|x| ApAddress::Address(x.clone())).collect()),
            cc: Some(cc),
            tag: Some(tag),
            attachment: {
                if let Some(attachments) = params.attachments {
                    if let Ok(attachments) = serde_json::from_str::<Vec<ApAttachment>>(&attachments)
                    {
                        Some(attachments)
                    } else {
                        Some(vec![])
                    }
                } else {
                    Some(vec![])
                }
            },
            content: params.content,
            in_reply_to: params.in_reply_to,
            conversation: params.conversation,
            instrument,
            ..Default::default()
        }
    }
}

#[wasm_bindgen]
pub async fn get_local_conversation(uuid: String) -> Option<String> {
    let resp = Request::get(&format!("/conversation/{uuid}"))
        .header("Content-Type", "application/activity+json")
        .send()
        .await
        .ok()?;

    let text = resp.text().await.ok()?;

    if let Ok(ApObject::Collection(object)) = serde_json::from_str(&text) {
        object
            .items
            .map(|items| serde_json::to_string(&items).unwrap())
    } else {
        error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
        None
    }
}

#[wasm_bindgen]
pub async fn get_note(id: String) -> Option<String> {
    let path = format!("/api/remote/object?id={}", urlencoding::encode(&id));

    send_get(None, path, "application/json".to_string()).await
}

#[wasm_bindgen]
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendParams {
    attributed_to: String,
    // @name@example.com -> https://example.com/user/name
    recipients: HashMap<String, String>,

    // https://server/user/username - used for EncryptedNotes where tags
    // are undesirable
    recipient_ids: Vec<String>,
    content: String,
    in_reply_to: Option<String>,
    conversation: Option<String>,
    attachments: Option<String>,

    // OLM session information
    session_data: Option<String>,
    session_hash: Option<String>,
    session_uuid: Option<String>,
    mutation_of: Option<String>,

    identity_key: Option<String>,
    resolves: Option<String>,
    is_public: bool,
    is_encrypted: bool,
}

#[wasm_bindgen]
impl SendParams {
    pub async fn new() -> SendParams {
        let state = get_state();
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            SendParams {
                attributed_to: format!("{server_url}/user/{}", profile.username),
                ..Default::default()
            }
        } else {
            SendParams::default()
        }
    }

    pub fn resolves(&mut self, queue_id: String) -> Self {
        self.resolves = Some(queue_id);
        self.clone()
    }

    pub fn set_identity_key(&mut self, identity_key: String) -> Self {
        self.identity_key = Some(identity_key);
        self.clone()
    }

    pub fn set_encrypted(&mut self) -> Self {
        self.is_encrypted = true;
        self.clone()
    }

    pub fn set_public(&mut self) -> Self {
        self.is_public = true;
        self.clone()
    }

    pub async fn add_recipient_id(&mut self, recipient_id: String, tag: bool) -> Self {
        if tag {
            if let Some(webfinger) = get_webfinger_from_id(recipient_id.clone()).await {
                self.recipients.insert(webfinger, recipient_id);
            }
        } else {
            self.recipient_ids.push(recipient_id);
        }

        self.clone()
    }

    // address: @user@domain.tld
    pub async fn add_address(&mut self, address: String) -> Self {
        let actor = get_actor_from_webfinger(address.clone()).await;

        if let Some(actor) = actor {
            if let Some(id) = actor.id {
                self.recipients.insert(address.clone(), id);
            }
        }
        self.clone()
    }

    pub fn set_content(&mut self, content: String) -> Self {
        self.content = content;
        self.clone()
    }

    pub fn set_session_uuid(&mut self, uuid: Option<String>) -> Self {
        self.session_uuid = uuid;
        self.clone()
    }

    pub fn set_session_data(&mut self, session_data: String) -> Self {
        self.session_hash = get_hash(session_data.clone().into_bytes());
        self.session_data = encrypt(None, session_data).ok();
        self.clone()
    }

    pub fn set_mutation_of(&mut self, mutation_of: String) -> Self {
        self.mutation_of = mutation_of.into();
        self.clone()
    }

    pub fn get_recipients(&self) -> String {
        serde_json::to_string(&self.recipients).unwrap()
    }

    pub fn get_content(&self) -> String {
        self.content.clone()
    }

    pub fn set_in_reply_to(&mut self, in_reply_to: String) -> Self {
        self.in_reply_to = Some(in_reply_to);
        self.clone()
    }

    pub fn set_conversation(&mut self, conversation: String) -> Self {
        self.conversation = Some(conversation);
        self.clone()
    }

    pub fn set_attachments(&mut self, attachments: String) -> Self {
        self.attachments = Some(attachments);
        self.clone()
    }

    pub fn export(&self) -> String {
        serde_json::to_string(&self.clone()).unwrap()
    }
}

pub async fn encrypt_note(mut params: SendParams) -> Result<SendParams> {
    let state = get_state();

    if params.recipients.len() == 1 && state.is_authenticated() {
        if let Some((webfinger, id)) = params.recipients.iter().last() {
            let keys = get_remote_keys(webfinger.clone()).await;

            if let Some(keys) = keys {
                log(&format!("{keys:#?}"));

                let (one_time_key, identity_key) =
                    keys.items
                        .map(|items| {
                            items
                                .into_iter()
                                .fold((None, None), |(one_time, identity), item| match item {
                                    ActivityPub::Object(ApObject::Instrument(instrument)) => {
                                        match instrument.kind {
                                            ApInstrumentType::SessionKey if one_time.is_none() => {
                                                (instrument.content, identity)
                                            }
                                            ApInstrumentType::IdentityKey if identity.is_none() => {
                                                (one_time, instrument.content)
                                            }
                                            _ => (one_time, identity),
                                        }
                                    }
                                    _ => (one_time, identity),
                                })
                        })
                        .unwrap_or((None, None));

                if let (Some(identity_key), Some(one_time_key)) = (identity_key, one_time_key) {
                    let identity_key = Curve25519PublicKey::from_base64(&identity_key).map_err(anyhow::Error::msg)?;
                    let one_time_key = Curve25519PublicKey::from_base64(&one_time_key).map_err(anyhow::Error::msg)?;
                    if let Some(pickled_account) = state.get_olm_pickled_account() {
                        let pickled_account = serde_json::from_str::<AccountPickle>(&pickled_account).map_err(anyhow::Error::msg)?;
                        let account = Account::from(pickled_account);
                        let mut outbound =
                        account.create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key);
            
                        let message = serde_json::to_string(&outbound.encrypt(params.get_content())).map_err(anyhow::Error::msg)?;
                        log(&format!("ENCRYPTED MESSAGE: {message}"));
                    }
                }
            }
        }
    }

    Ok(params.clone())
}

#[wasm_bindgen]
pub async fn send_note(params: SendParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let params = encrypt_note(params).await.unwrap();
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let id = format!(
            "{}/user/{}",
            state.server_url.unwrap(),
            profile.username.clone()
        );
        let mut note = ApNote::from(params);
        note.attributed_to = id;

        log(&format!("NOTE\n{note:#?}"));
        // send_post(
        //     outbox,
        //     serde_json::to_string(&note).unwrap(),
        //     "application/activity+json".to_string(),
        // )
        // .await
        Some("".to_string())
    })
    .await
    .is_some()
}

#[wasm_bindgen]
pub async fn send_encrypted_note(params: SendParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        log("IN send_encrypted_note");

        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let id = format!(
            "{}/user/{}",
            state.server_url.unwrap(),
            profile.username.clone()
        );

        let mut encrypted_message = ApNote::from(params.clone());
        encrypted_message.attributed_to = id;

        if send_post(
            outbox,
            serde_json::to_string(&encrypted_message).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
        .is_some()
        {
            if let Some(resolves) = params.clone().resolves {
                resolve_processed_item(resolves).await
            } else {
                None
            }
        } else {
            None
        }
    })
    .await
    .is_some()
}
