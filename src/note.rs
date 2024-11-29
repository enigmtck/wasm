use std::{
    collections::HashMap,
    fmt::{self, Debug},
};

use anyhow::Result;
use chrono::Utc;
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, create_olm_session, error, get_actor_from_webfinger, get_olm_session, get_state,
    get_webfinger_from_id, log, resolve_processed_item, send_get, send_post, ApAddress, ApAttachment, ApCollection, ApContext, ApInstrument, ApMention, ApMentionType, ApObject, ApTag, EnigmatickState, Ephemeral,
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
    pub attributed_to: ApAddress,
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub kind: ApNoteType,
    //pub to: Vec<String>,
    pub to: MaybeMultiple<ApAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub published: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<MaybeMultiple<ApAddress>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replies: Option<ApCollection>,
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
    pub conversation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_map: Option<OrdValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument: Option<MaybeMultiple<ApInstrument>>,

    // These are ephemeral attributes to facilitate client operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}

impl ApNote {
    pub fn is_encrypted(&self) -> bool {
        matches!(self.kind, ApNoteType::EncryptedNote)
    }
}

impl Default for ApNote {
    fn default() -> ApNote {
        ApNote {
            context: Some(ApContext::default()),
            tag: None,
            attributed_to: ApAddress::default(),
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

        let tag = params
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

        let mut to: Vec<ApAddress> = vec![];
        let mut cc: Vec<ApAddress> = vec![];

        if params.is_public {
            to.push(
                "https://www.w3.org/ns/activitystreams#Public"
                    .to_string()
                    .into(),
            );
            cc.extend(
                params
                    .clone()
                    .recipients
                    .into_values()
                    .map(ApAddress::Address)
                    .collect::<Vec<ApAddress>>(),
            );
            cc.extend(
                params
                    .clone()
                    .recipient_ids
                    .into_iter()
                    .map(ApAddress::Address)
                    .collect::<Vec<ApAddress>>(),
            );
        } else {
            to.extend(
                params
                    .clone()
                    .recipients
                    .into_values()
                    .map(ApAddress::Address)
                    .collect::<Vec<ApAddress>>(),
            );
            to.extend(
                params
                    .clone()
                    .recipient_ids
                    .into_iter()
                    .map(ApAddress::Address)
                    .collect::<Vec<ApAddress>>(),
            );
        }

        let instrument = {
            if params.is_encrypted {
                let instruments = params.get_instruments();

                if instruments.is_empty() {
                    None
                } else {
                    Some(MaybeMultiple::Multiple(instruments))
                }
            } else {
                None
            }
        };

        ApNote {
            context: Some(ApContext::default()),
            kind: if params.is_encrypted {
                ApNoteType::EncryptedNote
            } else {
                ApNoteType::Note
            },
            to: MaybeMultiple::Multiple(to),
            cc: Some(cc.into()),
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
    #[wasm_bindgen(skip)]
    pub recipients: HashMap<String, String>,

    // https://server/user/username - used for EncryptedNotes where tags
    // are undesirable
    recipient_ids: Vec<String>,
    content: String,
    in_reply_to: Option<String>,
    conversation: Option<String>,
    attachments: Option<String>,

    olm_account: Option<ApInstrument>,
    olm_session: Option<ApInstrument>,
    olm_identity_key: Option<ApInstrument>,
    vault_item: Option<ApInstrument>,

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

    fn set_vault_item(&mut self, instrument: ApInstrument) -> Self {
        self.vault_item = Some(instrument);
        self.clone()
    }

    pub fn set_olm_identity_key(&mut self, instrument: ApInstrument) -> Self {
        self.olm_identity_key = Some(instrument);
        self.clone()
    }

    fn set_olm_session(&mut self, instrument: ApInstrument) -> Self {
        self.olm_session = Some(instrument);
        self.clone()
    }

    pub fn set_olm_account(&mut self, instrument: ApInstrument) -> Self {
        self.olm_account = Some(instrument);
        self.clone()
    }

    fn get_instruments(&self) -> Vec<ApInstrument> {
        let mut instruments = vec![];

        if let Some(olm_account) = self.olm_account.clone() {
            instruments.push(olm_account);
        }

        if let Some(olm_session) = self.olm_session.clone() {
            instruments.push(olm_session);
        }

        if let Some(olm_identity_key) = self.olm_identity_key.clone() {
            instruments.push(olm_identity_key);
        }

        if let Some(vault_item) = self.vault_item.clone() {
            instruments.push(vault_item);
        }

        instruments
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

pub async fn encrypt_note(params: &mut SendParams) -> Result<()> {
    let mut session = if params.conversation.is_some() {
        get_olm_session(params.conversation.clone().unwrap()).await?
    } else {
        create_olm_session(params).await?
    };

    log(&format!("Olm Session\n{session:#?}"));

    params.set_vault_item(params.get_content().clone().try_into()?);
    params.set_content(
        serde_json::to_string(&session.encrypt(params.get_content()))
            .map_err(anyhow::Error::msg)?,
    );
    params.set_olm_session(ApInstrument::try_from(session)?);

    Ok(())
}

#[wasm_bindgen]
pub async fn send_note(params: &mut SendParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        log(&format!("SendParams before encrypt\n{params:#?}"));

        if params.is_encrypted {
            encrypt_note(params).await.unwrap();
        }

        log(&format!("SendParams after encrypt\n{params:#?}"));

        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let id = format!(
            "{}/user/{}",
            state.server_url.unwrap(),
            profile.username.clone()
        );
        let mut note = ApNote::from(params.clone());
        note.attributed_to = id.into();

        log(&format!("NOTE\n{}", serde_json::to_string(&note).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&note).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
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
        encrypted_message.attributed_to = id.into();

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
