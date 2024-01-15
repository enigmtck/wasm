use std::{collections::HashMap, fmt::{self, Debug}};

use chrono::{DateTime, Utc};
use gloo_net::http::Request;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, log, send_post, send_get, ApContext, ApTag, ApFlexible, ApAttachment, ApMention, get_webfinger_from_id, encrypt, get_hash, get_state, ApMentionType, resolve_processed_item, ApInstruments, ApInstrument, ApInstrumentType, ApActor, MaybeMultiple, ApAddress, ApObject, error};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
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

#[derive(Serialize, Deserialize, Clone, Debug)]
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
    pub content_map: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument: Option<ApInstruments>,

    // These are ephemeral attributes to facilitate client operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_announces: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_actors: Option<Vec<ApActor>>,

    // The result of a join with the "likes" table to indicate that a
    // user has liked this post - should contain the UUID of the record
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_liked: Option<String>,

    // The result of a join with the "announces" table to indicate that a
    // user has announced this post - should contain the UUID of the record
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_announced: Option<String>,

    // The result of a join with the "timeline_cc" table to indicate that
    // a user was copied directly
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_targeted: Option<bool>,

    // This is here because "published" is unreliable; it may or
    // may not exist and may or may not match the ordering of data
    // pulled from the database based on "created_at". A mismatch
    // causes jittery rendering; exposing "created_at" here allows
    // the UI to order consistently with the database and improves UX.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_timestamp: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_metadata: Option<Vec<Metadata>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_likes: Option<Vec<String>>,
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
            ephemeral_announces: None,
            ephemeral_announced: None,
            ephemeral_actors: None,
            ephemeral_liked: None,
            ephemeral_likes: None,
            ephemeral_targeted: None,
            ephemeral_timestamp: None,
            ephemeral_metadata: None,
        }
    }
}

impl From<SendParams> for ApNote {
    fn from(params: SendParams) -> Self {
        log(&format!("params\n{params:#?}"));
        
        let mut tag = params.recipients.iter().map(|(x, y)| ApTag::Mention ( ApMention { kind: ApMentionType::Mention, name: x.to_string(), href: Some(y.to_string()), value: None})).collect::<Vec<ApTag>>();

        if let Some(idk) = params.identity_key {
            tag.push(ApTag::Mention (ApMention { kind: ApMentionType::Mention, name: params.attributed_to, href: None, value: Some(idk) }));
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
        
        let mut instrument: Option<ApInstruments> = Option::None;
        if let (Some(session), Some(hash)) = (params.session_data, params.session_hash) {
            instrument = Some(ApInstruments::Single(ApInstrument {
                kind: ApInstrumentType::OlmSession,
                content: session,
                hash: hash.into(),
                uuid: params.session_uuid,
            }))
        }
        
        ApNote {
            context: Option::from(ApContext::default()),
            kind: { if params.is_encrypted { ApNoteType::EncryptedNote } else { ApNoteType::Note } },
            to: MaybeMultiple::Multiple(to.iter().map(|x| ApAddress::Address(x.clone())).collect()),
            cc: Option::from(cc),
            tag: Option::from(tag),
            attachment: {
                if let Some(attachments) = params.attachments {
                    if let Ok(attachments) = serde_json::from_str::<Vec<ApAttachment>>(&attachments) {
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
    if let Ok(resp) = Request::get(&format!("/conversation/{uuid}"))
        .header("Content-Type", "application/activity+json")
        .send().await
    {
        if let Ok(text) = resp.text().await {
            if let Ok(ApObject::Collection(object)) = serde_json::from_str(&text) {
                if let Some(items) = object.items {
                    Option::from(serde_json::to_string(&items).unwrap())
                } else {
                    None
                }
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        } else {
            error("FAILED TO DECODE RESPONSE TO TEXT");
            None
        }
    } else {
        error("FAILED TO SEND REQUEST");
        None
    }
}

#[wasm_bindgen]
pub async fn get_note(id: String) -> Option<String> {
    let path = format!("/api/remote/note?id={}", urlencoding::encode(&id));
    
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
                attributed_to: format!("{server_url}/user/{}",
                                       profile.username),
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
        self.recipients.insert(address.clone(), get_webfinger_from_id(address).await.unwrap_or_default());
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
        self.session_data = encrypt(session_data);
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

#[wasm_bindgen]
pub async fn send_note(params: SendParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let id = format!("{}/user/{}",
                         state.server_url.unwrap(),
                         profile.username.clone());
        let mut note = ApNote::from(params);
        note.attributed_to = id;

        log(&format!("NOTE\n{note:#?}"));
        send_post(outbox,
                  serde_json::to_string(&note).unwrap(),
                  "application/activity+json".to_string()).await
        //Some("".to_string())
    }).await.is_some()
}

#[wasm_bindgen]
pub async fn send_encrypted_note(params: SendParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        log("IN send_encrypted_note");
        
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let id = format!("{}/user/{}",
                         state.server_url.unwrap(),
                         profile.username.clone());
        
        let mut encrypted_message = ApNote::from(params.clone());
        encrypted_message.attributed_to = id;
        
        if send_post(outbox,
                     serde_json::to_string(&encrypted_message).unwrap(),
                     "application/activity+json".to_string()).await.is_some() {
            if let Some(resolves) = params.clone().resolves {
                resolve_processed_item(resolves).await
            } else {
                None
            }
        } else {
            None
        }
    }).await.is_some()
}
