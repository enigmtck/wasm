use std::{collections::HashMap, fmt::{self, Debug}};

use serde::{Serialize, Deserialize};
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, log, send_post, get_webfinger, ApContext, ApTag, ApFlexible, ApAttachment, ApMention, get_webfinger_from_id, encrypt, ApAttachmentType, get_hash, get_state, ApMentionType, resolve_processed_item, ApInstruments, ApInstrument, ApInstrumentType, ApActor};

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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
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
    pub to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
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
    pub ephemeral_announce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_actors: Option<Vec<ApActor>>,
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

        let attachment: Vec<ApAttachment> = vec![];
        
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
            to,
            cc: Option::from(cc),
            tag: Option::from(tag),
            attachment: attachment.into(),
            content: params.content,
            in_reply_to: params.in_reply_to,
            conversation: params.conversation,
            instrument,
            ..Default::default()
        }
    }
}

#[wasm_bindgen]
pub async fn get_note(id: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        #[derive(Debug, Clone, Default, Serialize)]
        pub struct NoteParams {
            id: String,
        }
        
        let url = format!("/api/user/{}/remote/note",
                          profile.username.clone());
        
        let params = NoteParams {
            id
        };
        
        send_post(url,
                  serde_json::to_string(&params).unwrap(),
                  "application/json".to_string()).await
    }).await 
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
        let state = get_state().await;
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
        self.recipients.insert(address.clone(), get_webfinger(address).await.unwrap_or_default());
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
        self.session_hash = get_hash(session_data.clone());
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
