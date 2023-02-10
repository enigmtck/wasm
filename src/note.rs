use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, log, send_post, get_webfinger, send_updated_olm_sessions, ApContext, ApTag, ApObjectType, ApFlexible, ApAttachment, ApMention, ApTagType, get_actor, ApActor, get_webfinger_from_id};

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
    pub kind: ApObjectType,
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

    // These are ephemeral attributes to facilitate client operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_announce: Option<String>,
}

impl From<SendParams> for ApNote {
    fn from(params: SendParams) -> Self {
        log(&format!("params\n{params:#?}"));
        
        let tag = Option::from(params.recipients.iter().map(|(x, y)| ApTag::Mention ( ApMention { kind: ApTagType::Mention, name: x.to_string(), href: y.to_string()})).collect::<Vec<ApTag>>());

        log("after tag");
        
        let mut to: Vec<String> = vec![];
        let mut cc: Vec<String> = vec![];

        log("after recipients");
        
        if params.is_public {
            to.push("https://www.w3.org/ns/activitystreams#Public".to_string());
            cc.extend(params.recipients.into_values().collect::<Vec<String>>());
            cc.extend(params.recipient_ids);
        } else {
            to.extend(params.recipients.into_values().collect::<Vec<String>>());
            to.extend(params.recipient_ids);
        }

        log("after push");
        
        ApNote {
            context: Option::from(ApContext::default()),
            kind: params.kind.parse().unwrap(),
            to,
            cc: Option::from(cc),
            tag,
            content: params.content,
            in_reply_to: params.in_reply_to,
            conversation: params.conversation,
            ..Default::default()
        }
    }
}

#[wasm_bindgen]
pub async fn get_note(id: String) -> Option<String> {
    log("in get_note: {id:#?}");
    
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        log("in authenticated");
        
        #[derive(Debug, Clone, Default, Serialize)]
        pub struct NoteParams {
            id: String,
        }
        
        let url = format!("/api/user/{}/remote/note",
                          profile.username.clone());

        log(&format!("{url:#?}"));
        
        let params = NoteParams {
            id
        };

        log(&format!("{params:#?}"));
        
        send_post(url,
                  serde_json::to_string(&params).unwrap(),
                  "application/json".to_string()).await
    }).await 
}

#[wasm_bindgen]
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendParams {
    // @name@example.com -> https://example.com/user/name
    #[wasm_bindgen(skip)]
    pub recipients: HashMap<String, String>,

    // https://server/user/username - used for EncryptedNotes where tags
    // are undesirable
    #[wasm_bindgen(skip)]
    pub recipient_ids: Vec<String>,
    #[wasm_bindgen(skip)]
    pub content: String,
    #[wasm_bindgen(skip)]
    pub kind: String,
    #[wasm_bindgen(skip)]
    pub in_reply_to: Option<String>,
    #[wasm_bindgen(skip)]
    pub conversation: Option<String>,
    pub is_public: bool
}

#[wasm_bindgen]
impl SendParams {
    pub fn new() -> SendParams {
        SendParams::default()
    }

    pub fn set_kind(&mut self, kind: String) -> Self {
        self.kind = kind;
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
        log("in send_encrypted_note");
        
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());

        log("after outbox");
        
        let id = format!("{}/user/{}",
                         state.server_url.unwrap(),
                         profile.username.clone());

        log("after id");
        
        let mut encrypted_message = ApNote::from(params);
        encrypted_message.attributed_to = id;

        log("after encrypted_message");
        
        if send_post(outbox,
                     serde_json::to_string(&encrypted_message).unwrap(),
                     "application/activity+json".to_string()).await.is_some() {
            if send_updated_olm_sessions().await {
                Option::from("{\"success\":true}".to_string())
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    }).await.is_some()
}
