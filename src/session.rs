use base64::encode;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{log, authenticated, EnigmatickState, Profile, send_get, decrypt, send_post, ApContext, get_actor_from_webfinger, ApActor};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApSessionType {
    #[default]
    EncryptedSession,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub enum ApInstrumentType {
    #[default]
    IdentityKey,
    SessionKey,
    OlmSession,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ApInstrument {
    #[serde(rename = "type")]
    pub kind: ApInstrumentType,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

impl From<OlmSession> for ApInstrument {
    fn from(session: OlmSession) -> Self {
        ApInstrument {
            kind: ApInstrumentType::OlmSession,
            content: session.session_data,
            hash: Some(session.session_hash),
            uuid: Some(session.uuid)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApInstruments {
    Multiple(Vec<ApInstrument>),
    Single(ApInstrument),
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApSession {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApSessionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub to: String,
    pub attributed_to: String,
    pub instrument: ApInstruments,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub uuid: Option<String>,
}

impl From<KexInitParams> for ApSession {
    fn from(params: KexInitParams) -> Self {
        ApSession {
            context: Some(ApContext::default()),
            kind: ApSessionType::EncryptedSession,
            to: params.recipient,
            instrument: ApInstruments::Single(ApInstrument {
                kind: ApInstrumentType::IdentityKey,
                content: params.identity_key,
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Deserialize)]
pub struct OlmSession {
    pub created_at: String,
    pub updated_at: String,
    pub uuid: String,
    pub session_data: String,
    pub session_hash: String,
    pub encrypted_session_id: i32,
}

// expose encrypted_session_id to pass along to Svelte
#[derive(Serialize)]
pub struct OlmSessionResponse {
    pub session_pickle: String,
    pub uuid: String,
}

#[wasm_bindgen]
pub async fn get_session(id: String) -> Option<String> {
    log("IN get_session");

    authenticated(move |_state: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/session/{}",
                          profile.username.clone(),
                          encode(id));

        if let Some(response) = send_get(url,
                                         "application/json".to_string()).await {
            
            if let Ok(mut session) = serde_json::from_str::<ApSession>(&response) {
                let mut session_pickle: Option<String> = None;

                // the below is probably unnecessarily complex, but I'm keeping it in case I want
                // to change to passing the whole EncryptedSession to Svelte rather than just the
                // reduced OlmSessionResponse
                let mut modified: Vec<ApInstrument> = vec![];
                
                match session.instrument {
                    ApInstruments::Multiple(instruments) => {
                        for mut instrument in instruments {
                            if instrument.kind == ApInstrumentType::OlmSession {
                                if let Some(decrypted) = decrypt(instrument.clone().content) {
                                    instrument.content = decrypted.clone();
                                    session_pickle = Some(decrypted);
                                }
                            }

                            modified.push(instrument);
                        };
                    },
                    ApInstruments::Single(mut instrument) => {
                        if instrument.kind == ApInstrumentType::OlmSession {
                                if let Some(decrypted) = decrypt(instrument.clone().content) {
                                    instrument.content = decrypted;
                                }
                            }

                        modified.push(instrument);
                    },
                    _ => ()
                };

                session.instrument = ApInstruments::Multiple(modified);
                
                if let (Some(session_pickle), Some(uuid)) = (session_pickle, session.uuid) {
                    let response = OlmSessionResponse {
                        session_pickle,
                        uuid,
                    };

                    if let Ok(response) = serde_json::to_string(&response) {
                        Some(response)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }).await
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Default)]
pub struct KexInitParams {
    pub recipient: String,
    pub identity_key: String
}

#[wasm_bindgen]
impl KexInitParams {
    pub fn new() -> KexInitParams {
        KexInitParams::default()
    }

    pub fn set_recipient_id(&mut self, id: String) -> Self {
        self.recipient = id;
        self.clone()
    }
    
    pub async fn set_recipient_webfinger(&mut self, address: String) -> Self {
        if let Some(actor) = get_actor_from_webfinger(address).await {
            if let Ok(actor) = serde_json::from_str::<ApActor>(&actor) {
                if let Some(id) = actor.id {
                    self.recipient = id;
                }
            }
        }
        self.clone()
    }

    pub fn set_identity_key(&mut self, key: String) -> Self {
        self.identity_key = key;
        self.clone()
    }
}

#[wasm_bindgen]
pub async fn send_kex_init(params: KexInitParams) -> bool {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let id = format!("{}/user/{}",
                         state.server_url.unwrap(),
                         profile.username.clone());
        let mut encrypted_session = ApSession::from(params);
        encrypted_session.attributed_to = id;

        send_post(outbox,
                  serde_json::to_string(&encrypted_session).unwrap(),
                  "application/activity+json".to_string()).await
    }).await.is_some()
}

#[wasm_bindgen]
pub async fn get_sessions() -> Option<String> {
    authenticated(move |_state: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/sessions",
                             profile.username.clone());
        
        send_get(url, "application/json".to_string()).await
    }).await
}
