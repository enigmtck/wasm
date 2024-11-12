use base64::{engine::general_purpose, engine::Engine as _};
use serde::{Deserialize, Serialize};
use vodozemac::{olm::{Account, Session}, Curve25519PublicKey};
use wasm_bindgen::prelude::wasm_bindgen;
use crate::{encrypt, get_hash};

use crate::{
    authenticated, decrypt, get_actor_from_webfinger, get_key, log, send_get, send_post, ApActor, ApContext, EnigmatickState, MaybeMultiple, Profile
};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum ApSessionType {
    #[default]
    EncryptedSession,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
pub enum ApInstrumentType {
    #[default]
    OlmIdentityKey,
    OlmOneTimeKey,
    OlmSession,
    OlmAccount,
    VaultItem,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct ApInstrument {
    #[serde(rename = "type")]
    pub kind: ApInstrumentType,
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation_of: Option<String>,
}

impl ApInstrument {
    pub fn set_mutation_of(&mut self, mutation_of: String) -> &Self {
        self.mutation_of = Some(mutation_of);
        self
    }
}

impl TryFrom<String> for ApInstrument {
    type Error = anyhow::Error;

    fn try_from(data: String) -> Result<Self, Self::Error> {
        let content = Some(encrypt(None, data).map_err(anyhow::Error::msg)?);

        Ok(
            ApInstrument {
                kind: ApInstrumentType::VaultItem,
                id: None,
                content,
                hash: None,
                uuid: None,
                name: None,
                url: None,
                mutation_of: None
            }
        )
    }
}

impl TryFrom<&Account> for ApInstrument {
    type Error = anyhow::Error;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let key = &*get_key()?;
        let pickle = account.pickle();
        let hash = get_hash(serde_json::to_string(&pickle)?.into_bytes());
        let content = Some(pickle.encrypt(key.try_into()?));
        Ok(
            ApInstrument {
                kind: ApInstrumentType::OlmAccount,
                id: None,
                content,
                hash,
                uuid: None,
                name: None,
                url: None,
                mutation_of: None,
            }
        )
    }
}

impl TryFrom<Session> for ApInstrument {
    type Error = anyhow::Error;

    fn try_from(session: Session) -> Result<Self, Self::Error> {
        let key = &*get_key()?;
        let pickle = session.pickle();
        let hash = get_hash(serde_json::to_string(&pickle)?.into_bytes());
        let content = Some(pickle.encrypt(key.try_into()?));
        Ok(
            ApInstrument {
                kind: ApInstrumentType::OlmSession,
                id: None,
                content,
                hash,
                uuid: None,
                name: None,
                url: None,
                mutation_of: None,
            }
        )
    }
}

type PublicKeyInstrument = (ApInstrumentType, Curve25519PublicKey);
impl From<PublicKeyInstrument> for ApInstrument {
    fn from((instrument_type, key): PublicKeyInstrument) -> Self {
        ApInstrument {
            kind: instrument_type,
            id: None,
            content: Some(key.to_base64()),
            hash: None,
            uuid: None,
            name: None,
            url: None,
            mutation_of: None
        }
    }
}

impl From<OlmSession> for ApInstrument {
    fn from(session: OlmSession) -> Self {
        ApInstrument {
            kind: ApInstrumentType::OlmSession,
            content: Some(session.session_data),
            hash: Some(session.session_hash),
            uuid: Some(session.uuid),
            ..Default::default()
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

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
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
    pub instrument: MaybeMultiple<ApInstrument>,
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
            instrument: MaybeMultiple::Single(ApInstrument {
                kind: ApInstrumentType::OlmIdentityKey,
                content: Some(params.identity_key),
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

    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let url = format!(
            "/api/user/{}/session/{}",
            profile.username.clone(),
            general_purpose::STANDARD.encode(id)
        );

        if let Some(response) = send_get(None, url, "application/json".to_string()).await {
            if let Ok(mut session) = serde_json::from_str::<ApSession>(&response) {
                let mut session_pickle: Option<String> = None;

                // the below is probably unnecessarily complex, but I'm keeping it in case I want
                // to change to passing the whole EncryptedSession to Svelte rather than just the
                // reduced OlmSessionResponse
                let mut modified: Vec<ApInstrument> = vec![];

                match session.instrument {
                    MaybeMultiple::Multiple(instruments) => {
                        for mut instrument in instruments {
                            if instrument.kind == ApInstrumentType::OlmSession {
                                if let Ok(decrypted) =
                                    decrypt(None, instrument.clone().content.unwrap())
                                {
                                    instrument.content = Some(decrypted.clone());
                                    session_pickle = Some(decrypted);
                                }
                            }

                            modified.push(instrument);
                        }
                    }
                    MaybeMultiple::Single(mut instrument) => {
                        if instrument.kind == ApInstrumentType::OlmSession {
                            if let Ok(decrypted) =
                                decrypt(None, instrument.clone().content.unwrap())
                            {
                                instrument.content = Some(decrypted);
                            }
                        }

                        modified.push(instrument);
                    }
                    _ => (),
                };

                session.instrument = MaybeMultiple::Multiple(modified);

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
    })
    .await
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Default)]
pub struct KexInitParams {
    pub recipient: String,
    pub identity_key: String,
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
            if let Some(id) = actor.id {
                self.recipient = id;
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
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let id = format!(
            "{}/user/{}",
            state.server_url.unwrap(),
            profile.username.clone()
        );
        let mut encrypted_session = ApSession::from(params);
        encrypted_session.attributed_to = id;

        send_post(
            outbox,
            serde_json::to_string(&encrypted_session).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
    .is_some()
}

#[wasm_bindgen]
pub async fn get_sessions() -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let url = format!("/api/user/{}/sessions", profile.username.clone());

        send_get(None, url, "application/json".to_string()).await
    })
    .await
}
