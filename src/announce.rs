use std::fmt::{self, Debug};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, get_state, log, send_post, ApContext,
    EnigmatickState, Profile, MaybeMultiple, ApAddress, ApUndo,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApAnnounceType {
    #[default]
    Announce,
}

impl fmt::Display for ApAnnounceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApAnnounce {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApAnnounceType,
    pub actor: String,
    pub to: MaybeMultiple<ApAddress>,
    pub cc: Option<MaybeMultiple<ApAddress>>,
    pub id: Option<String>,
    pub object: String,
}

impl ApAnnounce {
    pub async fn new(object: String, id: Option<String>) -> Option<Self> {
        let state = get_state().await;
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            Some(ApAnnounce {
                context: None,
                kind: ApAnnounceType::default(),
                actor: format!("{server_url}/user/{}",
                               profile.username),
                id,
                object,
                to: MaybeMultiple::Multiple(vec![ApAddress::get_public()]),
                cc: None,
            })
        } else {
            None
        }
    }
}

#[wasm_bindgen]
pub async fn send_announce(object: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let announce = ApAnnounce::new(object, None).await;

        log(&format!("ANNOUNCE\n{announce:#?}"));
        send_post(outbox,
                  serde_json::to_string(&announce).unwrap(),
                  "application/activity+json".to_string()).await
    }).await
}

#[wasm_bindgen]
pub async fn send_unannounce(object: String, id: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());

        if let Some(announce) = ApAnnounce::new(object, Some(id)).await {
            let undo: ApUndo = announce.into();

            log(&format!("UNANNOUNCE\n{undo:#?}"));
            send_post(outbox,
                      serde_json::to_string(&undo).unwrap(),
                      "application/activity+json".to_string()).await
        } else {
            None
        }
    }).await
}
