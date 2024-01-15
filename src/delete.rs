use std::fmt::{self, Debug};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, get_state, log, send_post, ApContext,
    EnigmatickState, Profile, MaybeReference, MaybeMultiple, ApAddress, ApObject, ApSignature,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApDeleteType {
    #[default]
    Delete,
}

impl fmt::Display for ApDeleteType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApDelete {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApDeleteType,
    pub actor: String,
    pub id: Option<String>,
    pub object: MaybeReference<ApObject>,
    pub signature: Option<ApSignature>,
    pub to: MaybeMultiple<ApAddress>,
}

impl ApDelete {
    pub async fn new(object: String) -> Self {
        let state = get_state();
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            ApDelete {
                context: None,
                kind: ApDeleteType::default(),
                actor: format!("{server_url}/user/{}",
                               profile.username),
                id: None,
                object: MaybeReference::Reference(object),
                to: MaybeMultiple::Multiple(vec![ApAddress::get_public()]),
                signature: None
            }
        } else {
            ApDelete::default()
        }
    }
}

#[wasm_bindgen]
pub async fn send_delete(object: String) -> bool {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox",
                             profile.username.clone());
        
        let delete = ApDelete::new(object).await;

        log(&format!("DELETE\n{delete:#?}"));
        send_post(outbox,
                  serde_json::to_string(&delete).unwrap(),
                  "application/activity+json".to_string()).await
        //Some("".to_string())
    }).await.is_some()
}
