#![allow(non_upper_case_globals)]

use std::collections::HashMap;

use crate::{
    add_one_time_keys, authenticated, get_hash, get_state, log, send_get, EnigmatickState,
    OtkUpdateParams, Profile,
};
use jdt_activity_pub::ApCollection;
use serde::{Deserialize, Serialize};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::{Curve25519PublicKey, KeyId};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn create_olm_account() -> String {
    let account = Account::new();
    serde_json::to_string(&account.pickle()).unwrap()
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize)]
pub struct MessageResponse {
    pub remote_actor: String,
    pub message: String,
    pub session: String,
}

#[wasm_bindgen]
pub fn create_olm_message(
    ap_id: String,
    message: String,
    pickled_account: String,
    identity_key: Option<String>,
    one_time_key: Option<String>,
    olm_session: Option<String>,
) -> Option<MessageResponse> {
    log(&format!(
        "in create_olm_message state\nchecking for\n{:#?}",
        ap_id
    ));
    if let Some(session) = olm_session {
        let pickle: SessionPickle = serde_json::from_str::<SessionPickle>(&session).ok()?;

        let mut session = Session::from_pickle(pickle);
        let message = serde_json::to_string(&session.encrypt(message)).ok()?;
        let remote_actor = ap_id;
        let session = serde_json::to_string(&session.pickle()).ok()?;
        Some(MessageResponse {
            remote_actor,
            message,
            session,
        })
    } else if let (Some(identity_key), Some(one_time_key)) = (identity_key, one_time_key) {
        // if there's no pre-existing session and keys are submitted, create a new session
        let one_time_key = Curve25519PublicKey::from_base64(&one_time_key).ok()?;
        let identity_key = Curve25519PublicKey::from_base64(&identity_key).ok()?;
        let pickled_account = serde_json::from_str::<AccountPickle>(&pickled_account).ok()?;

        let account = Account::from(pickled_account);

        let mut outbound =
            account.create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key);

        let message = serde_json::to_string(&outbound.encrypt(message)).ok()?;

        log(&format!(
            "OLM SESSION PICKLE: {:#?}",
            serde_json::to_string(&outbound.pickle()).ok()?
        ));
        let remote_actor = ap_id;
        let session = serde_json::to_string(&outbound.pickle()).ok()?;

        Some(MessageResponse {
            remote_actor,
            message,
            session,
        })
    } else {
        None
    }
}

#[wasm_bindgen]
pub fn decrypt_olm_message(
    ap_id: String,
    message: String,
    pickled_account: String,
    identity_key: String,
    olm_session: Option<String>,
) -> Option<MessageResponse> {
    let identity_key = Curve25519PublicKey::from_base64(&identity_key).ok()?;

    let mut account = Account::from(serde_json::from_str::<AccountPickle>(&pickled_account).ok()?);

    if let Some(session) = olm_session {
        let pickle: SessionPickle = serde_json::from_str::<SessionPickle>(&session).ok()?;

        let mut session = Session::from_pickle(pickle);

        if let OlmMessage::Normal(m) = serde_json::from_str(&message).ok()? {
            let bytes = session.decrypt(&m.into()).ok()?;
            let message = String::from_utf8(bytes).ok()?;
            let remote_actor = ap_id;
            let session = serde_json::to_string(&session.pickle()).ok()?;
            Some(MessageResponse {
                remote_actor,
                message,
                session,
            })
        } else {
            None
        }
    } else if let OlmMessage::PreKey(m) = serde_json::from_str(&message).ok()? {
        let inbound = account.create_inbound_session(identity_key, &m).ok()?;

        let session = serde_json::to_string(&inbound.session.pickle()).ok()?;
        let remote_actor = ap_id;
        let message = String::from_utf8(inbound.plaintext).ok()?;

        Some(MessageResponse {
            remote_actor,
            message,
            session,
        })
    } else {
        None
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize)]
pub struct AccountResponse {
    pub one_time_keys: String,
    pub updated_pickled_account: String,
    pub original_account: String,
}

pub fn get_one_time_keys(keys: usize) -> Option<OtkUpdateParams> {
    let state = get_state();

    log("AFTER STATE");
    let original_pickled_account = state.get_olm_pickled_account()?;
    log("AFTER original_pickled_account");

    let original_pickled_account_hash = get_hash(original_pickled_account.clone().into_bytes())?;

    log("AFTER original_pickled_account_hash");
    let mut account =
        Account::from(serde_json::from_str::<AccountPickle>(&original_pickled_account).ok()?);

    log("AFTER account");
    account.generate_one_time_keys(keys);

    log("AFTER generate");

    let b64map: HashMap<KeyId, String> = account
        .one_time_keys()
        .into_iter()
        .map(|(k, v)| (k, v.to_base64()))
        .collect();

    log("AFTER hashmap");
    account.mark_keys_as_published();

    log("AFTER published");
    let updated_pickled_account = serde_json::to_string(&account.pickle()).ok()?;

    log("AFTER updated_pickled_account");
    let mut params = OtkUpdateParams::new();
    params.set_account(updated_pickled_account);
    params.set_mutation(original_pickled_account_hash);
    params.set_keys(serde_json::to_string(&b64map).ok()?);

    Some(params)
}

#[wasm_bindgen]
pub fn get_identity_public_key(pickled_account: String) -> String {
    let account = Account::from(serde_json::from_str::<AccountPickle>(&pickled_account).unwrap());
    account.curve25519_key().to_base64()
}

pub async fn get_otk_collection() -> Option<ApCollection> {
    let response = authenticated(move |_: EnigmatickState, profile: Profile| async move {
        let username = profile.username;
        let path = format!("/user/{username}/keys");

        send_get(None, path, "application/activity+json".to_string()).await
    })
    .await;

    response.and_then(|x| serde_json::from_str(&x).ok())
}

#[wasm_bindgen]
pub async fn replenish_otk() -> Option<bool> {
    let otk_collection = get_otk_collection().await?;

    log(&format!("{otk_collection:#?}"));

    if otk_collection.total_items? < 20 {
        add_one_time_keys(get_one_time_keys(10)?).await;
    }

    Some(true)
}
