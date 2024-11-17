use crate::{
    authenticated, decrypt, error, get_state, log, send_get, ActivityPub, ApActivity, ApCreate,
    ApInstrument, ApNote, ApObject, EnigmatickState, MaybeReference, Profile,
};
use gloo_net::http::Request;
use serde_wasm_bindgen;
use urlencoding::encode;
use vodozemac::{olm::{Account, AccountPickle, OlmMessage}, Curve25519PublicKey};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

pub fn convert_hashtags_to_query_string(hashtags: &[String]) -> String {
    hashtags
        .iter()
        .map(|tag| format!("&hashtags[]={}", encode(tag)))
        .collect::<Vec<String>>()
        .join("")
}

#[wasm_bindgen]
pub async fn get_timeline(
    max: Option<String>,
    min: Option<String>,
    limit: i32,
    view: String,
    hashtags: JsValue,
) -> Option<String> {
    let state = get_state();

    let hashtags: Vec<String> = serde_wasm_bindgen::from_value(hashtags).unwrap_or_default();
    let hashtags = convert_hashtags_to_query_string(&hashtags);
    log(&hashtags);

    let position = {
        if let Some(max) = max {
            format!("&max={max}")
        } else if let Some(min) = min {
            format!("&min={min}")
        } else {
            String::new()
        }
    };

    fn is_encrypted_note(item: &ActivityPub) -> Option<(ApCreate, ApNote)> {
        match item {
            ActivityPub::Activity(ApActivity::Create(create)) => match &create.object {
                MaybeReference::Actual(ApObject::Note(note)) if note.is_encrypted() => {
                    Some((create.clone(), note.clone()))
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn find_vault_instrument(create: &ApCreate) -> Option<ApInstrument> {
        create
            .instrument
            .clone()
            .map(|instruments| instruments.multiple())
            .unwrap_or_default()
            .into_iter()
            .find(|instrument| instrument.is_vault_item() && instrument.content.is_some())
    }

    fn find_identity_key_instrument(create: &ApCreate) -> Option<ApInstrument> {
        create
            .instrument
            .clone()
            .map(|instruments| instruments.multiple())
            .unwrap_or_default()
            .into_iter()
            .find(|instrument| instrument.is_olm_identity_key() && instrument.content.is_some())
    }

    fn decrypt_instrument_content(instrument: &ApInstrument) -> Option<String> {
        instrument
            .content
            .clone()
            .and_then(|content| decrypt(None, content).ok())
    }

    fn create_session(idk: ApInstrument, note: &ApNote) -> Option<(String, String)> {
        let state = get_state();
        if let Some(pickled_account) = state.get_olm_pickled_account() {
            let pickled_account = serde_json::from_str::<AccountPickle>(&pickled_account)
                .map_err(anyhow::Error::msg).ok()?;

            let mut account = Account::from(pickled_account);
            let identity_key = Curve25519PublicKey::from_base64(&idk.content.unwrap()).ok()?;

            if let OlmMessage::PreKey(m) = serde_json::from_str(&note.content).ok()? {
                let inbound = account.create_inbound_session(identity_key, &m).ok()?;

                let session = serde_json::to_string(&inbound.session.pickle()).ok()?;
                let message = String::from_utf8(inbound.plaintext).ok()?;

                Some((session, message))
            } else {
                None
            }
        } else {
            None
        }
    }

    fn build_activity(create: ApCreate, note: ApNote) -> ActivityPub {
        ActivityPub::Activity(ApActivity::Create(ApCreate {
            object: ApObject::Note(note).into(),
            ..create.clone()
        }))
    }

    fn transform_encrypted_activity(create: ApCreate, mut note: ApNote) -> Option<ActivityPub> {
        find_vault_instrument(&create)
            .and_then(|instrument| {
                decrypt_instrument_content(&instrument).map(|decrypted| {
                    note.content = decrypted;
                    build_activity(create.clone(), note.clone())
                })
            })
            .or_else(|| {
                find_identity_key_instrument(&create).and_then(|instrument| {
                    create_session(instrument, &note).map(|(session, message)| {
                        note.content = message;
                        build_activity(create.clone(), note.clone())
                    })
                })
            })
    }

    if state.authenticated {
        authenticated(move |_: EnigmatickState, profile: Profile| async move {
            let username = profile.username;
            let url =
                format!("/user/{username}/inbox?limit={limit}{position}&view={view}{hashtags}");

            let text = send_get(None, url, "application/activity+json".to_string()).await?;
            if let ApObject::CollectionPage(mut object) = serde_json::from_str(&text).ok()? {
                let items = object.clone().ordered_items?;
                object.ordered_items = Some(
                    items
                        .iter()
                        .filter_map(|item| {
                            is_encrypted_note(item)
                                .and_then(|(create, note)| {
                                    transform_encrypted_activity(create, note)
                                })
                                .or_else(|| Some(item.clone()))
                        })
                        .collect(),
                );
                serde_json::to_string(&object).ok()
            } else {
                error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
                None
            }
        })
        .await
    } else {
        let resp = Request::get(&format!(
            "/inbox?limit={limit}{position}&view=global{hashtags}"
        ))
        .header("Content-Type", "application/activity+json")
        .send()
        .await
        .ok()?;

        let text = resp.text().await.ok()?;
        log(&text);
        if let ApObject::CollectionPage(object) = serde_json::from_str(&text).ok()? {
            //object.ordered_items.map(|items| serde_json::to_string(&items).unwrap())
            serde_json::to_string(&object).ok()
        } else {
            error(&format!("FAILED TO CONVERT TEXT TO COLLECTION\n{text:#}"));
            None
        }
    }
}

#[wasm_bindgen]
pub async fn get_conversation(conversation: String, limit: i32) -> Option<String> {
    authenticated(
        move |_state: EnigmatickState, _profile: Profile| async move {
            let conversation = urlencoding::encode(&conversation).to_string();
            let inbox = format!("/api/conversation?id={conversation}&limit={limit}");

            send_get(None, inbox, "application/activity+json".to_string()).await
        },
    )
    .await
}
