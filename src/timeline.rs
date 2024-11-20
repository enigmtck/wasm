use crate::{
    authenticated, decrypt, error, get_hash, get_olm_account, get_state, log, send_get, send_post, ActivityPub, ApActivity, ApCollection, ApCreate, ApInstrument, ApNote, ApObject, EnigmatickState, Ephemeral, MaybeReference, Profile
};
use gloo_net::http::Request;
use serde_json::json;
use serde_wasm_bindgen;
use urlencoding::encode;
use vodozemac::{
    olm::{Account, AccountPickle, OlmMessage},
    Curve25519PublicKey,
};
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
    let mut instruments_to_update: Vec<ApInstrument> = vec![];

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

    fn create_session(
        account: &mut Account,
        idk: ApInstrument,
        create: ApCreate,
        note: &ApNote,
    ) -> Option<(Vec<ApInstrument>, String)> {
        let identity_key = Curve25519PublicKey::from_base64(&idk.content.unwrap()).ok()?;

        if let OlmMessage::PreKey(m) = serde_json::from_str(&note.content).ok()? {
            let inbound = account.create_inbound_session(identity_key, &m).ok()?;

            let message = String::from_utf8(inbound.plaintext).ok()?;

            let mut session_instrument = ApInstrument::try_from(inbound.session).ok()?;
            session_instrument.conversation = note.conversation.clone();

            let mut vault_instrument = ApInstrument::try_from(message.clone()).ok()?;
            vault_instrument.activity = create.id;

            Some((vec![session_instrument, vault_instrument], message))
        } else {
            None
        }
    }

    async fn update_instruments(instruments: Vec<ApInstrument>) {
        let state = get_state();

        let collection = ApCollection::from(instruments);

        if state.authenticated {
            authenticated(move |_: EnigmatickState, _profile: Profile| async move {
                let url = format!("/api/instruments");

                let body = json!(collection);
                send_post(
                    url,
                    body.to_string(),
                    "application/activity+json".to_string(),
                )
                .await
            })
            .await;
        }
    }

    fn build_activity(create: ApCreate, note: ApNote) -> ActivityPub {
        ActivityPub::Activity(ApActivity::Create(ApCreate {
            object: ApObject::Note(note).into(),
            ..create.clone()
        }))
    }

    fn transform_encrypted_activity(
        account: &mut Account,
        mut create: ApCreate,
        mut note: ApNote,
    ) -> Option<ActivityPub> {
        find_vault_instrument(&create)
            .and_then(|instrument| {
                decrypt_instrument_content(&instrument).map(|decrypted| {
                    note.content = decrypted;
                    build_activity(create.clone(), note.clone())
                })
            })
            .or_else(|| {
                find_identity_key_instrument(&create).and_then(|instrument| {
                    create_session(account, instrument, create.clone(), &note).map(
                        |(instruments, message)| {
                            create.ephemeral = Some(Ephemeral {
                                instruments_to_update: Some(instruments),
                                ..Default::default()
                            });

                            note.content = message;
                            build_activity(create.clone(), note.clone())
                        },
                    )
                })
            })
    }

    if state.authenticated {
        authenticated(move |_state: EnigmatickState, profile: Profile| async move {
            let username = profile.username;
            let url =
                format!("/user/{username}/inbox?limit={limit}{position}&view={view}{hashtags}");

            let text = send_get(None, url, "application/activity+json".to_string()).await?;

            if let Some(olm_account) = get_olm_account().await {
            //if let Some(pickled_account) = state.get_olm_pickled_account() {
                //let mutation_of = get_hash(pickled_account.clone().into_bytes())?;
                let mutation_of = olm_account.hash?;
                log(&format!(
                    "Olm Pickled Account Hash (before mutation): {}",
                    mutation_of
                ));

                // let pickled_account = serde_json::from_str::<AccountPickle>(&pickled_account)
                //     .map_err(anyhow::Error::msg)
                //     .ok()?;

                let pickled_account = serde_json::from_str::<AccountPickle>(&decrypt(None, olm_account.content?).ok()?)
                    .map_err(anyhow::Error::msg)
                    .ok()?;

                let mut account = Account::from(pickled_account);

                if let ApObject::CollectionPage(mut object) = serde_json::from_str(&text).ok()? {
                    let items = object.clone().ordered_items?;
                    let mut decrypted_items: Vec<ActivityPub> = items
                        .iter()
                        .filter_map(|item| {
                            is_encrypted_note(item)
                                .and_then(|(create, note)| {
                                    transform_encrypted_activity(&mut account, create, note)
                                })
                                .or_else(|| Some(item.clone()))
                        })
                        .collect();

                    for item in &mut decrypted_items {
                        if let ActivityPub::Activity(ApActivity::Create(ref mut create)) = item {
                            if let Some(mut ephemeral) = create.ephemeral.take() {
                                if let Some(instruments) = ephemeral.instruments_to_update.take() {
                                    update_instruments(instruments).await;
                                }
                            }
                        }
                    }

                    let mut account_instrument = ApInstrument::try_from(&account).ok()?;
                    log(&format!(
                        "Olm Pickled Account Hash (post mutation): {}",
                        account_instrument.hash.clone().unwrap_or_default()
                    ));

                    if account_instrument.hash != Some(mutation_of.clone()) {
                        account_instrument.set_mutation_of(mutation_of);
                        update_instruments(vec![account_instrument]).await;
                    }

                    object.ordered_items = Some(decrypted_items);

                    serde_json::to_string(&object).ok()
                } else {
                    None
                }
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
