use std::collections::HashMap;

use crate::{
    authenticated, decrypt, get_object, get_state, log, retrieve_credentials, send_get, send_post,
    EnigmatickState, Profile, ENCRYPT_FN,
};
use anyhow::{anyhow, Result};
use base64::engine::{general_purpose, Engine as _};
use jdt_activity_pub::{
    ActivityPub, ApActivity, ApCollection, ApCreate, ApInstrument, ApNote, ApObject, Collectible,
};
use jdt_maybe_reference::MaybeReference;
use openmls::{
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    prelude::{
        tls_codec::Deserialize, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
        ProcessedMessageContent, ProtocolMessage, Welcome,
    },
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::json;
use serde_wasm_bindgen;
use urlencoding::encode;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
use wasm_bindgen_futures::spawn_local;

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
    log("IN get_timeline");
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
            .multiple()
            .into_iter()
            .find(|instrument| instrument.is_vault_item() && instrument.content.is_some())
    }

    fn find_welcome_instrument(create: &ApCreate) -> Option<ApInstrument> {
        create
            .instrument
            .multiple()
            .into_iter()
            .find(|instrument| instrument.is_mls_welcome() && instrument.content.is_some())
    }

    fn find_group_instrument(create: &ApCreate) -> Option<ApInstrument> {
        create
            .instrument
            .multiple()
            .into_iter()
            .find(|instrument| instrument.is_mls_group_id() && instrument.content.is_some())
    }

    fn decrypt_instrument_content(instrument: &ApInstrument) -> Option<String> {
        instrument
            .content
            .clone()
            .and_then(|content| decrypt(None, content).ok())
    }

    fn create_group(
        provider: &mut OpenMlsRustCrypto,
        welcome: Welcome,
        create: ApCreate,
        note: ApNote,
        groups: &mut HashMap<String, GroupId>,
    ) -> Result<Vec<ApInstrument>> {
        let mut instruments = vec![];

        log(&format!("Setting up GroupJoinConfig"));
        let group_join_config_builder =
            MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true);
        let group_join_config = group_join_config_builder.build();

        log(&format!("Setting up StagedJoin"));
        let staged_join =
            StagedWelcome::new_from_welcome(provider, &group_join_config, welcome, None)?;

        log(&format!("Creating MlsGroup"));
        let group = staged_join
            .into_group(provider)
            .map_err(anyhow::Error::msg)?;

        groups.insert(
            note.conversation
                .clone()
                .ok_or(anyhow!("Conversation must be Some"))?,
            group.group_id().clone(),
        );
        instruments.push(ApInstrument::from(group.group_id().clone()));
        instruments.append(&mut use_group(provider, create, note, group)?);
        Ok(instruments)
    }

    fn use_group(
        provider: &mut OpenMlsRustCrypto,
        create: ApCreate,
        note: ApNote,
        group: MlsGroup,
    ) -> Result<Vec<ApInstrument>> {
        let mut instruments = vec![];
        let encrypted_decoded = general_purpose::STANDARD.decode(note.content.ok_or(anyhow!("content must be Some"))?).unwrap();
        let encrypted_deserialized =
            MlsMessageIn::tls_deserialize(&mut encrypted_decoded.as_slice()).unwrap();

        fn create_vault_instrument(
            provider: &mut OpenMlsRustCrypto,
            message: impl Into<ProtocolMessage>,
            mut group: MlsGroup,
            create: ApCreate,
        ) -> Result<ApInstrument> {
            let message = group.process_message(provider, message).unwrap();
            match message.into_content() {
                ProcessedMessageContent::ApplicationMessage(message) => {
                    let message: String = String::from_utf8(message.into_bytes()).unwrap();
                    log(&format!("Re-encrypting MlsMessage: {message}"));
                    let mut instrument = ApInstrument::try_from((message, ENCRYPT_FN))?;
                    instrument.activity = create.id;
                    Ok(instrument)
                }
                _ => {
                    log(&format!(
                        "Unable to transform private ProcessedMessage into_content"
                    ));
                    Err(anyhow!("Unable to create Instrument"))
                }
            }
        }

        match encrypted_deserialized.extract() {
            MlsMessageBodyIn::PrivateMessage(msg) => {
                instruments.push(create_vault_instrument(provider, msg, group, create)?);
            }
            MlsMessageBodyIn::PublicMessage(msg) => {
                instruments.push(create_vault_instrument(provider, msg, group, create)?);
            }
            _ => log(&format!(
                "Unable to transform public ProcessedMessage into_content"
            )),
        };

        Ok(instruments)
    }

    async fn update_instruments(instruments: Vec<ApInstrument>) {
        if instruments.len() == 0 {
            return;
        }

        let state = get_state();

        let collection = ApCollection::from(instruments);

        if state.authenticated {
            authenticated(
                move |_state: EnigmatickState, profile: Profile| async move {
                    let url = format!("/user/{}", profile.username);
                    let body = json!(collection);
                    send_post(
                        url,
                        body.to_string(),
                        "application/activity+json".to_string(),
                    )
                    .await
                },
            )
            .await;
        }
    }

    fn build_activity(create: ApCreate, note: ApNote) -> ActivityPub {
        ActivityPub::Activity(ApActivity::Create(ApCreate {
            object: ApObject::Note(note).into(),
            ..create.clone()
        }))
    }

    fn transform_asymmetric_activity(
        provider: &mut OpenMlsRustCrypto,
        create: ApCreate,
        note: ApNote,
        groups: &mut HashMap<String, GroupId>,
    ) -> Option<Vec<ApInstrument>> {
        find_group_instrument(&create)
            .and_then(|instrument| {
                log(&format!("Found MlsGroup instrument\n{instrument:#?}"));
                let group_id = GroupId::try_from(instrument).ok()?;
                let group = MlsGroup::load(provider.storage(), &group_id).ok()??;
                use_group(provider, create.clone(), note.clone(), group).ok()
            })
            .or_else(|| {
                find_welcome_instrument(&create).and_then(|instrument| {
                    log(&format!("Found Welcome instrument\n{instrument:#?}"));
                    if let Some(group_id) = groups.get(note.conversation.clone()?.as_str()) {
                        log(&format!("Found previously processed GroupId"));
                        let group = MlsGroup::load(provider.storage(), &group_id).ok()??;
                        use_group(provider, create, note, group).ok()
                    } else {
                        log(&format!("Creating new MlsGroup"));
                        let welcome = Welcome::try_from(instrument).ok()?;
                        create_group(provider, welcome, create, note, groups).ok()
                    }
                })
            })
    }

    fn transform_encrypted_activity(create: ApCreate, mut note: ApNote) -> Option<ActivityPub> {
        find_vault_instrument(&create).and_then(|instrument| {
            decrypt_instrument_content(&instrument).map(|decrypted| {
                note.content = Some(decrypted);
                build_activity(create.clone(), note.clone())
            })
        })
    }

    async fn retrieve_encrypted_notes() -> Option<String> {
        authenticated(
            move |_state: EnigmatickState, _profile: Profile| async move {
                let url = format!("/api/encrypted");

                send_get(None, url, "application/activity+json".to_string()).await
            },
        )
        .await
    }

    async fn process_encrypted_notes(
        provider: &mut OpenMlsRustCrypto,
    ) -> Option<Vec<ApInstrument>> {
        if let Some(text) = retrieve_encrypted_notes().await {
            let mut instruments: Vec<ApInstrument> = vec![];
            let mut groups = HashMap::<String, GroupId>::new();

            if let ApObject::Collection(object) = serde_json::from_str(&text).ok()? {
                let items = object.clone().items()?;

                let encrypted_items: Vec<(ApCreate, ApNote)> = items
                    .iter()
                    .filter_map(|item| is_encrypted_note(item).or_else(|| None))
                    .collect();

                for (create, note) in encrypted_items {
                    let mut vault_instruments =
                        transform_asymmetric_activity(provider, create, note, &mut groups)?;
                    instruments.append(&mut vault_instruments);
                }

                Some(instruments)
            } else {
                None
            }
        } else {
            None
        }
    }

    async fn decrypt_task() {
        // Note that this will return an error if credentials do not exist (they should already exist)
        if let Some((_credentials_key_pair, mut provider, mutation_of)) =
            retrieve_credentials().await.ok()
        {
            log(&format!(
                "Provider Hash (before mutation): {mutation_of:#?}"
            ));

            let instruments = process_encrypted_notes(&mut provider)
                .await
                .unwrap_or_default();

            log(&format!(
                "Instruments from processed encrypted_notes\n{instruments:#?}"
            ));

            update_instruments(instruments).await;
        }
    }

    if state.authenticated {
        log("IN authenticated");
        authenticated(
            move |_state: EnigmatickState, profile: Profile| async move {
                let username = profile.username;

                // If retrieving the Direct view, we want to wait for decrypt_task to transform
                // any pending EncryptedNotes before retrieving the Vault collection. Otherwise,
                // launch the task in the background to avoid delaying page load.
                if view.to_lowercase().as_str() == "direct" {
                    decrypt_task().await;
                } else {
                    spawn_local(decrypt_task());
                }

                let url =
                    format!("/user/{username}/inbox?limit={limit}{position}&view={view}{hashtags}");

                let text = send_get(None, url, "application/activity+json".to_string()).await?;

                if let ApObject::Collection(object) = serde_json::from_str(&text).ok()? {
                    let items = object.clone().items()?;

                    let _decrypted_items: Vec<ActivityPub> = items
                        .iter()
                        .filter_map(|item| {
                            is_encrypted_note(item)
                                .and_then(|(create, note)| {
                                    transform_encrypted_activity(create, note)
                                })
                                .or_else(|| Some(item.clone()))
                        })
                        .collect();

                    serde_json::to_string(&object).ok()
                } else {
                    None
                }
            },
        )
        .await
    } else {
        log("IN NOT authenticated");
        let object: ApCollection = get_object(
            format!("/inbox?limit={limit}{position}&view=global{hashtags}"),
            None,
            "application/activity+json",
        )
        .await
        .ok()?;

        serde_json::to_string(&object).ok()
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
