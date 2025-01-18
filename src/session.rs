use crate::{
    get_hash, get_mls_keys, get_remote_keys, get_state, SendParams, DECRYPT_FN, ENCRYPT_FN, HASH_FN,
};
use crate::{get_key, log, send_get};
use anyhow::{anyhow, Result};
use base64::engine::{general_purpose, Engine as _};
use jdt_activity_pub::session::CredentialKeyPair;
use jdt_activity_pub::{ActivityPub, ApInstrument, ApInstrumentType, ApObject, Collectible};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls::prelude::{
    tls_codec::*, CredentialWithKey, KeyPackage, MlsMessageOut, OpenMlsCrypto, OpenMlsProvider,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use vodozemac::{
    olm::{Account, AccountPickle, Session, SessionConfig, SessionPickle},
    Curve25519PublicKey,
};

pub async fn retrieve_credentials() -> Result<(CredentialKeyPair, OpenMlsRustCrypto, Option<String>)>
{
    let activity_pubs = get_mls_keys()
        .await
        .ok_or(anyhow!(
            "Failed to retrieve user MLS credentials and storage"
        ))?
        .items()
        .ok_or(anyhow!("No items"))?;

    let instruments: Vec<ApInstrument> = activity_pubs
        .iter()
        .filter_map(|item| {
            if let ActivityPub::Object(ApObject::Instrument(x)) = item {
                Some(x.clone())
            } else {
                None
            }
        })
        .collect();

    let credentials = instruments
        .iter()
        .find(|instrument| instrument.is_mls_credentials())
        .ok_or(anyhow!("Instrument must be Some"))?
        .to_credentials(DECRYPT_FN)?;

    let provider = instruments
        .iter()
        .find(|instrument| instrument.is_mls_storage())
        .ok_or(anyhow!("Instrument must be Some"))?;

    let mutation_of = provider.hash.clone();
    let provider = provider.to_provider(DECRYPT_FN)?;

    Ok((credentials, provider, mutation_of))
}

pub async fn create_mls_group(params: &mut SendParams) -> Result<()> {
    let (credentials, provider, mutation_of) = retrieve_credentials().await?;

    let mut key_packages: Vec<KeyPackage> = vec![];
    for webfinger in params.mentions.keys() {
        if let Some(keys) = get_remote_keys(webfinger.clone())
            .await
            .and_then(|x| x.items())
        {
            key_packages.extend(keys.into_iter().filter_map(|ap| match ap {
                ActivityPub::Object(ApObject::Instrument(instrument)) => {
                    KeyPackage::try_from(instrument).ok()
                }
                _ => None,
            }));
        }
    }

    let group_config_builder = MlsGroupCreateConfig::builder().use_ratchet_tree_extension(true);
    let group_config = group_config_builder.build();

    let mut group = MlsGroup::new(
        &provider,
        &credentials.key_pair,
        &group_config,
        credentials.credential_with_key.clone(),
    )?;

    let (_commit, welcome_out, _group_info) =
        group.add_members(&provider, &credentials.key_pair, &key_packages)?;

    group.merge_pending_commit(&provider)?;

    params.add_instrument(ApInstrument::try_from((
        params.get_content().clone(),
        ENCRYPT_FN,
    ))?);

    let encrypted = group.create_message(
        &provider,
        &credentials.key_pair,
        params.get_content().as_bytes(),
    )?;

    let encrypted_serialized = encrypted.tls_serialize_detached().unwrap();
    let encrypted_encoded = general_purpose::STANDARD.encode(encrypted_serialized);

    params.set_content(encrypted_encoded);
    params.add_instrument(ApInstrument::from((
        provider.storage(),
        mutation_of,
        ENCRYPT_FN,
        HASH_FN,
    )));
    //params.add_instrument(ApInstrument::from((credentials, ENCRYPT_FN)));
    params.add_instrument(welcome_out.try_into()?);
    params.add_instrument(group.group_id().clone().into());

    Ok(())
}

pub async fn create_olm_session(params: &mut SendParams) -> Result<Session> {
    let state = get_state();

    let (webfinger, _id) = params
        .mentions
        .iter()
        .last()
        .ok_or(anyhow!("webfinger must be Some"))?;

    let keys = get_remote_keys(webfinger.clone())
        .await
        .ok_or(anyhow!("keys must be Some"))?;

    log(&format!("{keys:#?}"));

    let (one_time_key, identity_key) = keys
        .items()
        .map(|items| {
            items
                .into_iter()
                .fold((None, None), |(one_time, identity), item| match item {
                    ActivityPub::Object(ApObject::Instrument(instrument)) => {
                        match instrument.kind {
                            ApInstrumentType::OlmOneTimeKey if one_time.is_none() => {
                                (instrument.content, identity)
                            }
                            ApInstrumentType::OlmIdentityKey if identity.is_none() => {
                                (one_time, instrument.content)
                            }
                            _ => (one_time, identity),
                        }
                    }
                    _ => (one_time, identity),
                })
        })
        .unwrap_or((None, None));

    let identity_key: String = identity_key.ok_or(anyhow!("identity_key must be Some"))?;
    let one_time_key: String = one_time_key.ok_or(anyhow!("one_time_key must be Some"))?;
    let identity_key =
        Curve25519PublicKey::from_base64(&identity_key).map_err(anyhow::Error::msg)?;
    let one_time_key =
        Curve25519PublicKey::from_base64(&one_time_key).map_err(anyhow::Error::msg)?;
    let pickled_account = state
        .get_olm_pickled_account()
        .ok_or(anyhow!("pickled_account must be Some"))?;

    let _original_account_hash = get_hash(pickled_account.clone().into_bytes()).unwrap();

    let pickled_account =
        serde_json::from_str::<AccountPickle>(&pickled_account).map_err(anyhow::Error::msg)?;

    let account = Account::from(pickled_account);

    let session =
        account.create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key);

    // params.set_olm_account(
    //     ApInstrument::try_from(&account)?
    //         .set_mutation_of(original_account_hash)
    //         .clone(),
    // );

    // params.set_olm_identity_key(ApInstrument::from((
    //     ApInstrumentType::OlmIdentityKey,
    //     account.curve25519_key(),
    // )));

    Ok(session)
}

pub async fn get_olm_session(conversation: String) -> Result<Session> {
    log("in get_olm_session");
    let conversation = urlencoding::encode(&conversation).to_string();
    let url = format!("/api/instruments/olm-session?conversation={conversation}");

    log(&url);

    let instrument_str = send_get(None, url, "application/activity+json".to_string())
        .await
        .ok_or_else(|| {
            log("failed to retrieve olm-session");
            anyhow!("Failed to retrieve session")
        })?;

    log(&instrument_str);

    let instrument: ApInstrument = serde_json::from_str(&instrument_str)?;
    let content = instrument
        .content
        .ok_or(anyhow!("Olm Session Instrument must have content"))?;

    let key = &*get_key()?;
    Ok(SessionPickle::from_encrypted(&content, key.try_into()?)?.into())
}
