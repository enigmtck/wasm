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
