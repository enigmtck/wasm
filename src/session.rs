use crate::{get_hash, get_remote_keys, get_state, SendParams};
use crate::{get_key, log, send_get};
use anyhow::{anyhow, Result};
use jdt_activity_pub::{ActivityPub, ApInstrument, ApInstrumentType, ApObject, Collectible};
use vodozemac::{
    olm::{Account, AccountPickle, Session, SessionConfig, SessionPickle},
    Curve25519PublicKey,
};

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
