use base64::engine::{general_purpose, Engine as _};
use jdt_activity_pub::{
    session::CredentialKeyPair, ApAddress, ApCollection, ApInstrument, ApObject, 
};
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, decrypt_bytes, encrypt_bytes, get_state, log, send_post,
    EnigmatickState, Profile, ENCRYPT_FN, HASH_FN,
};

// A helper to create and store credentials.
fn generate_credential_with_key(
    identity: Vec<u8>,
    _credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm).expect("Error generating a signature key pair.");

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    signature_keys
        .store(provider.storage())
        .expect("Error storing signature keys in key store.");

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

// A helper to create key package bundles.
fn generate_key_packages(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    count: i32,
) -> Vec<KeyPackageBundle> {
    (0..count)
        .map(|_| {
            KeyPackage::builder()
                .build(ciphersuite, provider, signer, credential_with_key.clone())
                .unwrap()
        })
        .collect()
}

pub async fn send_object(object: ApObject) -> Option<String> {
    authenticated(
        move |_state: EnigmatickState, profile: Profile| async move {
            let outbox = format!("/user/{}", profile.username.clone());

            send_post(
                outbox,
                serde_json::to_string(&object).unwrap(),
                "application/activity+json".to_string(),
            )
            .await
        },
    )
    .await
}

pub async fn initialize_credentials() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = &OpenMlsRustCrypto::default();
    let state = get_state();

    let profile = state.get_profile().unwrap();
    let id = profile.id;

    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("Error generating a signature key pair.");

    let credential_key_pair: CredentialKeyPair = (id.clone(), signature_keys.clone()).into();

    let mut key_packages: Vec<ApInstrument> = generate_key_packages(
        ciphersuite,
        provider,
        &signature_keys,
        credential_key_pair.credential_with_key.clone(),
        10,
    )
    .into_iter()
    .map(ApInstrument::from)
    .collect();

    let storage_instrument = ApInstrument::from((provider.storage(), None, ENCRYPT_FN, HASH_FN));
    let credentials = ApInstrument::from((credential_key_pair, ENCRYPT_FN));

    let mut instruments = vec![credentials, storage_instrument];
    instruments.append(&mut key_packages);

    let collection = ApCollection::from(instruments);

    let resp = send_object(ApObject::Collection(collection)).await;
    log(&format!("Response: {resp:#?}"));
}

#[wasm_bindgen]
pub async fn test() {
    initialize_credentials().await;
    return;
    // Define ciphersuite ...
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // ... and the crypto provider to use.
    let provider = &OpenMlsRustCrypto::default();

    log("Generate identifying credentials");
    // First they need credentials to identify them
    let (sasha_credential_with_key, sasha_signer) = generate_credential_with_key(
        "Sasha".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        provider,
    );

    let sasha_credential_key_pair: CredentialKeyPair =
        (ApAddress::from("sasha".to_string()), sasha_signer.clone()).into();
    let sasha_signer_instrument =
        ApInstrument::from((sasha_credential_key_pair, |data: Vec<u8>| -> Vec<u8> {
            encrypt_bytes(None, data.as_slice()).unwrap()
        }));

    let (maxim_credential_with_key, maxim_signer) = generate_credential_with_key(
        "Maxim".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        provider,
    );

    let maxim_credential_key_pair: CredentialKeyPair =
        (ApAddress::from("maxim".to_string()), sasha_signer.clone()).into();
    let maxim_signer_instrument =
        ApInstrument::from((maxim_credential_key_pair, |data: Vec<u8>| -> Vec<u8> {
            encrypt_bytes(None, data.as_slice()).unwrap()
        }));

    // Then they generate key packages to facilitate the asynchronous handshakes
    // in MLS

    // Generate KeyPackages
    let maxim_key_package_bundle = generate_key_packages(
        ciphersuite,
        provider,
        &maxim_signer,
        maxim_credential_with_key,
        10,
    );

    let maxim_key_package_instrument = ApInstrument::from(maxim_key_package_bundle[0].clone());

    let maxim_key_package = KeyPackage::try_from(maxim_key_package_instrument).unwrap();

    // Now Sasha starts a new group ...
    let mut sasha_group = MlsGroup::new(
        provider,
        &sasha_signer,
        &MlsGroupCreateConfig::default(),
        sasha_credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    // ... and invites Maxim.
    // The key package has to be retrieved from Maxim in some way. Most likely
    // via a server storing key packages for users.
    let (_commit, welcome_out, _group_info) = sasha_group
        .add_members(provider, &sasha_signer, &[maxim_key_package.clone()])
        .expect("Could not add members.");

    // Sasha merges the pending commit that adds Maxim.
    sasha_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let _first_encrypted = sasha_group
        .create_message(provider, &sasha_signer, "welcome dude".as_bytes())
        .unwrap();

    let storage_instrument = ApInstrument::from((provider.storage(), None, |data: Vec<u8>| -> Vec<u8> {
        encrypt_bytes(None, data.as_slice()).unwrap()
    }, HASH_FN));
    log(&format!(
        "Sasha Storage Instrument: {storage_instrument:#?}"
    ));

    let group_instrument = ApInstrument::from(sasha_group.group_id().clone());
    log(&format!("Sasha Group Instrument: {group_instrument:#?}"));

    let welcome_instrument = ApInstrument::try_from(welcome_out).unwrap();
    log(&format!(
        "Sasha Welcome Instrument (to send to Maxim): {welcome_instrument:#?}"
    ));

    let welcome = Welcome::try_from(welcome_instrument).unwrap();

    // Now Maxim can build a staged join for the group in order to inspect the welcome
    let maxim_staged_join = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        // The public tree is need and transferred out of band.
        // It is also possible to use the [`RatchetTreeExtension`]
        Some(sasha_group.export_ratchet_tree().into()),
    )
    .expect("Error creating a staged join from Welcome");

    // Finally, Maxim can create the group
    let mut maxim_group = maxim_staged_join
        .into_group(provider)
        .expect("Error creating the group from the staged join");

    let first_post = "F1r5t P05t!!!";

    let encrypted = maxim_group
        .create_message(provider, &maxim_signer, first_post.as_bytes())
        .unwrap();
    let encrypted_serialized = encrypted.tls_serialize_detached().unwrap();
    let encrypted_encoded = general_purpose::STANDARD.encode(encrypted_serialized);

    log(&format!("First Post Encoded: {encrypted_encoded}"));

    let encrypted_decoded = general_purpose::STANDARD.decode(encrypted_encoded).unwrap();
    let encrypted_deserialized =
        MlsMessageIn::tls_deserialize(&mut encrypted_decoded.as_slice()).unwrap();

    let gid_reloaded = GroupId::try_from(group_instrument).unwrap();

    let provider_reloaded = storage_instrument
        .to_provider(|encoded_data| -> Vec<u8> { decrypt_bytes(None, encoded_data).unwrap() })
        .unwrap();

    let mut sasha_group_reloaded = MlsGroup::load(provider_reloaded.storage(), &gid_reloaded)
        .unwrap()
        .unwrap();

    match encrypted_deserialized.extract() {
        MlsMessageBodyIn::PrivateMessage(msg) => {
            let message = sasha_group_reloaded
                .process_message(&provider_reloaded, msg)
                .unwrap();
            match message.into_content() {
                ProcessedMessageContent::ApplicationMessage(message) => {
                    let message: String = String::from_utf8(message.into_bytes()).unwrap();
                    log(&format!("Private Message: {message:#?}"));
                }
                _ => log(&format!("Something Else")),
            }
        }
        MlsMessageBodyIn::PublicMessage(msg) => {
            let message = sasha_group
                .process_message(&provider_reloaded, msg)
                .unwrap();
            let message = message.content();
            log(&format!("Public Message: {message:#?}"));
        }
        _ => log(&format!("Something Else")),
    };
}
