use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct KeyStore {
    // salt is base64 encoded and is used for the KDF that generates the
    // key for the AEAD encryption used in this struct
    pub salt: String,

    // client_private_key is pem encoded, encrypted, and then base64 encoded
    pub client_private_key: String,

    // olm_identity_public_key is a Curve25519PublicKey that has been base64
    // encoded without padding by the vodozemac library (which will also import
    // it using native functions)
    pub olm_identity_public_key: String,

    // olm_one_time_keys is a JSON object in the form of {"u8": [u8,u8,u8..], "u8": [...]}
    // these are public keys to be distributed to parties who want to initiate Olm sessions
    pub olm_one_time_keys: HashMap<String, Vec<u8>>,

    // olm_pickled_account is converted from an Account to an AccountPickle and then serialized
    // via serde_json by the Olm component; it is then encrypted and base64 encoded here
    pub olm_pickled_account: String,

    // olm_external_identity_keys is a cache of keys to use for decrypting messages with
    // other parties; the format is https://server/user/username -> base64-encoded-identitykey
    pub olm_external_identity_keys: HashMap<String, String>,

    // olm_external_one_time_keys is a cache of keys to use for decrypting messages with
    // other parties; the format is https://server/user/username -> base64-encoded-onetimekey
    pub olm_external_one_time_keys: HashMap<String, String>,

    // olm_sessions is a HashMap<String, String> that maps user identities to pickled Olm
    // sessions; the HashMap is stored via serde_json::to_string -> AEAD encrypt -> base64
    pub olm_sessions: String,
}
