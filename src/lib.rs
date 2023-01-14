#![allow(non_upper_case_globals)]

use gloo_net::http::Request;
use orion::aead::SecretKey;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use lazy_static::lazy_static;

use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, Signature};
use rsa::{pkcs8::DecodePrivateKey, pkcs8::EncodePublicKey, pkcs8::EncodePrivateKey, pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use orion::{aead, kdf};
use base64::{encode, decode};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fmt::{self, Debug};
use url::Url;
use serde_json::Value;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct EnigmatickState {
    authenticated: bool,
    
    // this is stored in state because derivation is expensive
    derived_key: Option<String>,

    // the keystore is in the profile, but it's stringified
    profile: Option<Profile>,

    // this is the un-stringified version of the keystore from the profile
    // it includes the encrypted data stored on the server accessible via
    // object getters
    keystore: Option<KeyStore>,

    // this is the decrypted, PEM encoded client key from the keystore
    client_private_key_pem: Option<String>,

    // this is the decrypted, pickled olm account from the keystore
    olm_pickled_account: Option<String>,

    // this is the decrypted map of user identities to pickled sessions decrypted
    // and decoded from the keystore
    olm_sessions: Option<HashMap<String, String>>
}

#[wasm_bindgen]
impl EnigmatickState {
    pub fn new() -> EnigmatickState {
        EnigmatickState::default()
    }

    pub fn cache_external_identity_key(&mut self, ap_id: String, identity_key: String) -> Self {
        if let Some(keystore) = &self.keystore {
            let mut keystore = keystore.clone();
            keystore.olm_external_identity_keys.insert(ap_id, identity_key);
            self.keystore = Option::from(keystore);
        }
        self.clone()
    }

    pub fn get_external_identity_key(&self, ap_id: String) -> Option<String> {
        if let Some(keystore) = &self.keystore {
            keystore.olm_external_identity_keys.get(&ap_id).cloned()
        } else {
            Option::None
        }
    }
    
    pub fn set_derived_key(&mut self, key: String) -> Self {
        self.derived_key = Option::from(key);
        self.clone()
    }

    pub fn get_derived_key(&self) -> Option<String> {
        self.derived_key.clone()
    }

    pub fn set_profile(&mut self, profile: Profile) -> Self {
        self.profile = Option::from(profile);
        self.clone()
    }

    pub fn get_profile(&self) -> Option<Profile> {
        self.profile.clone()
    }

    fn set_keystore(&mut self, keystore: KeyStore) -> Self {
        self.keystore = Option::from(keystore);
        self.clone()
    }

    fn get_keystore(&self) -> Option<KeyStore> {
        self.keystore.clone()
    }

    pub fn set_client_private_key_pem(&mut self, pem: String) -> Self {
        self.client_private_key_pem = Option::from(pem);
        self.clone()
    }

    pub fn get_client_private_key_pem(&self) -> Option<String> {
        self.client_private_key_pem.clone()
    }

    pub fn set_olm_pickled_account(&mut self, olm_pickled_account: String) -> Self {
        self.olm_pickled_account = Option::from(olm_pickled_account);
        self.clone()
    }

    pub fn get_olm_pickled_account(&self) -> Option<String> {
        self.olm_pickled_account.clone()
    }

    pub fn set_olm_sessions(&mut self, olm_sessions: String) -> Self {
        self.olm_sessions = Option::<HashMap<String, String>>::from(
            serde_json::from_str::<HashMap<String, String>>(&olm_sessions).unwrap());
        self.clone()
    }

    pub fn get_olm_sessions(&self) -> String {
        serde_json::to_string(&self.olm_sessions).unwrap()
    }

    pub fn set_olm_session(&mut self, ap_id: String, session: String) -> Self {
        if let Some(olm_sessions) = self.olm_sessions.clone() {
            let mut olm_sessions = olm_sessions;
            olm_sessions.insert(ap_id, session);
            self.olm_sessions = Option::from(olm_sessions);
        } 
        self.clone()
    }
    
    pub fn get_olm_session(&self, ap_id: String) -> Option<String> {
        if let Some(olm_sessions) = self.olm_sessions.clone() {
            olm_sessions.get(&ap_id).cloned()
        } else {
            Option::None
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn export(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

lazy_static! {
    pub static ref ENIGMATICK_STATE: Arc<Mutex<EnigmatickState>> = {
        Arc::new(Mutex::new(EnigmatickState::new()))
    };
}

#[wasm_bindgen]
pub fn import_state(data: String) {
    let imported_state: EnigmatickState = serde_json::from_str(&data).unwrap();

    let state = &*ENIGMATICK_STATE.clone();
                
    if let Ok(mut x) = state.try_lock() {
        x.set_derived_key(imported_state.derived_key.unwrap());
        x.authenticated = imported_state.authenticated;
        x.set_client_private_key_pem(imported_state.client_private_key_pem.unwrap());
        x.set_profile(imported_state.profile.unwrap());
        x.set_keystore(imported_state.keystore.unwrap());
    };
}

struct KeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

fn get_key_pair() -> KeyPair {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed");
    let public_key = RsaPublicKey::from(&private_key);

    KeyPair {
        private_key,
        public_key,
    }
}


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

    // olm_sessions is a HashMap<String, String> that maps user identities to pickled Olm
    // sessions; the HashMap is stored via serde_json::to_string -> AEAD encrypt -> base64
    pub olm_sessions: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub display_name: String,
    pub client_public_key: String,
    pub keystore: String,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Profile {
    pub created_at: String,
    pub updated_at: String,
    pub uuid: String,
    pub username: String,
    pub display_name: String,
    #[wasm_bindgen(skip)]
    pub summary: Option<String>,
    pub public_key: String,
    #[wasm_bindgen(skip)]
    pub keystore: KeyStore,
    pub client_public_key: String,
}

#[wasm_bindgen]
pub async fn get_state() -> EnigmatickState {
    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.lock() {
        x.clone()
    } else {
        EnigmatickState::default()
    }
}

#[wasm_bindgen]
pub async fn authenticate(username: String,
                          password: String,
                          passphrase: String) -> Option<Profile> {

    #[derive(Serialize, Debug, Clone)]
    struct AuthenticationData {
        username: String,
        password: String,
    }
    
    let req = AuthenticationData {
        username,
        password,
    };

    if let Ok(passphrase) = kdf::Password::from_slice(passphrase.as_bytes()) {
        log("in passphrase");
        if let Ok(x) = Request::post("http://localhost:8010/api/user/authenticate").json(&req) {   
            if let Ok(y) = x.send().await {
                log("in request");
                let state = &*ENIGMATICK_STATE.clone();
                //log(&format!("y\n{:#?}", y.text().await));
                let user = y.json().await.ok();
                
                if let Ok(mut x) = state.try_lock() {
                    log("in lock");
                    x.authenticated = true;

                    log(&format!("user\n{:#?}", user));
                    let user: Profile = user.clone().unwrap();
                    x.set_profile(user.clone());
                    log("after profile");
                    x.set_keystore(user.keystore.clone());
                    log("after keystore");
                    let salt = kdf::Salt::from_slice(&decode(user.keystore.salt).unwrap()).unwrap();

                    if let Ok(derived_key) = kdf::derive_key(&passphrase, &salt, 3, 1<<4, 32) {
                        log("in derive");
                        let encoded_derived_key = encode(derived_key.unprotected_as_bytes());
                        x.set_derived_key(encoded_derived_key);

                        if let Ok(decrypted_client_key_pem) =
                            aead::open(&derived_key,
                                       &decode(user.keystore.client_private_key)
                                       .unwrap())
                        {
                            log("in decrypted pem");
                            x.set_client_private_key_pem(
                                String::from_utf8(decrypted_client_key_pem).unwrap()
                            );
                        }

                        if let Ok(decrypted_olm_pickled_account) =
                            aead::open(&derived_key,
                                       &decode(user.keystore.olm_pickled_account)
                                       .unwrap())
                        {
                            log("in decrypted pickle");
                            x.set_olm_pickled_account(String::from_utf8(decrypted_olm_pickled_account)
                                                      .unwrap());
                        }

                        if let Ok(decrypted_olm_sessions) =
                            aead::open(&derived_key,
                                       &decode(user.keystore.olm_sessions)
                                       .unwrap())
                        {
                            log("in decrypted olm_sessions");
                            match String::from_utf8(decrypted_olm_sessions) {
                                Ok(y) => {
                                    log(&format!("olm_sessions: {:#?}", y));
                                    x.set_olm_sessions(y);
                                },
                                Err(e) => log(&format!("olm_sessions error: {:#?}", e))
                            }           
                        }
                    }
                };

                user
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub async fn create_user(username: String,
                         display_name: String,
                         password: String,
                         passphrase: String,
                         olm_identity_public_key: String,
                         olm_one_time_keys: String,
                         olm_pickled_account: String
) -> Option<Profile> {
    
    let key = get_key_pair();

    if let (Ok(client_public_key),
            Ok(client_private_key),
            Ok(passphrase)) =
        (key.public_key.to_public_key_pem(LineEnding::default()),
         key.private_key.to_pkcs8_pem(LineEnding::default()),
         kdf::Password::from_slice(passphrase.as_bytes()))
    {

        let client_private_key = client_private_key.to_string();
        let encoded_client_private_key = client_private_key.clone();
        
        let salt = kdf::Salt::default();
        
        // the example uses 1<<16 (64MiB) for the memory; I'm using 1<<4 (16KiB) for my test machine
        // this should be increased to what is tolerable
        if let Ok(derived_key) = kdf::derive_key(&passphrase, &salt, 3, 1<<4, 32) {
            let salt = encode(&salt);
            let encoded_derived_key = encode(derived_key.unprotected_as_bytes());

            let olm_sessions = serde_json::to_string(&HashMap::<String, String>::new()).unwrap();
            
            if let (Ok(cpk_ciphertext), Ok(olm_ciphertext), Ok(sessions_ciphertext)) =
                (aead::seal(&derived_key, client_private_key.as_bytes()),
                 aead::seal(&derived_key, olm_pickled_account.as_bytes()),
                 aead::seal(&derived_key, olm_sessions.as_bytes())) {
                    
                    let client_private_key = encode(cpk_ciphertext);
                    let olm_pickled_account = encode(olm_ciphertext);
                    let olm_sessions = encode(sessions_ciphertext);
                    let olm_one_time_keys: HashMap<String, Vec<u8>> =
                        serde_json::from_str(&olm_one_time_keys).unwrap();
                    let olm_external_identity_keys: HashMap<String, String> = HashMap::new();
                    
                    if let Ok(keystore) = serde_json::to_string(&KeyStore {
                        client_private_key,
                        salt,
                        olm_identity_public_key,
                        olm_one_time_keys,
                        olm_pickled_account,
                        olm_external_identity_keys,
                        olm_sessions,
                    }) {

                        log(&format!("serialized keystore\n{:#?}", keystore));
                        let req = NewUser {
                            username,
                            password,
                            display_name,
                            client_public_key,
                            keystore
                        };
                        
                        if let Ok(x) =
                            Request::post("http://localhost:8010/api/user/create").json(&req) {   
                            if let Ok(y) = x.send().await {
                                let state = &*ENIGMATICK_STATE.clone();
                                let user = y.json().await.ok();
                                
                                if let Ok(mut x) = state.try_lock() {
                                    let user: Profile = user.clone().unwrap();
                                    x.set_profile(user.clone());
                                    x.set_derived_key(encoded_derived_key);
                                    x.set_keystore(user.keystore);
                                    x.set_client_private_key_pem(encoded_client_private_key);
                                };
                                //let user = y.text().await.ok();

                                user
                            } else {
                                Option::None
                            }
                        } else {
                            Option::None
                        }
                    } else {
                        Option::None
                    }
                } else {
                    Option::None
                }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[derive(Debug, Clone)]
pub enum Method {
    Get,
    Post
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Clone)]
pub struct SignParams {
    pub url: String,
    pub body: Option<String>,
    pub method: Method,
}

#[derive(Default, Debug)]
pub struct SignResponse {
    pub signature: String,
    pub date: String,
    pub digest: Option<String>,
}

pub fn sign(params: SignParams) -> SignResponse {
    // (request-target): post /users/justin/inbox
    // host: ser.endipito.us
    // date: Tue, 20 Dec 2022 22:02:48 GMT
    // digest: sha-256=uus37v4gf3z6ze+jtuyk+8xsT01FhYOi/rOoDfFV1u4=
    
    let digest = {
        if let Some(body) = params.body {
            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            let hashed = base64::encode(hasher.finalize());
            Option::from(format!("sha-256={}", hashed))
        } else {
            Option::None
        }
    };

    let url = Url::parse(&params.url).unwrap();
    let host = url.host().unwrap().to_string();
    let request_target = format!("{} {}",
                                 params.method.to_string().to_lowercase(),
                                 url.path());

    fn perf_to_system(amt: f64) -> std::time::SystemTime {
        let secs = (amt as u64) / 1_000;
        let nanos = ((amt as u32) % 1_000) * 1_000_000;
        std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos)
    }
    
    let date = httpdate::fmt_http_date(perf_to_system(date_now()));

    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.try_lock() {
        if let (Some(y), Some(profile)) = (&x.client_private_key_pem, &x.profile) {

            let private_key = RsaPrivateKey::from_pkcs8_pem(y).unwrap();
            let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);

            let structured_data = {
                if let Some(digest) = digest.clone() {
                    Option::from(format!(
                        "(request-target): {}\nhost: {}\ndate: {}\ndigest: {}",
                        request_target,
                        host,
                        date,
                        digest
                    ))
                } else {
                    Option::from(format!(
                        "(request-target): {}\nhost: {}\ndate: {}",
                        request_target,
                        host,
                        date
                    ))
                }
            };

            if let Some(structured_data) = structured_data {
                let mut rng = rand::thread_rng();
                let signature = signing_key.sign_with_rng(&mut rng, structured_data.as_bytes());

                if let Some(digest) = digest {
                    SignResponse {
                        signature: format!(
                            "keyId=\"https://enigmatick.jdt.dev/user/{}#client-key\",headers=\"(request-target) host date digest\",signature=\"{}\"",
                            profile.username,
                            base64::encode(signature.as_bytes())),
                        date,
                        digest: Option::from(digest)
                    }
                } else {
                    SignResponse {
                        signature: format!(
                            "keyId=\"https://enigmatick.jdt.dev/user/{}#client-key\",headers=\"(request-target) host date\",signature=\"{}\"",
                            profile.username,
                            base64::encode(signature.as_bytes())),
                        date,
                        digest: Option::None
                    }
                }
            } else {
                SignResponse::default()
            }
        } else {
            SignResponse::default()
        }
    } else {
        SignResponse::default()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApFlexible {
    Single(Value),
    Multiple(Vec<Value>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApTag {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    href: String,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApNote {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    context: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    published: Option<String>,
    url: Option<ApFlexible>,
    to: Vec<String>,
    cc: Option<Vec<String>>,
    tag: Vec<ApTag>,
    attributed_to: String,
    content: String,
    in_reply_to: Option<String>,
    replies: Option<ApFlexible>,
}

impl From<SendParams> for ApNote {
    fn from(params: SendParams) -> Self {
        let tag = params.recipients.iter().map(|(x, y)| ApTag { kind: "Mention".to_string(), name: x.to_string(), href: y.to_string()}).collect::<Vec<ApTag>>();

        let mut recipients: Vec<String> = params.recipients.into_values().collect();
        recipients.extend(params.recipient_ids);
        
        ApNote {
            context: Option::from("https://www.w3.org/ns/activitystreams".to_string()),
            kind: params.kind,
            to: recipients,
            tag,
            content: params.content,
            ..Default::default()
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Default)]
pub struct SendParams {
    // @name@example.com -> https://example.com/user/name
    recipients: HashMap<String, String>,

    // https://server/user/username - used for EncryptedNotes where tags
    // are undesirable
    recipient_ids: Vec<String>,
    content: String,
    kind: String,
}

#[wasm_bindgen]
impl SendParams {
    pub fn new() -> SendParams {
        SendParams::default()
    }

    pub fn set_kind(&mut self, kind: String) -> Self {
        self.kind = kind;
        self.clone()
    }
    
    pub fn add_recipient_id(&mut self, recipient_id: String) -> Self {
        self.recipient_ids.push(recipient_id);
        self.clone()
    }
    
    pub async fn add_address(&mut self, address: String) -> Self {
        self.recipients.insert(address.clone(), get_webfinger(address).await.unwrap_or_default());
        self.clone()
    }

    pub fn set_content(&mut self, content: String) -> Self {
        self.content = content;
        self.clone()
    }

    pub fn get_recipients(&self) -> String {
        serde_json::to_string(&self.recipients).unwrap()
    }

    pub fn get_content(&self) -> String {
        self.content.clone()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApContext {
    Plain(String),
    Complex(Vec<Value>),
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApObjectType {
    Article,
    Audio,
    Document,
    Event,
    Image,
    Note,
    Page,
    Place,
    Profile,
    Relationship,
    Tombstone,
    Video,
    EncryptedSession,
    IdentityKey,
    SessionKey,
}

impl fmt::Display for ApObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApBaseObjectType {
    Object,
    Link,
    Activity,
    IntransitiveActivity,
    Collection,
    OrderedCollection,
    CollectionPage,
    OrderedCollectionPage,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApCollection {
    #[serde(rename = "@context")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApBaseObjectType,
    pub id: Option<String>,
    pub total_items: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<ApObject>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    part_of: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApObject {
    Plain(String),
    Collection(ApCollection),
    Session(ApSession),
    Note(ApNote),
    Basic(ApBasicContent),
    #[default]
    Unknown,
}

#[wasm_bindgen]
pub async fn get_processing_queue() -> Option<String> {
    log("in get processing_queue");
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};
    
    if let Some(state) = state {
        log("in state");
        if state.is_authenticated() {
            log("in authenticated");
            if let Some(profile) = &state.profile {
                log("in profile");

                let inbox = format!("https://enigmatick.jdt.dev/api/user/{}/processing_queue",
                                    profile.username.clone());
                
                let signature = sign(SignParams {
                    url: inbox.clone(),
                    body: Option::None,
                    method: Method::Get
                });

                if let Ok(resp) = Request::get(&inbox)
                    .header("Enigmatick-Date", &signature.date)
                    .header("Signature", &signature.signature)
                    .header("Content-Type", "application/activity+json")
                    .send().await
                {
                    log(&format!("queue response\n{:#?}", resp.text().await));
                    if let Ok(ApObject::Collection(object)) = resp.json().await {
                        if let Some(items) = object.items.clone() {
                            for o in items {
                                if let ApObject::Session(session) = o {
                                    match session.instrument {
                                        ApInstrument::Multiple(x) => {
                                            for i in x {
                                                if let ApObject::Basic(y) = i {
                                                    if y.kind == ApBasicContentType::IdentityKey {
                                                        if let Ok(mut x) =
                                                            (*ENIGMATICK_STATE).try_lock()
                                                        {
                                                            log(&format!("caching: {:#?}",
                                                                        session.attributed_to
                                                                        .clone()));
                                                            x.cache_external_identity_key(
                                                                session.attributed_to.clone(),
                                                                y.content);
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        ApInstrument::Single(x) => {
                                            if let ApObject::Basic(y) = *x {
                                                if y.kind == ApBasicContentType::IdentityKey {
                                                    if let Ok(mut x) =
                                                        (*ENIGMATICK_STATE).try_lock()
                                                    {
                                                        log(&format!("caching: {:#?}",
                                                                     session.attributed_to
                                                                     .clone()));
                                                        x.cache_external_identity_key(
                                                            session.attributed_to.clone(),
                                                            y.content);
                                                    }
                                                }
                                            }
                                        },
                                        _ => {
                                        }
                                    }
                                }
                            }
                            send_updated_identity_cache().await;
                        }
                        Option::from(serde_json::to_string(&object).unwrap())
                    } else {
                        Option::None
                    }
                } else {
                    Option::None
                }
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub async fn get_inbox() -> Option<String> {
    log("in get inbox");
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};
    
    if let Some(state) = state {
        log("in state");
        if state.is_authenticated() {
            log("in authenticated");
            if let Some(profile) = &state.profile {
                log("in profile");

                let inbox = format!("https://enigmatick.jdt.dev/user/{}/inbox",
                                    profile.username.clone());
                
                let signature = sign(SignParams {
                    url: inbox.clone(),
                    body: Option::None,
                    method: Method::Get
                });

                if let Ok(resp) = Request::get(&inbox)
                    .header("Enigmatick-Date", &signature.date)
                    .header("Signature", &signature.signature)
                    .header("Content-Type", "application/activity+json")
                    .send().await
                {
                    if let Ok(ApObject::Collection(object)) = resp.json().await {
                        Option::from(serde_json::to_string(&object).unwrap())
                    } else {
                        Option::None
                    }
                } else {
                    Option::None
                }
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

pub async fn send_post(url: String, body: String, content_type: String) -> bool {
    let signature = sign(SignParams {
        url: url.clone(),
        body: Option::from(body.clone()),
        method: Method::Post
    });

    Request::post(&url)
        .header("Enigmatick-Date", &signature.date)
        .header("Digest", &signature.digest.unwrap())
        .header("Signature", &signature.signature)
        .header("Content-Type", &content_type)
        .body(body)
        .send().await.is_ok()
}

pub async fn send_updated_identity_cache() -> bool {
    let state = &*ENIGMATICK_STATE;
    let keystore: Option<KeyStore> = { if let Ok(x) = state.try_lock() {
        x.clone().get_keystore()
    } else {
        Option::None
    }};

    let profile: Option<Profile> = { if let Ok(x) = state.try_lock() {
        x.clone().get_profile()
    } else {
        Option::None
    }};

    if let (Some(keystore), Some(profile)) = (keystore, profile) {
        let url = format!("https://enigmatick.jdt.dev/api/user/{}/update_identity_cache",
                          profile.username);

        let data = serde_json::to_string(&keystore).unwrap();
        send_post(url, data, "application/json".to_string()).await
    } else {
        false
    }
}

pub async fn send_updated_olm_sessions() -> bool {
    let state = &*ENIGMATICK_STATE;
    let keystore: Option<KeyStore> = { if let Ok(x) = state.try_lock() {
        x.clone().get_keystore()
    } else {
        Option::None
    }};

    let profile: Option<Profile> = { if let Ok(x) = state.try_lock() {
        x.clone().get_profile()
    } else {
        Option::None
    }};

    if let (Some(keystore), Some(profile)) = (keystore, profile) {
        let url = format!("https://enigmatick.jdt.dev/api/user/{}/update_olm_sessions",
                          profile.username);

        let data = serde_json::to_string(&keystore).unwrap();
        send_post(url, data, "application/json".to_string()).await
    } else {
        false
    }
}

#[wasm_bindgen]
pub fn update_keystore_olm_sessions(olm_sessions: String) -> bool {
    if let Ok(mut x) = (*ENIGMATICK_STATE).try_lock() {
        if let Some(derived_key) = &x.derived_key {
            let derived_key = SecretKey::from_slice(&decode(derived_key).unwrap()).unwrap();
            
            if let Ok(ciphertext) = aead::seal(&derived_key, olm_sessions.as_bytes()) {
                let mut keystore = x.keystore.clone().unwrap();
                keystore.olm_sessions = encode(ciphertext);
                x.keystore = Option::from(keystore);
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

#[wasm_bindgen]
pub fn get_olm_session(ap_id: String) -> Option<String> {
    if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
        x.get_olm_session(ap_id)
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn get_external_identity_key(ap_id: String) -> Option<String> {
    if let Ok(x) = (*ENIGMATICK_STATE).try_lock() {
        x.get_external_identity_key(ap_id)
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub async fn send_note(params: SendParams) -> bool {
    // I'm probably doing this badly; I'm trying to appease the compiler
    // warning me about holding the lock across the await further down
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};

    log("in send_note");
    
    if let Some(state) = state {
        log("in state");
        if state.is_authenticated() {
            log("in authenticated");
            if let Some(profile) = &state.profile {
                log("in profile");

                let outbox = format!("https://enigmatick.jdt.dev/user/{}/outbox",
                                     profile.username.clone());
                
                let id = format!("https://enigmatick.jdt.dev/user/{}", profile.username.clone());
                let mut note = ApNote::from(params);
                note.attributed_to = id;

                send_post(outbox,
                          serde_json::to_string(&note).unwrap(),
                          "application/activity+json".to_string()).await
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

#[wasm_bindgen]
pub async fn send_encrypted_note(params: SendParams) -> bool {
    // I'm probably doing this badly; I'm trying to appease the compiler
    // warning me about holding the lock across the await further down
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};

    log("in send_encrypted_note");
    
    if let Some(state) = state {
        log("in state");
        if state.is_authenticated() {
            log("in authenticated");
            if let Some(profile) = &state.profile {
                log("in profile");

                let outbox = format!("https://enigmatick.jdt.dev/user/{}/outbox",
                                     profile.username.clone());
                
                let id = format!("https://enigmatick.jdt.dev/user/{}", profile.username.clone());
                let mut encrypted_message = ApNote::from(params);
                encrypted_message.attributed_to = id;

                
                if send_post(outbox,
                             serde_json::to_string(&encrypted_message).unwrap(),
                             "application/activity+json".to_string()).await {
                    send_updated_olm_sessions().await
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ApBasicContentType {
    IdentityKey,
    SessionKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApBasicContent {
    #[serde(rename = "type")]
    pub kind: ApBasicContentType,
    pub content: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum ApInstrument {
    Single(Box<ApObject>),
    Multiple(Vec<ApObject>),
    #[default]
    Unknown,
}

// #[derive(Serialize, Deserialize, Default, Debug, Clone)]
// #[serde(rename_all = "camelCase")]
// pub struct ApInstrument {
//     #[serde(rename = "type")]
//     kind: String,
//     content: String,
// }

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApSession {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@context")]
    context: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
    to: String,
    attributed_to: String,
    instrument: ApInstrument,
    reference: Option<String>,
}

impl From<KexInitParams> for ApSession {
    fn from(params: KexInitParams) -> Self {
        ApSession {
            context: Option::from("https://www.w3.org/ns/activitystreams".to_string()),
            kind: "EncryptedSession".to_string(),
            to: params.recipient,
            instrument: ApInstrument::Single(Box::new(ApObject::Basic(ApBasicContent {
                kind: ApBasicContentType::IdentityKey,
                content: params.identity_key
            }))),
            ..Default::default()
        }
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Default)]
pub struct KexInitParams {
    recipient: String,
    identity_key: String
}

#[wasm_bindgen]
impl KexInitParams {
    pub fn new() -> KexInitParams {
        KexInitParams::default()
    }

    pub async fn set_recipient(&mut self, address: String) -> Self {
        self.recipient = get_webfinger(address).await.unwrap_or_default();
        self.clone()
    }

    pub fn set_identity_key(&mut self, key: String) -> Self {
        self.identity_key = key;
        self.clone()
    }
}

#[wasm_bindgen]
pub async fn send_kex_init(params: KexInitParams) -> bool {
    // I'm probably doing this badly; I'm trying to appease the compiler
    // warning me about holding the lock across the await further down
    let state = &*ENIGMATICK_STATE;
    let state = { if let Ok(x) = state.try_lock() { Option::from(x.clone()) } else { Option::None }};

    log("in send_kex_init");
    
    if let Some(state) = state {
        log("in state");
        if state.is_authenticated() {
            log("in authenticated");
            if let Some(profile) = &state.profile {
                log("in profile");

                let outbox = format!("https://enigmatick.jdt.dev/user/{}/outbox",
                                     profile.username.clone());
                
                let id = format!("https://enigmatick.jdt.dev/user/{}", profile.username.clone());
                let mut encrypted_session = ApSession::from(params);
                encrypted_session.attributed_to = id;

                send_post(outbox,
                          serde_json::to_string(&encrypted_session).unwrap(),
                          "application/activity+json".to_string()).await
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

#[derive(Serialize, Deserialize)]
pub struct WebfingerLink {
    rel: String,
    #[serde(rename = "type")]
    kind: Option<String>,
    href: Option<String>,
    template: Option<String>
}

#[derive(Serialize, Deserialize)]
pub struct WebfingerResponse {
    pub subject: String,
    pub aliases: Vec<String>,
    pub links: Vec<WebfingerLink>,
}

#[wasm_bindgen]
pub async fn get_webfinger(address: String) -> Option<String> {
    let address_re = regex::Regex::new(r#"@(.+?)@(.+)"#).unwrap();
    
    if let Some(address_match) = address_re.captures(&address) {
        //let username = &address_match[1].to_string();
        let domain = &address_match[2].to_string();
        
        let url = format!("https://{}/.well-known/webfinger?resource=acct:{}",
                          domain,
                          address.trim_start_matches('@'));

        if let Ok(x) = Request::get(&url).send().await {
            if let Ok(t) = x.json::<WebfingerResponse>().await {

                let mut ret = Option::<String>::None;
                
                for link in t.links {
                    if link.rel == "self" {
                        ret = link.href;
                    }
                }

                ret
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}
