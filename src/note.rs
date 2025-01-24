use anyhow::Result;
use jdt_activity_pub::{
    ApAddress, ApAttachment, ApContext, ApHashtag, ApHashtagType, ApInstrument, ApMention,
    ApMentionType, ApNote, ApNoteType, ApObject, ApTag, Collectible,
};
use jdt_maybe_multiple::MaybeMultiple;
use serde::Serialize;
use std::{collections::HashMap, fmt::Debug};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, create_mls_group, error, get_state, get_string, log, send_get, send_post,
    EnigmatickState, Profile,
};

impl SendParams {
    pub async fn to_note(&mut self) -> ApNote {
        log(&format!("params\n{self:#?}"));
        let state = get_state();
        let mut encrypted = false;

        let mut mentions = self
            .mentions
            .iter()
            .map(|(x, (y, _))| {
                ApTag::Mention(ApMention {
                    kind: ApMentionType::Mention,
                    name: Some(x.to_string()),
                    href: Some(y.to_string()),
                    value: None,
                })
            })
            .collect::<Vec<ApTag>>();

        let mut tag = self
            .hashtags
            .iter()
            .map(|x| {
                ApTag::HashTag(ApHashtag {
                    kind: ApHashtagType::Hashtag,
                    name: x.to_string(),
                    href: format!(
                        "{}/tags/{}",
                        state.server_url.clone().unwrap_or_default(),
                        x.replace('#', "")
                    ),
                })
            })
            .collect::<Vec<ApTag>>();

        tag.append(&mut mentions);

        let tag: MaybeMultiple<ApTag> = tag.into();

        let mut to: Vec<(ApAddress, bool)> = vec![];
        let mut cc: Vec<ApAddress> = vec![];

        if self.is_public {
            to.push((ApAddress::get_public(), false));

            if let Some(profile) = state.get_profile() {
                if let Some(followers) = profile.followers {
                    cc.push(followers.into());
                }
            }

            cc.extend(
                self.clone()
                    .mentions
                    .into_values()
                    .map(|(x, _)| x.into())
                    .collect::<Vec<ApAddress>>(),
            );
        } else {
            to.extend(
                self.clone()
                    .mentions
                    .into_values()
                    .map(|(x, y)| (x.into(), y))
                    .collect::<Vec<(ApAddress, bool)>>(),
            );

            if to.len() == 1 && cc.is_empty() {
                if let Some((address, enigmatick)) = to.first() {
                    log(&format!("Sending to single address : {address}"));
                    encrypted = *enigmatick;
                    if encrypted {
                        encrypt_note(self).await.unwrap();
                    }
                }
            }
        }

        let instrument = {
            if encrypted {
                let instruments = self.get_instruments();

                if instruments.is_empty() {
                    MaybeMultiple::None
                } else {
                    MaybeMultiple::Multiple(instruments.to_owned())
                }
            } else {
                MaybeMultiple::None
            }
        };

        ApNote {
            context: Some(ApContext::default()),
            kind: if encrypted {
                ApNoteType::EncryptedNote
            } else {
                ApNoteType::Note
            },
            to: MaybeMultiple::Multiple(to.iter().map(|(x, _)| x.clone()).collect()),
            cc: cc.into(),
            tag,
            attachment: {
                if let Some(attachments) = self.attachments.clone() {
                    if let Ok(attachments) = serde_json::from_str::<Vec<ApAttachment>>(&attachments)
                    {
                        attachments.into()
                    } else {
                        vec![].into()
                    }
                } else {
                    vec![].into()
                }
            },
            content: self.content.clone(),
            in_reply_to: self.in_reply_to.clone(),
            conversation: self.conversation.clone(),
            instrument,
            ..Default::default()
        }
    }
}

// impl Default for ApNote {
//     fn default() -> ApNote {
//         ApNote {
//             context: Some(ApContext::default()),
//             tag: MaybeMultiple::None,
//             attributed_to: ApAddress::default(),
//             id: None,
//             kind: ApNoteType::Note,
//             to: MaybeMultiple::Multiple(vec![]),
//             url: None,
//             published: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
//             cc: MaybeMultiple::None,
//             replies: None,
//             attachment: MaybeMultiple::None,
//             in_reply_to: None,
//             content: String::new(),
//             summary: None,
//             sensitive: None,
//             conversation: None,
//             content_map: None,
//             instrument: None,
//             ephemeral: None,
//         }
//     }
// }

#[wasm_bindgen]
pub async fn get_local_conversation(uuid: String) -> Option<String> {
    let response = get_string(
        format!("/conversation/{uuid}"),
        None,
        "application/activity+json",
    )
    .await
    .ok()??;

    if let Ok(ApObject::Collection(object)) = serde_json::from_str(&response) {
        object
            .items()
            .map(|items| serde_json::to_string(&items).unwrap())
    } else {
        error(&format!(
            "Failed to convert text to Collection: {response:?}"
        ));
        None
    }
}

#[wasm_bindgen]
pub async fn get_note(id: String) -> Option<String> {
    let path = format!("/api/remote/object?id={}", urlencoding::encode(&id));

    send_get(None, path, "application/json".to_string()).await
}

#[wasm_bindgen]
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendParams {
    attributed_to: String,
    // @name@example.com -> https://example.com/user/name
    // #[wasm_bindgen(skip)]
    // pub recipients: HashMap<String, String>,

    // https://server/user/username - used for EncryptedNotes where tags
    // are undesirable
    //recipient_ids: Vec<String>,

    // @name@example.com -> https://example.com/user/name
    #[wasm_bindgen(skip)]
    pub mentions: HashMap<String, (String, bool)>,
    hashtags: Vec<String>,
    content: String,
    in_reply_to: Option<String>,
    conversation: Option<String>,
    attachments: Option<String>,

    instruments: Vec<ApInstrument>,

    resolves: Option<String>,
    is_public: bool,
}

#[wasm_bindgen]
impl SendParams {
    pub async fn new() -> SendParams {
        let state = get_state();
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            SendParams {
                attributed_to: format!("{server_url}/user/{}", profile.username),
                ..Default::default()
            }
        } else {
            SendParams::default()
        }
    }

    pub fn add_instrument(&mut self, instrument: ApInstrument) -> Self {
        self.instruments.push(instrument);
        self.clone()
    }

    pub fn resolves(&mut self, queue_id: String) -> Self {
        self.resolves = Some(queue_id);
        self.clone()
    }

    fn get_instruments(&mut self) -> &Vec<ApInstrument> {
        &self.instruments
    }

    // pub fn set_encrypted(&mut self) -> Self {
    //     self.is_encrypted = true;
    //     self.clone()
    // }

    pub fn set_public(&mut self) -> Self {
        self.is_public = true;
        self.clone()
    }

    // pub async fn add_recipient_id(&mut self, recipient_id: String, tag: bool) -> Self {
    //     if tag {
    //         if let Some(webfinger) = get_webfinger_from_id(recipient_id.clone()).await {
    //             self.recipients.insert(webfinger, recipient_id);
    //         }
    //     } else {
    //         self.recipient_ids.push(recipient_id);
    //     }

    //     self.clone()
    // }

    // // address: @user@domain.tld
    // pub async fn add_address(&mut self, address: String) -> Self {
    //     let actor = get_actor_from_webfinger(address.clone()).await;

    //     if let Some(actor) = actor {
    //         if let Some(id) = actor.id {
    //             self.recipients.insert(address.clone(), id);
    //         }
    //     }
    //     self.clone()
    // }

    pub fn set_hashtags(&mut self, hashtags: Vec<String>) -> Self {
        self.hashtags = hashtags;
        self.clone()
    }

    pub fn add_mention(&mut self, webfinger: String, id: String, enigmatick: bool) -> Self {
        self.mentions.insert(webfinger, (id, enigmatick));
        self.clone()
    }

    pub fn set_content(&mut self, content: String) -> Self {
        self.content = content;
        self.clone()
    }

    // pub fn get_recipients(&self) -> String {
    //     serde_json::to_string(&self.recipients).unwrap()
    // }

    pub fn get_content(&self) -> String {
        self.content.clone()
    }

    pub fn set_in_reply_to(&mut self, in_reply_to: String) -> Self {
        self.in_reply_to = Some(in_reply_to);
        self.clone()
    }

    pub fn set_conversation(&mut self, conversation: String) -> Self {
        self.conversation = Some(conversation);
        self.clone()
    }

    pub fn set_attachments(&mut self, attachments: String) -> Self {
        self.attachments = Some(attachments);
        self.clone()
    }

    pub fn export(&self) -> String {
        serde_json::to_string(&self.clone()).unwrap()
    }
}

pub async fn encrypt_note(params: &mut SendParams) -> Result<()> {
    if params.conversation.is_some() {
        //use_mls_group(params).await;
    } else {
        create_mls_group(params).await?;
    };

    log(&format!("Params\n{params:#?}"));

    Ok(())
}

#[wasm_bindgen]
pub async fn send_note(params: &mut SendParams) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let id = format!(
            "{}/user/{}",
            state.server_url.unwrap(),
            profile.username.clone()
        );
        let mut note = params.clone().to_note().await;
        note.attributed_to = id.into();

        log(&format!("NOTE\n{}", serde_json::to_string(&note).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&note).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

// #[wasm_bindgen]
// pub async fn send_encrypted_note(params: SendParams) -> bool {
//     authenticated(move |state: EnigmatickState, profile: Profile| async move {
//         log("IN send_encrypted_note");

//         let outbox = format!("/user/{}/outbox", profile.username.clone());

//         let id = format!(
//             "{}/user/{}",
//             state.server_url.unwrap(),
//             profile.username.clone()
//         );

//         let mut encrypted_message = ApNote::from(params.clone());
//         encrypted_message.attributed_to = id.into();

//         if send_post(
//             outbox,
//             serde_json::to_string(&encrypted_message).unwrap(),
//             "application/activity+json".to_string(),
//         )
//         .await
//         .is_some()
//         {
//             if let Some(resolves) = params.clone().resolves {
//                 resolve_processed_item(resolves).await
//             } else {
//                 None
//             }
//         } else {
//             None
//         }
//     })
//     .await
//     .is_some()
// }
