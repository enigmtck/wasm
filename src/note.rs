use anyhow::Result;
use chrono::Utc;
use jdt_activity_pub::{
    ApAddress, ApArticle, ApAttachment, ApContext, ApDateTime, ApHashtag, ApHashtagType, ApInstrument, ApMention,
    ApMentionType, ApNote, ApNoteType, ApObject, ApQuestion, ApSource, ApTag, Collectible, MaybeReference, QuestionNote,
};
use jdt_activity_pub::MaybeMultiple;
use serde::Serialize;
use std::{collections::HashMap, fmt::Debug};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, create_mls_group, error, get_state, get_string, log, send_get, send_post,
    EnigmatickState, Profile,
};

impl NoteParams {
    pub async fn to_note(&mut self) -> ApNote {
        //log(&format!("params\n{self:#?}"));
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
                ApTag::Hashtag(ApHashtag {
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

        // If preserve_to/preserve_cc are set, use them (for updates)
        if let Some(to_json) = &self.preserve_to {
            if let Ok(to_addresses) = serde_json::from_str::<Vec<String>>(to_json) {
                to = to_addresses
                    .iter()
                    .map(|addr| (ApAddress::from(addr.clone()), false))
                    .collect();
            }
        }
        if let Some(cc_json) = &self.preserve_cc {
            if let Ok(cc_addresses) = serde_json::from_str::<Vec<String>>(cc_json) {
                cc = cc_addresses
                    .iter()
                    .map(|addr| ApAddress::from(addr.clone()))
                    .collect();
            }
        }

        // If preserve_to/preserve_cc weren't set, build from scratch (for new notes)
        if to.is_empty() && cc.is_empty() {
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
                    if let Some((_address, enigmatick)) = to.first() {
                        //log(&format!("Sending to single address : {_address}"));
                        encrypted = *enigmatick;
                        if encrypted {
                            encrypt_note(self).await.unwrap();
                        }
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

        let source = if let (Some(content), Some(media_type)) = (&self.source_content, &self.source_media_type) {
            Some(ApSource {
                content: content.clone(),
                media_type: media_type.clone(),
            })
        } else {
            None
        };

        ApNote {
            context: Some(ApContext::default()),
            id: self.id.clone(),
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
            content: Some(self.content.clone()),
            in_reply_to: {
                if let Some(in_reply_to) = self.in_reply_to.clone() {
                    MaybeMultiple::Single(MaybeReference::Reference(in_reply_to))
                } else {
                    MaybeMultiple::None
                }
            },
            conversation: self.conversation.clone(),
            instrument,
            source,
            ..Default::default()
        }
    }
}

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
pub struct NoteParams {
    id: Option<String>,
    attributed_to: String,
    // @name@example.com -> https://example.com/user/name
    #[wasm_bindgen(skip)]
    pub mentions: HashMap<String, (String, bool)>,
    hashtags: Vec<String>,
    content: String,
    in_reply_to: Option<String>,
    conversation: Option<String>,
    attachments: Option<String>,
    source_content: Option<String>,
    source_media_type: Option<String>,
    instruments: Vec<ApInstrument>,
    resolves: Option<String>,
    is_public: bool,
    // For preserving original to/cc lists during updates
    preserve_to: Option<String>, // JSON array of addresses
    preserve_cc: Option<String>, // JSON array of addresses
}

#[wasm_bindgen]
impl NoteParams {
    pub async fn new() -> NoteParams {
        let state = get_state();
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            NoteParams {
                attributed_to: format!("{server_url}/user/{}", profile.username),
                ..Default::default()
            }
        } else {
            NoteParams::default()
        }
    }

    pub fn set_id(&mut self, id: String) -> Self {
        self.id = Some(id);
        self.clone()
    }

    pub fn set_source(&mut self, content: String, media_type: String) -> Self {
        self.source_content = Some(content);
        self.source_media_type = Some(media_type);
        self.clone()
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

    pub fn set_preserve_to(&mut self, to_json: String) -> Self {
        self.preserve_to = Some(to_json);
        self.clone()
    }

    pub fn set_preserve_cc(&mut self, cc_json: String) -> Self {
        self.preserve_cc = Some(cc_json);
        self.clone()
    }

    pub fn export(&self) -> String {
        serde_json::to_string(&self.clone()).unwrap()
    }
}

// Article builder struct
#[wasm_bindgen]
#[derive(Debug, Clone, Default, Serialize)]
pub struct ArticleParams {
    id: Option<String>,
    name: Option<String>,
    summary: Option<String>,
    content: String,
    attributed_to: String,
    published: String,
    in_reply_to: Option<String>,
    conversation: Option<String>,
    #[wasm_bindgen(skip)]
    pub mentions: HashMap<String, (String, bool)>,
    hashtags: Vec<String>,
    attachments: Option<String>,
    source_content: Option<String>,
    source_media_type: Option<String>,
    is_public: bool,
    // For preserving original to/cc lists during updates
    preserve_to: Option<String>, // JSON array of addresses
    preserve_cc: Option<String>, // JSON array of addresses
}

#[wasm_bindgen]
impl ArticleParams {
    pub async fn new() -> ArticleParams {
        let state = get_state();
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            ArticleParams {
                attributed_to: format!("{server_url}/user/{}", profile.username),
                published: chrono::Utc::now().to_rfc3339(),
                ..Default::default()
            }
        } else {
            ArticleParams::default()
        }
    }

    pub fn set_id(&mut self, id: String) -> Self {
        self.id = Some(id);
        self.clone()
    }

    pub fn set_name(&mut self, name: String) -> Self {
        self.name = Some(name);
        self.clone()
    }

    pub fn set_summary(&mut self, summary: String) -> Self {
        self.summary = Some(summary);
        self.clone()
    }

    pub fn set_content(&mut self, content: String) -> Self {
        self.content = content;
        self.clone()
    }

    pub fn set_public(&mut self) -> Self {
        self.is_public = true;
        self.clone()
    }

    pub fn set_hashtags(&mut self, hashtags: Vec<String>) -> Self {
        self.hashtags = hashtags;
        self.clone()
    }

    pub fn add_mention(&mut self, webfinger: String, id: String, enigmatick: bool) -> Self {
        self.mentions.insert(webfinger, (id, enigmatick));
        self.clone()
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

    pub fn set_source(&mut self, content: String, media_type: String) -> Self {
        self.source_content = Some(content);
        self.source_media_type = Some(media_type);
        self.clone()
    }

    pub fn set_preserve_to(&mut self, to_json: String) -> Self {
        self.preserve_to = Some(to_json);
        self.clone()
    }

    pub fn set_preserve_cc(&mut self, cc_json: String) -> Self {
        self.preserve_cc = Some(cc_json);
        self.clone()
    }

    // Internal method - not exposed to WASM
    pub(crate) fn to_article(&self) -> ApArticle {
        let state = get_state();
        let server_url = state.server_url.clone().unwrap_or_default();

        // Build tags (hashtags + mentions)
        let mut mentions_tags: Vec<ApTag> = self
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
            .collect();

        let mut hashtag_tags: Vec<ApTag> = self
            .hashtags
            .iter()
            .map(|x| {
                ApTag::Hashtag(ApHashtag {
                    kind: ApHashtagType::Hashtag,
                    name: x.to_string(),
                    href: format!("{}/tags/{}", server_url, x.replace('#', "")),
                })
            })
            .collect();

        hashtag_tags.append(&mut mentions_tags);
        let tag: MaybeMultiple<ApTag> = hashtag_tags.into();

        // Build to/cc addresses
        let mut to: Vec<(ApAddress, bool)> = vec![];
        let mut cc: Vec<ApAddress> = vec![];

        // If preserve_to/preserve_cc are set, use them (for updates)
        if let Some(to_json) = &self.preserve_to {
            if let Ok(to_addresses) = serde_json::from_str::<Vec<String>>(to_json) {
                to = to_addresses
                    .iter()
                    .map(|addr| (ApAddress::from(addr.clone()), false))
                    .collect();
            }
        }
        if let Some(cc_json) = &self.preserve_cc {
            if let Ok(cc_addresses) = serde_json::from_str::<Vec<String>>(cc_json) {
                cc = cc_addresses
                    .iter()
                    .map(|addr| ApAddress::from(addr.clone()))
                    .collect();
            }
        }

        // If preserve_to/preserve_cc weren't set, build from scratch (for new notes)
        if to.is_empty() && cc.is_empty() {
            if self.is_public {
                to.push((ApAddress::get_public(), false));
                if let Some(profile) = state.get_profile() {
                    if let Some(followers) = profile.followers {
                        cc.push(ApAddress::from(followers));
                    }
                }
                cc.extend(
                    self.mentions
                        .iter()
                        .map(|(_, (id, _))| ApAddress::from(id.clone()))
                        .collect::<Vec<ApAddress>>(),
                );
            } else {
                to.extend(
                    self.mentions
                        .iter()
                        .map(|(_, (id, enigmatick))| (ApAddress::from(id.clone()), *enigmatick))
                        .collect::<Vec<(ApAddress, bool)>>(),
                );
            }
        }

        // Build attachments
        let attachment: MaybeMultiple<ApAttachment> = if let Some(attachments_str) = &self.attachments {
            if let Ok(attachments) = serde_json::from_str::<Vec<ApAttachment>>(attachments_str) {
                attachments.into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };

        // Build source
        let source = if let (Some(content), Some(media_type)) = (&self.source_content, &self.source_media_type) {
            Some(ApSource {
                content: content.clone(),
                media_type: media_type.clone(),
            })
        } else {
            None
        };

        // ApArticle.published is ApDateTime (not Option)
        let published_dt = chrono::DateTime::parse_from_rfc3339(&self.published)
            .ok()
            .map(|dt| ApDateTime::from(dt.with_timezone(&Utc)))
            .unwrap_or_else(|| ApDateTime::from(Utc::now()));

        ApArticle {
            context: Some(ApContext::default()),
            id: self.id.clone(),
            name: self.name.clone(),
            summary: self.summary.clone(),
            content: Some(self.content.clone()),
            attributed_to: ApAddress::from(self.attributed_to.clone()),
            published: published_dt,
            to: MaybeMultiple::Multiple(to.iter().map(|(x, _)| x.clone()).collect()),
            cc: cc.into(),
            tag,
            attachment,
            in_reply_to: {
                if let Some(in_reply_to) = &self.in_reply_to {
                    MaybeMultiple::Single(MaybeReference::Reference(in_reply_to.clone()))
                } else {
                    MaybeMultiple::None
                }
            },
            source,
            ..Default::default()
        }
    }
}

// Question builder struct
#[wasm_bindgen]
#[derive(Debug, Clone, Default, Serialize)]
pub struct QuestionParams {
    id: Option<String>,
    content: String,
    attributed_to: String,
    published: String,
    in_reply_to: Option<String>,
    conversation: Option<String>,
    #[wasm_bindgen(skip)]
    pub mentions: HashMap<String, (String, bool)>,
    hashtags: Vec<String>,
    attachments: Option<String>,
    source_content: Option<String>,
    source_media_type: Option<String>,
    poll_type: String, // "oneOf" or "anyOf"
    poll_options: Vec<String>,
    end_time: Option<String>,
    is_public: bool,
    // For preserving original to/cc lists during updates
    preserve_to: Option<String>, // JSON array of addresses
    preserve_cc: Option<String>, // JSON array of addresses
}

#[wasm_bindgen]
impl QuestionParams {
    pub async fn new() -> QuestionParams {
        let state = get_state();
        if let (Some(profile), Some(server_url)) = (state.profile, state.server_url) {
            QuestionParams {
                attributed_to: format!("{server_url}/user/{}", profile.username),
                published: chrono::Utc::now().to_rfc3339(),
                poll_type: "oneOf".to_string(),
                ..Default::default()
            }
        } else {
            QuestionParams::default()
        }
    }

    pub fn set_id(&mut self, id: String) -> Self {
        self.id = Some(id);
        self.clone()
    }

    pub fn set_content(&mut self, content: String) -> Self {
        self.content = content;
        self.clone()
    }

    pub fn set_public(&mut self) -> Self {
        self.is_public = true;
        self.clone()
    }

    pub fn set_hashtags(&mut self, hashtags: Vec<String>) -> Self {
        self.hashtags = hashtags;
        self.clone()
    }

    pub fn add_mention(&mut self, webfinger: String, id: String, enigmatick: bool) -> Self {
        self.mentions.insert(webfinger, (id, enigmatick));
        self.clone()
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

    pub fn set_source(&mut self, content: String, media_type: String) -> Self {
        self.source_content = Some(content);
        self.source_media_type = Some(media_type);
        self.clone()
    }

    pub fn set_poll_type(&mut self, poll_type: String) -> Self {
        self.poll_type = poll_type;
        self.clone()
    }

    pub fn set_poll_options(&mut self, options: Vec<String>) -> Self {
        self.poll_options = options;
        self.clone()
    }

    pub fn set_end_time(&mut self, end_time: String) -> Self {
        self.end_time = Some(end_time);
        self.clone()
    }

    pub fn set_preserve_to(&mut self, to_json: String) -> Self {
        self.preserve_to = Some(to_json);
        self.clone()
    }

    pub fn set_preserve_cc(&mut self, cc_json: String) -> Self {
        self.preserve_cc = Some(cc_json);
        self.clone()
    }

    // Internal method - not exposed to WASM
    pub(crate) fn to_question(&self) -> ApQuestion {
        let state = get_state();
        let server_url = state.server_url.clone().unwrap_or_default();

        // Build tags (hashtags + mentions)
        let mut mentions_tags: Vec<ApTag> = self
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
            .collect();

        let mut hashtag_tags: Vec<ApTag> = self
            .hashtags
            .iter()
            .map(|x| {
                ApTag::Hashtag(ApHashtag {
                    kind: ApHashtagType::Hashtag,
                    name: x.to_string(),
                    href: format!("{}/tags/{}", server_url, x.replace('#', "")),
                })
            })
            .collect();

        hashtag_tags.append(&mut mentions_tags);
        let tag: MaybeMultiple<ApTag> = hashtag_tags.into();

        // Build to/cc addresses
        let mut to: Vec<(ApAddress, bool)> = vec![];
        let mut cc: Vec<ApAddress> = vec![];

        // If preserve_to/preserve_cc are set, use them (for updates)
        if let Some(to_json) = &self.preserve_to {
            if let Ok(to_addresses) = serde_json::from_str::<Vec<String>>(to_json) {
                to = to_addresses
                    .iter()
                    .map(|addr| (ApAddress::from(addr.clone()), false))
                    .collect();
            }
        }
        if let Some(cc_json) = &self.preserve_cc {
            if let Ok(cc_addresses) = serde_json::from_str::<Vec<String>>(cc_json) {
                cc = cc_addresses
                    .iter()
                    .map(|addr| ApAddress::from(addr.clone()))
                    .collect();
            }
        }

        // If preserve_to/preserve_cc weren't set, build from scratch (for new notes)
        if to.is_empty() && cc.is_empty() {
            if self.is_public {
                to.push((ApAddress::get_public(), false));
                if let Some(profile) = state.get_profile() {
                    if let Some(followers) = profile.followers {
                        cc.push(ApAddress::from(followers));
                    }
                }
                cc.extend(
                    self.mentions
                        .iter()
                        .map(|(_, (id, _))| ApAddress::from(id.clone()))
                        .collect::<Vec<ApAddress>>(),
                );
            } else {
                to.extend(
                    self.mentions
                        .iter()
                        .map(|(_, (id, enigmatick))| (ApAddress::from(id.clone()), *enigmatick))
                        .collect::<Vec<(ApAddress, bool)>>(),
                );
            }
        }

        // Build attachments
        let attachment: MaybeMultiple<ApAttachment> = if let Some(attachments_str) = &self.attachments {
            if let Ok(attachments) = serde_json::from_str::<Vec<ApAttachment>>(attachments_str) {
                attachments.into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };

        // Build poll options as QuestionNote (used in oneOf/anyOf)
        let question_options: Vec<QuestionNote> = self
            .poll_options
            .iter()
            .map(|option| {
                QuestionNote {
                    name: option.clone(),
                    attributed_to: Some(self.attributed_to.clone()),
                    kind: ApNoteType::Note,
                    ..Default::default()
                }
            })
            .collect();

        let one_of = if self.poll_type == "oneOf" {
            question_options.clone().into()
        } else {
            MaybeMultiple::None
        };

        let any_of = if self.poll_type == "anyOf" {
            question_options.into()
        } else {
            MaybeMultiple::None
        };

        // Build source
        let source = if let (Some(content), Some(media_type)) = (&self.source_content, &self.source_media_type) {
            Some(ApSource {
                content: content.clone(),
                media_type: media_type.clone(),
            })
        } else {
            None
        };

        // ApQuestion.published is Option<ApDateTime>
        let published_dt = chrono::DateTime::parse_from_rfc3339(&self.published)
            .ok()
            .map(|dt| ApDateTime::from(dt.with_timezone(&Utc)));

        ApQuestion {
            context: Some(ApContext::default()),
            id: self.id.clone(),
            content: Some(self.content.clone()),
            attributed_to: ApAddress::from(self.attributed_to.clone()),
            published: published_dt,
            to: MaybeMultiple::Multiple(to.iter().map(|(x, _)| x.clone()).collect()),
            cc: cc.into(),
            tag,
            attachment,
            in_reply_to: {
                if let Some(in_reply_to) = &self.in_reply_to {
                    MaybeMultiple::Single(MaybeReference::Reference(in_reply_to.clone()))
                } else {
                    MaybeMultiple::None
                }
            },
            source,
            one_of,
            any_of,
            end_time: self.end_time.clone()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok())
                .map(|dt| ApDateTime::from(dt.with_timezone(&Utc))),
            ..Default::default()
        }
    }
}

pub async fn encrypt_note(params: &mut NoteParams) -> Result<()> {
    if params.conversation.is_some() {
        //use_mls_group(params).await;
    } else {
        create_mls_group(params).await?;
    };

    //log(&format!("Params\n{params:#?}"));

    Ok(())
}

#[wasm_bindgen]
pub async fn send_note(params: &mut NoteParams) -> Option<String> {
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

#[wasm_bindgen]
pub async fn send_vote(option_name: String, question_id: String, question_author: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let actor_id = format!(
            "{}/user/{}",
            state.server_url.unwrap(),
            profile.username.clone()
        );

        // Create a vote note according to Mastodon's ActivityPub specification
        let vote_note = ApNote {
            context: Some(ApContext::default()),
            kind: ApNoteType::Note,
            name: Some(option_name.clone()),
            content: None,
            attributed_to: actor_id.into(),
            to: vec![question_author.into()].into(),
            in_reply_to: MaybeMultiple::Single(MaybeReference::Reference(question_id)),
            ..Default::default()
        };

        log(&format!("VOTE NOTE\n{}", serde_json::to_string(&vote_note).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&vote_note).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_question(question_json: String) -> Option<String> {
    authenticated(move |_state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        log(&format!("QUESTION JSON\n{}", question_json));

        // Send just the Question object - server will wrap it in a Create Activity
        send_post(
            outbox,
            question_json,
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
