use serde::{Deserialize, Serialize};

use crate::{ApActivity, ApAnnounce, ApContext, ApFollow, ApLike, MaybeReference};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum ApUndoType {
    #[default]
    Undo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApUndo {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApContext>,
    #[serde(rename = "type")]
    pub kind: ApUndoType,
    pub actor: String,
    pub id: Option<String>,
    pub object: MaybeReference<ApActivity>,
}

impl From<ApFollow> for ApUndo {
    fn from(follow: ApFollow) -> Self {
        ApUndo {
            context: Some(ApContext::default()),
            kind: ApUndoType::default(),
            actor: follow.actor.clone(),
            id: follow.id.clone().map(|follow| format!("{}#undo", follow)),
            object: MaybeReference::Actual(ApActivity::Follow(follow)),
        }
    }
}

impl From<ApLike> for ApUndo {
    fn from(like: ApLike) -> Self {
        ApUndo {
            context: Some(ApContext::default()),
            kind: ApUndoType::default(),
            actor: like.actor.clone(),
            id: like.id.clone().map(|like| format!("{}#undo", like)),
            object: MaybeReference::Actual(ApActivity::Like(Box::new(like))),
        }
    }
}

impl From<ApAnnounce> for ApUndo {
    fn from(announce: ApAnnounce) -> Self {
        ApUndo {
            context: Some(ApContext::default()),
            kind: ApUndoType::default(),
            actor: announce.actor.clone(),
            id: announce
                .id
                .clone()
                .map(|announce| format!("{}#undo", announce)),
            object: MaybeReference::Actual(ApActivity::Announce(announce)),
        }
    }
}
