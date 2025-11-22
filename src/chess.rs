use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, log, send_post, EnigmatickState, Profile};

#[wasm_bindgen]
pub async fn send_chess_invite(opponent_id: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let actor_id = state.profile?.id.clone();
        let activity_id = format!("{}/activity/invite/{}", actor_id, Uuid::new_v4());

        // Create Invite activity per ActivityStreams vocabulary
        let invite_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Invite",
            "actor": actor_id,
            "id": activity_id,
            "to": [opponent_id.clone()],
            "cc": [],
            "object": {
                "type": "Object",
                "attributedTo": [actor_id, opponent_id],
                "to": [opponent_id]
            },
            "target": opponent_id,
            "published": Utc::now().to_rfc3339()
        });

        log(&format!("CHESS INVITE\n{}", serde_json::to_string_pretty(&invite_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&invite_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_chess_accept(game_id: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let actor_id = state.profile?.id.clone();
        let activity_id = format!("{}/activity/accept/{}", actor_id, Uuid::new_v4());

        // Create Accept activity per ActivityStreams vocabulary
        let accept_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Accept",
            "actor": actor_id,
            "id": activity_id,
            "to": [],
            "cc": [],
            "object": game_id,
            "published": Utc::now().to_rfc3339()
        });

        log(&format!("CHESS ACCEPT\n{}", serde_json::to_string_pretty(&accept_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&accept_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_chess_move(
    game_id: String,
    from: String,
    to: String,
    promotion: Option<String>,
) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let actor_id = state.profile?.id.clone();
        let activity_id = format!("{}/activity/move/{}", actor_id, Uuid::new_v4());

        // Build move object with custom properties
        let mut move_object = json!({
            "type": "Note",
            "name": format!("{}{}", from, to),
            "origin": from,
            "target": to
        });

        if let Some(promotion_piece) = promotion.clone() {
            move_object["promotion"] = json!(promotion_piece);
        }

        // Create Move activity per ActivityStreams vocabulary
        // Using Update to modify the game object, containing Move in object
        let mut move_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Update",
            "actor": actor_id,
            "id": activity_id,
            "to": [],
            "cc": [],
            "object": {
                "type": "Move",
                "actor": actor_id,
                "origin": from,
                "target": to,
                "inReplyTo": game_id,
                "object": move_object
            },
            "target": game_id,
            "published": Utc::now().to_rfc3339()
        });

        if let Some(promotion_piece) = promotion.clone() {
            move_activity["object"]["promotion"] = json!(promotion_piece);
        }

        log(&format!("CHESS MOVE\n{}", serde_json::to_string_pretty(&move_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&move_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_chess_resign(game_id: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());

        let actor_id = state.profile?.id.clone();
        let activity_id = format!("{}/activity/update/{}", actor_id, Uuid::new_v4());

        // Create Update activity to resign the game
        let update_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Update",
            "actor": actor_id,
            "id": activity_id,
            "to": [],
            "cc": [],
            "object": {
                "type": "Object",
                "id": game_id,
                "gameStatus": "resigned"
            },
            "target": game_id,
            "published": Utc::now().to_rfc3339()
        });

        log(&format!("CHESS RESIGN\n{}", serde_json::to_string_pretty(&update_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&update_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

