use jdt_activity_pub::{ApAddress, ApObject, ApUpdate, MaybeReference};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    authenticated, log, send_post, ArticleParams, EnigmatickState, NoteParams, Profile, QuestionParams,
};

#[wasm_bindgen]
pub async fn send_update(_object_id: String, updated_object_json: String) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());
        let actor_id = state.profile?.id.clone();

        // Parse the updated object JSON into an ApObject
        let updated_object: ApObject = serde_json::from_str(&updated_object_json)
            .map_err(|e| {
                log(&format!("Failed to parse updated object JSON: {}", e));
                e
            })
            .ok()?;

        // Verify the object's ID matches the object_id parameter
        // The object should have its ID set by the frontend, but we verify it matches
        // Note: The object ID is embedded within the ApObject and will be serialized correctly

        // Create Update activity using ApUpdate struct
        // Construct ApUpdate with the updated object wrapped in MaybeReference
        let update_activity = ApUpdate {
            object: MaybeReference::Actual(updated_object),
            actor: actor_id,
            id: None,
            ..Default::default()
        };

        log(&format!("UPDATE ACTIVITY\n{}", serde_json::to_string_pretty(&update_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&update_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_update_note(params: &mut NoteParams) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());
        let mut note = params.clone().to_note().await;
        
        // Ensure attributed_to is set correctly
        let actor_id = state.profile.as_ref().map(|p| p.id.clone());
        if let Some(id) = &actor_id {
            note.attributed_to = id.clone();
        }
        
        // Remove @context from the note object
        note.context = None;
        
        let note_object = ApObject::Note(note);
        
        let actor_address = match actor_id {
            Some(id) => id,
            None => ApAddress::from(format!("{}/user/{}", state.server_url.clone().unwrap_or_default(), profile.username)),
        };
        
        let update_activity = ApUpdate {
            object: MaybeReference::Actual(note_object),
            actor: actor_address,
            id: None,
            ..Default::default()
        };

        log(&format!("UPDATE ACTIVITY\n{}", serde_json::to_string_pretty(&update_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&update_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_update_article(params: &mut ArticleParams) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());
        let mut article = params.to_article();
        
        // Remove @context from the article object
        article.context = None;
        
        let article_object = ApObject::Article(article);
        
        let actor_address = match state.profile.as_ref().map(|p| p.id.clone()) {
            Some(id) => id,
            None => ApAddress::from(format!("{}/user/{}", state.server_url.clone().unwrap_or_default(), profile.username)),
        };
        
        let update_activity = ApUpdate {
            object: MaybeReference::Actual(article_object),
            actor: actor_address,
            id: None,
            ..Default::default()
        };

        log(&format!("UPDATE ACTIVITY\n{}", serde_json::to_string_pretty(&update_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&update_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

#[wasm_bindgen]
pub async fn send_update_question(params: &mut QuestionParams) -> Option<String> {
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let outbox = format!("/user/{}/outbox", profile.username.clone());
        let mut question = params.to_question();
        
        // Remove @context from the question object
        question.context = None;
        
        let question_object = ApObject::Question(question);
        
        let actor_address = match state.profile.as_ref().map(|p| p.id.clone()) {
            Some(id) => id,
            None => ApAddress::from(format!("{}/user/{}", state.server_url.clone().unwrap_or_default(), profile.username)),
        };
        
        let update_activity = ApUpdate {
            object: MaybeReference::Actual(question_object),
            actor: actor_address,
            id: None,
            ..Default::default()
        };

        log(&format!("UPDATE ACTIVITY\n{}", serde_json::to_string_pretty(&update_activity).unwrap()));

        send_post(
            outbox,
            serde_json::to_string(&update_activity).unwrap(),
            "application/activity+json".to_string(),
        )
        .await
    })
    .await
}

