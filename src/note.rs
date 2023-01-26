use gloo_net::http::Request;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, log, send_post};


#[wasm_bindgen]
pub async fn get_note(id: String) -> Option<String> {
    log("in get_note: {id:#?}");
    
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        log("in authenticated");
        
        #[derive(Debug, Clone, Default, Serialize)]
        pub struct NoteParams {
            id: String,
        }
        
        let url = format!("/api/user/{}/remote/note",
                          profile.username.clone());

        log(&format!("{url:#?}"));
        
        let params = NoteParams {
            id
        };

        log(&format!("{params:#?}"));
        
        send_post(url,
                  serde_json::to_string(&params).unwrap(),
                  "application/json".to_string()).await
    }).await 
}
