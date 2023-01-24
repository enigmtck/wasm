use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{log, authenticated, EnigmatickState, Profile, SignParams, sign, Method, ApObject, ApInstrument, ApBasicContentType, ENIGMATICK_STATE, send_updated_identity_cache};


#[wasm_bindgen]
pub async fn get_processing_queue() -> Option<String> {
    log("in get processing_queue");
    
    authenticated(move |state: EnigmatickState, profile: Profile| async move {
        let inbox = format!("/api/user/{}/processing_queue",
                            profile.username.clone());
        
        let signature = sign(SignParams {
            host: state.server_name.unwrap(),
            request_target: inbox.clone(),
            body: Option::None,
            data: Option::None,
            method: Method::Get
        });

        if let Ok(resp) = Request::get(&inbox)
            .header("Enigmatick-Date", &signature.date)
            .header("Signature", &signature.signature)
            .header("Content-Type", "application/activity+json")
            .send().await
        {
            //log(&format!("queue response\n{:#?}", resp.text().await));
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
    }).await
}
