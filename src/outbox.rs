use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ ApObject, ENIGMATICK_STATE, Profile, log};

// #[wasm_bindgen]
// pub async fn get_outbox(username: String, offset: i32, limit: i32) -> Option<String> {
//     let outbox = format!("/user/{username}/outbox?offset={offset}&limit={limit}");

//     if let Ok(resp) = Request::get(&outbox)
//         .header("Content-Type", "application/activity+json")
//         .send().await
//     {
//         if let Ok(ApObject::Collection(object)) = resp.json().await {
//             object.items.map(|items| serde_json::to_string(&items).unwrap())
//         } else {
//             None
//         }
//     } else {
//         None
//     }
// }

fn extract_outbox_elements(url: String) -> (Option<String>, Option<String>, Option<String>) {
    let state = (*ENIGMATICK_STATE).try_lock().ok();
    
    let result = state.as_ref().and_then(|state| state.server_url.clone()).and_then(|server_url| {
        let pattern = format!(r"^{}/user/(.+?)/outbox\??(?:(min|max)=(\d+)&?|(page=true)&?)*$", regex::escape(&server_url));
        let re = regex::Regex::new(&pattern).unwrap();

        let captures = re.captures(&url).unwrap();
        
        if captures.len() == 5 && captures.get(4).map_or(false, |page| page.as_str() == "page=true") {
            Some((
                captures.get(1).map(|x| x.as_str().to_string()),
                captures.get(2).map(|x| x.as_str().to_string()),
                captures.get(3).map(|x| x.as_str().to_string()),
            ))
        } else {
            None
        }
    });

    result.unwrap_or((None, None, None))
}

#[wasm_bindgen]
pub async fn get_outbox(url: String) -> Option<String> {
    log(&format!("REQUEST {url}"));
    let (username, kind, timestamp) = extract_outbox_elements(url);

    log(&format!("USERNAME {username:#?} KIND {kind:#?} TIMESTAMP {timestamp:#?}"));
    
    let outbox = match (username, kind, timestamp) {
        (Some(username), Some(kind), Some(timestamp)) => {
            Some(format!("/user/{username}/outbox?page=true&{kind}={timestamp}"))
        },
        (Some(username), None, None) => Some(format!("/user/{username}/outbox?page=true")),
        _ => None
    };

    log(&format!("OUTBOX {outbox:#?}"));

    if let Some(outbox) = outbox {
        if let Ok(resp) = Request::get(&outbox)
            .header("Content-Type", "application/activity+json")
            .send().await
        {
            if let Ok(ApObject::CollectionPage(object)) = resp.json().await {
                serde_json::to_string(&object).ok()
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}
