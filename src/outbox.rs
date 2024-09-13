use gloo_net::http::Request;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ ApObject, get_state, log};

fn extract_outbox_elements(url: String) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let state = get_state();
    
    let result = state.server_url.clone().and_then(|server_url| {
        log(&format!("OUTBOX {url}"));

        let pattern = format!(r"^{}/user/(.+?)/outbox(?:\?(?:limit=(\d+))?(?:&(min|max)=(\d+))?)?*$", regex::escape(&server_url));
        let re = regex::Regex::new(&pattern).unwrap();

        let captures = re.captures(&url).unwrap();

        log(&format!("CAPTURES {captures:#?}"));
        
        if captures.len() == 5 {
            Some((
                captures.get(1).map(|x| x.as_str().to_string()),
                captures.get(2).map(|x| x.as_str().to_string()),
                captures.get(3).map(|x| x.as_str().to_string()),
                captures.get(4).map(|x| x.as_str().to_string()),
            ))
        } else {
            None
        }
    });

    result.unwrap_or((None, None, None, None))
}

#[wasm_bindgen]
pub async fn get_outbox(url: String) -> Option<String> {
    log(&format!("REQUEST {url}"));
    let (username, limit, kind, timestamp) = extract_outbox_elements(url);

    log(&format!("LIMIT {limit:#?} USERNAME {username:#?} KIND {kind:#?} TIMESTAMP {timestamp:#?}"));
    
    let outbox = match (username, kind, timestamp) {
        (Some(username), Some(kind), Some(timestamp)) => {
            Some(format!("/user/{username}/outbox?{kind}={timestamp}"))
        },
        (Some(username), None, None) => Some(format!("/user/{username}/outbox")),
        _ => None
    };

    log(&format!("OUTBOX {outbox:#?}"));

    let resp = Request::get(&outbox?)
        .header("Content-Type", "application/activity+json")
        .send()
        .await
        .ok()?;
    
    if let Ok(ApObject::Collection(object)) = resp.json().await {
        serde_json::to_string(&object).ok()
    } else {
        None
    }
}
