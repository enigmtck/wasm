use gloo_net::http::Request;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, log, send_post, ApActor};

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
                    if link.rel == "self" && link.kind == Some("application/activity+json".to_string()) {
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

#[wasm_bindgen]
pub async fn get_actor(id: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        #[derive(Debug, Clone, Default, Serialize)]
        pub struct ActorParams {
            id: String,
        }
        
        let url = format!("/api/user/{}/remote/actor",
                          profile.username.clone());

        log(&format!("{url:#?}"));
        
        let params = ActorParams {
            id
        };

        log(&format!("{params:#?}"));
        
        send_post(url,
                  serde_json::to_string(&params).unwrap(),
                  "application/json".to_string()).await
    }).await 
}

#[wasm_bindgen]
pub async fn get_webfinger_from_id(id: String) -> Option<String> {
    log(&format!("ID: {id}"));
    if let Some(actor) = get_actor(id.clone()).await {
        log(&format!("ACTOR\n{actor:#?}"));
        match serde_json::from_str::<ApActor>(&actor) {
            Ok(actor) => {
                let id_re = regex::Regex::new(r#"https://([a-zA-Z0-9\-\.]+?)/.+"#).unwrap();
                if let Some(captures) = id_re.captures(&id.clone()) {
                    if let Some(server_name) = captures.get(1) {
                        Option::from(format!("@{}@{}", actor.preferred_username, server_name.as_str()))
                    } else {
                        log("INSUFFICIENT REGEX CAPTURES");
                        Option::None
                    }
                } else {
                    log("FAILED TO MATCH PATTERN");
                    Option::None
                }
            }   
            Err(e) => {
                log(&format!("FAILED TO DESERIALIZE ACTOR\n{e:#?}"));
                Option::None
            }
        }
    } else {
        log("FAILED TO RETRIEVE ACTOR");
        Option::None
    }
}
