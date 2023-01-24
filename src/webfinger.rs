use gloo_net::http::Request;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{authenticated, EnigmatickState, Profile, log, send_post};

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
                    if link.rel == "self" {
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
pub async fn get_actor(webfinger: String) -> Option<String> {
    authenticated(move |_: EnigmatickState, profile: Profile| async move {
        #[derive(Debug, Clone, Default, Serialize)]
        pub struct ActorParams {
            webfinger: String,
        }
        
        let url = format!("/api/user/{}/remote",
                          profile.username.clone());

        log(&format!("{url:#?}"));
        
        let params = ActorParams {
            webfinger
        };

        log(&format!("{params:#?}"));
        
        send_post(url,
                  serde_json::to_string(&params).unwrap(),
                  "application/json".to_string()).await
    }).await 
}
