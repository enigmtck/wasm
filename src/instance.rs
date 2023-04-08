use gloo_net::http::Request;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ENIGMATICK_STATE, error};

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct RegistrationInformation {
    pub enabled: bool,
    pub approval_required: bool,
    pub message: Option<String>,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ContactInformation {
    pub contact: String,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct InstanceInformation {
    pub domain: String,
    pub url: String,
    pub title: String,
    pub version: String,
    pub source_url: String,
    pub description: String,
    pub registrations: RegistrationInformation,
    pub contact: ContactInformation,
}

#[wasm_bindgen]
pub async fn load_instance_information() -> Option<InstanceInformation> {
    let url = "/api/v2/instance";
    
    if let Ok(x) = Request::get(url).send().await {
        if let Ok(instance) = x.json::<InstanceInformation>().await {
            if let Ok(mut x) = (*ENIGMATICK_STATE).try_lock() {
                x.set_server_name(instance.domain.clone());
                x.set_server_url(instance.url.clone());
                Option::from(instance)
            } else {
                error("UNABLE TO LOCK STATE IN WASM MODULE");
                None
            }           
        } else {
            error("FAILED TO PARSE RETRIEVED INSTANCE INFORMATION");
            None
        }
    } else {
        error("UNABLE TO RETRIEVE INSTANCE INFORMATION");
        None
    }
}
