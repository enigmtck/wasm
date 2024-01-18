use gloo_net::http::Request;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::update_state;

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

    let resp = Request::get(url).send().await.ok()?;
    let instance = resp.json::<InstanceInformation>().await.ok()?;
    
    update_state(|state| {
        state.set_server_name(instance.domain.clone());
        state.set_server_url(instance.url.clone());
        Ok(())
    }).ok();
    
    Some(instance)
}
