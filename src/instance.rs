use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{get_object, update_state};

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
pub async fn load_instance_information(url: Option<String>) -> Option<InstanceInformation> {
    let url = format!("{}/api/v2/instance", url.unwrap_or_default());

    let instance: InstanceInformation = get_object(url, None, "application/json").await.ok()?;

    update_state(|state| {
        state.set_server_name(instance.domain.clone());
        state.set_server_url(instance.url.clone());
        Ok(())
    })
    .ok();

    Some(instance)
}
