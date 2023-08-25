use std::sync::Arc;

use log::trace;
use reqwest::Certificate;

use super::{
    config_file::SlotConfig,
    device::{Device, Slot},
};

const DEFAULT_USER_AGENT: &str = "pkcs11-rs/0.1.0";

#[derive(Debug)]
pub enum InitializationError {
    Config(crate::config::config_file::ConfigError),
    Reqwest(reqwest::Error),
    NoUser(String),
    ReadFile(std::io::Error),
}

pub fn initialize_configuration() -> Result<Device, InitializationError> {
    let config =
        crate::config::config_file::read_configuration().map_err(InitializationError::Config)?;
    crate::config::logging::configure_logger(&config);

    // initialize the clients
    let mut slots = vec![];
    for slot in config.slots.iter() {
        slots.push(Arc::new(slot_from_config(slot)?));
    }

    Ok(Device {
        slots,
        log_file: config.log_file,
        enable_set_attribute_value: config.enable_set_attribute_value,
    })
}

pub fn slot_from_config(slot: &SlotConfig) -> Result<Slot, InitializationError> {
    let mut instances = vec![];

    let default_user = slot
        .operator
        .as_ref()
        .or(slot.administrator.as_ref())
        .ok_or(InitializationError::NoUser(slot.label.clone()))?;

    for instance in slot.instances.iter() {
        let mut reqwest_builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(instance.danger_insecure_cert)
            .pool_max_idle_per_host(2);
        // .tcp_keepalive(Some(std::time::Duration::from_secs(20)))
        // .pool_idle_timeout(std::time::Duration::from_secs(10))
        // .timeout(std::time::Duration::from_secs(10));
        // .http2_keep_alive_timeout(std::time::Duration::from_secs(10));
        // .http2_keep_alive_while_idle(false);

        if let Some(cert_str) = instance.certificate.as_ref() {
            let cert = Certificate::from_pem(cert_str.trim().as_bytes())
                .map_err(InitializationError::Reqwest)?;
            reqwest_builder = reqwest_builder.add_root_certificate(cert);
            trace!("Added certificate to slot {}", instance.url);
        }
        if let Some(file) = instance.certificate_file.as_ref() {
            let cert = Certificate::from_pem(
                std::fs::read(file)
                    .map_err(InitializationError::ReadFile)?
                    .as_slice(),
            )
            .map_err(InitializationError::Reqwest)?;
            reqwest_builder = reqwest_builder.add_root_certificate(cert);
            trace!("Added certificate to slot {}", instance.url);
        }

        let reqwest_client = reqwest_builder
            .build()
            .map_err(InitializationError::Reqwest)?;

        let api_config = nethsm_sdk_rs::apis::configuration::Configuration {
            client: reqwest_client,
            base_path: instance.url.clone(),
            basic_auth: Some((default_user.username.clone(), default_user.password.clone())),
            user_agent: Some(DEFAULT_USER_AGENT.to_string()),
            ..Default::default()
        };
        instances.push(api_config);
    }

    Ok(Slot {
        description: slot.description.clone(),
        label: slot.label.clone(),
        instances,
        administrator: slot.administrator.clone(),
        operator: slot.operator.clone(),
        db: Arc::new(tokio::sync::Mutex::new(crate::backend::db::Db::new())),
    })
}
