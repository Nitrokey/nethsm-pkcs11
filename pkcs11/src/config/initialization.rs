use std::sync::Arc;

use log::trace;
use reqwest::Certificate;

use super::device::{Device, Slot};

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
        // configure the reqwest client

        let mut reqwest_builder = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(slot.danger_insecure_cert);

        if let Some(cert_str) = slot.certificate.as_ref() {
            let cert = Certificate::from_pem(cert_str.trim().as_bytes())
                .map_err(InitializationError::Reqwest)?;
            reqwest_builder = reqwest_builder.add_root_certificate(cert);
            trace!("Added certificate to slot {}", slot.label);
        }
        if let Some(file) = slot.certificate_file.as_ref() {
            let cert = Certificate::from_pem(
                std::fs::read(file)
                    .map_err(InitializationError::ReadFile)?
                    .as_slice(),
            )
            .map_err(InitializationError::Reqwest)?;
            reqwest_builder = reqwest_builder.add_root_certificate(cert);
            trace!("Added certificate to slot {}", slot.label);
        }

        let reqwest_client = reqwest_builder
            .build()
            .map_err(InitializationError::Reqwest)?;

        let default_user = slot
            .operator
            .as_ref()
            .or(slot.administrator.as_ref())
            .ok_or(InitializationError::NoUser(slot.label.clone()))?;

        let api_config = openapi::apis::configuration::Configuration {
            client: reqwest_client,
            base_path: slot.url.clone(),
            basic_auth: Some((default_user.username.clone(), default_user.password.clone())),
            user_agent: Some(DEFAULT_USER_AGENT.to_string()),
            ..Default::default()
        };

        slots.push(Arc::new(Slot {
            api_config: api_config.clone(),
            description: slot.description.clone(),
            label: slot.label.clone(),
            operator: slot.operator.clone(),
            administator: slot.administrator.clone(),
        }));
    }

    Ok(Device {
        slots,
        log_file: config.log_file,
    })
}
