use std::sync::{Arc, Mutex};

use super::{
    config_file::SlotConfig,
    device::{Device, Slot},
};
use log::trace;
use nethsm_sdk_rs::ureq;
use rustls::client::ServerCertVerifier;
use sha2::Digest;

const DEFAULT_USER_AGENT: &str = "pkcs11-rs/0.1.0";

#[derive(Debug)]
pub enum InitializationError {
    Config(crate::config::config_file::ConfigError),
    NoUser(String),
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

struct DangerIgnoreVerifier {}

impl ServerCertVerifier for DangerIgnoreVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        // always accept the certificate
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

struct FingerprintVerifier {
    fingerprints: Vec<Vec<u8>>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&end_entity.0);
        let result = hasher.finalize();
        for fingerprint in self.fingerprints.iter() {
            if fingerprint == &result[..] {
                trace!("Certificate fingerprint matches");
                return Ok(rustls::client::ServerCertVerified::assertion());
            }
        }
        Err(rustls::Error::General(
            "Could not verify certificate fingerprint".to_string(),
        ))
    }
}

fn slot_from_config(slot: &SlotConfig) -> Result<Slot, InitializationError> {
    let mut instances = vec![];

    let default_user = slot
        .operator
        .as_ref()
        .or(slot.administrator.as_ref())
        .ok_or(InitializationError::NoUser(slot.label.clone()))?;

    for instance in slot.instances.iter() {
        let tls_conf = rustls::ClientConfig::builder().with_safe_defaults();

        let tls_conf = if instance.danger_insecure_cert {
            tls_conf
                .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier {}))
                .with_no_client_auth()
        } else if !instance.sha256_fingerprints.is_empty() {
            let mut fingerprints = vec![];

            for fingerprint in instance.sha256_fingerprints.iter() {
                fingerprints.push(hex::decode(fingerprint.replace(':', "")).unwrap());
            }

            tls_conf
                .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { fingerprints }))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            for cert in
                rustls_native_certs::load_native_certs().expect("could not load platform certs")
            {
                roots.add(&rustls::Certificate(cert.0)).unwrap();
            }

            tls_conf.with_root_certificates(roots).with_no_client_auth()
        };

        let agent = ureq::AgentBuilder::new()
            .tls_config(Arc::new(tls_conf))
            .max_idle_connections(2)
            .max_idle_connections_per_host(2)
            .build();

        let api_config = nethsm_sdk_rs::apis::configuration::Configuration {
            client: agent,
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
        db: Arc::new(Mutex::new(crate::backend::db::Db::new())),
    })
}
