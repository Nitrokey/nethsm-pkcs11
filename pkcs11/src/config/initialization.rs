use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::available_parallelism,
    time::Duration,
};

use super::{
    config_file::{config_files, ConfigError, SlotConfig},
    device::{Device, Slot},
};
use log::{debug, error, info, trace};
use nethsm_sdk_rs::ureq;
use rustls::client::ServerCertVerifier;
use sha2::Digest;

const DEFAULT_USER_AGENT: &str = "pkcs11-rs/0.1.0";

#[derive(Debug)]
pub enum InitializationError {
    Config(crate::config::config_file::ConfigError),
    NoCerts,
    NoUser(String),
}

pub fn initialize_with_configs(
    configs: Result<Vec<(Vec<u8>, PathBuf)>, ConfigError>,
) -> Result<Device, InitializationError> {
    // Use a closure called immediately so that `?` can be used
    let config_res = (|| {
        let configs_files = configs.map_err(InitializationError::Config)?;

        let config = crate::config::config_file::merge_configurations(
            configs_files.iter().map(|(data, _)| &**data),
        )
        .map_err(InitializationError::Config)?;
        let file_paths: Vec<PathBuf> = configs_files.into_iter().map(|(_, path)| path).collect();
        Ok((config, file_paths))
    })();

    crate::config::logging::configure_logger(&config_res);
    let (config, _) = config_res?;

    info!("Loaded configuration with {} slots", config.slots.len());
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

pub fn initialize() -> Result<Device, InitializationError> {
    initialize_with_configs(config_files())
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

    info!(
        "Slot with {} instances, timeout: {:?}, retries: {:?}",
        slot.instances.len(),
        slot.timeout_seconds,
        slot.retries
    );

    for instance in slot.instances.iter() {
        let tls_conf = rustls::ClientConfig::builder().with_safe_defaults();

        let tls_conf = if instance.danger_insecure_cert {
            tls_conf
                .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier {}))
                .with_no_client_auth()
        } else if !instance.sha256_fingerprints.is_empty() {
            let fingerprints = instance
                .sha256_fingerprints
                .iter()
                .map(|f| f.value.clone())
                .collect();
            tls_conf
                .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { fingerprints }))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            let native_certs = rustls_native_certs::load_native_certs().map_err(|err| {
                error!("Failed to load certificates: {err}");
                InitializationError::NoCerts
            })?;

            let (added, failed) = roots.add_parsable_certificates(&native_certs);
            // panic!("{:?}", (added, failed));
            debug!("Added {added} certifcates and failed to parse {failed} certificates");

            if added == 0 {
                error!("Added no native certificates");
                return Err(InitializationError::NoCerts);
            }

            tls_conf.with_root_certificates(roots).with_no_client_auth()
        };

        info!(
            "Instance configured with: max_idle_connection: {:?}",
            instance.max_idle_connections
        );

        let max_idle_connections = instance
            .max_idle_connections
            .or_else(|| available_parallelism().ok().map(Into::into))
            .unwrap_or(100);

        // 100 idle connections is the default
        // By default there is 1 idle connection per host, but we are only connecting to 1 host.
        // So we need to allow the connection pool to scale to match the number of threads
        let mut builder = ureq::AgentBuilder::new()
            .tls_config(Arc::new(tls_conf))
            .max_idle_connections(max_idle_connections)
            .max_idle_connections_per_host(max_idle_connections);

        if let Some(t) = slot.timeout_seconds {
            builder = builder
                .timeout(Duration::from_secs(t))
                .timeout_connect(Duration::from_secs(10));
        }

        let agent = builder.build();

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
        retries: slot.retries,
        db: Arc::new(Mutex::new(crate::backend::db::Db::new())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test various good and bad configs for panics
    #[test]
    fn test_config_loading() {
        let config_content = r#"
slots:
  - label: LocalHSM
    description: Local HSM (docker)
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "Administrator"
    instances:
      - url: "https://localhost:8443/api/v1"
        danger_insecure_cert: true  
        sha256_fingerprints: 
          - "31:92:8E:A4:5E:16:5C:A7:33:44:E8:E9:8E:64:C4:AE:7B:2A:57:E5:77:43:49:F3:69:C9:8F:C4:2F:3A:3B:6E"
    retries: 
      count: 10
      delay_seconds: 1
    timeout_seconds: 10
            "#;
        let config_path = "/path/to/config.conf";
        let configs = vec![(config_content.into(), config_path.into())];

        assert!(initialize_with_configs(Ok(configs)).is_ok());

        let config_bad_fingerprint_content = r#"
slots:
  - label: LocalHSM
    description: Local HSM (docker)
    operator:
      username: "operator"
      password: "opPassphrase"
    administrator:
      username: "admin"
      password: "Administrator"
    instances:
      - url: "https://localhost:8443/api/v1"
        danger_insecure_cert: true  
        sha256_fingerprints: 
          - "31:92:8E:A4:5Eeeeee:16:5C:A7:33:44:E8:E9:8E:64:C4:AE:7B:2A:57:E5:77:43:49:F3:69:C9:8F:C4:2F:3A:3B:6E"
    retries: 
      count: 10
      delay_seconds: 1
    timeout_seconds: 10
            "#;
        let configs_bad_fingerprint =
            vec![(config_bad_fingerprint_content.into(), config_path.into())];
        assert!(initialize_with_configs(Ok(configs_bad_fingerprint)).is_err());
        let config_bad_yml_content = r#"
dict:
bad_yml
            "#;
        let configs_bad_yml = vec![(config_bad_yml_content.into(), config_path.into())];
        assert!(initialize_with_configs(Ok(configs_bad_yml)).is_err());
    }
}
