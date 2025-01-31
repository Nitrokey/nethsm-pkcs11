use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc, Condvar, Mutex},
    thread::available_parallelism,
    time::Duration,
};

use crate::{
    config::device::InstanceData,
    ureq::{rustls_connector::RustlsConnector, tcp_connector::TcpConnector},
};

use super::{
    config_file::{config_files, ConfigError, SlotConfig},
    device::{Device, Slot},
};
use arc_swap::ArcSwap;
use log::{debug, error, info, trace};
use nethsm_sdk_rs::ureq;
use rustls::{
    client::danger::ServerCertVerifier,
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
};
use sha2::Digest;
use ureq::{
    tls::{TlsConfig, TlsProvider::Rustls},
    unversioned::transport::{ConnectProxyConnector, Connector},
};

use ureq::unversioned::resolver::DefaultResolver;

const DEFAULT_USER_AGENT: &str = concat!("pkcs11-rs/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub enum InitializationError {
    #[error("Failed to load config")]
    Config(crate::config::config_file::ConfigError),
    #[error("Failed to load certificates")]
    NoCerts,
    #[error("No operator or administrator for slot: {0}")]
    NoUser(String),
    #[error("No instance given for a slot")]
    NoInstance,
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
        enable_set_attribute_value: config.enable_set_attribute_value,
    })
}

pub fn initialize() -> Result<Device, InitializationError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    initialize_with_configs(config_files())
}

#[derive(Debug)]
struct DangerIgnoreVerifier;

impl ServerCertVerifier for DangerIgnoreVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let default_provider = CryptoProvider::get_default().unwrap();

        default_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct FingerprintVerifier {
    fingerprints: Vec<Vec<u8>>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(end_entity.as_ref());
        let result = hasher.finalize();
        for fingerprint in &self.fingerprints {
            if fingerprint == &*result {
                trace!("Certificate fingerprint matches");
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        Err(rustls::Error::General(
            "Could not verify certificate fingerprint".to_string(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let default_provider = CryptoProvider::get_default().unwrap();

        default_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn slot_from_config(slot: &SlotConfig) -> Result<Slot, InitializationError> {
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
    let mut instances = Vec::new();
    for instance in &slot.instances {
        let tls_conf = rustls::ClientConfig::builder();

        let tls_conf = if instance.danger_insecure_cert {
            tls_conf
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier))
                .with_no_client_auth()
        } else if !instance.sha256_fingerprints.is_empty() {
            let fingerprints = instance
                .sha256_fingerprints
                .iter()
                .map(|f| f.value.clone())
                .collect();
            tls_conf
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { fingerprints }))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            let native_certs = rustls_native_certs::load_native_certs().map_err(|err| {
                error!("Failed to load certificates: {err}");
                InitializationError::NoCerts
            })?;

            let (added, failed) = roots.add_parsable_certificates(native_certs);
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
        let mut builder = ureq::Agent::config_builder()
            .tls_config(TlsConfig::builder().provider(Rustls).build())
            .max_idle_connections(max_idle_connections)
            .max_idle_connections_per_host(max_idle_connections);

        if let Some(t) = slot.timeout_seconds {
            builder = builder.timeout_global(Some(Duration::from_secs(t)));
        }

        let mut tcp_keepalive_time = None;
        let mut tcp_keepalive_retries = None;
        let mut tcp_keepalive_interval = None;
        if let Some(keepalive) = slot.tcp_keepalive {
            tcp_keepalive_time = Some(Duration::from_secs(keepalive.time_seconds));
            tcp_keepalive_interval = Some(Duration::from_secs(keepalive.interval_seconds));
            tcp_keepalive_retries = Some(keepalive.retries);
        }

        if let Some(max_idle_duration) = slot.connections_max_idle_duration {
            builder = builder.max_idle_age(Duration::from_secs(max_idle_duration));
        }

        let clear_flag = Arc::new(ArcSwap::new(Arc::new(AtomicBool::new(true))));

        let api_config = nethsm_sdk_rs::apis::configuration::Configuration {
            client: ureq::Agent::with_parts(
                builder.build(),
                ().chain(TcpConnector {
                    tcp_keepalive_time,
                    tcp_keepalive_retries,
                    tcp_keepalive_interval,
                    clear_flag: clear_flag.clone(),
                })
                .chain(RustlsConnector {
                    config: tls_conf.into(),
                })
                .chain(ConnectProxyConnector::default()),
                DefaultResolver::default(),
            ),
            base_path: instance.url.clone(),
            basic_auth: Some((default_user.username.clone(), default_user.password.clone())),
            user_agent: Some(DEFAULT_USER_AGENT.to_string()),
            ..Default::default()
        };
        instances.push(InstanceData {
            config: api_config,
            state: Default::default(),
            clear_flag,
        });
    }
    if instances.is_empty() {
        error!("Slot without any instance configured");
        return Err(InitializationError::NoInstance);
    }

    Ok(Slot {
        _description: slot.description.clone(),
        label: slot.label.clone(),
        instances,
        administrator: slot.administrator.clone(),
        operator: slot.operator.clone(),
        retries: slot.retries,
        db: Arc::new((Mutex::new(crate::backend::db::Db::new()), Condvar::new())),
        instance_balancer: Default::default(),
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
