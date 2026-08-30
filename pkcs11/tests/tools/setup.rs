use std::{
    env,
    io::BufWriter,
    mem,
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};

use config_file::{CertificateFormat, InstanceConfig, P11Config, SlotConfig, UserConfig};
use nethsm_sdk_rs::{
    apis::{
        configuration::Configuration,
        default_api::{health_state_get, provision_post, users_user_id_put},
    },
    models::{ProvisionRequestData, SystemState, UserPostData, UserRole},
};
use tempfile::NamedTempFile;
use time::format_description;
use ureq::tls::TlsConfig;

pub const NETHSM_DOCKER_HOSTNAME: &str = match option_env!("NETHSM_DOCKER_HOSTNAME") {
    Some(v) => v,
    None => "localhost",
};

/// Contains true if the nethsm has already been provisioned
static CONTAINER_IS_PROVISIONED: Mutex<bool> = Mutex::new(false);

pub fn setup() -> MutexGuard<'static, bool> {
    let mut guard = CONTAINER_IS_PROVISIONED
        .lock()
        .expect("failed to lock test mutex");
    let is_provisioned = mem::replace(&mut *guard, true);
    if !is_provisioned {
        provision(NETHSM_DOCKER_HOSTNAME, 8443);
    } else {
        println!("Already provisioned")
    }
    guard
}

pub fn with_pkcs11_config<F, R>(config: &P11Config, f: F) -> R
where
    F: FnOnce() -> R,
{
    let mut tmpfile: NamedTempFile = NamedTempFile::new().unwrap();
    serde_yaml::to_writer(BufWriter::new(tmpfile.as_file_mut()), config).unwrap();
    let path = tmpfile.path();
    env::set_var(config_file::ENV_VAR_CONFIG_FILE, path);
    f()
}

pub fn with_default_pkcs11_config<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let config = P11Config {
        slots: vec![SlotConfig {
            label: "Test slot".into(),
            operator: Some(UserConfig {
                username: "operator".into(),
                password: Some("opPassphrase".into()),
            }),
            administrator: Some(UserConfig {
                username: "admin".into(),
                password: Some("Administrator".into()),
            }),
            description: Some("Test slot".into()),
            instances: vec![InstanceConfig {
                url: format!("https://{NETHSM_DOCKER_HOSTNAME}:8443/api/v1"),
                danger_insecure_cert: true,
                sha256_fingerprints: Vec::new(),
                max_idle_connections: None,
            }],
            certificate_format: CertificateFormat::Pem,
            retries: None,
            timeout_seconds: Some(10),
            connections_max_idle_duration: None,
            tcp_keepalive: None,
        }],
        ..Default::default()
    };
    with_pkcs11_config(&config, f)
}

fn provision(host: &str, port: u16) {
    let client = ureq::Agent::config_builder()
        .tls_config(TlsConfig::builder().disable_verification(true).build())
        .timeout_connect(Some(Duration::from_secs(1)))
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();

    let sdk_config = Configuration {
        client,
        base_path: format!("https://{host}:{port}/api/v1"),
        basic_auth: Some(("admin".into(), Some("Administrator".into()))),
        ..Default::default()
    };

    println!(
        "Configuration built, waiting for test instance to be up at {}",
        &sdk_config.base_path
    );
    thread::sleep(Duration::from_secs(2));
    println!("Attempting provisionning");

    match health_state_get(&sdk_config).unwrap().entity.state {
        SystemState::Unprovisioned => {}
        SystemState::Operational => {
            println!("NetHSM is already operational, skipping provisioning.");
            return;
        }
        SystemState::Locked => panic!("Cannot provision locked NetHSM"),
        state => panic!("Unexpected system state: {state:?}"),
    }

    provision_post(
        &sdk_config,
        ProvisionRequestData::new(
            "1234567890".into(),
            "Administrator".into(),
            time::OffsetDateTime::now_utc()
                .format(
                    &format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
                        .unwrap(),
                )
                .unwrap(),
        ),
    )
    .unwrap();
    users_user_id_put(
        &sdk_config,
        "operator",
        UserPostData::new("Operator".into(), UserRole::Operator, "opPassphrase".into()),
    )
    .unwrap();
}
