#![cfg(feature = "pkcs11-full-tests")]

use config_file::{InstanceConfig, P11Config, SlotConfig, UserConfig};

mod tools;

#[test]
fn basic() {
    tools::run_tests(
        P11Config {
            slots: vec![SlotConfig {
                label: "Test slot".into(),
                operator: Some(UserConfig {
                    username: "operator".into(),
                    password: Some("opPassphrase".into()),
                }),
                administrator: None,
                description: Some("Test slot".into()),
                instances: vec![InstanceConfig {
                    url: "https://localhost:8443/api/v1".into(),
                    danger_insecure_cert: true,
                    sha256_fingerprints: Vec::new(),
                    max_idle_connections: None,
                }],
                retries: None,
                timeout_seconds: None,
            }],
            ..Default::default()
        },
        |ctx| {
            let session = 0;
            ctx.open_session(session, 0x04, None, None).unwrap();
        },
    )
}
