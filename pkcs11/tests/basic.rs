#![cfg(feature = "pkcs11-full-tests")]

use core::ptr;
use std::{
    thread,
    time::{Duration, Instant},
};

use config_file::{
    CertificateFormat, InstanceConfig, P11Config, RetryConfig, SlotConfig, UserConfig,
};
use pkcs11::types::{
    CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_TOKEN, CKA_VERIFY, CKM_RSA_PKCS,
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_MECHANISM, CK_TRUE, CK_ULONG,
};

mod tools;
use tools::NETHSM_DOCKER_HOSTNAME;

const RSA_PRIVATE_KEY_ATTRIBUTES: &[CK_ATTRIBUTE] = &[
    CK_ATTRIBUTE {
        attrType: CKA_SIGN,
        pValue: &CK_TRUE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_TOKEN,
        pValue: &CK_FALSE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
];

const RSA_PUBLIC_KEY_ATTRIBUTES: &[CK_ATTRIBUTE] = &[
    CK_ATTRIBUTE {
        attrType: CKA_VERIFY,
        pValue: &CK_TRUE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_MODULUS_BITS,
        pValue: &(2048 as CK_ULONG) as *const _ as *mut _,
        ulValueLen: size_of::<CK_ULONG>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_TOKEN,
        pValue: &CK_FALSE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_PUBLIC_EXPONENT,
        pValue: [0x01, 0x00, 0x01].as_ptr() as *mut _,
        ulValueLen: 3 as _,
    },
];

const RSA_MECHANISM: CK_MECHANISM = CK_MECHANISM {
    mechanism: CKM_RSA_PKCS,
    pParameter: ptr::null_mut(),
    ulParameterLen: 0,
};

#[test_log::test]
fn basic() {
    tools::run_tests(
        &[],
        P11Config {
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
                    url: "https://localhost:8443/api/v1".into(),
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
        },
        |_test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (public_key, private_key) = ctx
                .generate_key_pair(
                    session,
                    &RSA_MECHANISM,
                    RSA_PUBLIC_KEY_ATTRIBUTES,
                    RSA_PRIVATE_KEY_ATTRIBUTES,
                )
                .unwrap();
            let data = [0x42; 32];
            ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();

            // Verifying signatures is not supported
            let _signature = ctx.sign(session, &data).unwrap();
            ctx.destroy_object(session, public_key).unwrap();
            ctx.destroy_object(session, private_key).unwrap();
        },
    )
}

#[test_log::test]
fn multiple_instances() {
    tools::run_tests(
        &[(8444, 8443)],
        P11Config {
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
                instances: vec![
                    InstanceConfig {
                        url: format!("https://{NETHSM_DOCKER_HOSTNAME}:8443/api/v1"),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                    InstanceConfig {
                        url: format!("https://{NETHSM_DOCKER_HOSTNAME}:8444/api/v1"),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                ],
                certificate_format: CertificateFormat::Pem,
                retries: None,
                timeout_seconds: Some(10),
                connections_max_idle_duration: None,
                tcp_keepalive: None,
            }],
            ..Default::default()
        },
        |_test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (public_key, private_key) = ctx
                .generate_key_pair(
                    session,
                    &RSA_MECHANISM,
                    RSA_PUBLIC_KEY_ATTRIBUTES,
                    RSA_PRIVATE_KEY_ATTRIBUTES,
                )
                .unwrap();
            let data = [0x42; 32];

            for _ in 0..10 {
                ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
                // Verifying signatures is not supported
                let _signature = ctx.sign(session, &data).unwrap();
            }
            ctx.destroy_object(session, public_key).unwrap();
            ctx.destroy_object(session, private_key).unwrap();
        },
    )
}

#[test_log::test]
fn timeout() {
    tools::run_tests(
        &[],
        P11Config {
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
                    url: "https://localhost:8443/api/v1".into(),
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
        },
        |test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (public_key, private_key) = ctx
                .generate_key_pair(
                    session,
                    &RSA_MECHANISM,
                    RSA_PUBLIC_KEY_ATTRIBUTES,
                    RSA_PRIVATE_KEY_ATTRIBUTES,
                )
                .unwrap();
            let data = [0x42; 32];

            for _ in 0..10 {
                ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
                // Verifying signatures is not supported
                let _signature = ctx.sign(session, &data).unwrap();
            }

            test_ctx.add_block(8443);
            ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
            let start = Instant::now();
            ctx.sign(session, &data).unwrap_err();
            let elapsed = start.elapsed();
            assert!(elapsed > Duration::from_secs(10), "Elapsed: {elapsed:?}");
            assert!(elapsed < Duration::from_secs(11), "Elapsed: {elapsed:?}");
            test_ctx.remove_block(8443);
            ctx.destroy_object(session, public_key).unwrap();
            ctx.destroy_object(session, private_key).unwrap();
        },
    )
}

#[test_log::test]
fn retries() {
    tools::run_tests(
        &[],
        P11Config {
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
                    url: "https://localhost:8443/api/v1".into(),
                    danger_insecure_cert: true,
                    sha256_fingerprints: Vec::new(),
                    max_idle_connections: None,
                }],
                certificate_format: CertificateFormat::Pem,
                retries: Some(RetryConfig {
                    count: 2,
                    delay_seconds: 2,
                }),
                timeout_seconds: Some(10),
                connections_max_idle_duration: None,
                tcp_keepalive: None,
            }],
            ..Default::default()
        },
        |test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (public_key, private_key) = ctx
                .generate_key_pair(
                    session,
                    &RSA_MECHANISM,
                    RSA_PUBLIC_KEY_ATTRIBUTES,
                    RSA_PRIVATE_KEY_ATTRIBUTES,
                )
                .unwrap();
            let data = [0x42; 32];

            for _ in 0..10 {
                ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
                // Verifying signatures is not supported
                let _signature = ctx.sign(session, &data).unwrap();
            }

            test_ctx.add_block(8443);
            ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
            thread::scope(|s| {
                s.spawn(|| {
                    // 10s and 500ms to unblock while waiting fort the retry
                    thread::sleep(Duration::new(10, 500_000_000));
                    test_ctx.remove_block(8443);
                });
                let start = Instant::now();
                ctx.sign(session, &data).unwrap();
                let elapsed = start.elapsed();
                assert!(elapsed > Duration::from_secs(11), "Elapsed: {elapsed:?}");
                assert!(elapsed < Duration::from_secs(13), "Elapsed: {elapsed:?}");
            });
            ctx.destroy_object(session, public_key).unwrap();
            ctx.destroy_object(session, private_key).unwrap();
        },
    )
}

#[test_log::test]
fn multi_instance_retries() {
    tools::run_tests(
        &[(8444, 8443)],
        P11Config {
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
                instances: vec![
                    InstanceConfig {
                        url: format!("https://{NETHSM_DOCKER_HOSTNAME}:8443/api/v1"),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                    InstanceConfig {
                        url: format!("https://{NETHSM_DOCKER_HOSTNAME}:8444/api/v1"),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                ],
                certificate_format: CertificateFormat::Pem,
                retries: Some(RetryConfig {
                    count: 3,
                    delay_seconds: 1,
                }),
                timeout_seconds: Some(1),
                connections_max_idle_duration: None,
                tcp_keepalive: None,
            }],
            ..Default::default()
        },
        |test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (public_key, private_key) = ctx
                .generate_key_pair(
                    session,
                    &RSA_MECHANISM,
                    RSA_PUBLIC_KEY_ATTRIBUTES,
                    RSA_PRIVATE_KEY_ATTRIBUTES,
                )
                .unwrap();
            let data = [0x42; 32];

            for _ in 0..2 {
                ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
                // Verifying signatures is not supported
                let _signature = ctx.sign(session, &data).unwrap();
            }

            test_ctx.add_block(8444);
            for _ in 0..2 {
                ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
                ctx.sign(session, &data).unwrap();
            }
            test_ctx.remove_block(8444);
            ctx.destroy_object(session, public_key).unwrap();
            ctx.destroy_object(session, private_key).unwrap();
        },
    )
}

#[test_log::test]
fn pool_not_reused() {
    tools::run_tests(
        &[(8444, 8443), (8445, 8443)],
        P11Config {
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
                instances: vec![
                    InstanceConfig {
                        url: format!("https://{NETHSM_DOCKER_HOSTNAME}:8444/api/v1"),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                    InstanceConfig {
                        url: format!("https://{NETHSM_DOCKER_HOSTNAME}:8445/api/v1"),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                ],
                certificate_format: CertificateFormat::Pem,
                retries: None,
                timeout_seconds: Some(5),
                connections_max_idle_duration: None,
                tcp_keepalive: None,
            }],
            ..Default::default()
        },
        |test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (public_key, private_key) = ctx
                .generate_key_pair(
                    session,
                    &RSA_MECHANISM,
                    RSA_PUBLIC_KEY_ATTRIBUTES,
                    RSA_PRIVATE_KEY_ATTRIBUTES,
                )
                .unwrap();
            let data = [0x42; 32];

            for _ in 0..2 {
                ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
                // Verifying signatures is not supported
                let _signature = ctx.sign(session, &data).unwrap();
            }

            test_ctx.stall_active_connections();
            let start_at = Instant::now();
            ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
            ctx.sign(session, &data).unwrap_err();
            assert!(start_at.elapsed() > Duration::from_secs(5));
            assert!(start_at.elapsed() < Duration::from_secs(6));

            let start_at = Instant::now();
            ctx.sign_init(session, &RSA_MECHANISM, private_key).unwrap();
            ctx.sign(session, &data).unwrap();
            assert!(start_at.elapsed() < Duration::from_secs(1));

            ctx.destroy_object(session, public_key).unwrap();
            ctx.destroy_object(session, private_key).unwrap();
        },
    )
}
