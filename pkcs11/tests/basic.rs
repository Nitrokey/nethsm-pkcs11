#![cfg(feature = "pkcs11-full-tests")]

use core::ptr;
use std::{
    thread,
    time::{Duration, Instant},
};

use config_file::{InstanceConfig, P11Config, RetryConfig, SlotConfig, UserConfig};
use pkcs11::types::{
    CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_TOKEN, CKA_VERIFY, CKM_RSA_PKCS,
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_MECHANISM, CK_TRUE, CK_ULONG,
};

mod tools;

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
                    url: option_env!("TEST_NETHSM_INSTANCE")
                        .unwrap_or("https://localhost:8443/api/v1")
                        .into(),
                    danger_insecure_cert: true,
                    sha256_fingerprints: Vec::new(),
                    max_idle_connections: None,
                }],
                retries: None,
                timeout_seconds: None,
            }],
            ..Default::default()
        },
        |_test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (_public_key, private_key) = ctx
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
                        url: option_env!("TEST_NETHSM_INSTANCE")
                            .unwrap_or("https://localhost:8443/api/v1")
                            .into(),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                    InstanceConfig {
                        url: option_env!("TEST_NETHSM_INSTANCE")
                            .unwrap_or("https://localhost:8444/api/v1")
                            .into(),
                        danger_insecure_cert: true,
                        sha256_fingerprints: Vec::new(),
                        max_idle_connections: None,
                    },
                ],
                retries: None,
                timeout_seconds: None,
            }],
            ..Default::default()
        },
        |_test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (_public_key, private_key) = ctx
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
                    url: option_env!("TEST_NETHSM_INSTANCE")
                        .unwrap_or("https://localhost:8443/api/v1")
                        .into(),
                    danger_insecure_cert: true,
                    sha256_fingerprints: Vec::new(),
                    max_idle_connections: None,
                }],
                retries: None,
                timeout_seconds: Some(10),
            }],
            ..Default::default()
        },
        |test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (_public_key, private_key) = ctx
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
                    url: option_env!("TEST_NETHSM_INSTANCE")
                        .unwrap_or("https://localhost:8443/api/v1")
                        .into(),
                    danger_insecure_cert: true,
                    sha256_fingerprints: Vec::new(),
                    max_idle_connections: None,
                }],
                retries: Some(RetryConfig {
                    count: 2,
                    delay_seconds: 1,
                }),
                timeout_seconds: Some(10),
            }],
            ..Default::default()
        },
        |test_ctx, ctx| {
            let slot = 0;
            let session = ctx.open_session(slot, 0x04, None, None).unwrap();
            let (_public_key, private_key) = ctx
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
                assert!(elapsed < Duration::from_secs(12), "Elapsed: {elapsed:?}");
            });
        },
    )
}
