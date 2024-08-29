#![cfg(feature = "pkcs11-full-tests")]

use core::ptr;

use config_file::{InstanceConfig, P11Config, SlotConfig, UserConfig};
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

#[test]
fn basic() {
    env_logger::init();
    tools::run_tests(
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
        |ctx| {
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
