use base64ct::{Base64, Encoding};
use cryptoki_sys::CKR_OK;
use log::{error, trace};
use nethsm_sdk_rs::apis::default_api;

use crate::{
    backend::{
        db::attr::CkRawAttrTemplate,
        mechanism::{CkRawMechanism, Mechanism},
    },
    lock_session, read_session,
};

pub extern "C" fn C_GenerateKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateKey() called");
    ensure_init!();

    // pTemplate and pMechanism are checked for null with `from_raw_ptr`

    if phKey.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mech = match unsafe { CkRawMechanism::from_raw_ptr(pMechanism) } {
        Some(mech) => mech,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

    trace!("C_GenerateKey() mech: {:?}", mech.type_());
    trace!("C_GenerateKey() mech param len: {:?}", mech.len());
    let mech = match Mechanism::from_ckraw_mech(&mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_GenerateKey() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    let template = match unsafe { CkRawAttrTemplate::from_raw_ptr(pTemplate, ulCount as usize) } {
        Some(template) => template,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

    read_session!(hSession, session);

    let key = match session.generate_key(&template, None, &mech) {
        Ok(key) => key,
        Err(e) => {
            error!("C_GenerateKey() failed to generate key: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    if key.is_empty() {
        error!(
            "C_GenerateKey() failed to generate key,invalid length: {:?}",
            key
        );
        return cryptoki_sys::CKR_FUNCTION_FAILED;
    }

    unsafe {
        std::ptr::write(phKey, key[0].0);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GenerateKeyPair(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pPublicKeyTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: cryptoki_sys::CK_ULONG,
    pPrivateKeyTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: cryptoki_sys::CK_ULONG,
    phPublicKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    phPrivateKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateKeyPair() called");
    ensure_init!();

    // pMechanism, pPrivateKeyTemplate, pPublicKeyTemplate  checked for null with `from_raw_ptr`

    if phPublicKey.is_null() || phPrivateKey.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mech = match unsafe { CkRawMechanism::from_raw_ptr(pMechanism) } {
        Some(mech) => mech,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

    trace!("C_GenerateKeyPair() mech: {:?}", mech.type_());
    trace!("C_GenerateKeyPair() mech param len: {:?}", mech.len());

    trace!("Private count: {:?}", ulPrivateKeyAttributeCount);
    trace!("Public count: {:?}", ulPublicKeyAttributeCount);

    let mech = match Mechanism::from_ckraw_mech(&mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_GenerateKeyPair() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };
    let public_template = match unsafe {
        CkRawAttrTemplate::from_raw_ptr(pPublicKeyTemplate, ulPublicKeyAttributeCount as usize)
    } {
        Some(public_template) => public_template,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

    let private_template = match unsafe {
        CkRawAttrTemplate::from_raw_ptr(pPrivateKeyTemplate, ulPrivateKeyAttributeCount as usize)
    } {
        Some(private_template) => private_template,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

    read_session!(hSession, session);

    let keys = match session.generate_key(&private_template, Some(&public_template), &mech) {
        Ok(keys) => keys,
        Err(e) => {
            error!("C_GenerateKeyPair() failed to generate key: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    if keys.len() < 2 {
        error!(
            "C_GenerateKeyPair() failed to generate key,invalid length: {:?}",
            keys
        );
        return cryptoki_sys::CKR_FUNCTION_FAILED;
    }

    unsafe {
        std::ptr::write(phPublicKey, keys[0].0);
        std::ptr::write(phPrivateKey, keys[1].0);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_WrapKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hWrappingKey: cryptoki_sys::CK_OBJECT_HANDLE,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pWrappedKey: cryptoki_sys::CK_BYTE_PTR,
    pulWrappedKeyLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_WrapKey() called");
    ensure_init!();

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_UnwrapKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hUnwrappingKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pWrappedKey: cryptoki_sys::CK_BYTE_PTR,
    ulWrappedKeyLen: cryptoki_sys::CK_ULONG,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulAttributeCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_UnwrapKey() called");
    ensure_init!();

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DeriveKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hBaseKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulAttributeCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DeriveKey() called");
    ensure_init!();

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

// we silently ignore this function as NetHSM handles the random number generation
pub extern "C" fn C_SeedRandom(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSeed: cryptoki_sys::CK_BYTE_PTR,
    ulSeedLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SeedRandom() called");
    ensure_init!();

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GenerateRandom(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    RandomData: cryptoki_sys::CK_BYTE_PTR,
    ulRandomLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateRandom() called");
    ensure_init!();

    if RandomData.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    if ulRandomLen == 0 {
        return CKR_OK;
    }

    if ulRandomLen > 1024 {
        error!(
            "C_GenerateRandom() called with invalid length {}, NetHSM supports up to 1024 bytes",
            ulRandomLen
        );

        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }
    lock_session!(hSession, session);

    if !session
        .login_ctx
        .can_run_mode(crate::backend::login::UserMode::Operator)
    {
        error!(
            "C_GenerateRandom() called with session not connected as operator {}.",
            hSession
        );
        return cryptoki_sys::CKR_USER_NOT_LOGGED_IN;
    }

    let data = match session.login_ctx.try_(
        |api_config| {
            default_api::random_post(
                api_config,
                nethsm_sdk_rs::models::RandomRequestData {
                    length: ulRandomLen as i32,
                },
            )
        },
        crate::backend::login::UserMode::Operator,
    ) {
        Ok(data) => data,
        Err(e) => {
            error!("C_GenerateRandom() failed to generate random data: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    // parse base64 string to bytes

    let raw_data = match Base64::decode_vec(&data.entity.random) {
        Ok(raw_data) => raw_data,
        Err(e) => {
            error!("C_GenerateRandom() failed to decode random data: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    unsafe {
        std::ptr::copy_nonoverlapping(raw_data.as_ptr(), RandomData, ulRandomLen as usize);
    }

    CKR_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_null_mech() {
        let mut template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut phKey = 0;

        let rv = C_GenerateKey(
            0,
            std::ptr::null_mut(),
            template.as_mut_ptr(),
            0,
            &mut phKey,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_null_template() {
        let mut phKey = 0;

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_GenerateKey(0, &mut mech, std::ptr::null_mut(), 0, &mut phKey);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_null_phkey() {
        let mut template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_GenerateKey(0, &mut mech, template.as_mut_ptr(), 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_unknown_mech() {
        let mut template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut phKey = 0;

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: 15000,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_GenerateKey(0, &mut mech, template.as_mut_ptr(), 0, &mut phKey);
        assert_eq!(rv, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_generate_key_pair_null_mech() {
        let mut template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut phPublicKey = 0;
        let mut phPrivateKey = 0;

        let rv = C_GenerateKeyPair(
            0,
            std::ptr::null_mut(),
            template.as_mut_ptr(),
            0,
            template.as_mut_ptr(),
            0,
            &mut phPublicKey,
            &mut phPrivateKey,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_null_public_template() {
        let mut phPublicKey = 0;
        let mut phPrivateKey = 0;

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut private_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let rv = C_GenerateKeyPair(
            0,
            &mut mech,
            std::ptr::null_mut(),
            0,
            private_template.as_mut_ptr(),
            0,
            &mut phPublicKey,
            &mut phPrivateKey,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_null_private_template() {
        let mut phPublicKey = 0;
        let mut phPrivateKey = 0;

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut public_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let rv = C_GenerateKeyPair(
            0,
            &mut mech,
            public_template.as_mut_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            &mut phPublicKey,
            &mut phPrivateKey,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_null_ph_public_key() {
        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut public_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut private_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let rv = C_GenerateKeyPair(
            0,
            &mut mech,
            public_template.as_mut_ptr(),
            0,
            private_template.as_mut_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_null_ph_private_key() {
        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut public_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut private_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let rv = C_GenerateKeyPair(
            0,
            &mut mech,
            public_template.as_mut_ptr(),
            0,
            private_template.as_mut_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_unknown_mech() {
        let mut public_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];
        let mut private_template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];
        let mut phPublicKey = 0;
        let mut phPrivateKey = 0;

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: 15000,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_GenerateKeyPair(
            0,
            &mut mech,
            public_template.as_mut_ptr(),
            0,
            private_template.as_mut_ptr(),
            0,
            &mut phPublicKey,
            &mut phPrivateKey,
        );
        assert_eq!(rv, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_generate_random_null_data() {
        let rv = C_GenerateRandom(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_random_invalid_length() {
        let mut random_data = vec![0; 1500];

        let rv = C_GenerateRandom(0, random_data.as_mut_ptr(), 1500);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_random_zero_length() {
        let mut random_data = vec![0; 1500];

        let rv = C_GenerateRandom(0, random_data.as_mut_ptr(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_wrap_key() {
        let rv = C_WrapKey(
            0,
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_unwrap_key() {
        let rv = C_UnwrapKey(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_derive_key() {
        let rv = C_DeriveKey(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_seed_random() {
        let rv = C_SeedRandom(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }
}
