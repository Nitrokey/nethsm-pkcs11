use base64ct::{Base64, Encoding};
use log::{error, trace};
use nethsm_sdk_rs::apis::default_api;

use crate::{
    api::api_function,
    backend::{
        db::attr::CkRawAttrTemplate,
        mechanism::{CkRawMechanism, Mechanism},
        Pkcs11Error,
    },
    data,
};

api_function!(
    C_GenerateKey = generate_key;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
);

fn generate_key(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    mechanism_ptr: cryptoki_sys::CK_MECHANISM_PTR,
    template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    count: cryptoki_sys::CK_ULONG,
    key_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> Result<(), Pkcs11Error> {
    // template_ptr and mechanism_ptr are checked for null with `from_raw_ptr`

    if key_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let mech =
        unsafe { CkRawMechanism::from_raw_ptr(mechanism_ptr) }.ok_or(Pkcs11Error::ArgumentsBad)?;

    trace!("C_GenerateKey() mech: {:?}", mech.type_());
    trace!("C_GenerateKey() mech param len: {:?}", mech.len());
    let mech = Mechanism::from_ckraw_mech(&mech).map_err(|err| {
        error!("C_GenerateKey() failed to convert mechanism: {err}");
        Pkcs11Error::MechanismInvalid
    })?;

    let template = unsafe { CkRawAttrTemplate::from_raw_ptr(template_ptr, count as usize) }
        .ok_or(Pkcs11Error::ArgumentsBad)?;

    let session = data::get_session(session)?;
    let session = data::lock_session(&session)?;

    let key = session
        .generate_key(&template, None, &mech)
        .map_err(|err| {
            error!("C_GenerateKey() failed to generate key: {err:?}");
            Pkcs11Error::FunctionFailed
        })?;

    if key.is_empty() {
        error!("C_GenerateKey() failed to generate key,invalid length: {key:?}");
        return Err(Pkcs11Error::FunctionFailed);
    }

    unsafe {
        std::ptr::write(key_ptr, key[0].0);
    }

    Ok(())
}

api_function!(
    C_GenerateKeyPair = generate_key_pair;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pPublicKeyTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: cryptoki_sys::CK_ULONG,
    pPrivateKeyTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: cryptoki_sys::CK_ULONG,
    phPublicKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    phPrivateKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
);

#[allow(clippy::too_many_arguments)]
fn generate_key_pair(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    mechanism_ptr: cryptoki_sys::CK_MECHANISM_PTR,
    public_key_template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    public_key_attribute_count: cryptoki_sys::CK_ULONG,
    private_key_template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    private_key_attribute_count: cryptoki_sys::CK_ULONG,
    public_key_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    private_key_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> Result<(), Pkcs11Error> {
    // mechamism_ptr, private_key_template_ptr, public_key_template_ptr  checked for null with `from_raw_ptr`

    if public_key_ptr.is_null() || private_key_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let mech =
        unsafe { CkRawMechanism::from_raw_ptr(mechanism_ptr) }.ok_or(Pkcs11Error::ArgumentsBad)?;

    trace!("C_GenerateKeyPair() mech: {:?}", mech.type_());
    trace!("C_GenerateKeyPair() mech param len: {:?}", mech.len());

    trace!("Private count: {private_key_attribute_count:?}");
    trace!("Public count: {public_key_attribute_count:?}");

    let mech = Mechanism::from_ckraw_mech(&mech).map_err(|err| {
        error!("C_GenerateKeyPair() failed to convert mechanism: {err}");
        Pkcs11Error::MechanismInvalid
    })?;
    let public_template = unsafe {
        CkRawAttrTemplate::from_raw_ptr(
            public_key_template_ptr,
            public_key_attribute_count as usize,
        )
    }
    .ok_or(Pkcs11Error::ArgumentsBad)?;

    let private_template = unsafe {
        CkRawAttrTemplate::from_raw_ptr(
            private_key_template_ptr,
            private_key_attribute_count as usize,
        )
    }
    .ok_or(Pkcs11Error::ArgumentsBad)?;

    let session = data::get_session(session)?;
    let session = data::lock_session(&session)?;

    let keys = session
        .generate_key(&private_template, Some(&public_template), &mech)
        .map_err(|err| {
            error!("C_GenerateKeyPair() failed to generate key: {err:?}");
            Pkcs11Error::FunctionFailed
        })?;

    if keys.len() < 2 {
        error!("C_GenerateKeyPair() failed to generate key,invalid length: {keys:?}");
        return Err(Pkcs11Error::FunctionFailed);
    }

    unsafe {
        std::ptr::write(public_key_ptr, keys[0].0);
        std::ptr::write(private_key_ptr, keys[1].0);
    }

    Ok(())
}

api_function!(
    C_WrapKey = wrap_key;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hWrappingKey: cryptoki_sys::CK_OBJECT_HANDLE,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pWrappedKey: cryptoki_sys::CK_BYTE_PTR,
    pulWrappedKeyLen: cryptoki_sys::CK_ULONG_PTR,
);

fn wrap_key(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _mechanism_ptr: cryptoki_sys::CK_MECHANISM_PTR,
    _wrapping_key: cryptoki_sys::CK_OBJECT_HANDLE,
    _key: cryptoki_sys::CK_OBJECT_HANDLE,
    _wrapped_key_ptr: cryptoki_sys::CK_BYTE_PTR,
    _wrapped_key_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_UnwrapKey = unwrap_key;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hUnwrappingKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pWrappedKey: cryptoki_sys::CK_BYTE_PTR,
    ulWrappedKeyLen: cryptoki_sys::CK_ULONG,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulAttributeCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
);

#[allow(clippy::too_many_arguments)]
fn unwrap_key(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _mechanism_ptr: cryptoki_sys::CK_MECHANISM_PTR,
    _unwrapping_key: cryptoki_sys::CK_OBJECT_HANDLE,
    _wrapped_key_ptr: cryptoki_sys::CK_BYTE_PTR,
    _wrapped_key_len: cryptoki_sys::CK_ULONG,
    _template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    _attribute_count: cryptoki_sys::CK_ULONG,
    _key_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_DeriveKey = derive_key;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hBaseKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulAttributeCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
);

fn derive_key(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _mechanism_ptr: cryptoki_sys::CK_MECHANISM_PTR,
    _base_key: cryptoki_sys::CK_OBJECT_HANDLE,
    _template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    _attribute_count: cryptoki_sys::CK_ULONG,
    _key_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_SeedRandom = seed_random;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSeed: cryptoki_sys::CK_BYTE_PTR,
    ulSeedLen: cryptoki_sys::CK_ULONG,
);

// we silently ignore this function as NetHSM handles the random number generation
fn seed_random(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _seed_ptr: cryptoki_sys::CK_BYTE_PTR,
    _seed_len: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    Ok(())
}

api_function!(
    C_GenerateRandom = generate_random;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pRandomData: cryptoki_sys::CK_BYTE_PTR,
    ulRandomLen: cryptoki_sys::CK_ULONG,
);

fn generate_random(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    random_data_ptr: cryptoki_sys::CK_BYTE_PTR,
    random_len: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    if random_data_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    if random_len == 0 {
        return Ok(());
    }

    if random_len > 1024 {
        error!(
            "C_GenerateRandom() called with invalid length {random_len}, NetHSM supports up to 1024 bytes"
        );
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let session = data::get_session(session)?;
    let session = data::lock_session(&session)?;

    if !session
        .login_ctx
        .can_run_mode(crate::backend::login::UserMode::Operator)
    {
        error!("C_GenerateRandom() called with session not connected as operator.");
        return Err(Pkcs11Error::UserNotLoggedIn);
    }

    let data = session
        .login_ctx
        .try_(
            |api_config| {
                default_api::random_post(
                    api_config,
                    nethsm_sdk_rs::models::RandomRequestData::new(random_len as i32),
                )
            },
            crate::backend::login::UserMode::Operator,
        )
        .map_err(|err| {
            error!("C_GenerateRandom() failed to generate random data: {err:?}");
            Pkcs11Error::FunctionFailed
        })?;

    // parse base64 string to bytes

    let raw_data = Base64::decode_vec(&data.entity.random).map_err(|err| {
        error!("C_GenerateRandom() failed to decode random data: {err:?}");
        Pkcs11Error::FunctionFailed
    })?;

    unsafe {
        std::ptr::copy_nonoverlapping(raw_data.as_ptr(), random_data_ptr, random_len as usize);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::backend::slot::init_for_tests;

    use super::*;

    #[test]
    fn test_generate_key_null_mech() {
        let _guard = init_for_tests();
        let mut template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut key = 0;

        let rv = C_GenerateKey(0, std::ptr::null_mut(), template.as_mut_ptr(), 0, &mut key);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_null_template() {
        let _guard = init_for_tests();
        let mut key = 0;

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_GenerateKey(0, &mut mech, std::ptr::null_mut(), 0, &mut key);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_null_phkey() {
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
        let mut template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut key = 0;

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: 15000,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_GenerateKey(0, &mut mech, template.as_mut_ptr(), 0, &mut key);
        assert_eq!(rv, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_generate_key_pair_null_mech() {
        let _guard = init_for_tests();
        let mut template = vec![cryptoki_sys::CK_ATTRIBUTE {
            type_: 0,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];

        let mut public_key = 0;
        let mut private_key = 0;

        let rv = C_GenerateKeyPair(
            0,
            std::ptr::null_mut(),
            template.as_mut_ptr(),
            0,
            template.as_mut_ptr(),
            0,
            &mut public_key,
            &mut private_key,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_null_public_template() {
        let _guard = init_for_tests();
        let mut public_key = 0;
        let mut private_key = 0;

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
            &mut public_key,
            &mut private_key,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_null_private_template() {
        let _guard = init_for_tests();
        let mut public_key = 0;
        let mut private_key = 0;

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
            &mut public_key,
            &mut private_key,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_key_pair_null_ph_public_key() {
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
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
        let mut public_key = 0;
        let mut private_key = 0;

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
            &mut public_key,
            &mut private_key,
        );
        assert_eq!(rv, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_generate_random_null_data() {
        let _guard = init_for_tests();
        let rv = C_GenerateRandom(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_random_invalid_length() {
        let _guard = init_for_tests();
        let mut random_data = vec![0; 1500];

        let rv = C_GenerateRandom(0, random_data.as_mut_ptr(), 1500);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_generate_random_zero_length() {
        let _guard = init_for_tests();
        let mut random_data = vec![0; 1500];

        let rv = C_GenerateRandom(0, random_data.as_mut_ptr(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_wrap_key() {
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
        let rv = C_SeedRandom(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }
}
