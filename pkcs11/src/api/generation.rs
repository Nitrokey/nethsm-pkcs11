use base64::{engine::general_purpose, Engine};
use cryptoki_sys::CKR_OK;
use log::{error, trace};
use nethsm_sdk_rs::apis::default_api;

use crate::{
    backend::{
        db::attr::CkRawAttrTemplate,
        mechanism::{CkRawMechanism, Mechanism},
    },
    lock_mutex, lock_session,
    utils::get_tokio_rt,
};

pub extern "C" fn C_GenerateKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateKey() called");

    if pMechanism.is_null() || phKey.is_null() || pTemplate.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    lock_session!(hSession, session);

    let mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };

    trace!("C_GenerateKey() mech: {:?}", mech.type_());
    trace!("C_GenerateKey() mech param len: {:?}", mech.len());

    let template =
        unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) };

    let mech = match Mechanism::from_ckraw_mech(&mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_GenerateKey() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

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

    if pMechanism.is_null()
        || phPublicKey.is_null()
        || phPrivateKey.is_null()
        || pPublicKeyTemplate.is_null()
        || pPrivateKeyTemplate.is_null()
    {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    lock_session!(hSession, session);

    let mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };

    trace!("C_GenerateKeyPair() mech: {:?}", mech.type_());
    trace!("C_GenerateKey() mech param len: {:?}", mech.len());

    trace!("Private count: {:?}", ulPrivateKeyAttributeCount);
    trace!("Public count: {:?}", ulPublicKeyAttributeCount);

    let mech = match Mechanism::from_ckraw_mech(&mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_GenerateKeyPair() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    let public_template = unsafe {
        CkRawAttrTemplate::from_raw_ptr_unchecked(
            pPublicKeyTemplate,
            ulPublicKeyAttributeCount as usize,
        )
    };

    let private_template = unsafe {
        CkRawAttrTemplate::from_raw_ptr_unchecked(
            pPrivateKeyTemplate,
            ulPrivateKeyAttributeCount as usize,
        )
    };

    public_template.iter().for_each(|attr| {
        trace!(
            "Public template: {:?}, {:?}",
            attr.type_(),
            attr.val_bytes()
        );
    });

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
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

// we silently ignore this function as NetHSM handles the random number generation
pub extern "C" fn C_SeedRandom(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSeed: cryptoki_sys::CK_BYTE_PTR,
    ulSeedLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SeedRandom() called");
    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GenerateRandom(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    RandomData: cryptoki_sys::CK_BYTE_PTR,
    ulRandomLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateRandom() called");

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

    let a = |api_config: nethsm_sdk_rs::apis::configuration::Configuration| {
        // let api_config = api_config;
        async {
            let api_config = api_config;
            default_api::random_post(
                &api_config,
                nethsm_sdk_rs::models::RandomRequestData {
                    length: ulRandomLen as i32,
                },
            )
            .await
        }
    };

    let data = match get_tokio_rt().block_on(async {
        session
            .login_ctx
            .try_(
                |api_config| async move {
                    default_api::random_post(
                        &api_config,
                        nethsm_sdk_rs::models::RandomRequestData {
                            length: ulRandomLen as i32,
                        },
                    )
                    .await
                },
                crate::backend::login::UserMode::Operator,
            )
            .await
    }) {
        Ok(data) => data,
        Err(e) => {
            error!("C_GenerateRandom() failed to generate random data: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    // parse base64 string to bytes

    let raw_data = match general_purpose::STANDARD.decode(data.entity.random) {
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
