use base64::{engine::general_purpose, Engine};
use cryptoki_sys::CKR_OK;
use log::{error, trace};
use openapi::apis::default_api;

use crate::{lock_mutex, lock_session};

pub extern "C" fn C_GenerateKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateKey() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
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
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
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

    let api_config = match session.login_ctx.operator() {
        Some(conf) => conf,
        None => {
            error!(
                "C_GenerateRandom() called with session not connected as operator {}.",
                hSession
            );
            return cryptoki_sys::CKR_USER_NOT_LOGGED_IN;
        }
    };

    let data = match default_api::random_post(
        &api_config,
        openapi::models::RandomRequestData {
            length: ulRandomLen as i32,
        },
    ) {
        Ok(data) => data,
        Err(e) => {
            error!("C_GenerateRandom() failed to generate random data: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    // parse base64 string to bytes

    let raw_data = match general_purpose::STANDARD.decode(data.random) {
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
