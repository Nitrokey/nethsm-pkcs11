/*
    We won't implement these function as it is not a feature of NetHSM.
*/

use cryptoki_sys::CKR_OK;
use log::{error, trace};
use openapi::apis::default_api;

use crate::{data::SESSION_MANAGER, lock_mutex};

pub extern "C" fn C_InitPIN(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    uPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_InitPIN() called ");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SetPIN(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOldPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulOldLen: cryptoki_sys::CK_ULONG,
    pNewPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulNewLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SetPIN() called ");
    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!("Function called with invalid session handle {}.", hSession);
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    if pOldPin.is_null() || pNewPin.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let old_pin = unsafe { std::slice::from_raw_parts(pOldPin, ulOldLen as usize) };
    let new_pin = unsafe { std::slice::from_raw_parts(pNewPin, ulNewLen as usize) };

    // parse string to utf8

    let old_pin = match std::str::from_utf8(old_pin) {
        Ok(pin) => pin,
        Err(_) => return cryptoki_sys::CKR_ARGUMENTS_BAD,
    };

    let new_pin = match std::str::from_utf8(new_pin) {
        Ok(pin) => pin,
        Err(_) => return cryptoki_sys::CKR_ARGUMENTS_BAD,
    };

    if CKR_OK != session.login(cryptoki_sys::CKU_USER, old_pin.to_string()) {
        return cryptoki_sys::CKR_PIN_INCORRECT;
    }

    let user_id = match session.api_config.basic_auth.as_ref() {
        Some(basic_auth) => basic_auth.0.clone(),
        None => return cryptoki_sys::CKR_GENERAL_ERROR,
    };

    match default_api::users_user_id_passphrase_post(
        &session.api_config,
        &user_id,
        openapi::models::UserPassphrasePostData {
            passphrase: new_pin.to_string(),
        },
    ) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(err) => {
            error!("Failed to set new pin: {:?}", err);
            cryptoki_sys::CKR_GENERAL_ERROR
        }
    }
}
