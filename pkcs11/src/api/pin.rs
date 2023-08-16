/*
    We won't implement these function as it is not a feature of NetHSM.
*/

use log::{error, trace};

use crate::{lock_mutex, lock_session};

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
    lock_session!(hSession, session);

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

    if let Err(err) = session.login(cryptoki_sys::CKU_USER, old_pin.to_string()) {
        return err.into();
    }

    if !session
        .login_ctx
        .can_run_mode(crate::backend::login::UserMode::OperatorOrAdministrator)
    {
        error!(
            "C_SetPIN() called with session not connected as operator {}.",
            hSession
        );
        return cryptoki_sys::CKR_USER_NOT_LOGGED_IN;
    }
    session.login_ctx.change_pin(new_pin.to_string())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_init_pin() {
        let rv = C_InitPIN(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
