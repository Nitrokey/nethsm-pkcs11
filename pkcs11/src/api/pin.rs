use log::error;

use crate::{api::api_function, backend::Pkcs11Error, data};

api_function!(
    C_InitPIN = init_pin;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    uPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
);

fn init_pin(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    uPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_SetPIN = set_pin;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOldPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulOldLen: cryptoki_sys::CK_ULONG,
    pNewPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulNewLen: cryptoki_sys::CK_ULONG,
);

fn set_pin(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOldPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulOldLen: cryptoki_sys::CK_ULONG,
    pNewPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulNewLen: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    if pOldPin.is_null() || pNewPin.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let old_pin = unsafe { std::slice::from_raw_parts(pOldPin, ulOldLen as usize) };
    let new_pin = unsafe { std::slice::from_raw_parts(pNewPin, ulNewLen as usize) };

    // parse string to utf8

    let old_pin = std::str::from_utf8(old_pin).map_err(|_| Pkcs11Error::ArgumentsBad)?;
    let new_pin = std::str::from_utf8(new_pin).map_err(|_| Pkcs11Error::ArgumentsBad)?;

    session.login(cryptoki_sys::CKU_USER, old_pin.to_string())?;

    if !session
        .login_ctx
        .can_run_mode(crate::backend::login::UserMode::OperatorOrAdministrator)
    {
        error!("C_SetPIN() called with session not connected as operator {hSession}.");
        return Err(Pkcs11Error::UserNotLoggedIn);
    }
    session.login_ctx.change_pin(new_pin.to_string())
}

#[cfg(test)]
mod tests {

    use cryptoki_sys::CK_ULONG;

    use crate::{backend::slot::init_for_tests, data::SESSION_MANAGER};

    use super::*;

    #[test]
    fn test_init_pin() {
        init_for_tests();
        let rv = C_InitPIN(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_set_pin_null_old_pin() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let newPin = "12345678";
        let rv = C_SetPIN(
            session_handle,
            std::ptr::null_mut(),
            0,
            newPin.as_ptr() as *mut u8,
            newPin.len() as CK_ULONG,
        );

        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_set_pin_null_new_pin() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let oldPin = "12345678";
        let rv = C_SetPIN(
            session_handle,
            oldPin.as_ptr() as *mut u8,
            oldPin.len() as CK_ULONG,
            std::ptr::null_mut(),
            0,
        );

        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_set_pin_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let oldPin = "12345678";
        let newPin = "12345678";

        let rv = C_SetPIN(
            0,
            oldPin.as_ptr() as *mut u8,
            oldPin.len() as CK_ULONG,
            newPin.as_ptr() as *mut u8,
            newPin.len() as CK_ULONG,
        );
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_set_pin_no_utf8_old_pin() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        // random bytes
        let oldPin = [
            0xC0, 0xC1, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        ];
        let newPin = "12345678";

        let rv = C_SetPIN(
            session_handle,
            oldPin.as_ptr() as *mut u8,
            oldPin.len() as CK_ULONG,
            newPin.as_ptr() as *mut u8,
            newPin.len() as CK_ULONG,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_set_pin_no_utf8_new_pin() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let oldPin = "12345678";
        // random bytes
        let newPin = [
            0xC0, 0xC1, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        ];

        let rv = C_SetPIN(
            session_handle,
            oldPin.as_ptr() as *mut u8,
            oldPin.len() as CK_ULONG,
            newPin.as_ptr() as *mut u8,
            newPin.len() as CK_ULONG,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_set_pin_no_user() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let oldPin = "12345678";
        let newPin = "12345678";

        let rv = C_SetPIN(
            session_handle,
            oldPin.as_ptr() as *mut u8,
            oldPin.len() as CK_ULONG,
            newPin.as_ptr() as *mut u8,
            newPin.len() as CK_ULONG,
        );
        assert_eq!(rv, cryptoki_sys::CKR_USER_TYPE_INVALID);
    }
}
