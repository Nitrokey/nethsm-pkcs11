/*
    We won't implement these function as it is not a feature of NetHSM.
*/

use log::trace;

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
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
