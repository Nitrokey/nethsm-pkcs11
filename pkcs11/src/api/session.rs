use log::{error, trace};

use crate::backend::slot::get_slot;
use crate::data::SESSION_MANAGER;
use crate::lock_mutex;

pub extern "C" fn C_OpenSession(
    slotID: cryptoki_sys::CK_SLOT_ID,
    flags: cryptoki_sys::CK_FLAGS,
    _pApplication: cryptoki_sys::CK_VOID_PTR,
    _Notify: cryptoki_sys::CK_NOTIFY,
    phSession: cryptoki_sys::CK_SESSION_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_OpenSession() called");

    if phSession.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }
    // Serial should always be set
    if flags & cryptoki_sys::CKF_SERIAL_SESSION == 0 {
        return cryptoki_sys::CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    if get_slot(slotID as usize).is_err() {
        error!("C_OpenSession() called with invalid slotID {}.", slotID);
        return cryptoki_sys::CKR_SLOT_ID_INVALID;
    }

    // create the session in memory
    let mut manager = lock_mutex!(SESSION_MANAGER);
    let session = manager.create_session(slotID, flags);

    unsafe {
        *phSession = session;
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_CloseSession(hSession: cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV {
    trace!("C_CloseSession() called");

    let mut manager = lock_mutex!(SESSION_MANAGER);
    let result = manager.delete_session(hSession);

    if result.is_none() {
        error!(
            "C_CloseSession() called with invalid session handle {}.",
            hSession
        );
        return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_CloseAllSessions(slotID: cryptoki_sys::CK_SLOT_ID) -> cryptoki_sys::CK_RV {
    trace!("C_CloseAllSessions() called");

    if get_slot(slotID as usize).is_err() {
        error!(
            "C_CloseAllSessions() called with invalid slotID {}.",
            slotID
        );
        return cryptoki_sys::CKR_SLOT_ID_INVALID;
    }

    let mut manager = lock_mutex!(SESSION_MANAGER);

    manager.delete_all_slot_sessions(slotID);

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GetSessionInfo(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pInfo: cryptoki_sys::CK_SESSION_INFO_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetSessionInfo() called");

    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let manager = lock_mutex!(SESSION_MANAGER);

    let session_info = manager.get_session_info(hSession);

    if session_info.is_none() {
        error!(
            "C_GetSessionInfo() called with invalid session handle {}.",
            hSession
        );
        return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
    }

    unsafe {
        *pInfo = *session_info.unwrap();
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GetOperationState(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOperationState: cryptoki_sys::CK_BYTE_PTR,
    pulOperationStateLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetOperationState() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SetOperationState(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOperationState: cryptoki_sys::CK_BYTE_PTR,
    ulOperationStateLen: cryptoki_sys::CK_ULONG,
    hEncryptionKey: cryptoki_sys::CK_OBJECT_HANDLE,
    hAuthenticationKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_SetOperationState() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GetFunctionStatus(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetFunctionStatus() called");
    cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL
}

pub extern "C" fn C_CancelFunction(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_CancelFunction() called");
    cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL
}
