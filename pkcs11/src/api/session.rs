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
    trace!(
        "C_OpenSession() called with slotID {}, flags {}",
        slotID,
        flags
    );

    if phSession.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }
    // Serial should always be set
    if flags & cryptoki_sys::CKF_SERIAL_SESSION == 0 {
        return cryptoki_sys::CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    let slot = match get_slot(slotID as usize) {
        Ok(slot) => slot,
        Err(_) => {
            error!("C_OpenSession() called with invalid slotID {}.", slotID);
            return cryptoki_sys::CKR_SLOT_ID_INVALID;
        }
    };

    // create the session in memory
    let mut manager = lock_mutex!(SESSION_MANAGER);
    let session = manager.create_session(slotID, slot, flags);

    trace!("C_OpenSession() created session: {:?}", session);

    unsafe {
        *phSession = session;
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_CloseSession(hSession: cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV {
    trace!("C_CloseSession() called with session handle {}.", hSession);

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
    trace!(
        "C_GetSessionInfo() called with session handle {}.",
        hSession
    );

    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let manager = lock_mutex!(SESSION_MANAGER);

    let session = manager.get_session(hSession);

    let session_info = match session {
        Some(session) => session.get_ck_info(),
        None => {
            error!(
                "C_GetSessionInfo() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    trace!("C_GetSessionInfo() session info: {:?}", session_info);

    unsafe {
        std::ptr::write(pInfo, session_info);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_operation_state() {
        let rv = C_GetOperationState(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_set_operation_state() {
        let rv = C_SetOperationState(0, std::ptr::null_mut(), 0, 0, 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_get_function_status() {
        let rv = C_GetFunctionStatus(0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL);
    }

    #[test]
    fn test_cancel_function() {
        let rv = C_CancelFunction(0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL);
    }
}
