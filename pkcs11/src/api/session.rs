use log::{error, trace};

use crate::backend::slot::get_slot;
use crate::data::SESSION_MANAGER;
use crate::read_session;

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
    ensure_init!();

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
    let mut manager = SESSION_MANAGER.lock().unwrap();
    let session = manager.create_session(slotID, slot, flags);

    trace!("C_OpenSession() created session: {:?}", session);

    unsafe {
        std::ptr::write(phSession, session);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_CloseSession(hSession: cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV {
    trace!("C_CloseSession() called with session handle {}.", hSession);
    ensure_init!();

    let mut manager = SESSION_MANAGER.lock().unwrap();
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
    ensure_init!();

    if get_slot(slotID as usize).is_err() {
        error!(
            "C_CloseAllSessions() called with invalid slotID {}.",
            slotID
        );
        return cryptoki_sys::CKR_SLOT_ID_INVALID;
    }

    let mut manager = SESSION_MANAGER.lock().unwrap();

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
    ensure_init!();

    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    read_session!(hSession, session);

    unsafe {
        std::ptr::write(pInfo, session.get_ck_info());
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GetOperationState(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOperationState: cryptoki_sys::CK_BYTE_PTR,
    pulOperationStateLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetOperationState() called");
    ensure_init!();

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
    ensure_init!();

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GetFunctionStatus(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetFunctionStatus() called");
    ensure_init!();

    cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL
}

pub extern "C" fn C_CancelFunction(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_CancelFunction() called");
    ensure_init!();

    cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL
}

#[cfg(test)]
mod tests {
    use crate::backend::slot::set_test_config_env;

    use super::*;

    #[test]
    fn test_open_session_null_session() {
        set_test_config_env();
        let rv = C_OpenSession(
            0,
            cryptoki_sys::CKF_SERIAL_SESSION | cryptoki_sys::CKF_RW_SESSION,
            std::ptr::null_mut(),
            None,
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_open_session_parallel() {
        set_test_config_env();
        let mut session = 0;
        let rv = C_OpenSession(0, 0, std::ptr::null_mut(), None, &mut session);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    }

    #[test]
    fn test_delete_session_invalid() {
        set_test_config_env();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_CloseSession(0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_close_all_sessions_invalid_slot() {
        set_test_config_env();

        let rv = C_CloseAllSessions(99);
        assert_eq!(rv, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_close_all_sessions() {
        set_test_config_env();
        let slot = get_slot(0).unwrap();

        let handle = SESSION_MANAGER.lock().unwrap().create_session(0, slot, 0);

        let rv = C_CloseAllSessions(0);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert!(SESSION_MANAGER
            .lock()
            .unwrap()
            .get_session(handle)
            .is_none());
    }

    #[test]
    fn test_get_session_info_invalid_session() {
        set_test_config_env();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut info = cryptoki_sys::CK_SESSION_INFO::default();
        let rv = C_GetSessionInfo(0, &mut info);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_session_info_null_info() {
        set_test_config_env();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_GetSessionInfo(session_handle, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_operation_state() {
        set_test_config_env();
        let rv = C_GetOperationState(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_set_operation_state() {
        set_test_config_env();
        let rv = C_SetOperationState(0, std::ptr::null_mut(), 0, 0, 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_get_function_status() {
        set_test_config_env();
        let rv = C_GetFunctionStatus(0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL);
    }

    #[test]
    fn test_cancel_function() {
        set_test_config_env();
        let rv = C_CancelFunction(0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL);
    }
}
