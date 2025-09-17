use log::{error, trace};

use crate::{
    api::api_function,
    backend::{slot::get_slot, Pkcs11Error},
    data::{self, SESSION_MANAGER},
};

api_function!(
    C_OpenSession = open_session;
    slotID: cryptoki_sys::CK_SLOT_ID,
    flags: cryptoki_sys::CK_FLAGS,
    pApplication: cryptoki_sys::CK_VOID_PTR,
    Notify: cryptoki_sys::CK_NOTIFY,
    phSession: cryptoki_sys::CK_SESSION_HANDLE_PTR,
);

fn open_session(
    slot_id: cryptoki_sys::CK_SLOT_ID,
    flags: cryptoki_sys::CK_FLAGS,
    _application_ptr: cryptoki_sys::CK_VOID_PTR,
    _notify: cryptoki_sys::CK_NOTIFY,
    session_ptr: cryptoki_sys::CK_SESSION_HANDLE_PTR,
) -> Result<(), Pkcs11Error> {
    trace!("C_OpenSession() called with slotID {slot_id}, flags {flags}");

    if session_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }
    // Serial should always be set
    if flags & cryptoki_sys::CKF_SERIAL_SESSION == 0 {
        return Err(Pkcs11Error::SessionParallelNotSupported);
    }

    let slot = get_slot(slot_id).map_err(|_| {
        error!("C_OpenSession() called with invalid slotID {slot_id}.");
        Pkcs11Error::SlotIdInvalid
    })?;

    // create the session in memory
    let mut manager = SESSION_MANAGER.lock().unwrap();
    let session = manager.create_session(slot_id, slot, flags);

    trace!("C_OpenSession() created session: {session:?}");

    unsafe {
        std::ptr::write(session_ptr, session);
    }

    Ok(())
}

api_function!(
    C_CloseSession = close_session;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
);

fn close_session(session: cryptoki_sys::CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
    trace!("C_CloseSession() called with session handle {session}.");

    let mut manager = SESSION_MANAGER.lock().unwrap();
    let result = manager.delete_session(session);

    if result.is_none() {
        error!("C_CloseSession() called with invalid session handle {session}.");
        return Err(Pkcs11Error::SessionHandleInvalid);
    }

    Ok(())
}

api_function!(
    C_CloseAllSessions = close_all_sessions;
    slotID: cryptoki_sys::CK_SLOT_ID,
);

fn close_all_sessions(slot_id: cryptoki_sys::CK_SLOT_ID) -> Result<(), Pkcs11Error> {
    if get_slot(slot_id).is_err() {
        error!("C_CloseAllSessions() called with invalid slotID {slot_id}.");
        return Err(Pkcs11Error::SlotIdInvalid);
    }

    let mut manager = SESSION_MANAGER.lock().unwrap();
    manager.delete_all_slot_sessions(slot_id);
    Ok(())
}

api_function!(
    C_GetSessionInfo = get_session_info;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pInfo: cryptoki_sys::CK_SESSION_INFO_PTR,
);

fn get_session_info(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    info_ptr: cryptoki_sys::CK_SESSION_INFO_PTR,
) -> Result<(), Pkcs11Error> {
    if info_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let session = data::get_session(session)?;
    let session = data::lock_session(&session)?;

    unsafe {
        std::ptr::write(info_ptr, session.get_ck_info());
    }

    Ok(())
}

api_function!(
    C_GetOperationState = get_operation_state;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOperationState: cryptoki_sys::CK_BYTE_PTR,
    pulOperationStateLen: cryptoki_sys::CK_ULONG_PTR,
);

fn get_operation_state(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _operation_state_ptr: cryptoki_sys::CK_BYTE_PTR,
    _operation_state_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_SetOperationState = set_operation_state;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pOperationState: cryptoki_sys::CK_BYTE_PTR,
    ulOperationStateLen: cryptoki_sys::CK_ULONG,
    hEncryptionKey: cryptoki_sys::CK_OBJECT_HANDLE,
    hAuthenticationKey: cryptoki_sys::CK_OBJECT_HANDLE,
);

fn set_operation_state(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _operation_state_ptr: cryptoki_sys::CK_BYTE_PTR,
    _operation_state_len: cryptoki_sys::CK_ULONG,
    _encryption_key: cryptoki_sys::CK_OBJECT_HANDLE,
    _authentication_key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_GetFunctionStatus = get_function_status;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
);

fn get_function_status(_session: cryptoki_sys::CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotParallel)
}

api_function!(
    C_CancelFunction = cancel_function;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
);

fn cancel_function(_session: cryptoki_sys::CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotParallel)
}

#[cfg(test)]
mod tests {
    use crate::backend::slot::init_for_tests;

    use super::*;

    #[test]
    fn test_open_session_null_session() {
        init_for_tests();
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
        init_for_tests();
        let mut session = 0;
        let rv = C_OpenSession(0, 0, std::ptr::null_mut(), None, &mut session);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    }

    #[test]
    fn test_delete_session_invalid() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_CloseSession(0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_close_all_sessions_invalid_slot() {
        init_for_tests();

        let rv = C_CloseAllSessions(99);
        assert_eq!(rv, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_close_all_sessions() {
        init_for_tests();
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
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut info = cryptoki_sys::CK_SESSION_INFO::default();
        let rv = C_GetSessionInfo(0, &mut info);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_session_info_null_info() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_GetSessionInfo(session_handle, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_operation_state() {
        init_for_tests();
        let rv = C_GetOperationState(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_set_operation_state() {
        init_for_tests();
        let rv = C_SetOperationState(0, std::ptr::null_mut(), 0, 0, 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_get_function_status() {
        init_for_tests();
        let rv = C_GetFunctionStatus(0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL);
    }

    #[test]
    fn test_cancel_function() {
        init_for_tests();
        let rv = C_CancelFunction(0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_PARALLEL);
    }
}
