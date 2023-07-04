use log::trace;

pub extern "C" fn C_OpenSession(
    slotID: cryptoki_sys::CK_SLOT_ID,
    flags: cryptoki_sys::CK_FLAGS,
    _pApplication: cryptoki_sys::CK_VOID_PTR,
    _Notify: cryptoki_sys::CK_NOTIFY,
    phSession: cryptoki_sys::CK_SESSION_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_OpenSession() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_CloseSession(hSession: cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV {
    trace!("C_CloseSession() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_CloseAllSessions(slotID: cryptoki_sys::CK_SLOT_ID) -> cryptoki_sys::CK_RV {
    trace!("C_CloseAllSessions() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GetSessionInfo(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pInfo: cryptoki_sys::CK_SESSION_INFO_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetSessionInfo() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
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
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_CancelFunction(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_CancelFunction() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
