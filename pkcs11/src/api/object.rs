use log::trace;

pub extern "C" fn C_FindObjectsInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_FindObjectsInit() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_FindObjects(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    phObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: cryptoki_sys::CK_ULONG,
    pulObjectCount: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_FindObjects() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
pub extern "C" fn C_FindObjectsFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_FindObjectsFinal() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
pub extern "C" fn C_GetAttributeValue(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetAttributeValue() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
pub extern "C" fn C_GetObjectSize(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pulSize: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetObjectSize() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_CreateObject(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_CreateObject() called - NYI");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_CopyObject(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phNewObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_CopyObject() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DestroyObject(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_DestroyObject() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SetAttributeValue(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SetAttributeValue() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
