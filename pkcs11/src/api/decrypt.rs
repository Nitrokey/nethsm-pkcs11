use log::trace;

pub extern "C" fn C_DecryptInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptInit() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_Decrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedDataLen: cryptoki_sys::CK_ULONG,
    pData: cryptoki_sys::CK_BYTE_PTR,
    pulDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_Decrypt() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptUpdate() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptFinal() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptVerifyUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptVerifyUpdate() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
