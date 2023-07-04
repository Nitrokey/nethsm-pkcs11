use log::trace;

pub extern "C" fn C_EncryptInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_EncryptInit() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_Encrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_Encrypt() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_EncryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_EncryptUpdate() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_EncryptFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_EncryptFinal() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
