use log::trace;

pub extern "C" fn C_DigestInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: *mut cryptoki_sys::CK_MECHANISM,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestInit() called");

    if pMechanism.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_Digest(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: *mut cryptoki_sys::CK_BYTE,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Digest() called");

    if pData.is_null() || pDigest.is_null() || pulDigestLen.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: *mut cryptoki_sys::CK_BYTE,
    ulPartLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestUpdate() called");

    if pPart.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestFinal() called");

    if pDigest.is_null() || pulDigestLen.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestKey() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestEncryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestEncryptUpdate() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptDigestUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptDigestUpdate() called ");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
