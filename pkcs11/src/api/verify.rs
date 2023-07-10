/*
    We won't implement these function as it is not a feature of NetHSM.
*/

use log::trace;

pub extern "C" fn C_VerifyInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyInit() called");
    if pMechanism.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_Verify(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    ulSignatureLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Verify() called");
    if pData.is_null() || pSignature.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_VerifyUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyUpdate() called");
    if pPart.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_VerifyFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    ulSignatureLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyFinal() called");

    if pSignature.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_VerifyRecoverInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyRecoverInit() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_VerifyRecover(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    ulSignatureLen: cryptoki_sys::CK_ULONG,
    pData: cryptoki_sys::CK_BYTE_PTR,
    pulDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyRecover() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
