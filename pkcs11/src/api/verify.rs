/*
    We won't implement these function as it is not a feature of NetHSM.
*/

use log::trace;

#[no_mangle]
pub extern "C" fn C_VerifyInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyInit() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_Verify(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    ulSignatureLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Verify() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyUpdate() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    ulSignatureLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyFinal() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_VerifyRecoverInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_VerifyRecoverInit() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
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

// just test that the functions return CKR_FUNCTION_NOT_SUPPORTED
#[cfg(test)]
mod tests {
    use cryptoki_sys::CK_ULONG;

    use crate::backend::slot::init_for_tests;

    use super::*;

    #[test]
    fn test_verify_init() {
        init_for_tests();
        let rv = C_VerifyInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_verify() {
        init_for_tests();
        let mut data = [0u8; 1];
        let mut sig = [0u8; 1];
        let rv = C_Verify(
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            sig.len() as CK_ULONG,
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_verify_update() {
        init_for_tests();
        let mut data = [0u8; 1];
        let rv = C_VerifyUpdate(0, data.as_mut_ptr(), data.len() as CK_ULONG);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_verify_final() {
        init_for_tests();
        let mut sig = [0u8; 1];
        let rv = C_VerifyFinal(0, sig.as_mut_ptr(), sig.len() as CK_ULONG);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_verify_recover_init() {
        init_for_tests();
        let rv = C_VerifyRecoverInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_verify_recover() {
        init_for_tests();
        let mut sig = [0u8; 1];
        let mut data = [0u8; 1];
        let mut data_len = 0;
        let rv = C_VerifyRecover(
            0,
            sig.as_mut_ptr(),
            sig.len() as CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
