use cryptoki_sys::{CKR_OK, CK_ULONG};
use log::{error, trace};

use crate::{
    backend::mechanism::{CkRawMechanism, Mechanism},
    lock_session,
};

#[no_mangle]
pub extern "C" fn C_SignInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: *mut cryptoki_sys::CK_MECHANISM,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!(
        "C_SignInit() called with hKey {} and session {}",
        hKey,
        hSession
    );

    let raw_mech = match unsafe { CkRawMechanism::from_raw_ptr(pMechanism) } {
        Some(mech) => mech,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

    let mech = match Mechanism::from_ckraw_mech(&raw_mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_SignInit() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    lock_session!(hSession, session);

    match session.sign_init(&mech, hKey) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn C_Sign(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: *mut cryptoki_sys::CK_BYTE,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: *mut cryptoki_sys::CK_BYTE,
    pulSignatureLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Sign() called");

    lock_session!(hSession, session);

    trace!("pData null {}", pData.is_null());
    trace!("pulSignatureLen null {}", pulSignatureLen.is_null());

    if pData.is_null() || pulSignatureLen.is_null() {
        trace!("aborting sign due to null");
        session.sign_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };

    let buffer_size = unsafe { *pulSignatureLen } as usize;

    let theoretical_size = match session.sign_theoretical_size() {
        Ok(size) => size,
        Err(err) => {
            session.sign_clear();
            return err.into();
        }
    };

    unsafe {
        std::ptr::write(pulSignatureLen, theoretical_size as CK_ULONG);
    }

    if pSignature.is_null() {
        trace!("sending only the size");
        // only the size was requested
        return cryptoki_sys::CKR_OK;
    }

    if buffer_size < theoretical_size {
        trace!("buffer too small");
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let signature = match session.sign(data) {
        Ok(signature) => signature,
        Err(err) => {
            session.sign_clear();
            return err.into();
        }
    };
    unsafe {
        std::ptr::write(pulSignatureLen, signature.len() as CK_ULONG);
    }

    // double check the buffer size

    if signature.len() > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
    }

    session.sign_clear();

    cryptoki_sys::CKR_OK
}

#[no_mangle]
pub extern "C" fn C_SignUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: *mut cryptoki_sys::CK_BYTE,
    ulPartLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignUpdate() called");

    lock_session!(hSession, session);

    if pPart.is_null() {
        session.sign_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let part = unsafe { std::slice::from_raw_parts(pPart, ulPartLen as usize) };

    match session.sign_update(part) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(err) => {
            session.sign_clear();
            err.into()
        }
    }
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSignature: *mut cryptoki_sys::CK_BYTE,
    pulSignatureLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignFinal() called");

    lock_session!(hSession, session);

    if pulSignatureLen.is_null() {
        session.sign_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let buffer_size = unsafe { *pulSignatureLen } as usize;

    let theoretical_size = match session.sign_theoretical_size() {
        Ok(size) => size,
        Err(err) => {
            session.sign_clear();
            return err.into();
        }
    };

    unsafe {
        std::ptr::write(pulSignatureLen, theoretical_size as CK_ULONG);
    }

    if pSignature.is_null() {
        // only the size was requested
        return cryptoki_sys::CKR_OK;
    }

    if buffer_size < theoretical_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let signature = match session.sign_final() {
        Ok(signature) => signature,
        Err(err) => {
            session.sign_clear();
            return err.into();
        }
    };

    unsafe {
        std::ptr::write(pulSignatureLen, signature.len() as CK_ULONG);
    }

    // double check the buffer size

    if signature.len() > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
    }
    session.sign_clear();

    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_SignRecoverInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignRecoverInit() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_SignRecover(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    pulSignatureLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignRecover() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_SignEncryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignEncryptUpdate() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[cfg(test)]
mod tests {
    use crate::{backend::slot::init_for_tests, data::SESSION_MANAGER};

    use super::*;

    #[test]
    fn test_sign_init_null_mechanism() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_SignInit(session, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_sign_init_invalid_mechanism() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut mechanism = cryptoki_sys::CK_MECHANISM {
            mechanism: 15000,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_SignInit(session, &mut mechanism, 0);
        assert_eq!(rv, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_sign_init_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut mechanism = cryptoki_sys::CK_MECHANISM {
            mechanism: 0,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_SignInit(0, &mut mechanism, 0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_sign_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut data = [0u8; 32];
        let mut signature = [0u8; 32];
        let mut signature_len = 32;

        let rv = C_Sign(
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_sign_null_data() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut signature = [0u8; 32];
        let mut signature_len = 32;

        let rv = C_Sign(
            session,
            std::ptr::null_mut(),
            0,
            signature.as_mut_ptr(),
            &mut signature_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_sign_null_signature_len() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data = [0u8; 32];
        let mut signature = [0u8; 32];

        let rv = C_Sign(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_sign_operation_not_initialized() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data = [0u8; 32];
        let mut signature = [0u8; 32];
        let mut signature_len = 32;

        let rv = C_Sign(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    // #[test]
    // fn test_sign_null_signature() {
    //     init_for_tests();
    //     let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

    //     let mut data = [0u8; 32];
    //     let mut signature_len = 32;

    //     let rv = C_Sign(
    //         session,
    //         data.as_mut_ptr(),
    //         data.len() as CK_ULONG,
    //         std::ptr::null_mut(),
    //         &mut signature_len,
    //     );
    //     assert_eq!(rv, cryptoki_sys::CKR_OK);
    // }

    #[test]
    fn test_sign_update_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut data = [0u8; 32];

        let rv = C_SignUpdate(0, data.as_mut_ptr(), data.len() as CK_ULONG);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_sign_update_null_data() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_SignUpdate(session, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_sign_update_operation_not_initialized() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data = [0u8; 32];

        let rv = C_SignUpdate(session, data.as_mut_ptr(), data.len() as CK_ULONG);
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    #[test]
    fn test_sign_final_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut signature = [0u8; 32];
        let mut signature_len = 32;

        let rv = C_SignFinal(0, signature.as_mut_ptr(), &mut signature_len);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_sign_final_null_signature_len() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut signature = [0u8; 32];

        let rv = C_SignFinal(session, signature.as_mut_ptr(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_sign_final_operation_not_initialized() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut signature = [0u8; 32];
        let mut signature_len = 32;

        let rv = C_SignFinal(session, signature.as_mut_ptr(), &mut signature_len);
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    #[test]
    fn test_sign_recover_init() {
        init_for_tests();
        let rv = C_SignRecoverInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_sign_recover() {
        init_for_tests();
        let rv = C_SignRecover(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_sign_encrypt_update() {
        init_for_tests();
        let rv = C_SignEncryptUpdate(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
