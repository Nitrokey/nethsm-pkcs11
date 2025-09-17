use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    api::api_function,
    backend::{
        mechanism::{CkRawMechanism, Mechanism},
        Pkcs11Error,
    },
    data,
};

api_function!(
    C_SignInit = sign_init;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: *mut cryptoki_sys::CK_MECHANISM,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
);

fn sign_init(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    mechanism_ptr: *mut cryptoki_sys::CK_MECHANISM,
    key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    trace!("C_SignInit() called with hKey {key} and session {session}");

    let raw_mech =
        unsafe { CkRawMechanism::from_raw_ptr(mechanism_ptr) }.ok_or(Pkcs11Error::ArgumentsBad)?;

    let mech = Mechanism::from_ckraw_mech(&raw_mech).map_err(|e| {
        error!("C_SignInit() failed to convert mechanism: {e}");
        Pkcs11Error::MechanismInvalid
    })?;

    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    session.sign_init(&mech, key).map_err(From::from)
}

api_function!(
    C_Sign = sign;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: *mut cryptoki_sys::CK_BYTE,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: *mut cryptoki_sys::CK_BYTE,
    pulSignatureLen: *mut cryptoki_sys::CK_ULONG,
);

fn sign(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    data_ptr: *mut cryptoki_sys::CK_BYTE,
    data_len: cryptoki_sys::CK_ULONG,
    signature_ptr: *mut cryptoki_sys::CK_BYTE,
    signature_len_ptr: *mut cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    trace!("pData null {}", data_ptr.is_null());
    trace!("pulSignatureLen null {}", signature_len_ptr.is_null());

    if data_ptr.is_null() || signature_len_ptr.is_null() {
        trace!("aborting sign due to null");
        session.sign_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len as usize) };

    let buffer_size = unsafe { *signature_len_ptr } as usize;

    let theoretical_size = session
        .sign_theoretical_size()
        .inspect_err(|_| session.sign_clear())?;

    unsafe {
        std::ptr::write(signature_len_ptr, theoretical_size as CK_ULONG);
    }

    if signature_ptr.is_null() {
        trace!("sending only the size");
        // only the size was requested
        return Ok(());
    }

    if buffer_size < theoretical_size {
        trace!("buffer too small");
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let signature = session.sign(data).inspect_err(|_| session.sign_clear())?;
    unsafe {
        std::ptr::write(signature_len_ptr, signature.len() as CK_ULONG);
    }

    // double check the buffer size

    if signature.len() > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), signature_ptr, signature.len());
    }

    session.sign_clear();

    Ok(())
}

api_function!(
    C_SignUpdate = sign_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: *mut cryptoki_sys::CK_BYTE,
    ulPartLen: cryptoki_sys::CK_ULONG,
);

fn sign_update(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    part_ptr: *mut cryptoki_sys::CK_BYTE,
    part_len: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    if part_ptr.is_null() {
        session.sign_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let part = unsafe { std::slice::from_raw_parts(part_ptr, part_len as usize) };

    session.sign_update(part).map_err(|err| {
        session.sign_clear();
        err.into()
    })
}

api_function!(
    C_SignFinal = sign_final;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSignature: *mut cryptoki_sys::CK_BYTE,
    pulSignatureLen: *mut cryptoki_sys::CK_ULONG,
);

fn sign_final(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    signature_ptr: *mut cryptoki_sys::CK_BYTE,
    signature_len_ptr: *mut cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    if signature_len_ptr.is_null() {
        session.sign_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let buffer_size = unsafe { *signature_len_ptr } as usize;

    let theoretical_size = session
        .sign_theoretical_size()
        .inspect_err(|_| session.sign_clear())?;

    unsafe {
        std::ptr::write(signature_len_ptr, theoretical_size as CK_ULONG);
    }

    if signature_ptr.is_null() {
        // only the size was requested
        return Ok(());
    }

    if buffer_size < theoretical_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let signature = session.sign_final().inspect_err(|_| session.sign_clear())?;

    unsafe {
        std::ptr::write(signature_len_ptr, signature.len() as CK_ULONG);
    }

    // double check the buffer size

    if signature.len() > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), signature_ptr, signature.len());
    }
    session.sign_clear();

    Ok(())
}

api_function!(
    C_SignRecoverInit = sign_recover_init;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
);

fn sign_recover_init(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _mechanism_ptr: cryptoki_sys::CK_MECHANISM_PTR,
    _key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_SignRecover = sign_recover;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    pulSignatureLen: cryptoki_sys::CK_ULONG_PTR,
);

fn sign_recover(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _data_ptr: cryptoki_sys::CK_BYTE_PTR,
    _data_len: cryptoki_sys::CK_ULONG,
    _signature_ptr: cryptoki_sys::CK_BYTE_PTR,
    _signature_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_SignEncryptUpdate = sign_encrypt_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn sign_encrypt_update(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _part_ptr: cryptoki_sys::CK_BYTE_PTR,
    _part_len: cryptoki_sys::CK_ULONG,
    _encrypted_part_ptr: cryptoki_sys::CK_BYTE_PTR,
    _encrypted_part_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
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
