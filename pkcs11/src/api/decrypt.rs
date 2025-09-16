use cryptoki_sys::CK_ULONG;
use log::error;

use crate::{
    api::api_function,
    backend::{
        mechanism::{CkRawMechanism, Mechanism},
        Pkcs11Error,
    },
    data,
};

api_function!(
    C_DecryptInit = decrypt_init;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
);

fn decrypt_init(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    let raw_mech =
        unsafe { CkRawMechanism::from_raw_ptr(pMechanism) }.ok_or(Pkcs11Error::ArgumentsBad)?;

    let mech = Mechanism::from_ckraw_mech(&raw_mech).map_err(|err| {
        error!("C_DecryptInit() failed to convert mechanism: {err}");
        Pkcs11Error::MechanismInvalid
    })?;

    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    session.decrypt_init(&mech, hKey).map_err(From::from)
}

api_function!(
    C_Decrypt = decrypt;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedDataLen: cryptoki_sys::CK_ULONG,
    pData: cryptoki_sys::CK_BYTE_PTR,
    pulDataLen: cryptoki_sys::CK_ULONG_PTR,
);

fn decrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedDataLen: cryptoki_sys::CK_ULONG,
    pData: cryptoki_sys::CK_BYTE_PTR,
    pulDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    if pulDataLen.is_null() || pEncryptedData.is_null() {
        session.decrypt_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let buffer_size = unsafe { *pulDataLen } as usize;

    let theoretical_size = session.decrypt_theoretical_size(ulEncryptedDataLen as usize);

    unsafe {
        std::ptr::write(pulDataLen, theoretical_size as CK_ULONG);
    }

    if pData.is_null() {
        return Ok(());
    }

    if theoretical_size > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let data = unsafe { std::slice::from_raw_parts(pEncryptedData, ulEncryptedDataLen as usize) };

    let decrypted_data = session
        .decrypt(data)
        .inspect_err(|_| session.decrypt_clear())?;

    unsafe {
        std::ptr::write(pulDataLen, decrypted_data.len() as CK_ULONG);
    }

    // we double-check the buffer size here, in case the theoretical size was wrong
    if decrypted_data.len() > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), pData, decrypted_data.len());
    }

    session.decrypt_clear();

    Ok(())
}

api_function!(
    C_DecryptUpdate = decrypt_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn decrypt_update(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    if pulPartLen.is_null() || pEncryptedPart.is_null() {
        session.decrypt_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let data = unsafe { std::slice::from_raw_parts(pEncryptedPart, ulEncryptedPartLen as usize) };

    // we only add to the buffer, so we don't need to check the size
    unsafe {
        std::ptr::write(pulPartLen, 0 as CK_ULONG);
    }
    session.decrypt_update(data).map_err(|err| {
        session.decrypt_clear();
        err.into()
    })
}

api_function!(
    C_DecryptFinal = decrypt_final;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn decrypt_final(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    if pulLastPartLen.is_null() {
        session.decrypt_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let buffer_size = unsafe { *pulLastPartLen } as usize;

    let theoretical_size = session
        .decrypt_theoretical_final_size()
        .inspect_err(|_| session.decrypt_clear())?;

    unsafe {
        std::ptr::write(pulLastPartLen, theoretical_size as CK_ULONG);
    }

    if pLastPart.is_null() {
        return Ok(());
    }

    if theoretical_size > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let decrypted_data = session
        .decrypt_final()
        .inspect_err(|_| session.decrypt_clear())?;

    unsafe {
        std::ptr::write(pulLastPartLen, decrypted_data.len() as CK_ULONG);
    }

    // we double-check the buffer size here, in case the theoretical size was wrong
    if decrypted_data.len() > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), pLastPart, decrypted_data.len());
    }

    session.decrypt_clear();

    Ok(())
}

api_function!(
    C_DecryptVerifyUpdate = decrypt_verify_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn decrypt_verify_update(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{backend::slot::init_for_tests, data::SESSION_MANAGER};

    fn setup_session() -> cryptoki_sys::CK_SESSION_HANDLE {
        SESSION_MANAGER.lock().unwrap().setup_dummy_session()
    }

    #[test]
    fn test_decrypt_init_null_mech() {
        init_for_tests();
        let rv = C_DecryptInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_init_unknown_mech() {
        init_for_tests();
        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: 15000, // doesn't exist
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_DecryptInit(0, &mut mech, 0);
        assert_eq!(rv, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_decrypt_init_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: 0,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_DecryptInit(0, &mut mech, 0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_decrypt_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_Decrypt(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_decrypt_null_data_len() {
        init_for_tests();
        let mut pEncryptedData = [0u8; 32];

        let session_handle = setup_session();

        let rv = C_Decrypt(
            session_handle,
            pEncryptedData.as_mut_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_null_encrypted_data() {
        init_for_tests();
        let mut pulDataLen = 0;

        let session_handle = setup_session();

        let rv = C_Decrypt(
            session_handle,
            std::ptr::null_mut(),
            32,
            std::ptr::null_mut(),
            &mut pulDataLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_null_data() {
        init_for_tests();
        let mut pulDataLen = 0;

        let session_handle = setup_session();

        let mut pEncryptedData = [0u8; 32];

        let rv = C_Decrypt(
            session_handle,
            pEncryptedData.as_mut_ptr(),
            32,
            std::ptr::null_mut(),
            &mut pulDataLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_decrypt_update_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_DecryptUpdate(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_decrypt_update_null_encrypted_part() {
        init_for_tests();
        let session_handle = setup_session();

        let mut pulPartLen = 0;
        let mut pPart = [0u8; 32];

        let rv = C_DecryptUpdate(
            session_handle,
            std::ptr::null_mut(),
            0,
            pPart.as_mut_ptr(),
            &mut pulPartLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_update_null_part_len() {
        init_for_tests();
        let session_handle = setup_session();

        let mut pEncryptedPart = [0u8; 32];
        let mut pPart = [0u8; 32];

        let rv = C_DecryptUpdate(
            session_handle,
            pEncryptedPart.as_mut_ptr(),
            0,
            pPart.as_mut_ptr(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_update_operation_not_initialized() {
        init_for_tests();
        let session_handle = setup_session();

        let mut pEncryptedPart = [0u8; 32];
        let mut pPart = [0u8; 32];
        let mut pulPartLen = 0;

        let rv = C_DecryptUpdate(
            session_handle,
            pEncryptedPart.as_mut_ptr(),
            0,
            pPart.as_mut_ptr(),
            &mut pulPartLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    #[test]
    fn test_decrypt_final_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut pulLastPartLen = 0;

        let rv = C_DecryptFinal(0, std::ptr::null_mut(), &mut pulLastPartLen);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_decrypt_final_null_last_part_len() {
        init_for_tests();
        let session_handle = setup_session();

        let mut lastPart = [0u8; 32];

        let rv = C_DecryptFinal(session_handle, lastPart.as_mut_ptr(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_final_operation_not_initialized() {
        init_for_tests();
        let session_handle = setup_session();

        let mut lastPart = [0u8; 32];
        let mut pulLastPartLen = 0;

        let rv = C_DecryptFinal(session_handle, lastPart.as_mut_ptr(), &mut pulLastPartLen);
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    // #[test]
    // fn test_decrypt_final_null_last_part() {
    //     init_for_tests();
    //     let session_handle = setup_session();

    //     let mut pulLastPartLen = 0;

    //     let rv = C_DecryptFinal(session_handle, std::ptr::null_mut(), &mut pulLastPartLen);
    //     assert_eq!(rv, cryptoki_sys::CKR_OK);
    // }

    // unsupported function
    #[test]
    fn test_decrypt_verify_update() {
        init_for_tests();
        let rv = C_DecryptVerifyUpdate(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
