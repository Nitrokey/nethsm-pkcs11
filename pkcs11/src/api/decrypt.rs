use cryptoki_sys::CK_ULONG;
use log::error;

use crate::{
    api::api_function,
    backend::{
        mechanism::{CkRawMechanism, Mechanism},
        session::Session,
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
    session: cryptoki_sys::CK_SESSION_HANDLE,
    mechanism_ptr: cryptoki_sys::CK_MECHANISM_PTR,
    key: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    let raw_mech =
        unsafe { CkRawMechanism::from_raw_ptr(mechanism_ptr) }.ok_or(Pkcs11Error::ArgumentsBad)?;

    let mech = Mechanism::from_ckraw_mech(&raw_mech).map_err(|err| {
        error!("C_DecryptInit() failed to convert mechanism: {err}");
        Pkcs11Error::MechanismInvalid
    })?;

    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    session.decrypt_init(&mech, key).map_err(From::from)
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
    session: cryptoki_sys::CK_SESSION_HANDLE,
    encrypted_data_ptr: cryptoki_sys::CK_BYTE_PTR,
    encrypted_data_len: cryptoki_sys::CK_ULONG,
    data_ptr: cryptoki_sys::CK_BYTE_PTR,
    data_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;
    let result = decrypt_impl(
        &mut session,
        encrypted_data_ptr,
        encrypted_data_len,
        data_ptr,
        data_len_ptr,
    );

    // A call to C_Decrypt always terminates the active decryption operation unless it returns
    // CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK) to determine
    // the length of the buffer needed to hold the plaintext.
    let is_buffer_too_small = result == Err(Pkcs11Error::BufferTooSmall);
    let is_buffer_size_query = result.is_ok() && data_ptr.is_null();
    if !(is_buffer_too_small || is_buffer_size_query) {
        session.decrypt_clear();
    }

    result
}

fn decrypt_impl(
    session: &mut Session,
    encrypted_data_ptr: cryptoki_sys::CK_BYTE_PTR,
    encrypted_data_len: cryptoki_sys::CK_ULONG,
    data_ptr: cryptoki_sys::CK_BYTE_PTR,
    data_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    if data_len_ptr.is_null() || encrypted_data_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let buffer_size = unsafe { *data_len_ptr } as usize;

    let theoretical_size = session.decrypt_theoretical_size(encrypted_data_len as usize);

    unsafe {
        std::ptr::write(data_len_ptr, theoretical_size as CK_ULONG);
    }

    if data_ptr.is_null() {
        return Ok(());
    }

    if theoretical_size > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let data =
        unsafe { std::slice::from_raw_parts(encrypted_data_ptr, encrypted_data_len as usize) };

    let decrypted_data = session.decrypt(data)?;

    unsafe {
        std::ptr::write(data_len_ptr, decrypted_data.len() as CK_ULONG);
    }

    // we double-check the buffer size here, in case the theoretical size was wrong
    if decrypted_data.len() > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), data_ptr, decrypted_data.len());
    }

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
    session: cryptoki_sys::CK_SESSION_HANDLE,
    encrypted_part_ptr: cryptoki_sys::CK_BYTE_PTR,
    encrypted_part_len: cryptoki_sys::CK_ULONG,
    part_ptr: cryptoki_sys::CK_BYTE_PTR,
    part_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;
    let result = decrypt_update_impl(
        &mut session,
        encrypted_part_ptr,
        encrypted_part_len,
        part_ptr,
        part_len_ptr,
    );

    // A call to C_DecryptUpdate which results in an error other than CKR_BUFFER_TOO_SMALL
    // terminates the current decryption operation.
    if result.is_err() && result != Err(Pkcs11Error::BufferTooSmall) {
        session.decrypt_clear();
    }

    result
}

fn decrypt_update_impl(
    session: &mut Session,
    encrypted_part_ptr: cryptoki_sys::CK_BYTE_PTR,
    encrypted_part_len: cryptoki_sys::CK_ULONG,
    _part_ptr: cryptoki_sys::CK_BYTE_PTR,
    part_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    if part_len_ptr.is_null() || encrypted_part_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let data =
        unsafe { std::slice::from_raw_parts(encrypted_part_ptr, encrypted_part_len as usize) };

    // we only add to the buffer, so we don't need to check the size
    unsafe {
        std::ptr::write(part_len_ptr, 0 as CK_ULONG);
    }
    session.decrypt_update(data).map_err(From::from)
}

api_function!(
    C_DecryptFinal = decrypt_final;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn decrypt_final(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    last_part_ptr: cryptoki_sys::CK_BYTE_PTR,
    last_part_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;
    let result = decrypt_final_impl(&mut session, last_part_ptr, last_part_len_ptr);

    // A call to C_DecryptFinal always terminates the active decryption operation unless it returns
    // CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK) to determine
    // the length of the buffer needed to hold the plaintext.
    let is_buffer_too_small = result == Err(Pkcs11Error::BufferTooSmall);
    let is_buffer_size_query = result.is_ok() && last_part_ptr.is_null();
    if !(is_buffer_too_small || is_buffer_size_query) {
        session.decrypt_clear();
    }

    result
}

fn decrypt_final_impl(
    session: &mut Session,
    last_part_ptr: cryptoki_sys::CK_BYTE_PTR,
    last_part_len_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    if last_part_len_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let buffer_size = unsafe { *last_part_len_ptr } as usize;

    let theoretical_size = session.decrypt_theoretical_final_size()?;

    unsafe {
        std::ptr::write(last_part_len_ptr, theoretical_size as CK_ULONG);
    }

    if last_part_ptr.is_null() {
        return Ok(());
    }

    if theoretical_size > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let decrypted_data = session.decrypt_final()?;

    unsafe {
        std::ptr::write(last_part_len_ptr, decrypted_data.len() as CK_ULONG);
    }

    // we double-check the buffer size here, in case the theoretical size was wrong
    if decrypted_data.len() > buffer_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), last_part_ptr, decrypted_data.len());
    }

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
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _encrypted_part_ptr: cryptoki_sys::CK_BYTE_PTR,
    _encrypted_part_len: cryptoki_sys::CK_ULONG,
    _part_ptr: cryptoki_sys::CK_BYTE_PTR,
    _part_len_ptr: cryptoki_sys::CK_ULONG_PTR,
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
        let _guard = init_for_tests();
        let rv = C_DecryptInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_init_unknown_mech() {
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
        let mut encrypted_data = [0u8; 32];

        let session_handle = setup_session();

        let rv = C_Decrypt(
            session_handle,
            encrypted_data.as_mut_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_null_encrypted_data() {
        let _guard = init_for_tests();
        let mut data_len = 0;

        let session_handle = setup_session();

        let rv = C_Decrypt(
            session_handle,
            std::ptr::null_mut(),
            32,
            std::ptr::null_mut(),
            &mut data_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_null_data() {
        let _guard = init_for_tests();
        let mut data_len = 0;

        let session_handle = setup_session();

        let mut encrypted_data = [0u8; 32];

        let rv = C_Decrypt(
            session_handle,
            encrypted_data.as_mut_ptr(),
            32,
            std::ptr::null_mut(),
            &mut data_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_decrypt_update_invalid_session() {
        let _guard = init_for_tests();
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
        let _guard = init_for_tests();
        let session_handle = setup_session();

        let mut part_len = 0;
        let mut part = [0u8; 32];

        let rv = C_DecryptUpdate(
            session_handle,
            std::ptr::null_mut(),
            0,
            part.as_mut_ptr(),
            &mut part_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_update_null_part_len() {
        let _guard = init_for_tests();
        let session_handle = setup_session();

        let mut encrypted_part = [0u8; 32];
        let mut part = [0u8; 32];

        let rv = C_DecryptUpdate(
            session_handle,
            encrypted_part.as_mut_ptr(),
            0,
            part.as_mut_ptr(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_update_operation_not_initialized() {
        let _guard = init_for_tests();
        let session_handle = setup_session();

        let mut encrypted_part = [0u8; 32];
        let mut part = [0u8; 32];
        let mut part_len = 0;

        let rv = C_DecryptUpdate(
            session_handle,
            encrypted_part.as_mut_ptr(),
            0,
            part.as_mut_ptr(),
            &mut part_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    #[test]
    fn test_decrypt_final_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut last_part_len = 0;

        let rv = C_DecryptFinal(0, std::ptr::null_mut(), &mut last_part_len);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_decrypt_final_null_last_part_len() {
        let _guard = init_for_tests();
        let session_handle = setup_session();

        let mut last_part = [0u8; 32];

        let rv = C_DecryptFinal(session_handle, last_part.as_mut_ptr(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_final_operation_not_initialized() {
        let _guard = init_for_tests();
        let session_handle = setup_session();

        let mut last_part = [0u8; 32];
        let mut last_part_len = 0;

        let rv = C_DecryptFinal(session_handle, last_part.as_mut_ptr(), &mut last_part_len);
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
        let _guard = init_for_tests();
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
