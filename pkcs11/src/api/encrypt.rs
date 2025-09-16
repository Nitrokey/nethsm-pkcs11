use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    api::api_function,
    backend::{
        encrypt::ENCRYPT_BLOCK_SIZE,
        mechanism::{CkRawMechanism, Mechanism},
        Pkcs11Error,
    },
    data,
};

api_function!(
    C_EncryptInit = encrypt_init;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
);

fn encrypt_init(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    let raw_mech =
        unsafe { CkRawMechanism::from_raw_ptr(pMechanism) }.ok_or(Pkcs11Error::ArgumentsBad)?;

    let mech = Mechanism::from_ckraw_mech(&raw_mech).map_err(|err| {
        error!("C_EncryptInit() failed to convert mechanism: {err}");
        Pkcs11Error::MechanismInvalid
    })?;

    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    session.encrypt_init(&mech, hKey).map_err(From::from)
}

api_function!(
    C_Encrypt = encrypt;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedDataLen: cryptoki_sys::CK_ULONG_PTR,
);

fn encrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    if pData.is_null() || pulEncryptedDataLen.is_null() {
        session.encrypt_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };

    // We only support AES-CBC for now the size of the encrypted data is the same as the size of the input

    if pEncryptedData.is_null() {
        unsafe {
            std::ptr::write(pulEncryptedDataLen, data.len() as CK_ULONG);
        }
        return Ok(());
    }

    let buffer_len = unsafe { *pulEncryptedDataLen } as usize;

    unsafe {
        std::ptr::write(pulEncryptedDataLen, data.len() as CK_ULONG);
    }

    if data.len() > buffer_len {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let encrypted_data = session
        .encrypt(data)
        .inspect_err(|_| session.encrypt_clear())?;

    unsafe {
        std::ptr::write(pulEncryptedDataLen, encrypted_data.len() as CK_ULONG);
    }

    // this shouldn't happen as it's checked above, but it's safe to keep it if encrypted_data.len() != data.len()

    if encrypted_data.len() > buffer_len {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            encrypted_data.as_ptr(),
            pEncryptedData,
            encrypted_data.len(),
        );
    }

    session.encrypt_clear();
    Ok(())
}

api_function!(
    C_EncryptUpdate = encrypt_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn encrypt_update(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    if pPart.is_null() || pulEncryptedPartLen.is_null() {
        session.encrypt_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    trace!("C_EncryptUpdate() called with {ulPartLen} bytes");

    let data = unsafe { std::slice::from_raw_parts(pPart, ulPartLen as usize) };

    let buffer_len = unsafe { std::ptr::read(pulEncryptedPartLen) as usize };

    // We only support AES-CBC for now the size of the encrypted data is the same as the size of the input

    let theoretical_size = ENCRYPT_BLOCK_SIZE * (data.len() / ENCRYPT_BLOCK_SIZE + 1);

    unsafe {
        std::ptr::write(pulEncryptedPartLen, theoretical_size as CK_ULONG);
    }
    if pEncryptedPart.is_null() {
        return Ok(());
    }

    if buffer_len < theoretical_size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let encrypted_data = session
        .encrypt_update(data)
        .inspect_err(|_| session.encrypt_clear())?;

    unsafe {
        std::ptr::write(pulEncryptedPartLen, encrypted_data.len() as CK_ULONG);
    }
    // shouldn't happen
    if encrypted_data.len() > buffer_len {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            encrypted_data.as_ptr(),
            pEncryptedPart,
            encrypted_data.len(),
        );
    }

    Ok(())
}

api_function!(
    C_EncryptFinal = encrypt_final;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn encrypt_final(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(hSession)?;
    let mut session = data::lock_session(&session)?;

    if pulLastEncryptedPartLen.is_null() {
        session.encrypt_clear();
        return Err(Pkcs11Error::ArgumentsBad);
    }

    // enverything should be encrypted at this point, so we just need to return the last block

    let buffer_len = unsafe { std::ptr::read(pulLastEncryptedPartLen) as usize };
    unsafe {
        std::ptr::write(pulLastEncryptedPartLen, ENCRYPT_BLOCK_SIZE as CK_ULONG);
    }

    if pLastEncryptedPart.is_null() {
        return Ok(());
    }

    let size = session
        .encrypt_get_theoretical_final_size()
        .inspect_err(|_| session.encrypt_clear())?;

    if buffer_len < size {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    let encrypted_data = session
        .encrypt_final()
        .inspect_err(|_| session.encrypt_clear())?;

    unsafe {
        std::ptr::write(pulLastEncryptedPartLen, encrypted_data.len() as CK_ULONG);
    }

    // shouldn't happen

    if encrypted_data.len() > buffer_len {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            encrypted_data.as_ptr(),
            pLastEncryptedPart,
            encrypted_data.len(),
        );
    }

    session.encrypt_clear();

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{backend::slot::init_for_tests, data::SESSION_MANAGER};

    use super::*;

    #[test]
    fn test_encrypt_init_null_mechanism() {
        init_for_tests();
        let rv = C_EncryptInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_encrypt_init_invalid_mechanism() {
        init_for_tests();
        let mut mechanism = cryptoki_sys::CK_MECHANISM {
            mechanism: 15000,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_EncryptInit(0, &mut mechanism, 0);
        assert_eq!(rv, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_encrypt_init_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(1);

        let mut mechanism = cryptoki_sys::CK_MECHANISM {
            mechanism: 0,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_EncryptInit(1, &mut mechanism, 0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_encrypt_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(1);

        let mut data: Vec<u8> = Vec::new();
        let mut encrypted_data: Vec<u8> = Vec::new();
        let mut encrypted_data_len: CK_ULONG = 0;

        let rv = C_Encrypt(
            1,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            encrypted_data.as_mut_ptr(),
            &mut encrypted_data_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_encrypt_update_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(1);

        let mut data: Vec<u8> = Vec::new();
        let mut encrypted_data: Vec<u8> = Vec::new();
        let mut encrypted_data_len: CK_ULONG = 0;

        let rv = C_EncryptUpdate(
            1,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            encrypted_data.as_mut_ptr(),
            &mut encrypted_data_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_encrypt_final_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(1);

        let mut encrypted_data: Vec<u8> = Vec::new();
        let mut encrypted_data_len: CK_ULONG = 0;

        let rv = C_EncryptFinal(1, encrypted_data.as_mut_ptr(), &mut encrypted_data_len);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_encrypt_null_data() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pEncryptedDataLen: CK_ULONG = 0;
        let mut pEncryptedData: Vec<u8> = Vec::new();

        let rv = C_Encrypt(
            session_handle,
            std::ptr::null_mut(),
            0 as CK_ULONG,
            pEncryptedData.as_mut_ptr(),
            &mut pEncryptedDataLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_encrypt_null_encrypted_data_len() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data: Vec<u8> = Vec::new();
        let mut pEncryptedData: Vec<u8> = Vec::new();

        let rv = C_Encrypt(
            session_handle,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            pEncryptedData.as_mut_ptr(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_encrypt_null_encrypted_data() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data: Vec<u8> = Vec::new();
        let mut pEncryptedDataLen: CK_ULONG = 0;

        let rv = C_Encrypt(
            session_handle,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut pEncryptedDataLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_encrypt_operation_not_initialized() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data: Vec<u8> = Vec::new();
        let mut pEncryptedData: Vec<u8> = Vec::new();
        let mut pEncryptedDataLen: CK_ULONG = 0;

        let rv = C_Encrypt(
            session_handle,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            pEncryptedData.as_mut_ptr(),
            &mut pEncryptedDataLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    #[test]
    fn test_encrypt_update_null_part() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pEncryptedPartLen: CK_ULONG = 0;
        let mut pEncryptedPart: Vec<u8> = Vec::new();

        let rv = C_EncryptUpdate(
            session_handle,
            std::ptr::null_mut(),
            0 as CK_ULONG,
            pEncryptedPart.as_mut_ptr(),
            &mut pEncryptedPartLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_encrypt_update_null_encrypted_part_len() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data: Vec<u8> = Vec::new();
        let mut pEncryptedPart: Vec<u8> = Vec::new();

        let rv = C_EncryptUpdate(
            session_handle,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            pEncryptedPart.as_mut_ptr(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_encrypt_update_null_encrypted_part() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data: Vec<u8> = Vec::new();
        let mut pEncryptedPartLen: CK_ULONG = 0;

        let rv = C_EncryptUpdate(
            session_handle,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut pEncryptedPartLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_encrypt_update_buffer_too_small() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data: Vec<u8> = vec![0; 100];
        let mut pEncryptedPart: Vec<u8> = Vec::new();
        let mut pEncryptedPartLen: CK_ULONG = 0;

        let rv = C_EncryptUpdate(
            session_handle,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            pEncryptedPart.as_mut_ptr(),
            &mut pEncryptedPartLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_BUFFER_TOO_SMALL);
    }

    #[test]
    fn test_encrypt_update_operation_not_initialized() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut data: Vec<u8> = vec![0; 100];
        let mut pEncryptedPart: Vec<u8> = Vec::new();
        let mut pEncryptedPartLen: CK_ULONG = 512;

        let rv = C_EncryptUpdate(
            session_handle,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            pEncryptedPart.as_mut_ptr(),
            &mut pEncryptedPartLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    #[test]
    fn test_encrypt_final_null_encrypted_part() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pEncryptedPartLen: CK_ULONG = 0;

        let rv = C_EncryptFinal(session_handle, std::ptr::null_mut(), &mut pEncryptedPartLen);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_encrypt_final_null_encrypted_part_len() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pEncryptedPart: Vec<u8> = Vec::new();

        let rv = C_EncryptFinal(
            session_handle,
            pEncryptedPart.as_mut_ptr(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    // #[test]
    // fn test_encrypt_final_buffer_too_small() {
    //     init_for_tests();
    //     let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

    //     let mut pEncryptedPart: Vec<u8> = Vec::new();
    //     let mut pEncryptedPartLen: CK_ULONG = 0;

    //     let rv = C_EncryptFinal(
    //         session_handle,
    //         pEncryptedPart.as_mut_ptr(),
    //         &mut pEncryptedPartLen,
    //     );
    //     assert_eq!(rv, cryptoki_sys::CKR_BUFFER_TOO_SMALL);
    // }

    #[test]
    fn test_encrypt_final_operation_not_initialized() {
        init_for_tests();
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pEncryptedPart: Vec<u8> = Vec::new();
        let mut pEncryptedPartLen: CK_ULONG = 512;

        let rv = C_EncryptFinal(
            session_handle,
            pEncryptedPart.as_mut_ptr(),
            &mut pEncryptedPartLen,
        );
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }
}
