use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    backend::{
        encrypt::ENCRYPT_BLOCK_SIZE,
        mechanism::{CkRawMechanism, Mechanism},
    },
    lock_session,
};

pub extern "C" fn C_EncryptInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_EncryptInit() called");

    if pMechanism.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    trace!("C_EncryptInit() mech: {:?}", unsafe { *pMechanism });

    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };

    let mech = match Mechanism::from_ckraw_mech(&raw_mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_EncryptInit() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    lock_session!(hSession, session);

    match session.encrypt_init(&mech, hKey) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(e) => e.into(),
    }
}

pub extern "C" fn C_Encrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_Encrypt() called");

    lock_session!(hSession, session);

    if pData.is_null() || pulEncryptedDataLen.is_null() {
        session.encrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };

    // We only support AES-CBC for now the size of the encrypted data is the same as the size of the input

    if pEncryptedData.is_null() {
        unsafe {
            std::ptr::write(pulEncryptedDataLen, data.len() as CK_ULONG);
        }
        return cryptoki_sys::CKR_OK;
    }

    let buffer_len = unsafe { *pulEncryptedDataLen } as usize;

    unsafe {
        std::ptr::write(pulEncryptedDataLen, data.len() as CK_ULONG);
    }

    if data.len() > buffer_len {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let encrypted_data = match session.encrypt(data) {
        Ok(data) => data,
        Err(e) => {
            session.encrypt_clear();
            return e.into();
        }
    };

    unsafe {
        std::ptr::write(pulEncryptedDataLen, encrypted_data.len() as CK_ULONG);
    }

    // this shouldn't happen as it's checked above, but it's safe to keep it if encrypted_data.len() != data.len()

    if encrypted_data.len() > buffer_len {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            encrypted_data.as_ptr(),
            pEncryptedData,
            encrypted_data.len(),
        );
    }

    session.encrypt_clear();

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_EncryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_EncryptUpdate() called");

    lock_session!(hSession, session);

    if pPart.is_null() || pulEncryptedPartLen.is_null() {
        session.encrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    trace!("C_EncryptUpdate() called with {} bytes", ulPartLen);

    let data = unsafe { std::slice::from_raw_parts(pPart, ulPartLen as usize) };

    let buffer_len = unsafe { std::ptr::read(pulEncryptedPartLen) as usize };

    // We only support AES-CBC for now the size of the encrypted data is the same as the size of the input

    let theoretical_size = ENCRYPT_BLOCK_SIZE * (data.len() / ENCRYPT_BLOCK_SIZE + 1);

    unsafe {
        std::ptr::write(pulEncryptedPartLen, theoretical_size as CK_ULONG);
    }
    if pEncryptedPart.is_null() {
        return cryptoki_sys::CKR_OK;
    }

    if buffer_len < theoretical_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let encrypted_data = match session.encrypt_update(data) {
        Ok(data) => data,
        Err(e) => {
            session.encrypt_clear();
            return e.into();
        }
    };

    unsafe {
        std::ptr::write(pulEncryptedPartLen, encrypted_data.len() as CK_ULONG);
    }
    // shouldn't happen
    if encrypted_data.len() > buffer_len {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            encrypted_data.as_ptr(),
            pEncryptedPart,
            encrypted_data.len(),
        );
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_EncryptFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_EncryptFinal() called");

    lock_session!(hSession, session);

    if pulLastEncryptedPartLen.is_null() {
        session.encrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    // enverything should be encrypted at this point, so we just need to return the last block

    let buffer_len = unsafe { std::ptr::read(pulLastEncryptedPartLen) as usize };
    unsafe {
        std::ptr::write(pulLastEncryptedPartLen, ENCRYPT_BLOCK_SIZE as CK_ULONG);
    }

    if pLastEncryptedPart.is_null() {
        return cryptoki_sys::CKR_OK;
    }

    let size = match session.encrypt_get_theoretical_final_size() {
        Ok(size) => size,
        Err(e) => {
            session.encrypt_clear();
            return e.into();
        }
    };

    if buffer_len < size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let encrypted_data = match session.encrypt_final() {
        Ok(data) => data,
        Err(e) => {
            session.encrypt_clear();
            return e.into();
        }
    };

    unsafe {
        std::ptr::write(pulLastEncryptedPartLen, encrypted_data.len() as CK_ULONG);
    }

    // shouldn't happen

    if encrypted_data.len() > buffer_len {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            encrypted_data.as_ptr(),
            pLastEncryptedPart,
            encrypted_data.len(),
        );
    }

    session.encrypt_clear();

    cryptoki_sys::CKR_OK
}

#[cfg(test)]
mod tests {
    use crate::data::SESSION_MANAGER;

    use super::*;

    #[test]
    fn test_encrypt_init_null_mechanism() {
        let rv = C_EncryptInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_encrypt_init_invalid_mechanism() {
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
        SESSION_MANAGER.lock().unwrap().delete_session(1);

        let mut encrypted_data: Vec<u8> = Vec::new();
        let mut encrypted_data_len: CK_ULONG = 0;

        let rv = C_EncryptFinal(1, encrypted_data.as_mut_ptr(), &mut encrypted_data_len);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_encrypt_null_data() {
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
        let session_handle = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pEncryptedPartLen: CK_ULONG = 0;

        let rv = C_EncryptFinal(session_handle, std::ptr::null_mut(), &mut pEncryptedPartLen);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_encrypt_final_null_encrypted_part_len() {
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
