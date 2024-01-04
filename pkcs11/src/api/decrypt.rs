use cryptoki_sys::{CKR_ARGUMENTS_BAD, CK_ULONG};
use log::{error, trace};

use crate::{
    backend::mechanism::{CkRawMechanism, Mechanism},
    lock_session,
};

pub extern "C" fn C_DecryptInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptInit() called");

    ensure_init!();

    let raw_mech = match unsafe { CkRawMechanism::from_raw_ptr(pMechanism) } {
        Some(mech) => mech,
        None => {
            return CKR_ARGUMENTS_BAD;
        }
    };

    let mech = match Mechanism::from_ckraw_mech(&raw_mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_DecryptInit() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    lock_session!(hSession, session);

    match session.decrypt_init(&mech, hKey) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(e) => e.into(),
    }
}

pub extern "C" fn C_Decrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedDataLen: cryptoki_sys::CK_ULONG,
    pData: cryptoki_sys::CK_BYTE_PTR,
    pulDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_Decrypt() called");

    ensure_init!();

    lock_session!(hSession, session);

    if pulDataLen.is_null() || pEncryptedData.is_null() {
        session.decrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let buffer_size = unsafe { *pulDataLen } as usize;

    let theoretical_size = session.decrypt_theoretical_size(ulEncryptedDataLen as usize);

    unsafe {
        std::ptr::write(pulDataLen, theoretical_size as CK_ULONG);
    }

    if pData.is_null() {
        return cryptoki_sys::CKR_OK;
    }

    if theoretical_size > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let data = unsafe { std::slice::from_raw_parts(pEncryptedData, ulEncryptedDataLen as usize) };

    let decrypted_data = match session.decrypt(data) {
        Ok(data) => data,
        Err(e) => {
            session.decrypt_clear();
            return e.into();
        }
    };

    unsafe {
        std::ptr::write(pulDataLen, decrypted_data.len() as CK_ULONG);
    }

    // we double-check the buffer size here, in case the theoretical size was wrong
    if decrypted_data.len() > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), pData, decrypted_data.len());
    }

    session.decrypt_clear();

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_DecryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptUpdate() called");

    lock_session!(hSession, session);

    if pulPartLen.is_null() || pEncryptedPart.is_null() {
        session.decrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { std::slice::from_raw_parts(pEncryptedPart, ulEncryptedPartLen as usize) };

    // we only add to the buffer, so we don't need to check the size
    unsafe {
        std::ptr::write(pulPartLen, 0 as CK_ULONG);
    }
    match session.decrypt_update(data) {
        Ok(()) => cryptoki_sys::CKR_OK,
        Err(e) => {
            session.decrypt_clear();
            e.into()
        }
    }
}

pub extern "C" fn C_DecryptFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptFinal() called");

    ensure_init!();

    lock_session!(hSession, session);

    if pulLastPartLen.is_null() {
        session.decrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let buffer_size = unsafe { *pulLastPartLen } as usize;

    let theoretical_size = match session.decrypt_theoretical_final_size() {
        Ok(size) => size,
        Err(e) => {
            session.decrypt_clear();
            return e.into();
        }
    };

    unsafe {
        std::ptr::write(pulLastPartLen, theoretical_size as CK_ULONG);
    }

    if pLastPart.is_null() {
        return cryptoki_sys::CKR_OK;
    }

    if theoretical_size > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let decrypted_data = match session.decrypt_final() {
        Ok(data) => data,
        Err(e) => {
            session.decrypt_clear();
            return e.into();
        }
    };

    unsafe {
        std::ptr::write(pulLastPartLen, decrypted_data.len() as CK_ULONG);
    }

    // we double-check the buffer size here, in case the theoretical size was wrong
    if decrypted_data.len() > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), pLastPart, decrypted_data.len());
    }

    session.decrypt_clear();

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_DecryptVerifyUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptVerifyUpdate() called");

    ensure_init!();

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::data::SESSION_MANAGER;

    fn setup_session() -> cryptoki_sys::CK_SESSION_HANDLE {
        SESSION_MANAGER.lock().unwrap().setup_dummy_session()
    }

    #[test]
    fn test_decrypt_init_null_mech() {
        let rv = C_DecryptInit(0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_init_unknown_mech() {
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
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut pulLastPartLen = 0;

        let rv = C_DecryptFinal(0, std::ptr::null_mut(), &mut pulLastPartLen);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_decrypt_final_null_last_part_len() {
        let session_handle = setup_session();

        let mut lastPart = [0u8; 32];

        let rv = C_DecryptFinal(session_handle, lastPart.as_mut_ptr(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_decrypt_final_operation_not_initialized() {
        let session_handle = setup_session();

        let mut lastPart = [0u8; 32];
        let mut pulLastPartLen = 0;

        let rv = C_DecryptFinal(session_handle, lastPart.as_mut_ptr(), &mut pulLastPartLen);
        assert_eq!(rv, cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED);
    }

    // #[test]
    // fn test_decrypt_final_null_last_part() {
    //     let session_handle = setup_session();

    //     let mut pulLastPartLen = 0;

    //     let rv = C_DecryptFinal(session_handle, std::ptr::null_mut(), &mut pulLastPartLen);
    //     assert_eq!(rv, cryptoki_sys::CKR_OK);
    // }

    // unsupported function
    #[test]
    fn test_decrypt_verify_update() {
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
