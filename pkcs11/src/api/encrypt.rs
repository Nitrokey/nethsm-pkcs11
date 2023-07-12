use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    backend::{
        encrypt::ENCRYPT_BLOCK_SIZE,
        mechanism::{CkRawMechanism, Mechanism},
    },
    data::SESSION_MANAGER,
    lock_mutex,
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
            error!("C_EncryptInit() failed to convert mechanism: {:?}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_EncryptInit() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    session.encrypt_init(&mech, hKey)
}

pub extern "C" fn C_Encrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_Encrypt() called");

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_Encrypt() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

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
            return e;
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

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_EncryptUpdate() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

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
            return e;
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

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_EncryptFinal() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    if pLastEncryptedPart.is_null() || pulLastEncryptedPartLen.is_null() {
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

    if buffer_len < ENCRYPT_BLOCK_SIZE {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let encrypted_data = match session.encrypt_final() {
        Ok(data) => data,
        Err(e) => {
            session.encrypt_clear();
            return e;
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
