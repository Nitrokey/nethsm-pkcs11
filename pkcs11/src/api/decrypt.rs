use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    backend::mechanism::{CkRawMechanism, Mechanism},
    lock_mutex, lock_session,
};

pub extern "C" fn C_DecryptInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptInit() called");

    if pMechanism.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    trace!("C_DecryptInit() mech: {:?}", unsafe { *pMechanism });

    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };

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
        Err(e) => return e.into(),
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
        Err(e) => e.into(),
    }
}

pub extern "C" fn C_DecryptFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptFinal() called");

    lock_session!(hSession, session);

    if pulLastPartLen.is_null() {
        session.decrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let buffer_size = unsafe { *pulLastPartLen } as usize;

    let theoretical_size = match session.decrypt_theoretical_final_size() {
        Ok(size) => size,
        Err(e) => return e.into(),
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
        Err(e) => return e.into(),
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
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
