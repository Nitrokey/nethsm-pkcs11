use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    backend::mechanism::{CkRawMechanism, Mechanism},
    data::SESSION_MANAGER,
    lock_mutex,
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
            error!("C_DecryptInit() failed to convert mechanism: {:?}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_DecryptInit() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    session.decrypt_init(&mech, hKey)
}

pub extern "C" fn C_Decrypt(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedData: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedDataLen: cryptoki_sys::CK_ULONG,
    pData: cryptoki_sys::CK_BYTE_PTR,
    pulDataLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_Decrypt() called");

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_Decrypt() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    if pData.is_null() || pulDataLen.is_null() || pEncryptedData.is_null() {
        session.decrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { std::slice::from_raw_parts(pEncryptedData, ulEncryptedDataLen as usize) };

    let decrypted_data = match session.decrypt(data) {
        Ok(data) => data,
        Err(e) => return e,
    };

    if decrypted_data.len() > unsafe { *pulDataLen } as usize {
        unsafe {
            std::ptr::write(pulDataLen, decrypted_data.len() as CK_ULONG);
        }

        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), pData, decrypted_data.len());
        std::ptr::write(pulDataLen, decrypted_data.len() as CK_ULONG);
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
    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_DecryptFinal() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    if pPart.is_null() || pulPartLen.is_null() || pEncryptedPart.is_null() {
        session.decrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { std::slice::from_raw_parts(pEncryptedPart, ulEncryptedPartLen as usize) };

    let decrypted_data = match session.decrypt(data) {
        Ok(data) => data,
        Err(e) => return e,
    };

    if decrypted_data.len() > unsafe { *pulPartLen } as usize {
        unsafe {
            std::ptr::write(pulPartLen, decrypted_data.len() as CK_ULONG);
        }

        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), pPart, decrypted_data.len());
        std::ptr::write(pulPartLen, decrypted_data.len() as CK_ULONG);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_DecryptFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptFinal() called");

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_DecryptFinal() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    if pLastPart.is_null() || pulLastPartLen.is_null() {
        session.decrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    // write 0 to the length

    unsafe {
        std::ptr::write(pulLastPartLen, 0);
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
