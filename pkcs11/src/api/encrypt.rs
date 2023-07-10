use log::{error, trace};

use crate::{
    backend::mechanism::{CkRawMechanism, Mechanism},
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

    if pData.is_null() || pEncryptedData.is_null() || pulEncryptedDataLen.is_null() {
        session.encrypt_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };

    let encrypted_data = match session.encrypt(data) {
        Ok(data) => data,
        Err(e) => {
            session.encrypt_clear();
            return e;
        }
    };

    if encrypted_data.len() > unsafe { *pulEncryptedDataLen } as usize {
        unsafe {
            std::ptr::write(pulEncryptedDataLen, encrypted_data.len() as u64);
        }
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            encrypted_data.as_ptr(),
            pEncryptedData,
            encrypted_data.len(),
        );
        std::ptr::write(pulEncryptedDataLen, encrypted_data.len() as u64);
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
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_EncryptFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pLastEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulLastEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_EncryptFinal() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
