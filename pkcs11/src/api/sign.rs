use cryptoki_sys::{CKR_OK, CK_ULONG};
use log::{error, trace};

use crate::{
    backend::mechanism::{CkRawMechanism, Mechanism},
    lock_mutex, lock_session,
};

pub extern "C" fn C_SignInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: *mut cryptoki_sys::CK_MECHANISM,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!(
        "C_SignInit() called with hKey {} and session {}",
        hKey,
        hSession
    );
    if pMechanism.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }
    trace!("C_SignInit() mech: {:?}", unsafe { *pMechanism });

    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };

    let mech = match Mechanism::from_ckraw_mech(&raw_mech) {
        Ok(mech) => mech,
        Err(e) => {
            error!("C_SignInit() failed to convert mechanism: {}", e);
            return cryptoki_sys::CKR_MECHANISM_INVALID;
        }
    };

    lock_session!(hSession, session);

    match session.sign_init(&mech, hKey) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(e) => e.into(),
    }
}

pub extern "C" fn C_Sign(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: *mut cryptoki_sys::CK_BYTE,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: *mut cryptoki_sys::CK_BYTE,
    pulSignatureLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Sign() called");

    lock_session!(hSession, session);

    trace!("pData null {}", pData.is_null());
    trace!("pulSignatureLen null {}", pulSignatureLen.is_null());

    if pData.is_null() || pulSignatureLen.is_null() {
        trace!("aborting sign due to null");
        session.sign_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };

    let buffer_size = unsafe { *pulSignatureLen } as usize;

    let theoretical_size = session.sign_theoretical_size();
    unsafe {
        std::ptr::write(pulSignatureLen, theoretical_size as CK_ULONG);
    }

    if pSignature.is_null() {
        trace!("sending only the size");
        // only the size was requested
        return cryptoki_sys::CKR_OK;
    }

    if buffer_size < theoretical_size {
        trace!("buffer too small");
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let signature = match session.sign(data) {
        Ok(signature) => signature,
        Err(err) => {
            session.sign_clear();
            return err.into();
        }
    };
    unsafe {
        std::ptr::write(pulSignatureLen, signature.len() as CK_ULONG);
    }

    // double check the buffer size

    if signature.len() > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
    }

    session.sign_clear();

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_SignUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: *mut cryptoki_sys::CK_BYTE,
    ulPartLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignUpdate() called");

    lock_session!(hSession, session);

    if pPart.is_null() {
        session.sign_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let part = unsafe { std::slice::from_raw_parts(pPart, ulPartLen as usize) };

    match session.sign_update(part) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(err) => {
            session.sign_clear();
            err.into()
        }
    }
}

pub extern "C" fn C_SignFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSignature: *mut cryptoki_sys::CK_BYTE,
    pulSignatureLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignFinal() called");

    lock_session!(hSession, session);

    if pulSignatureLen.is_null() {
        session.sign_clear();
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let buffer_size = unsafe { *pulSignatureLen } as usize;

    let theoretical_size = session.sign_theoretical_size();

    unsafe {
        std::ptr::write(pulSignatureLen, theoretical_size as CK_ULONG);
    }

    if pSignature.is_null() {
        // only the size was requested
        return cryptoki_sys::CKR_OK;
    }

    if buffer_size < theoretical_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    let signature = match session.sign_final() {
        Ok(signature) => signature,
        Err(err) => {
            session.sign_clear();
            return err.into();
        }
    };

    unsafe {
        std::ptr::write(pulSignatureLen, signature.len() as CK_ULONG);
    }

    // double check the buffer size

    if signature.len() > buffer_size {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
    }
    session.sign_clear();

    CKR_OK
}

pub extern "C" fn C_SignRecoverInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignRecoverInit() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SignRecover(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: cryptoki_sys::CK_BYTE_PTR,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pSignature: cryptoki_sys::CK_BYTE_PTR,
    pulSignatureLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignRecover() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SignEncryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_SignEncryptUpdate() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
