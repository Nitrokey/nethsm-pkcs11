use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{backend::db::attr::CkRawAttrTemplate, data::SESSION_MANAGER, lock_mutex};

pub extern "C" fn C_FindObjectsInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_FindObjectsInit() called");

    if ulCount > 0 && pTemplate.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_FindObjectsInit() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    let template = if !pTemplate.is_null() {
        Some(unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) })
    } else {
        None
    };
    trace!("C_FindObjectsInit() template: {:?}", template);
    session.enum_init(template)
}

pub extern "C" fn C_FindObjects(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    phObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: cryptoki_sys::CK_ULONG,
    pulObjectCount: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_FindObjects() called");

    if phObject.is_null() || pulObjectCount.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_FindObjects() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    let objects = match session.enum_next_chunk(ulMaxObjectCount as usize) {
        Ok(objects) => objects,
        Err(err) => {
            error!("C_FindObjects() failed: {:?}", err);
            return err;
        }
    };
    trace!("C_FindObjects() objects: {:?}", objects);

    unsafe {
        std::ptr::copy_nonoverlapping(
            objects.as_ptr(),
            phObject,
            objects.len().min(ulMaxObjectCount as usize),
        );
        std::ptr::write(pulObjectCount, objects.len() as CK_ULONG);
    }

    cryptoki_sys::CKR_OK
}
pub extern "C" fn C_FindObjectsFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_FindObjectsFinal() called");
    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_FindObjects() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    session.enum_final();

    cryptoki_sys::CKR_OK
}
pub extern "C" fn C_GetAttributeValue(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetAttributeValue() called for object {}.", hObject);

    if pTemplate.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!(
                "C_GetAttributeValue() called with invalid session handle {}.",
                hSession
            );
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    let object = match session.get_object(hObject) {
        Some(object) => object,
        None => {
            error!(
                "C_GetAttributeValue() called with invalid object handle {}.",
                hObject
            );
            return cryptoki_sys::CKR_OBJECT_HANDLE_INVALID;
        }
    };

    let mut template =
        unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) };

    object.fill_attr_template(&mut template)
}
pub extern "C" fn C_GetObjectSize(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pulSize: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetObjectSize() called");

    if pulSize.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!("function called with invalid session handle {}.", hSession);
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    let object = match session.get_object(hObject) {
        Some(object) => object,
        None => {
            error!("function called with invalid object handle {}.", hObject);
            return cryptoki_sys::CKR_OBJECT_HANDLE_INVALID;
        }
    };

    unsafe {
        std::ptr::write(pulSize, object.size.unwrap_or(0) as CK_ULONG);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_CreateObject(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_CreateObject() called ");

    if pTemplate.is_null() || phObject.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mut manager = lock_mutex!(SESSION_MANAGER);

    let session = match manager.get_session_mut(hSession) {
        Some(session) => session,
        None => {
            error!("function called with invalid session handle {}.", hSession);
            return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
        }
    };

    let template =
        unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) };

    let objects = match session.create_object(template) {
        Ok(object) => object,
        Err(err) => {
            error!("C_CreateObject() failed: {:?}", err);
            return err;
        }
    };

    if objects.is_empty() {
        error!("C_CreateObject() failed: no object created");
        return cryptoki_sys::CKR_GENERAL_ERROR;
    }

    unsafe {
        std::ptr::write(phObject, objects[0].0);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_CopyObject(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phNewObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_CopyObject() called");
    cryptoki_sys::CKR_ACTION_PROHIBITED
}

pub extern "C" fn C_DestroyObject(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_DestroyObject() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SetAttributeValue(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SetAttributeValue() called");
    cryptoki_sys::CKR_ACTION_PROHIBITED
}
