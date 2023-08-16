use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    backend::{db::attr::CkRawAttrTemplate, key},
    data::{DEVICE, KEY_ALIASES},
    lock_mutex, lock_session,
    utils::get_tokio_rt,
};

pub extern "C" fn C_FindObjectsInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_FindObjectsInit() called with session {}", hSession);

    if ulCount > 0 && pTemplate.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    lock_session!(hSession, session);

    let template = if !pTemplate.is_null() {
        Some(unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) })
    } else {
        None
    };
    trace!("C_FindObjectsInit() template: {:?}", template);
    match session.enum_init(template) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(err) => err.into(),
    }
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

    lock_session!(hSession, session);

    trace!("C_FindObjects() ulMaxObjectCount: {}", ulMaxObjectCount);
    let objects = match session.enum_next_chunk(ulMaxObjectCount as usize) {
        Ok(objects) => objects,
        Err(err) => {
            return err.into();
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
    lock_session!(hSession, session);

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

    lock_session!(hSession, session);

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

    trace!(
        "C_GetAttributeValue() object id : {} {:?}",
        object.id,
        object.kind
    );

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

    lock_session!(hSession, session);

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

    lock_session!(hSession, session);

    let template =
        unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) };

    let objects = match get_tokio_rt().block_on(session.create_object(template)) {
        Ok(object) => object,
        Err(err) => {
            return err.into();
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
    trace!("C_DestroyObject() called : {}", hObject);

    lock_session!(hSession, session);

    match session.delete_object(hObject) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(err) => err.into(),
    }
}

pub extern "C" fn C_SetAttributeValue(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SetAttributeValue() called");

    if pTemplate.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let template =
        unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) };
    let parsed = match key::parse_attributes(&template) {
        Ok(parsed) => parsed,
        Err(err) => {
            return err.into();
        }
    };

    // if the hack is enabled, we update the key alias map
    if DEVICE.enable_set_attribute_value {
        lock_session!(hSession, session);

        let object = match session.get_object(hObject) {
            Some(object) => object,
            None => {
                error!(
                    "C_SetAttributeValue() called with invalid object handle {}.",
                    hObject
                );
                return cryptoki_sys::CKR_OBJECT_HANDLE_INVALID;
            }
        };

        if let Some(new_name) = parsed.id {
            KEY_ALIASES.lock().unwrap().insert(new_name, object.id);
            cryptoki_sys::CKR_OK
        } else {
            error!("C_SetAttributeValue() is supported only on CKA_ID");

            // We only support changing the ID
            cryptoki_sys::CKR_ATTRIBUTE_READ_ONLY
        }
    } else {
        if parsed.id.is_some() {
            error!("The application tried to change the CKA_ID attribute of a key. If you are using the Sun PKCS11 provider for Java KeyStore (or EJBCA), you can set enable_set_attribute_value option to true in the configuration file. See our documentation to understand its implications.")
        }

        cryptoki_sys::CKR_ATTRIBUTE_READ_ONLY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_object() {
        let rv = C_CopyObject(0, 0, std::ptr::null_mut(), 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ACTION_PROHIBITED);
    }
}
