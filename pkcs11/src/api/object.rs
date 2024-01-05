use cryptoki_sys::CK_ULONG;
use log::{error, trace};

use crate::{
    backend::{db::attr::CkRawAttrTemplate, key},
    data::{DEVICE, KEY_ALIASES},
    lock_session, read_session,
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

    let template = unsafe { CkRawAttrTemplate::from_raw_ptr(pTemplate, ulCount as usize) };

    lock_session!(hSession, session);
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

    let returned_count = objects.len();

    unsafe {
        std::ptr::copy_nonoverlapping(objects.as_ptr(), phObject, returned_count);
        std::ptr::write(pulObjectCount, returned_count as CK_ULONG);
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

    read_session!(hSession, session);

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

    let mut template = match unsafe { CkRawAttrTemplate::from_raw_ptr(pTemplate, ulCount as usize) }
    {
        Some(template) => template,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

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

    read_session!(hSession, session);

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

    // pTemplate checked with from_raw_ptr

    if phObject.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let template = match unsafe { CkRawAttrTemplate::from_raw_ptr(pTemplate, ulCount as usize) } {
        Some(template) => template,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };

    lock_session!(hSession, session);

    let objects = match session.create_object(template) {
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

    let template = match unsafe { CkRawAttrTemplate::from_raw_ptr(pTemplate, ulCount as usize) } {
        Some(template) => template,
        None => {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }
    };
    let parsed = match key::parse_attributes(&template) {
        Ok(parsed) => parsed,
        Err(err) => {
            return err.into();
        }
    };

    let Some(device) = DEVICE.get() else {
        error!("Initialization was not performed or failed");
        return cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED;
    };

    // if the hack is enabled, we update the key alias map
    if device.enable_set_attribute_value {
        read_session!(hSession, session);

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
    use std::sync::{Arc, Mutex};

    use crate::{
        backend::{
            db::{Db, Object},
            login::LoginCtx,
            session::Session,
            slot::init_for_tests,
        },
        config::config_file::RetryConfig,
        data::SESSION_MANAGER,
    };

    use super::*;

    #[test]
    fn test_find_objects_init_bad_arguments() {
        init_for_tests();
        let rv = C_FindObjectsInit(0, std::ptr::null_mut(), 1);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_find_objects_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut phObject: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        let mut pulObjectCount: cryptoki_sys::CK_ULONG = 0;

        let rv = C_FindObjects(0, &mut phObject, 1, &mut pulObjectCount);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_find_objects_null_object() {
        init_for_tests();
        let mut pulObjectCount: cryptoki_sys::CK_ULONG = 0;

        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_FindObjects(session, std::ptr::null_mut(), 1, &mut pulObjectCount);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_find_objects_null_object_count() {
        init_for_tests();
        let mut phObject: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_FindObjects(session, &mut phObject, 1, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_find_objects_final_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_FindObjectsFinal(0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_attribute_value_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut template = vec![];

        let rv = C_GetAttributeValue(0, 0, template.as_mut_ptr(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_attribute_value_null_template() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_GetAttributeValue(session, 0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_attribute_value_invalid_object() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut template = vec![];

        let rv = C_GetAttributeValue(session, 0, template.as_mut_ptr(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn test_get_object_size_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut pulSize: cryptoki_sys::CK_ULONG = 0;

        let rv = C_GetObjectSize(0, 0, &mut pulSize);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_object_size_null_size() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_GetObjectSize(session, 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_object_size_invalid_object() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pulSize: cryptoki_sys::CK_ULONG = 0;

        let rv = C_GetObjectSize(session, 0, &mut pulSize);
        assert_eq!(rv, cryptoki_sys::CKR_OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn test_get_object_size() {
        init_for_tests();
        let size = 32;
        let mut db = Db::new();
        let mut object = Object::default();
        object.size = Some(size);
        let (object_handle, _) = db.add_object(object);

        let session_handle = 1;
        let session = Session {
            db: Arc::new(Mutex::new(db)),
            decrypt_ctx: None,
            encrypt_ctx: None,
            sign_ctx: None,
            device_error: 0,
            enum_ctx: None,
            flags: 0,
            login_ctx: LoginCtx::new(
                None,
                None,
                vec![],
                Some(RetryConfig {
                    count: 2,
                    delay_seconds: 0,
                }),
            ),
            slot_id: 0,
        };

        SESSION_MANAGER
            .lock()
            .unwrap()
            .set_session(session_handle, session);

        let mut pulSize: cryptoki_sys::CK_ULONG = 0;

        let rv = C_GetObjectSize(session_handle, object_handle, &mut pulSize);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert_eq!(pulSize, size as CK_ULONG);
    }

    #[test]
    fn test_create_object_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);
        let mut template = vec![];
        let mut phObject: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        let rv = C_CreateObject(0, template.as_mut_ptr(), 0, &mut phObject);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_create_object_null_object() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut template = vec![];

        let rv = C_CreateObject(session, template.as_mut_ptr(), 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_create_object_null_template() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut phObject: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        let rv = C_CreateObject(session, std::ptr::null_mut(), 0, &mut phObject);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_destroy_object_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_DestroyObject(0, 0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_set_attribute_null_template() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_SetAttributeValue(session, 0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_copy_object() {
        init_for_tests();
        let rv = C_CopyObject(0, 0, std::ptr::null_mut(), 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ACTION_PROHIBITED);
    }
}
