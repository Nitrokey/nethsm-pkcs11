use std::slice;

use cryptoki_sys::CK_ULONG;
use log::{error, info, trace};

use crate::{
    api::api_function,
    backend::{
        db::attr::CkRawAttrTemplate,
        key::{NetHSMId, Pkcs11Id},
        Pkcs11Error,
    },
    data,
};

api_function!(
    C_FindObjectsInit = find_objects_init;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
);

fn find_objects_init(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    count: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    if count > 0 && template_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let template = unsafe { CkRawAttrTemplate::from_raw_ptr(template_ptr, count as usize) };

    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;
    trace!("C_FindObjectsInit() template: {template:?}");
    session.enum_init(template).map_err(From::from)
}

api_function!(
    C_FindObjects = find_objects;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    phObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: cryptoki_sys::CK_ULONG,
    pulObjectCount: cryptoki_sys::CK_ULONG_PTR,
);

fn find_objects(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    object_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    max_object_count: cryptoki_sys::CK_ULONG,
    object_count_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    if object_ptr.is_null() || object_count_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    trace!("C_FindObjects() ulMaxObjectCount: {max_object_count}");
    let objects = session.enum_next_chunk(max_object_count as usize)?;
    trace!("C_FindObjects() objects: {objects:?}");

    let returned_count = objects.len();

    unsafe {
        std::ptr::copy_nonoverlapping(objects.as_ptr(), object_ptr, returned_count);
        std::ptr::write(object_count_ptr, returned_count as CK_ULONG);
    }

    Ok(())
}

api_function!(
    C_FindObjectsFinal = find_objects_final;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
);

fn find_objects_final(session: cryptoki_sys::CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    session.enum_final();

    Ok(())
}

api_function!(
    C_GetAttributeValue = get_attribute_value;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
);

fn get_attribute_value(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    object: cryptoki_sys::CK_OBJECT_HANDLE,
    template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    count: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    if template_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let session = data::get_session(session)?;
    let session = data::lock_session(&session)?;

    let object = session.get_object(object).ok_or_else(|| {
        error!("C_GetAttributeValue() called with invalid object handle {object}.");
        Pkcs11Error::ObjectHandleInvalid
    })?;

    trace!(
        "C_GetAttributeValue() object id : {} {:?}",
        object.id,
        object.kind
    );

    let mut template = unsafe { CkRawAttrTemplate::from_raw_ptr(template_ptr, count as usize) }
        .ok_or(Pkcs11Error::ArgumentsBad)?;

    object.fill_attr_template(&mut template)
}

api_function!(
    C_GetObjectSize = get_object_size;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pulSize: cryptoki_sys::CK_ULONG_PTR,
);

fn get_object_size(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    object: cryptoki_sys::CK_OBJECT_HANDLE,
    size_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    if size_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let session = data::get_session(session)?;
    let session = data::lock_session(&session)?;

    let object = session.get_object(object).ok_or_else(|| {
        error!("function called with invalid object handle {object}.");
        Pkcs11Error::ObjectHandleInvalid
    })?;

    unsafe {
        std::ptr::write(size_ptr, object.size.unwrap_or(0) as CK_ULONG);
    }

    Ok(())
}

api_function!(
    C_CreateObject = create_object;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
);

fn create_object(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    count: cryptoki_sys::CK_ULONG,
    object_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> Result<(), Pkcs11Error> {
    // template_ptr checked with from_raw_ptr
    if object_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let template = unsafe { CkRawAttrTemplate::from_raw_ptr(template_ptr, count as usize) }
        .ok_or(Pkcs11Error::ArgumentsBad)?;

    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    let objects = session.create_object(template)?;

    if objects.is_empty() {
        error!("C_CreateObject() failed: no object created");
        return Err(Pkcs11Error::GeneralError);
    }

    unsafe {
        std::ptr::write(object_ptr, objects[0].0);
    }

    Ok(())
}

api_function!(
    C_CopyObject = copy_object;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phNewObject: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
);

fn copy_object(
    _session: cryptoki_sys::CK_SESSION_HANDLE,
    _object: cryptoki_sys::CK_OBJECT_HANDLE,
    _template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    _count: cryptoki_sys::CK_ULONG,
    _new_object_ptr: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::ActionProhibited)
}

api_function!(
    C_DestroyObject = destroy_object;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
);

fn destroy_object(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    object: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    session.delete_object(object).map_err(From::from)
}

api_function!(
    C_SetAttributeValue = set_attribute_value;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hObject: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
);

fn set_attribute_value(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    object: cryptoki_sys::CK_OBJECT_HANDLE,
    template_ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    count: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let session = data::lock_session(&session)?;

    if template_ptr.is_null() || count == 0 {
        error!("C_SetAttributeValue called without attributes in the template");
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let object = session.get_object(object).ok_or_else(|| {
        error!("C_SetAttributeValue() called with invalid object handle {object}.");
        Pkcs11Error::ObjectHandleInvalid
    })?;

    let n = usize::try_from(count).map_err(|_| {
        error!("C_SetAttributeValue called with too many attributes in the template");
        Pkcs11Error::ArgumentsBad
    })?;
    // SAFETY: The caller must ensure that pTemplate points to an array of ulCount attributes.
    // We already checked for null pointers and length zero above.
    let attrs = unsafe { slice::from_raw_parts(template_ptr, n) };

    let mut id = None;
    for attr in attrs {
        if attr.type_ != cryptoki_sys::CKA_ID {
            error!("C_SetAttributeValue() is supported only on CKA_ID");
            return Err(Pkcs11Error::AttributeReadOnly);
        }
        if id.is_some() {
            error!("CKA_ID cannot be set twice in C_SetAttributeValue");
            return Err(Pkcs11Error::TemplateInconsistent);
        }
        if attr.ulValueLen == 0
            || attr.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION
            || attr.pValue.is_null()
        {
            error!("CKA_ID value may not be empty in C_SetAttributeValue");
            return Err(Pkcs11Error::AttributeValueInvalid);
        }
        let Ok(n) = usize::try_from(attr.ulValueLen) else {
            error!("CKA_ID value is too long in C_SetAttributeValue");
            return Err(Pkcs11Error::AttributeValueInvalid);
        };
        // SAFETY: The caller must provide a byte slice of the correct size for CKA_ID attributes.
        // We already checked for null pointers and length zero above.
        id = Some(unsafe { slice::from_raw_parts(attr.pValue as *const u8, n) });
    }
    // We already checked before that there is at least one attribute. As CKA_ID is the only
    // attribute we support, id cannot be None.
    let id = id.ok_or(Pkcs11Error::ArgumentsBad)?;
    let id = Pkcs11Id::from(id);
    let id = NetHSMId::try_from(&id).map_err(|_| {
        error!("CKA_ID value is not a valid NetHSM ID: {id:?}");
        Pkcs11Error::AttributeValueInvalid
    })?;

    info!("Changing ID to: {}", id);
    session.rename_objects(&object.id, &id).map_err(From::from)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Condvar, Mutex};

    use crate::{
        backend::{
            db::{Db, Object},
            login::LoginCtx,
            session::Session,
            slot::{get_slot, init_for_tests},
        },
        data::SESSION_MANAGER,
    };

    use super::*;

    #[test]
    fn test_find_objects_init_bad_arguments() {
        let _guard = init_for_tests();
        let rv = C_FindObjectsInit(0, std::ptr::null_mut(), 1);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_find_objects_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut object: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        let mut object_count: cryptoki_sys::CK_ULONG = 0;

        let rv = C_FindObjects(0, &mut object, 1, &mut object_count);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_find_objects_null_object() {
        let _guard = init_for_tests();
        let mut object_count: cryptoki_sys::CK_ULONG = 0;

        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_FindObjects(session, std::ptr::null_mut(), 1, &mut object_count);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_find_objects_null_object_count() {
        let _guard = init_for_tests();
        let mut object: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_FindObjects(session, &mut object, 1, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_find_objects_final_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_FindObjectsFinal(0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_attribute_value_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut template = vec![];

        let rv = C_GetAttributeValue(0, 0, template.as_mut_ptr(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_attribute_value_null_template() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_GetAttributeValue(session, 0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_attribute_value_invalid_object() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut template = vec![];

        let rv = C_GetAttributeValue(session, 0, template.as_mut_ptr(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn test_get_object_size_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut size: cryptoki_sys::CK_ULONG = 0;

        let rv = C_GetObjectSize(0, 0, &mut size);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_get_object_size_null_size() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_GetObjectSize(session, 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_object_size_invalid_object() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut size: cryptoki_sys::CK_ULONG = 0;

        let rv = C_GetObjectSize(session, 0, &mut size);
        assert_eq!(rv, cryptoki_sys::CKR_OBJECT_HANDLE_INVALID);
    }

    #[test]
    fn test_get_object_size() {
        let _guard = init_for_tests();
        let slot = get_slot(0).unwrap();
        let size = 32;
        let mut db = Db::new();
        let id = NetHSMId::try_from("test".to_owned()).unwrap();
        let mut object = Object::new(id);
        object.size = Some(size);
        let (object_handle, _) = db.add_object(object);

        let session_handle = 1;
        let session = Session {
            db: Arc::new((Mutex::new(db), Condvar::new())),
            decrypt_ctx: None,
            encrypt_ctx: None,
            sign_ctx: None,
            device_error: None,
            enum_ctx: None,
            flags: 0,
            login_ctx: LoginCtx::new(slot, false, false),
            slot_id: 0,
        };

        SESSION_MANAGER
            .lock()
            .unwrap()
            .set_session(session_handle, session);

        let mut object_size: cryptoki_sys::CK_ULONG = 0;

        let rv = C_GetObjectSize(session_handle, object_handle, &mut object_size);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert_eq!(object_size, size as CK_ULONG);
    }

    #[test]
    fn test_create_object_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);
        let mut template = vec![];
        let mut object: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        let rv = C_CreateObject(0, template.as_mut_ptr(), 0, &mut object);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_create_object_null_object() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut template = vec![];

        let rv = C_CreateObject(session, template.as_mut_ptr(), 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_create_object_null_template() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut object: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        let rv = C_CreateObject(session, std::ptr::null_mut(), 0, &mut object);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_destroy_object_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let rv = C_DestroyObject(0, 0);
        assert_eq!(rv, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_set_attribute_null_template() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let rv = C_SetAttributeValue(session, 0, std::ptr::null_mut(), 0);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_copy_object() {
        let _guard = init_for_tests();
        let rv = C_CopyObject(0, 0, std::ptr::null_mut(), 0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ACTION_PROHIBITED);
    }
}
