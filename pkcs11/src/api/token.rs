use cryptoki_sys::{
    CKF_RNG, CKF_TOKEN_INITIALIZED, CKF_USER_PIN_INITIALIZED, CK_SLOT_ID, CK_SLOT_INFO,
    CK_TOKEN_INFO, CK_ULONG,
};
use log::{debug, error, trace, warn};
use nethsm_sdk_rs::{
    apis::default_api,
    models::{HealthStateData, InfoData, SystemState},
};

use crate::{
    api::api_function,
    backend::{
        events::fetch_slots_state,
        login::{LoginCtx, UserMode},
        slot::get_slot,
        Pkcs11Error,
    },
    data::{self, EVENTS_MANAGER},
    defs::{DEFAULT_FIRMWARE_VERSION, DEFAULT_HARDWARE_VERSION, MECHANISM_LIST},
    utils::{padded_str, version_struct_from_str},
};

api_function!(
    C_GetSlotList = get_slot_list;
    tokenPresent: cryptoki_sys::CK_BBOOL,
    pSlotList: cryptoki_sys::CK_SLOT_ID_PTR,
    pulCount: cryptoki_sys::CK_ULONG_PTR,
);

fn get_slot_list(
    _token_present: cryptoki_sys::CK_BBOOL,
    slot_list_ptr: cryptoki_sys::CK_SLOT_ID_PTR,
    count_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    if count_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let device = data::load_device()?;

    let count = device.slots.len() as CK_ULONG;

    // only the count is requested
    if slot_list_ptr.is_null() {
        unsafe {
            std::ptr::write(count_ptr, count);
        }
        return Ok(());
    }

    // check if the buffer is large enough
    if unsafe { *count_ptr } < count {
        unsafe {
            std::ptr::write(count_ptr, count);
        }
        return Err(Pkcs11Error::BufferTooSmall);
    }

    // list the ids
    let id_list: Vec<CK_SLOT_ID> = device
        .slots
        .iter()
        .enumerate()
        .map(|(i, _)| i as CK_SLOT_ID)
        .collect();

    unsafe {
        std::ptr::copy_nonoverlapping(id_list.as_ptr(), slot_list_ptr, id_list.len());
        std::ptr::write(count_ptr, count as CK_ULONG);
    }

    Ok(())
}

api_function!(
    C_GetSlotInfo = get_slot_info;
    slotID: cryptoki_sys::CK_SLOT_ID,
    pInfo: cryptoki_sys::CK_SLOT_INFO_PTR,
);

fn get_slot_info(
    slot_id: cryptoki_sys::CK_SLOT_ID,
    info_ptr: cryptoki_sys::CK_SLOT_INFO_PTR,
) -> Result<(), Pkcs11Error> {
    trace!("C_GetSlotInfo() called with slotID: {slot_id}");

    if info_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    // get the slot
    let slot = get_slot(slot_id)?;

    let mut flags = 0;

    let login_ctx = LoginCtx::new(slot.clone(), false, false);

    let result = login_ctx.try_(
        default_api::info_get,
        crate::backend::login::UserMode::Guest,
    );

    // fetch info from the device

    let info = match result {
        Ok(info) => info.entity,
        Err(e) => {
            trace!("Error getting info: {e:?}");
            InfoData {
                product: "unknown".to_string(),
                vendor: "unknown".to_string(),
            }
        }
    };

    let result = login_ctx.try_(
        default_api::health_state_get,
        crate::backend::login::UserMode::Guest,
    );

    // fetch the sysem state

    let system_state = match result {
        Ok(info) => info.entity,
        Err(e) => {
            trace!("Error getting system state: {e:?}");
            HealthStateData {
                state: SystemState::Unprovisioned,
            }
        }
    };

    if system_state.state == SystemState::Operational {
        flags |= cryptoki_sys::CKF_TOKEN_PRESENT;
    }

    let info: CK_SLOT_INFO = CK_SLOT_INFO {
        slotDescription: padded_str(&info.product),
        manufacturerID: padded_str(&info.vendor),
        flags,
        hardwareVersion: DEFAULT_HARDWARE_VERSION,
        firmwareVersion: DEFAULT_FIRMWARE_VERSION,
    };

    unsafe {
        std::ptr::write(info_ptr, info);
    }

    Ok(())
}

api_function!(
    C_GetTokenInfo = get_token_info;
    slotID: cryptoki_sys::CK_SLOT_ID,
    pInfo: cryptoki_sys::CK_TOKEN_INFO_PTR,
);

fn get_token_info(
    slot_id: cryptoki_sys::CK_SLOT_ID,
    info_ptr: cryptoki_sys::CK_TOKEN_INFO_PTR,
) -> Result<(), Pkcs11Error> {
    trace!("C_GetTokenInfo() called with slotID: {slot_id}");

    // get the slot
    let slot = get_slot(slot_id)?;

    if info_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let login_ctx = LoginCtx::new(slot.clone(), true, false);

    // fetch info from the device
    let info = login_ctx
        .try_(
            default_api::info_get,
            crate::backend::login::UserMode::Guest,
        )
        .map_err(|err| {
            error!("Error getting info: {err:?}");
            Pkcs11Error::FunctionFailed
        })?;

    let mut serial_number = "unknown".to_string();
    let mut hardware_version = DEFAULT_HARDWARE_VERSION;
    let mut firmware_version = DEFAULT_FIRMWARE_VERSION;

    // Try to fech system info

    if login_ctx.can_run_mode(crate::backend::login::UserMode::Administrator) {
        match login_ctx.try_(default_api::system_info_get, UserMode::Administrator) {
            Err(e) => {
                warn!("Error getting system info: {e:?}");
            }
            Ok(system_info) => {
                serial_number = system_info.entity.device_id;
                hardware_version = version_struct_from_str(system_info.entity.hardware_version);
                // The PKCS11 firmware version actually corresponds to the NetHSM software version
                firmware_version = version_struct_from_str(system_info.entity.software_version);
            }
        }
    }

    let mut flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_RNG;

    // if the slot has no password, set the login required flag
    if !slot.is_connected() {
        flags |= cryptoki_sys::CKF_LOGIN_REQUIRED;
        debug!("Login required");
    }

    let token_info = CK_TOKEN_INFO {
        label: padded_str(&slot.label),
        manufacturerID: padded_str(&info.entity.vendor),
        model: padded_str(&info.entity.product),
        serialNumber: padded_str(&serial_number),
        flags,
        hardwareVersion: hardware_version,
        firmwareVersion: firmware_version,
        ..Default::default()
    };

    unsafe {
        std::ptr::write(info_ptr, token_info);
    }

    Ok(())
}

api_function!(
    C_InitToken = init_token;
    slotID: cryptoki_sys::CK_SLOT_ID,
    pPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
    pLabel: cryptoki_sys::CK_UTF8CHAR_PTR,
);

fn init_token(
    _slot_id: cryptoki_sys::CK_SLOT_ID,
    _pin_ptr: cryptoki_sys::CK_UTF8CHAR_PTR,
    _pin_len: cryptoki_sys::CK_ULONG,
    _label_ptr: cryptoki_sys::CK_UTF8CHAR_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_GetMechanismList = get_mechanism_list;
    slotID: cryptoki_sys::CK_SLOT_ID,
    pMechanismList: cryptoki_sys::CK_MECHANISM_TYPE_PTR,
    pulCount: cryptoki_sys::CK_ULONG_PTR,
);

fn get_mechanism_list(
    slot_id: cryptoki_sys::CK_SLOT_ID,
    mechanism_list_ptr: cryptoki_sys::CK_MECHANISM_TYPE_PTR,
    count_ptr: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    if count_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    get_slot(slot_id)?;

    let count = MECHANISM_LIST.len() as CK_ULONG;

    // only the count is requested
    if mechanism_list_ptr.is_null() {
        unsafe {
            std::ptr::write(count_ptr, count);
        }
        return Ok(());
    }

    let buffer_size = unsafe { std::ptr::read(count_ptr) };

    // set the buffer size
    unsafe {
        std::ptr::write(count_ptr, count);
    }
    // check if the buffer is large enough
    if buffer_size < count {
        return Err(Pkcs11Error::BufferTooSmall);
    }

    // list the ids
    let id_list: Vec<cryptoki_sys::CK_MECHANISM_TYPE> = MECHANISM_LIST
        .iter()
        .map(|mechanism| mechanism.ck_type())
        .collect();

    unsafe {
        std::ptr::copy_nonoverlapping(id_list.as_ptr(), mechanism_list_ptr, id_list.len());
    }

    Ok(())
}

api_function!(
    C_GetMechanismInfo = get_mechanism_info;
    slotID: cryptoki_sys::CK_SLOT_ID,
    type_: cryptoki_sys::CK_MECHANISM_TYPE,
    pInfo: cryptoki_sys::CK_MECHANISM_INFO_PTR,
);

fn get_mechanism_info(
    slot_id: cryptoki_sys::CK_SLOT_ID,
    type_: cryptoki_sys::CK_MECHANISM_TYPE,
    info_ptr: cryptoki_sys::CK_MECHANISM_INFO_PTR,
) -> Result<(), Pkcs11Error> {
    get_slot(slot_id)?;

    if info_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    // find the mechanism in the list

    let mechanism = MECHANISM_LIST
        .iter()
        .find(|m| m.ck_type() == type_)
        .ok_or(Pkcs11Error::MechanismInvalid)?;

    unsafe {
        std::ptr::write(info_ptr, mechanism.ck_info());
    }

    Ok(())
}

api_function!(
    C_Login = login;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    userType: cryptoki_sys::CK_USER_TYPE,
    pPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
);

fn login(
    session: cryptoki_sys::CK_SESSION_HANDLE,
    user_type: cryptoki_sys::CK_USER_TYPE,
    pin_ptr: cryptoki_sys::CK_UTF8CHAR_PTR,
    pin_len: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    if pin_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let pin = unsafe { std::slice::from_raw_parts(pin_ptr, pin_len as usize) };

    // parse string to utf8
    let pin = std::str::from_utf8(pin).map_err(|_| Pkcs11Error::ArgumentsBad)?;

    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    session
        .login(user_type, pin.to_string())
        .map_err(From::from)
}

api_function!(
    C_Logout = logout;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
);

fn logout(session: cryptoki_sys::CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
    let session = data::get_session(session)?;
    let mut session = data::lock_session(&session)?;

    session.logout().map_err(From::from)
}

api_function!(
    C_WaitForSlotEvent = wait_for_slot_event;
    flags: cryptoki_sys::CK_FLAGS,
    pSlot: cryptoki_sys::CK_SLOT_ID_PTR,
    pReserved: cryptoki_sys::CK_VOID_PTR,
);

fn wait_for_slot_event(
    flags: cryptoki_sys::CK_FLAGS,
    slot_ptr: cryptoki_sys::CK_SLOT_ID_PTR,
    _reserved_ptr: cryptoki_sys::CK_VOID_PTR,
) -> Result<(), Pkcs11Error> {
    if slot_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    fetch_slots_state()?;

    loop {
        // check if there is an event in the queue

        let slot = EVENTS_MANAGER.write().unwrap().events.pop();
        if let Some(slot) = slot {
            unsafe {
                std::ptr::write(slot_ptr, slot);
            }
            return Ok(());
        }

        // if the dont block flag is set, return no event
        if flags & cryptoki_sys::CKF_DONT_BLOCK == 1 {
            return Err(Pkcs11Error::NoEvent);
        } else {
            // Otherwise, wait for an event

            // If C_Finalize() has been called, return an error
            if EVENTS_MANAGER.read().unwrap().finalized {
                return Err(Pkcs11Error::CryptokiNotInitialized);
            }

            // sleep for 1 second
            std::thread::sleep(std::time::Duration::from_secs(1));

            // fetch the slots state so we get the latest events in the next iteration
            fetch_slots_state()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptoki_sys::{CKF_DONT_BLOCK, CKU_USER, CK_MECHANISM_INFO};

    use crate::{
        api::C_Finalize,
        backend::{
            events::{update_slot_state, EventsManager},
            slot::init_for_tests,
        },
        data::{SESSION_MANAGER, TOKENS_STATE},
    };

    use super::*;

    // Ignored by default because it would race with the other #[ignore] tests
    // Run with cargo test -- --test-threads=1 --ignored
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_no_event() {
        let _guard = init_for_tests();
        *EVENTS_MANAGER.write().unwrap() = EventsManager::new();
        *TOKENS_STATE.lock().unwrap() = std::collections::HashMap::new();

        let mut slot = 0;
        let result = C_WaitForSlotEvent(CKF_DONT_BLOCK, &mut slot, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_NO_EVENT);
    }

    // Ignored by default because it would race with the other #[ignore] tests
    // Run with cargo test -- --test-threads=1 --ignored
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_one_event() {
        let _guard = init_for_tests();
        *EVENTS_MANAGER.write().unwrap() = EventsManager::new();
        *TOKENS_STATE.lock().unwrap() = std::collections::HashMap::new();

        update_slot_state(0, false);
        update_slot_state(0, true);

        println!("Events: {:?}", EVENTS_MANAGER.read().unwrap().events);

        let mut slot = 15;
        let result = C_WaitForSlotEvent(CKF_DONT_BLOCK, &mut slot, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_OK);
        assert_eq!(slot, 0);
    }

    // Ignored by default because it would race with the other #[ignore] tests
    // Run with cargo test -- --test-threads=1 --ignored
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_blocking_one_event() {
        let _guard = init_for_tests();
        *EVENTS_MANAGER.write().unwrap() = EventsManager::new();
        *TOKENS_STATE.lock().unwrap() = std::collections::HashMap::new();

        // update the slot state in a separate thread

        let handle = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            update_slot_state(0, false);
            update_slot_state(0, true);
        });

        let mut slot = 15;
        let result = C_WaitForSlotEvent(0, &mut slot, std::ptr::null_mut());
        handle.join().unwrap();
        assert_eq!(result, cryptoki_sys::CKR_OK);
        assert_eq!(slot, 0);
    }

    // Ignored by default because it would race with the other #[ignore] tests
    // Run with cargo test -- --test-threads=1 --ignored
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_blocking_finalize() {
        let _guard = init_for_tests();
        *EVENTS_MANAGER.write().unwrap() = EventsManager::new();
        *TOKENS_STATE.lock().unwrap() = std::collections::HashMap::new();

        // update the slot state in a separate thread

        let handle = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));

            C_Finalize(std::ptr::null_mut());
        });

        let mut slot = 15;
        let result = C_WaitForSlotEvent(0, &mut slot, std::ptr::null_mut());
        handle.join().unwrap();
        println!("slot: {slot}");
        assert_eq!(result, cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    fn test_wait_for_slot_event_null_slot_ptr() {
        let _guard = init_for_tests();

        let result = C_WaitForSlotEvent(CKF_DONT_BLOCK, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_slot_list_null_count() {
        let _guard = init_for_tests();
        let result = C_GetSlotList(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_slot_list_null_list() {
        let _guard = init_for_tests();

        let mut count = 0;
        let result = C_GetSlotList(0, std::ptr::null_mut(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_OK);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_slot_list_small_buffer() {
        let _guard = init_for_tests();

        let mut count = 0;
        let mut list = [0; 1];
        let result = C_GetSlotList(0, list.as_mut_ptr(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_BUFFER_TOO_SMALL);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_slot_info_invalid_slot() {
        let _guard = init_for_tests();

        let mut info = CK_SLOT_INFO::default();
        let result = C_GetSlotInfo(99, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_slot_info_null_info() {
        let _guard = init_for_tests();

        let result = C_GetSlotInfo(0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_mechanism_list_null_count() {
        let _guard = init_for_tests();

        let result = C_GetMechanismList(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_mechanism_list_null_list() {
        let _guard = init_for_tests();

        let mut count = 0;
        let result = C_GetMechanismList(0, std::ptr::null_mut(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_OK);
        assert_eq!(count, MECHANISM_LIST.len() as CK_ULONG);
    }

    #[test]
    fn test_get_mechanism_list_small_buffer() {
        let _guard = init_for_tests();

        let mut count = 0;
        let mut list = [0; 1];
        let result = C_GetMechanismList(0, list.as_mut_ptr(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_BUFFER_TOO_SMALL);
        assert_eq!(count, MECHANISM_LIST.len() as CK_ULONG);
    }

    #[test]
    fn test_get_mechanism_list_invalid_slot() {
        let _guard = init_for_tests();

        let mut count = 0;
        let mut list = [0; 1];
        let result = C_GetMechanismList(99, list.as_mut_ptr(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_invalid_mechanism() {
        let _guard = init_for_tests();

        let mut info = CK_MECHANISM_INFO::default();
        let result = C_GetMechanismInfo(0, 15000, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_invalid_slot() {
        let _guard = init_for_tests();

        let mut info = CK_MECHANISM_INFO::default();
        let result = C_GetMechanismInfo(99, 0, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_null_info() {
        let _guard = init_for_tests();

        let result = C_GetMechanismInfo(0, 0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_token_info_invalid_slot() {
        let _guard = init_for_tests();

        let mut info = CK_TOKEN_INFO::default();
        let result = C_GetTokenInfo(99, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_token_info_null_info() {
        let _guard = init_for_tests();

        let result = C_GetTokenInfo(0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_login_null_pin() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let result = C_Login(session, CKU_USER, std::ptr::null_mut(), 0);
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_login_non_utf8_pin() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pin = [0xFF, 0xFF, 0xFF, 0xFF];

        let result = C_Login(session, CKU_USER, pin.as_mut_ptr(), 4);
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_login_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut pin = "1234".to_string();

        let result = C_Login(0, CKU_USER, pin.as_mut_ptr(), 4);
        assert_eq!(result, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_logout_invalid_session() {
        let _guard = init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let result = C_Logout(0);
        assert_eq!(result, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_logout() {
        let _guard = init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let result = C_Logout(session);
        assert_eq!(result, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_init_token() {
        let _guard = init_for_tests();
        let result = C_InitToken(0, std::ptr::null_mut(), 0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
