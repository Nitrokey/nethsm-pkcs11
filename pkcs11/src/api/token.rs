use cryptoki_sys::{
    CKF_RNG, CKF_TOKEN_INITIALIZED, CKF_USER_PIN_INITIALIZED, CKR_OK, CK_SLOT_ID, CK_SLOT_INFO,
    CK_TOKEN_INFO, CK_ULONG,
};
use log::{debug, error, trace, warn};
use nethsm_sdk_rs::{
    apis::default_api,
    models::{HealthStateData, InfoData, SystemState},
};

use crate::{
    backend::{
        events::fetch_slots_state,
        login::{LoginCtx, UserMode},
        slot::get_slot,
    },
    data::{DEVICE, EVENTS_MANAGER},
    defs::{DEFAULT_FIRMWARE_VERSION, DEFAULT_HARDWARE_VERSION, MECHANISM_LIST},
    lock_session,
    utils::{padded_str, version_struct_from_str},
};

pub extern "C" fn C_GetSlotList(
    tokenPresent: cryptoki_sys::CK_BBOOL,
    pSlotList: cryptoki_sys::CK_SLOT_ID_PTR,
    pulCount: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetSlotList() called");

    if pulCount.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let Some(device) = DEVICE.get() else {
        error!("Initialization was not performed or failed");
        return cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED;
    };

    let count = device.slots.len() as CK_ULONG;

    // only the count is requested
    if pSlotList.is_null() {
        unsafe {
            std::ptr::write(pulCount, count);
        }
        return cryptoki_sys::CKR_OK;
    } else {
        // check if the buffer is large enough
        if unsafe { *pulCount } < count {
            unsafe {
                std::ptr::write(pulCount, count);
            }
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
    }

    // list the ids

    let id_list: Vec<CK_SLOT_ID> = device
        .slots
        .iter()
        .enumerate()
        .map(|(i, client)| i as CK_SLOT_ID)
        .collect();

    unsafe {
        std::ptr::copy_nonoverlapping(id_list.as_ptr(), pSlotList, id_list.len());
        std::ptr::write(pulCount, count as CK_ULONG);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GetSlotInfo(
    slotID: cryptoki_sys::CK_SLOT_ID,
    pInfo: cryptoki_sys::CK_SLOT_INFO_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetSlotInfo() called with slotID: {}", slotID);

    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    // get the slot

    let slot = match get_slot(slotID as usize) {
        Ok(client) => client,
        Err(e) => {
            return e;
        }
    };

    let mut flags = 0;

    let mut login_ctx = LoginCtx::new(None, None, slot.instances.clone(), slot.retries);

    let result = login_ctx.try_(
        default_api::info_get,
        crate::backend::login::UserMode::Guest,
    );

    // fetch info from the device

    let info = match result {
        Ok(info) => info.entity,
        Err(e) => {
            trace!("Error getting info: {:?}", e);
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
            trace!("Error getting system state: {:?}", e);
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
        std::ptr::write(pInfo, info);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GetTokenInfo(
    slotID: cryptoki_sys::CK_SLOT_ID,
    pInfo: cryptoki_sys::CK_TOKEN_INFO_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetTokenInfo() called with slotID: {}", slotID);

    // get the slot
    let slot = match get_slot(slotID as usize) {
        Ok(slot) => slot,
        Err(e) => {
            return e;
        }
    };

    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mut login_ctx = LoginCtx::new(
        None,
        slot.administrator.clone(),
        slot.instances.clone(),
        slot.retries,
    );

    let result = login_ctx.try_(
        default_api::info_get,
        crate::backend::login::UserMode::Guest,
    );

    // fetch info from the device

    let info = match result {
        Ok(info) => info,
        Err(e) => {
            error!("Error getting info: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    let mut serial_number = "unknown".to_string();
    let mut hardware_version = DEFAULT_HARDWARE_VERSION;
    let mut firmware_version = DEFAULT_FIRMWARE_VERSION;

    // Try to fech system info

    if login_ctx.can_run_mode(crate::backend::login::UserMode::Administrator) {
        match login_ctx.try_(default_api::system_info_get, UserMode::Administrator) {
            Err(e) => {
                warn!("Error getting system info: {:?}", e);
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
        std::ptr::write(pInfo, token_info);
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_InitToken(
    slotID: cryptoki_sys::CK_SLOT_ID,
    pPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
    pLabel: cryptoki_sys::CK_UTF8CHAR_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_InitToken() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GetMechanismList(
    slotID: cryptoki_sys::CK_SLOT_ID,
    pMechanismList: cryptoki_sys::CK_MECHANISM_TYPE_PTR,
    pulCount: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetMechanismList() called");

    if pulCount.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    if let Err(e) = get_slot(slotID as usize) {
        return e;
    }

    let count = MECHANISM_LIST.len() as CK_ULONG;

    // only the count is requested
    if pMechanismList.is_null() {
        unsafe {
            std::ptr::write(pulCount, count);
        }
        return cryptoki_sys::CKR_OK;
    }

    let buffer_size = unsafe { std::ptr::read(pulCount) };

    // set the buffer size
    unsafe {
        std::ptr::write(pulCount, count);
    }
    // check if the buffer is large enough
    if buffer_size < count {
        return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
    }

    // list the ids

    let id_list: Vec<cryptoki_sys::CK_MECHANISM_TYPE> = MECHANISM_LIST
        .iter()
        .map(|mechanism| mechanism.ck_type())
        .collect();

    unsafe {
        std::ptr::copy_nonoverlapping(id_list.as_ptr(), pMechanismList, id_list.len());
    }

    CKR_OK
}

pub extern "C" fn C_GetMechanismInfo(
    slotID: cryptoki_sys::CK_SLOT_ID,
    type_: cryptoki_sys::CK_MECHANISM_TYPE,
    pInfo: cryptoki_sys::CK_MECHANISM_INFO_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetMechanismInfo() called");

    if let Err(e) = get_slot(slotID as usize) {
        return e;
    }

    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    // find the mechanism in the list

    let mechanism = match MECHANISM_LIST.iter().find(|m| m.ck_type() == type_) {
        Some(mechanism) => mechanism,
        None => return cryptoki_sys::CKR_MECHANISM_INVALID,
    };

    unsafe {
        std::ptr::write(pInfo, mechanism.ck_info());
    }

    CKR_OK
}

pub extern "C" fn C_Login(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    userType: cryptoki_sys::CK_USER_TYPE,
    pPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Login() called");

    if pPin.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let pin = unsafe { std::slice::from_raw_parts(pPin, ulPinLen as usize) };

    // parse string to utf8

    let pin = match std::str::from_utf8(pin) {
        Ok(pin) => pin,
        Err(_) => return cryptoki_sys::CKR_ARGUMENTS_BAD,
    };

    lock_session!(hSession, session);

    match session.login(userType, pin.to_string()) {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(e) => e.into(),
    }
}
pub extern "C" fn C_Logout(hSession: cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV {
    trace!("C_Logout() called");

    lock_session!(hSession, session);

    match session.logout() {
        Ok(_) => cryptoki_sys::CKR_OK,
        Err(e) => e.into(),
    }
}

pub extern "C" fn C_WaitForSlotEvent(
    flags: cryptoki_sys::CK_FLAGS,
    pSlot: cryptoki_sys::CK_SLOT_ID_PTR,
    pReserved: cryptoki_sys::CK_VOID_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_WaitForSlotEvent() called");

    if pSlot.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    match fetch_slots_state() {
        Ok(()) => {}
        Err(err) => return err,
    }

    loop {
        // check if there is an event in the queue

        let slot = EVENTS_MANAGER.write().unwrap().events.pop();
        if let Some(slot) = slot {
            unsafe {
                std::ptr::write(pSlot, slot);
            }
            return cryptoki_sys::CKR_OK;
        }

        // if the dont block flag is set, return no event
        if flags & cryptoki_sys::CKF_DONT_BLOCK == 1 {
            return cryptoki_sys::CKR_NO_EVENT;
        } else {
            // Otherwise, wait for an event

            // If C_Finalize() has been called, return an error
            if EVENTS_MANAGER.read().unwrap().finalized {
                return cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED;
            }

            // sleep for 1 second
            std::thread::sleep(std::time::Duration::from_secs(1));

            // fetch the slots state so we get the latest events in the next iteration
            match fetch_slots_state() {
                Ok(()) => {}
                Err(err) => return err,
            }
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

    // ignored because it needs to be run alone on one thread
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_no_event() {
        init_for_tests();
        *EVENTS_MANAGER.write().unwrap() = EventsManager::new();
        *TOKENS_STATE.lock().unwrap() = std::collections::HashMap::new();

        let mut slot = 0;
        let result = C_WaitForSlotEvent(CKF_DONT_BLOCK, &mut slot, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_NO_EVENT);
    }

    // ignored because it needs to be run alone on one thread
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_one_event() {
        init_for_tests();
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

    // we ignore this test because it requires cargo test -- --test-threads=1
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_blocking_one_event() {
        init_for_tests();
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

    // we ignore this test because it requires cargo test -- --test-threads=1
    #[test]
    #[ignore]
    fn test_wait_for_slot_event_blocking_finalize() {
        init_for_tests();
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
        println!("slot: {}", slot);
        assert_eq!(result, cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    fn test_wait_for_slot_event_null_slot_ptr() {
        init_for_tests();

        let result = C_WaitForSlotEvent(CKF_DONT_BLOCK, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_slot_list_null_count() {
        init_for_tests();
        let result = C_GetSlotList(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_slot_list_null_list() {
        init_for_tests();

        let mut count = 0;
        let result = C_GetSlotList(0, std::ptr::null_mut(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_OK);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_slot_list_small_buffer() {
        init_for_tests();

        let mut count = 0;
        let mut list = [0; 1];
        let result = C_GetSlotList(0, list.as_mut_ptr(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_BUFFER_TOO_SMALL);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_slot_info_invalid_slot() {
        init_for_tests();

        let mut info = CK_SLOT_INFO::default();
        let result = C_GetSlotInfo(99, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_slot_info_null_info() {
        init_for_tests();

        let result = C_GetSlotInfo(0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_mechanism_list_null_count() {
        init_for_tests();

        let result = C_GetMechanismList(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_mechanism_list_null_list() {
        init_for_tests();

        let mut count = 0;
        let result = C_GetMechanismList(0, std::ptr::null_mut(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_OK);
        assert_eq!(count, MECHANISM_LIST.len() as CK_ULONG);
    }

    #[test]
    fn test_get_mechanism_list_small_buffer() {
        init_for_tests();

        let mut count = 0;
        let mut list = [0; 1];
        let result = C_GetMechanismList(0, list.as_mut_ptr(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_BUFFER_TOO_SMALL);
        assert_eq!(count, MECHANISM_LIST.len() as CK_ULONG);
    }

    #[test]
    fn test_get_mechanism_list_invalid_slot() {
        init_for_tests();

        let mut count = 0;
        let mut list = [0; 1];
        let result = C_GetMechanismList(99, list.as_mut_ptr(), &mut count);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_invalid_mechanism() {
        init_for_tests();

        let mut info = CK_MECHANISM_INFO::default();
        let result = C_GetMechanismInfo(0, 15000, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_invalid_slot() {
        init_for_tests();

        let mut info = CK_MECHANISM_INFO::default();
        let result = C_GetMechanismInfo(99, 0, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_null_info() {
        init_for_tests();

        let result = C_GetMechanismInfo(0, 0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_token_info_invalid_slot() {
        init_for_tests();

        let mut info = CK_TOKEN_INFO::default();
        let result = C_GetTokenInfo(99, &mut info);
        assert_eq!(result, cryptoki_sys::CKR_SLOT_ID_INVALID);
    }

    #[test]
    fn test_get_token_info_null_info() {
        init_for_tests();

        let result = C_GetTokenInfo(0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_login_null_pin() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let result = C_Login(session, CKU_USER, std::ptr::null_mut(), 0);
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_login_non_utf8_pin() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let mut pin = [0xFF, 0xFF, 0xFF, 0xFF];

        let result = C_Login(session, CKU_USER, pin.as_mut_ptr(), 4);
        assert_eq!(result, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_login_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let mut pin = "1234".to_string();

        let result = C_Login(0, CKU_USER, pin.as_mut_ptr(), 4);
        assert_eq!(result, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_logout_invalid_session() {
        init_for_tests();
        SESSION_MANAGER.lock().unwrap().delete_session(0);

        let result = C_Logout(0);
        assert_eq!(result, cryptoki_sys::CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_logout() {
        init_for_tests();
        let session = SESSION_MANAGER.lock().unwrap().setup_dummy_session();

        let result = C_Logout(session);
        assert_eq!(result, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_init_token() {
        init_for_tests();
        let result = C_InitToken(0, std::ptr::null_mut(), 0, std::ptr::null_mut());
        assert_eq!(result, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
