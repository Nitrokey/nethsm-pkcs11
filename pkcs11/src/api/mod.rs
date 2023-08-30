#![allow(non_snake_case)]
// for now we allow unused variables, but we should remove this when we have implemented all the functions we need
#![allow(unused_variables)]

pub mod decrypt;
pub mod digest;
pub mod encrypt;
pub mod generation;
pub mod object;
pub mod pin;
pub mod session;
pub mod sign;
pub mod token;
pub mod verify;

use crate::{
    backend::events::{fetch_slots_state, EventsManager},
    data::{self, DEVICE, EVENTS_MANAGER, TOKENS_STATE},
    defs, padded_str,
};
use cryptoki_sys::{CK_INFO, CK_INFO_PTR, CK_RV, CK_VOID_PTR};
use log::{debug, trace};

#[no_mangle]
pub extern "C" fn C_GetFunctionList(
    pp_fn_list: *mut *mut cryptoki_sys::CK_FUNCTION_LIST,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetFunctionList() called");
    if pp_fn_list.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    unsafe {
        std::ptr::write(pp_fn_list, &mut data::FN_LIST);
    }
    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    // we force the initialization of the lazy static here
    if DEVICE.slots.is_empty() {
        debug!("No slots configured");
    }

    trace!("C_Initialize() called with args: {:?}", pInitArgs);
    if defs::CRYPTOKI_VERSION.major == 2
        && defs::CRYPTOKI_VERSION.minor == 40
        && !pInitArgs.is_null()
    {
        let args = pInitArgs as cryptoki_sys::CK_C_INITIALIZE_ARGS_PTR;
        let args = unsafe { std::ptr::read(args) };

        // for cryptoki 2.40 this should always be null
        if !(args).pReserved.is_null() {
            return cryptoki_sys::CKR_ARGUMENTS_BAD;
        }

        let flags = args.flags;
        let CreateMutex = args.CreateMutex;

        trace!("C_Initialize() called with flags: {:?}", flags);
        trace!("C_Initialize() called with CreateMutex: {:?}", CreateMutex);

        // currently we don't support custom locking
        // if the flag is not set and the mutex functions are not null, the program asks us to use only the mutex functions, we can't do that
        if flags & cryptoki_sys::CKF_OS_LOCKING_OK == 0 && CreateMutex.is_some() {
            return cryptoki_sys::CKR_CANT_LOCK;
        }

        // currently we are using tokio that needs to create threads, so if the programs forbids us to create threads we return an error
        if flags & cryptoki_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS != 0 {
            return cryptoki_sys::CKR_NEED_TO_CREATE_THREADS;
        }
    }

    // Initialize the events manager
    *EVENTS_MANAGER.write().unwrap() = EventsManager::new();
    *TOKENS_STATE.lock().unwrap() = std::collections::HashMap::new();

    fetch_slots_state();

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    trace!("C_Finalize() called");
    if !pReserved.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }
    EVENTS_MANAGER.write().unwrap().finalized = true;

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    trace!("C_GetInfo() called");
    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let infos = CK_INFO {
        cryptokiVersion: defs::CRYPTOKI_VERSION,
        manufacturerID: padded_str!(defs::LIB_MANUFACTURER, 32),
        flags: 0,
        libraryDescription: padded_str!(defs::LIB_DESCRIPTION, 32),
        libraryVersion: defs::LIB_VERSION,
    };

    unsafe {
        std::ptr::write(pInfo, infos);
    }
    cryptoki_sys::CKR_OK
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_function_list() {
        let mut fn_list: *mut cryptoki_sys::CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = C_GetFunctionList(&mut fn_list);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert!(!fn_list.is_null());
    }

    #[test]
    fn test_get_function_list_null_ptr() {
        let rv = C_GetFunctionList(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_info_null_ptr() {
        let rv = C_GetInfo(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }
}
