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

use std::sync::atomic::Ordering;
use std::{ptr::addr_of_mut, sync::Arc};

use crate::config::device::{start_background_timer, stop_background_timer};
use crate::{
    backend::{
        events::{fetch_slots_state, EventsManager},
        Pkcs11Error,
    },
    data::{self, DEVICE, EVENTS_MANAGER, THREADS_ALLOWED, TOKENS_STATE},
    defs,
    utils::padded_str,
};
use cryptoki_sys::{CK_INFO, CK_INFO_PTR, CK_VOID_PTR};
use log::{debug, error, trace};

macro_rules! api_function {
    (
        $c_fn:ident = $rust_fn:ident;
        $(
            $arg:ident: $ty:ty,
        )+
        $(,)?
    ) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn $c_fn($($arg: $ty,)*) -> ::cryptoki_sys::CK_RV {
            ::log::trace!("{} called", stringify!($c_fn));
            let result = $rust_fn($($arg,)*);
            match result {
                Ok(()) => {
                    ::log::trace!("{} was successful", stringify!($c_fn));
                    ::cryptoki_sys::CKR_OK
                }
                Err(err) => {
                    ::log::warn!("{} failed with error {err:?}", stringify!($c_fn));
                    ::std::convert::From::from(err)
                }
            }
        }
    }
}

use api_function;

api_function!(
    C_GetFunctionList = get_function_list;
    ppFunctionList: *mut *mut cryptoki_sys::CK_FUNCTION_LIST,
);

fn get_function_list(
    fn_list_ptr: *mut *mut cryptoki_sys::CK_FUNCTION_LIST,
) -> Result<(), Pkcs11Error> {
    if fn_list_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    unsafe {
        std::ptr::write(fn_list_ptr, addr_of_mut!(data::FN_LIST));
    }
    Ok(())
}

api_function!(
    C_Initialize = initialize;
    pInitArgs: CK_VOID_PTR,
);

fn initialize(init_args_ptr: CK_VOID_PTR) -> Result<(), Pkcs11Error> {
    let device = crate::config::initialization::initialize().map_err(|err| {
        error!("NetHSM PKCS#11: Failed to initialize configuration: {err}");
        Pkcs11Error::FunctionFailed
    })?;
    let device = Arc::new(device);
    DEVICE.store(Some(device.clone()));

    // we force the initialization of the lazy static here
    if device.slots.is_empty() {
        debug!("No slots configured");
    }

    if defs::CRYPTOKI_VERSION.major == 2
        && defs::CRYPTOKI_VERSION.minor == 40
        && !init_args_ptr.is_null()
    {
        let args = init_args_ptr as cryptoki_sys::CK_C_INITIALIZE_ARGS_PTR;
        let args = unsafe { std::ptr::read(args) };

        // for cryptoki 2.40 this should always be null
        if !(args).pReserved.is_null() {
            return Err(Pkcs11Error::ArgumentsBad);
        }

        let flags = args.flags;
        let create_mutex = args.CreateMutex;

        trace!("C_Initialize() called with flags: {flags:?}");
        trace!("C_Initialize() called with CreateMutex: {create_mutex:?}");

        // currently we don't support custom locking
        // if the flag is not set and the mutex functions are not null, the program asks us to use only the mutex functions, we can't do that
        if flags & cryptoki_sys::CKF_OS_LOCKING_OK == 0 && create_mutex.is_some() {
            return Err(Pkcs11Error::CantLock);
        }

        if flags & cryptoki_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS != 0 {
            THREADS_ALLOWED.store(false, Ordering::Relaxed);
        } else {
            THREADS_ALLOWED.store(true, Ordering::Relaxed);
            start_background_timer();
        }
    }

    // Initialize the events manager
    *EVENTS_MANAGER.write().unwrap() = EventsManager::new();
    *TOKENS_STATE.lock().unwrap() = std::collections::HashMap::new();

    fetch_slots_state()
}

api_function!(
    C_Finalize = finalize;
    pReserved: CK_VOID_PTR,
);

fn finalize(reserved_ptr: CK_VOID_PTR) -> Result<(), Pkcs11Error> {
    if !reserved_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }
    DEVICE.store(None);
    stop_background_timer();
    EVENTS_MANAGER.write().unwrap().finalized = true;
    Ok(())
}

api_function!(
    C_GetInfo = get_info;
    pInfo: CK_INFO_PTR,
);

struct OutputPointer<T>(*mut T);

impl<T> OutputPointer<T> {
    unsafe fn new(ptr: *mut T) -> Result<Self, Pkcs11Error> {
        if ptr.is_null() {
            Err(Pkcs11Error::ArgumentsBad)
        } else {
            Ok(Self(ptr))
        }
    }

    fn write(&mut self, value: T) {
        unsafe {
            std::ptr::write(self.0, value);
        }
    }
}

fn get_info(info_ptr: CK_INFO_PTR) -> Result<(), Pkcs11Error> {
    let mut info_ptr = unsafe { OutputPointer::new(info_ptr)? };
    let infos = CK_INFO {
        cryptokiVersion: defs::CRYPTOKI_VERSION,
        manufacturerID: padded_str(defs::LIB_MANUFACTURER),
        flags: 0,
        libraryDescription: padded_str(defs::LIB_DESCRIPTION),
        libraryVersion: defs::LIB_VERSION,
    };
    info_ptr.write(infos);
    Ok(())
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
