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

fn get_info(info_ptr: CK_INFO_PTR) -> Result<(), Pkcs11Error> {
    if info_ptr.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    let infos = CK_INFO {
        cryptokiVersion: defs::CRYPTOKI_VERSION,
        manufacturerID: padded_str(defs::LIB_MANUFACTURER),
        flags: 0,
        libraryDescription: padded_str(defs::LIB_DESCRIPTION),
        libraryVersion: defs::LIB_VERSION,
    };

    unsafe {
        std::ptr::write(info_ptr, infos);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{backend::slot::init_lock, config::device::RETRY_THREAD};

    use super::*;

    fn assert_initialized(threads_allowed: bool) {
        assert!(DEVICE.load_full().is_some());
        assert_eq!(THREADS_ALLOWED.load(Ordering::Relaxed), threads_allowed);
        assert_eq!(RETRY_THREAD.read().unwrap().is_some(), threads_allowed);
        assert!(!EVENTS_MANAGER.read().unwrap().finalized);
    }

    fn assert_uninitialized() {
        assert!(DEVICE.load_full().is_none());
        assert!(RETRY_THREAD.read().unwrap().is_none());
        assert!(EVENTS_MANAGER.read().unwrap().finalized);
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_finalize() {
        let _guard = init_lock();

        let rv = C_Initialize(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert_initialized(true);

        let rv = C_Finalize(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        assert_uninitialized();
    }

    fn init_with_args<F: FnOnce(cryptoki_sys::CK_RV)>(
        mut args: cryptoki_sys::CK_C_INITIALIZE_ARGS,
        callback: F,
    ) {
        let _guard = init_lock();
        let args_ptr: cryptoki_sys::CK_C_INITIALIZE_ARGS_PTR = &mut args;
        let rv = C_Initialize(args_ptr as _);
        callback(rv);
        if rv == cryptoki_sys::CKR_OK {
            let rv = C_Finalize(std::ptr::null_mut());
            assert_eq!(rv, cryptoki_sys::CKR_OK);
        }
    }

    unsafe extern "C" fn mutex_callback<T>(_arg1: T) -> cryptoki_sys::CK_RV {
        cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_args_reserved() {
        let args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: 0,
            pReserved: "test".as_ptr() as _,
        };
        init_with_args(args, |rv| {
            assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
        });
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_args_no_threads() {
        let args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: cryptoki_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS,
            pReserved: std::ptr::null_mut(),
        };
        init_with_args(args, |rv| {
            assert_eq!(rv, cryptoki_sys::CKR_OK);
            assert_initialized(false);
        });
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_args_bad_callbacks() {
        let args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: Some(mutex_callback),
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: 0,
            pReserved: std::ptr::null_mut(),
        };
        init_with_args(args, |rv| {
            assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
        });
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_args_case_1() {
        let args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: 0,
            pReserved: std::ptr::null_mut(),
        };
        init_with_args(args, |rv| {
            assert_eq!(rv, cryptoki_sys::CKR_OK);
            assert_initialized(true);
        });
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_args_case_2() {
        let args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: cryptoki_sys::CKF_OS_LOCKING_OK,
            pReserved: std::ptr::null_mut(),
        };
        init_with_args(args, |rv| {
            assert_eq!(rv, cryptoki_sys::CKR_OK);
            assert_initialized(true);
        });
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_args_case_3() {
        let args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: Some(mutex_callback),
            DestroyMutex: Some(mutex_callback),
            LockMutex: Some(mutex_callback),
            UnlockMutex: Some(mutex_callback),
            flags: 0,
            pReserved: std::ptr::null_mut(),
        };
        init_with_args(args, |rv| {
            assert_eq!(rv, cryptoki_sys::CKR_CANT_LOCK);
        });
    }

    #[test]
    #[ignore]
    // https://github.com/Nitrokey/nethsm-pkcs11/issues/325
    fn test_init_args_case_4() {
        let args = cryptoki_sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: Some(mutex_callback),
            DestroyMutex: Some(mutex_callback),
            LockMutex: Some(mutex_callback),
            UnlockMutex: Some(mutex_callback),
            flags: cryptoki_sys::CKF_OS_LOCKING_OK,
            pReserved: std::ptr::null_mut(),
        };
        init_with_args(args, |rv| {
            assert_eq!(rv, cryptoki_sys::CKR_OK);
            assert_initialized(true);
        });
    }

    #[test]
    fn test_init_twice() {
        let _guard = init_lock();

        let rv = C_Initialize(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        let rv = C_Initialize(std::ptr::null_mut());
        // TODO: https://github.com/Nitrokey/nethsm-pkcs11/issues/324
        // assert_eq!(rv, cryptoki_sys::CKR_CRYPTOKI_ALREADY_INITIALIZED);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        let rv = C_Finalize(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_finalize() {
        let _guard = init_lock();

        let rv = C_Finalize(std::ptr::null_mut());
        // TODO: https://github.com/Nitrokey/nethsm-pkcs11/issues/324
        // assert_eq!(rv, cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

    #[test]
    fn test_finalize_args() {
        let _guard = init_lock();

        let mut args = 0;
        let args_ptr: *mut u8 = &mut args;
        let rv = C_Finalize(args_ptr as _);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_finalize_twice() {
        let _guard = init_lock();

        let rv = C_Initialize(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        let rv = C_Finalize(std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_OK);
        let rv = C_Finalize(std::ptr::null_mut());
        // TODO: https://github.com/Nitrokey/nethsm-pkcs11/issues/324
        // assert_eq!(rv, cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED);
        assert_eq!(rv, cryptoki_sys::CKR_OK);
    }

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
