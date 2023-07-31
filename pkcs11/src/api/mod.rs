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
    data::{self, DEVICE},
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
        unsafe {
            if !(*args).pReserved.is_null() {
                return cryptoki_sys::CKR_ARGUMENTS_BAD;
            }
        }
    }

    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    trace!("C_Finalize() called");
    if !pReserved.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }
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
