#![allow(non_snake_case)]

use cryptoki_sys::{CK_RV, CK_VOID_PTR, CK_INFO, CK_INFO_PTR};
use log::{trace, debug};

pub mod token;
use crate::{data, defs, padded_str};

#[no_mangle]
pub extern "C" fn C_GetFunctionList(
    pp_fn_list: *mut *mut cryptoki_sys::CK_FUNCTION_LIST,
) -> cryptoki_sys::CK_RV {
    if pp_fn_list.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    unsafe {
        std::ptr::write(pp_fn_list, &mut data::FN_LIST);
    }
    cryptoki_sys::CKR_OK
}

pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    env_logger::init();

    trace!("C_Initialize() called");

    trace!("C_Initialize() called with args: {:?}", pInitArgs);
    if defs::CRYPTOKI_VERSION.major == 2
        && defs::CRYPTOKI_VERSION.minor == 40
        && !pInitArgs.is_null()
    {
        let args = pInitArgs as cryptoki_sys::CK_C_INITIALIZE_ARGS_PTR;
        trace!("C_Initialize() called with args: {:?}", args);
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
    

    let infos = CK_INFO{
        cryptokiVersion: defs::CRYPTOKI_VERSION,
        manufacturerID: padded_str!("Rust PKCS#11", 32),
        flags: 0,
        libraryDescription:  padded_str!("Rust PKCS#11", 32),
        libraryVersion: defs::LIB_VERSION,
    };
    

    unsafe {
        std::ptr::write(pInfo, infos);
    }
    cryptoki_sys::CKR_OK
}