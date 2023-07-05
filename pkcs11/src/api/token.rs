use cryptoki_sys::{CK_SLOT_ID, CK_SLOT_INFO, CK_ULONG};
use log::{error, trace};
use openapi::models::SystemState;

use crate::{data::CLIENTS, padded_str, version_struct_from_str};

pub extern "C" fn C_GetSlotList(
    tokenPresent: cryptoki_sys::CK_BBOOL,
    pSlotList: cryptoki_sys::CK_SLOT_ID_PTR,
    pulCount: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetSlotList() called");

    if pulCount.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let clients = match CLIENTS.read() {
        Ok(clients) => clients,
        Err(e) => {
            error!("Error reading clients: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    let count = clients.len() as u64;

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

    let id_list: Vec<CK_SLOT_ID> = clients
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

    // get the client

    let client = match CLIENTS.read() {
        Ok(clients) => match clients.get(slotID as usize) {
            Some(client) => client.clone(),
            None => {
                error!("No client found for slotID: {}", slotID);
                return cryptoki_sys::CKR_SLOT_ID_INVALID;
            }
        },
        Err(e) => {
            error!("Error reading clients: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    if pInfo.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    let mut flags = 0;

    // fetch info from the device

    let info = match openapi::apis::default_api::info_get(&client) {
        Ok(info) => info,
        Err(e) => {
            error!("Error getting info: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    // fetch system info from the device

    let system_info = match openapi::apis::default_api::system_info_get(&client) {
        Ok(info) => info,
        Err(e) => {
            error!("Error getting system info: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    // fetch the sysem state

    let system_state = match openapi::apis::default_api::health_state_get(&client) {
        Ok(info) => info,
        Err(e) => {
            error!("Error getting system state: {:?}", e);
            return cryptoki_sys::CKR_FUNCTION_FAILED;
        }
    };

    if system_state.state == SystemState::Operational {
        flags |= cryptoki_sys::CKF_TOKEN_PRESENT;
    }

    let info: CK_SLOT_INFO = CK_SLOT_INFO {
        slotDescription: padded_str!(info.product, 64),
        manufacturerID: padded_str!(info.vendor, 32),
        flags,
        hardwareVersion: version_struct_from_str!(system_info.hardware_version),
        firmwareVersion: version_struct_from_str!(system_info.firmware_version),
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
    trace!("C_GetTokenInfo() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
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

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GetMechanismInfo(
    slotID: cryptoki_sys::CK_SLOT_ID,
    type_: cryptoki_sys::CK_MECHANISM_TYPE,
    pInfo: cryptoki_sys::CK_MECHANISM_INFO_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GetMechanismInfo() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_Login(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    userType: cryptoki_sys::CK_USER_TYPE,
    pPin: cryptoki_sys::CK_UTF8CHAR_PTR,
    ulPinLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Login() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
pub extern "C" fn C_Logout(hSession: cryptoki_sys::CK_SESSION_HANDLE) -> cryptoki_sys::CK_RV {
    trace!("C_Logout() called");

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_WaitForSlotEvent(
    flags: cryptoki_sys::CK_FLAGS,
    pSlot: cryptoki_sys::CK_SLOT_ID_PTR,
    pReserved: cryptoki_sys::CK_VOID_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_WaitForSlotEvent() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
