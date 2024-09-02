use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Mutex, RwLock};

use crate::backend::events::EventsManager;

use crate::{api, backend::session::SessionManager, config::device::Device};
use arc_swap::ArcSwapOption;
use cryptoki_sys::{CK_FUNCTION_LIST, CK_SLOT_ID, CK_VERSION};
use lazy_static::lazy_static;

pub const DEVICE_VERSION: CK_VERSION = CK_VERSION {
    major: 2,
    minor: 40,
};

pub static DEVICE: ArcSwapOption<Device> = ArcSwapOption::const_empty();

lazy_static! {
    pub static ref SESSION_MANAGER : Mutex<SessionManager> =  Mutex::new(SessionManager::new());

    // Aliases for the keys, used when enable_set_attribute_value is set.
    // As we are using lazy_static, this field will be initialized the first time it's used.
    // The key of the map is the name the application tries to use, the value is the name given by the NetHSM.
    pub static ref KEY_ALIASES : Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    // Token present or not (true = present)
    pub static ref TOKENS_STATE : Mutex<HashMap<CK_SLOT_ID, bool>> = Mutex::new(HashMap::new());
}

// Storage of events
pub static EVENTS_MANAGER: RwLock<EventsManager> = RwLock::new(EventsManager::new());

// If the calling application allows threads to be used
pub static THREADS_ALLOWED: AtomicBool = AtomicBool::new(true);

pub static mut FN_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: DEVICE_VERSION,
    C_Initialize: Some(api::C_Initialize),
    C_Finalize: Some(api::C_Finalize),
    C_GetInfo: Some(api::C_GetInfo),
    C_GetFunctionList: Some(api::C_GetFunctionList),
    C_GetSlotList: Some(api::token::C_GetSlotList),
    C_GetSlotInfo: Some(api::token::C_GetSlotInfo),
    C_GetTokenInfo: Some(api::token::C_GetTokenInfo),
    C_GetMechanismList: Some(api::token::C_GetMechanismList),
    C_GetMechanismInfo: Some(api::token::C_GetMechanismInfo),
    C_InitToken: Some(api::token::C_InitToken),
    C_InitPIN: Some(api::pin::C_InitPIN),
    C_SetPIN: Some(api::pin::C_SetPIN),
    C_OpenSession: Some(api::session::C_OpenSession),
    C_CloseSession: Some(api::session::C_CloseSession),
    C_CloseAllSessions: Some(api::session::C_CloseAllSessions),
    C_GetSessionInfo: Some(api::session::C_GetSessionInfo),
    C_GetOperationState: Some(api::session::C_GetOperationState),
    C_SetOperationState: Some(api::session::C_SetOperationState),
    C_Login: Some(api::token::C_Login),
    C_Logout: Some(api::token::C_Logout),
    C_CreateObject: Some(api::object::C_CreateObject),
    C_CopyObject: Some(api::object::C_CopyObject),
    C_DestroyObject: Some(api::object::C_DestroyObject),
    C_GetObjectSize: Some(api::object::C_GetObjectSize),
    C_GetAttributeValue: Some(api::object::C_GetAttributeValue),
    C_SetAttributeValue: Some(api::object::C_SetAttributeValue),
    C_FindObjectsInit: Some(api::object::C_FindObjectsInit),
    C_FindObjects: Some(api::object::C_FindObjects),
    C_FindObjectsFinal: Some(api::object::C_FindObjectsFinal),
    C_EncryptInit: Some(api::encrypt::C_EncryptInit),
    C_Encrypt: Some(api::encrypt::C_Encrypt),
    C_EncryptUpdate: Some(api::encrypt::C_EncryptUpdate),
    C_EncryptFinal: Some(api::encrypt::C_EncryptFinal),
    C_DecryptInit: Some(api::decrypt::C_DecryptInit),
    C_Decrypt: Some(api::decrypt::C_Decrypt),
    C_DecryptUpdate: Some(api::decrypt::C_DecryptUpdate),
    C_DecryptFinal: Some(api::decrypt::C_DecryptFinal),
    C_DigestInit: Some(api::digest::C_DigestInit),
    C_Digest: Some(api::digest::C_Digest),
    C_DigestUpdate: Some(api::digest::C_DigestUpdate),
    C_DigestKey: Some(api::digest::C_DigestKey),
    C_DigestFinal: Some(api::digest::C_DigestFinal),
    C_SignInit: Some(api::sign::C_SignInit),
    C_Sign: Some(api::sign::C_Sign),
    C_SignUpdate: Some(api::sign::C_SignUpdate),
    C_SignFinal: Some(api::sign::C_SignFinal),
    C_SignRecoverInit: Some(api::sign::C_SignRecoverInit),
    C_SignRecover: Some(api::sign::C_SignRecover),
    C_VerifyInit: Some(api::verify::C_VerifyInit),
    C_Verify: Some(api::verify::C_Verify),
    C_VerifyUpdate: Some(api::verify::C_VerifyUpdate),
    C_VerifyFinal: Some(api::verify::C_VerifyFinal),
    C_VerifyRecoverInit: Some(api::verify::C_VerifyRecoverInit),
    C_VerifyRecover: Some(api::verify::C_VerifyRecover),
    C_DigestEncryptUpdate: Some(api::digest::C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(api::digest::C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(api::sign::C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(api::decrypt::C_DecryptVerifyUpdate),
    C_GenerateKey: Some(api::generation::C_GenerateKey),
    C_GenerateKeyPair: Some(api::generation::C_GenerateKeyPair),
    C_WrapKey: Some(api::generation::C_WrapKey),
    C_UnwrapKey: Some(api::generation::C_UnwrapKey),
    C_DeriveKey: Some(api::generation::C_DeriveKey),
    C_SeedRandom: Some(api::generation::C_SeedRandom),
    C_GenerateRandom: Some(api::generation::C_GenerateRandom),
    C_GetFunctionStatus: Some(api::session::C_GetFunctionStatus),
    C_CancelFunction: Some(api::session::C_CancelFunction),
    C_WaitForSlotEvent: Some(api::token::C_WaitForSlotEvent),
};
