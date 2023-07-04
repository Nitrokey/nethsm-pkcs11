mod api;

mod utils;  

mod defs {
    use cryptoki_sys::CRYPTOKI_VERSION_MAJOR;

    pub const CRYPTOKI_VERSION: cryptoki_sys::CK_VERSION = cryptoki_sys::CK_VERSION {
        major: CRYPTOKI_VERSION_MAJOR,
        minor: cryptoki_sys::CRYPTOKI_VERSION_MINOR,
    };
    pub const LIB_VERSION: cryptoki_sys::CK_VERSION = cryptoki_sys::CK_VERSION {
        major: 0,
        minor: 1,
    };
}

mod data {
    use cryptoki_sys::{CK_FUNCTION_LIST, CK_VERSION};

    use crate::api;
    pub const DEVICE_VERSION: CK_VERSION = CK_VERSION {
        major: 2,
        minor: 40,
    };

    pub static mut FN_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
        version: DEVICE_VERSION,
        C_Initialize: Some(api::C_Initialize),
        C_Finalize: Some(api::C_Finalize),
        C_GetInfo:  Some(api::C_GetInfo),
        C_GetFunctionList: Some(api::C_GetFunctionList),
        C_GetSlotList: Some(api::token::C_GetSlotList),
        C_GetSlotInfo: None,
        C_GetTokenInfo: None,
        C_GetMechanismList: None,
        C_GetMechanismInfo: None,
        C_InitToken: None,
        C_InitPIN: None,
        C_SetPIN: None,
        C_OpenSession: None,
        C_CloseSession: None,
        C_CloseAllSessions: None,
        C_GetSessionInfo: None,
        C_GetOperationState: None,
        C_SetOperationState: None,
        C_Login: None,
        C_Logout: None,
        C_CreateObject: None,
        C_CopyObject: None,
        C_DestroyObject: None,
        C_GetObjectSize: None,
        C_GetAttributeValue: None,
        C_SetAttributeValue: None,
        C_FindObjectsInit: None,
        C_FindObjects: None,
        C_FindObjectsFinal: None,
        C_EncryptInit: None,
        C_Encrypt: None,
        C_EncryptUpdate: None,
        C_EncryptFinal: None,
        C_DecryptInit: None,
        C_Decrypt: None,
        C_DecryptUpdate: None,
        C_DecryptFinal: None,
        C_DigestInit: None,
        C_Digest: None,
        C_DigestUpdate: None,
        C_DigestKey: None,
        C_DigestFinal: None,
        C_SignInit: None,
        C_Sign: None,
        C_SignUpdate: None,
        C_SignFinal: None,
        C_SignRecoverInit: None,
        C_SignRecover: None,
        C_VerifyInit: None,
        C_Verify: None,
        C_VerifyUpdate: None,
        C_VerifyFinal: None,
        C_VerifyRecoverInit: None,
        C_VerifyRecover: None,
        C_DigestEncryptUpdate: None,
        C_DecryptDigestUpdate: None,
        C_SignEncryptUpdate: None,
        C_DecryptVerifyUpdate: None,
        C_GenerateKey: None,
        C_GenerateKeyPair: None,
        C_WrapKey: None,
        C_UnwrapKey: None,
        C_DeriveKey: None,
        C_SeedRandom: None,
        C_GenerateRandom: None,
        C_GetFunctionStatus: None,
        C_CancelFunction: None,
        C_WaitForSlotEvent: None,
    };
}
