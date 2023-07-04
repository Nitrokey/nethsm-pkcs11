use log::trace;

pub extern "C" fn C_GenerateKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateKey() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GenerateKeyPair(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    pPublicKeyTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: cryptoki_sys::CK_ULONG,
    pPrivateKeyTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: cryptoki_sys::CK_ULONG,
    phPublicKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
    phPrivateKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateKeyPair() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_WrapKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hWrappingKey: cryptoki_sys::CK_OBJECT_HANDLE,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pWrappedKey: cryptoki_sys::CK_BYTE_PTR,
    pulWrappedKeyLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_WrapKey() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_UnwrapKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hUnwrappingKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pWrappedKey: cryptoki_sys::CK_BYTE_PTR,
    ulWrappedKeyLen: cryptoki_sys::CK_ULONG,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulAttributeCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_UnwrapKey() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DeriveKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: cryptoki_sys::CK_MECHANISM_PTR,
    hBaseKey: cryptoki_sys::CK_OBJECT_HANDLE,
    pTemplate: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ulAttributeCount: cryptoki_sys::CK_ULONG,
    phKey: cryptoki_sys::CK_OBJECT_HANDLE_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DeriveKey() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_SeedRandom(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pSeed: cryptoki_sys::CK_BYTE_PTR,
    ulSeedLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_SeedRandom() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GenerateRandom(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    RandomData: cryptoki_sys::CK_BYTE_PTR,
    ulRandomLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_GenerateRandom() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}
