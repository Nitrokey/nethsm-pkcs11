/*
    We won't implement these function as it is not a feature of NetHSM.
*/

use crate::{api::api_function, backend::Pkcs11Error};

api_function!(
    C_DigestInit = digest_init;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: *mut cryptoki_sys::CK_MECHANISM,
);

fn digest_init(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: *mut cryptoki_sys::CK_MECHANISM,
) -> Result<(), Pkcs11Error> {
    if pMechanism.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_Digest = digest;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: *mut cryptoki_sys::CK_BYTE,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
);

fn digest(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: *mut cryptoki_sys::CK_BYTE,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    if pData.is_null() || pDigest.is_null() || pulDigestLen.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_DigestUpdate = digest_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: *mut cryptoki_sys::CK_BYTE,
    ulPartLen: cryptoki_sys::CK_ULONG,
);

fn digest_update(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: *mut cryptoki_sys::CK_BYTE,
    ulPartLen: cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    if pPart.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_DigestFinal = digest_final;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
);

fn digest_final(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
) -> Result<(), Pkcs11Error> {
    if pDigest.is_null() || pulDigestLen.is_null() {
        return Err(Pkcs11Error::ArgumentsBad);
    }

    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_DigestKey = digest_key;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
);

fn digest_key(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_DigestEncryptUpdate = digest_encrypt_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn digest_encrypt_update(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

api_function!(
    C_DecryptDigestUpdate = decrypt_digest_update;
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
);

fn decrypt_digest_update(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> Result<(), Pkcs11Error> {
    Err(Pkcs11Error::FunctionNotSupported)
}

#[cfg(test)]
mod tests {
    use cryptoki_sys::CK_ULONG;

    use crate::backend::slot::init_for_tests;

    use super::*;
    #[test]
    fn test_digest_init() {
        init_for_tests();
        let rv = C_DigestInit(0, std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);

        let mut mech = cryptoki_sys::CK_MECHANISM {
            mechanism: 0,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_DigestInit(0, &mut mech);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest() {
        init_for_tests();
        let rv = C_Digest(
            0,
            std::ptr::null_mut(),
            0 as CK_ULONG,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);

        let mut digest_len: CK_ULONG = 0;
        let mut digest: Vec<u8> = Vec::new();
        let mut data: Vec<u8> = Vec::new();

        let rv = C_Digest(
            0,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            digest.as_mut_ptr(),
            &mut digest_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest_update() {
        init_for_tests();
        let rv = C_DigestUpdate(0, std::ptr::null_mut(), 0 as CK_ULONG);
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);

        let mut data: Vec<u8> = Vec::new();

        let rv = C_DigestUpdate(0, data.as_mut_ptr(), data.len() as CK_ULONG);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest_final() {
        init_for_tests();
        let rv = C_DigestFinal(0, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(rv, cryptoki_sys::CKR_ARGUMENTS_BAD);

        let mut digest_len: CK_ULONG = 0;
        let mut digest: Vec<u8> = Vec::new();

        let rv = C_DigestFinal(0, digest.as_mut_ptr(), &mut digest_len);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest_key() {
        init_for_tests();
        let rv = C_DigestKey(0, 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest_encrypt_update() {
        init_for_tests();
        let mut encrypted_part_len: CK_ULONG = 0;
        let mut encrypted_part: Vec<u8> = Vec::new();
        let mut part: Vec<u8> = Vec::new();

        let rv = C_DigestEncryptUpdate(
            0,
            part.as_mut_ptr(),
            part.len() as CK_ULONG,
            encrypted_part.as_mut_ptr(),
            &mut encrypted_part_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_decrypt_digest_update() {
        init_for_tests();
        let mut encrypted_part_len: CK_ULONG = 0;
        let mut encrypted_part: Vec<u8> = Vec::new();
        let mut part: Vec<u8> = Vec::new();

        let rv = C_DecryptDigestUpdate(
            0,
            encrypted_part.as_mut_ptr(),
            encrypted_part.len() as CK_ULONG,
            part.as_mut_ptr(),
            &mut encrypted_part_len,
        );
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }
}
