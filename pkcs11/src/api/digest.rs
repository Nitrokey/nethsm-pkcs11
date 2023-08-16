/*
    We won't implement these function as it is not a feature of NetHSM.
*/

use log::trace;

pub extern "C" fn C_DigestInit(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pMechanism: *mut cryptoki_sys::CK_MECHANISM,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestInit() called");

    if pMechanism.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_Digest(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pData: *mut cryptoki_sys::CK_BYTE,
    ulDataLen: cryptoki_sys::CK_ULONG,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_Digest() called");

    if pData.is_null() || pDigest.is_null() || pulDigestLen.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: *mut cryptoki_sys::CK_BYTE,
    ulPartLen: cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestUpdate() called");

    if pPart.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestFinal(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pDigest: *mut cryptoki_sys::CK_BYTE,
    pulDigestLen: *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestFinal() called");

    if pDigest.is_null() || pulDigestLen.is_null() {
        return cryptoki_sys::CKR_ARGUMENTS_BAD;
    }

    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestKey(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    hKey: cryptoki_sys::CK_OBJECT_HANDLE,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestKey() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DigestEncryptUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    ulPartLen: cryptoki_sys::CK_ULONG,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    pulEncryptedPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DigestEncryptUpdate() called");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_DecryptDigestUpdate(
    hSession: cryptoki_sys::CK_SESSION_HANDLE,
    pEncryptedPart: cryptoki_sys::CK_BYTE_PTR,
    ulEncryptedPartLen: cryptoki_sys::CK_ULONG,
    pPart: cryptoki_sys::CK_BYTE_PTR,
    pulPartLen: cryptoki_sys::CK_ULONG_PTR,
) -> cryptoki_sys::CK_RV {
    trace!("C_DecryptDigestUpdate() called ");
    cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED
}

#[cfg(test)]
mod tests {
    use cryptoki_sys::CK_ULONG;

    use super::*;
    #[test]
    fn test_digest_init() {
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
        let mut data: Vec<u8> = Vec::new();

        let rv = C_DigestUpdate(0, data.as_mut_ptr(), data.len() as CK_ULONG);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest_final() {
        let mut digest_len: CK_ULONG = 0;
        let mut digest: Vec<u8> = Vec::new();

        let rv = C_DigestFinal(0, digest.as_mut_ptr(), &mut digest_len);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest_key() {
        let rv = C_DigestKey(0, 0);
        assert_eq!(rv, cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn test_digest_encrypt_update() {
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
