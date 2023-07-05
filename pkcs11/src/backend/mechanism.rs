use std::string;

use cryptoki_sys::{CKM_MD5, CKM_RSA_PKCS_OAEP, CKM_SHA_1};
use openapi::models::{DecryptMode, SignMode};

// from https://github.com/aws/aws-nitro-enclaves-acm/blob/main/src/vtok_p11/src/backend/mech.rs
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub enum CkRawError {
    BufTooSmall,
    MechParamTypeMismatch,
    NullPtrDeref,
}

pub struct CkRawMechanism {
    ptr: *mut cryptoki_sys::CK_MECHANISM,
}
pub trait MechParams {}
impl MechParams for cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS {}

impl CkRawMechanism {
    pub unsafe fn from_raw_ptr_unchecked(ptr: *mut cryptoki_sys::CK_MECHANISM) -> Self {
        Self { ptr }
    }

    pub fn type_(&self) -> cryptoki_sys::CK_MECHANISM_TYPE {
        unsafe { (*self.ptr).mechanism }
    }

    // Note: marking this unsafe, even if it breaks our pattern of using object constructors
    // to cover unsafe FFI code.
    // Reading the wrong data type is bad, mkay?
    pub unsafe fn params<T: MechParams>(&self) -> Result<Option<T>, CkRawError> {
        let param_ptr = (*self.ptr).pParameter;
        let param_len = (*self.ptr).ulParameterLen;
        if param_ptr.is_null() || param_len == 0 {
            return Ok(None);
        }
        if std::mem::size_of::<T>() != param_len as usize {
            return Err(CkRawError::MechParamTypeMismatch);
        }
        Ok(Some(std::ptr::read(param_ptr as *const T)))
    }
}

pub enum Error {
    CkRaw(CkRawError),
    DigestMechMismatch,
    UnknownMech,
}

#[derive(Clone, Copy, Debug)]
pub enum MechDigest {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug)]
pub enum Mechanism {
    Digest(MechDigest),
    RsaPkcs,
    RsaPkcsOaep(Option<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>),
    RsaPkcsPss(Option<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>),
    RsaX509,
    EdDsa,
    Ecdsa(Option<MechDigest>),
}

/// The token supported mechanisms and their capabilities.
/// See PKCS#11 Mechanisms Specification Version 2.40 for details on how these
/// mechanisms should behave.
///
/// Mechanisms are split into single-part (i.e. sign()) and/or multi-part
/// operations (i.e. sign_update() + sign_final()) depending on type and capabilities.
impl Mechanism {
    const RSA_MIN_KEY_BITS: cryptoki_sys::CK_ULONG = 1024;
    const RSA_MAX_KEY_BITS: cryptoki_sys::CK_ULONG = 8192;
    const EC_MIN_KEY_BITS: cryptoki_sys::CK_ULONG = 224;
    const EC_MAX_KEY_BITS: cryptoki_sys::CK_ULONG = 521;

    pub fn from_ckraw_mech(raw_mech: &CkRawMechanism) -> Result<Self, Error> {
        let mech = match raw_mech.type_() {
            cryptoki_sys::CKM_SHA_1 => Self::Digest(MechDigest::Sha1),
            cryptoki_sys::CKM_SHA224 => Self::Digest(MechDigest::Sha224),
            cryptoki_sys::CKM_SHA256 => Self::Digest(MechDigest::Sha256),
            cryptoki_sys::CKM_SHA384 => Self::Digest(MechDigest::Sha384),
            cryptoki_sys::CKM_SHA512 => Self::Digest(MechDigest::Sha512),
            cryptoki_sys::CKM_RSA_PKCS => Self::RsaPkcs,
            cryptoki_sys::CKM_RSA_PKCS_PSS => Self::RsaPkcsPss(
                // Safe because Self::RsaPkcsPss defines the correct params struct type
                // (i.e. CK_RSA_PKCS_PSS_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),
            cryptoki_sys::CKM_RSA_PKCS_OAEP => Self::RsaPkcsOaep(
                // Safe because Self::RsaPkcsOaep defines the correct params struct type
                // (i.e. CK_RSA_PKCS_OAEP_PARAMS).
                unsafe { raw_mech.params() }.map_err(Error::CkRaw)?,
            ),

            cryptoki_sys::CKM_RSA_X_509 => Self::RsaX509,
            cryptoki_sys::CKM_ECDSA => Self::Ecdsa(None),
            cryptoki_sys::CKM_ECDSA_SHA1 => Self::Ecdsa(Some(MechDigest::Sha1)),
            cryptoki_sys::CKM_ECDSA_SHA224 => Self::Ecdsa(Some(MechDigest::Sha224)),
            cryptoki_sys::CKM_ECDSA_SHA256 => Self::Ecdsa(Some(MechDigest::Sha256)),
            cryptoki_sys::CKM_ECDSA_SHA384 => Self::Ecdsa(Some(MechDigest::Sha384)),
            cryptoki_sys::CKM_ECDSA_SHA512 => Self::Ecdsa(Some(MechDigest::Sha512)),
            cryptoki_sys::CKM_EDDSA => Self::EdDsa,
            _ => return Err(Error::UnknownMech),
        };

        Ok(mech)
    }

    pub fn ck_type(&self) -> cryptoki_sys::CK_MECHANISM_TYPE {
        match self {
            Self::Digest(digest) => match digest {
                MechDigest::Sha1 => cryptoki_sys::CKM_SHA_1,
                MechDigest::Sha224 => cryptoki_sys::CKM_SHA224,
                MechDigest::Sha256 => cryptoki_sys::CKM_SHA256,
                MechDigest::Sha384 => cryptoki_sys::CKM_SHA384,
                MechDigest::Sha512 => cryptoki_sys::CKM_SHA512,
            },
            Self::RsaPkcs => cryptoki_sys::CKM_RSA_PKCS,

            Self::RsaPkcsPss(_) => cryptoki_sys::CKM_RSA_PKCS_PSS,
            Self::RsaPkcsOaep(_) => CKM_RSA_PKCS_OAEP,

            Self::RsaX509 => cryptoki_sys::CKM_RSA_X_509,
            Self::Ecdsa(digest) => match digest {
                None => cryptoki_sys::CKM_ECDSA,
                Some(MechDigest::Sha1) => cryptoki_sys::CKM_ECDSA_SHA1,
                Some(MechDigest::Sha224) => cryptoki_sys::CKM_ECDSA_SHA224,
                Some(MechDigest::Sha256) => cryptoki_sys::CKM_ECDSA_SHA256,
                Some(MechDigest::Sha384) => cryptoki_sys::CKM_ECDSA_SHA384,
                Some(MechDigest::Sha512) => cryptoki_sys::CKM_ECDSA_SHA512,
            },
            Self::EdDsa => cryptoki_sys::CKM_EDDSA,
        }
    }

    pub fn ck_info(&self) -> cryptoki_sys::CK_MECHANISM_INFO {
        let (min_bits, max_bits) = match self {
            Self::Digest(_) => (0, 0),
            Self::RsaPkcs | Self::RsaPkcsPss(_) | Self::RsaX509 => {
                (Self::RSA_MIN_KEY_BITS, Self::RSA_MAX_KEY_BITS)
            }
            Self::Ecdsa(_) => (Self::EC_MIN_KEY_BITS, Self::EC_MAX_KEY_BITS),
            Self::RsaPkcsOaep(_) => (Self::RSA_MIN_KEY_BITS, Self::RSA_MAX_KEY_BITS),
            Self::EdDsa => (0, 0),
        };
        cryptoki_sys::CK_MECHANISM_INFO {
            ulMinKeySize: min_bits,
            ulMaxKeySize: max_bits,
            flags: self.ck_flags(),
        }
    }

    pub fn ck_flags(&self) -> cryptoki_sys::CK_FLAGS {
        // NOTE: Though we have a soft-token, we stamp the cryptoki_sys::CKF_HW flag since most unit
        // tests out there seem to check for it
        cryptoki_sys::CKF_HW
            | match self {
                Self::Digest(_) => cryptoki_sys::CKF_DIGEST,
                // Single-part CKM_RSA_PKCS also has encrypt/decrypt
                Self::RsaPkcs => cryptoki_sys::CKF_SIGN | cryptoki_sys::CKF_DECRYPT,
                // Multi-part CKM_RSA_PKCS has sign/verify only
                Self::RsaPkcsPss(_) => cryptoki_sys::CKF_SIGN | cryptoki_sys::CKF_VERIFY,

                // "RAW" RSA has decrypt only
                Self::RsaX509 => cryptoki_sys::CKF_DECRYPT,
                Self::Ecdsa(_) => {
                    cryptoki_sys::CKF_SIGN
                        | cryptoki_sys::CKF_VERIFY
                        | cryptoki_sys::CKF_EC_F_P
                        | cryptoki_sys::CKF_EC_NAMEDCURVE
                        | cryptoki_sys::CKF_EC_UNCOMPRESS
                }
                Self::RsaPkcsOaep(_) => cryptoki_sys::CKF_SIGN | cryptoki_sys::CKF_DECRYPT,
                Self::EdDsa => cryptoki_sys::CKF_SIGN,
            }
    }

    pub fn is_multipart(&self) -> bool {
        match self {
            Self::RsaPkcsOaep(_) => true,
            Self::RsaPkcsPss(_) => true,
            Self::Ecdsa(ref digest) => digest.is_some(),
            _ => false,
        }
    }

    /// returns the name to use in the api, None if not supported
    pub fn sign_name(&self) -> Option<SignMode> {
        match self {
            Self::RsaPkcs => Some(SignMode::EdDsa),
            Self::RsaPkcsPss(Some(params)) => match params.hashAlg {
                CKM_MD5 => Some(SignMode::PssMd5),
                CKM_SHA_1 => Some(SignMode::PssSha1),
                CKM_SHA_224 => Some(SignMode::PssSha256),
                CKM_SHA_256 => Some(SignMode::PssSha256),
                CKM_SHA_384 => Some(SignMode::PssSha384),
                CKM_SHA_512 => Some(SignMode::PssSha512),
                _ => None,
            },
            Self::Ecdsa(_) => Some(SignMode::Ecdsa),
            Self::EdDsa => Some(SignMode::EdDsa),
            _ => None,
        }
    }

    /// Returns the name to use in the api, None if not supported
    pub fn decrypt_name(&self) -> Option<DecryptMode> {
        match self {
            Self::RsaX509 => Some(DecryptMode::Raw),
            Self::RsaPkcs => Some(DecryptMode::Pkcs1),
            Self::RsaPkcsOaep(Some(param)) => match param.hashAlg {
                CKM_MD5 => Some(DecryptMode::OaepMd5),
                CKM_SHA_1 => Some(DecryptMode::OaepSha1),
                CKM_SHA_224 => Some(DecryptMode::OaepSha224),
                CKM_SHA_256 => Some(DecryptMode::OaepSha256),
                CKM_SHA_384 => Some(DecryptMode::OaepSha384),
                CKM_SHA_512 => Some(DecryptMode::OaepSha512),

                _ => None,
            },

            _ => None,
        }
    }
}
