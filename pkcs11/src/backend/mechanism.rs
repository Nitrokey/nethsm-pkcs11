// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Nitrokey
// SPDX-License-Identifier: Apache-2.0

use cryptoki_sys::{CKM_RSA_PKCS_OAEP, CK_MECHANISM_TYPE, CK_ULONG};
use log::trace;
use nethsm_sdk_rs::models::{DecryptMode, EncryptMode, KeyMechanism, KeyType, SignMode};

// from https://github.com/aws/aws-nitro-enclaves-acm/blob/main/src/vtok_p11/src/backend/mech.rs
#[derive(Debug)]
pub enum CkRawError {
    MechParamTypeMismatch,
    NullPtrDeref,
}

#[derive(Debug)]
pub struct CkRawMechanism {
    ptr: *mut cryptoki_sys::CK_MECHANISM,
}
pub trait MechParams {}
impl MechParams for cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS {}
impl MechParams for cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS {}
impl MechParams for [cryptoki_sys::CK_BYTE; 16] {}

impl CkRawMechanism {
    pub unsafe fn from_raw_ptr(ptr: *mut cryptoki_sys::CK_MECHANISM) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }

        Some(Self { ptr })
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
    pub fn len(&self) -> CK_ULONG {
        unsafe { (*self.ptr).ulParameterLen }
    }
}

#[derive(Debug)]
pub enum Error {
    CkRaw(CkRawError),
    UnknownMech(CK_MECHANISM_TYPE),
    UnknownDigest(CK_MECHANISM_TYPE),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::CkRaw(e) => write!(f, "CkRaw error: {:?}", e),
            Error::UnknownMech(t) => write!(f, "Unknown mechanism {}", t),
            Error::UnknownDigest(t) => write!(f, "Unknown digest {}", t),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MechDigest {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl MechDigest {
    pub fn from_ck_mech(mech: CK_MECHANISM_TYPE) -> Option<Self> {
        match mech {
            cryptoki_sys::CKM_MD5 => Some(Self::Md5),
            cryptoki_sys::CKM_SHA_1 => Some(Self::Sha1),
            cryptoki_sys::CKM_SHA224 => Some(Self::Sha224),
            cryptoki_sys::CKM_SHA256 => Some(Self::Sha256),
            cryptoki_sys::CKM_SHA384 => Some(Self::Sha384),
            cryptoki_sys::CKM_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }
}

pub type InitializationVector = Option<[u8; 16]>;

#[derive(Clone, Debug, PartialEq)]
pub enum Mechanism {
    // Digest(MechDigest),
    AesCbc(InitializationVector),
    RsaPkcs(Option<MechDigest>),
    RsaPkcsOaep(MechDigest),
    RsaPkcsPss(MechDigest, bool), // (Hashing algorithm, pre-hashing needed)
    RsaX509,
    EdDsa,
    Ecdsa(Option<MechDigest>),
    GenerateGeneric,
    GenerateAes,
    GenerateRsa,
    GenerateEc,
    GenerateEd,
}

impl From<KeyMechanism> for Mechanism {
    fn from(value: KeyMechanism) -> Self {
        match value {
            KeyMechanism::AesDecryptionCbc => Self::AesCbc(None),
            KeyMechanism::AesEncryptionCbc => Self::AesCbc(None),
            KeyMechanism::EcdsaSignature => Self::Ecdsa(None),
            KeyMechanism::EdDsaSignature => Self::EdDsa,
            KeyMechanism::RsaDecryptionOaepMd5 => Self::RsaPkcsOaep(MechDigest::Md5),
            KeyMechanism::RsaDecryptionOaepSha1 => Self::RsaPkcsOaep(MechDigest::Sha1),
            KeyMechanism::RsaDecryptionOaepSha224 => Self::RsaPkcsOaep(MechDigest::Sha224),
            KeyMechanism::RsaDecryptionOaepSha256 => Self::RsaPkcsOaep(MechDigest::Sha256),
            KeyMechanism::RsaDecryptionOaepSha384 => Self::RsaPkcsOaep(MechDigest::Sha384),
            KeyMechanism::RsaDecryptionOaepSha512 => Self::RsaPkcsOaep(MechDigest::Sha512),
            KeyMechanism::RsaSignaturePssMd5 => Self::RsaPkcsPss(MechDigest::Md5, false),
            KeyMechanism::RsaSignaturePssSha1 => Self::RsaPkcsPss(MechDigest::Sha1, false),
            KeyMechanism::RsaSignaturePssSha224 => Self::RsaPkcsPss(MechDigest::Sha224, false),
            KeyMechanism::RsaSignaturePssSha256 => Self::RsaPkcsPss(MechDigest::Sha256, false),
            KeyMechanism::RsaSignaturePssSha384 => Self::RsaPkcsPss(MechDigest::Sha384, false),
            KeyMechanism::RsaSignaturePssSha512 => Self::RsaPkcsPss(MechDigest::Sha512, false),
            KeyMechanism::RsaDecryptionPkcs1 => Self::RsaPkcs(None),
            KeyMechanism::RsaDecryptionRaw => Self::RsaX509,
            KeyMechanism::RsaSignaturePkcs1 => Self::RsaPkcs(None),
        }
    }
}

#[derive(Clone, Debug)]
pub enum MechMode {
    Sign,
    Encrypt,
    Decrypt,
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
    const ED_MIN_KEY_BITS: cryptoki_sys::CK_ULONG = 256;
    const ED_MAX_KEY_BITS: cryptoki_sys::CK_ULONG = 256;

    pub fn from_key_type(key_type: KeyType) -> Vec<Self> {
        match key_type {
            KeyType::Generic => vec![Self::AesCbc(None)],
            KeyType::Rsa => vec![
                Self::RsaPkcs(None),
                Self::RsaPkcsOaep(MechDigest::Md5),
                Self::RsaPkcsOaep(MechDigest::Sha1),
                Self::RsaPkcsOaep(MechDigest::Sha224),
                Self::RsaPkcsOaep(MechDigest::Sha256),
                Self::RsaPkcsOaep(MechDigest::Sha384),
                Self::RsaPkcsOaep(MechDigest::Sha512),
                Self::RsaPkcsPss(MechDigest::Md5, false),
                Self::RsaPkcsPss(MechDigest::Sha1, false),
                Self::RsaPkcsPss(MechDigest::Sha224, false),
                Self::RsaPkcsPss(MechDigest::Sha256, false),
                Self::RsaPkcsPss(MechDigest::Sha384, false),
                Self::RsaPkcsPss(MechDigest::Sha512, false),
                Self::RsaX509,
            ],
            KeyType::EcP224 | KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
                vec![Self::Ecdsa(None)]
            }
            KeyType::Curve25519 => vec![Self::EdDsa],
        }
    }

    pub fn to_key_type(&self) -> KeyType {
        match self {
            Self::AesCbc(_) | Self::GenerateAes | Self::GenerateGeneric => KeyType::Generic,
            Self::RsaPkcs(_)
            | Self::RsaPkcsOaep(_)
            | Self::RsaPkcsPss(_, _)
            | Self::RsaX509
            | Self::GenerateRsa => KeyType::Rsa,
            // return a default one, the right size will be obtained from the OID in the template
            Self::Ecdsa(_) | Self::GenerateEc => KeyType::EcP256,
            Self::EdDsa | Self::GenerateEd => KeyType::Curve25519,
        }
    }

    pub fn get_all_possible_api_mechs(&self) -> Vec<KeyMechanism> {
        match self {
            Self::AesCbc(_) | Self::GenerateAes | Self::GenerateGeneric => vec![
                KeyMechanism::AesDecryptionCbc,
                KeyMechanism::AesEncryptionCbc,
            ],
            Self::RsaPkcs(_)
            | Self::RsaPkcsOaep(_)
            | Self::RsaPkcsPss(_, _)
            | Self::RsaX509
            | Self::GenerateRsa => vec![
                KeyMechanism::RsaDecryptionOaepMd5,
                KeyMechanism::RsaDecryptionOaepSha1,
                KeyMechanism::RsaDecryptionOaepSha224,
                KeyMechanism::RsaDecryptionOaepSha256,
                KeyMechanism::RsaDecryptionOaepSha384,
                KeyMechanism::RsaDecryptionOaepSha512,
                KeyMechanism::RsaSignaturePssMd5,
                KeyMechanism::RsaSignaturePssSha1,
                KeyMechanism::RsaSignaturePssSha224,
                KeyMechanism::RsaSignaturePssSha256,
                KeyMechanism::RsaSignaturePssSha384,
                KeyMechanism::RsaSignaturePssSha512,
                KeyMechanism::RsaDecryptionPkcs1,
                KeyMechanism::RsaDecryptionRaw,
                KeyMechanism::RsaSignaturePkcs1,
            ],
            Self::Ecdsa(_) | Self::GenerateEc => vec![KeyMechanism::EcdsaSignature],
            Self::EdDsa | Self::GenerateEd => vec![KeyMechanism::EdDsaSignature],
        }
    }

    pub fn to_api_mech(&self, mode: MechMode) -> Option<KeyMechanism> {
        match mode {
            MechMode::Sign => match self {
                Self::AesCbc(_) => None,
                Self::RsaPkcs(_) => Some(KeyMechanism::RsaSignaturePkcs1),
                Self::RsaPkcsPss(digest, _) => match digest {
                    MechDigest::Md5 => Some(KeyMechanism::RsaSignaturePssMd5),
                    MechDigest::Sha1 => Some(KeyMechanism::RsaSignaturePssSha1),
                    MechDigest::Sha224 => Some(KeyMechanism::RsaSignaturePssSha224),
                    MechDigest::Sha256 => Some(KeyMechanism::RsaSignaturePssSha256),
                    MechDigest::Sha384 => Some(KeyMechanism::RsaSignaturePssSha384),
                    MechDigest::Sha512 => Some(KeyMechanism::RsaSignaturePssSha512),
                },
                Self::RsaX509 => None,
                Self::Ecdsa(_) => Some(KeyMechanism::EcdsaSignature),
                Self::EdDsa => Some(KeyMechanism::EdDsaSignature),
                Self::RsaPkcsOaep(_) => None,
                _ => None,
            },
            MechMode::Encrypt => match self {
                Self::AesCbc(_) => Some(KeyMechanism::AesEncryptionCbc),
                _ => None,
            },
            MechMode::Decrypt => match self {
                Self::AesCbc(_) => Some(KeyMechanism::AesDecryptionCbc),
                Self::RsaX509 => Some(KeyMechanism::RsaDecryptionRaw),
                Self::RsaPkcs(_) => Some(KeyMechanism::RsaDecryptionPkcs1),
                Self::RsaPkcsOaep(digest) => match digest {
                    MechDigest::Md5 => Some(KeyMechanism::RsaDecryptionOaepMd5),
                    MechDigest::Sha1 => Some(KeyMechanism::RsaDecryptionOaepSha1),
                    MechDigest::Sha224 => Some(KeyMechanism::RsaDecryptionOaepSha224),
                    MechDigest::Sha256 => Some(KeyMechanism::RsaDecryptionOaepSha256),
                    MechDigest::Sha384 => Some(KeyMechanism::RsaDecryptionOaepSha384),
                    MechDigest::Sha512 => Some(KeyMechanism::RsaDecryptionOaepSha512),
                },
                _ => None,
            },
        }
    }

    pub fn from_ckraw_mech(raw_mech: &CkRawMechanism) -> Result<Self, Error> {
        let mech = match raw_mech.type_() {
            cryptoki_sys::CKM_AES_KEY_GEN => Self::GenerateAes,
            cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN => Self::GenerateRsa,
            cryptoki_sys::CKM_EC_KEY_PAIR_GEN => Self::GenerateEc,
            cryptoki_sys::CKM_EC_EDWARDS_KEY_PAIR_GEN => Self::GenerateEd,
            cryptoki_sys::CKM_GENERIC_SECRET_KEY_GEN => Self::GenerateGeneric,
            cryptoki_sys::CKM_AES_CBC => {
                let params = unsafe { raw_mech.params::<[cryptoki_sys::CK_BYTE; 16]>() }
                    .map_err(Error::CkRaw)?;

                let params = params.ok_or(Error::CkRaw(CkRawError::NullPtrDeref))?;

                Self::AesCbc(Some(params))
            }

            cryptoki_sys::CKM_RSA_PKCS => Self::RsaPkcs(None),
            cryptoki_sys::CKM_SHA1_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha1)),
            cryptoki_sys::CKM_SHA224_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha224)),
            cryptoki_sys::CKM_SHA256_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha256)),
            cryptoki_sys::CKM_SHA384_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha384)),
            cryptoki_sys::CKM_SHA512_RSA_PKCS => Self::RsaPkcs(Some(MechDigest::Sha512)),

            cryptoki_sys::CKM_RSA_PKCS_PSS => {
                let params = unsafe { raw_mech.params::<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>() }
                    .map_err(Error::CkRaw)?;
                let params = params.ok_or(Error::CkRaw(CkRawError::NullPtrDeref))?;

                let hash_alg = params.hashAlg;

                trace!("params.hashAlg: {:?}", hash_alg);
                Self::RsaPkcsPss(
                    MechDigest::from_ck_mech(params.hashAlg)
                        .ok_or(Error::UnknownDigest(hash_alg))?,
                    false,
                )
            }
            cryptoki_sys::CKM_SHA1_RSA_PKCS_PSS => Self::RsaPkcsPss(MechDigest::Sha1, true),
            cryptoki_sys::CKM_SHA224_RSA_PKCS_PSS => Self::RsaPkcsPss(MechDigest::Sha224, true),
            cryptoki_sys::CKM_SHA256_RSA_PKCS_PSS => Self::RsaPkcsPss(MechDigest::Sha256, true),
            cryptoki_sys::CKM_SHA384_RSA_PKCS_PSS => Self::RsaPkcsPss(MechDigest::Sha384, true),
            cryptoki_sys::CKM_SHA512_RSA_PKCS_PSS => Self::RsaPkcsPss(MechDigest::Sha512, true),

            cryptoki_sys::CKM_RSA_PKCS_OAEP => {
                let params = unsafe { raw_mech.params::<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>() }
                    .map_err(Error::CkRaw)?;
                let params = params.ok_or(Error::CkRaw(CkRawError::NullPtrDeref))?;

                Self::RsaPkcsOaep(
                    MechDigest::from_ck_mech(params.hashAlg)
                        .ok_or(Error::UnknownDigest(params.hashAlg))?,
                )
            }

            cryptoki_sys::CKM_RSA_X_509 => Self::RsaX509,
            cryptoki_sys::CKM_ECDSA => Self::Ecdsa(None),
            cryptoki_sys::CKM_ECDSA_SHA1 => Self::Ecdsa(Some(MechDigest::Sha1)),
            cryptoki_sys::CKM_ECDSA_SHA224 => Self::Ecdsa(Some(MechDigest::Sha224)),
            cryptoki_sys::CKM_ECDSA_SHA256 => Self::Ecdsa(Some(MechDigest::Sha256)),
            cryptoki_sys::CKM_ECDSA_SHA384 => Self::Ecdsa(Some(MechDigest::Sha384)),
            cryptoki_sys::CKM_ECDSA_SHA512 => Self::Ecdsa(Some(MechDigest::Sha512)),
            cryptoki_sys::CKM_EDDSA => Self::EdDsa,
            _ => return Err(Error::UnknownMech(raw_mech.type_())),
        };

        Ok(mech)
    }

    pub fn ck_type(&self) -> cryptoki_sys::CK_MECHANISM_TYPE {
        match self {
            Self::AesCbc(_) => cryptoki_sys::CKM_AES_CBC,
            Self::RsaPkcs(digest) => match digest {
                Some(MechDigest::Sha1) => cryptoki_sys::CKM_SHA1_RSA_PKCS,
                Some(MechDigest::Sha224) => cryptoki_sys::CKM_SHA224_RSA_PKCS,
                Some(MechDigest::Sha256) => cryptoki_sys::CKM_SHA256_RSA_PKCS,
                Some(MechDigest::Sha384) => cryptoki_sys::CKM_SHA384_RSA_PKCS,
                Some(MechDigest::Sha512) => cryptoki_sys::CKM_SHA512_RSA_PKCS,
                _ => cryptoki_sys::CKM_RSA_PKCS,
            },

            Self::RsaPkcsPss(digest, pre_hash) => {
                if *pre_hash {
                    match digest {
                        MechDigest::Sha1 => cryptoki_sys::CKM_SHA1_RSA_PKCS_PSS,
                        MechDigest::Sha224 => cryptoki_sys::CKM_SHA224_RSA_PKCS_PSS,
                        MechDigest::Sha256 => cryptoki_sys::CKM_SHA256_RSA_PKCS_PSS,
                        MechDigest::Sha384 => cryptoki_sys::CKM_SHA384_RSA_PKCS_PSS,
                        MechDigest::Sha512 => cryptoki_sys::CKM_SHA512_RSA_PKCS_PSS,
                        _ => cryptoki_sys::CKM_RSA_PKCS_PSS,
                    }
                } else {
                    cryptoki_sys::CKM_RSA_PKCS_PSS
                }
            }
            Self::RsaPkcsOaep(_) => CKM_RSA_PKCS_OAEP,

            Self::RsaX509 => cryptoki_sys::CKM_RSA_X_509,
            Self::Ecdsa(None) => cryptoki_sys::CKM_ECDSA,
            Self::Ecdsa(Some(MechDigest::Sha1)) => cryptoki_sys::CKM_ECDSA_SHA1,
            Self::Ecdsa(Some(MechDigest::Sha224)) => cryptoki_sys::CKM_ECDSA_SHA224,
            Self::Ecdsa(Some(MechDigest::Sha256)) => cryptoki_sys::CKM_ECDSA_SHA256,
            Self::Ecdsa(Some(MechDigest::Sha384)) => cryptoki_sys::CKM_ECDSA_SHA384,
            Self::Ecdsa(Some(MechDigest::Sha512)) => cryptoki_sys::CKM_ECDSA_SHA512,
            // should not exist
            Self::Ecdsa(Some(MechDigest::Md5)) => cryptoki_sys::CKM_ECDSA,
            Self::EdDsa => cryptoki_sys::CKM_EDDSA,

            Self::GenerateAes => cryptoki_sys::CKM_AES_KEY_GEN,
            Self::GenerateRsa => cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            Self::GenerateEc => cryptoki_sys::CKM_EC_KEY_PAIR_GEN,
            Self::GenerateEd => cryptoki_sys::CKM_EC_EDWARDS_KEY_PAIR_GEN,
            Self::GenerateGeneric => cryptoki_sys::CKM_GENERIC_SECRET_KEY_GEN,
        }
    }

    pub fn ck_info(&self) -> cryptoki_sys::CK_MECHANISM_INFO {
        let (min_bits, max_bits) = match self {
            // Self::Digest(_) => (0, 0),
            Self::AesCbc(_) | Self::GenerateAes => (128, 256),
            Self::RsaPkcs(_) | Self::RsaPkcsPss(_, _) | Self::RsaX509 | Self::GenerateRsa => {
                (Self::RSA_MIN_KEY_BITS, Self::RSA_MAX_KEY_BITS)
            }
            Self::Ecdsa(_) | Self::GenerateEc => (Self::EC_MIN_KEY_BITS, Self::EC_MAX_KEY_BITS),
            Self::RsaPkcsOaep(_) => (Self::RSA_MIN_KEY_BITS, Self::RSA_MAX_KEY_BITS),
            Self::EdDsa | Self::GenerateEd => (Self::ED_MIN_KEY_BITS, Self::ED_MAX_KEY_BITS),
            Self::GenerateGeneric => (128, 256),
        };
        cryptoki_sys::CK_MECHANISM_INFO {
            ulMinKeySize: min_bits,
            ulMaxKeySize: max_bits,
            flags: self.ck_flags(),
        }
    }

    // get the initialization vector for AES CBC
    pub fn iv(&self) -> Option<[u8; 16]> {
        match self {
            Self::AesCbc(Some(iv)) => Some(*iv),
            _ => None,
        }
    }

    pub fn ck_flags(&self) -> cryptoki_sys::CK_FLAGS {
        // NOTE: Though we have a soft-token, we stamp the cryptoki_sys::CKF_HW flag since most unit
        // tests out there seem to check for it
        cryptoki_sys::CKF_HW
            | match self {
                Self::GenerateGeneric => {
                    cryptoki_sys::CKF_GENERATE
                        | cryptoki_sys::CKF_GENERATE_KEY_PAIR
                        | cryptoki_sys::CKF_DERIVE
                }
                Self::AesCbc(_) | Self::GenerateAes => {
                    cryptoki_sys::CKF_ENCRYPT
                        | cryptoki_sys::CKF_DECRYPT
                        | cryptoki_sys::CKF_GENERATE
                }
                // Self::Digest(_) => cryptoki_sys::CKF_DIGEST,
                // Single-part CKM_RSA_PKCS also has encrypt/decrypt
                Self::RsaPkcs(_) | Self::GenerateRsa => {
                    cryptoki_sys::CKF_SIGN
                        | cryptoki_sys::CKF_DECRYPT
                        | cryptoki_sys::CKF_GENERATE_KEY_PAIR
                }
                // Multi-part CKM_RSA_PKCS has sign only
                Self::RsaPkcsPss(_, _) => cryptoki_sys::CKF_SIGN,

                // "RAW" RSA has decrypt only
                Self::RsaX509 => cryptoki_sys::CKF_DECRYPT,
                Self::Ecdsa(_) | Self::GenerateEc => {
                    cryptoki_sys::CKF_SIGN
                        | cryptoki_sys::CKF_EC_F_P
                        | cryptoki_sys::CKF_EC_NAMEDCURVE
                        | cryptoki_sys::CKF_EC_UNCOMPRESS
                        | cryptoki_sys::CKF_GENERATE_KEY_PAIR
                }
                Self::RsaPkcsOaep(_) => cryptoki_sys::CKF_SIGN,
                Self::EdDsa | Self::GenerateEd => {
                    cryptoki_sys::CKF_SIGN | cryptoki_sys::CKF_GENERATE_KEY_PAIR
                }
            }
    }

    // return the digest to apply to the data before signing if needed
    pub fn internal_digest(&self) -> Option<MechDigest> {
        match self {
            Self::RsaPkcs(digest) => *digest,
            Self::RsaPkcsPss(digest, pre_hash) => {
                if *pre_hash {
                    Some(*digest)
                } else {
                    None
                }
            }
            Self::Ecdsa(digest) => *digest,
            _ => None,
        }
    }

    /// returns the name to use in the api, None if not supported
    pub fn sign_name(&self) -> Option<SignMode> {
        match self {
            Self::RsaPkcs(_) => Some(SignMode::Pkcs1),
            Self::RsaPkcsPss(digest, _) => match digest {
                MechDigest::Md5 => Some(SignMode::PssSha1),
                MechDigest::Sha1 => Some(SignMode::PssSha1),
                MechDigest::Sha224 => Some(SignMode::PssSha224),
                MechDigest::Sha256 => Some(SignMode::PssSha256),
                MechDigest::Sha384 => Some(SignMode::PssSha384),
                MechDigest::Sha512 => Some(SignMode::PssSha512),
            },
            Self::Ecdsa(_) => Some(SignMode::Ecdsa),
            Self::EdDsa => Some(SignMode::EdDsa),
            _ => None,
        }
    }

    pub fn encrypt_name(&self) -> Option<EncryptMode> {
        match self {
            Self::AesCbc(_) => Some(EncryptMode::AesCbc),
            _ => None,
        }
    }

    /// Returns the name to use in the api, None if not supported
    pub fn decrypt_name(&self) -> Option<DecryptMode> {
        match self {
            Self::AesCbc(_) => Some(DecryptMode::AesCbc),
            Self::RsaX509 => Some(DecryptMode::Raw),
            Self::RsaPkcs(_) => Some(DecryptMode::Pkcs1),
            Self::RsaPkcsOaep(digest) => match digest {
                MechDigest::Md5 => Some(DecryptMode::OaepMd5),
                MechDigest::Sha1 => Some(DecryptMode::OaepSha1),
                MechDigest::Sha224 => Some(DecryptMode::OaepSha224),
                MechDigest::Sha256 => Some(DecryptMode::OaepSha256),
                MechDigest::Sha384 => Some(DecryptMode::OaepSha384),
                MechDigest::Sha512 => Some(DecryptMode::OaepSha512),
            },
            _ => None,
        }
    }

    // get the theoretical size of the key in bytes
    pub fn get_key_size(&self, key_size: Option<usize>) -> usize {
        match self {
            Self::RsaPkcs(_) => key_size.unwrap_or((Self::RSA_MAX_KEY_BITS / 8) as usize),
            Self::RsaPkcsPss(_, _) => key_size.unwrap_or((Self::RSA_MAX_KEY_BITS / 8) as usize),
            Self::Ecdsa(_) => {
                let s = key_size.unwrap_or((Self::EC_MAX_KEY_BITS / 8) as usize);
                if s == 65 {
                    66 // correct the division error for 521
                } else {
                    s
                }
            }
            Self::EdDsa => key_size.unwrap_or((Self::ED_MAX_KEY_BITS / 8) as usize),
            _ => (Self::RSA_MAX_KEY_BITS / 8) as usize,
        }
    }

    pub fn get_input_size(&self, key_size: Option<usize>) -> usize {
        match self {
            Self::RsaPkcs(_) => key_size.unwrap_or((Self::RSA_MAX_KEY_BITS / 8) as usize),
            Self::RsaPkcsPss(_, _) => key_size.unwrap_or((Self::RSA_MAX_KEY_BITS / 8) as usize),
            Self::Ecdsa(_) => {
                let s = key_size.unwrap_or((Self::EC_MAX_KEY_BITS / 8) as usize);
                if s == 65 {
                    // p512 uses 64 bytes
                    64
                } else {
                    s
                }
            }
            Self::EdDsa => key_size.unwrap_or((Self::ED_MAX_KEY_BITS / 8) as usize),
            _ => (Self::RSA_MAX_KEY_BITS / 8) as usize,
        }
    }

    // get the theoretical size of the signature in bytes
    pub fn get_signature_size(&self, key_size: Option<usize>) -> usize {
        let key_size = self.get_key_size(key_size);
        match self {
            Self::RsaPkcs(_) => key_size,
            Self::RsaPkcsPss(_, _) => key_size,
            Self::Ecdsa(_) => key_size * 2,
            Self::EdDsa => key_size * 2,
            _ => key_size,
        }
    }
}
