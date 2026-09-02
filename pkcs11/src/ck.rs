//! This modules provides Rust wrappers for the types provided by the `cryptoki-sys` crate.
//!
//! # Handles
//!
//! `cryptoki-sys` uses different kind of handles that are typedefs for `unsigned long`. This
//! module provides newtypes wrapping these handles to avoid mixups.
//!
//! # Enums
//!
//! `cryptoki-sys` provides some enums which are just typedefs for `unsigned long`. This module
//! provides corresponding Rust enums. These enums only provide those variants that are used by
//! the Rust code. Other variants are grouped into an `Other` variant.

use std::fmt::{self, Display, Formatter};

macro_rules! impl_newtype {
    ($newtype:ident = $oldtype:ident) => {
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $newtype(cryptoki_sys::$oldtype);

        impl Display for $newtype {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<cryptoki_sys::$oldtype> for $newtype {
            fn from(value: cryptoki_sys::$oldtype) -> Self {
                Self(value)
            }
        }

        impl From<$newtype> for cryptoki_sys::$oldtype {
            fn from(value: $newtype) -> Self {
                value.0
            }
        }
    };
}

impl_newtype!(CkObjectHandle = CK_OBJECT_HANDLE);

impl CkObjectHandle {
    pub const FIRST: Self = Self(1);

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl_newtype!(CkSessionHandle = CK_SESSION_HANDLE);

impl CkSessionHandle {
    pub const FIRST: Self = Self(1);

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

macro_rules! impl_enum {
    (
        $name:ident = $type:ident [
            $(
                $variant:ident = $constant:ident,
            )+
            $(,)?
        ]
    ) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum $name {
            $(
                $variant,
            )+
            Other(cryptoki_sys::$type),
        }

        impl From<$name> for cryptoki_sys::$type {
            fn from(value: $name) -> Self {
                match value {
                    $(
                        $name::$variant => cryptoki_sys::$constant,
                    )+
                    $name::Other(value) => value,
                }
            }
        }

        impl From<cryptoki_sys::$type> for $name {
            fn from(value: cryptoki_sys::$type) -> Self {
                match value {
                    $(
                        cryptoki_sys::$constant => $name::$variant,
                    )+
                    value => $name::Other(value),
                }
            }
        }
    }
}

impl_enum!(
    CkAttributeType = CK_ATTRIBUTE_TYPE [
        AllowedMechanisms = CKA_ALLOWED_MECHANISMS,
        AlwaysAuthenticate = CKA_ALWAYS_AUTHENTICATE,
        AlwaysSensitive = CKA_ALWAYS_SENSITIVE,
        CertificateCategory = CKA_CERTIFICATE_CATEGORY,
        CertificateType = CKA_CERTIFICATE_TYPE,
        Class = CKA_CLASS,
        Decrypt = CKA_DECRYPT,
        Derive = CKA_DERIVE,
        EcParams = CKA_EC_PARAMS,
        EcPoint = CKA_EC_POINT,
        Encrypt = CKA_ENCRYPT,
        Extractable = CKA_EXTRACTABLE,
        Id = CKA_ID,
        Issuer = CKA_ISSUER,
        KeyGenMechanism = CKA_KEY_GEN_MECHANISM,
        KeyType = CKA_KEY_TYPE,
        Label = CKA_LABEL,
        Local = CKA_LOCAL,
        Modifiable = CKA_MODIFIABLE,
        Modulus = CKA_MODULUS,
        ModulusBits = CKA_MODULUS_BITS,
        NeverExtractable = CKA_NEVER_EXTRACTABLE,
        Prime1 = CKA_PRIME_1,
        Prime2 = CKA_PRIME_2,
        Private = CKA_PRIVATE,
        PublicExponent = CKA_PUBLIC_EXPONENT,
        Sensitive = CKA_SENSITIVE,
        SerialNumber = CKA_SERIAL_NUMBER,
        Sign = CKA_SIGN,
        SignRecover = CKA_SIGN_RECOVER,
        Subject = CKA_SUBJECT,
        Token = CKA_TOKEN,
        Trusted = CKA_TRUSTED,
        Unwrap = CKA_UNWRAP,
        Value = CKA_VALUE,
        ValueLen = CKA_VALUE_LEN,
        Verify = CKA_VERIFY,
        VerifyRecover = CKA_VERIFY_RECOVER,
        Wrap = CKA_WRAP,
        WrapWithTrusted = CKA_WRAP_WITH_TRUSTED,
    ]
);

impl_enum!(
    CkCertificateCategory = CK_CERTIFICATE_CATEGORY [
        Unspecified = CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
    ]
);

impl_enum!(
    CkCertificateType = CK_CERTIFICATE_TYPE [
        X509 = CKC_X_509,
    ]
);

impl_enum!(
    CkKeyType = CK_KEY_TYPE [
        Ec = CKK_EC,
        EcEdwards = CKK_EC_EDWARDS,
        GenericSecret = CKK_GENERIC_SECRET,
        Rsa = CKK_RSA,
    ]
);

impl_enum!(
    CkObjectClass = CK_OBJECT_CLASS [
        PrivateKey = CKO_PRIVATE_KEY,
        PublicKey = CKO_PUBLIC_KEY,
        SecretKey = CKO_SECRET_KEY,
        Certificate = CKO_CERTIFICATE,
    ]
);
