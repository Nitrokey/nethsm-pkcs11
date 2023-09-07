use cryptoki_sys::{CK_VERSION, CRYPTOKI_VERSION_MAJOR};

use crate::backend::mechanism::Mechanism;

pub const CRYPTOKI_VERSION: cryptoki_sys::CK_VERSION = cryptoki_sys::CK_VERSION {
    major: CRYPTOKI_VERSION_MAJOR,
    minor: cryptoki_sys::CRYPTOKI_VERSION_MINOR,
};
pub const LIB_VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 1 };
pub const LIB_DESCRIPTION: &str = "Nitrokey PKCS#11 library";
pub const LIB_MANUFACTURER: &str = "Nitrokey";
pub const DEFAULT_FIRMWARE_VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 1 };
pub const DEFAULT_HARDWARE_VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 1 };

pub const MECHANISM_LIST: [Mechanism; 17] = [
    Mechanism::AesCbc(None),
    Mechanism::RsaX509,
    Mechanism::RsaPkcs,
    Mechanism::RsaPkcsPss(crate::backend::mechanism::MechDigest::Md5),
    Mechanism::RsaPkcsOaep(crate::backend::mechanism::MechDigest::Md5),
    Mechanism::EdDsa,
    Mechanism::Ecdsa(None),
    Mechanism::Ecdsa(Some(crate::backend::mechanism::MechDigest::Sha1)),
    Mechanism::Ecdsa(Some(crate::backend::mechanism::MechDigest::Sha224)),
    Mechanism::Ecdsa(Some(crate::backend::mechanism::MechDigest::Sha256)),
    Mechanism::Ecdsa(Some(crate::backend::mechanism::MechDigest::Sha384)),
    Mechanism::Ecdsa(Some(crate::backend::mechanism::MechDigest::Sha512)),
    Mechanism::GenerateAes,
    Mechanism::GenerateRsa,
    Mechanism::GenerateEc,
    Mechanism::GenerateEd,
    Mechanism::GenerateGeneric,
];
