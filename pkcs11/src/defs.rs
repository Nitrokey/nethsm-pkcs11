use cryptoki_sys::{CK_VERSION, CRYPTOKI_VERSION_MAJOR};

use crate::backend::mechanism::Mechanism;

pub const CRYPTOKI_VERSION: cryptoki_sys::CK_VERSION = cryptoki_sys::CK_VERSION {
    major: CRYPTOKI_VERSION_MAJOR,
    minor: cryptoki_sys::CRYPTOKI_VERSION_MINOR,
};

#[allow(clippy::result_unit_err)]
const fn parse_u8(s: &str) -> Result<u8, ()> {
    let mut idx = 0;
    let mut acc = 0u8;
    while idx < s.len() {
        let Some(temp1) = acc.checked_mul(10u8) else {
            return Err(());
        };
        let Some(digit) = s.as_bytes()[idx].checked_sub(b'0') else {
            return Err(());
        };
        if digit >= 10 {
            return Err(());
        }
        let Some(temp2) = temp1.checked_add(digit) else {
            return Err(());
        };
        acc = temp2;
        idx += 1;
    }
    Ok(acc)
}

pub const LIB_VERSION_MINOR: u8 = {
    match parse_u8(env!("CARGO_PKG_VERSION_MINOR")) {
        Ok(v) => v,
        Err(()) => panic!("Failed to parse minor version"),
    }
};
pub const LIB_VERSION_MAJOR: u8 = {
    match parse_u8(env!("CARGO_PKG_VERSION_MAJOR")) {
        Ok(v) => v,
        Err(()) => panic!("Failed to parse major version"),
    }
};

pub const LIB_VERSION: CK_VERSION = CK_VERSION {
    major: LIB_VERSION_MAJOR,
    minor: LIB_VERSION_MINOR,
};
pub const LIB_DESCRIPTION: &str = {
    let v = "Nitrokey NetHsm PKCS#11 library";
    // max length of libraryDescription in CK_INFO
    assert!(v.len() < 32);
    v
};

pub const LIB_MANUFACTURER: &str = "Nitrokey";
pub const DEFAULT_FIRMWARE_VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 1 };
pub const DEFAULT_HARDWARE_VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 1 };

pub const MECHANISM_LIST: [Mechanism; 27] = [
    Mechanism::AesCbc(None),
    Mechanism::RsaX509,
    Mechanism::RsaPkcs(None),
    Mechanism::RsaPkcs(Some(crate::backend::mechanism::MechDigest::Sha1)),
    Mechanism::RsaPkcs(Some(crate::backend::mechanism::MechDigest::Sha224)),
    Mechanism::RsaPkcs(Some(crate::backend::mechanism::MechDigest::Sha256)),
    Mechanism::RsaPkcs(Some(crate::backend::mechanism::MechDigest::Sha384)),
    Mechanism::RsaPkcs(Some(crate::backend::mechanism::MechDigest::Sha512)),
    Mechanism::RsaPkcsPss(crate::backend::mechanism::MechDigest::Md5, false),
    Mechanism::RsaPkcsPss(crate::backend::mechanism::MechDigest::Sha1, true),
    Mechanism::RsaPkcsPss(crate::backend::mechanism::MechDigest::Sha224, true),
    Mechanism::RsaPkcsPss(crate::backend::mechanism::MechDigest::Sha256, true),
    Mechanism::RsaPkcsPss(crate::backend::mechanism::MechDigest::Sha384, true),
    Mechanism::RsaPkcsPss(crate::backend::mechanism::MechDigest::Sha512, true),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing() {
        assert_eq!(
            LIB_VERSION_MAJOR,
            env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>().unwrap()
        );
        assert_eq!(
            LIB_VERSION_MINOR,
            env!("CARGO_PKG_VERSION_MINOR").parse::<u8>().unwrap()
        );
    }
}
