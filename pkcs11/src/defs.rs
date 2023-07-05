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

// TODO: add more mechanisms
pub const MECHANISM_LIST: [Mechanism; 4] = [
    Mechanism::RsaX509,
    Mechanism::RsaPkcs,
    Mechanism::RsaPkcsPss(None),
    Mechanism::RsaPkcsOaep(None),
];
