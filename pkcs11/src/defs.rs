use cryptoki_sys::{CK_VERSION, CRYPTOKI_VERSION_MAJOR, CKF_HW, CKF_ENCRYPT, CKF_DECRYPT};

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
pub const MECHANISM_LIST: [Mechanism; 1] = [Mechanism {
    mechanism_type: cryptoki_sys::CKM_AES_CBC,
    min_key_size: 1024,
    max_key_size: 4096,
    flags: CKF_HW | CKF_ENCRYPT | CKF_DECRYPT,
    api_name: "AES_CBC",
}];
