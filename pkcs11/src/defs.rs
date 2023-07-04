use cryptoki_sys::CRYPTOKI_VERSION_MAJOR;

pub const CRYPTOKI_VERSION: cryptoki_sys::CK_VERSION = cryptoki_sys::CK_VERSION {
    major: CRYPTOKI_VERSION_MAJOR,
    minor: cryptoki_sys::CRYPTOKI_VERSION_MINOR,
};
pub const LIB_VERSION: cryptoki_sys::CK_VERSION = cryptoki_sys::CK_VERSION { major: 0, minor: 1 };
