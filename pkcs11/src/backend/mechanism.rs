use std::os;

use cryptoki_sys::{CK_FLAGS, CK_MECHANISM_TYPE};

#[derive(Debug, Clone)]
pub struct Mechanism {
    pub mechanism_type: CK_MECHANISM_TYPE,
    pub min_key_size: os::raw::c_ulong,
    pub max_key_size: os::raw::c_ulong,
    pub flags: CK_FLAGS,
    pub api_name : &'static str,
}
