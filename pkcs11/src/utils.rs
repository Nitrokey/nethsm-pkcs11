// makes a CK_VERSION struct from a string like "1.2"
#[macro_export]
macro_rules! version_struct_from_str {
    ($version_str:expr) => {{
        let parts: Vec<&str> = $version_str.split('.').collect();
        let (major, minor) = match &parts[..] {
            [major_str, minor_str] => {
                let major = major_str.parse().unwrap_or(0);
                let minor = minor_str.parse().unwrap_or(1);
                (major, minor)
            }
            _ => (0, 1),
        };

        cryptoki_sys::CK_VERSION {
            major: major as ::std::os::raw::c_uchar,
            minor: minor as ::std::os::raw::c_uchar,
        }
    }};
}


// Modified from the ACM project : https://github.com/aws/aws-nitro-enclaves-acm/blob/main/src/vtok_p11/src/util/mod.rs
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#[macro_export]
macro_rules! padded_str {
    ($src:expr, $len: expr) => {{
        let mut ret = [b' '; $len];
        let count = std::cmp::min($src.len(), $len);
        ret[..count].copy_from_slice(&$src.as_bytes()[..count]);
        ret
    }};
}
