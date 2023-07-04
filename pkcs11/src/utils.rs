// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// modified from the ACM project
#[macro_export]
macro_rules! padded_str {
    ($src:expr, $len: expr) => {{
        let mut ret = [b' '; $len];
        let count = std::cmp::min($src.len(), $len);
        ret[..count].copy_from_slice(&$src.as_bytes()[..count]);
        ret
    }};
}
