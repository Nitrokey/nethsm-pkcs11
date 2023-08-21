use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use lazy_static::lazy_static;
use log::trace;

// Create a runtime if we forked
pub fn get_tokio_rt() -> Arc<tokio::runtime::Runtime> {
    let pid = std::process::id();
    trace!("runtime for pid : {:?}", pid);
    let mut rt_conf = RUNTIME.lock().unwrap();
    trace!("runtime locked : {:?}", rt_conf);
    match rt_conf.get(&pid) {
        Some(rt) => rt.clone(),
        None => {
            trace!("Creating runtime for pid : {:?}", pid);

            let rt = Arc::new(create_runtime());
            trace!("Runtime created : {:?}", rt);

            rt_conf.insert(pid, rt.clone());
            trace!("Runtime inserted : {:?}", rt);
            rt
        }
    }
}

lazy_static! {
    pub static ref RUNTIME: Arc<Mutex<HashMap<u32, Arc<tokio::runtime::Runtime>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

fn create_runtime() -> tokio::runtime::Runtime {
    trace!("Creating runtime");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build();

    trace!("Runtime created : {:?}", rt);

    rt.unwrap()
}

// lock a mutex and returns the guard, returns CKR_FUNCTION_FAILED if the lock fails
#[macro_export]
macro_rules! lock_mutex {
    ($session_manager:expr) => {
        match $session_manager.lock() {
            Ok(manager) => manager,
            Err(e) => {
                error!("Failed to lock : {:?}", e);
                return cryptoki_sys::CKR_FUNCTION_FAILED;
            }
        }
    };
}

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

#[macro_export]
macro_rules! lock_session {
    ($hSession:expr, $session:ident) => {
        let mut _manager_arc = lock_mutex!($crate::data::SESSION_MANAGER);
        let $session = match _manager_arc.get_session_mut($hSession) {
            Some(session) => session,
            None => {
                error!("function called with invalid session handle {}.", $hSession);
                return cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
            }
        };
    };
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
