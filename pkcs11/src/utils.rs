use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{
    mem,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        Mutex, RwLock,
    },
    thread::{available_parallelism, JoinHandle},
};

use crate::data::THREADS_ALLOWED;

// makes a CK_VERSION struct from a string like "1.2"
pub fn version_struct_from_str(version_str: String) -> cryptoki_sys::CK_VERSION {
    let parts: Vec<&str> = version_str.split('.').collect();
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
}

// Modified from the ACM project : https://github.com/aws/aws-nitro-enclaves-acm/blob/main/src/vtok_p11/src/util/mod.rs
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub fn padded_str<const N: usize>(s: &str) -> [u8; N] {
    let mut ret = [b' '; N];
    let count = std::cmp::min(s.len(), N);
    ret[..count].copy_from_slice(&s.as_bytes()[..count]);
    ret
}

static DEAD_THREADS: AtomicUsize = AtomicUsize::new(0);
static RAYON_HANDLES: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
static RAYON_THREADPOOL: RwLock<Option<ThreadPool>> = RwLock::new(None);

pub fn initialize_threadpool() {
    assert!(THREADS_ALLOWED.load(Relaxed));

    let num_cpus = available_parallelism().map(|m| m.get()).unwrap_or(1);
    let threadpool = Some(
        ThreadPoolBuilder::new()
            .spawn_handler(move |thread| {
                let mut builder = std::thread::Builder::new();
                if let Some(name) = thread.name() {
                    builder = builder.name(name.to_string());
                }
                if let Some(size) = thread.stack_size() {
                    builder = builder.stack_size(size);
                }
                let handle = builder.spawn(move || {
                    thread.run();
                    let dead_threads = DEAD_THREADS.fetch_add(1, Relaxed);
                    // Prevent potential infinitely growing handle count
                    if dead_threads > 2 * num_cpus {
                        // Should be somewhat fast as the number of threads should be proportional to the number of CPU
                        // Only use try_lock to avoid any deadlock
                        if let Ok(mut handles) = RAYON_HANDLES.try_lock() {
                            let tmp = mem::replace(&mut *handles, Vec::with_capacity(2 * num_cpus));
                            let mut removed_threads = 0;
                            *handles = tmp
                                .into_iter()
                                .filter_map(|h| {
                                    if h.is_finished() {
                                        removed_threads += 1;
                                        h.join()
                                            .inspect_err(|err| {
                                                if let Some(err) =
                                                    err.downcast_ref::<&'static str>()
                                                {
                                                    log::error!(
                                                        "Thread pool thread panicked: {err}"
                                                    );
                                                } else if let Some(err) =
                                                    err.downcast_ref::<String>()
                                                {
                                                    log::error!(
                                                        "Thread pool thread panicked: {err}"
                                                    );
                                                } else {
                                                    log::error!(
                                                        "Thread pool thread panicked: {err:?}"
                                                    );
                                                }
                                            })
                                            .ok();
                                        None
                                    } else {
                                        Some(h)
                                    }
                                })
                                .collect();
                            DEAD_THREADS.fetch_sub(removed_threads, Relaxed);
                        }
                    }
                })?;
                RAYON_HANDLES
                    .lock()
                    .expect("Rayon handles not poisoned")
                    .push(handle);
                Ok(())
            })
            .build()
            .expect("Failed to start rayon pool"),
    );
    let mut handle = RAYON_THREADPOOL
        .try_write()
        .expect("During initialization, pool should be free");
    assert!(
        handle.is_none(),
        "During initialization, threadpool should be empty"
    );
    *handle = threadpool;
}

pub fn run_in_threadpool<OP, R>(op: OP) -> R
where
    OP: FnOnce() -> R + Send,
    R: Send,
{
    assert!(THREADS_ALLOWED.load(Relaxed));
    RAYON_THREADPOOL
        .read()
        .expect("THREADPOOL to be initialized")
        .as_ref()
        .expect("Thread pool should not be closed")
        .install(op)
}

pub fn close_threadpool() {
    assert!(THREADS_ALLOWED.load(Relaxed));
    *RAYON_THREADPOOL.write().unwrap() = None;
    for handle in mem::take(&mut *RAYON_HANDLES.lock().unwrap()) {
        handle
            .join()
            .inspect_err(|err| {
                if let Some(err) = err.downcast_ref::<&'static str>() {
                    log::error!("Thread pool thread panicked: {err}");
                } else if let Some(err) = err.downcast_ref::<String>() {
                    log::error!("Thread pool thread panicked: {err}");
                } else {
                    log::error!("Thread pool thread panicked: {err:?}");
                }
            })
            .ok();
    }
}
