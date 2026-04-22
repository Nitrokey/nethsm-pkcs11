mod api;

mod data;

pub mod utils;

mod backend;
mod config;
mod defs;
mod ureq;

#[cfg(panic = "abort")]
mod unwind_stubs;

#[macro_use]
extern crate std;

const _VERSION_ASSERT: () = {
    // if the cryptoki version is updated, we need to review the specification for relevant changes
    assert!(defs::CRYPTOKI_VERSION.major == 3);
    assert!(defs::CRYPTOKI_VERSION.minor == 2);
};
