#![allow(unreachable_code)]

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
