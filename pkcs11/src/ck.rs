//! This modules provides Rust wrappers for the types provided by the `cryptoki-sys` crate.
//!
//! # Handles
//!
//! `cryptoki-sys` uses different kind of handles that are typedefs for `unsigned long`. This
//! module provides newtypes wrapping these handles to avoid mixups.

use std::fmt::{self, Display, Formatter};

macro_rules! impl_newtype {
    ($newtype:ident = $oldtype:ident) => {
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $newtype(cryptoki_sys::$oldtype);

        impl Display for $newtype {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<cryptoki_sys::$oldtype> for $newtype {
            fn from(value: cryptoki_sys::$oldtype) -> Self {
                Self(value)
            }
        }

        impl From<$newtype> for cryptoki_sys::$oldtype {
            fn from(value: $newtype) -> Self {
                value.0
            }
        }
    };
}

impl_newtype!(CkObjectHandle = CK_OBJECT_HANDLE);

impl CkObjectHandle {
    pub const FIRST: Self = Self(1);

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl_newtype!(CkSessionHandle = CK_SESSION_HANDLE);

impl CkSessionHandle {
    pub const FIRST: Self = Self(1);

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}
