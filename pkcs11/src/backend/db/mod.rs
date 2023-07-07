// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Nitrokey
// SPDX-License-Identifier: Apache-2.0
// modified from https://github.com/aws/aws-nitro-enclaves-acm

pub mod attr;
pub mod object;
use std::collections::HashMap;

use cryptoki_sys::CK_OBJECT_HANDLE;
pub use object::{Object, ObjectHandle, ObjectKind};
use openapi::apis::default_api::{self, KeysGetError, KeysKeyIdGetError};

use crate::config::device::Slot;

// NOTE: for now, we use these *Info structs to construct key objects. The source PEM is
// preserved, so that a crypto::Pkey (an EVP_PKEY wrapper) can be constructed whenever
// it is needed (e.g. at operation context initialization).
// If the PEM to EVP_PKEY conversion turns out to impact performance, we could construct
// the crypto::Pkey object at DB creation time, and replace the *Info structs with it,
// provided we also implement a proper cloning mechanism for crypto::Pkey. This is needed
// in order to make sure that each session gets its own copy of each key, and maintain
// thread safety.
// Cloning could be done via RSAPrivateKey_dup() and EC_KEY_dup(), together with a TryClone
// trait, since these operations can fail.
#[derive(Clone)]
pub struct RsaKeyInfo {
    pub priv_pem: String,
    pub id: cryptoki_sys::CK_BYTE,
    pub label: String,
    pub num_bits: cryptoki_sys::CK_ULONG,
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

#[derive(Clone)]
pub struct EcKeyInfo {
    pub priv_pem: String,
    pub id: cryptoki_sys::CK_BYTE,
    pub label: String,
    pub params_x962: Vec<u8>,
    pub point_q_x962: Vec<u8>,
}
/// Certificate object type
#[derive(Clone)]
pub enum CertCategory {
    #[allow(dead_code)]
    /// Default (unverified)
    Unverified,
    /// Token certificate
    Token,
    /// CA certificate
    Authority,
    #[allow(dead_code)]
    /// Other
    Other,
}
#[derive(Clone)]
pub struct CertInfo {
    pub categ: CertCategory,
    pub id: cryptoki_sys::CK_BYTE,
    pub label: String,
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub serno_der: Vec<u8>,
    pub cert_der: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    ListKeys(openapi::apis::Error<KeysGetError>),
    GetKey(openapi::apis::Error<KeysKeyIdGetError>),
}

#[derive(Debug, Clone)]
pub struct Db {
    objects: HashMap<CK_OBJECT_HANDLE, Object>,
    next_handle: CK_OBJECT_HANDLE,
}

impl Db {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            next_handle: 1,
        }
    }

    pub fn clear(&mut self) {
        self.objects.clear();
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (ObjectHandle, &Object)> {
        self.objects
            .iter()
            .enumerate()
            .map(|(_, (handle, object))| (ObjectHandle::from(*handle), object))
    }

    pub fn add_object(&mut self, object: Object) -> CK_OBJECT_HANDLE {
        let handle = self.next_handle;
        self.objects.insert(handle, object);
        self.next_handle += 1;
        handle
    }

    pub fn object(&self, handle: ObjectHandle) -> Option<&Object> {
        self.objects.get(&CK_OBJECT_HANDLE::from(handle))
    }
}
