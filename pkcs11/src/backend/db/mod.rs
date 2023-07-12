// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Nitrokey
// SPDX-License-Identifier: Apache-2.0
// modified from https://github.com/aws/aws-nitro-enclaves-acm

pub mod attr;
pub mod object;
use std::collections::HashMap;

use cryptoki_sys::CK_OBJECT_HANDLE;
pub use object::{Object, ObjectHandle};

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
