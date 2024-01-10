// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Nitrokey
// SPDX-License-Identifier: Apache-2.0
// modified from https://github.com/aws/aws-nitro-enclaves-acm

pub mod attr;
pub mod object;
use cryptoki_sys::CK_OBJECT_HANDLE;
use std::{collections::HashMap, time::SystemTime};

pub use object::Object;

#[derive(Debug)]
pub struct Db {
    objects: HashMap<CK_OBJECT_HANDLE, Object>,
    next_handle: CK_OBJECT_HANDLE,
    last_fetchall_timestamp: Option<SystemTime>,
}

impl Db {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            // 0 means invalid handle, we need to start from 1
            next_handle: 1,
            last_fetchall_timestamp: None,
        }
    }

    pub fn fetched_all_keys(&self) -> bool {
        self.last_fetchall_timestamp
            .map(|last| {
                last.elapsed()
                    // cache for 1 hour
                    .map(|elapsed| elapsed.as_secs() < 3600)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    pub fn set_fetched_all_keys(&mut self, fetched_all_keys: bool) {
        if fetched_all_keys {
            self.last_fetchall_timestamp = Some(SystemTime::now());
        } else {
            self.last_fetchall_timestamp = None;
        }
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.set_fetched_all_keys(false);
        self.objects.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (CK_OBJECT_HANDLE, &Object)> {
        self.objects
            .iter()
            .map(|(handle, object)| (*handle, object))
    }

    pub fn add_object(&mut self, object: Object) -> (CK_OBJECT_HANDLE, Object) {
        // check if the object already exists

        let found = self
            .objects
            .iter_mut()
            .find(|(_, obj)| obj.id == object.id && obj.kind == object.kind);

        if let Some((handle, obj)) = found {
            *obj = object;
            return (*handle, obj.clone());
        }

        // increment the handle

        let handle = self.next_handle;
        self.next_handle += 1;

        self.objects.insert(handle, object);

        (handle, self.objects.get(&handle).unwrap().clone())
    }

    pub fn object(&self, handle: CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.get(&handle)
    }

    pub fn remove(&mut self, handle: CK_OBJECT_HANDLE) -> Option<Object> {
        self.objects.remove(&handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adding_same_object() {
        let mut db = Db::new();
        let mut object = Object::default();

        object.id = "id".to_string();

        let (handle1, object1) = db.add_object(object.clone());
        let (handle2, object2) = db.add_object(object.clone());
        assert_eq!(handle1, handle2);
        assert_eq!(object1.id, object2.id);
    }
}
