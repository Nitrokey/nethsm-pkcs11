// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Nitrokey
// SPDX-License-Identifier: Apache-2.0

use std::iter::Iterator;

pub enum Error {
    BufTooSmall,
    NullPtrDeref,
}

pub struct CkRawAttr(cryptoki_sys::CK_ATTRIBUTE_PTR);

impl CkRawAttr {
    pub unsafe fn from_raw_ptr_unchecked(ptr: cryptoki_sys::CK_ATTRIBUTE_PTR) -> Self {
        Self(ptr)
    }

    pub fn type_(&self) -> cryptoki_sys::CK_ATTRIBUTE_TYPE {
        unsafe { (*self.0).type_ }
    }

    pub fn val_bytes(&self) -> Option<&[u8]> {
        let val_ptr = unsafe { (*self.0).pValue };
        if val_ptr.is_null() {
            return None;
        }
        unsafe {
            Some(std::slice::from_raw_parts(
                val_ptr as *const u8,
                self.len() as usize,
            ))
        }
    }

    pub fn read_value<T>(&self) -> Option<T> {
        let val_ptr = unsafe { (*self.0).pValue };
        if val_ptr.is_null() {
            return None;
        }
        unsafe { Some(std::ptr::read(val_ptr as *const T)) }
    }

    pub fn len(&self) -> cryptoki_sys::CK_ULONG {
        unsafe { (*self.0).ulValueLen }
    }

    pub fn set_len(&mut self, len: cryptoki_sys::CK_ULONG) {
        unsafe {
            (*self.0).ulValueLen = len;
        }
    }

    pub fn set_val_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        unsafe {
            if (*self.0).pValue.is_null() {
                return Err(Error::NullPtrDeref);
            }
            if bytes.len() > (*self.0).ulValueLen as usize {
                return Err(Error::BufTooSmall);
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*self.0).pValue as *mut u8, bytes.len());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CkRawAttrTemplate {
    ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
    count: usize,
}

impl CkRawAttrTemplate {
    pub unsafe fn from_raw_ptr_unchecked(
        ptr: cryptoki_sys::CK_ATTRIBUTE_PTR,
        count: usize,
    ) -> Self {
        Self { ptr, count }
    }

    pub fn attr_wrapper(&self, index: usize) -> Option<CkRawAttr> {
        if index >= self.count {
            return None;
        }
        Some(unsafe { CkRawAttr::from_raw_ptr_unchecked(self.ptr.add(index)) })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn iter(&self) -> CkRawAttrTemplateIter {
        CkRawAttrTemplateIter {
            tpl: self,
            index: 0,
        }
    }
}

pub struct CkRawAttrTemplateIter<'a> {
    tpl: &'a CkRawAttrTemplate,
    index: usize,
}

impl<'a> Iterator for CkRawAttrTemplateIter<'a> {
    type Item = CkRawAttr;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.tpl.len() {
            let ret = self.tpl.attr_wrapper(self.index);
            self.index += 1;
            ret
        } else {
            None
        }
    }
}
