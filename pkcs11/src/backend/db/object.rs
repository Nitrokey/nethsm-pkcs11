// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cryptoki_sys::{
    CK_C_GetMechanismInfo, CKA_ALLOWED_MECHANISMS, CKA_CLASS, CKA_ID, CKA_KEY_TYPE, CKK_EC,
    CKK_ECDSA, CKK_GENERIC_SECRET, CKK_RSA, CKM_AES_CBC, CK_KEY_TYPE, CK_MECHANISM_TYPE, CK_ULONG,
};
use openapi::models::{KeyMechanism, KeyType, PublicKey};
use std::collections::HashMap;
use std::mem::size_of;

// these were not in the lib
const CK_CERTIFICATE_CATEGORY_UNSPECIFIED: CK_ULONG = 0x00000000;
const CK_CERTIFICATE_CATEGORY_TOKEN_USER: CK_ULONG = 0x00000001;
const CK_CERTIFICATE_CATEGORY_AUTHORITY: CK_ULONG = 0x00000002;
const CK_CERTIFICATE_CATEGORY_OTHER_ENTITY: CK_ULONG = 0x00000003;

use super::{
    attr::{self, CkRawAttrTemplate},
    CertCategory, CertInfo, EcKeyInfo, RsaKeyInfo,
};
use crate::backend::mechanism::Mechanism;

/// Object and object attribute handling logic. See the PKCS#11
/// Section 4 on objects for more details on how these attributes
/// are handled. Each object has a unique handle and
/// a well defined class (i.e. private key, certificate etc.) and
/// based on this class a well defined set of valid attributes.
/// Since there is no R/W session support these objects are created
/// from the user provisioned database.
#[derive(Clone, Copy, Debug, Hash)]
pub struct ObjectHandle(u64);

impl From<cryptoki_sys::CK_OBJECT_HANDLE> for ObjectHandle {
    fn from(src: cryptoki_sys::CK_OBJECT_HANDLE) -> Self {
        Self(src)
    }
}

impl From<usize> for ObjectHandle {
    fn from(src: usize) -> Self {
        Self(src as u64)
    }
}

impl From<u32> for ObjectHandle {
    fn from(src: u32) -> Self {
        Self(src as u64)
    }
}

impl From<ObjectHandle> for u64 {
    fn from(src: ObjectHandle) -> Self {
        src.0
    }
}

impl From<ObjectHandle> for usize {
    fn from(src: ObjectHandle) -> Self {
        src.0 as usize
    }
}

#[derive(Debug, Clone)]
pub enum Attr {
    Bytes(Vec<u8>),
    CkBbool([u8; size_of::<cryptoki_sys::CK_BBOOL>()]),
    CkByte([u8; size_of::<cryptoki_sys::CK_BYTE>()]),
    CkKeyType([u8; size_of::<cryptoki_sys::CK_KEY_TYPE>()]),
    CkCertType([u8; size_of::<cryptoki_sys::CK_CERTIFICATE_TYPE>()]),
    CkCertCategory([u8; size_of::<cryptoki_sys::CK_ULONG>()]),
    CkMechanismType([u8; size_of::<cryptoki_sys::CK_MECHANISM_TYPE>()]),
    CkObjectClass([u8; size_of::<cryptoki_sys::CK_OBJECT_CLASS>()]),
    CkUlong([u8; size_of::<cryptoki_sys::CK_ULONG>()]),
    Sensitive,
}

impl Attr {
    const CK_TRUE: Self = Self::CkBbool([cryptoki_sys::CK_TRUE; 1]);
    const CK_FALSE: Self = Self::CkBbool([cryptoki_sys::CK_FALSE; 1]);

    fn len(&self) -> usize {
        match self {
            Self::CkBbool(v) => v.len(),
            Self::CkByte(v) => v.len(),
            Self::CkKeyType(v) => v.len(),
            Self::CkCertType(v) => v.len(),
            Self::CkCertCategory(v) => v.len(),
            Self::CkMechanismType(v) => v.len(),
            Self::CkObjectClass(v) => v.len(),
            Self::CkUlong(v) => v.len(),
            Self::Bytes(v) => v.len(),
            Self::Sensitive => 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::CkBbool(v) => v,
            Self::CkByte(v) => v,
            Self::CkKeyType(v) => v,
            Self::CkCertType(v) => v,
            Self::CkCertCategory(v) => v,
            Self::CkMechanismType(v) => v,
            Self::CkObjectClass(v) => v,
            Self::CkUlong(v) => v,
            Self::Bytes(v) => v,

            Self::Sensitive => &[0u8; 0],
        }
    }

    fn from_ck_byte(src: cryptoki_sys::CK_BYTE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkByte(src.to_le_bytes())
    }

    fn from_ck_key_type(src: cryptoki_sys::CK_KEY_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkKeyType(src.to_le_bytes())
    }

    fn from_ck_cert_type(src: cryptoki_sys::CK_CERTIFICATE_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkCertType(src.to_le_bytes())
    }
    fn from_ck_cert_category(src: cryptoki_sys::CK_ULONG) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkCertCategory(src.to_le_bytes())
    }

    fn from_ck_mechanism_type(src: cryptoki_sys::CK_MECHANISM_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkMechanismType(src.to_le_bytes())
    }

    fn from_ck_mechanism_type_vec(src: Vec<cryptoki_sys::CK_MECHANISM_TYPE>) -> Self {
        #[cfg(target_endian = "little")]
        Self::Bytes(src.iter().flat_map(|x| x.to_le_bytes()).collect())
    }

    fn from_ck_object_class(src: cryptoki_sys::CK_OBJECT_CLASS) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkObjectClass(src.to_le_bytes())
    }

    fn from_ck_ulong(src: cryptoki_sys::CK_ULONG) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkUlong(src.to_le_bytes())
    }
}

impl PartialEq<Attr> for Attr {
    fn eq(&self, other: &Attr) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

#[derive(Clone, Debug)]
pub enum ObjectKind {
    Mechanism(Mechanism),
    Data,
    Key,
    Certificate,
}

#[derive(Debug, Clone)]
pub struct Object {
    attrs: HashMap<cryptoki_sys::CK_ATTRIBUTE_TYPE, Attr>,
    kind: ObjectKind,
}

impl Object {
    pub fn from_key_data(key_data: PublicKey, id: String) -> Self {
        let mut attrs = HashMap::new();

        attrs.insert(CKA_ID, Attr::Bytes(id.as_bytes().to_vec()));
        attrs.insert(
            CKA_CLASS,
            Attr::from_ck_object_class(cryptoki_sys::CKO_PRIVATE_KEY),
        );

        let key_type: CK_KEY_TYPE = match key_data.r#type {
            KeyType::Rsa => CKK_RSA,
            KeyType::Curve25519 => CKK_EC,
            KeyType::EcP224 => CKK_ECDSA,
            KeyType::EcP256 => CKK_ECDSA,
            KeyType::EcP384 => CKK_ECDSA,
            KeyType::EcP521 => CKK_ECDSA,
            KeyType::Generic => CKK_GENERIC_SECRET,
        };
        attrs.insert(CKA_KEY_TYPE, Attr::from_ck_key_type(key_type));

        let allowed_mechanism: Vec<CK_MECHANISM_TYPE> = key_data
            .mechanisms
            .iter()
            .map(|mech| Mechanism::from_api_mech(mech).ck_type())
            .collect();

        attrs.insert(
            CKA_ALLOWED_MECHANISMS,
            Attr::from_ck_mechanism_type_vec(allowed_mechanism),
        );

        Self {
            attrs,
            kind: ObjectKind::Key,
        }
    }

    pub fn attr(&self, attr_type: cryptoki_sys::CK_ATTRIBUTE_TYPE) -> Option<&Attr> {
        self.attrs.get(&attr_type)
    }

    pub fn kind(&self) -> &ObjectKind {
        &self.kind
    }

    pub fn is_private(&self) -> bool {
        match self.attr(cryptoki_sys::CKA_PRIVATE) {
            Some(attr) => *attr == Attr::CK_TRUE,
            _ => false,
        }
    }

    pub fn is_mechanism(&self) -> bool {
        match self.kind {
            ObjectKind::Mechanism(_) => true,
            _ => false,
        }
    }

    pub fn match_attr_template(&self, tpl: &CkRawAttrTemplate) -> bool {
        let mut class_matched = false;
        for raw_attr in tpl.iter() {
            match self.attr(raw_attr.type_()) {
                Some(attr) => match raw_attr.val_bytes() {
                    Some(raw_bytes) => {
                        if attr.as_bytes() != raw_bytes {
                            return false;
                        }
                    }
                    None => return false,
                },
                None => return false,
            };
            class_matched = class_matched || (raw_attr.type_() == cryptoki_sys::CKA_CLASS);
        }

        // Per the PKCS#11 v2.40 spec, mechanism objects must only match templates that
        // explicitely provide CKA_CLASS = CKO_MECHANISM.
        if self.is_mechanism() {
            class_matched
        } else {
            true
        }
    }

    pub fn fill_attr_template(&self, tpl: &mut CkRawAttrTemplate) -> cryptoki_sys::CK_RV {
        let mut rcode = cryptoki_sys::CKR_OK;

        for mut raw_attr in tpl.iter() {
            match self.attr(raw_attr.type_()) {
                Some(attr) => {
                    let sres = match attr {
                        Attr::Sensitive => {
                            rcode = cryptoki_sys::CKR_ATTRIBUTE_SENSITIVE;
                            raw_attr.set_len(cryptoki_sys::CK_UNAVAILABLE_INFORMATION);
                            continue;
                        }
                        a => raw_attr.set_val_bytes(a.as_bytes()),
                    };
                    match sres {
                        Err(attr::Error::BufTooSmall) => {
                            rcode = cryptoki_sys::CKR_BUFFER_TOO_SMALL;
                            raw_attr.set_len(cryptoki_sys::CK_UNAVAILABLE_INFORMATION);
                        }
                        _ => raw_attr.set_len(attr.len() as cryptoki_sys::CK_ULONG),
                    };
                }
                None => {
                    rcode = cryptoki_sys::CKR_ATTRIBUTE_TYPE_INVALID;
                    raw_attr.set_len(cryptoki_sys::CK_UNAVAILABLE_INFORMATION);
                }
            };
        }
        rcode
    }
}
