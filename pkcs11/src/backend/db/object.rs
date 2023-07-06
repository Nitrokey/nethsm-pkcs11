// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cryptoki_sys::CK_ULONG;
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

#[derive(Clone)]
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
    RsaPrivateKey(String),
    RsaPublicKey(String),
    EcPrivateKey(String),
    EcPublicKey(String),
    Certificate,
    Mechanism(Mechanism),
}

#[derive(Clone)]
pub struct Object {
    attrs: HashMap<cryptoki_sys::CK_ATTRIBUTE_TYPE, Attr>,
    kind: ObjectKind,
}

impl Object {
    pub fn new_mechanism(mech: Mechanism) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(
            cryptoki_sys::CKA_CLASS,
            Attr::from_ck_object_class(cryptoki_sys::CKO_MECHANISM),
        );
        attrs.insert(
            cryptoki_sys::CKA_MECHANISM_TYPE,
            Attr::from_ck_mechanism_type(mech.ck_type()),
        );
        Self {
            kind: ObjectKind::Mechanism(mech),
            attrs,
        }
    }

    pub fn new_rsa_private_key(info: RsaKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(
            cryptoki_sys::CKA_CLASS,
            Attr::from_ck_object_class(cryptoki_sys::CKO_PRIVATE_KEY),
        );
        attrs.insert(
            cryptoki_sys::CKA_KEY_TYPE,
            Attr::from_ck_key_type(cryptoki_sys::CKK_RSA),
        );
        attrs.insert(cryptoki_sys::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(cryptoki_sys::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(cryptoki_sys::CKA_PRIVATE, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_ALWAYS_AUTHENTICATE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_SENSITIVE, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_EXTRACTABLE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_SIGN, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_DECRYPT, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(
            cryptoki_sys::CKA_MODULUS_BITS,
            Attr::from_ck_ulong(info.num_bits),
        );
        attrs.insert(cryptoki_sys::CKA_MODULUS, Attr::Bytes(info.modulus));
        attrs.insert(
            cryptoki_sys::CKA_PUBLIC_EXPONENT,
            Attr::Bytes(info.public_exponent),
        );
        attrs.insert(cryptoki_sys::CKA_PRIVATE_EXPONENT, Attr::Sensitive);
        attrs.insert(cryptoki_sys::CKA_PRIME_1, Attr::Sensitive);
        attrs.insert(cryptoki_sys::CKA_PRIME_2, Attr::Sensitive);
        attrs.insert(cryptoki_sys::CKA_EXPONENT_1, Attr::Sensitive);
        attrs.insert(cryptoki_sys::CKA_EXPONENT_2, Attr::Sensitive);
        attrs.insert(cryptoki_sys::CKA_COEFFICIENT, Attr::Sensitive);
        Self {
            kind: ObjectKind::RsaPrivateKey(info.priv_pem),
            attrs,
        }
    }

    pub fn new_rsa_public_key(info: RsaKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(
            cryptoki_sys::CKA_CLASS,
            Attr::from_ck_object_class(cryptoki_sys::CKO_PUBLIC_KEY),
        );
        attrs.insert(
            cryptoki_sys::CKA_KEY_TYPE,
            Attr::from_ck_key_type(cryptoki_sys::CKK_RSA),
        );
        attrs.insert(cryptoki_sys::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(cryptoki_sys::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(cryptoki_sys::CKA_PRIVATE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_SENSITIVE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_EXTRACTABLE, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_VERIFY, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_ENCRYPT, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(
            cryptoki_sys::CKA_MODULUS_BITS,
            Attr::from_ck_ulong(info.num_bits),
        );
        attrs.insert(cryptoki_sys::CKA_MODULUS, Attr::Bytes(info.modulus));
        attrs.insert(
            cryptoki_sys::CKA_PUBLIC_EXPONENT,
            Attr::Bytes(info.public_exponent),
        );
        Self {
            kind: ObjectKind::RsaPublicKey(info.priv_pem),
            attrs,
        }
    }

    pub fn new_ec_private_key(info: EcKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(
            cryptoki_sys::CKA_CLASS,
            Attr::from_ck_object_class(cryptoki_sys::CKO_PRIVATE_KEY),
        );
        attrs.insert(
            cryptoki_sys::CKA_KEY_TYPE,
            Attr::from_ck_key_type(cryptoki_sys::CKK_EC),
        );
        attrs.insert(cryptoki_sys::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(cryptoki_sys::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(cryptoki_sys::CKA_PRIVATE, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_SENSITIVE, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_EXTRACTABLE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_SIGN, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_DECRYPT, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_EC_PARAMS, Attr::Bytes(info.params_x962));
        attrs.insert(cryptoki_sys::CKA_EC_POINT, Attr::Bytes(info.point_q_x962));
        attrs.insert(cryptoki_sys::CKA_VALUE, Attr::Sensitive);
        Self {
            kind: ObjectKind::EcPrivateKey(info.priv_pem),
            attrs,
        }
    }

    pub fn new_ec_public_key(info: EcKeyInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(
            cryptoki_sys::CKA_CLASS,
            Attr::from_ck_object_class(cryptoki_sys::CKO_PUBLIC_KEY),
        );
        attrs.insert(
            cryptoki_sys::CKA_KEY_TYPE,
            Attr::from_ck_key_type(cryptoki_sys::CKK_EC),
        );
        attrs.insert(cryptoki_sys::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(cryptoki_sys::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(cryptoki_sys::CKA_PRIVATE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_SENSITIVE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_EXTRACTABLE, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_VERIFY, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_ENCRYPT, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_DERIVE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_WRAP, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_LOCAL, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_EC_PARAMS, Attr::Bytes(info.params_x962));
        attrs.insert(cryptoki_sys::CKA_EC_POINT, Attr::Bytes(info.point_q_x962));
        Self {
            kind: ObjectKind::EcPublicKey(info.priv_pem),
            attrs,
        }
    }

    pub fn new_x509_cert(info: CertInfo) -> Self {
        let mut attrs = HashMap::new();
        attrs.insert(
            cryptoki_sys::CKA_CLASS,
            Attr::from_ck_object_class(cryptoki_sys::CKO_CERTIFICATE),
        );
        attrs.insert(
            cryptoki_sys::CKA_CERTIFICATE_TYPE,
            Attr::from_ck_cert_type(cryptoki_sys::CKC_X_509),
        );
        let categ = match info.categ {
            CertCategory::Unverified => CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
            CertCategory::Token => CK_CERTIFICATE_CATEGORY_TOKEN_USER,
            CertCategory::Authority => CK_CERTIFICATE_CATEGORY_AUTHORITY,
            CertCategory::Other => CK_CERTIFICATE_CATEGORY_OTHER_ENTITY,
        };
        attrs.insert(
            cryptoki_sys::CKA_CERTIFICATE_CATEGORY,
            Attr::from_ck_cert_category(categ),
        );
        attrs.insert(cryptoki_sys::CKA_ID, Attr::from_ck_byte(info.id));
        attrs.insert(cryptoki_sys::CKA_LABEL, Attr::Bytes(info.label.into()));
        attrs.insert(cryptoki_sys::CKA_TOKEN, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_SENSITIVE, Attr::CK_FALSE);
        attrs.insert(cryptoki_sys::CKA_EXTRACTABLE, Attr::CK_TRUE);
        attrs.insert(cryptoki_sys::CKA_TRUSTED, Attr::CK_TRUE);
        attrs.insert(
            cryptoki_sys::CKA_SUBJECT,
            Attr::Bytes(info.subject_der.into()),
        );
        attrs.insert(
            cryptoki_sys::CKA_ISSUER,
            Attr::Bytes(info.issuer_der.into()),
        );
        attrs.insert(
            cryptoki_sys::CKA_SERIAL_NUMBER,
            Attr::Bytes(info.serno_der.into()),
        );
        attrs.insert(cryptoki_sys::CKA_VALUE, Attr::Bytes(info.cert_der.into()));
        Self {
            kind: ObjectKind::Certificate,
            attrs,
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
