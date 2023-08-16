// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Nitrokey
// SPDX-License-Identifier: Apache-2.0
use base64::{engine::general_purpose, Engine as _};

use cryptoki_sys::{
    CKA_ALWAYS_AUTHENTICATE, CKA_ALWAYS_SENSITIVE, CKA_CERTIFICATE_CATEGORY, CKA_CERTIFICATE_TYPE,
    CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT, CKA_EXTRACTABLE,
    CKA_ID, CKA_ISSUER, CKA_KEY_GEN_MECHANISM, CKA_KEY_TYPE, CKA_LABEL, CKA_LOCAL, CKA_MODIFIABLE,
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_NEVER_EXTRACTABLE, CKA_PRIVATE, CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE, CKA_SIGN, CKA_SIGN_RECOVER, CKA_SUBJECT, CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP,
    CKA_VALUE, CKA_VALUE_LEN, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP, CKA_WRAP_WITH_TRUSTED,
    CKC_X_509, CK_ATTRIBUTE_TYPE, CK_KEY_TYPE, CK_OBJECT_CLASS, CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
};
use log::{debug, trace};
use nethsm_sdk_rs::models::{KeyMechanism, KeyType, PublicKey};
use std::collections::HashMap;
use std::mem::size_of;

use crate::backend::{
    key::{key_size, key_type_to_asn1},
    Error,
};

use super::attr::{self, CkRawAttrTemplate};

/// Object and object attribute handling logic. See the PKCS#11
/// Section 4 on objects for more details on how these attributes
/// are handled. Each object has a unique handle and
/// a well defined class (i.e. private key, certificate etc.) and
/// based on this class a well defined set of valid attributes.
/// Since there is no R/W session support these objects are created
/// from the user provisioned database.

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
    #[allow(dead_code)]
    Sensitive,
}

impl Attr {
    const CK_TRUE: Self = Self::CkBbool([cryptoki_sys::CK_TRUE; 1]);
    const CK_FALSE: Self = Self::CkBbool([cryptoki_sys::CK_FALSE; 1]);

    pub fn len(&self) -> usize {
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

    pub fn as_bytes(&self) -> &[u8] {
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

    #[allow(dead_code)]
    fn from_ck_byte(src: cryptoki_sys::CK_BYTE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkByte(src.to_le_bytes())
    }

    fn from_ck_key_type(src: cryptoki_sys::CK_KEY_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkKeyType(src.to_le_bytes())
    }

    #[allow(dead_code)]
    fn from_ck_cert_type(src: cryptoki_sys::CK_CERTIFICATE_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkCertType(src.to_le_bytes())
    }

    #[allow(dead_code)]
    fn from_ck_cert_category(src: cryptoki_sys::CK_ULONG) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkCertCategory(src.to_le_bytes())
    }

    fn from_ck_mechanism_type(src: cryptoki_sys::CK_MECHANISM_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkMechanismType(src.to_le_bytes())
    }

    #[allow(dead_code)]
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ObjectKind {
    PrivateKey,
    PublicKey,
    SecretKey,
    Certificate,
    Other,
}

impl From<CK_OBJECT_CLASS> for ObjectKind {
    fn from(src: CK_OBJECT_CLASS) -> Self {
        match src {
            cryptoki_sys::CKO_PRIVATE_KEY => Self::PrivateKey,
            cryptoki_sys::CKO_PUBLIC_KEY => Self::PublicKey,
            cryptoki_sys::CKO_SECRET_KEY => Self::SecretKey,
            cryptoki_sys::CKO_CERTIFICATE => Self::Certificate,
            _ => Self::Other,
        }
    }
}

impl From<ObjectKind> for CK_OBJECT_CLASS {
    fn from(src: ObjectKind) -> Self {
        match src {
            ObjectKind::PrivateKey => cryptoki_sys::CKO_PRIVATE_KEY,
            ObjectKind::PublicKey => cryptoki_sys::CKO_PUBLIC_KEY,
            ObjectKind::SecretKey => cryptoki_sys::CKO_SECRET_KEY,
            ObjectKind::Certificate => cryptoki_sys::CKO_CERTIFICATE,
            ObjectKind::Other => cryptoki_sys::CKO_DATA,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Object {
    attrs: HashMap<cryptoki_sys::CK_ATTRIBUTE_TYPE, Attr>,
    pub kind: ObjectKind,
    pub id: String,
    pub size: Option<usize>, // the size of the object in bytes
    pub mechanisms: Vec<KeyMechanism>,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: Object,
    pub private_key: Object,
}

struct KeyData {
    key_type: CK_KEY_TYPE,
    key_size: Option<usize>,
    attrs: HashMap<CK_ATTRIBUTE_TYPE, Attr>,
}

fn configure_rsa(key_data: &PublicKey) -> Result<KeyData, Error> {
    let key_data = key_data
        .key
        .as_ref()
        .ok_or(Error::KeyField("key".to_string()))?;

    let modulus = key_data
        .modulus
        .as_ref()
        .ok_or(Error::KeyField("modulus".to_string()))?;
    let public_exponent = key_data
        .public_exponent
        .as_ref()
        .ok_or(Error::KeyField("public_exponent".to_string()))?;
    let modulus = general_purpose::STANDARD.decode(modulus.as_bytes())?;
    let public_exponent = general_purpose::STANDARD.decode(public_exponent.as_bytes())?;

    let mut attrs = HashMap::new();

    let size = modulus.len();
    attrs.insert(CKA_KEY_TYPE, Attr::from_ck_key_type(cryptoki_sys::CKK_RSA));
    attrs.insert(CKA_DERIVE, Attr::CK_FALSE);
    attrs.insert(CKA_DECRYPT, Attr::CK_TRUE);
    attrs.insert(CKA_SIGN, Attr::CK_TRUE);
    attrs.insert(CKA_SIGN_RECOVER, Attr::CK_FALSE);
    attrs.insert(CKA_UNWRAP, Attr::CK_FALSE);
    attrs.insert(CKA_WRAP_WITH_TRUSTED, Attr::CK_FALSE);
    attrs.insert(CKA_MODULUS, Attr::Bytes(modulus));
    attrs.insert(CKA_PUBLIC_EXPONENT, Attr::Bytes(public_exponent));
    attrs.insert(
        CKA_MODULUS_BITS,
        Attr::from_ck_ulong((size * 8) as CK_ULONG),
    );

    Ok(KeyData {
        key_type: cryptoki_sys::CKK_RSA,
        key_size: Some(size),
        attrs,
    })
}

fn configure_ec(key_data: &PublicKey) -> Result<KeyData, Error> {
    let ec_points = key_data
        .key
        .as_ref()
        .ok_or(Error::KeyField("key".to_string()))?
        .data
        .as_ref()
        .ok_or(Error::KeyField("data".to_string()))?;

    let size = key_size(&key_data.r#type).ok_or(Error::KeyField("type".to_string()))?;

    trace!("EC key data: {:?}", ec_points);

    let mut ec_point_bytes = general_purpose::STANDARD.decode(ec_points)?;

    trace!("EC key data bytes length : {}", ec_point_bytes.len());

    // add padding
    while ec_point_bytes.len() < size {
        ec_point_bytes.insert(0, 0);
    }

    trace!("EC key data bytes: {:?}", ec_point_bytes);

    let encoded_points = yasna::construct_der(|writer| {
        writer.write_bytes(&ec_point_bytes);
    });

    trace!("EC key data encoded len : {}", encoded_points.len());

    let key_params = key_type_to_asn1(key_data.r#type).ok_or(Error::KeyField(format!(
        "Unsupported key type: {:?}",
        key_data.r#type
    )))?;

    let ec_params = yasna::construct_der(|writer| {
        writer.write_oid(&key_params);
    });

    let key_type = match key_data.r#type {
        KeyType::Curve25519 => cryptoki_sys::CKK_EC_EDWARDS,
        _ => cryptoki_sys::CKK_EC,
    };

    let mut attrs = HashMap::new();

    attrs.insert(CKA_KEY_TYPE, Attr::from_ck_key_type(key_type));
    attrs.insert(CKA_DERIVE, Attr::CK_TRUE);
    attrs.insert(CKA_DECRYPT, Attr::CK_FALSE);
    attrs.insert(CKA_SIGN, Attr::CK_TRUE);
    attrs.insert(CKA_SIGN_RECOVER, Attr::CK_FALSE);
    attrs.insert(CKA_UNWRAP, Attr::CK_FALSE);
    attrs.insert(CKA_WRAP_WITH_TRUSTED, Attr::CK_FALSE);
    attrs.insert(CKA_EC_PARAMS, Attr::Bytes(ec_params));
    attrs.insert(CKA_EC_POINT, Attr::Bytes(encoded_points));

    Ok(KeyData {
        key_type,
        key_size: Some(size),
        attrs,
    })
}

// should be an aes key ??
fn configure_generic() -> Result<KeyData, Error> {
    let mut attrs = HashMap::new();

    attrs.insert(
        CKA_CLASS,
        Attr::from_ck_object_class(cryptoki_sys::CKO_SECRET_KEY),
    );
    attrs.insert(
        CKA_KEY_TYPE,
        Attr::from_ck_key_type(cryptoki_sys::CKK_GENERIC_SECRET),
    );
    attrs.insert(CKA_DERIVE, Attr::CK_FALSE);
    attrs.insert(CKA_DECRYPT, Attr::CK_TRUE);
    attrs.insert(CKA_ENCRYPT, Attr::CK_TRUE);
    attrs.insert(CKA_SIGN, Attr::CK_FALSE);
    attrs.insert(CKA_SIGN_RECOVER, Attr::CK_FALSE);
    attrs.insert(CKA_UNWRAP, Attr::CK_FALSE);
    attrs.insert(CKA_WRAP_WITH_TRUSTED, Attr::CK_FALSE);
    attrs.insert(CKA_VALUE_LEN, Attr::from_ck_ulong(0));
    attrs.insert(CKA_ALWAYS_AUTHENTICATE, Attr::CK_FALSE);

    Ok(KeyData {
        key_type: cryptoki_sys::CKK_GENERIC_SECRET,
        key_size: None,
        attrs,
    })
}

pub fn from_key_data(
    key_data: PublicKey,
    id: &str,
    raw_id: Option<Vec<u8>>,
) -> Result<Vec<Object>, Error> {
    let mut attrs = HashMap::new();

    if let Some(raw_id) = raw_id {
        attrs.insert(CKA_ID, Attr::Bytes(raw_id));
    } else {
        attrs.insert(CKA_ID, Attr::Bytes(id.as_bytes().to_vec()));
    }

    attrs.insert(
        CKA_CLASS,
        Attr::from_ck_object_class(cryptoki_sys::CKO_PRIVATE_KEY),
    );
    attrs.insert(CKA_LABEL, Attr::Bytes(id.as_bytes().to_vec()));
    attrs.insert(
        CKA_KEY_GEN_MECHANISM,
        Attr::from_ck_mechanism_type(CK_UNAVAILABLE_INFORMATION),
    );
    attrs.insert(CKA_LOCAL, Attr::CK_FALSE);
    attrs.insert(CKA_MODIFIABLE, Attr::CK_FALSE);
    attrs.insert(CKA_TOKEN, Attr::CK_TRUE);
    attrs.insert(CKA_ALWAYS_AUTHENTICATE, Attr::CK_FALSE);
    attrs.insert(CKA_SENSITIVE, Attr::CK_TRUE);
    attrs.insert(CKA_ALWAYS_SENSITIVE, Attr::CK_TRUE);
    attrs.insert(CKA_EXTRACTABLE, Attr::CK_FALSE);
    attrs.insert(CKA_NEVER_EXTRACTABLE, Attr::CK_TRUE);
    attrs.insert(CKA_PRIVATE, Attr::CK_TRUE);
    attrs.insert(CKA_VERIFY_RECOVER, Attr::CK_FALSE);
    attrs.insert(CKA_VALUE, Attr::Bytes(vec![]));
    attrs.insert(CKA_TRUSTED, Attr::CK_FALSE);
    attrs.insert(CKA_WRAP, Attr::CK_FALSE);

    let key_attrs = match key_data.r#type {
        KeyType::Rsa => configure_rsa(&key_data)?,
        KeyType::Curve25519
        | KeyType::EcP224
        | KeyType::EcP256
        | KeyType::EcP384
        | KeyType::EcP521 => configure_ec(&key_data)?,
        KeyType::Generic => configure_generic()?,
    };
    attrs.extend(key_attrs.attrs);

    let private_key = Object {
        attrs: attrs.clone(),
        kind: ObjectKind::PrivateKey,
        id: id.to_string(),
        size: key_attrs.key_size,
        mechanisms: key_data.mechanisms.clone(),
    };

    if key_data.r#type == KeyType::Generic {
        let secret = Object {
            kind: ObjectKind::SecretKey,
            ..private_key
        };

        return Ok(vec![secret]);
    }

    let mut public_key = Object {
        attrs: attrs.clone(),
        kind: ObjectKind::PublicKey,
        id: id.to_string(),
        size: key_attrs.key_size,
        mechanisms: vec![],
    };

    public_key.attrs.insert(
        CKA_CLASS,
        Attr::from_ck_object_class(cryptoki_sys::CKO_PUBLIC_KEY),
    );
    public_key
        .attrs
        .insert(CKA_KEY_TYPE, Attr::from_ck_key_type(key_attrs.key_type));

    public_key.attrs.insert(CKA_PRIVATE, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_SENSITIVE, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CKA_ALWAYS_SENSITIVE, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_EXTRACTABLE, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CKA_NEVER_EXTRACTABLE, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_DECRYPT, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_ENCRYPT, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_SIGN, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_VERIFY, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_DERIVE, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_SIGN_RECOVER, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_UNWRAP, Attr::CK_FALSE);
    public_key.attrs.insert(CKA_WRAP, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CKA_WRAP_WITH_TRUSTED, Attr::CK_FALSE);

    Ok(vec![public_key, private_key])
}

pub fn from_cert_data(
    cert: String,
    key_id: &str,
    raw_id: Option<Vec<u8>>,
) -> Result<Object, Error> {
    let openssl_cert = openssl::x509::X509::from_pem(cert.as_bytes())?;

    let cert_der = openssl_cert.to_der()?.to_vec();

    let length = cert_der.len();

    let mut attrs = HashMap::new();
    if let Some(raw_id) = raw_id {
        attrs.insert(CKA_ID, Attr::Bytes(raw_id));
    } else {
        attrs.insert(CKA_ID, Attr::Bytes(key_id.as_bytes().to_vec()));
    }
    attrs.insert(
        CKA_CLASS,
        Attr::from_ck_object_class(cryptoki_sys::CKO_CERTIFICATE),
    );
    attrs.insert(CKA_LABEL, Attr::Bytes(key_id.as_bytes().to_vec()));
    attrs.insert(
        CKA_KEY_GEN_MECHANISM,
        Attr::from_ck_mechanism_type(CK_UNAVAILABLE_INFORMATION),
    );
    attrs.insert(CKA_LOCAL, Attr::CK_TRUE);
    attrs.insert(CKA_MODIFIABLE, Attr::CK_FALSE);
    attrs.insert(CKA_TOKEN, Attr::CK_TRUE);
    attrs.insert(CKA_ALWAYS_AUTHENTICATE, Attr::CK_FALSE);
    attrs.insert(CKA_SENSITIVE, Attr::CK_FALSE);
    attrs.insert(CKA_ALWAYS_SENSITIVE, Attr::CK_FALSE);
    attrs.insert(CKA_EXTRACTABLE, Attr::CK_FALSE);
    attrs.insert(CKA_NEVER_EXTRACTABLE, Attr::CK_TRUE);
    attrs.insert(CKA_PRIVATE, Attr::CK_FALSE);
    attrs.insert(
        CKA_CERTIFICATE_TYPE,
        Attr::from_ck_cert_type(cryptoki_sys::CKC_X_509),
    );
    attrs.insert(CKA_VALUE, Attr::Bytes(cert_der));
    attrs.insert(CKA_VALUE_LEN, Attr::from_ck_ulong(length as CK_ULONG));
    attrs.insert(
        CKA_SUBJECT,
        Attr::Bytes(openssl_cert.subject_name().to_der()?),
    );
    attrs.insert(
        CKA_ISSUER,
        Attr::Bytes(openssl_cert.issuer_name().to_der()?),
    );
    attrs.insert(CKA_TRUSTED, Attr::CK_TRUE);
    attrs.insert(CKA_CERTIFICATE_TYPE, Attr::from_ck_cert_type(CKC_X_509));
    attrs.insert(CKA_CERTIFICATE_CATEGORY, Attr::from_ck_cert_category(0));

    Ok(Object {
        attrs,
        kind: ObjectKind::Certificate,
        id: key_id.to_owned(),
        size: Some(length),
        mechanisms: vec![],
    })
}

impl Object {
    pub fn attr(&self, attr_type: cryptoki_sys::CK_ATTRIBUTE_TYPE) -> Option<&Attr> {
        self.attrs.get(&attr_type)
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
            debug!(
                "fill_attr_template: {:?} | code : {:?}",
                raw_attr.type_(),
                rcode
            );
        }
        rcode
    }
}
