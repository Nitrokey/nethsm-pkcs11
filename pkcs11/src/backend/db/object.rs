use base64ct::{Base64, Encoding};
use config_file::CertificateFormat;
// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Nitrokey
// SPDX-License-Identifier: Apache-2.0
use cryptoki_sys::{CK_ULONG, CK_UNAVAILABLE_INFORMATION};
use der::{asn1::OctetString, Decode, DecodePem, Encode};
use log::{debug, error, info, trace, warn};
use nethsm_sdk_rs::models::PublicKey;
use std::collections::HashMap;
use std::mem::size_of;

use crate::{
    backend::{
        key::{EcKeyType, KeyType, NetHSMId, Pkcs11Id},
        mechanism::{KeyMechanism, Mechanism},
        Error, Pkcs11Error,
    },
    ck::{
        CkAttributeType, CkCertificateCategory, CkCertificateType, CkKeyType, CkMechanismType,
        CkObjectClass,
    },
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

    fn from_bool(value: bool) -> Self {
        if value {
            Self::CK_TRUE
        } else {
            Self::CK_FALSE
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

    fn from_ck_key_type(src: CkKeyType) -> Self {
        let src: cryptoki_sys::CK_KEY_TYPE = src.into();
        #[cfg(target_endian = "little")]
        Self::CkKeyType(src.to_le_bytes())
    }

    #[allow(dead_code)]
    fn from_ck_cert_type(src: CkCertificateType) -> Self {
        let src: cryptoki_sys::CK_CERTIFICATE_TYPE = src.into();
        #[cfg(target_endian = "little")]
        Self::CkCertType(src.to_le_bytes())
    }

    #[allow(dead_code)]
    fn from_ck_cert_category(src: CkCertificateCategory) -> Self {
        let src: cryptoki_sys::CK_CERTIFICATE_CATEGORY = src.into();
        #[cfg(target_endian = "little")]
        Self::CkCertCategory(src.to_le_bytes())
    }

    fn from_ck_mechanism_type(src: cryptoki_sys::CK_MECHANISM_TYPE) -> Self {
        #[cfg(target_endian = "little")]
        Self::CkMechanismType(src.to_le_bytes())
    }

    #[allow(dead_code)]
    fn from_ck_mechanism_type_vec(src: Vec<CkMechanismType>) -> Self {
        #[cfg(target_endian = "little")]
        Self::Bytes(
            src.iter()
                .flat_map(|x| cryptoki_sys::CK_MECHANISM_TYPE::from(*x).to_le_bytes())
                .collect(),
        )
    }

    fn from_ck_object_class(src: CkObjectClass) -> Self {
        let src: cryptoki_sys::CK_OBJECT_CLASS = src.into();
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
}

impl TryFrom<CkObjectClass> for ObjectKind {
    type Error = Error;

    fn try_from(class: CkObjectClass) -> Result<Self, Self::Error> {
        Ok(match class {
            CkObjectClass::PrivateKey => Self::PrivateKey,
            CkObjectClass::PublicKey => Self::PublicKey,
            CkObjectClass::SecretKey => Self::SecretKey,
            CkObjectClass::Certificate => Self::Certificate,
            CkObjectClass::Other(value) => {
                warn!("Object class not supported: {value}");
                return Err(Error::ObjectClassNotSupported);
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct Object {
    attrs: HashMap<CkAttributeType, Attr>,
    pub kind: ObjectKind,
    pub id: NetHSMId,
    pub label: String,
    pub size: Option<usize>, // the size of the object in bytes
    pub mechanisms: Vec<KeyMechanism>,
}

impl Object {
    #[cfg(test)]
    pub fn new(id: NetHSMId) -> Self {
        Self {
            id,
            attrs: Default::default(),
            kind: ObjectKind::PrivateKey,
            label: Default::default(),
            size: Default::default(),
            mechanisms: Default::default(),
        }
    }

    pub fn update(&mut self, id: Option<NetHSMId>, label: Option<String>) {
        info!("updating {} with id = {id:?}, label = {label:?}", self.id);
        if let Some(id) = id {
            let id_bytes = Attr::Bytes(Pkcs11Id::from(&id).into_bytes());
            self.attrs.insert(CkAttributeType::Id, id_bytes);
            self.id = id;
        }
        if let Some(label) = label {
            self.attrs.insert(
                CkAttributeType::Label,
                Attr::Bytes(label.clone().into_bytes()),
            );
            self.label = label;
        }
    }
}

struct KeyData {
    key_type: CkKeyType,
    key_size: Option<usize>,
    attrs: HashMap<CkAttributeType, Attr>,
}

fn configure_rsa(key_data: &PublicKey, mechanisms: &[KeyMechanism]) -> Result<KeyData, Error> {
    let key_data = key_data
        .public
        .as_ref()
        .ok_or(Error::KeyField("public".to_string()))?;

    let modulus = key_data
        .modulus
        .as_ref()
        .ok_or(Error::KeyField("modulus".to_string()))?;
    let public_exponent = key_data
        .public_exponent
        .as_ref()
        .ok_or(Error::KeyField("public_exponent".to_string()))?;
    let modulus = Base64::decode_vec(modulus)?;
    let public_exponent = Base64::decode_vec(public_exponent)?;

    let mut attrs = HashMap::new();

    let size = modulus.len();
    attrs.insert(
        CkAttributeType::KeyType,
        Attr::from_ck_key_type(CkKeyType::Rsa),
    );
    attrs.insert(CkAttributeType::Derive, Attr::CK_FALSE);
    attrs.insert(
        CkAttributeType::Decrypt,
        Attr::from_bool(mechanisms.iter().any(KeyMechanism::is_rsa_decryption)),
    );
    attrs.insert(
        CkAttributeType::Sign,
        Attr::from_bool(mechanisms.iter().any(KeyMechanism::is_rsa_signature)),
    );
    attrs.insert(CkAttributeType::SignRecover, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Unwrap, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::WrapWithTrusted, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Modulus, Attr::Bytes(modulus));
    attrs.insert(
        CkAttributeType::PublicExponent,
        Attr::Bytes(public_exponent),
    );
    attrs.insert(
        CkAttributeType::ModulusBits,
        Attr::from_ck_ulong((size * 8) as CK_ULONG),
    );

    Ok(KeyData {
        key_type: CkKeyType::Rsa,
        key_size: Some(size),
        attrs,
    })
}

fn configure_ec(key_data: &PublicKey, key_type: EcKeyType) -> Result<KeyData, Error> {
    let ec_points = key_data
        .public
        .as_ref()
        .ok_or(Error::KeyField("public".to_string()))?
        .data
        .as_ref()
        .ok_or(Error::KeyField("data".to_string()))?;

    let size = key_type.key_size();

    trace!("EC key data: {ec_points:?}");

    let mut ec_point_bytes = Base64::decode_vec(ec_points)?;

    trace!("EC key data bytes length : {}", ec_point_bytes.len());

    // add padding
    while ec_point_bytes.len() < size / 8 {
        ec_point_bytes.insert(0, 0);
    }

    trace!("EC key data bytes: {ec_point_bytes:?}");

    let encoded_points = OctetString::new(ec_point_bytes).unwrap().to_der().unwrap();

    trace!("EC key data encoded len : {}", encoded_points.len());

    let key_params = key_type.to_asn1();
    let ec_params = key_params.to_der().map_err(Error::Der)?;

    let key_type = match key_type {
        EcKeyType::Curve25519 => CkKeyType::EcEdwards,
        _ => CkKeyType::Ec,
    };

    let mut attrs = HashMap::new();

    attrs.insert(CkAttributeType::KeyType, Attr::from_ck_key_type(key_type));
    attrs.insert(CkAttributeType::Derive, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Decrypt, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Sign, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::SignRecover, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Unwrap, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::WrapWithTrusted, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::EcParams, Attr::Bytes(ec_params));
    attrs.insert(CkAttributeType::EcPoint, Attr::Bytes(encoded_points));

    Ok(KeyData {
        key_type,
        key_size: Some(size),
        attrs,
    })
}

// should be an aes key ??
fn configure_generic(mechanisms: &[KeyMechanism]) -> Result<KeyData, Error> {
    let mut attrs = HashMap::new();

    attrs.insert(
        CkAttributeType::Class,
        Attr::from_ck_object_class(CkObjectClass::SecretKey),
    );
    attrs.insert(
        CkAttributeType::KeyType,
        Attr::from_ck_key_type(CkKeyType::GenericSecret),
    );
    attrs.insert(CkAttributeType::Derive, Attr::CK_FALSE);
    attrs.insert(
        CkAttributeType::Decrypt,
        Attr::from_bool(mechanisms.contains(&KeyMechanism::AesDecryptionCbc)),
    );
    attrs.insert(
        CkAttributeType::Encrypt,
        Attr::from_bool(mechanisms.contains(&KeyMechanism::AesEncryptionCbc)),
    );
    attrs.insert(CkAttributeType::Sign, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::SignRecover, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Unwrap, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::WrapWithTrusted, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::ValueLen, Attr::from_ck_ulong(0));
    attrs.insert(CkAttributeType::AlwaysAuthenticate, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Verify, Attr::CK_FALSE);

    Ok(KeyData {
        key_type: CkKeyType::GenericSecret,
        key_size: None,
        attrs,
    })
}

pub fn from_key_data(key_data: PublicKey, id: NetHSMId) -> Result<Vec<Object>, Error> {
    let key_type = KeyType::try_from(key_data.r#type).map_err(|_| {
        error!(
            "Failed to create key with unsupported type {}",
            key_data.r#type
        );
        Error::KeyField(format!("Unsupported key type: {:?}", key_data.r#type))
    })?;

    let mut attrs = HashMap::new();
    attrs.insert(
        CkAttributeType::Class,
        Attr::from_ck_object_class(CkObjectClass::PrivateKey),
    );
    let id_bytes = Attr::Bytes(Pkcs11Id::from(&id).into_bytes());
    attrs.insert(CkAttributeType::Id, id_bytes);
    attrs.insert(
        CkAttributeType::Label,
        Attr::Bytes(
            key_data
                .label
                .clone()
                .map(String::into_bytes)
                .unwrap_or_default(),
        ),
    );
    attrs.insert(CkAttributeType::Local, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Modifiable, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Token, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::AlwaysAuthenticate, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Sensitive, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::AlwaysSensitive, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::Extractable, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::NeverExtractable, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::Private, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::VerifyRecover, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Value, Attr::Bytes(vec![]));
    attrs.insert(CkAttributeType::Trusted, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Wrap, Attr::CK_FALSE);

    let mechanisms: Vec<_> = key_data
        .mechanisms
        .iter()
        .copied()
        .flat_map(TryFrom::try_from)
        .collect();

    let key_attrs = match key_type {
        KeyType::Rsa => configure_rsa(&key_data, &mechanisms)?,
        KeyType::Ec(key_type) => configure_ec(&key_data, key_type)?,
        KeyType::Generic => configure_generic(&mechanisms)?,
    };
    attrs.extend(key_attrs.attrs);

    let ck_mech_list: Vec<_> = mechanisms
        .iter()
        .flat_map(|mech| Mechanism::try_from(*mech).ok())
        .map(|m: Mechanism| m.ck_type())
        .collect();

    attrs.insert(
        CkAttributeType::AllowedMechanisms,
        Attr::from_ck_mechanism_type_vec(ck_mech_list),
    );

    let private_key = Object {
        attrs: attrs.clone(),
        kind: ObjectKind::PrivateKey,
        id: id.clone(),
        label: key_data.label.clone().unwrap_or_default(),
        size: key_attrs.key_size,
        mechanisms,
    };

    if key_type == KeyType::Generic {
        let secret = Object {
            kind: ObjectKind::SecretKey,
            ..private_key
        };

        return Ok(vec![secret]);
    }

    let mut public_key = Object {
        attrs: attrs.clone(),
        kind: ObjectKind::PublicKey,
        id,
        label: key_data.label.unwrap_or_default(),
        size: key_attrs.key_size,
        mechanisms: vec![],
    };

    public_key
        .attrs
        .insert(CkAttributeType::AllowedMechanisms, Attr::Bytes(vec![]));
    public_key.attrs.insert(
        CkAttributeType::Class,
        Attr::from_ck_object_class(CkObjectClass::PublicKey),
    );
    public_key.attrs.insert(
        CkAttributeType::KeyType,
        Attr::from_ck_key_type(key_attrs.key_type),
    );

    public_key
        .attrs
        .insert(CkAttributeType::Private, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Sensitive, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::AlwaysSensitive, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Extractable, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::NeverExtractable, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Decrypt, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Encrypt, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Sign, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Verify, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Derive, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::SignRecover, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Unwrap, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::Wrap, Attr::CK_FALSE);
    public_key
        .attrs
        .insert(CkAttributeType::WrapWithTrusted, Attr::CK_FALSE);

    Ok(vec![public_key, private_key])
}

pub fn from_cert_data(
    key_data: PublicKey,
    cert: Vec<u8>,
    key_id: NetHSMId,
    certificate_format: CertificateFormat,
) -> Result<Object, Error> {
    debug!("Loading certificate, expecting {certificate_format} encoding as per configuration");
    let (cert, cert_der) = match certificate_format {
        CertificateFormat::Der => (
            x509_cert::Certificate::from_der(&cert).map_err(Error::Der)?,
            cert,
        ),
        CertificateFormat::Pem => {
            let mut buf = Vec::new();
            let parsed_cert = x509_cert::Certificate::from_pem(&cert).map_err(Error::Der)?;
            parsed_cert.encode_to_vec(&mut buf).map_err(Error::Der)?;
            (parsed_cert, buf)
        }
    };
    let tbs_cert = cert.tbs_certificate();

    let length = cert_der.len();

    let mut attrs = HashMap::new();
    attrs.insert(
        CkAttributeType::Class,
        Attr::from_ck_object_class(CkObjectClass::Certificate),
    );
    let id_bytes = Attr::Bytes(Pkcs11Id::from(&key_id).into_bytes());
    attrs.insert(CkAttributeType::Id, id_bytes.clone());
    attrs.insert(
        CkAttributeType::Label,
        Attr::Bytes(
            key_data
                .label
                .clone()
                .map(String::into_bytes)
                .unwrap_or_default(),
        ),
    );
    attrs.insert(
        CkAttributeType::KeyGenMechanism,
        Attr::from_ck_mechanism_type(CK_UNAVAILABLE_INFORMATION),
    );
    attrs.insert(CkAttributeType::Local, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::Modifiable, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Token, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::AlwaysAuthenticate, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Sensitive, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::AlwaysSensitive, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::Extractable, Attr::CK_FALSE);
    attrs.insert(CkAttributeType::NeverExtractable, Attr::CK_TRUE);
    attrs.insert(CkAttributeType::Private, Attr::CK_FALSE);
    attrs.insert(
        CkAttributeType::CertificateType,
        Attr::from_ck_cert_type(CkCertificateType::X509),
    );
    attrs.insert(CkAttributeType::Value, Attr::Bytes(cert_der));
    attrs.insert(
        CkAttributeType::ValueLen,
        Attr::from_ck_ulong(length as CK_ULONG),
    );
    attrs.insert(
        CkAttributeType::Subject,
        Attr::Bytes(tbs_cert.subject().to_der().map_err(Error::Der)?),
    );
    attrs.insert(
        CkAttributeType::Issuer,
        Attr::Bytes(tbs_cert.issuer().to_der().map_err(Error::Der)?),
    );
    attrs.insert(
        CkAttributeType::SerialNumber,
        Attr::Bytes(tbs_cert.serial_number().to_der().map_err(Error::Der)?),
    );
    attrs.insert(CkAttributeType::Trusted, Attr::CK_TRUE);
    attrs.insert(
        CkAttributeType::CertificateType,
        Attr::from_ck_cert_type(CkCertificateType::X509),
    );
    attrs.insert(
        CkAttributeType::CertificateCategory,
        Attr::from_ck_cert_category(CkCertificateCategory::Unspecified),
    );

    Ok(Object {
        attrs,
        kind: ObjectKind::Certificate,
        id: key_id,
        label: key_data.label.unwrap_or_default(),
        size: Some(length),
        mechanisms: vec![],
    })
}

impl Object {
    pub fn attr(&self, attr_type: CkAttributeType) -> Option<&Attr> {
        self.attrs.get(&attr_type)
    }

    pub fn fill_attr_template(&self, tpl: &mut CkRawAttrTemplate) -> Result<(), Pkcs11Error> {
        let mut result = Ok(());

        for mut raw_attr in tpl.iter() {
            match self.attr(raw_attr.type_()) {
                Some(attr) => {
                    let sres = match attr {
                        Attr::Sensitive => {
                            result = Err(Pkcs11Error::AttributeSensitive);
                            raw_attr.set_unavailable();
                            continue;
                        }
                        a => raw_attr.set_val_bytes(a.as_bytes()),
                    };
                    if matches!(sres, Err(attr::Error::BufTooSmall)) {
                        result = Err(Pkcs11Error::BufferTooSmall);
                        raw_attr.set_unavailable();
                    }
                }
                None => {
                    // rcode = cryptoki_sys::CKR_CRYPTOKI_ALREADY_INITIALIZED;
                    raw_attr.set_unavailable();
                }
            };
            debug!(
                "fill_attr_template: {:?} | result: {:?}",
                raw_attr.type_(),
                result
            );
        }

        result
    }
}
