use super::db::attr::CkRawAttrTemplate;
use crate::backend::mechanism::Mechanism;
use base64::{engine::general_purpose, Engine};
use cryptoki_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_EC_PARAMS, CKA_ENCRYPT, CKA_ID, CKA_KEY_TYPE, CKA_PRIME_1,
    CKA_PRIME_2, CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_VALUE, CKK_EC, CKK_RSA, CKO_CERTIFICATE,
    CKO_PRIVATE_KEY, CK_KEY_TYPE,
};
use lazy_static::lazy_static;
use log::{debug, trace};
use openapi::{
    apis::{
        configuration::Configuration,
        default_api::{self, KeysKeyIdPutError},
    },
    models::{KeyPrivateData, KeyType, PrivateKey},
};
use yasna::models::ObjectIdentifier;

#[derive(Debug)]
pub enum CreateKeyError {
    MissingAttribute,
    InvalidAttribute,
    ClassNotSupported,
    PutError(openapi::apis::Error<KeysKeyIdPutError>),
    PostError(openapi::apis::Error<default_api::KeysPostError>),
}

impl PartialEq for CreateKeyError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::MissingAttribute, Self::MissingAttribute)
                | (Self::InvalidAttribute, Self::InvalidAttribute)
                | (Self::ClassNotSupported, Self::ClassNotSupported)
                | (Self::PutError(_), Self::PutError(_))
                | (Self::PostError(_), Self::PostError(_))
        )
    }
}

#[derive(Debug)]
enum KeyClass {
    Private,
    Certificate,
}

pub fn create_key_from_template(
    template: CkRawAttrTemplate,
    api_config: &Configuration,
) -> Result<String, CreateKeyError> {
    let mut id = None;
    let mut key_type = None;
    let mut mechanisms = Vec::new();
    let mut sign = true;
    let mut encrypt = true;
    let mut decrypt = true;
    let mut key_class = KeyClass::Private;
    let mut ec_params = None;
    let mut value = None;
    let mut public_exponent = None;
    let mut prime_p = None;
    let mut prime_q = None;

    for attr in template.iter() {
        match attr.type_() {
            CKA_CLASS => match attr.read_value() {
                Some(val) => {
                    key_class = match val {
                        CKO_PRIVATE_KEY => KeyClass::Private,
                        CKO_CERTIFICATE => KeyClass::Certificate,
                        _ => return Err(CreateKeyError::ClassNotSupported),
                    }
                }
                None => return Err(CreateKeyError::InvalidAttribute),
            },
            CKA_ID => {
                id = Some(String::from_utf8(attr.val_bytes().unwrap().to_vec()).unwrap());
            }
            CKA_KEY_TYPE => {
                let ktype: CK_KEY_TYPE = match attr.read_value() {
                    Some(val) => val,
                    None => return Err(CreateKeyError::InvalidAttribute),
                };
                key_type = Some(ktype);
            }
            CKA_EC_PARAMS => {
                ec_params = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_VALUE => {
                value = attr.val_bytes().map(|val| val.to_vec());
            }

            CKA_SIGN => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        sign = true;
                    }
                }
            }
            CKA_ENCRYPT => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        encrypt = true;
                    }
                }
            }
            CKA_DECRYPT => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        decrypt = true;
                    }
                }
            }
            CKA_PUBLIC_EXPONENT => {
                public_exponent = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_PRIME_1 => {
                prime_p = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_PRIME_2 => {
                prime_q = attr.val_bytes().map(|val| val.to_vec());
            }

            _ => {
                debug!("Attribute not supported: {:?}", attr.type_());
            }
        }
    }

    debug!("key_class: {:?}", key_class);
    debug!("key_type: {:?}", key_type);

    let (r#type, key) = match key_type.ok_or(CreateKeyError::InvalidAttribute)? {
        CKK_RSA => {
            trace!("Creating RSA key");

            trace!("prime_p: {:?}", prime_p);
            trace!("prime_q: {:?}", prime_q);
            trace!("public_exponent: {:?}", public_exponent);

            let prime_p =
                general_purpose::STANDARD.encode(prime_p.ok_or(CreateKeyError::MissingAttribute)?);

            let prime_q =
                general_purpose::STANDARD.encode(prime_q.ok_or(CreateKeyError::MissingAttribute)?);

            let public_exponent = general_purpose::STANDARD
                .encode(public_exponent.ok_or(CreateKeyError::MissingAttribute)?);

            let key = Box::new(KeyPrivateData {
                data: None,
                prime_p: Some(prime_p),
                prime_q: Some(prime_q),
                public_exponent: Some(public_exponent),
            });
            (KeyType::Rsa, key)
        }
        CKK_EC => {
            let b64_private = general_purpose::STANDARD.encode(
                value
                    .as_ref()
                    .ok_or(CreateKeyError::MissingAttribute)?
                    .as_slice(),
            );

            let ec_type = key_type_from_params(&ec_params.ok_or(CreateKeyError::MissingAttribute)?)
                .ok_or(CreateKeyError::InvalidAttribute)?;

            let key = Box::new(KeyPrivateData {
                data: Some(b64_private),
                prime_p: None,
                prime_q: None,
                public_exponent: None,
            });

            (ec_type, key)
        }

        _ => return Err(CreateKeyError::InvalidAttribute),
    };

    let mechs = Mechanism::from_key_type(r#type);

    for mech in mechs {
        if sign {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Sign) {
                mechanisms.push(m);
            }
        }
        if encrypt {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Encrypt) {
                mechanisms.push(m);
            }
        }
        if decrypt {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Decrypt) {
                mechanisms.push(m);
            }
        }
    }

    let private_key = PrivateKey {
        mechanisms: mechanisms.clone(),
        r#type,
        key,
        restrictions: None,
    };

    let id = if let Some(key_id) = id {
        default_api::keys_key_id_put(api_config, &key_id, private_key, Some(mechanisms), None)
            .map_err(CreateKeyError::PutError)?;
        key_id
    } else {
        default_api::keys_post(api_config, private_key, Some(mechanisms), None)
            .map_err(CreateKeyError::PostError)?
    };

    Ok(id)
}

lazy_static! {
    static ref KEYTYPE_EC_P224: ObjectIdentifier =
        ObjectIdentifier::from_slice(&[1, 3, 132, 0, 33]);
    static ref KEYTYPE_EC_P256: ObjectIdentifier =
        ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]);
    static ref KEYTYPE_EC_P384: ObjectIdentifier =
        ObjectIdentifier::from_slice(&[1, 3, 132, 0, 34]);
    static ref KEYTYPE_EC_P521: ObjectIdentifier =
        ObjectIdentifier::from_slice(&[1, 3, 132, 0, 35]);
    static ref KEYTYPE_CURVE25519: ObjectIdentifier =
        ObjectIdentifier::from_slice(&[1, 3, 101, 112]);
}
pub fn key_type_to_asn1(key_type: KeyType) -> Option<ObjectIdentifier> {
    Some(match key_type {
        KeyType::EcP224 => (*KEYTYPE_EC_P224).clone(),
        KeyType::EcP256 => (*KEYTYPE_EC_P256).clone(),
        KeyType::EcP384 => (*KEYTYPE_EC_P384).clone(),
        KeyType::EcP521 => (*KEYTYPE_EC_P521).clone(),
        KeyType::Curve25519 => (*KEYTYPE_CURVE25519).clone(),
        _ => return None,
    })
}

fn key_type_from_params(params: &[u8]) -> Option<KeyType> {
    // decode der to ObjectIdentifier
    let oid: ObjectIdentifier = yasna::decode_ber(params).unwrap();

    // we can't do a match on vecs
    if oid == *KEYTYPE_CURVE25519 {
        Some(KeyType::Curve25519)
    } else if oid == *KEYTYPE_EC_P224 {
        Some(KeyType::EcP224)
    } else if oid == *KEYTYPE_EC_P256 {
        Some(KeyType::EcP256)
    } else if oid == *KEYTYPE_EC_P384 {
        Some(KeyType::EcP384)
    } else if oid == *KEYTYPE_EC_P521 {
        Some(KeyType::EcP521)
    } else {
        None
    }
}
