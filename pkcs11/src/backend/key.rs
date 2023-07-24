use super::db::attr::CkRawAttrTemplate;
use crate::backend::{db::object::ObjectKind, mechanism::Mechanism};
use base64::{engine::general_purpose, Engine};
use cryptoki_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_EC_PARAMS, CKA_ENCRYPT, CKA_ID, CKA_KEY_TYPE, CKA_LABEL,
    CKA_MODULUS_BITS, CKA_PRIME_1, CKA_PRIME_2, CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_VALUE,
    CKA_VALUE_LEN, CKK_EC, CKK_GENERIC_SECRET, CKK_RSA, CK_KEY_TYPE, CK_OBJECT_CLASS, CK_ULONG,
};
use lazy_static::lazy_static;
use log::{debug, error, trace};
use openapi::{
    apis::{
        configuration::Configuration,
        default_api::{self, KeysKeyIdPutError},
    },
    models::{KeyGenerateRequestData, KeyPrivateData, KeyType, PrivateKey},
};
use yasna::models::ObjectIdentifier;

#[derive(Debug)]
pub enum CreateKeyError {
    MissingAttribute,
    InvalidAttribute,
    ClassNotSupported,
    PutCertError(openapi::apis::Error<default_api::KeysKeyIdCertPutError>),
    PutError(openapi::apis::Error<KeysKeyIdPutError>),
    PostError(openapi::apis::Error<default_api::KeysPostError>),
    GenerateError(openapi::apis::Error<default_api::KeysGeneratePostError>),
    StringParseError(std::string::FromUtf8Error),
    OpenSSL(openssl::error::ErrorStack),
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

#[derive(Debug, Default)]
struct ParsedAttributes {
    pub id: Option<String>,
    pub key_type: Option<CK_KEY_TYPE>,
    pub sign: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub key_class: Option<ObjectKind>,
    pub ec_params: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
    pub public_exponent: Option<Vec<u8>>,
    pub prime_p: Option<Vec<u8>>,
    pub prime_q: Option<Vec<u8>>,
    pub value_len: Option<CK_ULONG>,
    pub modulus_bits: Option<CK_ULONG>,
}

fn parse_attributes(template: &CkRawAttrTemplate) -> Result<ParsedAttributes, CreateKeyError> {
    let mut parsed = ParsedAttributes::default();

    for attr in template.iter() {
        let t = attr.type_();

        debug!("attr: {:?}, value: {:?}", t, attr.val_bytes());

        match t {
            CKA_CLASS => match attr.read_value::<CK_OBJECT_CLASS>() {
                Some(val) => {
                    parsed.key_class = match ObjectKind::from(val) {
                        ObjectKind::Other => {
                            debug!("Class not supported: {:?}", val);
                            None
                        }

                        k => Some(k),
                    }
                }
                None => return Err(CreateKeyError::InvalidAttribute),
            },
            CKA_ID => {
                if let Some(bytes) = attr.val_bytes() {
                    let str_result = String::from_utf8(bytes.to_vec());
                    let mut output = None;
                    if let Ok(str) = str_result {
                        // check if the string contains only alphanumeric characters
                        if str.chars().all(|c| c.is_alphanumeric()) {
                            output = Some(str);
                        }
                    }

                    if output.is_none() {
                        // store as hex value string
                        output = Some(hex::encode(bytes));
                    }
                    parsed.id = output;
                }
            }
            CKA_LABEL => {
                let label = attr
                    .val_bytes()
                    .map(|val| String::from_utf8(val.to_vec()))
                    .transpose()
                    .map_err(CreateKeyError::StringParseError)?;
                trace!("label: {:?}", label);
                if parsed.id.is_none() {
                    parsed.id = label;
                }
            }

            CKA_KEY_TYPE => {
                let ktype: CK_KEY_TYPE = match attr.read_value() {
                    Some(val) => val,
                    None => return Err(CreateKeyError::InvalidAttribute),
                };
                parsed.key_type = Some(ktype);
            }
            CKA_EC_PARAMS => {
                parsed.ec_params = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_VALUE => {
                parsed.value = attr.val_bytes().map(|val| val.to_vec());
            }

            CKA_SIGN => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        parsed.sign = true;
                    }
                }
            }
            CKA_ENCRYPT => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        parsed.encrypt = true;
                    }
                }
            }
            CKA_DECRYPT => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        parsed.decrypt = true;
                    }
                }
            }
            CKA_PUBLIC_EXPONENT => {
                parsed.public_exponent = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_PRIME_1 => {
                parsed.prime_p = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_PRIME_2 => {
                parsed.prime_q = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_VALUE_LEN => {
                parsed.value_len = attr.read_value();
            }
            CKA_MODULUS_BITS => {
                parsed.modulus_bits = attr.read_value();

                trace!("modulus_bits: {:?}", parsed.modulus_bits)
            }

            _ => {
                debug!("Attribute not supported: {:?}", attr.type_());
            }
        }
    }

    Ok(parsed)
}

fn upload_certificate(
    parsed_template: &ParsedAttributes,
    api_config: &Configuration,
) -> Result<(String, ObjectKind), CreateKeyError> {
    let cert = parsed_template
        .value
        .as_ref()
        .ok_or(CreateKeyError::MissingAttribute)?;

    let openssl_cert = openssl::x509::X509::from_der(cert).map_err(CreateKeyError::OpenSSL)?;

    let id = match parsed_template.id {
        Some(ref id) => id.clone(),
        None => {
            error!("A key ID is required");
            return Err(CreateKeyError::MissingAttribute);
        }
    };

    let cert_file = openssl_cert.to_pem().map_err(CreateKeyError::OpenSSL)?;

    let body = String::from_utf8(cert_file).map_err(CreateKeyError::StringParseError)?;

    default_api::keys_key_id_cert_put(api_config, &id, &body)
        .map_err(CreateKeyError::PutCertError)?;

    Ok((id, ObjectKind::Certificate))
}

pub fn create_key_from_template(
    template: CkRawAttrTemplate,
    api_config: &Configuration,
) -> Result<(String, ObjectKind), CreateKeyError> {
    let parsed = parse_attributes(&template)?;

    debug!("key_class: {:?}", parsed.key_class);
    debug!("key_type: {:?}", parsed.key_type);

    let key_class = if let Some(ref key_class) = parsed.key_class {
        let key_class = key_class.clone();
        if key_class == ObjectKind::Other && key_class == ObjectKind::PublicKey {
            return Err(CreateKeyError::ClassNotSupported);
        }
        key_class
    } else {
        return Err(CreateKeyError::ClassNotSupported);
    };

    if key_class == ObjectKind::Certificate {
        return upload_certificate(&parsed, api_config);
    }

    let (r#type, key) = match parsed.key_type.ok_or(CreateKeyError::InvalidAttribute)? {
        CKK_RSA => {
            trace!("Creating RSA key");

            trace!("prime_p: {:?}", parsed.prime_p);
            trace!("prime_q: {:?}", parsed.prime_q);
            trace!("public_exponent: {:?}", parsed.public_exponent);

            let prime_p = general_purpose::STANDARD
                .encode(parsed.prime_p.ok_or(CreateKeyError::MissingAttribute)?);

            let prime_q = general_purpose::STANDARD
                .encode(parsed.prime_q.ok_or(CreateKeyError::MissingAttribute)?);

            let public_exponent = general_purpose::STANDARD.encode(
                parsed
                    .public_exponent
                    .ok_or(CreateKeyError::MissingAttribute)?,
            );

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
                parsed
                    .value
                    .as_ref()
                    .ok_or(CreateKeyError::MissingAttribute)?
                    .as_slice(),
            );

            let ec_type =
                key_type_from_params(&parsed.ec_params.ok_or(CreateKeyError::MissingAttribute)?)
                    .ok_or(CreateKeyError::InvalidAttribute)?;

            let key = Box::new(KeyPrivateData {
                data: Some(b64_private),
                prime_p: None,
                prime_q: None,
                public_exponent: None,
            });

            (ec_type, key)
        }
        CKK_GENERIC_SECRET => {
            let b64_private = general_purpose::STANDARD.encode(
                parsed
                    .value
                    .as_ref()
                    .ok_or(CreateKeyError::MissingAttribute)?
                    .as_slice(),
            );

            let key = Box::new(KeyPrivateData {
                data: Some(b64_private),
                prime_p: None,
                prime_q: None,
                public_exponent: None,
            });
            (KeyType::Generic, key)
        }

        _ => return Err(CreateKeyError::InvalidAttribute),
    };

    let mechs = Mechanism::from_key_type(r#type);

    let mut mechanisms = vec![];

    for mech in mechs {
        if parsed.sign {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Sign) {
                mechanisms.push(m);
            }
        }
        if parsed.encrypt {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Encrypt) {
                mechanisms.push(m);
            }
        }
        if parsed.decrypt {
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

    let id = if let Some(key_id) = parsed.id {
        default_api::keys_key_id_put(api_config, &key_id, private_key, Some(mechanisms), None)
            .map_err(CreateKeyError::PutError)?;
        key_id
    } else {
        default_api::keys_post(api_config, private_key, Some(mechanisms), None)
            .map_err(CreateKeyError::PostError)?
    };

    Ok((id, key_class))
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

pub fn generate_key_from_template(
    template: &CkRawAttrTemplate,
    public_template: Option<&CkRawAttrTemplate>,
    mechanism: &Mechanism,
    api_config: &Configuration,
) -> Result<String, CreateKeyError> {
    let parsed = parse_attributes(template)?;
    let parsed_public = public_template.map(parse_attributes).transpose()?;

    let api_mechs = mechanism.get_all_possible_api_mechs();

    let length = parsed.value_len.or(parsed.modulus_bits).or(parsed_public
        .as_ref()
        .and_then(|p| p.value_len.or(p.modulus_bits)));

    trace!("length: {:?}", length);

    let mut key_type = mechanism.to_key_type();

    if let Some(public) = parsed_public {
        if let Some(ec_params) = public.ec_params {
            key_type = key_type_from_params(&ec_params).ok_or(CreateKeyError::InvalidAttribute)?;
        }
    }

    default_api::keys_generate_post(
        api_config,
        KeyGenerateRequestData {
            mechanisms: api_mechs,
            r#type: key_type,
            restrictions: None,
            id: parsed.id,
            length: length.map(|len| len as i32),
        },
    )
    .map_err(CreateKeyError::GenerateError)
}
