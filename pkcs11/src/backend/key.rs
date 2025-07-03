use std::{collections::HashMap, sync::Mutex};

use super::{
    db::{self, attr::CkRawAttrTemplate, Object},
    login::{self, LoginCtx},
    Error,
};
use crate::{
    backend::{self, db::object::ObjectKind, mechanism::Mechanism, ApiError},
    data::{DEVICE, KEY_ALIASES},
};
use base64ct::{Base64, Encoding};
use config_file::CertificateFormat;
use cryptoki_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_EC_PARAMS, CKA_ENCRYPT, CKA_ID, CKA_KEY_TYPE, CKA_LABEL,
    CKA_MODULUS_BITS, CKA_PRIME_1, CKA_PRIME_2, CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_VALUE,
    CKA_VALUE_LEN, CKK_EC, CKK_EC_EDWARDS, CKK_GENERIC_SECRET, CKK_RSA, CK_KEY_TYPE,
    CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_ULONG,
};
use der::{oid::ObjectIdentifier, Decode};
use log::{debug, error, trace, warn};
use nethsm_sdk_rs::{
    apis::default_api,
    models::{KeyGenerateRequestData, KeyItem, KeyPrivateData, KeyType, PrivateKey},
};

#[derive(Debug, Default)]
pub struct ParsedAttributes {
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
    pub raw_id: Option<Vec<u8>>,
}

pub fn parse_attributes(template: &CkRawAttrTemplate) -> Result<ParsedAttributes, Error> {
    let mut parsed = ParsedAttributes::default();

    for attr in template.iter() {
        let t = attr.type_();

        match t {
            CKA_CLASS => match unsafe { attr.read_value::<CK_OBJECT_CLASS>() } {
                Some(val) => {
                    parsed.key_class = match ObjectKind::from(val) {
                        ObjectKind::Other => {
                            debug!("Class not supported: {val:?}");
                            None
                        }

                        k => Some(k),
                    }
                }
                None => return Err(Error::InvalidAttribute(CKA_CLASS)),
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
                        parsed.raw_id = Some(bytes.to_vec());
                    }
                    parsed.id = output;
                }
            }
            CKA_LABEL => {
                let label = attr
                    .val_bytes()
                    .map(|val| String::from_utf8(val.to_vec()))
                    .transpose()
                    .map_err(Error::StringParse)?;
                trace!("label: {label:?}");
                if parsed.id.is_none() {
                    parsed.id = label;
                }
            }

            CKA_KEY_TYPE => {
                let ktype = match unsafe { attr.read_value::<CK_KEY_TYPE>() } {
                    Some(val) => val,
                    None => return Err(Error::InvalidAttribute(CKA_KEY_TYPE)),
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
                parsed.value_len = unsafe { attr.read_value::<CK_ULONG>() };
            }
            CKA_MODULUS_BITS => {
                parsed.modulus_bits = unsafe { attr.read_value::<CK_ULONG>() };
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
    login_ctx: &LoginCtx,
) -> Result<(String, ObjectKind, Option<Vec<u8>>), Error> {
    let cert = parsed_template
        .value
        .as_ref()
        .ok_or(Error::MissingAttribute(CKA_VALUE))?;

    let mut id = match parsed_template.id {
        Some(ref id) => id.clone(),
        None => {
            error!("A key ID is required");
            return Err(Error::MissingAttribute(CKA_ID));
        }
    };

    let Some(device) = DEVICE.load_full() else {
        error!("Initialization was not performed or failed");
        return Err(Error::LibraryNotInitialized);
    };

    // Check if an alias is defined for this key
    if device.enable_set_attribute_value {
        if let Some(real_name) = KEY_ALIASES.lock()?.get(&id).cloned() {
            id = real_name;
        }
    }

    let certificate_format = login_ctx.slot().certificate_format;
    debug!("Uploading certificate, sending {certificate_format} encoding to the nethsm as per configuration");
    let body = match certificate_format {
        CertificateFormat::Pem => {
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::default(), cert)
                .map_err(Error::Pem)?
                .into_bytes()
        }
        CertificateFormat::Der => cert.clone(),
    };

    let key_id = id.as_str();

    login_ctx.try_(
        |api_config| default_api::keys_key_id_cert_put(api_config, key_id, body),
        login::UserMode::Administrator,
    )?;

    Ok((id, ObjectKind::Certificate, parsed_template.raw_id.clone()))
}

pub fn create_key_from_template(
    template: CkRawAttrTemplate,
    login_ctx: &LoginCtx,
) -> Result<(String, ObjectKind, Option<Vec<u8>>), Error> {
    let parsed = parse_attributes(&template)?;

    debug!("key_class: {:?}", parsed.key_class);
    debug!("key_type: {:?}", parsed.key_type);

    let key_class = if let Some(ref key_class) = parsed.key_class {
        let key_class = *key_class;
        if key_class == ObjectKind::Other || key_class == ObjectKind::PublicKey {
            // Supported object types are Certificates, Private keys and keypairs
            warn!("Creating object of class {key_class:?} is not supported by the nethsm");
            return Err(Error::ObjectClassNotSupported);
        }
        key_class
    } else {
        return Err(Error::ObjectClassNotSupported);
    };

    if key_class == ObjectKind::Certificate {
        return upload_certificate(&parsed, login_ctx);
    }

    let (r#type, key) = match parsed
        .key_type
        .ok_or(Error::InvalidAttribute(CKA_KEY_TYPE))?
    {
        CKK_RSA => {
            trace!("Creating RSA key");

            let prime_p =
                Base64::encode_string(&parsed.prime_p.ok_or(Error::MissingAttribute(CKA_PRIME_1))?);

            let prime_q =
                Base64::encode_string(&parsed.prime_q.ok_or(Error::MissingAttribute(CKA_PRIME_2))?);

            let public_exponent = Base64::encode_string(
                &parsed
                    .public_exponent
                    .ok_or(Error::MissingAttribute(CKA_PUBLIC_EXPONENT))?,
            );

            let key = Box::new(KeyPrivateData {
                data: None,
                prime_p: Some(prime_p),
                prime_q: Some(prime_q),
                public_exponent: Some(public_exponent),
            });
            (KeyType::Rsa, key)
        }
        CKK_EC | CKK_EC_EDWARDS => {
            let ec_type = key_type_from_params(
                &parsed
                    .ec_params
                    .ok_or(Error::MissingAttribute(CKA_EC_PARAMS))?,
            )
            .ok_or(Error::InvalidAttribute(CKA_EC_PARAMS))?;

            let size = key_size(&ec_type).ok_or(Error::InvalidAttribute(CKA_EC_PARAMS))?;
            let mut value = parsed.value.ok_or(Error::MissingAttribute(CKA_VALUE))?;

            // add padding
            while value.len() < size {
                value.insert(0, 0);
            }

            let b64_private = Base64::encode_string(value.as_slice());

            let key = Box::new(KeyPrivateData {
                data: Some(b64_private),
                prime_p: None,
                prime_q: None,
                public_exponent: None,
            });

            (ec_type, key)
        }
        CKK_GENERIC_SECRET => {
            let b64_private = Base64::encode_string(
                parsed
                    .value
                    .as_ref()
                    .ok_or(Error::MissingAttribute(CKA_VALUE))?
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

        _ => return Err(Error::InvalidAttribute(CKA_KEY_TYPE)),
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
        mechanisms,
        r#type,
        private: key,
        restrictions: None,
    };

    let id = if let Some(id) = parsed.id {
        let key_id = id.as_str();
        if let Err(err) = login_ctx.try_(
            |api_config| {
                default_api::keys_key_id_put(
                    api_config,
                    key_id,
                    default_api::KeysKeyIdPutBody::ApplicationJson(private_key),
                )
            },
            login::UserMode::Administrator,
        ) {
            Err(err)
        } else {
            Ok(id)
        }
    } else {
        let resp = login_ctx.try_(
            |api_config| {
                default_api::keys_post(
                    api_config,
                    default_api::KeysPostBody::ApplicationJson(private_key),
                )
            },
            login::UserMode::Administrator,
        );

        match resp {
            Ok(resp) => {
                let id = extract_key_id_location_header(resp.headers)?;
                Ok(id)
            }
            Err(err) => Err(err),
        }
    }?;

    Ok((id, key_class, parsed.raw_id))
}

const KEYTYPE_EC_P224: ObjectIdentifier = der::oid::db::rfc5912::SECP_224_R_1;
const KEYTYPE_EC_P256: ObjectIdentifier = der::oid::db::rfc5912::SECP_256_R_1;
const KEYTYPE_EC_P384: ObjectIdentifier = der::oid::db::rfc5912::SECP_384_R_1;
const KEYTYPE_EC_P521: ObjectIdentifier = der::oid::db::rfc5912::SECP_521_R_1;
const KEYTYPE_CURVE25519: ObjectIdentifier = der::oid::db::rfc8410::ID_ED_25519;

pub fn key_type_to_asn1(key_type: KeyType) -> Option<ObjectIdentifier> {
    Some(match key_type {
        KeyType::EcP224 => KEYTYPE_EC_P224,
        KeyType::EcP256 => KEYTYPE_EC_P256,
        KeyType::EcP384 => KEYTYPE_EC_P384,
        KeyType::EcP521 => KEYTYPE_EC_P521,
        KeyType::Curve25519 => KEYTYPE_CURVE25519,
        _ => return None,
    })
}

// returns the key size in bytes
pub const fn key_size(t: &KeyType) -> Option<usize> {
    let size = match t {
        KeyType::EcP224 => 224,
        KeyType::EcP256 => 256,
        KeyType::EcP384 => 384,
        KeyType::EcP521 => 521,
        KeyType::Curve25519 => 255,
        _ => return None,
    };

    Some(size / 8)
}

fn key_type_from_params(params: &[u8]) -> Option<KeyType> {
    // decode der to ObjectIdentifier
    let oid: der::oid::ObjectIdentifier = der::oid::ObjectIdentifier::from_der(params).ok()?;

    // we can't do a match on vecs
    if oid == KEYTYPE_CURVE25519 {
        Some(KeyType::Curve25519)
    } else if oid == KEYTYPE_EC_P224 {
        Some(KeyType::EcP224)
    } else if oid == KEYTYPE_EC_P256 {
        Some(KeyType::EcP256)
    } else if oid == KEYTYPE_EC_P384 {
        Some(KeyType::EcP384)
    } else if oid == KEYTYPE_EC_P521 {
        Some(KeyType::EcP521)
    } else {
        None
    }
}

pub fn generate_key_from_template(
    template: &CkRawAttrTemplate,
    public_template: Option<&CkRawAttrTemplate>,
    mechanism: &Mechanism,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
    let parsed = parse_attributes(template)?;
    let parsed_public = public_template.map(parse_attributes).transpose()?;

    let api_mechs = mechanism.get_all_possible_api_mechs();

    let length = parsed.value_len.or(parsed.modulus_bits).or(parsed_public
        .as_ref()
        .and_then(|p| p.value_len.or(p.modulus_bits)));

    trace!("length: {length:?}");

    let mut key_type = mechanism.to_key_type();

    if let Some(public) = parsed_public {
        if let Some(ec_params) = public.ec_params {
            key_type =
                key_type_from_params(&ec_params).ok_or(Error::InvalidAttribute(CKA_EC_PARAMS))?;
        }
    }

    let id = login_ctx.try_(
        |api_config| {
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
        },
        login::UserMode::Administrator,
    )?;

    let id = extract_key_id_location_header(id.headers)?;

    fetch_key(&id, parsed.raw_id, login_ctx, db)
}

fn fetch_one_key(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
) -> Result<Vec<Object>, Error> {
    if !login_ctx.can_run_mode(super::login::UserMode::OperatorOrAdministrator) {
        return Err(Error::NotLoggedIn(
            super::login::UserMode::OperatorOrAdministrator,
        ));
    }

    let key_data = match login_ctx.try_(
        |api_config| default_api::keys_key_id_get(api_config, key_id),
        super::login::UserMode::OperatorOrAdministrator,
    ) {
        Ok(key_data) => key_data.entity,
        Err(err) => {
            debug!("Failed to fetch key {key_id}: {err:?}");
            if matches!(
                err,
                Error::Api(ApiError::ResponseError(backend::ResponseContent {
                    status: 404,
                    ..
                }))
            ) {
                return Ok(vec![]);
            }
            return Err(err);
        }
    };

    let objects = db::object::from_key_data(key_data, key_id, raw_id)?;

    Ok(objects)
}

// we need the raw id when the CKA_KEY_ID doesn't parse to an alphanumeric string
pub fn fetch_key(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
    let objects = fetch_one_key(key_id, raw_id, login_ctx)?;

    let mut db = db.lock()?;

    Ok(objects.into_iter().map(|o| db.add_object(o)).collect())
}

fn fetch_one_certificate(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
) -> Result<Object, Error> {
    if !login_ctx.can_run_mode(super::login::UserMode::OperatorOrAdministrator) {
        return Err(Error::NotLoggedIn(
            super::login::UserMode::OperatorOrAdministrator,
        ));
    }

    let cert_data = login_ctx.try_(
        |api_config| default_api::keys_key_id_cert_get(api_config, key_id),
        super::login::UserMode::OperatorOrAdministrator,
    )?;

    let object = db::object::from_cert_data(
        cert_data.entity,
        key_id,
        raw_id,
        login_ctx.slot().certificate_format,
    )?;

    Ok(object)
}

pub fn fetch_certificate(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<(CK_OBJECT_HANDLE, Object), Error> {
    let object = fetch_one_certificate(key_id, raw_id, login_ctx)?;
    let r = db.lock()?.add_object(object);

    Ok(r)
}

// get the id from the logation header value :
// location: /api/v1/keys/<id>?mechanisms=ECDSA_Signature
fn extract_key_id_location_header(headers: HashMap<String, String>) -> Result<String, Error> {
    let location_header = headers.get("location").ok_or(Error::InvalidData)?;
    let key_id = location_header
        .split('/')
        .next_back()
        .ok_or(Error::InvalidData)?
        .split('?')
        .next()
        .ok_or(Error::InvalidData)?
        .to_string();
    Ok(key_id)
}

pub fn fetch_one(
    key: &KeyItem,
    login_ctx: &LoginCtx,
    kind: Option<ObjectKind>,
) -> Result<Vec<Object>, Error> {
    let mut acc = Vec::new();

    if matches!(
        kind,
        None | Some(ObjectKind::Other)
            | Some(ObjectKind::PrivateKey)
            | Some(ObjectKind::PublicKey)
            | Some(ObjectKind::SecretKey)
    ) {
        acc = fetch_one_key(&key.id, None, login_ctx)?;
    }

    if matches!(kind, None | Some(ObjectKind::Certificate)) {
        match fetch_one_certificate(&key.id, None, login_ctx) {
            Ok(cert) => acc.push(cert),
            Err(err) => {
                debug!("Failed to fetch certificate: {err:?}");
            }
        }
    }
    Ok(acc)
}
