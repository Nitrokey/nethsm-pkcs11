use std::{collections::HashMap, sync::Mutex};

use super::{
    db::{self, attr::CkRawAttrTemplate, Object},
    login::{self, LoginCtx},
    Error,
};
use crate::backend::{self, db::object::ObjectKind, mechanism::Mechanism, ApiError};
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
    models::{KeyGenerateRequestData, KeyItem, KeyPrivateData, KeyType as RawKeyType, PrivateKey},
};

// Exhaustive version of nethsm_sdk_rs::models::KeyType
#[derive(Clone, Copy, PartialEq)]
pub enum KeyType {
    Rsa,
    Ec(EcKeyType),
    Generic,
}

impl From<KeyType> for RawKeyType {
    fn from(ty: KeyType) -> Self {
        match ty {
            KeyType::Rsa => Self::Rsa,
            KeyType::Ec(ty) => ty.into(),
            KeyType::Generic => Self::Generic,
        }
    }
}

pub struct UnsupportedKeyTypeError;

impl TryFrom<RawKeyType> for KeyType {
    type Error = UnsupportedKeyTypeError;

    fn try_from(ty: RawKeyType) -> Result<Self, Self::Error> {
        let ty = match ty {
            RawKeyType::Rsa => Self::Rsa,
            RawKeyType::Curve25519 => Self::Ec(EcKeyType::Curve25519),
            RawKeyType::EcP256 => Self::Ec(EcKeyType::EcP256),
            RawKeyType::EcP384 => Self::Ec(EcKeyType::EcP384),
            RawKeyType::EcP521 => Self::Ec(EcKeyType::EcP521),
            RawKeyType::EcP256K1 => Self::Ec(EcKeyType::EcP256K1),
            RawKeyType::BrainpoolP256 => Self::Ec(EcKeyType::BrainpoolP256),
            RawKeyType::BrainpoolP384 => Self::Ec(EcKeyType::BrainpoolP384),
            RawKeyType::BrainpoolP512 => Self::Ec(EcKeyType::BrainpoolP512),
            RawKeyType::Generic => Self::Generic,
            _ => {
                warn!("Unsupported key type: {ty:?}");
                return Err(UnsupportedKeyTypeError);
            }
        };
        Ok(ty)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum EcKeyType {
    Curve25519,
    EcP256,
    EcP384,
    EcP521,
    EcP256K1,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
}

impl EcKeyType {
    pub fn to_asn1(self) -> ObjectIdentifier {
        match self {
            Self::EcP256 => KEYTYPE_EC_P256,
            Self::EcP384 => KEYTYPE_EC_P384,
            Self::EcP521 => KEYTYPE_EC_P521,
            Self::Curve25519 => KEYTYPE_CURVE25519,
            Self::EcP256K1 => KEYTYPE_EC_P256_K1,
            Self::BrainpoolP256 => KEYTYPE_BRAINPOOL_P256,
            Self::BrainpoolP384 => KEYTYPE_BRAINPOOL_P384,
            Self::BrainpoolP512 => KEYTYPE_BRAINPOOL_P512,
        }
    }

    pub fn key_size(&self) -> usize {
        let size = match self {
            Self::EcP256 => 256,
            Self::EcP384 => 384,
            Self::EcP521 => 521,
            Self::Curve25519 => 255,
            Self::EcP256K1 => 256,
            Self::BrainpoolP256 => 256,
            Self::BrainpoolP384 => 384,
            Self::BrainpoolP512 => 512,
        };

        size / 8
    }
}

impl From<EcKeyType> for RawKeyType {
    fn from(ty: EcKeyType) -> Self {
        match ty {
            EcKeyType::Curve25519 => Self::Curve25519,
            EcKeyType::EcP256 => Self::EcP256,
            EcKeyType::EcP384 => Self::EcP384,
            EcKeyType::EcP521 => Self::EcP521,
            EcKeyType::EcP256K1 => Self::EcP256K1,
            EcKeyType::BrainpoolP256 => Self::BrainpoolP256,
            EcKeyType::BrainpoolP384 => Self::BrainpoolP384,
            EcKeyType::BrainpoolP512 => Self::BrainpoolP512,
        }
    }
}

impl TryFrom<ObjectIdentifier> for EcKeyType {
    type Error = UnsupportedKeyTypeError;

    fn try_from(oid: ObjectIdentifier) -> Result<Self, Self::Error> {
        let ty = match oid {
            KEYTYPE_CURVE25519 => Self::Curve25519,
            KEYTYPE_EC_P256 => Self::EcP256,
            KEYTYPE_EC_P384 => Self::EcP384,
            KEYTYPE_EC_P521 => Self::EcP521,
            KEYTYPE_EC_P256_K1 => Self::EcP256K1,
            KEYTYPE_BRAINPOOL_P256 => Self::BrainpoolP256,
            KEYTYPE_BRAINPOOL_P384 => Self::BrainpoolP384,
            KEYTYPE_BRAINPOOL_P512 => Self::BrainpoolP512,
            _ => {
                warn!("Unsupported EC key type OID {oid}");
                return Err(UnsupportedKeyTypeError);
            }
        };
        Ok(ty)
    }
}

#[derive(Debug, PartialEq)]
pub struct Id(String);

impl Id {
    pub fn new(s: String) -> Result<Self, InvalidIdError> {
        // See https://github.com/Nitrokey/nethsm/blob/60b9b2c0caa609f53e50870451731c5803c4b724/src/keyfender/json.ml#L459-L472
        const ALLOWED_CHARS: &[u8] = b"-_.";
        const MAX_LEN: usize = 128;
        if s.len() > MAX_LEN {
            warn!(
                "ID '{s}' is invalid: length is {} bytes (maximum: {MAX_LEN} bytes)",
                s.len(),
            );
            return Err(InvalidIdError);
        }
        let (first, rest) = s.as_bytes().split_first().ok_or_else(|| {
            warn!("Empty IDs are invalid");
            InvalidIdError
        })?;
        if !first.is_ascii_alphanumeric() {
            warn!("ID '{s}' is invalid: first character must be alphanumeric");
            return Err(InvalidIdError);
        }
        if let Some(c) = rest
            .iter()
            .find(|c| !c.is_ascii_alphanumeric() && !ALLOWED_CHARS.contains(c))
        {
            warn!("ID '{s}' is invalid: invalid character '{c}'");
            return Err(InvalidIdError);
        }
        Ok(Self(s))
    }
}

impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Id> for String {
    fn from(id: Id) -> String {
        id.0
    }
}

impl TryFrom<String> for Id {
    type Error = InvalidIdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<Vec<u8>> for Id {
    type Error = InvalidIdError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        String::from_utf8(bytes)
            .map_err(|err| {
                warn!("ID {:?} is invalid: not a UTF-8 string", err.into_bytes());
                InvalidIdError
            })
            .and_then(Id::try_from)
    }
}

#[derive(Debug, PartialEq)]
pub struct InvalidIdError;

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
                    let id = Id::try_from(bytes.to_owned())
                        .map_err(|_| Error::InvalidAttribute(CKA_ID))?;
                    parsed.id = Some(id.0);
                }
            }
            CKA_LABEL => {
                if let Some(bytes) = attr.val_bytes() {
                    let id = Id::try_from(bytes.to_owned())
                        .map_err(|_| Error::InvalidAttribute(CKA_LABEL))?;
                    trace!("label: {id:?}");
                    if parsed.id.is_none() {
                        parsed.id = Some(id.0);
                    }
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
) -> Result<(String, ObjectKind), Error> {
    let cert = parsed_template
        .value
        .as_ref()
        .ok_or(Error::MissingAttribute(CKA_VALUE))?;

    let id = parsed_template.id.clone().ok_or_else(|| {
        error!("A key ID is required");
        Error::MissingAttribute(CKA_ID)
    })?;

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

    Ok((id, ObjectKind::Certificate))
}

pub fn create_key_from_template(
    template: CkRawAttrTemplate,
    login_ctx: &LoginCtx,
) -> Result<(String, ObjectKind), Error> {
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

            let mut key = KeyPrivateData::new();
            key.prime_p = Some(prime_p);
            key.prime_q = Some(prime_q);
            key.public_exponent = Some(public_exponent);
            (KeyType::Rsa, key)
        }
        CKK_EC | CKK_EC_EDWARDS => {
            let ec_params = parsed
                .ec_params
                .ok_or(Error::MissingAttribute(CKA_EC_PARAMS))?;
            let oid: der::oid::ObjectIdentifier = der::oid::ObjectIdentifier::from_der(&ec_params)
                .map_err(|_| Error::InvalidAttribute(CKA_EC_PARAMS))?;
            let ec_type =
                EcKeyType::try_from(oid).map_err(|_| Error::InvalidAttribute(CKA_EC_PARAMS))?;

            let size = ec_type.key_size();
            let mut value = parsed.value.ok_or(Error::MissingAttribute(CKA_VALUE))?;

            // add padding
            while value.len() < size {
                value.insert(0, 0);
            }

            let b64_private = Base64::encode_string(value.as_slice());

            let mut key = KeyPrivateData::new();
            key.data = Some(b64_private);
            (KeyType::Ec(ec_type), key)
        }
        CKK_GENERIC_SECRET => {
            let b64_private = Base64::encode_string(
                parsed
                    .value
                    .as_ref()
                    .ok_or(Error::MissingAttribute(CKA_VALUE))?
                    .as_slice(),
            );

            let mut key = KeyPrivateData::new();
            key.data = Some(b64_private);
            (KeyType::Generic, key)
        }

        _ => return Err(Error::InvalidAttribute(CKA_KEY_TYPE)),
    };

    let mechs = Mechanism::from_key_type(r#type);

    let mut mechanisms = vec![];

    for mech in mechs {
        if parsed.sign {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Sign) {
                mechanisms.push(m.into());
            }
        }
        if parsed.encrypt {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Encrypt) {
                mechanisms.push(m.into());
            }
        }
        if parsed.decrypt {
            if let Some(m) = mech.to_api_mech(super::mechanism::MechMode::Decrypt) {
                mechanisms.push(m.into());
            }
        }
    }

    let private_key = PrivateKey::new(mechanisms, r#type.into(), key);

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

    Ok((id, key_class))
}

const KEYTYPE_EC_P256: ObjectIdentifier = der::oid::db::rfc5912::SECP_256_R_1;
const KEYTYPE_EC_P384: ObjectIdentifier = der::oid::db::rfc5912::SECP_384_R_1;
const KEYTYPE_EC_P521: ObjectIdentifier = der::oid::db::rfc5912::SECP_521_R_1;
const KEYTYPE_CURVE25519: ObjectIdentifier = der::oid::db::rfc8410::ID_ED_25519;
const KEYTYPE_EC_P256_K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
const KEYTYPE_BRAINPOOL_P256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");
const KEYTYPE_BRAINPOOL_P384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.11");
const KEYTYPE_BRAINPOOL_P512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.13");

fn key_type_from_params(params: &[u8]) -> Option<KeyType> {
    // decode der to ObjectIdentifier
    let oid: der::oid::ObjectIdentifier = der::oid::ObjectIdentifier::from_der(params).ok()?;
    EcKeyType::try_from(oid).ok().map(KeyType::Ec)
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

    let api_mechs = api_mechs.into_iter().map(From::from).collect();
    let mut request = KeyGenerateRequestData::new(api_mechs, key_type.into());
    request.id = parsed.id;
    request.length = length.map(|length| length as i32);
    let id = login_ctx.try_(
        |api_config| default_api::keys_generate_post(api_config, request),
        login::UserMode::Administrator,
    )?;

    let id = extract_key_id_location_header(id.headers)?;

    fetch_key(&id, login_ctx, db)
}

fn fetch_one_key(key_id: &str, login_ctx: &LoginCtx) -> Result<Vec<Object>, Error> {
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

    let objects = db::object::from_key_data(key_data, key_id)?;

    Ok(objects)
}

pub fn fetch_key(
    key_id: &str,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
    let objects = fetch_one_key(key_id, login_ctx)?;

    let mut db = db.lock()?;

    Ok(objects.into_iter().map(|o| db.add_object(o)).collect())
}

fn fetch_one_certificate(key_id: &str, login_ctx: &LoginCtx) -> Result<Object, Error> {
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
        login_ctx.slot().certificate_format,
    )?;

    Ok(object)
}

pub fn fetch_certificate(
    key_id: &str,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<(CK_OBJECT_HANDLE, Object), Error> {
    let object = fetch_one_certificate(key_id, login_ctx)?;
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
        acc = fetch_one_key(&key.id, login_ctx)?;
    }

    if matches!(kind, None | Some(ObjectKind::Certificate)) {
        match fetch_one_certificate(&key.id, login_ctx) {
            Ok(cert) => acc.push(cert),
            Err(err) => {
                debug!("Failed to fetch certificate: {err:?}");
            }
        }
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::{Id, InvalidIdError};

    #[test]
    fn test_id_valid() {
        let valid_ids = ["keyID", "mykeyid", "test-key", "test_key", "test.key"];
        for id in valid_ids {
            assert_eq!(Id::new(id.to_owned()), Ok(Id(id.to_owned())));
        }
    }

    #[test]
    fn test_id_invalid() {
        let invalid_ids = [
            "",
            "&*&*&*",
            "-key",
            ".key",
            "_key",
            "--",
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "schlüssel",
            "¾藏",
        ];
        for id in invalid_ids {
            assert_eq!(
                Id::new(id.to_owned()),
                Err(InvalidIdError),
                "'{id}' should be rejected"
            );
        }
    }
}
