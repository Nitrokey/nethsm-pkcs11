use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::{self, Display, Formatter},
    sync::Mutex,
};

use super::{
    db::{self, attr::CkRawAttrTemplate, Object},
    login::{self, LoginCtx},
    Error,
};
use crate::backend::{db::object::ObjectKind, mechanism::Mechanism};
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
    models::{
        KeyGenerateRequestData, KeyItem, KeyPrivateData, KeyType as RawKeyType, PrivateKey,
        PublicKey,
    },
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
            Self::Curve25519 => 256,
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

#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs11Id<'a>(Cow<'a, [u8]>);

impl Pkcs11Id<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_owned()
    }
}

impl<'a> From<&'a NetHSMId> for Pkcs11Id<'a> {
    fn from(id: &'a NetHSMId) -> Self {
        if let Some(bytes) = id.decode() {
            Self(bytes.into())
        } else {
            Self(id.0.as_bytes().into())
        }
    }
}

impl<'a> From<&'a [u8]> for Pkcs11Id<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(bytes.into())
    }
}

/// An ID used by the NetHSM.
///
/// As we need to support arbitrary [`Pkcs11Id`][] values (byte sequences), an encoding scheme is
/// used:
/// - PKCS11 IDs that are also valid NetHSM IDs are used as-is (see [`NetHSMId::validate`][] and
///   [`NetHSMId::from_bytes`][]).
/// - PKCS11 IDs that are not valid NetHSM IDs are encoded by adding a prefix and using the hex
///   encoding of the PKCS11 ID (see [`NetHSMId::encode`]).
///
/// When mapping NetHSM IDs to PKCS11 IDs, we only perform the decoding step if the decoded PKCS11
/// ID would map to the same NetHSM ID.  Otherwise, the ID is used as-is.
#[derive(Clone, Debug, PartialEq)]
pub struct NetHSMId(String);

impl NetHSMId {
    const MAX_LEN: usize = 128;
    const ENCODING_PREFIX: &str = "0---";

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Checks if the given bytes are a valid NetHSM ID (without encoding).
    fn validate(bytes: &[u8]) -> Result<(), InvalidIdError> {
        // See https://github.com/Nitrokey/nethsm/blob/60b9b2c0caa609f53e50870451731c5803c4b724/src/keyfender/json.ml#L459-L472

        fn is_valid_first_character(c: u8) -> bool {
            c.is_ascii_alphanumeric()
        }

        fn is_valid_rest_character(c: u8) -> bool {
            const EXTRA_CHARS: &[u8] = b"-_.";
            c.is_ascii_alphanumeric() || EXTRA_CHARS.contains(&c)
        }

        if bytes.len() > Self::MAX_LEN {
            return Err(InvalidIdError::TooLong {
                length: bytes.len(),
                max_length: Self::MAX_LEN,
                encoded: false,
            });
        }

        let (first, rest) = bytes.split_first().ok_or(InvalidIdError::Empty)?;
        if !is_valid_first_character(*first) {
            return Err(InvalidIdError::InvalidCharacter {
                position: 0,
                character: *first,
            });
        }
        if let Some((i, c)) = rest
            .iter()
            .enumerate()
            .find(|(_i, c)| !is_valid_rest_character(**c))
        {
            return Err(InvalidIdError::InvalidCharacter {
                position: i + 1,
                character: *c,
            });
        }
        Ok(())
    }

    /// Creates a `NetHSMId` from the given bytes without encoding.
    ///
    /// This only works if the unencoded bytes are a valid NetHSM ID, see [`Self::validate`][].
    fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidIdError> {
        Self::validate(bytes)?;
        let s = str::from_utf8(bytes).map_err(|err| {
            let i = err.error_len().unwrap_or_else(|| err.valid_up_to() + 1);
            InvalidIdError::InvalidCharacter {
                position: i,
                character: bytes[i],
            }
        })?;
        Ok(Self(s.to_owned()))
    }

    /// Encodes the given bytes as a `NetHSMId`.
    ///
    /// The encoding uses a prefix ([`Self::ENCODING_PREFIX`][]) and the hex-encoding of the given
    /// bytes.  This works with arbitrary bytes but should only be used if the unencoded bytes are
    /// not a valid NetHSM ID, see [`Self::validate`][].
    fn encode(bytes: &[u8]) -> Result<Self, InvalidIdError> {
        let max_length = (Self::MAX_LEN - Self::ENCODING_PREFIX.len()) / 2;
        if bytes.len() > max_length {
            Err(InvalidIdError::TooLong {
                length: bytes.len(),
                max_length,
                encoded: true,
            })
        } else {
            let mut s = Self::ENCODING_PREFIX.to_owned();
            s += &hex::encode_upper(bytes);
            Ok(Self(s))
        }
    }

    /// Returns the unencoded bytes
    fn decode(&self) -> Option<Vec<u8>> {
        let rest = self.0.strip_prefix(Self::ENCODING_PREFIX)?;
        let decoded_bytes = hex::decode(rest).ok()?;
        let decoded_pkcs11_id = Pkcs11Id::from(decoded_bytes.as_slice());
        let encoded = Self::try_from(&decoded_pkcs11_id);
        if encoded.as_ref() == Ok(self) {
            Some(decoded_bytes)
        } else {
            None
        }
    }
}

impl Display for NetHSMId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<String> for NetHSMId {
    type Error = InvalidIdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let bytes = s.as_bytes();
        Self::validate(bytes).inspect_err(|err| err.log(bytes))?;
        Ok(Self(s))
    }
}

impl TryFrom<&Pkcs11Id<'_>> for NetHSMId {
    type Error = InvalidIdError;

    fn try_from(id: &Pkcs11Id<'_>) -> Result<Self, Self::Error> {
        let id = id.0.as_ref();
        Self::from_bytes(id)
            .or_else(|err| {
                if matches!(err, InvalidIdError::InvalidCharacter { .. }) {
                    Self::encode(id)
                } else {
                    Err(err)
                }
            })
            .inspect_err(|err| err.log(id))
    }
}

#[derive(Debug, PartialEq)]
pub enum InvalidIdError {
    Empty,
    TooLong {
        length: usize,
        max_length: usize,
        encoded: bool,
    },
    InvalidCharacter {
        position: usize,
        character: u8,
    },
}

impl InvalidIdError {
    fn log(&self, id: &[u8]) {
        let encoded = hex::encode(id);
        let id = str::from_utf8(id)
            .map(|s| format!("'{s}' ({encoded})"))
            .unwrap_or_else(|_| encoded);
        match self {
            Self::Empty => warn!("IDs must not be empty"),
            Self::TooLong {
                length,
                max_length,
                encoded,
            } => {
                if *encoded {
                    warn!("ID {id} is too long (length: {length}, maximum: {max_length})");
                } else {
                    warn!("ID {id} is too long (length: {length}, maximum for encoded IDs: {max_length})");
                }
            }
            Self::InvalidCharacter {
                position,
                character,
            } => {
                let character = if character.is_ascii() {
                    format!("'{}' ({character:x})", char::from(*character))
                } else {
                    format!("{character:x}")
                };
                warn!("ID {id} contains invalid character {character} at position {position}");
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct ParsedAttributes {
    pub id: Option<NetHSMId>,
    pub label: Option<String>,
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
                    let pkcs11_id = Pkcs11Id::from(bytes);
                    let id = NetHSMId::try_from(&pkcs11_id)
                        .map_err(|_| Error::InvalidAttribute(CKA_ID))?;
                    parsed.id = Some(id);
                }
            }
            CKA_LABEL => {
                if let Some(bytes) = attr.val_bytes() {
                    let label =
                        str::from_utf8(bytes).map_err(|_| Error::InvalidAttribute(CKA_LABEL))?;
                    trace!("label: {label}");
                    parsed.label = Some(label.to_owned());
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
) -> Result<(NetHSMId, ObjectKind), Error> {
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

    login_ctx.try_(
        |api_config| default_api::keys_key_id_cert_put(api_config, id.as_str(), body),
        login::UserMode::Administrator,
    )?;

    Ok((id, ObjectKind::Certificate))
}

pub fn create_key_from_template(
    template: CkRawAttrTemplate,
    login_ctx: &LoginCtx,
) -> Result<(NetHSMId, ObjectKind), Error> {
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

    let has_label = parsed.label.is_some();
    let mut private_key = PrivateKey::new(mechanisms, r#type.into(), key);
    if let Some(label) = parsed.label {
        private_key.label = Some(label);
    }

    let result = if let Some(id) = parsed.id {
        login_ctx
            .try_(
                |api_config| {
                    default_api::keys_key_id_put(
                        api_config,
                        id.as_str(),
                        default_api::KeysKeyIdPutBody::ApplicationJson(private_key),
                    )
                },
                login::UserMode::Administrator,
            )
            .map(|_| id)
    } else {
        login_ctx
            .try_(
                |api_config| {
                    default_api::keys_post(
                        api_config,
                        default_api::KeysPostBody::ApplicationJson(private_key),
                    )
                },
                login::UserMode::Administrator,
            )
            .and_then(|response| extract_key_id_location_header(response.headers))
    };

    let id = result.inspect_err(|err| {
        if err.is_api_400() && has_label {
            warn!("Setting CKA_LABEL is only supported with NetHSM v5.0 or later.");
        }
    })?;

    Ok((id, key_class))
}

/// A key on the NetHSM.
///
/// This key can be mapped to private key, public key and/or certificate objects in the PKCS11 space.
#[derive(Clone, Debug)]
pub struct NetHSMKey {
    id: NetHSMId,
    data: PublicKey,
}

impl NetHSMKey {
    /// Fetches the metadata for key from the NetHSM.
    ///
    /// This function returns `Err` if the key does not exist or any other error occured while
    /// fetching the key.
    pub fn fetch(key_id: NetHSMId, login_ctx: &LoginCtx) -> Result<Self, Error> {
        if !login_ctx.can_run_mode(super::login::UserMode::OperatorOrAdministrator) {
            return Err(Error::NotLoggedIn(
                super::login::UserMode::OperatorOrAdministrator,
            ));
        }

        login_ctx
            .try_(
                |api_config| default_api::keys_key_id_get(api_config, key_id.as_str()),
                super::login::UserMode::OperatorOrAdministrator,
            )
            .map(|response| Self {
                id: key_id,
                data: response.entity,
            })
    }

    /// Fetches the metadata for key from the NetHSM if it exists.
    ///
    /// This function returns `None` if the key does not exist and `Err` if any other error occured
    /// while fetching the key.
    pub fn try_fetch(key_id: NetHSMId, login_ctx: &LoginCtx) -> Result<Option<Self>, Error> {
        Self::fetch(key_id, login_ctx).map(Some).or_else(|err| {
            debug!("Failed to fetch key: {err:?}");
            if err.is_api_404() {
                Ok(None)
            } else {
                Err(err)
            }
        })
    }

    /// Returns all PKCS11 objects for this key that match the given `ObjectKind` filter.
    ///
    /// If there are no objects matching the filter, an empty `Vec` is returned.
    pub fn try_fetch_objects(
        self,
        login_ctx: &LoginCtx,
        kind: Option<ObjectKind>,
    ) -> Result<Vec<Object>, Error> {
        if let Some(kind) = kind {
            match kind {
                ObjectKind::Other
                | ObjectKind::PrivateKey
                | ObjectKind::PublicKey
                | ObjectKind::SecretKey => self.into_key_objects(),
                ObjectKind::Certificate => {
                    if let Some(cert) = self.try_fetch_certificate(login_ctx)? {
                        Ok(vec![cert])
                    } else {
                        Ok(Vec::new())
                    }
                }
            }
        } else {
            let mut objects = self.clone().into_key_objects()?;
            if let Some(object) = self.try_fetch_certificate(login_ctx)? {
                objects.push(object);
            }
            Ok(objects)
        }
    }

    /// Converts this key to PKCS11 PrivateKey, PublicKey and/or SecretKey objects.
    pub fn into_key_objects(self) -> Result<Vec<Object>, Error> {
        db::object::from_key_data(self.data, self.id)
    }

    /// Fetches the certificate for this key from the NetHSM and converts it to a PKCS11
    /// Certificate object.
    ///
    /// This function returns `Err` if the key does not exist, does not have a certificate or any
    /// other error occured while fetching the certificate.
    pub fn fetch_certificate(self, login_ctx: &LoginCtx) -> Result<Object, Error> {
        let response = login_ctx.try_(
            |api_config| default_api::keys_key_id_cert_get(api_config, self.id.as_str()),
            super::login::UserMode::OperatorOrAdministrator,
        )?;
        db::object::from_cert_data(
            self.data,
            response.entity,
            self.id,
            login_ctx.slot().certificate_format,
        )
    }

    /// Tries to fetch the certificate for this key from the NetHSM and converts it to a PKCS11
    /// Certificate object.
    ///
    /// This function returns `None` if the key does not exist or does not have a certificate and
    /// `Err` if any other error occured while fetching the certificate.
    pub fn try_fetch_certificate(self, login_ctx: &LoginCtx) -> Result<Option<Object>, Error> {
        self.fetch_certificate(login_ctx).map(Some).or_else(|err| {
            debug!("Failed to fetch certificate: {err:?}");
            if err.is_api_404() {
                Ok(None)
            } else {
                Err(err)
            }
        })
    }
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

    let has_label = parsed.label.is_some();
    let api_mechs = api_mechs.into_iter().map(From::from).collect();
    let mut request = KeyGenerateRequestData::new(api_mechs, key_type.into());
    request.id = parsed.id.map(NetHSMId::into_string);
    request.label = parsed.label;
    request.length = length.map(|length| length as i32);

    let result = login_ctx.try_(
        |api_config| default_api::keys_generate_post(api_config, request),
        login::UserMode::Administrator,
    );
    let response = result.inspect_err(|err| {
        if err.is_api_400() && has_label {
            warn!("Setting CKA_LABEL is only supported with NetHSM v5.0 or later.");
        }
    })?;

    let key_id = extract_key_id_location_header(response.headers)?;

    let key = NetHSMKey::fetch(key_id, login_ctx)?;
    let objects = key.into_key_objects()?;
    Ok(db.lock()?.add_objects(objects))
}

// get the id from the logation header value :
// location: /api/v1/keys/<id>?mechanisms=ECDSA_Signature
fn extract_key_id_location_header(headers: HashMap<String, String>) -> Result<NetHSMId, Error> {
    let location_header = headers.get("location").ok_or(Error::InvalidData)?;
    let key_id = location_header
        .split('/')
        .next_back()
        .ok_or(Error::InvalidData)?
        .split('?')
        .next()
        .ok_or(Error::InvalidData)?
        .to_string();
    NetHSMId::try_from(key_id)
        .inspect_err(|err| {
            error!("NetHSM returned invalid key ID: {err:?}");
        })
        .map_err(|_| Error::InvalidData)
}

pub fn fetch_one(
    key: &KeyItem,
    login_ctx: &LoginCtx,
    kind: Option<ObjectKind>,
) -> Result<Vec<Object>, Error> {
    let key_id = NetHSMId::try_from(key.id.clone())
        .inspect_err(|err| {
            error!("NetHSM returned invalid key ID: {err:?}");
        })
        .map_err(|_| Error::InvalidData)?;
    fetch_by_id(key_id, login_ctx, kind)
}

pub fn fetch_by_id(
    key_id: NetHSMId,
    login_ctx: &LoginCtx,
    kind: Option<ObjectKind>,
) -> Result<Vec<Object>, Error> {
    let Some(key) = NetHSMKey::try_fetch(key_id, login_ctx)? else {
        return Ok(Vec::new());
    };

    key.try_fetch_objects(login_ctx, kind)
}

#[cfg(test)]
mod tests {
    use super::{InvalidIdError, NetHSMId, Pkcs11Id};

    #[test]
    fn test_nethsm_id_valid() {
        let valid_ids: [(&[u8], &str); _] = [
            (b"keyID", "keyID"),
            (b"mykeyid", "mykeyid"),
            (b"test-key", "test-key"),
            (b"test_key", "test_key"),
            (b"test.key", "test.key"),
            (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"),
            (b"test~key", "0---746573747E6B6579"),
            (b"-key", "0---2D6B6579"),
            (b".key", "0---2E6B6579"),
            (b"_key", "0---5F6B6579"),
            (b"&*&*&*", "0---262A262A262A"),
            (b"--", "0---2D2D"),
            (b".2345678901234567890123456789012345678901234567890123456789012", "0---2E32333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132"),
            (&[0], "0---00"),
            ("schlüssel".as_bytes(), "0---7363686CC3BC7373656C"),
            ("¾藏".as_bytes(), "0---C2BEE8978F"),
        ];
        for (bytes, s) in valid_ids {
            let pkcs11_id = Pkcs11Id(bytes.into());
            let nethsm_id = NetHSMId(s.to_owned());
            assert_eq!(NetHSMId::try_from(&pkcs11_id).as_ref(), Ok(&nethsm_id));
            assert_eq!(Pkcs11Id::from(&nethsm_id), pkcs11_id);
        }
    }

    #[test]
    fn test_pkcs11_id_invalid() {
        let ids = [
            // invalid hex (odd number of characters)
            "0---2D6B657",
            // invalid hex (bad value)
            "0---2D6B657K",
            // encoding not necessary
            "0---6B6579",
        ];
        for id in ids {
            let nethsm_id = NetHSMId(id.to_owned());
            let pkcs11_id = Pkcs11Id::from(&nethsm_id);
            assert_eq!(pkcs11_id, Pkcs11Id(id.as_bytes().to_owned().into()));
        }
    }

    #[test]
    fn test_nethsm_id_invalid() {
        let invalid_ids: [(InvalidIdError, &[u8]); _] = [
            (InvalidIdError::Empty, b""),
            (InvalidIdError::TooLong {
                length: 129,
                max_length: 128,
                encoded: false,
            }, b"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"),
            (InvalidIdError::TooLong {
                length: 63,
                max_length: 62,
                encoded: true,
            }, b".23456789012345678901234567890123456789012345678901234567890123"),
        ];
        for (err, bytes) in invalid_ids {
            let id = Pkcs11Id(bytes.into());
            assert_eq!(
                NetHSMId::try_from(&id),
                Err(err),
                "'{bytes:?}' should be rejected"
            );
        }
    }
}
