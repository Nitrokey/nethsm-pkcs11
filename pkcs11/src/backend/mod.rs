use std::sync::PoisonError;

use self::{
    db::object::ObjectKind,
    login::{LoginError, UserMode},
    mechanism::{MechMode, Mechanism},
};
use cryptoki_sys::{CK_ATTRIBUTE_TYPE, CK_OBJECT_HANDLE, CK_RV};
use log::error;
use nethsm_sdk_rs::apis;

pub mod db;
pub mod decrypt;
pub mod encrypt;
pub mod events;
pub mod key;
pub mod login;
pub mod mechanism;
pub mod object;
pub mod session;
pub mod sign;
pub mod slot;

macro_rules! pkcs11_error {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($var:ident = $val:expr),+
            $(,)?
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $var,
            )*
        }

        impl From<$name> for ::cryptoki_sys::CK_RV {
            fn from(error: $name) -> Self {
                match error {
                    $(
                        $name::$var => $val,
                    )*
                }
            }
        }
    }
}

pkcs11_error! {
    #[derive(Clone, Copy, Debug)]
    pub enum Pkcs11Error {
        ArgumentsBad = cryptoki_sys::CKR_ARGUMENTS_BAD,
        AttributeSensitive = cryptoki_sys::CKR_ATTRIBUTE_SENSITIVE,
        AttributeValueInvalid = cryptoki_sys::CKR_ATTRIBUTE_VALUE_INVALID,
        BufferTooSmall = cryptoki_sys::CKR_BUFFER_TOO_SMALL,
        CryptokiNotInitialized = cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED,
        DataInvalid = cryptoki_sys::CKR_DATA_INVALID,
        DataLenRange = cryptoki_sys::CKR_DATA_LEN_RANGE,
        DeviceError = cryptoki_sys::CKR_DEVICE_ERROR,
        DeviceRemoved = cryptoki_sys::CKR_DEVICE_REMOVED,
        EncryptedDataLenRange = cryptoki_sys::CKR_ENCRYPTED_DATA_LEN_RANGE,
        KeyHandleInvalid = cryptoki_sys::CKR_KEY_HANDLE_INVALID,
        MechanismInvalid = cryptoki_sys::CKR_MECHANISM_INVALID,
        OperationActive = cryptoki_sys::CKR_OPERATION_ACTIVE,
        OperationNotInitialized = cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED,
        PinIncorrect = cryptoki_sys::CKR_PIN_INCORRECT,
        SlotIdInvalid = cryptoki_sys::CKR_SLOT_ID_INVALID,
        TokenNotPresent = cryptoki_sys::CKR_TOKEN_NOT_PRESENT,
        UserNotLoggedIn = cryptoki_sys::CKR_USER_NOT_LOGGED_IN,
        UserTypeInvalid = cryptoki_sys::CKR_USER_TYPE_INVALID,
    }
}

#[derive(Debug, Clone)]
pub struct ResponseContent {
    pub status: u16,
    pub content: String,
}

#[derive(Debug)]
pub enum ApiError {
    Ureq(String),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent),
    InstanceRemoved,
    NoInstance,
    StringParse(std::string::FromUtf8Error),
}

impl<T> From<apis::Error<T>> for ApiError {
    fn from(err: apis::Error<T>) -> Self {
        match err {
            apis::Error::Ureq(e) => ApiError::Ureq(e.to_string()),
            apis::Error::Serde(e) => ApiError::Serde(e),
            apis::Error::Io(e) => ApiError::Io(e),
            apis::Error::ResponseError(resp) => ApiError::ResponseError(ResponseContent {
                status: resp.status,
                content: String::from_utf8(resp.content).unwrap_or_else(|e| {
                    error!(
                        "Unable to parse response content into string: {:?}",
                        e.as_bytes()
                    );
                    String::default()
                }),
            }),
            apis::Error::StringParse(e) => ApiError::StringParse(e),
            apis::Error::Multipart { field: _, error } => ApiError::Io(error),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Der(der::Error),
    Pem(pem_rfc7468::Error),
    NotLoggedIn(UserMode),
    InvalidObjectHandle(CK_OBJECT_HANDLE),
    InvalidMechanism((String, ObjectKind), Mechanism),
    InvalidAttribute(CK_ATTRIBUTE_TYPE),
    MissingAttribute(CK_ATTRIBUTE_TYPE),
    ObjectClassNotSupported,
    InvalidMechanismMode(MechMode, Mechanism),
    Api(ApiError),
    Base64(base64ct::Error),
    StringParse(std::string::FromUtf8Error),
    Login(LoginError),
    OperationNotInitialized,
    LibraryNotInitialized,
    OperationActive,
    // a field recieved from the API is not valid
    KeyField(String),
    DbLock,
    InvalidDataLength,
    InvalidData,
    InvalidEncryptedDataLength,
}

impl From<ApiError> for Error {
    fn from(err: ApiError) -> Self {
        Error::Api(err)
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::DbLock
    }
}

impl<T> From<apis::Error<T>> for Error {
    fn from(err: apis::Error<T>) -> Self {
        Error::Api(err.into())
    }
}

impl From<base64ct::Error> for Error {
    fn from(err: base64ct::Error) -> Self {
        Error::Base64(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::StringParse(err)
    }
}

impl From<Error> for CK_RV {
    fn from(err: Error) -> Self {
        Pkcs11Error::from(err).into()
    }
}

impl From<Error> for Pkcs11Error {
    fn from(err: Error) -> Self {
        // diplay the error when converting to CK_RV
        error!("{err}");
        match err {
            Error::Der(_) => Self::DeviceError,
            Error::Pem(_) => Self::DeviceError,
            Error::InvalidEncryptedDataLength => Self::EncryptedDataLenRange,
            Error::InvalidData => Self::DataInvalid,
            Error::InvalidDataLength => Self::DataLenRange,
            Error::InvalidObjectHandle(_) => Self::KeyHandleInvalid,
            Error::OperationNotInitialized => Self::OperationNotInitialized,
            Error::LibraryNotInitialized => Self::CryptokiNotInitialized,
            Error::DbLock => Self::DeviceError,
            Error::KeyField(_) => Self::DeviceError,
            Error::OperationActive => Self::OperationActive,
            Error::Login(e) => e.into(),
            Error::InvalidAttribute(_) => Self::AttributeValueInvalid,
            Error::ObjectClassNotSupported => Self::AttributeValueInvalid,
            Error::MissingAttribute(_) => Self::ArgumentsBad,
            Error::NotLoggedIn(_) => Self::UserNotLoggedIn,
            Error::InvalidMechanism(_, _) => Self::MechanismInvalid,
            Error::InvalidMechanismMode(_, _) => Self::MechanismInvalid,
            Error::Base64(_) | Error::StringParse(_) => Self::DeviceError,
            Error::Api(err) => match err {
                ApiError::NoInstance => Self::TokenNotPresent,
                ApiError::Ureq(_) => Self::DeviceError,
                ApiError::Io(_) => Self::DeviceError,
                ApiError::Serde(_) => Self::DeviceError,
                ApiError::ResponseError(resp) => match resp.status {
                    404 => Self::KeyHandleInvalid,
                    401 | 403 => Self::UserNotLoggedIn,
                    412 => Self::TokenNotPresent,
                    _ => Self::DeviceError,
                },
                ApiError::StringParse(_) => Self::DeviceError,
                ApiError::InstanceRemoved => Self::DeviceRemoved,
            },
        }
    }
}

// display error
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg = match self {
            Error::Der(err) => format!("DER error: {err:?}"),
            Error::Pem(err) => format!("PEM error: {err:?}"),
            Error::InvalidEncryptedDataLength => "Invalid encrypted data length".to_string(),
            Error::InvalidData => "Invalid input data".to_string(),
            Error::InvalidDataLength => "Invalid input data length".to_string(),
            Error::InvalidObjectHandle(handle) => {
                format!("Object handle does not exist: {handle}")
            }
            Error::OperationNotInitialized => "Operation not initialized".to_string(),
            Error::LibraryNotInitialized => "Library not initialized".to_string(),
            Error::DbLock => "Internal mutex lock error".to_string(),
            Error::KeyField(field) => {
                format!("Key field {field} received from the NetHSM is not valid")
            }
            Error::OperationActive => "An operation is already active for this session".to_string(),
            Error::Login(err) => err.to_string(),
            Error::NotLoggedIn(mode) => {
                format!("The module needs to be logged in as {mode:?}, check the configuration")
            }
            Error::InvalidMechanism(obj, mech) => {
                format!(
                    "The mechanism {:?} not supported for {:?} {}",
                    mech, obj.1, obj.0
                )
            }
            Error::InvalidAttribute(attr) => format!("Invalid attribute: {attr:?}"),
            Error::MissingAttribute(attr) => format!("Missing attribute: {attr:?}"),
            Error::ObjectClassNotSupported => "Object class not supported".to_string(),
            Error::InvalidMechanismMode(mode, mechanism) => {
                format!("Unable to use mechanim {mechanism:?} for {mode:?}")
            }
            Error::Api(err) => match err {
                ApiError::NoInstance => "No valid instance in the slot".to_string(),
                ApiError::Ureq(err) => format!("Request error : {err}"),
                ApiError::Serde(err) => format!("Serde error: {err:?}"),
                ApiError::Io(err) => format!("IO error: {err:?}"),
                ApiError::ResponseError(resp) => match resp.status {
                    404 => "Key not found".to_string(),
                    401 | 403 => "Invalid credentials".to_string(),
                    412 => "The NetHSM is not set up properly".to_string(),
                    _ => format!("Api error: {resp:?}"),
                },
                ApiError::StringParse(err) => format!("String parse error: {err:?}"),
                ApiError::InstanceRemoved => "Failed to connect to instance".to_string(),
            },
            Error::Base64(err) => format!("Base64 Decode error: {err:?}"),
            Error::StringParse(err) => format!("String parse error: {err:?}"),
        };
        write!(f, "{msg}")
    }
}
