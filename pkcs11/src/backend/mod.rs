use std::sync::PoisonError;

use self::{
    db::object::ObjectKind,
    login::{LoginError, UserMode},
    mechanism::{MechMode, Mechanism},
};
use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_VALUE_INVALID, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
    CKR_TOKEN_NOT_PRESENT, CKR_USER_NOT_LOGGED_IN, CK_ATTRIBUTE_TYPE, CK_OBJECT_HANDLE, CK_RV,
};
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
                    format!(
                        "Unable to parse response content into string: {:?}",
                        e.as_bytes()
                    );
                    String::default()
                }),
            }),
            apis::Error::StringParse(e) => ApiError::StringParse(e),
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
    Base64Error(base64ct::Error),
    StringParse(std::string::FromUtf8Error),
    Login(LoginError),
    OperationNotInitialized,
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
        Error::Base64Error(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::StringParse(err)
    }
}

impl From<Error> for CK_RV {
    fn from(err: Error) -> Self {
        // diplay the error when converting to CK_RV
        error!("{}", err);
        match err {
            Error::Der(_) => CKR_DEVICE_ERROR,
            Error::Pem(_) => CKR_DEVICE_ERROR,
            Error::InvalidEncryptedDataLength => CKR_ENCRYPTED_DATA_LEN_RANGE,
            Error::InvalidData => CKR_DATA_INVALID,
            Error::InvalidDataLength => CKR_DATA_LEN_RANGE,
            Error::InvalidObjectHandle(_) => CKR_KEY_HANDLE_INVALID,
            Error::OperationNotInitialized => CKR_OPERATION_NOT_INITIALIZED,
            Error::DbLock => CKR_DEVICE_ERROR,
            Error::KeyField(_) => CKR_DEVICE_ERROR,
            Error::OperationActive => CKR_OPERATION_ACTIVE,
            Error::Login(e) => e.into(),
            Error::InvalidAttribute(_) => CKR_ATTRIBUTE_VALUE_INVALID,
            Error::ObjectClassNotSupported => CKR_DEVICE_MEMORY,
            Error::MissingAttribute(_) => CKR_ARGUMENTS_BAD,
            Error::NotLoggedIn(_) => CKR_USER_NOT_LOGGED_IN,
            Error::InvalidMechanism(_, _) => CKR_MECHANISM_INVALID,
            Error::InvalidMechanismMode(_, _) => CKR_MECHANISM_INVALID,
            Error::Base64Error(_) | Error::StringParse(_) => CKR_DEVICE_ERROR,
            Error::Api(err) => match err {
                ApiError::NoInstance => CKR_TOKEN_NOT_PRESENT,
                ApiError::Ureq(_) => CKR_DEVICE_ERROR,
                ApiError::Io(_) => CKR_DEVICE_ERROR,
                ApiError::Serde(_) => CKR_DEVICE_ERROR,
                ApiError::ResponseError(resp) => match resp.status {
                    404 => CKR_KEY_HANDLE_INVALID,
                    401 | 403 => CKR_USER_NOT_LOGGED_IN,
                    412 => CKR_TOKEN_NOT_PRESENT,
                    _ => CKR_DEVICE_ERROR,
                },
                ApiError::StringParse(_) => CKR_DEVICE_ERROR,
            },
        }
    }
}

// display error
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg = match self {
            Error::Der(err) => format!("DER error: {:?}", err),
            Error::Pem(err) => format!("PEM error: {:?}", err),
            Error::InvalidEncryptedDataLength => "Invalid encrypted data length".to_string(),
            Error::InvalidData => "Invalid input data".to_string(),
            Error::InvalidDataLength => "Invalid input data length".to_string(),
            Error::InvalidObjectHandle(handle) => {
                format!("Object handle does not exist: {}", handle)
            }
            Error::OperationNotInitialized => "Operation not initialized".to_string(),
            Error::DbLock => "Internal mutex lock error".to_string(),
            Error::KeyField(field) => {
                format!("Key field {} received from the NetHSM is not valid", field)
            }
            Error::OperationActive => "An operation is already active for this session".to_string(),
            Error::Login(err) => err.to_string(),
            Error::NotLoggedIn(mode) => format!(
                "The module needs to be logged in as {:?}, check the configuration",
                mode
            ),
            Error::InvalidMechanism(obj, mech) => {
                format!(
                    "The mechanism {:?} not supported for {:?} {}",
                    mech, obj.1, obj.0
                )
            }
            Error::InvalidAttribute(attr) => format!("Invalid attribute: {:?}", attr),
            Error::MissingAttribute(attr) => format!("Missing attribute: {:?}", attr),
            Error::ObjectClassNotSupported => "Object class not supported".to_string(),
            Error::InvalidMechanismMode(mode, mechanism) => {
                format!("Unable to use mechanim {:?} for {:?}", mechanism, mode)
            }
            Error::Api(err) => match err {
                ApiError::NoInstance => "No valid instance in the slot".to_string(),
                ApiError::Ureq(err) => format!("Request error : {}", err),
                ApiError::Serde(err) => format!("Serde error: {:?}", err),
                ApiError::Io(err) => format!("IO error: {:?}", err),
                ApiError::ResponseError(resp) => match resp.status {
                    404 => "Key not found".to_string(),
                    401 | 403 => "Invalid credentials".to_string(),
                    412 => "The NetHSM is not set up properly".to_string(),
                    _ => format!("Api error: {:?}", resp),
                },
                ApiError::StringParse(err) => format!("String parse error: {:?}", err),
            },
            Error::Base64Error(err) => format!("Base64 Decode error: {:?}", err),
            Error::StringParse(err) => format!("String parse error: {:?}", err),
        };
        write!(f, "{}", msg)
    }
}
