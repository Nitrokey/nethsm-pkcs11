use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_PIN_INCORRECT, CKR_USER_TYPE_INVALID, CKU_CONTEXT_SPECIFIC, CKU_SO,
    CKU_USER, CK_RV, CK_USER_TYPE,
};
use log::error;
use openapi::{
    apis::{configuration::Configuration, default_api},
    models::UserRole,
};

use crate::config::config_file::UserConfig;

#[derive(Debug, Clone)]
pub enum LoginError {
    InvalidUser,
    UserNotPresent,
    BadArgument,
    IncorrectPin,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UserStatus {
    Operator,
    Administrator,
    LoggedOut,
}

impl From<LoginError> for CK_RV {
    fn from(val: LoginError) -> Self {
        match val {
            LoginError::InvalidUser => CKR_USER_TYPE_INVALID,
            LoginError::UserNotPresent => CKR_USER_TYPE_INVALID,
            LoginError::BadArgument => CKR_ARGUMENTS_BAD,
            LoginError::IncorrectPin => CKR_PIN_INCORRECT,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoginCtx {
    operator: Option<UserConfig>,
    administator: Option<UserConfig>,
    api_config: openapi::apis::configuration::Configuration,
}

impl LoginCtx {
    pub fn new(
        operator: Option<UserConfig>,
        administator: Option<UserConfig>,
        api_config: openapi::apis::configuration::Configuration,
    ) -> Self {
        Self {
            operator,
            administator,
            api_config,
        }
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: String) -> Result<(), LoginError> {
        let expected = match user_type {
            CKU_CONTEXT_SPECIFIC => return Err(LoginError::InvalidUser),
            CKU_SO => {
                self.administator = match self.administator.as_ref() {
                    None => return Err(LoginError::UserNotPresent),
                    Some(user) => Some(UserConfig {
                        password: Some(pin),
                        ..user.clone()
                    }),
                };
                (UserStatus::Administrator, self.administrator())
            }
            CKU_USER => {
                self.operator = match self.operator.as_ref() {
                    None => return Err(LoginError::UserNotPresent),
                    Some(user) => Some(UserConfig {
                        password: Some(pin),
                        ..user.clone()
                    }),
                };
                (UserStatus::Operator, self.operator())
            }
            _ => return Err(LoginError::BadArgument),
        };

        let config = expected.1.ok_or(LoginError::UserNotPresent)?;

        if get_current_user_status(&config) == expected.0 {
            Ok(())
        } else {
            error!("Failed to login as {:?} with pin", expected.0);
            Err(LoginError::IncorrectPin)
        }
    }

    // Get the configuration to connect as operator
    pub fn operator(&self) -> Option<Configuration> {
        self.operator.as_ref().and_then(|user| {
            let config = self.api_config.clone();
            if user.password.is_none() {
                None
            } else {
                Some(Configuration {
                    basic_auth: Some((user.username.clone(), user.password.clone())),
                    ..config
                })
            }
        })
    }

    // Get the configuration to connect as administrator
    pub fn administrator(&self) -> Option<Configuration> {
        self.administator.as_ref().and_then(|user| {
            let config = self.api_config.clone();
            if user.password.is_none() {
                None
            } else {
                Some(Configuration {
                    basic_auth: Some((user.username.clone(), user.password.clone())),
                    ..config
                })
            }
        })
    }

    // Get the configuration to connect whith when we don't care if it's operator or administrator
    pub fn operator_or_administrator(&self) -> Option<Configuration> {
        self.operator().or_else(|| self.administrator())
    }

    // Get the user status
    pub fn user_status(&self) -> UserStatus {
        if self.administator.is_some() {
            UserStatus::Administrator
        } else if self.operator.is_some() {
            UserStatus::Operator
        } else {
            UserStatus::LoggedOut
        }
    }
}

pub fn get_current_user_status(
    api_config: &openapi::apis::configuration::Configuration,
) -> UserStatus {
    let auth = match api_config.basic_auth.as_ref() {
        Some(auth) => auth,
        None => return UserStatus::LoggedOut,
    };

    if auth.1.is_none() {
        return UserStatus::LoggedOut;
    }

    let user = match default_api::users_user_id_get(api_config, auth.0.as_str()) {
        Ok(user) => user,
        Err(err) => {
            error!("Failed to get user: {:?}", err);
            return UserStatus::LoggedOut;
        }
    };

    match user.role {
        UserRole::Operator => UserStatus::Operator,
        UserRole::Administrator => UserStatus::Administrator,
        _ => UserStatus::LoggedOut,
    }
}
