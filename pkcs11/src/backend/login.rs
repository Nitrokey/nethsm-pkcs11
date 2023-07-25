use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_PIN_INCORRECT, CKR_USER_TYPE_INVALID, CKS_RO_PUBLIC_SESSION,
    CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CKU_CONTEXT_SPECIFIC, CKU_SO, CKU_USER, CK_RV,
    CK_STATE, CK_USER_TYPE,
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
    ck_state: CK_STATE,
}

impl LoginCtx {
    pub fn new(
        operator: Option<UserConfig>,
        administator: Option<UserConfig>,
        api_config: openapi::apis::configuration::Configuration,
    ) -> Self {
        let mut state = CKS_RO_PUBLIC_SESSION;

        if get_user_api_config(&operator, &api_config).is_some() {
            state = CKS_RW_USER_FUNCTIONS;
        } else if get_user_api_config(&administator, &api_config).is_some() {
            state = CKS_RW_SO_FUNCTIONS;
        }

        Self {
            operator,
            administator,
            api_config,
            ck_state: state,
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
            self.ck_state = match expected.0 {
                UserStatus::Operator => CKS_RW_USER_FUNCTIONS,
                UserStatus::Administrator => CKS_RW_SO_FUNCTIONS,
                UserStatus::LoggedOut => CKS_RO_PUBLIC_SESSION,
            };
            Ok(())
        } else {
            error!("Failed to login as {:?} with pin", expected.0);
            Err(LoginError::IncorrectPin)
        }
    }

    // Get the configuration to connect as operator
    pub fn operator(&self) -> Option<Configuration> {
        get_user_api_config(&self.operator, &self.api_config)
    }

    // Get the configuration to connect as administrator
    pub fn administrator(&self) -> Option<Configuration> {
        get_user_api_config(&self.administator, &self.api_config)
    }

    // Get the configuration to connect whith when we don't care if it's operator or administrator
    pub fn operator_or_administrator(&self) -> Option<Configuration> {
        self.operator().or_else(|| self.administrator())
    }

    // Get the state for the session
    pub fn ck_state(&self) -> CK_STATE {
        self.ck_state
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

// Check if the user is logged in and then return the configuration to connect as this user
fn get_user_api_config(
    user: &Option<UserConfig>,
    api_config: &openapi::apis::configuration::Configuration,
) -> Option<openapi::apis::configuration::Configuration> {
    user.as_ref().and_then(|user| {
        let config = api_config.clone();
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
