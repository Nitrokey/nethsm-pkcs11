use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR, CKR_OK, CKR_PIN_INCORRECT, CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID, CKS_RO_PUBLIC_SESSION, CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS,
    CKU_CONTEXT_SPECIFIC, CKU_SO, CKU_USER, CK_RV, CK_STATE, CK_USER_TYPE,
};
use log::{debug, error, trace};
use openapi::{
    apis::{self, configuration::Configuration, default_api, ResponseContent},
    models::UserRole,
};
use std::{fmt::Debug, future::Future};

use crate::{config::config_file::UserConfig, utils::get_tokio_rt};

use super::Error;

#[derive(Debug, Clone)]
pub struct LoginCtx {
    operator: Option<UserConfig>,
    administrator: Option<UserConfig>,
    instances: Vec<Configuration>,
    index: usize,
    ck_state: CK_STATE,
}

#[derive(Debug, Clone)]
pub enum LoginError {
    InvalidUser,
    UserNotPresent,
    BadArgument,
    IncorrectPin,
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

impl From<LoginError> for Error {
    fn from(val: LoginError) -> Self {
        Error::Login(val)
    }
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::InvalidUser => write!(f, "User type not supported"),
            LoginError::UserNotPresent => write!(f, "Username not cofigured for this user"),
            LoginError::BadArgument => write!(f, "Bad argument"),
            LoginError::IncorrectPin => write!(f, "Incorrect pin"),
        }
    }
}

impl LoginCtx {
    pub fn new(
        operator: Option<UserConfig>,
        administrator: Option<UserConfig>,
        instances: Vec<Configuration>,
    ) -> Self {
        trace!(
            "Creating login context with administrator: {:?}",
            administrator
        );

        let mut ck_state = CKS_RO_PUBLIC_SESSION;

        let firt_instance = instances.first();
        if let Some(instance) = firt_instance {
            // CKS_RW_USER_FUNCTIONS has the priority, OpenDNSSEC checks for it
            if get_user_api_config(&operator, instance).is_some() {
                ck_state = CKS_RW_USER_FUNCTIONS;
            } else if get_user_api_config(&administrator, instance).is_some() {
                ck_state = CKS_RW_SO_FUNCTIONS
            }
        }

        Self {
            operator,
            administrator,
            instances,
            index: 0,
            ck_state,
        }
    }

    pub async fn login(&mut self, user_type: CK_USER_TYPE, pin: String) -> Result<(), LoginError> {
        trace!("Login as {:?} with pin", user_type);

        let expected = match user_type {
            CKU_CONTEXT_SPECIFIC => return Err(LoginError::InvalidUser),
            CKU_SO => {
                trace!("administrator: {:?}", self.administrator);

                self.administrator = match self.administrator.as_ref() {
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

        trace!("Config: {:?}", expected.1);

        let config = expected.1.ok_or(LoginError::UserNotPresent)?;

        if get_current_user_status(&config).await == expected.0 {
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

    fn next_instance(&mut self) -> Option<Configuration> {
        self.index = (self.index + 1) % self.instances.len();
        self.instances.get(self.index).cloned()
    }

    fn operator(&mut self) -> Option<Configuration> {
        self.next_instance()
            .and_then(|instance| get_user_api_config(&self.operator, &instance))
    }

    fn administrator(&mut self) -> Option<Configuration> {
        self.next_instance()
            .and_then(|instance| get_user_api_config(&self.administrator, &instance))
    }

    fn operator_or_administrator(&mut self) -> Option<Configuration> {
        self.operator().or_else(|| self.administrator())
    }

    fn guest(&mut self) -> Option<Configuration> {
        self.next_instance()
    }

    pub fn can_run_mode(&self, mode: UserMode) -> bool {
        if self.instances.is_empty() {
            debug!("No instance configured");
            return false;
        }

        // trace!("Checking if user can run mode: {:?}", mode);

        match mode {
            UserMode::Operator => user_is_valid(&self.operator),
            UserMode::Administrator => user_is_valid(&self.administrator),
            UserMode::Guest => true,
            UserMode::OperatorOrAdministrator => {
                user_is_valid(&self.operator) || user_is_valid(&self.administrator)
            }
        }
    }

    pub fn logout(&mut self) {
        self.ck_state = CKS_RO_PUBLIC_SESSION;
    }

    pub fn get_config_user_mode(&mut self, user_mode: &UserMode) -> Option<Configuration> {
        match user_mode {
            UserMode::Operator => self.operator(),
            UserMode::Administrator => self.administrator(),
            UserMode::Guest => self.guest(),
            UserMode::OperatorOrAdministrator => self.operator_or_administrator(),
        }
    }

    // Try to run the api call on each instance until one succeeds
    pub async fn try_<'a, F, T, R, Fut>(
        &mut self,
        api_call: F,
        user_mode: UserMode,
    ) -> Result<R, Error>
    where
        F: FnOnce(Configuration) -> Fut + Clone,
        Fut: Future<Output = Result<R, apis::Error<T>>>,
    {
        // we loop for a maximum of instances.len() times
        for _ in 0..self.instances.len() {
            let conf = match self.get_config_user_mode(&user_mode) {
                Some(conf) => conf,
                None => continue,
            };

            let api_call_clone = api_call.clone();
            match api_call_clone(conf).await {
                Ok(result) => return Ok(result),

                // If the server is in an unusable state, try the next one
                Err(apis::Error::ResponseError(ResponseContent {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    ..
                }))
                | Err(apis::Error::ResponseError(ResponseContent {
                    status: reqwest::StatusCode::GATEWAY_TIMEOUT,
                    ..
                }))
                | Err(apis::Error::ResponseError(ResponseContent {
                    status: reqwest::StatusCode::BAD_GATEWAY,
                    ..
                }))
                | Err(apis::Error::ResponseError(ResponseContent {
                    status: reqwest::StatusCode::NOT_IMPLEMENTED,
                    ..
                }))
                | Err(apis::Error::ResponseError(ResponseContent {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    ..
                }))
                | Err(apis::Error::ResponseError(ResponseContent {
                    status: reqwest::StatusCode::PRECONDITION_FAILED,
                    ..
                })) => continue,

                // Otherwise, return the error
                Err(err) => return Err(err.into()),
            }
        }
        Err(Error::NoInstance)
    }

    pub fn ck_state(&self) -> CK_STATE {
        self.ck_state
    }
    pub fn change_pin(&mut self, pin: String) -> CK_RV {
        let options = match self.ck_state {
            CKS_RW_SO_FUNCTIONS => {
                let username = match self.administrator {
                    Some(ref user) => user.username.clone(),
                    None => return CKR_USER_NOT_LOGGED_IN,
                };

                (username, UserMode::Administrator)
            }
            CKS_RW_USER_FUNCTIONS => {
                let username = match self.operator {
                    Some(ref user) => user.username.clone(),
                    None => return CKR_USER_NOT_LOGGED_IN,
                };

                (username, UserMode::Operator)
            }
            _ => return CKR_USER_NOT_LOGGED_IN,
        };

        match get_tokio_rt().block_on(self.try_(
            |config| async move {
                default_api::users_user_id_passphrase_post(
                    &config,
                    &options.0,
                    openapi::models::UserPassphrasePostData { passphrase: pin },
                )
                .await
            },
            options.1,
        )) {
            Ok(_) => CKR_OK,
            Err(err) => {
                error!("Failed to change pin: {:?}", err);
                CKR_DEVICE_ERROR
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum UserMode {
    Operator,
    Administrator,
    Guest,
    OperatorOrAdministrator,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UserStatus {
    Operator,
    Administrator,
    LoggedOut,
}

pub async fn get_current_user_status(
    api_config: &openapi::apis::configuration::Configuration,
) -> UserStatus {
    let auth = match api_config.basic_auth.as_ref() {
        Some(auth) => auth,
        None => return UserStatus::LoggedOut,
    };

    if auth.1.is_none() {
        return UserStatus::LoggedOut;
    }

    let user = match default_api::users_user_id_get(api_config, auth.0.as_str()).await {
        Ok(user) => user.entity,
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

fn user_is_valid(user: &Option<UserConfig>) -> bool {
    user.as_ref()
        .map(|user| {
            !user.username.is_empty()
                && user
                    .password
                    .as_ref()
                    .map(|password| !password.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_user_is_valid() {
        let user = UserConfig {
            username: "test".to_string(),
            password: Some("password".to_string()),
        };
        let empty_password_user = UserConfig {
            username: "test".to_string(),
            password: None,
        };

        assert!(user_is_valid(&Some(user)));
        assert!(!user_is_valid(&None));
        assert!(!user_is_valid(&Some(empty_password_user)));
    }
}
