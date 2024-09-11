use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR, CKR_OK, CKR_PIN_INCORRECT, CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID, CKS_RO_PUBLIC_SESSION, CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS,
    CKU_CONTEXT_SPECIFIC, CKU_SO, CKU_USER, CK_RV, CK_STATE, CK_USER_TYPE,
};
use log::{debug, error, trace, warn};
use nethsm_sdk_rs::{
    apis::{self, configuration::Configuration, default_api, ResponseContent},
    models::UserRole,
    ureq,
};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
};

use crate::config::{
    config_file::{RetryConfig, UserConfig},
    device::{InstanceAttempt, InstanceData, Slot},
};

use super::{ApiError, Error};

#[derive(Debug)]
pub struct LoginCtx {
    slot: Arc<Slot>,
    /// If set to `Some`, this will be used to replace the slot's default value when performing requests
    ///
    /// Set to `Some` by `C_Login`
    operator_login_override: Option<UserConfig>,
    admin_login_override: Option<UserConfig>,
    admin_allowed: bool,
    operator_allowed: bool,
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
    pub fn new(slot: Arc<Slot>, admin_allowed: bool, operator_allowed: bool) -> Self {
        let mut ck_state = CKS_RO_PUBLIC_SESSION;

        // CKS_RW_USER_FUNCTIONS has the priority, OpenDNSSEC checks for it
        if operator_allowed && slot.operator.is_some() {
            ck_state = CKS_RW_USER_FUNCTIONS;
        } else if admin_allowed && slot.administrator.is_some() {
            ck_state = CKS_RW_SO_FUNCTIONS
        }

        Self {
            slot,
            operator_login_override: None,
            admin_login_override: None,
            operator_allowed,
            admin_allowed,
            ck_state,
        }
    }

    fn operator_config(&self) -> Option<&UserConfig> {
        if !self.operator_allowed {
            return None;
        }
        self.operator_login_override
            .as_ref()
            .or(self.slot.operator.as_ref())
    }

    fn admin_config(&self) -> Option<&UserConfig> {
        if !self.admin_allowed {
            return None;
        }
        self.admin_login_override
            .as_ref()
            .or(self.slot.administrator.as_ref())
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: String) -> Result<(), LoginError> {
        trace!("Login as {:?} with pin", user_type);

        let expected = match user_type {
            CKU_CONTEXT_SPECIFIC => return Err(LoginError::InvalidUser),
            CKU_SO => {
                trace!("administrator: {:?}", self.slot.administrator);

                self.admin_login_override = match self.admin_config() {
                    None => return Err(LoginError::UserNotPresent),
                    Some(user) => Some(UserConfig {
                        password: Some(pin),
                        ..user.clone()
                    }),
                };
                self.admin_allowed = true;
                (UserStatus::Administrator, self.administrator())
            }
            CKU_USER => {
                self.operator_login_override = match self.operator_config() {
                    None => return Err(LoginError::UserNotPresent),
                    Some(user) => Some(UserConfig {
                        password: Some(pin),
                        ..user.clone()
                    }),
                };
                self.operator_allowed = true;
                (UserStatus::Operator, self.operator())
            }
            _ => return Err(LoginError::BadArgument),
        };

        trace!("Config: {:?}", expected.1);

        let config = expected.1.ok_or(LoginError::UserNotPresent)?.config;

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

    fn next_instance(&self) -> &InstanceData {
        let index = self.slot.instance_balancer.fetch_add(1, Relaxed);
        let index = index % self.slot.instances.len();
        let instance = &self.slot.instances[index];
        match instance.should_try() {
            InstanceAttempt::Failed => {}
            InstanceAttempt::Working | InstanceAttempt::Retry => return instance,
        }
        for i in 0..self.slot.instances.len() - 1 {
            let instance = &self.slot.instances[index + i];

            match instance.should_try() {
                InstanceAttempt::Failed => continue,
                InstanceAttempt::Working | InstanceAttempt::Retry => {
                    // This not true round-robin in case of multithreaded acces
                    // This is degraded mode so best-effort is attempted at best
                    self.slot.instance_balancer.fetch_add(i, Relaxed);
                    return instance;
                }
            }
        }

        // No instance is valid, return a failed instance for an attempt
        let index = self.slot.instance_balancer.fetch_add(1, Relaxed);
        let index = index % self.slot.instances.len();
        &self.slot.instances[index]
    }

    fn operator(&self) -> Option<InstanceData> {
        get_user_api_config(self.operator_config(), self.next_instance())
    }

    fn administrator(&self) -> Option<InstanceData> {
        get_user_api_config(self.admin_config(), self.next_instance())
    }

    fn operator_or_administrator(&self) -> Option<InstanceData> {
        self.operator().or_else(|| self.administrator())
    }

    fn guest(&self) -> &InstanceData {
        self.next_instance()
    }

    pub fn can_run_mode(&self, mode: UserMode) -> bool {
        if self.slot.instances.is_empty() {
            debug!("No instance configured");
            return false;
        }

        // trace!("Checking if user can run mode: {:?}", mode);

        match mode {
            UserMode::Operator => user_is_valid(self.operator_config()),
            UserMode::Administrator => user_is_valid(self.admin_config()),
            UserMode::Guest => true,
            UserMode::OperatorOrAdministrator => {
                user_is_valid(self.operator_config()) || user_is_valid(self.admin_config())
            }
        }
    }

    pub fn logout(&mut self) {
        self.ck_state = CKS_RO_PUBLIC_SESSION;
    }

    pub fn get_config_user_mode(&self, user_mode: &UserMode) -> Option<InstanceData> {
        match user_mode {
            UserMode::Operator => self.operator(),
            UserMode::Administrator => self.administrator(),
            UserMode::Guest => Some(self.guest().clone()),
            UserMode::OperatorOrAdministrator => self.operator_or_administrator(),
        }
    }

    // Try to run the api call on each instance until one succeeds
    pub fn try_<F, T, R>(&self, api_call: F, user_mode: UserMode) -> Result<R, Error>
    where
        F: FnOnce(&Configuration) -> Result<R, apis::Error<T>> + Clone,
    {
        // we loop for a maximum of instances.len() times
        let Some(mut instance) = self.get_config_user_mode(&user_mode) else {
            return Err(Error::Login(LoginError::UserNotPresent));
        };

        let mut retry_count = 0;
        let RetryConfig {
            count: retry_limit,
            delay_seconds,
        } = self.slot.retries.unwrap_or(RetryConfig {
            count: 1,
            delay_seconds: 0,
        });

        let delay = Duration::from_secs(delay_seconds);

        loop {
            if retry_count == retry_limit {
                error!(
                    "Retry count exceeded after {retry_limit} attempts, instance is unreachable"
                );
                return Err(ApiError::InstanceRemoved.into());
            }
            retry_count += 1;
            let api_call_clone = api_call.clone();
            match api_call_clone(&instance.config) {
                Ok(result) => {
                    instance.clear_failed();
                    return Ok(result);
                }

                // If the server is in an unusable state, skip retries and try the next one
                Err(apis::Error::ResponseError(err @ ResponseContent { status: 500, .. }))
                | Err(apis::Error::ResponseError(err @ ResponseContent { status: 501, .. }))
                | Err(apis::Error::ResponseError(err @ ResponseContent { status: 502, .. }))
                | Err(apis::Error::ResponseError(err @ ResponseContent { status: 503, .. }))
                | Err(apis::Error::ResponseError(err @ ResponseContent { status: 412, .. })) => {
                    instance.bump_failed();

                    warn!("Connection attempt {retry_count} failed: Status error connecting to the instance, {:?}, retrying in {delay_seconds}s", err.status);
                    thread::sleep(delay);
                    if let Some(new_conf) = self.get_config_user_mode(&user_mode) {
                        instance = new_conf;
                    }
                }

                // If the connection to the server failed with a network error, reconnecting might solve the issue
                Err(apis::Error::Ureq(ureq::Error::Transport(err)))
                    if matches!(
                        err.kind(),
                        ureq::ErrorKind::Io | ureq::ErrorKind::ConnectionFailed
                    ) =>
                {
                    instance.bump_failed();
                    warn!("Connection attempt {retry_count} failed: IO error connecting to the instance, {err}, retrying in {delay_seconds}s");
                    thread::sleep(delay);
                    if let Some(new_conf) = self.get_config_user_mode(&user_mode) {
                        instance = new_conf;
                    }
                }
                // Otherwise, return the error
                Err(err) => return Err(err.into()),
            }
        }
    }

    pub fn ck_state(&self) -> CK_STATE {
        self.ck_state
    }
    pub fn change_pin(&mut self, pin: String) -> CK_RV {
        let options = match self.ck_state {
            CKS_RW_SO_FUNCTIONS => {
                let username = match self.admin_config() {
                    Some(user) => user.username.clone(),
                    None => return CKR_USER_NOT_LOGGED_IN,
                };

                (username, UserMode::Administrator)
            }
            CKS_RW_USER_FUNCTIONS => {
                let username = match self.operator_config() {
                    Some(user) => user.username.clone(),
                    None => return CKR_USER_NOT_LOGGED_IN,
                };

                (username, UserMode::Operator)
            }
            _ => return CKR_USER_NOT_LOGGED_IN,
        };

        match self.try_(
            |config| {
                default_api::users_user_id_passphrase_post(
                    config,
                    &options.0,
                    nethsm_sdk_rs::models::UserPassphrasePostData { passphrase: pin },
                )
            },
            options.1,
        ) {
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

pub fn get_current_user_status(
    api_config: &nethsm_sdk_rs::apis::configuration::Configuration,
) -> UserStatus {
    let auth = match api_config.basic_auth.as_ref() {
        Some(auth) => auth,
        None => return UserStatus::LoggedOut,
    };

    if auth.1.is_none() {
        return UserStatus::LoggedOut;
    }

    let user = match default_api::users_user_id_get(api_config, auth.0.as_str()) {
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
    user: Option<&UserConfig>,
    api_config: &InstanceData,
) -> Option<InstanceData> {
    let user = user?;

    #[allow(clippy::question_mark)]
    if user.password.is_none() {
        return None;
    }

    Some(InstanceData {
        config: Configuration {
            basic_auth: Some((user.username.clone(), user.password.clone())),
            ..api_config.config.clone()
        },
        state: api_config.state.clone(),
    })
}

fn user_is_valid(user: Option<&UserConfig>) -> bool {
    let Some(user) = user else { return false };
    let Some(ref password) = user.password else {
        return false;
    };
    !user.username.is_empty() && !password.is_empty()
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

        assert!(user_is_valid(Some(&user)));
        assert!(!user_is_valid(None));
        assert!(!user_is_valid(Some(&empty_password_user)));
    }
}
