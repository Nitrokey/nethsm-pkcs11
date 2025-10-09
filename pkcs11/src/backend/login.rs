use cryptoki_sys::{
    CKS_RO_PUBLIC_SESSION, CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CKU_CONTEXT_SPECIFIC,
    CKU_SO, CKU_USER, CK_STATE, CK_USER_TYPE,
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

use crate::{
    config::{
        config_file::{RetryConfig, UserConfig},
        device::{InstanceAttempt, InstanceData, Slot},
    },
    data::THREADS_ALLOWED,
};

use super::{ApiError, Error, Pkcs11Error};

#[derive(Debug)]
enum ShouldHealthCheck {
    /// The instance is ready to be used
    RunDirectly,
    /// The instance needs to first be health checked
    HealthCheckFirst,
}

impl ShouldHealthCheck {
    fn should_check(&self) -> bool {
        matches!(self, ShouldHealthCheck::HealthCheckFirst)
    }
}

#[derive(Debug, Clone, Copy)]
enum HealthCheck {
    Possible,
    Avoid,
}

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

impl From<LoginError> for Pkcs11Error {
    fn from(val: LoginError) -> Self {
        match val {
            LoginError::InvalidUser => Self::UserTypeInvalid,
            LoginError::UserNotPresent => Self::UserTypeInvalid,
            LoginError::BadArgument => Self::ArgumentsBad,
            LoginError::IncorrectPin => Self::PinIncorrect,
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

/// Perform a health check with a timeout of 1 second
fn health_check_get_timeout(instance: &InstanceData) -> bool {
    instance.clear_pool();
    let config = &instance.config();
    let uri_str = format!("{}/health/ready", config.base_path);
    let mut req = config
        .client
        .get(&uri_str)
        .config()
        .timeout_global(Some(Duration::from_secs(1)))
        .build();
    if let Some(ref user_agent) = config.user_agent {
        req = req.header("user-agent", user_agent);
    }

    match req.call() {
        Ok(r) => {
            if r.status() == 200 {
                instance.clear_failed();
                return true;
            }
            log::warn!("Failed retry {}", r.status());
            instance.bump_failed();
            false
        }

        Err(err) => {
            log::warn!("Failed retry {err:?}");
            instance.bump_failed();
            false
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

    pub fn slot(&self) -> &Arc<Slot> {
        &self.slot
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
        trace!("Login as {user_type:?} with pin");

        let (user_status, user_mode) = match user_type {
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
                (UserStatus::Administrator, UserMode::Administrator)
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
                (UserStatus::Operator, UserMode::Operator)
            }
            _ => return Err(LoginError::BadArgument),
        };

        let got_user = self
            .try_(get_current_user_status, user_mode)
            .map_err(|err| {
                error!("Login check failed: {err:?}");
                LoginError::UserNotPresent
            })?;

        if got_user == user_status {
            self.ck_state = match user_status {
                UserStatus::Operator => CKS_RW_USER_FUNCTIONS,
                UserStatus::Administrator => CKS_RW_SO_FUNCTIONS,
                UserStatus::LoggedOut => CKS_RO_PUBLIC_SESSION,
            };
            Ok(())
        } else {
            error!("Failed to login as {user_mode:?} with pin, got user {got_user:?}");
            Err(LoginError::IncorrectPin)
        }
    }

    fn next_instance(
        &self,
        accept_health_check: HealthCheck,
    ) -> (&InstanceData, ShouldHealthCheck) {
        let threads_allowed = THREADS_ALLOWED.load(Relaxed);
        let index = self.slot.instance_balancer.fetch_add(1, Relaxed);
        let index = index % self.slot.instances.len();
        let instance = &self.slot.instances[index];
        match (instance.should_try(), threads_allowed, accept_health_check) {
            (InstanceAttempt::Failed, _, _)
            | (InstanceAttempt::Retry, true, _)
            | (InstanceAttempt::Retry, false, HealthCheck::Avoid) => {}
            (InstanceAttempt::Working, _, _) => return (instance, ShouldHealthCheck::RunDirectly),
            (InstanceAttempt::Retry, false, HealthCheck::Possible) => {
                return (instance, ShouldHealthCheck::HealthCheckFirst)
            }
        }
        for i in 0..self.slot.instances.len() - 1 {
            let instance = &self.slot.instances[index + i];

            match (instance.should_try(), threads_allowed, accept_health_check) {
                (InstanceAttempt::Failed, _, _)
                | (InstanceAttempt::Retry, true, _)
                | (InstanceAttempt::Retry, false, HealthCheck::Avoid) => continue,
                (InstanceAttempt::Working, _, _) => {
                    // This not true round-robin in case of multithreaded acces
                    // This is degraded mode so best-effort is attempted at best
                    self.slot.instance_balancer.fetch_add(i, Relaxed);
                    return (instance, ShouldHealthCheck::RunDirectly);
                }
                (InstanceAttempt::Retry, false, HealthCheck::Possible) => {
                    // This not true round-robin in case of multithreaded acces
                    // This is degraded mode so best-effort is attempted at best
                    self.slot.instance_balancer.fetch_add(i, Relaxed);
                    return (instance, ShouldHealthCheck::HealthCheckFirst);
                }
            }
        }

        // No instance is valid, return a failed instance for an attempt
        let index = self.slot.instance_balancer.fetch_add(1, Relaxed);
        let index = index % self.slot.instances.len();
        // Instance is not valid, don't try health check, it would only slow things down
        (&self.slot.instances[index], ShouldHealthCheck::RunDirectly)
    }

    fn operator(
        &self,
        accept_health_check: HealthCheck,
    ) -> Option<(InstanceData, ShouldHealthCheck)> {
        let (instance, should_health_check) = self.next_instance(accept_health_check);
        get_user_api_config(self.operator_config(), instance).map(|c| (c, should_health_check))
    }

    fn administrator(
        &self,
        accept_health_check: HealthCheck,
    ) -> Option<(InstanceData, ShouldHealthCheck)> {
        let (instance, should_health_check) = self.next_instance(accept_health_check);
        get_user_api_config(self.admin_config(), instance).map(|c| (c, should_health_check))
    }

    fn operator_or_administrator(
        &self,
        accept_health_check: HealthCheck,
    ) -> Option<(InstanceData, ShouldHealthCheck)> {
        self.operator(accept_health_check)
            .or_else(|| self.administrator(accept_health_check))
    }

    fn guest(&self, accept_health_check: HealthCheck) -> (&InstanceData, ShouldHealthCheck) {
        self.next_instance(accept_health_check)
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

    fn get_config_user_mode(
        &self,
        user_mode: &UserMode,
        accept_health_check: HealthCheck,
    ) -> Option<(InstanceData, ShouldHealthCheck)> {
        match user_mode {
            UserMode::Operator => self.operator(accept_health_check),
            UserMode::Administrator => self.administrator(accept_health_check),
            UserMode::Guest => {
                let (instance, should_health_check) = self.guest(accept_health_check);
                Some((instance.clone(), should_health_check))
            }
            UserMode::OperatorOrAdministrator => {
                self.operator_or_administrator(accept_health_check)
            }
        }
    }

    // Try to run the api call on each instance until one succeeds
    pub fn try_<F, T, R>(&self, api_call: F, user_mode: UserMode) -> Result<R, Error>
    where
        F: FnOnce(&Configuration) -> Result<R, apis::Error<T>> + Clone,
    {
        let mut health_check_count = 0;
        // we loop for a maximum of instances.len() times
        let Some((mut instance, mut should_health_check)) =
            self.get_config_user_mode(&user_mode, HealthCheck::Possible)
        else {
            return Err(Error::Login(LoginError::UserNotPresent));
        };

        let mut retry_count = 0;
        let RetryConfig {
            count: retry_limit,
            delay_seconds,
        } = self.slot.retries.unwrap_or(RetryConfig {
            count: 0,
            delay_seconds: 0,
        });

        let delay = Duration::from_secs(delay_seconds);

        loop {
            let accept_health_check = if health_check_count < 3 {
                HealthCheck::Possible
            } else {
                HealthCheck::Avoid
            };
            if retry_count > retry_limit {
                error!(
                    "Retry count exceeded after {retry_limit} attempts, instance is unreachable"
                );
                return Err(ApiError::InstanceRemoved.into());
            }

            if should_health_check.should_check() && !health_check_get_timeout(&instance) {
                health_check_count += 1;
                // Instance is not valid, we try the next one
                if let Some((new_instance, new_should_health_check)) =
                    self.get_config_user_mode(&user_mode, accept_health_check)
                {
                    instance = new_instance;
                    should_health_check = new_should_health_check;
                }
                continue;
            }

            retry_count += 1;
            let api_call_clone = api_call.clone();
            match api_call_clone(&instance.config()) {
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
                    if let Some((new_instance, new_should_health_check)) =
                        self.get_config_user_mode(&user_mode, accept_health_check)
                    {
                        instance = new_instance;
                        should_health_check = new_should_health_check;
                    }
                }

                // If the connection to the server failed with a network error, reconnecting might solve the issue
                // Err(apis::Error::Ureq(ureq::Error::Transport(err)))
                //     if matches!(
                //         err.kind(),
                //         ureq::ErrorKind::Io | ureq::ErrorKind::ConnectionFailed
                //     ) =>
                // {
                Err(apis::Error::Ureq(
                    err @ (ureq::Error::Io(_)
                    | ureq::Error::ConnectionFailed
                    | ureq::Error::Timeout(_)
                    | ureq::Error::ConnectProxyFailed(_)),
                )) => {
                    self.slot.clear_all_pools();
                    instance.bump_failed();
                    warn!("Connection attempt {retry_count} failed: IO error connecting to the instance, {err}, retrying in {delay_seconds}s");
                    thread::sleep(delay);
                    if let Some((new_instance, new_should_health_check)) =
                        self.get_config_user_mode(&user_mode, accept_health_check)
                    {
                        instance = new_instance;
                        should_health_check = new_should_health_check;
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

    pub fn change_pin(&mut self, pin: String) -> Result<(), Pkcs11Error> {
        let options = match self.ck_state {
            CKS_RW_SO_FUNCTIONS => {
                let username = match self.admin_config() {
                    Some(user) => user.username.clone(),
                    None => return Err(Pkcs11Error::UserNotLoggedIn),
                };

                (username, UserMode::Administrator)
            }
            CKS_RW_USER_FUNCTIONS => {
                let username = match self.operator_config() {
                    Some(user) => user.username.clone(),
                    None => return Err(Pkcs11Error::UserNotLoggedIn),
                };

                (username, UserMode::Operator)
            }
            _ => return Err(Pkcs11Error::UserNotLoggedIn),
        };

        self.try_(
            |config| {
                default_api::users_user_id_passphrase_post(
                    config,
                    &options.0,
                    nethsm_sdk_rs::models::UserPassphrasePostData::new(pin),
                )
            },
            options.1,
        )
        .map_err(|err| {
            error!("Failed to change pin: {err:?}");
            Pkcs11Error::DeviceError
        })?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
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
) -> Result<UserStatus, apis::Error<default_api::UsersUserIdGetError>> {
    let auth = match api_config.basic_auth.as_ref() {
        Some(auth) => auth,
        None => return Ok(UserStatus::LoggedOut),
    };

    if auth.1.is_none() {
        return Ok(UserStatus::LoggedOut);
    }

    let user = default_api::users_user_id_get(api_config, auth.0.as_str())?;

    Ok(match user.entity.role {
        UserRole::Operator => UserStatus::Operator,
        UserRole::Administrator => UserStatus::Administrator,
        _ => UserStatus::LoggedOut,
    })
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

    Some(api_config.with_custom_config(|config| Configuration {
        basic_auth: Some((user.username.clone(), user.password.clone())),
        ..config
    }))
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
