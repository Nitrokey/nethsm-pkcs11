use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use nethsm_sdk_rs::apis::configuration::Configuration;

use crate::backend::db::Db;

use super::config_file::{RetryConfig, UserConfig};

// stores the global configuration of the module
#[derive(Debug, Clone)]
pub struct Device {
    pub log_file: Option<PathBuf>,
    pub slots: Vec<Arc<Slot>>,
    pub enable_set_attribute_value: bool,
}

#[derive(Debug, Clone)]
pub struct ClusterInstance {
    pub api_config: nethsm_sdk_rs::apis::configuration::Configuration,
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub label: String,
    pub retries: Option<RetryConfig>,
    pub description: Option<String>,
    pub instances: Vec<Configuration>,
    pub operator: Option<UserConfig>,
    pub administrator: Option<UserConfig>,
    pub db: Arc<Mutex<Db>>,
}

impl Slot {
    // the user is connected if the basic auth is filled with an username and a password, otherwise the user will have to login
    pub fn is_connected(&self) -> bool {
        self.instances
            .first()
            .map(|c| {
                c.basic_auth
                    .as_ref()
                    .map(|auth| {
                        auth.1
                            .as_ref()
                            .map(|password| !password.is_empty())
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}
