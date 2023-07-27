use std::sync::{Arc, Mutex};

use openapi::apis::configuration::Configuration;

use crate::backend::db::Db;

use super::config_file::UserConfig;

#[derive(Debug, Clone)]
pub struct Device {
    pub log_file: Option<String>,
    pub slots: Vec<Arc<Slot>>,
}

#[derive(Debug, Clone)]
pub struct ClusterInstance {
    pub api_config: openapi::apis::configuration::Configuration,
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub label: String,
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
            .get(0)
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
