use std::{
    sync::{atomic::AtomicUsize, Arc, Condvar, Mutex, RwLock},
    time::Instant,
};

use nethsm_sdk_rs::apis::configuration::Configuration;

use crate::backend::db::Db;

use super::config_file::{RetryConfig, UserConfig};

// stores the global configuration of the module
#[derive(Debug, Clone)]
pub struct Device {
    pub slots: Vec<Arc<Slot>>,
    pub enable_set_attribute_value: bool,
}

#[derive(Debug, Clone, Default)]
pub enum InstanceState {
    #[default]
    Working,
    Failed {
        retry_count: usize,
        last_retry_at: Instant,
    },
}

#[derive(Debug, Clone)]
pub struct InstanceData {
    pub config: Configuration,
    pub state: Arc<RwLock<InstanceState>>,
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub label: String,
    pub retries: Option<RetryConfig>,
    pub _description: Option<String>,
    pub instances: Vec<InstanceData>,
    pub operator: Option<UserConfig>,
    pub administrator: Option<UserConfig>,
    pub db: Arc<(Mutex<Db>, Condvar)>,
    pub instance_balancer: Arc<AtomicUsize>,
}

impl Slot {
    // the user is connected if the basic auth is filled with an username and a password, otherwise the user will have to login
    pub fn is_connected(&self) -> bool {
        let Some(instance_data) = self.instances.first() else {
            return false;
        };
        let Some(auth) = &instance_data.config.basic_auth else {
            return false;
        };

        let Some(pwd) = &auth.1 else { return false };

        !pwd.is_empty()
    }
}
