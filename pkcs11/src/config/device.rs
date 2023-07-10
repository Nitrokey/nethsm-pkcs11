use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Device {
    pub log_file: Option<String>,
    pub slots: Vec<Arc<Slot>>,
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub label: String,
    pub description: Option<String>,
    pub api_config: openapi::apis::configuration::Configuration,
}

impl Slot {
    // the user is connected if the basic auth is filled with an username and a password, otherwise the user will have to login
    pub fn is_connected(&self) -> bool {
        self.api_config
            .basic_auth
            .as_ref()
            .map(|auth| {
                auth.1
                    .as_ref()
                    .map(|password| !password.is_empty())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}
