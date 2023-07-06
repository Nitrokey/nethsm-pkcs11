use crate::backend::db::Db;

#[derive(Debug, Clone)]
pub struct Device {
    pub log_file: Option<String>,
    pub slots: Vec<Slot>,
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub label: String,
    pub description: Option<String>,
    pub api_config: openapi::apis::configuration::Configuration,
    pub db : Db,
}
