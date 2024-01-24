use std::{io::Read, mem, net::SocketAddr, path::PathBuf};

use merge::Merge;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Yaml(serde_yaml::Error),
    NoConfigFile,
}

const CONFIG_FILE_NAME: &str = "p11nethsm.conf";
const ENV_VAR_CONFIG_FILE: &str = "P11NETHSM_CONFIG_FILE";

pub fn config_files() -> Result<Vec<(Vec<u8>, PathBuf)>, ConfigError> {
    if let Ok(file_path) = std::env::var(ENV_VAR_CONFIG_FILE) {
        let file = std::fs::read(&file_path).map_err(ConfigError::Io)?;
        return Ok(vec![(file, file_path.into())]);
    }

    let mut config_folders = vec![
        "/etc/nitrokey".to_string(),
        "/usr/local/etc/nitrokey".to_string(),
    ];

    if let Ok(home) = std::env::var("HOME") {
        config_folders.push(format!("{}/.config/nitrokey", home));
    }

    let mut res = Vec::new();
    let mut buffer = Vec::new();
    for folder in config_folders {
        let file_path = format!("{}/{}", folder, CONFIG_FILE_NAME);
        if let Ok(mut file) = std::fs::File::open(&file_path) {
            file.read_to_end(&mut buffer).map_err(ConfigError::Io)?;
            res.push((mem::take(&mut buffer), file_path.into()));
        }
    }

    Ok(res)
}

pub fn merge_configurations<'a>(
    configs: impl IntoIterator<Item = &'a [u8]>,
) -> Result<P11Config, ConfigError> {
    let mut config = P11Config::default();

    let mut no_config = true;
    for file in configs {
        let parsed = serde_yaml::from_slice(file).map_err(ConfigError::Yaml)?;
        no_config = false;
        config.merge(parsed);
    }

    if no_config {
        return Err(ConfigError::NoConfigFile);
    }

    Ok(config)
}

#[cfg(test)]
pub fn read_configuration() -> Result<P11Config, ConfigError> {
    let configs = config_files()?;

    merge_configurations(configs.iter().map(|(data, _)| &**data))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
        }
    }
}

// representation of the config file to parse
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyslogUdp {
    pub to_addr: SocketAddr,
    pub from_addr: SocketAddr,
}

// representation of the config file to parse
#[derive(Debug, Clone, Serialize, Deserialize, Merge, Default, PartialEq)]
pub struct P11Config {
    #[merge(strategy = merge::bool::overwrite_false)]
    #[serde(default)]
    pub enable_set_attribute_value: bool,
    pub syslog_socket: Option<PathBuf>,
    pub syslog_udp: Option<SyslogUdp>,
    pub syslog_tcp: Option<SocketAddr>,
    #[serde(default)]
    pub syslog_facility: Option<String>,
    #[serde(default)]
    pub syslog_hostname: Option<String>,
    #[serde(default)]
    pub syslog_process: Option<String>,
    #[serde(default)]
    pub syslog_pid: Option<u32>,
    pub log_file: Option<PathBuf>,
    pub log_level: Option<LogLevel>,
    #[merge(strategy = merge::vec::append)]
    pub slots: Vec<SlotConfig>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct RetryConfig {
    pub count: u32,
    pub delay_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexFingerprint {
    pub value: Vec<u8>,
}

impl Serialize for HexFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.value))
    }
}

impl<'de> Deserialize<'de> for HexFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct HexFingerprintVisitor;
        impl<'de> serde::de::Visitor<'de> for HexFingerprintVisitor {
            type Value = HexFingerprint;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("An hexadecimal value, possibly separated with ':'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(HexFingerprint {
                    value: hex::decode(v.replace(':', "")).map_err(|err| {
                        E::custom(format_args!(
                            "Failed to parse hexadecimal fingerprint: {err}"
                        ))
                    })?,
                })
            }
        }

        deserializer.deserialize_str(HexFingerprintVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstanceConfig {
    pub url: String,
    #[serde(default)]
    pub danger_insecure_cert: bool,
    #[serde(default)]
    pub sha256_fingerprints: Vec<HexFingerprint>,
    #[serde(default)]
    pub max_idle_connections: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlotConfig {
    pub label: String,
    pub operator: Option<UserConfig>,
    pub administrator: Option<UserConfig>,
    pub description: Option<String>,
    pub instances: Vec<InstanceConfig>,
    #[serde(default)]
    pub retries: Option<RetryConfig>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

// An user
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserConfig {
    pub username: String,
    #[serde(deserialize_with = "deserialize_password", default)]
    pub password: Option<String>,
}

const PASSWORD_ENV_PREFIX: &str = "env:";

// Deserialize a string, but if it starts with "env:" then read the environment variable corresponding to the rest of the string
fn deserialize_password<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        Some(s) => {
            if s.starts_with(PASSWORD_ENV_PREFIX) {
                let var = s.trim_start_matches(PASSWORD_ENV_PREFIX);
                let val = std::env::var(var).map_err(serde::de::Error::custom)?;
                return Ok(Some(val));
            }
            if s.is_empty() {
                return Ok(None);
            }
            Ok(Some(s))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use std::fs;

    use super::*;

    #[test]
    #[ignore]
    fn test_read_home_config() {
        let config = r#"
enable_set_attribute_value: true
log_file: /tmp/p11nethsm.log
log_level: Trace
slots:
  - label: test
    operator:
        username: test
        password: test_password
    instances:
        - url: https://localhost:23443
          danger_insecure_cert: true
"#;
        let home = "/tmp/home/";

        // create a temporary "fake" home folder
        fs::create_dir_all(format!("{}.config/nitrokey", home)).unwrap();
        fs::write(
            format!("{}/.config/nitrokey/{}", home, CONFIG_FILE_NAME),
            config,
        )
        .unwrap();

        std::env::remove_var(ENV_VAR_CONFIG_FILE);

        std::env::set_var("HOME", home);

        let config = read_configuration().unwrap();
        assert!(config.enable_set_attribute_value);
        assert_eq!(config.log_file, Some("/tmp/p11nethsm.log".into()));
        assert!(matches!(config.log_level, Some(LogLevel::Trace)));
        assert_eq!(config.slots.len(), 1);
        assert_eq!(config.slots[0].label, "test");
        assert_eq!(config.slots[0].operator.as_ref().unwrap().username, "test");
        assert_eq!(
            config.slots[0].operator.as_ref().unwrap().password,
            Some("test_password".to_string())
        );
        // clean up
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    #[ignore]
    fn test_read_config_no_file() {
        std::env::remove_var(ENV_VAR_CONFIG_FILE);
        let config = read_configuration();
        assert!(config.is_err());
        assert!(matches!(
            config.unwrap_err(),
            super::ConfigError::NoConfigFile
        ));
    }

    #[test]
    fn test_deserialize_password_env() {
        let config = r#"
username: test
password: env:TEST_PASSWORD
"#;

        std::env::set_var("TEST_PASSWORD", "test_password");
        let config: super::UserConfig = serde_yaml::from_str(config).unwrap();
        assert_eq!(config.username, "test");
        assert_eq!(config.password, Some("test_password".to_string()));
    }

    #[test]
    fn test_deserialize_password() {
        let config = r#"
username: test
password: test_password
"#;
        let config: super::UserConfig = serde_yaml::from_str(config).unwrap();
        assert_eq!(config.username, "test");
        assert_eq!(config.password, Some("test_password".to_string()));
    }

    #[test]
    fn test_deserialize_password_none() {
        let config = r#"
username: test
"#;
        let config: super::UserConfig = serde_yaml::from_str(config).unwrap();
        assert_eq!(config.username, "test");
        assert_eq!(config.password, None);
    }

    #[test]
    fn test_deserialize_password_empty() {
        let config = r#"
username: test
password: ""
"#;
        let config: super::UserConfig = serde_yaml::from_str(config).unwrap();
        assert_eq!(config.username, "test");
        assert_eq!(config.password, None);
    }

    #[test]
    fn test_deserialize_full_example_config() {
        let config = include_str!("../../../p11nethsm.example.conf");
        assert_eq!(
            P11Config {
                enable_set_attribute_value: false,
                syslog_socket: Some("/var/nethsm/log".into()),
                syslog_facility: Some("user".into()),
                syslog_hostname: None,
                syslog_pid: None,
                syslog_udp: None,
                syslog_tcp: None,
                syslog_process: None,
                log_file: None,
                log_level: Some(LogLevel::Debug),
                slots: vec![SlotConfig {
                    label: "LocalHSM".into(),
                    description: Some("Local HSM (docker)".into()),
                    operator: Some(UserConfig {
                        username: "operator".into(),
                        password: Some("localpass".into())
                    }),
                    administrator: Some(UserConfig {
                        username: "admin".into(),
                        password: None
                    }),
                    instances: vec![InstanceConfig {
                        url: "https://keyfender:8443/api/v1".into(),
                        danger_insecure_cert: false,
                        sha256_fingerprints: vec![HexFingerprint {
                            value: hex!(
                                "31928EA45E165CA73344E8E98E64C4AE7B2A57E5774349F369C98FC42F3A3B6E"
                            )
                            .into()
                        }],
                        max_idle_connections: Some(10),
                    }],
                    retries: Some(RetryConfig {
                        count: 3,
                        delay_seconds: 1
                    }),
                    timeout_seconds: Some(10),
                }]
            },
            serde_yaml::from_str(config).unwrap()
        );
    }
}
