use log::{info, warn, LevelFilter};
use syslog::{BasicLogger, Formatter3164};

use super::{config_file::P11Config, initialization::InitializationError};

pub struct MultiLog {
    syslog_logger: Option<BasicLogger>,
    env_logger: Option<env_logger::Logger>,
}

impl log::Log for MultiLog {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.syslog_logger
            .as_ref()
            .is_some_and(|logger| log::Log::enabled(logger, metadata))
            || self
                .env_logger
                .as_ref()
                .is_some_and(|logger| log::Log::enabled(logger, metadata))
    }

    fn log(&self, record: &log::Record) {
        if let Some(ref logger) = self.syslog_logger {
            log::Log::log(logger, record)
        };
        if let Some(ref logger) = self.env_logger {
            log::Log::log(logger, record)
        };
    }

    fn flush(&self) {
        if let Some(ref logger) = self.syslog_logger {
            log::Log::flush(logger)
        };
        if let Some(ref logger) = self.env_logger {
            log::Log::flush(logger)
        };
    }
}

// output to stdout, a file or syslog
pub fn configure_logger(config: &Result<P11Config, InitializationError>) {
    let Ok(config) = config else {
        let formatter = Formatter3164 {
            facility: syslog::Facility::LOG_USER,
            hostname: None,
            process: std::env::current_exe()
                .map(|p| p.into_os_string().to_string_lossy().into_owned())
                .unwrap_or_else(|_| "NetHSM PKCS11 module".into()),
            pid: std::process::id(),
        };

        let unix_logger = syslog::unix(formatter).map(BasicLogger::new).ok();
        let env_logger = env_logger::Builder::from_default_env().build();

        log::set_boxed_logger(Box::new(MultiLog {
            syslog_logger: unix_logger,
            env_logger: Some(env_logger),
        }))
        .ok();
        log::set_max_level(log::LevelFilter::Info);
        return;
    };

    // Warning messages for invalid configuration
    let mut messages = Vec::new();
    // Info messages to log after logger is configured
    let mut info_messages = Vec::new();
    if config.syslog_socket.is_some() as u32
        + config.syslog_tcp.is_some() as u32
        + config.syslog_udp.is_some() as u32
        > 1
    {
        messages.push("Multiple syslog target selected".to_string());
    }

    // The user asked for syslog
    let use_syslog_explicit = config.syslog_socket.is_some()
        || config.syslog_tcp.is_some()
        || config.syslog_udp.is_some()
        || config.syslog_facility.is_some()
        || config.syslog_hostname.is_some()
        || config.syslog_process.is_some()
        || config.syslog_pid.is_some();

    // The user asked for env logging
    let use_file_explicit = config.log_file.is_some();

    // Automatically enable a logger if the other is not enabled
    let use_syslog = use_syslog_explicit || !use_file_explicit;
    let use_file = use_file_explicit || !use_syslog_explicit;

    let mut syslog_logger = None;
    let mut env_logger = None;

    // syslog is used if neither syslog nor file is configured
    if use_syslog {
        let facility = config
            .syslog_facility
            .as_ref()
            .map(|f| match f.parse() {
                Ok(facility) => facility,
                Err(_) => {
                    messages.push(format!(
                        "Failed to parse {f} as facility. Defaulting to LOG_USER"
                    ));
                    Default::default()
                }
            })
            .unwrap_or_default();

        let process_name = || {
            let Ok(current_exe) = std::env::current_exe() else {
                return "Unknown".into();
            };
            current_exe.as_os_str().to_string_lossy().into_owned()
        };

        let formatter = Formatter3164 {
            facility,
            hostname: config.syslog_hostname.clone(),
            process: config.syslog_process.clone().unwrap_or_else(process_name),
            pid: config.syslog_pid.unwrap_or_else(std::process::id),
        };

        if let Some(path) = &config.syslog_socket {
            if let Ok(logger) = syslog::unix_custom(formatter, path) {
                syslog_logger = Some(BasicLogger::new(logger));
                info_messages.push("Logging to Unix socket".into());
            } else {
                messages.push("Could not open SYSLOG socket".into());
            }
        } else if let Some(addr) = config.syslog_tcp {
            if let Ok(logger) = syslog::tcp(formatter, addr) {
                syslog_logger = Some(BasicLogger::new(logger));
                info_messages.push("Logging to TCP".into());
            } else {
                messages.push("Failed to create TCP logger".to_string());
            }
        } else if let Some(udp_conf) = config.syslog_udp {
            if let Ok(logger) = syslog::udp(formatter, udp_conf.from_addr, udp_conf.to_addr) {
                syslog_logger = Some(BasicLogger::new(logger));
                info_messages.push("Logging to UDP".into());
            } else {
                messages.push("Failed to create UDP logger".to_string());
            }
        } else {
            #[allow(clippy::collapsible_else_if)]
            if let Ok(logger) = syslog::unix(formatter) {
                syslog_logger = Some(BasicLogger::new(logger));
                info_messages.push("Logging to standard Unix socket".into());
            } else {
                messages.push("Failed to create standard unix logger".to_string());
            }
        }
    }

    if use_file {
        let mut builder = env_logger::Builder::from_default_env();

        let path = &config.log_file.as_deref().unwrap_or("-".as_ref());

        if path.as_os_str() == "-" {
            builder.target(env_logger::Target::Stderr);
            info_messages.push("Logging to STDERR".into());
        } else {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                Ok(file) => {
                    // open the file for appending
                    builder.target(env_logger::Target::Pipe(Box::new(file)));
                    info_messages.push(format!(
                        "Logging to File {}",
                        path.as_os_str().to_string_lossy()
                    ));
                }
                Err(err) => {
                    messages.push(format!("Failed to open file for logging: {err}"));
                }
            };
        }

        env_logger = Some(builder.build());
    }

    // RUST_LOG must override the default filter
    match (env_logger.as_ref(), config.log_level.as_ref()) {
        (Some(logger), Some(config_filter)) => {
            log::set_max_level(logger.filter().min(LevelFilter::from(*config_filter)));
        }
        (Some(logger), _) if logger.filter() > LevelFilter::Error => {
            log::set_max_level(logger.filter());
        }
        (None, Some(level)) => {
            log::set_max_level((*level).into());
        }
        _ => {}
    }

    log::set_boxed_logger(Box::new(MultiLog {
        syslog_logger,
        env_logger,
    }))
    .ok();

    for m in info_messages {
        info!("{m}");
    }
    for m in messages {
        warn!("{m}");
    }
}
