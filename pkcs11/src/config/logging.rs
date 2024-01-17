use log::{info, warn};
use syslog::{BasicLogger, Formatter3164};

use super::{
    config_file::{LogLevel, P11Config},
    initialization::InitializationError,
};

// output to stdout, a file or syslog
pub fn configure_logger(config: &Result<P11Config, InitializationError>) {
    let Ok(config) = config else {
        // On error, first try logging to syslog
        if syslog::init_unix(syslog::Facility::LOG_USER, log::LevelFilter::Info).is_ok() {
            return;
        };
        // Otherwise try to log to stderr
        env_logger::try_init().ok();
        return;
    };

    let log_level = config.log_level.unwrap_or(LogLevel::Warn);

    let mut currently_logging = "Failed to set a logger";

    // Warning messages for invalid configuration
    let mut messages = Vec::new();
    if config.syslog_socket.is_some() as u32
        + config.syslog_tcp.is_some() as u32
        + config.syslog_udp.is_some() as u32
        > 1
    {
        messages.push("Multiple syslog target selected".to_string());
    }

    let use_syslog = config.syslog_socket.is_some()
        || config.syslog_tcp.is_some()
        || config.syslog_udp.is_some()
        || config.syslog_facility.is_some()
        || config.syslog_hostname.is_some()
        || config.syslog_process.is_some()
        || config.syslog_pid.is_some();

    let use_file = config.log_file.is_some();

    if use_syslog && use_file {
        messages.push("Cannot log both to file and to syslog".to_string())
    }

    // syslog is used if neither syslog nor file is configured
    if use_syslog || !use_file {
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

        if let Some(path) = &config.syslog_socket {
            syslog::init_unix_custom(facility, log_level.into(), path).ok();
            if config.syslog_hostname.is_some()
                || config.syslog_process.is_some()
                || config.syslog_pid.is_some()
            {
                messages.push(
                    "Cannot configure PID, Process  name or hostname when logging to unix socket"
                        .into(),
                );
            }
            currently_logging = "Logging to unix socket";
        } else if let Some(addr) = config.syslog_tcp {
            let formatter = Formatter3164 {
                facility,
                hostname: config.syslog_hostname.clone(),
                process: config.syslog_process.clone().unwrap_or_else(process_name),
                pid: config.syslog_pid.unwrap_or_else(std::process::id),
            };
            if let Ok(logger) = syslog::tcp(formatter, addr) {
                log::set_boxed_logger(Box::new(BasicLogger::new(logger))).ok();
                currently_logging = "Logging to TCP";
            } else {
                messages.push("Failed to create TCP logger".to_string());
            }
        } else if let Some(udp_conf) = config.syslog_udp {
            let formatter = Formatter3164 {
                facility,
                hostname: config.syslog_hostname.clone(),
                process: config.syslog_process.clone().unwrap_or_else(process_name),
                pid: config.syslog_pid.unwrap_or_else(std::process::id),
            };
            if let Ok(logger) = syslog::udp(formatter, udp_conf.from_addr, udp_conf.to_addr) {
                log::set_boxed_logger(Box::new(BasicLogger::new(logger))).ok();
                currently_logging = "Logging to UDP";
            } else {
                messages.push("Failed to create UDP logger".to_string());
            }
        } else {
            syslog::init_unix(facility, log_level.into()).ok();
            if config.syslog_hostname.is_some()
                || config.syslog_process.is_some()
                || config.syslog_pid.is_some()
            {
                messages.push(
                    "Cannot configure PID, Process  name or hostname when logging to unix socket"
                        .into(),
                );
            }
            currently_logging = "Logging to unix socket";
        }
    } else {
        let mut builder = env_logger::Builder::from_default_env();

        // set the log level

        builder.filter_level(log_level.into());

        if let Some(path) = &config.log_file {
            if path.as_os_str() == "-" {
                builder.target(env_logger::Target::Stderr);
                currently_logging = "Logging to STDERR";
            } else {
                currently_logging = "Logging to File";
                // get the current rights of the file
                if let Ok(metadata) = std::fs::metadata(path) {
                    let mut permissions = metadata.permissions();
                    if permissions.readonly() {
                        #[allow(clippy::permissions_set_readonly_false)]
                        permissions.set_readonly(false);
                        std::fs::set_permissions(path, permissions).unwrap();
                    }
                }

                // open the file for appending
                let file = Box::new(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .expect("could not open log file"),
                );
                builder.target(env_logger::Target::Pipe(file));
            }
        }

        // Don't crash on re-initialization
        builder.try_init().ok();
    }

    info!("{currently_logging}");
    for m in messages {
        warn!("{m}");
    }
}
