use super::{config_file::P11Config, initialization::InitializationError};

// output to stdout, a file or syslog
pub fn configure_logger(config: &Result<P11Config, InitializationError>) {
    let Ok(config) = config else {
        // On error, first try logging to syslog
        if syslog::init(syslog::Facility::LOG_USER, log::LevelFilter::Info, None).is_ok() {
            return;
        };
        // Otherwise try to log to stderr
        env_logger::try_init().ok();
        return;
    };

    let mut builder = env_logger::Builder::from_default_env();

    // set the log level

    if let Some(level) = &config.log_level {
        builder.filter_level(level.into());
    }

    if let Some(path) = &config.log_file {
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

    // Don't crash on re-initialization
    builder.try_init().ok();
}
