use super::config_file::P11Config;

// output to stdout and a file
pub fn configure_logger(config: &P11Config) {
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
