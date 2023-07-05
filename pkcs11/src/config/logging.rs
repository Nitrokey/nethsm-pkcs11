use super::config_file::P11Config;


// output to stdout and a file
pub fn configure_logger(config: &P11Config) {
  let mut builder = env_logger::Builder::from_default_env();

    builder.target(env_logger::Target::Stdout);

    if let Some(path) = &config.log_file {
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

    builder.init()
}
