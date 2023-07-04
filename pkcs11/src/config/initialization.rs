use crate::data;

#[derive(Debug)]
pub enum InitializationError {
    Config(crate::config::ConfigError),
    WLock(std::sync::PoisonError<std::sync::RwLockWriteGuard<'static, crate::config::P11Config>>),
    RLock(std::sync::PoisonError<std::sync::RwLockReadGuard<'static, crate::config::P11Config>>),
}

pub fn initialize_configuration() -> Result<(), InitializationError> {
    let config = crate::config::read_configuration().map_err(InitializationError::Config)?;

    // set the global config
    {
        let mut reference = data::GLOBAL_CONFIG
            .write()
            .map_err(InitializationError::WLock)?;
        *reference = config;
    }

    {
        // configure the logger
        let config = data::GLOBAL_CONFIG
            .read()
            .map_err(InitializationError::RLock)?;
        crate::config::logging::configure_logger(&config);
    }
    Ok(())
}
