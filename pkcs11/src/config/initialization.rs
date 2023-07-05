use crate::data;


const DEFAULT_USER_AGENT : &str = "pkcs11-rs/0.1.0";

#[derive(Debug)]
pub enum InitializationError {
    Config(crate::config::ConfigError),
    WLock(std::sync::PoisonError<std::sync::RwLockWriteGuard<'static, crate::config::P11Config>>),
    RLock(std::sync::PoisonError<std::sync::RwLockReadGuard<'static, crate::config::P11Config>>),
    WLockClients(
        std::sync::PoisonError<
            std::sync::RwLockWriteGuard<'static, Vec<openapi::apis::configuration::Configuration>>,
        >,
    ),
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

        // initialize the clients
        let mut clients = data::CLIENTS
            .write()
            .map_err(InitializationError::WLockClients)?;
        for slot in config.slots.iter() {
            let mut client = openapi::apis::configuration::Configuration::new();
            client.base_path = slot.url.clone();
            client.basic_auth = Some((slot.user.clone(), Some(slot.password.clone())));
            client.user_agent = Some(DEFAULT_USER_AGENT.to_string());
            clients.push(client);
        }
    }
    Ok(())
}
