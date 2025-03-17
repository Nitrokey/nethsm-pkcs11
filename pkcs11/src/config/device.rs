use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        mpsc::{self, RecvError, RecvTimeoutError},
        Arc, Condvar, LazyLock, Mutex, RwLock, Weak,
    },
    thread,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use config_file::CertificateFormat;
use nethsm_sdk_rs::apis::{configuration::Configuration, default_api::health_ready_get};
use ureq::unversioned::{
    resolver::{DefaultResolver, Resolver},
    transport::{ConnectProxyConnector, Connector},
};

use crate::{
    backend::db::Db,
    data::THREADS_ALLOWED,
    ureq::{rustls_connector::RustlsConnector, tcp_connector::TcpConnector},
};

use super::config_file::{RetryConfig, UserConfig};

#[allow(clippy::large_enum_variant)]
pub enum RetryThreadMessage {
    FailedInstnace {
        retry_in: Duration,
        instance: InstanceData,
    },
    /// The device is being removed, clear all connections
    Finalize,
}

pub static RETRY_THREAD: LazyLock<mpsc::Sender<RetryThreadMessage>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel();
    let (tx_instance, rx_instance) = mpsc::channel();
    thread::spawn(background_thread(rx_instance));
    thread::spawn(background_timer(rx, tx_instance));
    tx
});

fn background_timer(
    rx: mpsc::Receiver<RetryThreadMessage>,
    tx_instance: mpsc::Sender<InstanceData>,
) -> impl FnOnce() {
    let mut jobs: BTreeMap<Instant, WeakInstanceData> = BTreeMap::new();
    move || loop {
        let next_job = jobs.pop_first();
        let Some((next_job_deadline, next_job_instance)) = next_job else {
            // No jobs in the queue, we can just run the next
            match rx.recv() {
                Err(RecvError) => break,
                Ok(RetryThreadMessage::Finalize) => continue,
                Ok(RetryThreadMessage::FailedInstnace { retry_in, instance }) => {
                    jobs.insert(Instant::now() + retry_in, instance.into());
                    continue;
                }
            }
        };

        let now = Instant::now();

        if now >= next_job_deadline {
            if let Some(instance) = next_job_instance.upgrade() {
                tx_instance.send(instance).unwrap();
                continue;
            }
        } else {
            jobs.insert(next_job_deadline, next_job_instance);
        }

        let timeout = next_job_deadline.duration_since(now);
        match rx.recv_timeout(timeout) {
            Ok(RetryThreadMessage::Finalize) => {
                jobs.clear();
                continue;
            }
            Ok(RetryThreadMessage::FailedInstnace { retry_in, instance }) => {
                jobs.insert(now + retry_in, instance.into());
                continue;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn background_thread(rx: mpsc::Receiver<InstanceData>) -> impl FnOnce() {
    move || loop {
        while let Ok(instance) = rx.recv() {
            instance.clear_pool();
            match health_ready_get(&instance.config) {
                Ok(_) => instance.clear_failed(),
                Err(_) => instance.bump_failed(),
            }
        }
    }
}

// stores the global configuration of the module
#[derive(Debug, Clone)]
pub struct Device {
    pub slots: Vec<Arc<Slot>>,
    pub enable_set_attribute_value: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InstanceState {
    #[default]
    Working,
    Failed {
        retry_count: u8,
        last_retry_at: Instant,
    },
}

pub fn create_ureq_connector(tcp: TcpConnector, rustls: RustlsConnector) -> impl Connector {
    tcp.chain(rustls).chain(ConnectProxyConnector::default())
}

pub fn create_ureq_resolver() -> impl Resolver {
    DefaultResolver::default()
}

impl InstanceState {
    pub fn new_failed() -> InstanceState {
        InstanceState::Failed {
            retry_count: 0,
            last_retry_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstanceData {
    pub agent: Arc<ArcSwap<ureq::Agent>>,
    pub agent_config: ureq::config::Config,
    pub tcp_connector: TcpConnector,
    pub rustls_connector: RustlsConnector,
    config: Configuration,
    pub state: Arc<RwLock<InstanceState>>,
}

impl InstanceData {
    pub fn new(
        agent: Arc<ArcSwap<ureq::Agent>>,
        agent_config: ureq::config::Config,
        tcp_connector: TcpConnector,
        rustls_connector: RustlsConnector,
        config: Configuration,
        state: Arc<RwLock<InstanceState>>,
    ) -> Self {
        Self {
            agent,
            agent_config,
            tcp_connector,
            rustls_connector,
            config,
            state,
        }
    }

    pub fn with_custom_config(&self, f: impl FnOnce(Configuration) -> Configuration) -> Self {
        Self {
            config: f(self.config()),
            ..self.clone()
        }
    }

    pub fn clear_pool(&self) {
        let agent = ureq::Agent::with_parts(
            self.agent_config.clone(),
            self.tcp_connector
                .clone()
                .chain(self.rustls_connector.clone())
                .chain(ConnectProxyConnector::default()),
            DefaultResolver::default(),
        );
        self.agent.swap(Arc::new(agent.clone()));
    }

    pub fn config(&self) -> Configuration {
        Configuration {
            client: (**self.agent.load()).clone(),
            ..self.config.clone()
        }
    }

    #[cfg(test)]
    pub fn config_mut(&mut self) -> &mut Configuration {
        &mut self.config
    }
}

#[derive(Debug, Clone)]
pub struct WeakInstanceData {
    pub agent: Arc<ArcSwap<ureq::Agent>>,
    pub agent_config: ureq::config::Config,
    pub tcp_connector: TcpConnector,
    pub rustls_connector: RustlsConnector,
    config: Configuration,
    pub state: Weak<RwLock<InstanceState>>,
}

impl From<InstanceData> for WeakInstanceData {
    fn from(value: InstanceData) -> Self {
        Self {
            agent: value.agent,
            agent_config: value.agent_config,
            tcp_connector: value.tcp_connector,
            rustls_connector: value.rustls_connector,
            config: value.config,
            state: Arc::downgrade(&value.state),
        }
    }
}

impl WeakInstanceData {
    fn upgrade(self) -> Option<InstanceData> {
        let state = self.state.upgrade()?;
        Some(InstanceData {
            agent: self.agent,
            agent_config: self.agent_config,
            tcp_connector: self.tcp_connector,
            rustls_connector: self.rustls_connector,
            config: self.config,
            state,
        })
    }
}

pub enum InstanceAttempt {
    /// The instance is in the failed state and should not be used
    Failed,
    /// The instance is in the failed  state but a connection should be attempted
    Retry,
    /// The instance is in the working state
    Working,
}

impl InstanceData {
    pub fn should_try(&self) -> InstanceAttempt {
        let this = self.state.read().unwrap();
        match *this {
            InstanceState::Working => InstanceAttempt::Working,
            InstanceState::Failed {
                retry_count,
                last_retry_at,
            } => {
                if last_retry_at.elapsed() < retry_duration_from_count(retry_count) {
                    InstanceAttempt::Failed
                } else {
                    InstanceAttempt::Retry
                }
            }
        }
    }

    pub fn clear_failed(&self) {
        *self.state.write().unwrap() = InstanceState::Working;
    }

    pub fn bump_failed(&self) {
        let mut write = self.state.write().unwrap();
        let retry_count = match *write {
            InstanceState::Working => {
                *write = InstanceState::new_failed();
                0
            }
            InstanceState::Failed {
                retry_count: prev_retry_count,
                last_retry_at,
            } => {
                // We only bump if it's a "real" retry. This is to avoid race conditions where
                // the same instance stops working when multiple threads are simultaneously connecting
                // to it
                if last_retry_at.elapsed() >= retry_duration_from_count(prev_retry_count) {
                    let retry_count = prev_retry_count.saturating_add(1);
                    *write = InstanceState::Failed {
                        retry_count,
                        last_retry_at: Instant::now(),
                    };
                    retry_count
                } else {
                    prev_retry_count
                }
            }
        };
        drop(write);
        if THREADS_ALLOWED.load(Relaxed) {
            RETRY_THREAD
                .send(RetryThreadMessage::FailedInstnace {
                    retry_in: retry_duration_from_count(retry_count),
                    instance: self.clone(),
                })
                .ok();
        }
    }
}

fn retry_duration_from_count(retry_count: u8) -> Duration {
    let secs = match retry_count {
        0 | 1 => 1,
        2 => 2,
        3 => 5,
        4 => 10,
        5 => 60,
        6.. => 60 * 5,
    };

    Duration::from_secs(secs)
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub label: String,
    pub retries: Option<RetryConfig>,
    pub _description: Option<String>,
    pub instances: Vec<InstanceData>,
    pub operator: Option<UserConfig>,
    pub administrator: Option<UserConfig>,
    pub db: Arc<(Mutex<Db>, Condvar)>,
    pub instance_balancer: Arc<AtomicUsize>,
    pub certificate_format: CertificateFormat,
}

impl Slot {
    // the user is connected if the basic auth is filled with an username and a password, otherwise the user will have to login
    pub fn is_connected(&self) -> bool {
        let Some(instance_data) = self.instances.first() else {
            return false;
        };
        let Some(auth) = &instance_data.config.basic_auth else {
            return false;
        };

        let Some(pwd) = &auth.1 else { return false };

        !pwd.is_empty()
    }

    pub fn clear_all_pools(&self) {
        for instance in &self.instances {
            instance.clear_pool();
        }
    }
}
