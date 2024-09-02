use std::collections::HashSet;
use std::io::{BufWriter, Read};
use std::net::Ipv4Addr;
use std::process::{Child, Stdio};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::thread::sleep;
use std::time::Duration;
use std::{env::set_var, process::Command};

pub use config_file::P11Config;

use nethsm_sdk_rs::{
    apis::{
        configuration::Configuration,
        default_api::{provision_post, users_user_id_put},
    },
    models::{ProvisionRequestData, UserPostData, UserRole},
};
use pkcs11::Ctx;
use rustls::{
    client::danger::ServerCertVerifier,
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
};
use tempfile::NamedTempFile;
use time::format_description;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{self};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::AbortHandle;
use ureq::AgentBuilder;

pub const TEST_NETHSM_INSTANCE: &str = match option_env!("TEST_NETHSM_INSTANCE") {
    Some(v) => v,
    None => "https://localhost:8443/api/v1",
};

#[derive(Debug)]
struct DangerIgnoreVerifier;

impl ServerCertVerifier for DangerIgnoreVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let default_provider = CryptoProvider::get_default().unwrap();

        default_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_conf() -> rustls::ClientConfig {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier))
        .with_no_client_auth()
}

pub struct TestContext {
    blocked_ports: HashSet<u16>,
}

pub struct TestDropper {
    // treated as dead code even though it shouldn't: https://github.com/rust-lang/rust/issues/122833
    #[allow(dead_code)]
    serialize_test: MutexGuard<'static, ()>,
    command_to_kill: Child,
    context: TestContext,
}

fn iptables() -> Command {
    if option_env!("USE_SUDO").is_some() {
        let mut command = Command::new("sudo");
        command.arg("iptables");
        command
    } else {
        Command::new("iptables")
    }
}

impl TestContext {
    fn unblock(port: u16) {
        let out_in = iptables()
            .args([
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "DROP",
            ])
            .output()
            .unwrap();
        assert!(out_in.status.success());
        let out_in = iptables()
            .args([
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "DROP",
            ])
            .output()
            .unwrap();
        assert!(out_in.status.success());
    }
    pub fn remove_block(&mut self, port: u16) {
        assert!(self.blocked_ports.remove(&port));
        Self::unblock(port);
    }

    pub fn add_block(&mut self, port: u16) {
        if !self.blocked_ports.insert(port) {
            return;
        }

        let out_in = iptables()
            .args([
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "DROP",
            ])
            .output()
            .unwrap();
        assert!(out_in.status.success());
        let out_in = iptables()
            .args([
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "DROP",
            ])
            .output()
            .unwrap();
        assert!(out_in.status.success());
    }
}

impl Drop for TestDropper {
    fn drop(&mut self) {
        Command::new("kill")
            .args([self.command_to_kill.id().to_string()])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        self.command_to_kill.wait().unwrap();
        let mut buf = String::new();
        self.command_to_kill
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        buf.push('\n');
        self.command_to_kill
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        for p in self.context.blocked_ports.iter().cloned() {
            TestContext::unblock(p);
        }
        println!("{buf}");
    }
}

static PROXY_SENDER: LazyLock<UnboundedSender<(u16, u16)>> = LazyLock::new(|| {
    let (tx, mut rx) = unbounded_channel();
    std::thread::spawn(move || {
        runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
            .block_on(async move {
                let mut tasks = Vec::new();
                while let Some((from_port, to_port)) = rx.recv().await {
                    tasks.push(tokio::spawn(proxy(from_port, to_port)));
                }
                for task in tasks {
                    task.abort();
                }
            })
    });
    tx
});

async fn proxy(from_port: u16, to_port: u16) {
    let listener = TcpListener::bind(((Ipv4Addr::from([127, 0, 0, 1])), from_port))
        .await
        .unwrap();
    struct Droppper(Vec<AbortHandle>);
    impl Drop for Droppper {
        fn drop(&mut self) {
            assert!(!self.0.is_empty(), "The proxy was not used");
            for handle in &self.0 {
                handle.abort();
            }
        }
    }

    let mut dropper = Droppper(Vec::new());

    loop {
        let (socket1, _) = listener.accept().await.unwrap();

        let socket2 = TcpStream::connect((Ipv4Addr::from([127, 0, 0, 1]), to_port))
            .await
            .unwrap();

        async fn handle_stream(
            mut rx: tokio::net::tcp::OwnedReadHalf,
            mut tx: tokio::net::tcp::OwnedWriteHalf,
        ) {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buffer = vec![0; 12 * 1024];
            loop {
                let n = rx.read(&mut buffer).await.unwrap();

                if n == 0 {
                    return;
                }

                tx.write_all(&buffer[..n]).await.unwrap();
            }
        }

        let (rx1, tx1) = socket1.into_split();
        let (rx2, tx2) = socket2.into_split();
        dropper
            .0
            .push(tokio::spawn(handle_stream(rx1, tx2)).abort_handle());
        dropper
            .0
            .push(tokio::spawn(handle_stream(rx2, tx1)).abort_handle());
    }
}

static DOCKER_HELD: Mutex<()> = Mutex::new(());

pub fn run_tests(
    proxies: &[(u16, u16)],
    config: P11Config,
    f: impl FnOnce(&mut TestContext, &mut Ctx),
) {
    let mut test_dropper = TestDropper {
        serialize_test: DOCKER_HELD.lock().unwrap(),
        command_to_kill: Command::new("podman")
            .args([
                "run",
                "--rm",
                "-ti",
                "-p8443:8443",
                "-p8080:8080",
                "docker.io/nitrokey/nethsm:testing",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
        context: TestContext {
            blocked_ports: HashSet::new(),
        },
    };

    let client = AgentBuilder::new().tls_config(Arc::new(tls_conf())).build();

    let sdk_config = Configuration {
        client,
        base_path: TEST_NETHSM_INSTANCE.into(),
        basic_auth: Some(("admin".into(), Some("Administrator".into()))),
        ..Default::default()
    };

    sleep(Duration::from_secs(2));

    provision_post(
        &sdk_config,
        ProvisionRequestData {
            unlock_passphrase: "1234567890".into(),
            admin_passphrase: "Administrator".into(),
            system_time: time::OffsetDateTime::now_utc()
                .format(
                    &format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
                        .unwrap(),
                )
                .unwrap(),
        },
    )
    .unwrap();
    users_user_id_put(
        &sdk_config,
        "operator",
        UserPostData {
            real_name: "Operator".into(),
            role: UserRole::Operator,
            passphrase: "opPassphrase".into(),
        },
    )
    .unwrap();

    for (in_port, out_port) in proxies {
        PROXY_SENDER.send((*in_port, *out_port)).unwrap();
    }

    let mut tmpfile: NamedTempFile = NamedTempFile::new().unwrap();

    serde_yaml::to_writer(BufWriter::new(tmpfile.as_file_mut()), &config).unwrap();
    let path = tmpfile.path();
    set_var(config_file::ENV_VAR_CONFIG_FILE, path);
    let mut ctx = Ctx::new_and_initialize("../target/release/libnethsm_pkcs11.so").unwrap();
    f(&mut test_dropper.context, &mut ctx);
    ctx.close_all_sessions(0).unwrap();
}
