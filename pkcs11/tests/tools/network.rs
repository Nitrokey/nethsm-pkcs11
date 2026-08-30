use std::collections::HashSet;
use std::mem;
use std::net::Ipv4Addr;
use std::process::Command;
use std::ptr;
use std::sync::{LazyLock, MutexGuard};
use std::time::Duration;

pub use config_file::P11Config;

use pkcs11::{types::CK_C_INITIALIZE_ARGS, Ctx};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{self};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::AbortHandle;

pub struct TestContext {
    blocked_ports: HashSet<u16>,
    stall_connections: broadcast::Sender<()>,
}

pub struct TestDropper {
    // treated as dead code even though it shouldn't: https://github.com/rust-lang/rust/issues/122833
    #[allow(dead_code)]
    serialize_test: MutexGuard<'static, bool>,
    context: TestContext,
}

fn iptables() -> Command {
    if option_env!("USE_SUDO_IPTABLES").is_some() {
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

    /// Make all active connections wait before killing the connection
    pub fn stall_active_connections(&self) {
        self.stall_connections.send(()).unwrap();
    }
}

impl TestDropper {
    fn clear(&mut self) {
        for p in self.context.blocked_ports.iter().cloned() {
            TestContext::unblock(p);
        }
        println!("Finished unblocking ports");
    }
}

impl Drop for TestDropper {
    fn drop(&mut self) {
        self.clear();
    }
}

enum ProxyMessage {
    NewProxy(u16, u16, broadcast::Sender<()>),
    CloseAll,
}

static PROXY_SENDER: LazyLock<UnboundedSender<ProxyMessage>> = LazyLock::new(|| {
    let (tx, mut rx) = unbounded_channel();
    std::thread::spawn(move || {
        runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap()
            .block_on(async move {
                let mut tasks = Vec::new();
                while let Some(msg) = rx.recv().await {
                    match msg {
                        ProxyMessage::NewProxy(from_port, to_port, sender) => {
                            tasks.push(tokio::spawn(proxy(from_port, to_port, sender)))
                        }
                        ProxyMessage::CloseAll => {
                            for task in mem::take(&mut tasks) {
                                task.abort();
                            }
                        }
                    }
                }
                for task in tasks {
                    task.abort();
                }
            })
    });
    tx
});

async fn proxy(from_port: u16, to_port: u16, stall_sender: broadcast::Sender<()>) {
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
            mut stall_receiver: broadcast::Receiver<()>,
        ) {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buffer = vec![0; 12 * 1024];
            let mut should_stall = false;
            loop {
                let n = rx.read(&mut buffer).await.unwrap();

                match stall_receiver.try_recv() {
                    Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) => should_stall = true,
                    Err(broadcast::error::TryRecvError::Empty) => {}
                    Err(broadcast::error::TryRecvError::Closed) => {}
                }

                if n == 0 {
                    return;
                }

                if should_stall {
                    tokio::time::sleep(Duration::from_secs(50)).await;
                    return;
                }

                tx.write_all(&buffer[..n]).await.unwrap();
            }
        }

        let (rx1, tx1) = socket1.into_split();
        let (rx2, tx2) = socket2.into_split();
        let stall_rx = stall_sender.subscribe();
        let stall_tx = stall_sender.subscribe();
        dropper
            .0
            .push(tokio::spawn(handle_stream(rx1, tx2, stall_tx)).abort_handle());
        dropper
            .0
            .push(tokio::spawn(handle_stream(rx2, tx1, stall_rx)).abort_handle());
    }
}

pub fn run_tests(
    proxies: &[(u16, u16)],
    config: P11Config,
    f: impl FnOnce(&mut TestContext, &mut Ctx) + Clone,
) {
    let serialize_test = super::setup::setup();
    let mut test_dropper = TestDropper {
        serialize_test,
        context: TestContext {
            blocked_ports: HashSet::new(),
            stall_connections: broadcast::channel(1).0,
        },
    };

    for (in_port, out_port) in proxies {
        PROXY_SENDER
            .send(ProxyMessage::NewProxy(
                *in_port,
                *out_port,
                test_dropper.context.stall_connections.clone(),
            ))
            .unwrap();
    }

    super::setup::with_pkcs11_config(&config, || {
        {
            let mut ctx = Ctx::new_and_initialize("../target/release/libnethsm_pkcs11.so").unwrap();
            let f_cl = f.clone();
            f_cl(&mut test_dropper.context, &mut ctx);
            ctx.close_all_sessions(0).unwrap();
        }
        {
            let mut ctx = Ctx::new("../target/release/libnethsm_pkcs11.so").unwrap();
            ctx.initialize(Some(CK_C_INITIALIZE_ARGS {
                CreateMutex: None,
                DestroyMutex: None,
                LockMutex: None,
                UnlockMutex: None,
                flags: cryptoki_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS,
                pReserved: ptr::null_mut(),
            }))
            .unwrap();
            f(&mut test_dropper.context, &mut ctx);
            ctx.close_all_sessions(0).unwrap();
        }
    });
    PROXY_SENDER.send(ProxyMessage::CloseAll).unwrap();
    println!("Ending test");
}
