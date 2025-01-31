use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use std::{fmt, io};

use arc_swap::ArcSwap;
use ureq::config::Config;
use ureq::unversioned::transport::time::Duration;
use ureq::Error;

use crate::ureq::utils::{timeout_not_zero, IoResultExt};
use ureq::unversioned::resolver::ResolvedSocketAddrs;
use ureq::unversioned::transport::Either;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
};

use log::{debug, trace};

#[derive(Default)]
/// Connector for regular TCP sockets.
pub struct TcpConnector {
    pub tcp_keepalive_time: Option<StdDuration>,
    pub tcp_keepalive_interval: Option<StdDuration>,
    pub tcp_keepalive_retries: Option<u32>,
    /// True means connection can continue, false
    /// means connection must be closed
    pub clear_flag: Arc<ArcSwap<AtomicBool>>,
}

impl<In: Transport> Connector<In> for TcpConnector {
    type Out = Either<In, TcpTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, Error> {
        use socket2::TcpKeepalive;
        if chained.is_some() {
            // The chained connection overrides whatever we were to open here.
            // In the DefaultConnector chain this would be a SOCKS proxy connection.
            trace!("Skip");
            return Ok(chained.map(Either::A));
        }

        let config = &details.config;
        let stream = try_connect(&details.addrs, details.timeout, config)?;
        let socket: socket2::Socket = stream.into();
        let mut keepalive_config = TcpKeepalive::new();
        let mut keepalive_enable = false;
        if let Some(time) = self.tcp_keepalive_time {
            keepalive_config = keepalive_config.with_time(time);
            keepalive_enable = true;
        }

        if let Some(interval) = self.tcp_keepalive_interval {
            keepalive_config = keepalive_config.with_interval(interval);
            keepalive_enable = true;
        }

        #[cfg(not(target_os = "windows"))]
        if let Some(retries) = self.tcp_keepalive_retries {
            keepalive_config = keepalive_config.with_retries(retries);
            keepalive_enable = true;
        }

        #[cfg(target_os = "windows")]
        if self.tcp_keepalive_retries.is_some() {
            log::warn!("Keepalive retries configured but not supported on windows");
        }

        if keepalive_enable {
            socket.set_tcp_keepalive(&keepalive_config)?;
        }

        let buffers = LazyBuffers::new(config.input_buffer_size(), config.output_buffer_size());
        let transport = TcpTransport::new(socket.into(), buffers, self.clear_flag.load_full());

        Ok(Some(Either::B(transport)))
    }
}

fn try_connect(
    addrs: &ResolvedSocketAddrs,
    timeout: NextTimeout,
    config: &Config,
) -> Result<TcpStream, Error> {
    for addr in addrs {
        match try_connect_single(*addr, timeout, config) {
            // First that connects
            Ok(v) => return Ok(v),
            // Intercept ConnectionRefused to try next addrs
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
                trace!("{} connection refused", addr);
                continue;
            }
            // Other errors bail
            Err(e) => return Err(e),
        }
    }

    debug!("Failed to connect to any resolved address");
    Err(Error::Io(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "Connection refused",
    )))
}

fn try_connect_single(
    addr: SocketAddr,
    timeout: NextTimeout,
    config: &Config,
) -> Result<TcpStream, Error> {
    trace!("Try connect TcpStream to {}", addr);

    let maybe_stream = if let Some(when) = timeout_not_zero(&timeout) {
        TcpStream::connect_timeout(&addr, *when)
    } else {
        TcpStream::connect(addr)
    }
    .normalize_would_block();

    let stream = match maybe_stream {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            return Err(Error::Timeout(timeout.reason))
        }
        Err(e) => return Err(e.into()),
    };

    if config.no_delay() {
        stream.set_nodelay(true)?;
    }

    debug!("Connected TcpStream to {}", addr);

    Ok(stream)
}

pub struct TcpTransport {
    stream: TcpStream,
    buffers: LazyBuffers,
    timeout_write: Option<Duration>,
    timeout_read: Option<Duration>,
    /// Flag used to indicate that the connection must be closed
    clear_flag: Arc<AtomicBool>,
}

impl TcpTransport {
    pub fn new(
        stream: TcpStream,
        buffers: LazyBuffers,
        clear_flag: Arc<AtomicBool>,
    ) -> TcpTransport {
        TcpTransport {
            stream,
            buffers,
            timeout_read: None,
            timeout_write: None,
            clear_flag,
        }
    }
}

// The goal here is to only cause a syscall to set the timeout if it's necessary.
fn maybe_update_timeout(
    timeout: NextTimeout,
    previous: &mut Option<Duration>,
    stream: &TcpStream,
    f: impl Fn(&TcpStream, Option<std::time::Duration>) -> io::Result<()>,
) -> io::Result<()> {
    let maybe_timeout = timeout_not_zero(&timeout);

    if maybe_timeout != *previous {
        (f)(stream, maybe_timeout.map(|t| *t))?;
        *previous = maybe_timeout;
    }

    Ok(())
}

impl Transport for TcpTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), Error> {
        maybe_update_timeout(
            timeout,
            &mut self.timeout_write,
            &self.stream,
            TcpStream::set_write_timeout,
        )?;

        let output = &self.buffers.output()[..amount];
        match self.stream.write_all(output).normalize_would_block() {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(Error::Timeout(timeout.reason)),
            Err(e) => Err(e.into()),
        }?;

        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, Error> {
        if self.buffers.can_use_input() {
            return Ok(true);
        }

        // Proceed to fill the buffers from the TcpStream
        maybe_update_timeout(
            timeout,
            &mut self.timeout_read,
            &self.stream,
            TcpStream::set_read_timeout,
        )?;

        let input = self.buffers.input_append_buf();
        let amount = match self.stream.read(input).normalize_would_block() {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(Error::Timeout(timeout.reason)),
            Err(e) => Err(e.into()),
        }?;
        self.buffers.input_appended(amount);

        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.clear_flag.load(Ordering::Relaxed)
            && probe_tcp_stream(&mut self.stream).unwrap_or(false)
    }
}

fn probe_tcp_stream(stream: &mut TcpStream) -> Result<bool, Error> {
    // Temporary do non-blocking IO
    stream.set_nonblocking(true)?;

    let mut buf = [0];
    match stream.read(&mut buf) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            // This is the correct condition. There should be no waiting
            // bytes, and therefore reading would block
        }
        // Any bytes read means the server sent some garbage we didn't ask for
        Ok(_) => {
            debug!("Unexpected bytes from server. Closing connection");
            return Ok(false);
        }
        // Errors such as closed connection
        Err(_) => return Ok(false),
    };

    // Reset back to blocking
    stream.set_nonblocking(false)?;

    Ok(true)
}

impl fmt::Debug for TcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnector").finish()
    }
}

impl fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpTransport")
            .field("addr", &self.stream.peer_addr().ok())
            .finish()
    }
}
