use std::convert::TryInto;
use std::fmt;
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;

use ureq::tls::TlsProvider;
use ureq::unversioned::transport::{Buffers, ConnectionDetails, Connector, LazyBuffers};
use ureq::unversioned::transport::{Either, NextTimeout, Transport, TransportAdapter};
use ureq::Error;

use log::{debug, trace};

#[derive(Clone)]
/// Wrapper for TLS using rustls.
pub struct RustlsConnector {
    pub config: Arc<ClientConfig>,
}

impl<In: Transport> Connector<In> for RustlsConnector {
    type Out = Either<In, RustlsTransport<In>>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, Error> {
        let Some(transport) = chained else {
            panic!("RustlConnector requires a chained transport");
        };

        // Only add TLS if we are connecting via HTTPS and the transport isn't TLS
        // already, otherwise use chained transport as is.
        if !details.needs_tls() || transport.is_tls() {
            trace!("Skip");
            return Ok(Some(Either::A(transport)));
        }

        assert_eq!(
            details.config.tls_config().provider(),
            TlsProvider::Rustls,
            "Config must be set to rustls"
        );

        trace!("Try wrap in TLS");

        // Initialize the config on first run.
        let config = self.config.clone(); // cheap clone due to Arc

        let name_borrowed: ServerName<'_> = details
            .uri
            .authority()
            .expect("uri authority for tls")
            .host()
            .try_into()
            .map_err(|e| {
                debug!("rustls invalid dns name: {e}");
                Error::Tls("Rustls invalid dns name error")
            })?;

        let name = name_borrowed.to_owned();

        let conn = ClientConnection::new(config, name)?;
        let stream = StreamOwned {
            conn,
            sock: TransportAdapter::new(transport),
        };

        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );

        let transport = RustlsTransport { buffers, stream };

        debug!("Wrapped TLS");

        Ok(Some(Either::B(transport)))
    }
}

pub struct RustlsTransport<T: Transport> {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter<T>>,
}

impl<T: Transport> Transport for RustlsTransport<T> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), Error> {
        self.stream.get_mut().set_timeout(timeout);

        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;

        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, Error> {
        if self.buffers.can_use_input() {
            return Ok(true);
        }

        self.stream.get_mut().set_timeout(timeout);

        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);

        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

impl fmt::Debug for RustlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsConnector").finish()
    }
}

impl<T: Transport> fmt::Debug for RustlsTransport<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsTransport")
            .field("chained", &self.stream.sock.inner())
            .finish()
    }
}
