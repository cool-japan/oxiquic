//! Asynchronous UDP shell driving the [`Connection`] state machine over
//! `tokio`'s [`tokio::net::UdpSocket`].
//!
//! The protocol logic lives in the connection state machine; this module is the
//! thin I/O layer that:
//!
//! * binds a UDP socket,
//! * for a client, constructs a [`Connection`] and runs the handshake to
//!   completion by shuttling datagrams,
//! * for a server, demultiplexes many concurrent client connections on a single
//!   UDP socket using DCID-based routing, completing each handshake
//!   independently before delivering a [`QuicConnection`] via [`ServerEndpoint::accept`],
//! * exposes a [`QuicConnection`] handle for opening streams and reading data.
//!
//! # Background-driven connections
//!
//! [`QuicConnection::into_driven`] consumes a [`QuicConnection`] and returns a
//! [`DrivenConnection`] that runs the socket I/O loop in a background
//! [`tokio::task`]. Streams on a [`DrivenConnection`] expose the standard
//! [`tokio::io::AsyncWrite`] / [`tokio::io::AsyncRead`] traits through
//! [`SendStreamHandle`] / [`RecvStreamHandle`].
//!
//! # Multi-connection server demux
//!
//! When `ServerEndpoint::accept` is first called a background
//! `run_server_demux` task is spawned. It reads every datagram from the shared
//! UDP socket and routes it to the correct per-connection channel keyed by the
//! destination connection ID:
//!
//! * **Initial packets**: keyed by the client's chosen `initial_dcid` in
//!   `initial_map`. On the first packet for an unknown DCID a new handshake task
//!   is spawned.
//! * **Short-header (1-RTT) packets**: keyed by the server's issued 8-byte
//!   `local_cid` in `local_cid_map`.
//!
//! Each handshake task notifies the demux once it has derived its `local_cid`
//! so the demux can promote the entry from `initial_map` to `local_cid_map`.

pub mod driven;
pub mod zero_rtt;

pub use driven::DrivenConnection;
pub use zero_rtt::ZeroRttAccepted;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::sleep_until;

use oxiquic_core::{OxiQuicError, StreamId};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};

use crate::connection::cid::CidEvent;
use crate::connection::{Connection, MtuConfig, Role};
use crate::handle::{RecvStreamHandle, SendStreamHandle, WriteCmd};
use crate::packet::{encode_retry_packet, parse_initial_token};
use crate::TransportConfig;

use driven::{run_driven_connection, DrivenConnectionChannels};

/// Maximum UDP datagram OxiQUIC will read in one recv.
pub(super) const RECV_BUF: usize = 2048;

/// Length (bytes) of connection IDs OxiQUIC issues locally.  Must match
/// `LOCAL_CID_LEN` in `connection.rs` (both are 8).
const LOCAL_CID_LEN: usize = 8;

/// The only QUIC version this endpoint speaks (QUIC v1, RFC 9000).
const QUIC_V1: u32 = 0x0000_0001;

/// Type alias for the open-stream request channel element.
pub(super) type OpenStreamSender = oneshot::Sender<(StreamId, mpsc::Receiver<Vec<u8>>)>;
/// Type alias for an optional open-stream receiver used in the driven loop.
pub(super) type OptOpenRx = Option<mpsc::Receiver<OpenStreamSender>>;

/// Supported versions list for Version Negotiation responses.
const SUPPORTED_VERSIONS: &[u32] = &[QUIC_V1];

// ─────────────────────────────────────────────────────────────────────────────
// InboundSource
// ─────────────────────────────────────────────────────────────────────────────

/// Where inbound datagrams come from for a given connection.
///
/// * `Socket` — the connection reads directly from its own UDP socket clone.
///   Used for client connections and the legacy single-connection server path.
/// * `Channel` — the demux task has already read the datagram from the shared
///   socket and forwarded it here. Used for server connections in multi-demux
///   mode.
pub(super) enum InboundSource {
    /// Direct UDP socket receive.
    Socket(Arc<UdpSocket>),
    /// Pre-read datagrams forwarded from the demux task.
    Channel(mpsc::Receiver<(Vec<u8>, SocketAddr)>),
}

/// Receive one datagram from `inbound`, writing the payload into `buf` and
/// returning `(payload_bytes, source_addr)`.
///
/// Abstracting this out of `pump_once` avoids borrow-checker fights where the
/// async generator would require holding mutable references to both `inbound`
/// and other fields of `ConnectionDriver` simultaneously.
pub(super) async fn recv_inbound(
    inbound: &mut InboundSource,
    buf: &mut [u8],
) -> io::Result<(Vec<u8>, SocketAddr)> {
    match inbound {
        InboundSource::Socket(sock) => {
            let sock = Arc::clone(sock);
            let (len, addr) = sock.recv_from(buf).await?;
            Ok((buf[..len].to_vec(), addr))
        }
        InboundSource::Channel(rx) => rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")),
    }
}

/// Non-blocking attempt to receive one datagram from `inbound`.  Returns
/// `None` immediately when no datagram is waiting (rather than awaiting one).
/// Used to drain a burst of already-queued datagrams without yielding back to
/// the tokio scheduler between each one — which would round-trip through the
/// timer/wakeup infrastructure and add milliseconds of latency per datagram on
/// lightly-loaded systems.
fn try_recv_inbound(
    inbound: &mut InboundSource,
    buf: &mut [u8],
) -> Option<io::Result<(Vec<u8>, SocketAddr)>> {
    match inbound {
        InboundSource::Socket(sock) => match sock.try_recv_from(buf) {
            Ok((len, addr)) => Some(Ok((buf[..len].to_vec(), addr))),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
            Err(e) => Some(Err(e)),
        },
        InboundSource::Channel(rx) => match rx.try_recv() {
            Ok(item) => Some(Ok(item)),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => Some(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            ))),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClientEndpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A bound QUIC client endpoint that can establish outgoing connections.
pub struct ClientEndpoint {
    socket: Arc<UdpSocket>,
    config: Arc<ClientConfig>,
    transport: TransportConfig,
}

impl ClientEndpoint {
    /// Bind a client endpoint to `bind_addr` with the given rustls client
    /// configuration (which must be built from `oxiquic_crypto::quic_crypto_provider`).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the UDP socket cannot be bound.
    pub async fn bind(
        bind_addr: SocketAddr,
        config: Arc<ClientConfig>,
        transport: TransportConfig,
    ) -> Result<Self, OxiQuicError> {
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            config,
            transport,
        })
    }

    /// The local address the endpoint is bound to.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, OxiQuicError> {
        Ok(self.socket.local_addr()?)
    }

    /// Connect to `server_addr` with a configurable handshake timeout.
    ///
    /// Wraps [`Self::connect`] with [`tokio::time::timeout`].  If the
    /// handshake does not complete within `timeout`, the future is dropped and
    /// [`OxiQuicError::Timeout`] is returned.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Timeout`] when the deadline elapses, or any
    /// error that [`Self::connect`] would return (bind failure, TLS failure, …).
    pub async fn connect_timeout(
        &self,
        addr: SocketAddr,
        server_name: &str,
        timeout: std::time::Duration,
    ) -> Result<QuicConnection, OxiQuicError> {
        tokio::time::timeout(timeout, self.connect(addr, server_name))
            .await
            .map_err(|_| OxiQuicError::Timeout)?
    }

    /// Connect to `server_addr`, validating its certificate against the
    /// configured roots and the supplied `server_name`. Drives the handshake to
    /// completion before returning the established connection.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] if binding, the handshake or the TLS
    /// negotiation fails, or the handshake times out.
    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicConnection, OxiQuicError> {
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| OxiQuicError::Tls(format!("invalid server name {server_name}")))?;
        let params = self.transport.to_transport_params();
        let mtu_config = MtuConfig {
            max_mtu: self.transport.get_max_mtu(),
            discovery_enabled: true,
        };
        let conn = Connection::new_client_with_datagram_buf(
            self.config.clone(),
            name,
            server_addr,
            params,
            mtu_config,
            self.transport.get_congestion_controller(),
            self.transport.get_datagram_receive_buffer_size(),
        )?;
        let inbound = InboundSource::Socket(Arc::clone(&self.socket));
        let mut driver =
            ConnectionDriver::new(Arc::clone(&self.socket), inbound, conn, Some(server_addr));
        driver.run_handshake().await?;
        driver
            .conn
            .set_keep_alive_interval(self.transport.get_keep_alive_interval());
        Ok(QuicConnection::new(driver))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerEndpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A bound QUIC server endpoint that accepts many concurrent incoming connections
/// on a single UDP socket via DCID-based demultiplexing.
pub struct ServerEndpoint {
    socket: Arc<UdpSocket>,
    config: Arc<ServerConfig>,
    transport: TransportConfig,
    /// Lazily-initialised demux state. Populated on the first call to `accept`.
    demux: Mutex<Option<ServerDemuxState>>,
}

impl ServerEndpoint {
    /// Bind a server endpoint to `bind_addr` with the given rustls server
    /// configuration (built from `oxiquic_crypto::quic_crypto_provider`).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the UDP socket cannot be bound.
    pub async fn bind(
        bind_addr: SocketAddr,
        config: Arc<ServerConfig>,
        transport: TransportConfig,
    ) -> Result<Self, OxiQuicError> {
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            config,
            transport,
            demux: Mutex::new(None),
        })
    }

    /// The local address the endpoint is bound to.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Io`] if the address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, OxiQuicError> {
        Ok(self.socket.local_addr()?)
    }

    /// Accept the next incoming connection.
    ///
    /// On the first call a background demux task is spawned that reads all
    /// datagrams from the shared UDP socket and routes them to per-connection
    /// channel-based inbound sources.  Subsequent calls simply await the next
    /// fully-established connection from the accept channel.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] if the demux accept channel is closed or a
    /// connection-level error is forwarded from the handshake task.
    pub async fn accept(&self) -> Result<QuicConnection, OxiQuicError> {
        let mut guard = self.demux.lock().await;
        if guard.is_none() {
            let state = Self::start_demux(
                Arc::clone(&self.socket),
                Arc::clone(&self.config),
                self.transport.clone(),
            );
            *guard = Some(state);
        }
        let accept_rx = &mut guard
            .as_mut()
            .ok_or_else(|| OxiQuicError::Connection("demux not initialised".into()))?
            .accept_rx;
        accept_rx
            .recv()
            .await
            .ok_or_else(|| OxiQuicError::Connection("server accept channel closed".into()))?
    }

    /// Return an [`Incoming`] iterator that wraps repeated calls to
    /// [`Self::accept`].
    ///
    /// Use `.next().await` in a loop to accept connections without needing to
    /// hold an `async` block across the loop:
    ///
    /// ```rust,ignore
    /// let mut incoming = server.incoming();
    /// while let Some(conn) = incoming.next().await {
    ///     tokio::spawn(async move { /* handle conn */ });
    /// }
    /// ```
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { endpoint: self }
    }

    /// Spawn the background demux task and return the state record that holds
    /// its accept channel and join handle.
    fn start_demux(
        socket: Arc<UdpSocket>,
        config: Arc<ServerConfig>,
        transport: TransportConfig,
    ) -> ServerDemuxState {
        let (accept_tx, accept_rx) = mpsc::channel::<Result<QuicConnection, OxiQuicError>>(16);
        let task_handle = tokio::spawn(run_server_demux(socket, config, transport, accept_tx));
        ServerDemuxState {
            accept_rx,
            _task_handle: task_handle,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerEndpointBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`ServerEndpoint`] with optional session ticketer configuration.
///
/// Use this instead of [`ServerEndpoint::bind`] when you need to plug in a
/// custom [`rustls::server::ProducesTickets`] implementation (such as
/// `oxitls::OxiTicketer`) for QUIC 0-RTT session resumption.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use oxiquic_transport::{ServerEndpointBuilder, TransportConfig};
/// use oxitls::OxiTicketer;
///
/// let server = ServerEndpointBuilder::new("127.0.0.1:4433".parse()?, Arc::new(server_tls), TransportConfig::default())
///     .with_ticketer(Arc::new(OxiTicketer::new().expect("ticketer")))
///     .build()
///     .await?;
/// ```
pub struct ServerEndpointBuilder {
    bind_addr: SocketAddr,
    config: Arc<ServerConfig>,
    transport: TransportConfig,
    /// Optional custom session ticket provider for TLS session resumption and 0-RTT.
    ticketer: Option<Arc<dyn rustls::server::ProducesTickets>>,
}

impl ServerEndpointBuilder {
    /// Create a new builder bound to `bind_addr` with the given TLS and transport
    /// configuration.
    ///
    /// Call [`with_ticketer`][Self::with_ticketer] to override the session
    /// ticket provider before calling [`build`][Self::build].
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        config: Arc<ServerConfig>,
        transport: TransportConfig,
    ) -> Self {
        Self {
            bind_addr,
            config,
            transport,
            ticketer: None,
        }
    }

    /// Set a custom session ticket provider for TLS session resumption and 0-RTT.
    ///
    /// The ticketer is applied to the [`rustls::ServerConfig`] before binding the
    /// endpoint. Use `oxitls::OxiTicketer` for a pure-Rust AES-GCM-backed ticketer:
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use oxitls::OxiTicketer;
    /// builder.with_ticketer(Arc::new(OxiTicketer::new().expect("ticketer")));
    /// ```
    #[must_use]
    pub fn with_ticketer(mut self, ticketer: Arc<dyn rustls::server::ProducesTickets>) -> Self {
        self.ticketer = Some(ticketer);
        self
    }

    /// Set the ALPN protocol identifiers advertised in the TLS handshake.
    ///
    /// Replaces `alpn_protocols` on the underlying [`rustls::ServerConfig`]
    /// immediately. Call before [`build`][Self::build] to negotiate custom
    /// protocols on raw QUIC server endpoints.
    ///
    /// For HTTP/3 servers, prefer `H3ServerBuilder::with_tls_config` which
    /// automatically injects `b"h3"`. See [`oxiquic_core::alpn`] for well-known
    /// protocol constants.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use oxiquic_transport::{ServerEndpointBuilder, TransportConfig};
    ///
    /// let server = ServerEndpointBuilder::new(addr, config, TransportConfig::default())
    ///     .with_alpn_protocols(&[b"my-proto/1.0"])
    ///     .build()
    ///     .await?;
    /// ```
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: &[&[u8]]) -> Self {
        let mut cfg = (*self.config).clone();
        cfg.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        self.config = Arc::new(cfg);
        self
    }

    /// Bind the [`ServerEndpoint`], applying the ticketer (if set) to the TLS
    /// configuration before binding the UDP socket.
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError::Io`] if the UDP socket cannot be bound.
    pub async fn build(self) -> Result<ServerEndpoint, OxiQuicError> {
        let config = if let Some(ticketer) = self.ticketer {
            let mut cfg = (*self.config).clone();
            cfg.ticketer = ticketer;
            Arc::new(cfg)
        } else {
            self.config
        };
        ServerEndpoint::bind(self.bind_addr, config, self.transport).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerDemuxState
// ─────────────────────────────────────────────────────────────────────────────

/// Holds the background demux task handle and the accept channel receiver.
struct ServerDemuxState {
    accept_rx: mpsc::Receiver<Result<QuicConnection, OxiQuicError>>,
    /// Keeps the background task alive. Dropped when `ServerDemuxState` is
    /// dropped, which aborts the task if it has not already finished.
    _task_handle: tokio::task::JoinHandle<()>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Incoming — async iterator over accepted QuicConnections
// ─────────────────────────────────────────────────────────────────────────────

/// An async iterator over incoming QUIC connections.
///
/// Created by [`ServerEndpoint::incoming`].  Call `.next().await` to accept
/// connections one at a time without spawning a background task or requiring
/// the `Stream` trait.
///
/// # Lifetime
/// `Incoming` borrows the [`ServerEndpoint`] for its lifetime, so the endpoint
/// must outlive all `next()` calls.
pub struct Incoming<'a> {
    endpoint: &'a ServerEndpoint,
}

impl<'a> Incoming<'a> {
    /// Wait for the next established incoming connection.
    ///
    /// Returns `None` only when the server's accept channel has been
    /// permanently closed (i.e. the background demux task has exited), which
    /// typically means the [`ServerEndpoint`] is being torn down.
    pub async fn next(&self) -> Option<QuicConnection> {
        self.endpoint.accept().await.ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Demux routing-table update helper
// ─────────────────────────────────────────────────────────────────────────────

/// Type alias for the per-connection inbound datagram sender.
type ConnTx = mpsc::Sender<(Vec<u8>, SocketAddr)>;

/// Apply one `CidRouteUpdate` to the two demux routing tables.
///
/// Extracted from the hot `cid_route_rx` drain loop so the same logic can be
/// exercised in unit tests without a live UDP socket or tokio runtime.
///
/// Returns `true` if the update was applied successfully, `false` if the CID
/// bytes had the wrong length for a `Register`/`Unregister` event (impossible
/// in normal operation, but guards against future refactors).
fn apply_cid_route_update(
    initial_map: &mut HashMap<Vec<u8>, ConnTx>,
    local_cid_map: &mut HashMap<[u8; LOCAL_CID_LEN], ConnTx>,
    update: CidRouteUpdate,
) -> bool {
    match update.event {
        CidEvent::Register(cid) => {
            let key_bytes = cid.as_bytes();
            if key_bytes.len() == LOCAL_CID_LEN {
                let key: [u8; LOCAL_CID_LEN] = match key_bytes.try_into() {
                    Ok(k) => k,
                    Err(_) => return false,
                };
                local_cid_map.insert(key, update.conn_tx);
                true
            } else {
                false
            }
        }
        CidEvent::Unregister(cid) => {
            let key_bytes = cid.as_bytes();
            if key_bytes.len() == LOCAL_CID_LEN {
                let key: [u8; LOCAL_CID_LEN] = match key_bytes.try_into() {
                    Ok(k) => k,
                    Err(_) => return false,
                };
                local_cid_map.remove(&key);
                true
            } else {
                false
            }
        }
        // Handshake completed; evict the initial DCID from the routing
        // table. This is the primary GC path — the lazy Closed(_) removal
        // on the Initial routing entry acts only as a defence-in-depth
        // backstop for cases where this event is never delivered.
        CidEvent::InitialRetired(dcid) => {
            initial_map.remove(&dcid);
            true
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// run_server_demux
// ─────────────────────────────────────────────────────────────────────────────

/// Background demux task: reads every datagram from the shared UDP socket and
/// routes it to the appropriate per-connection channel.
///
/// For each new connection the demux **synchronously** constructs the
/// `Connection` state machine (no I/O), extracts the server-issued `local_cid`,
/// creates a single `(hs_tx, hs_rx)` channel pair and registers it in **both**
/// maps in the same task tick — eliminating any race where Handshake packets
/// arrive before the notify is processed:
///
/// * `initial_map[dcid] = hs_tx.clone()` — routes client Initial retransmits.
/// * `local_cid_map[local_cid_bytes] = hs_tx` — routes Handshake + 1-RTT
///   packets (client switches to server's issued CID as DCID immediately after
///   seeing it in the server's first Initial).
async fn run_server_demux(
    socket: Arc<UdpSocket>,
    config: Arc<ServerConfig>,
    mut transport: TransportConfig,
    accept_tx: mpsc::Sender<Result<QuicConnection, OxiQuicError>>,
) {
    // Map from client's initial DCID to the per-connection inbound channel.
    let mut initial_map: HashMap<Vec<u8>, mpsc::Sender<(Vec<u8>, SocketAddr)>> = HashMap::new();
    // Map from server-issued 8-byte local_cid to the per-connection inbound channel.
    // This covers both long-header Handshake packets and short-header 1-RTT packets.
    let mut local_cid_map: HashMap<[u8; LOCAL_CID_LEN], mpsc::Sender<(Vec<u8>, SocketAddr)>> =
        HashMap::new();

    // Channel for CID routing updates from connection tasks.
    // Capacity: 256 pending updates is ample for any realistic connection count.
    let (cid_route_tx, mut cid_route_rx) = mpsc::channel::<CidRouteUpdate>(256);

    let mut buf = vec![0u8; RECV_BUF];

    loop {
        // If accept_tx is closed no consumer is waiting; shut down the demux.
        if accept_tx.is_closed() {
            break;
        }

        // Drain any pending CID routing updates before blocking on the socket.
        // This keeps the routing table up-to-date for the next datagram.
        loop {
            match cid_route_rx.try_recv() {
                Ok(update) => {
                    apply_cid_route_update(&mut initial_map, &mut local_cid_map, update);
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let result = socket.recv_from(&mut buf).await;
        let (len, peer_addr) = match result {
            Ok(v) => v,
            Err(_) => {
                // Socket receive error; keep the demux running.
                continue;
            }
        };
        let datagram = buf[..len].to_vec();

        // Classify the packet and extract its DCID without decrypting.
        let (pkt_type, dcid) = match crate::packet::peek_dcid(&datagram, LOCAL_CID_LEN) {
            Ok(v) => v,
            Err(_) => {
                // Datagram too short or malformed; skip it.
                continue;
            }
        };

        // ── 1-RTT short header ──────────────────────────────────────────────
        if pkt_type == oxiquic_core::PacketType::Short {
            let key: [u8; LOCAL_CID_LEN] = match dcid.as_slice().try_into() {
                Ok(k) => k,
                Err(_) => continue,
            };
            if let Some(tx) = local_cid_map.get(&key) {
                match tx.try_send((datagram, peer_addr)) {
                    Ok(()) => {}
                    // Channel full: QUIC retransmits will re-deliver; drop this copy.
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    // Receiver gone: connection task has exited; clean up the map.
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        local_cid_map.remove(&key);
                    }
                }
            }
            // Unknown short-header CID: stale/misrouted datagram, silently drop.
            continue;
        }

        // ── Long-header packets (Initial / Handshake) ───────────────────────
        // Check local_cid_map first: the client switches to the server's issued
        // CID as DCID after receiving the server's first Initial. All subsequent
        // long-header packets (Handshake) carry the server local_cid as DCID.
        if dcid.len() == LOCAL_CID_LEN {
            let key: [u8; LOCAL_CID_LEN] = match dcid.as_slice().try_into() {
                Ok(k) => k,
                Err(_) => continue,
            };
            if let Some(tx) = local_cid_map.get(&key) {
                match tx.try_send((datagram, peer_addr)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        local_cid_map.remove(&key);
                    }
                }
                continue;
            }
        }

        // Route Initial to an existing or new handshake task.
        if pkt_type != oxiquic_core::PacketType::Initial {
            // Non-Initial long-header for unknown DCID; silently drop.
            continue;
        }

        // Existing handshake in progress for this DCID?
        if let Some(tx) = initial_map.get(&dcid) {
            match tx.try_send((datagram, peer_addr)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    initial_map.remove(&dcid);
                }
            }
            continue;
        }

        // ── New connection: build Connection, register both maps, spawn task ─
        let (initial_version, initial_dcid_parsed, scid_parsed) =
            match parse_client_initial_ids(&datagram) {
                Some(ids) => ids,
                None => continue,
            };

        // RFC 9000 §17.2.1: if the client's Initial carries an unsupported
        // version, respond with a Version Negotiation packet and do NOT create
        // a connection.
        if initial_version != QUIC_V1 {
            let vn = crate::packet::encode_version_negotiation(
                &scid_parsed,         // client's SCID → VN's DCID
                &initial_dcid_parsed, // client's DCID → VN's SCID
                SUPPORTED_VERSIONS,
            );
            let _ = socket.send_to(&vn, peer_addr).await;
            continue;
        }

        // ── RFC 9000 §8.1 Retry address validation ───────────────────────────
        if transport.get_retry_enabled() {
            let token = parse_initial_token(&datagram).unwrap_or_default();

            if token.is_empty() {
                // No token: send Retry, do not create a connection yet.
                let retry_scid = random_scid_for_retry(config.crypto_provider().secure_random);
                let retry_token = transport.generate_retry_token(&initial_dcid_parsed, peer_addr);
                if let Some(retry_pkt) = encode_retry_packet(
                    &retry_scid,
                    &scid_parsed,         // echo client's SCID back as DCID
                    &initial_dcid_parsed, // odcid for integrity tag
                    &retry_token,
                ) {
                    let _ = socket.send_to(&retry_pkt, peer_addr).await;
                }
                // Do NOT enter initial_map: client must retry with token.
                continue;
            }

            // Token present: validate it.
            match transport.validate_retry_token(&token, peer_addr) {
                Some(_odcid) => {
                    // Token valid.
                    //
                    // RFC 9001 §5.2: after a Retry, both the client and the server
                    // derive Initial keys from the Retry's SCID — which is the
                    // DCID of the client's second Initial (`initial_dcid_parsed`).
                    // The ODCID embedded in the token is only needed for transport
                    // parameter validation; key derivation uses the Retry SCID.
                    let params = transport.to_transport_params();
                    let mtu_config = MtuConfig {
                        max_mtu: transport.get_max_mtu(),
                        discovery_enabled: true,
                    };
                    let server_cfg_early = apply_early_data_config(Arc::clone(&config), &transport);
                    let conn = match Connection::new_server_with_datagram_buf(
                        server_cfg_early,
                        oxiquic_core::ConnectionId::new(initial_dcid_parsed.clone()),
                        oxiquic_core::ConnectionId::new(scid_parsed),
                        peer_addr,
                        params,
                        mtu_config,
                        transport.get_congestion_controller(),
                        transport.get_datagram_receive_buffer_size(),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = accept_tx.send(Err(e)).await;
                            continue;
                        }
                    };
                    let local_cid_bytes: [u8; LOCAL_CID_LEN] =
                        match conn.local_cid().as_bytes().try_into() {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                    let (hs_tx, hs_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(16384);
                    // Route future datagrams: after Retry the client uses the
                    // Retry SCID as DCID (`initial_dcid_parsed`).
                    // Clone before insert to preserve the key for `initial_dcid` arg.
                    let initial_dcid_key = initial_dcid_parsed.clone();
                    initial_map.insert(initial_dcid_parsed, hs_tx.clone());
                    local_cid_map.insert(local_cid_bytes, hs_tx.clone());
                    let _ = hs_tx.try_send((datagram, peer_addr));
                    tokio::spawn(run_server_handshake(
                        conn,
                        peer_addr,
                        Arc::clone(&socket),
                        ServerHandshakeArgs {
                            hs_tx,
                            hs_rx,
                            accept_tx: accept_tx.clone(),
                            keep_alive_interval: transport.get_keep_alive_interval(),
                            cid_route_tx: cid_route_tx.clone(),
                            initial_dcid: initial_dcid_key,
                        },
                    ));
                    continue;
                }
                None => {
                    // Invalid token: send a fresh Retry.
                    let retry_scid = random_scid_for_retry(config.crypto_provider().secure_random);
                    let retry_token =
                        transport.generate_retry_token(&initial_dcid_parsed, peer_addr);
                    if let Some(retry_pkt) = encode_retry_packet(
                        &retry_scid,
                        &scid_parsed,
                        &initial_dcid_parsed,
                        &retry_token,
                    ) {
                        let _ = socket.send_to(&retry_pkt, peer_addr).await;
                    }
                    continue;
                }
            }
        }

        // ─── No Retry required: create connection immediately ─────────────────
        let params = transport.to_transport_params();
        let mtu_config = MtuConfig {
            max_mtu: transport.get_max_mtu(),
            discovery_enabled: true,
        };
        let server_cfg_early = apply_early_data_config(Arc::clone(&config), &transport);
        let conn = match Connection::new_server_with_datagram_buf(
            server_cfg_early,
            oxiquic_core::ConnectionId::new(initial_dcid_parsed.clone()),
            oxiquic_core::ConnectionId::new(scid_parsed),
            peer_addr,
            params,
            mtu_config,
            transport.get_congestion_controller(),
            transport.get_datagram_receive_buffer_size(),
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = accept_tx.send(Err(e)).await;
                continue;
            }
        };

        let local_cid_bytes: [u8; LOCAL_CID_LEN] = match conn.local_cid().as_bytes().try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Single channel for this connection's entire lifetime (handshake + 1-RTT).
        // Capacity of 16 384 datagrams (each up to 2 KiB) provides ~32 MiB of
        // buffering, avoiding spurious drops during bulk transfers where the
        // connection task may momentarily lag behind the demux.
        let (hs_tx, hs_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(16384);

        // Register in BOTH maps atomically (same demux-task tick): this prevents
        // the race where Handshake packets arrive before the local_cid is known.
        // GC is proactive: `run_server_handshake` sends `CidEvent::InitialRetired`
        // after the handshake completes so the demux removes the entry immediately.
        // The lazy closed-channel removal below acts as a defence-in-depth backstop.
        let initial_dcid_key = initial_dcid_parsed.clone();
        initial_map.insert(initial_dcid_parsed, hs_tx.clone());
        local_cid_map.insert(local_cid_bytes, hs_tx.clone());

        // Forward the first datagram into the channel.
        let _ = hs_tx.try_send((datagram, peer_addr));

        tokio::spawn(run_server_handshake(
            conn,
            peer_addr,
            Arc::clone(&socket),
            ServerHandshakeArgs {
                hs_tx,
                hs_rx,
                accept_tx: accept_tx.clone(),
                keep_alive_interval: transport.get_keep_alive_interval(),
                cid_route_tx: cid_route_tx.clone(),
                initial_dcid: initial_dcid_key,
            },
        ));
    }
}

/// Apply `max_early_data_size` from transport config to the server TLS config,
/// returning a (possibly new) Arc. Clones the config only when needed.
fn apply_early_data_config(
    config: Arc<ServerConfig>,
    transport: &TransportConfig,
) -> Arc<ServerConfig> {
    let size = transport.get_max_early_data_size();
    if size == 0 {
        return config;
    }
    // Only clone if the current setting differs.
    if config.max_early_data_size == size {
        return config;
    }
    let mut cfg = (*config).clone();
    cfg.max_early_data_size = size;
    Arc::new(cfg)
}

/// Generate a random 8-byte SCID for a Retry packet using the server's CSPRNG.
fn random_scid_for_retry(rng: &dyn rustls::crypto::SecureRandom) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    if rng.fill(&mut bytes).is_ok() {
        bytes.to_vec()
    } else {
        // Fallback: derive from time (does not panic but is not cryptographically strong).
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        (0u32..8)
            .map(|i| t.wrapping_add(i.wrapping_mul(0x9e37_79b9)) as u8)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// run_server_handshake
// ─────────────────────────────────────────────────────────────────────────────

/// Channels and routing metadata bundled for [`run_server_handshake`] to keep
/// the argument count within clippy's `too_many_arguments` limit.
struct ServerHandshakeArgs {
    /// Sender side of the per-connection inbound channel (registered in both
    /// `initial_map` and `local_cid_map` by the demux before spawning).
    hs_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    /// Receiver side of the per-connection inbound channel.
    hs_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    /// Channel on which a successfully-established [`QuicConnection`] (or an
    /// error) is delivered to the accept loop.
    accept_tx: mpsc::Sender<Result<QuicConnection, OxiQuicError>>,
    /// Optional keep-alive ping interval forwarded from [`TransportConfig`].
    keep_alive_interval: Option<Duration>,
    /// Channel for notifying the demux of CID routing-table updates.
    cid_route_tx: mpsc::Sender<CidRouteUpdate>,
    /// The client's initial DCID bytes — the key used in `initial_map`.
    /// Sent as `CidEvent::InitialRetired` after handshake completes (success or
    /// failure) so the demux can reclaim the `initial_map` entry immediately
    /// rather than waiting for the channel to close.
    initial_dcid: Vec<u8>,
}

/// Per-connection handshake task spawned by the demux for each new Initial.
///
/// The demux has already:
///
/// * constructed the [`Connection`] state machine synchronously,
/// * registered `hs_tx` in both `initial_map` and `local_cid_map`, and
/// * forwarded the first datagram into `hs_rx`.
///
/// This task drives the handshake to completion and sends the fully-established
/// [`QuicConnection`] on `accept_tx`.
async fn run_server_handshake(
    conn: Connection,
    peer_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    args: ServerHandshakeArgs,
) {
    let ServerHandshakeArgs {
        hs_tx,
        hs_rx,
        accept_tx,
        keep_alive_interval,
        cid_route_tx,
        initial_dcid,
    } = args;
    // The single `hs_rx` channel carries all datagrams for this connection —
    // Initial retransmits, Handshake packets, and post-handshake 1-RTT packets.
    // The demux registered this channel in both maps before spawning us, so no
    // routing race can occur.

    // Clone routing handles BEFORE they are consumed by `with_cid_routing`.
    // We need them after the handshake to send the `InitialRetired` event.
    let retire_tx = cid_route_tx.clone();
    let retire_conn_tx = hs_tx.clone();

    let inbound = InboundSource::Channel(hs_rx);
    let driver = ConnectionDriver::new(Arc::clone(&socket), inbound, conn, Some(peer_addr))
        .with_cid_routing(cid_route_tx, hs_tx);
    let mut driver = driver;

    // Drive the handshake.  The first datagram is already in the channel (the
    // demux forwarded it via `hs_tx.try_send` before spawning this task).
    let handshake_result = driver.run_handshake().await;

    // Proactively remove the initial DCID from `initial_map` now that the
    // handshake has completed (success or failure). Without this, long-lived
    // servers accumulate stale entries because the lazy closed-channel removal
    // at the demux never fires for successful connections (the channel remains
    // open through the post-handshake 1-RTT lifetime).
    let retire_update = CidRouteUpdate {
        event: CidEvent::InitialRetired(initial_dcid),
        conn_tx: retire_conn_tx,
    };
    // best-effort: if the demux is gone, we still complete cleanly.
    let _ = retire_tx.try_send(retire_update);

    if let Err(e) = handshake_result {
        let _ = accept_tx.send(Err(e)).await;
        return;
    }

    driver.conn.set_keep_alive_interval(keep_alive_interval);
    let _ = accept_tx.send(Ok(QuicConnection::new(driver))).await;
}

/// Extract `(version, dcid, scid)` from a client's first long-header Initial
/// packet without decrypting it.  Returns `None` for short-header or truncated
/// datagrams.
fn parse_client_initial_ids(datagram: &[u8]) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    use crate::coding::Buf;
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None; // short header: not a first-flight Initial
    }
    let mut buf = Buf::new(datagram);
    let _ = buf.get_u8().ok()?;
    let version = buf.get_u32().ok()?;
    let dcid_len = buf.get_u8().ok()? as usize;
    let dcid = buf.get_bytes(dcid_len).ok()?.to_vec();
    let scid_len = buf.get_u8().ok()? as usize;
    let scid = buf.get_bytes(scid_len).ok()?.to_vec();
    Some((version, dcid, scid))
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectionDriver
// ─────────────────────────────────────────────────────────────────────────────

/// A routing update from a connection task to the demux: a CID has been
/// issued or retired and the demux's `local_cid_map` must be updated.
struct CidRouteUpdate {
    /// The CID routing event.
    event: CidEvent,
    /// The inbound channel sender for this connection, so the demux can
    /// register (or deregister) the CID in `local_cid_map`.
    conn_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

/// Owns the socket (for sends) + an inbound source + connection state and
/// shuttles datagrams between them.
struct ConnectionDriver {
    /// Used exclusively for sending outgoing datagrams.
    socket: Arc<UdpSocket>,
    /// The source of inbound datagrams (direct socket read or channel).
    inbound: InboundSource,
    conn: Connection,
    peer: Option<SocketAddr>,
    recv: Vec<u8>,
    /// Optional channel to the demux for CID routing table updates.
    /// `None` for client connections (no demux), `Some` for server connections.
    cid_route_tx: Option<mpsc::Sender<CidRouteUpdate>>,
    /// The inbound sender for this connection (needed when forwarding CID
    /// routing updates to the demux so it can register/unregister routes).
    self_tx: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
}

impl ConnectionDriver {
    fn new(
        socket: Arc<UdpSocket>,
        inbound: InboundSource,
        conn: Connection,
        peer: Option<SocketAddr>,
    ) -> Self {
        Self {
            socket,
            inbound,
            conn,
            peer,
            recv: vec![0u8; RECV_BUF],
            cid_route_tx: None,
            self_tx: None,
        }
    }

    /// Decompose this driver into the parts needed by [`run_driven_connection`].
    ///
    /// The remaining fields (`recv`, `cid_route_tx`, `self_tx`) are dropped.
    /// This is the safe alternative to struct destructuring when a `Drop` impl
    /// exists on a containing type ([`QuicConnection`]).
    fn into_parts(
        self,
    ) -> (
        Arc<UdpSocket>,
        InboundSource,
        Connection,
        Option<SocketAddr>,
    ) {
        (self.socket, self.inbound, self.conn, self.peer)
    }

    /// Attach a CID routing channel so this driver can notify the demux when
    /// new connection IDs are issued or retired.
    fn with_cid_routing(
        mut self,
        cid_route_tx: mpsc::Sender<CidRouteUpdate>,
        self_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> Self {
        self.cid_route_tx = Some(cid_route_tx);
        self.self_tx = Some(self_tx);
        self
    }

    /// Drain CID events from the connection and forward them to the demux.
    fn drain_cid_events(&mut self) {
        if let (Some(tx), Some(self_tx)) = (&self.cid_route_tx, &self.self_tx) {
            while let Some(event) = self.conn.pop_cid_event() {
                let update = CidRouteUpdate {
                    event,
                    conn_tx: self_tx.clone(),
                };
                // best-effort: if channel is full / closed, drop the event.
                let _ = tx.try_send(update);
            }
        } else {
            // No demux routing: drain events to prevent accumulation.
            while self.conn.pop_cid_event().is_some() {}
        }
    }

    /// Flush every datagram the connection currently wants to send.
    async fn flush(&mut self) -> Result<(), OxiQuicError> {
        loop {
            let mut out = Vec::new();
            let now = Instant::now();
            match self.conn.poll_transmit(now, &mut out) {
                Some(addr) if !out.is_empty() => {
                    self.socket.send_to(&out, addr).await?;
                }
                _ => break,
            }
        }
        Ok(())
    }

    /// Run the handshake to completion (or close/timeout).
    async fn run_handshake(&mut self) -> Result<(), OxiQuicError> {
        // Bound the handshake so a lost peer cannot hang the test forever.
        let deadline = Instant::now() + Duration::from_secs(10);
        self.flush().await?;
        while self.conn.is_handshaking() {
            if self.conn.is_closed() {
                return Err(self.close_error());
            }
            self.pump_once(deadline).await?;
        }
        // One more flush to emit the client's final handshake / HANDSHAKE_DONE.
        self.flush().await?;
        Ok(())
    }

    /// Receive one datagram (or time out), feed it to the connection, and flush
    /// any resulting output.
    /// Receive one datagram (or time out), feed it to the connection, and flush
    /// any resulting output.
    ///
    /// After the first blocking receive, any additional datagrams that are
    /// immediately available in the socket or channel buffer are drained in a
    /// tight non-blocking loop (up to [`BURST_DRAIN_LIMIT`] extra datagrams)
    /// before flushing. This coalesces ACK processing for a burst of packets —
    /// which is critical for throughput during slow-start: without batching, each
    /// `pump_once` call grows the congestion window by only one packet worth of
    /// ACKs and then yields back to the tokio scheduler (incurring scheduler
    /// wakeup latency, ~1–15 ms on macOS). With batching, a burst of N ACKs is
    /// processed in one call, growing the window by N × max_datagram at once.
    async fn pump_once(&mut self, deadline: Instant) -> Result<(), OxiQuicError> {
        /// Maximum number of additional (non-blocking) datagrams drained per
        /// `pump_once` call after the first blocking receive.  Caps the
        /// single-call work to a bounded amount, ensuring other async tasks still
        /// get scheduled.  128 was chosen to keep large-payload throughput high
        /// (each call processes up to 129 ACKs, growing the CUBIC window fast)
        /// while still yielding to the tokio scheduler regularly.
        const BURST_DRAIN_LIMIT: usize = 128;

        let timeout = self.conn.next_timeout().unwrap_or(deadline).min(deadline);
        tokio::select! {
            res = recv_inbound(&mut self.inbound, &mut self.recv) => {
                let (owned, from) = res?;
                self.handle_inbound_datagram(owned, from)?;
                // Drain additional immediately-available datagrams.  This
                // prevents per-datagram scheduler round-trips during ACK bursts.
                for _ in 0..BURST_DRAIN_LIMIT {
                    match try_recv_inbound(&mut self.inbound, &mut self.recv) {
                        Some(Ok((owned2, from2))) => self.handle_inbound_datagram(owned2, from2)?,
                        Some(Err(e)) => return Err(OxiQuicError::Io(e)),
                        None => break,
                    }
                }
                self.flush().await?;
            }
            () = sleep_until(timeout.into()) => {
                let now = Instant::now();
                self.conn.handle_timeout(now);
                if now >= deadline && self.conn.is_handshaking() {
                    return Err(OxiQuicError::Timeout);
                }
                self.flush().await?;
            }
        }
        Ok(())
    }

    /// Process a single inbound datagram: update peer-address state, feed the
    /// datagram to the connection state machine, and adopt any newly-validated
    /// path address.  Extracted from `pump_once` so the burst-drain loop can
    /// reuse it without duplicating the address-migration logic.
    fn handle_inbound_datagram(
        &mut self,
        owned: Vec<u8>,
        from: SocketAddr,
    ) -> Result<(), OxiQuicError> {
        if self.peer.is_none() {
            self.peer = Some(from);
        } else if self.peer != Some(from) && self.conn.is_established() {
            // Address change on an established connection: RFC 9000 §9.3
            // — register the candidate and kick off path validation.
            // NOTE: We trigger on any new source address, including
            // probing packets. Full RFC compliance would require
            // restricting to non-probing frames only (§9.3.1).
            self.conn.set_candidate_peer_addr(from);
            let _ = self.conn.initiate_path_challenge();
        }
        let mut data = owned;
        let now = Instant::now();
        self.conn.handle_datagram(now, &mut data)?;
        // After processing: if the path was just validated, adopt the
        // new peer address at the driver level too.
        if self.conn.path_validated() {
            self.peer = Some(self.conn.peer_addr());
        }
        // Drain CID routing events and forward them to the demux.
        self.drain_cid_events();
        Ok(())
    }

    fn close_error(&self) -> OxiQuicError {
        // `OxiQuicError` is not `Clone` (it wraps `io::Error`), so reconstruct
        // the error with full fidelity (preserving transport error codes and
        // application close codes) rather than flattening to a plain string.
        match self.conn.peer_close_reason() {
            Some(OxiQuicError::TransportError {
                code,
                frame_type,
                reason,
            }) => OxiQuicError::TransportError {
                code: *code,
                frame_type: *frame_type,
                reason: reason.clone(),
            },
            Some(OxiQuicError::ApplicationClose { code, reason }) => {
                OxiQuicError::ApplicationClose {
                    code: *code,
                    reason: reason.clone(),
                }
            }
            Some(other) => OxiQuicError::Connection(other.to_string()),
            None => OxiQuicError::Connection("connection closed".into()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QuicConnection
// ─────────────────────────────────────────────────────────────────────────────

/// An established QUIC connection handle.
///
/// Exposes the stream API and a receive pump. Streams are opened with
/// [`QuicConnection::open_bidi`], data is queued with
/// [`QuicConnection::send`], and inbound data is read with
/// [`QuicConnection::read`] / [`QuicConnection::accept_uni_or_bidi_data`].
pub struct QuicConnection {
    /// Wrapped in `Option` so the `Drop` impl and `into_driven` can take
    /// ownership without needing struct destructuring (which is blocked on
    /// types that implement `Drop`).
    driver: Option<ConnectionDriver>,
}

impl QuicConnection {
    fn new(driver: ConnectionDriver) -> Self {
        Self {
            driver: Some(driver),
        }
    }

    /// Return a reference to the inner driver.
    ///
    /// Panics only if called after `into_driven` (not possible through the
    /// public API since `into_driven` consumes `self`).
    fn drv(&self) -> &ConnectionDriver {
        self.driver
            .as_ref()
            .expect("QuicConnection driver already consumed by into_driven")
    }

    /// Return a mutable reference to the inner driver.
    fn drv_mut(&mut self) -> &mut ConnectionDriver {
        self.driver
            .as_mut()
            .expect("QuicConnection driver already consumed by into_driven")
    }

    /// The role (client or server) of this endpoint.
    #[must_use]
    pub fn role(&self) -> Role {
        self.drv().conn.role()
    }

    /// Whether the connection has fully closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.drv().conn.is_closed()
    }

    /// The peer's transport parameters, available post-handshake.
    #[must_use]
    pub fn peer_transport_params(&self) -> Option<&oxiquic_core::TransportParams> {
        self.drv().conn.peer_transport_params()
    }

    /// Number of Retry packets this client accepted (always 0 for server-side
    /// connections). Exposed primarily for test observability — a value of 1
    /// confirms the Retry round-trip completed successfully.
    #[must_use]
    pub fn retry_count(&self) -> u64 {
        self.drv().conn.retry_count()
    }

    /// Initiate a QUIC key update on the next outgoing 1-RTT packet
    /// (RFC 9001 §6).
    ///
    /// Returns `true` if the key update was accepted (will take effect on the
    /// next send), or `false` if:
    /// * The handshake has not yet completed (no 1-RTT keys).
    /// * A key update was performed recently and the 3-PTO cooldown has not
    ///   elapsed (RFC 9001 §6.5).
    pub fn initiate_key_update(&mut self) -> bool {
        self.drv_mut().conn.initiate_key_update(Instant::now())
    }

    /// Number of completed key updates (locally- and peer-initiated) so far.
    /// Useful for test observability.
    #[must_use]
    pub fn key_update_count(&self) -> u64 {
        self.drv().conn.key_update_count()
    }

    /// Begin a path challenge toward the current peer (RFC 9000 §9).
    ///
    /// Queues an 8-byte `PATH_CHALLENGE` frame for the next outgoing 1-RTT
    /// packet.  Call [`Self::path_validated`] after the next send/receive
    /// cycle to check whether the peer echoed it back.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if 1-RTT keys are not yet available.
    pub fn initiate_path_challenge(&mut self) -> Result<(), OxiQuicError> {
        self.drv_mut().conn.initiate_path_challenge()
    }

    /// Whether the most recent locally-initiated path challenge was answered
    /// by the peer (RFC 9000 §9.3).
    #[must_use]
    pub fn path_validated(&self) -> bool {
        self.drv().conn.path_validated()
    }

    /// The current confirmed path MTU in bytes (starts at 1200; advances as
    /// DPLPMTUD probes succeed).
    #[must_use]
    pub fn current_mtu(&self) -> u16 {
        self.drv().conn.current_mtu()
    }

    /// Whether any send stream still has buffered data or an unsent FIN.
    ///
    /// Use together with [`bytes_in_flight`] to know when it is safe to drop
    /// the connection: when `has_pending_stream_data()` is `false` **and**
    /// `bytes_in_flight()` is `0`, every byte and the FIN have been
    /// transmitted and the peer's ACK has been processed.
    ///
    /// [`bytes_in_flight`]: Self::bytes_in_flight
    #[must_use]
    pub fn has_pending_stream_data(&self) -> bool {
        self.drv().conn.has_pending_stream_data()
    }

    /// The bytes currently in flight (ack-eliciting, unacknowledged).
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.drv().conn.bytes_in_flight()
    }

    /// The MTU size of any in-flight probe, or `None` when no probe is pending.
    #[must_use]
    pub fn probe_mtu(&self) -> Option<u16> {
        self.drv().conn.probe_mtu()
    }

    /// Returns the ALPN protocol negotiated during the TLS handshake, if any.
    ///
    /// For HTTP/3, this should be `Some(b"h3".to_vec())` after a successful
    /// connection to an HTTP/3 server.
    #[must_use]
    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.drv().conn.negotiated_alpn()
    }

    /// Open a new bidirectional stream, returning its id.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if the peer's stream limit has been
    /// reached (RFC 9000 §4.6). A `STREAMS_BLOCKED` frame is queued automatically.
    pub fn open_bidi(&mut self) -> Result<StreamId, OxiQuicError> {
        self.drv_mut().conn.open_bidi()
    }

    /// Open a bidirectional stream with an associated priority hint.
    ///
    /// The `priority` value is recorded in the returned stream ID (as a hint for
    /// future scheduler support) but does **not** currently affect packet ordering
    /// or scheduling — all streams share the same transmit queue.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if the peer's stream limit has been
    /// reached.
    pub fn open_bidi_with_priority(&mut self, _priority: i32) -> Result<StreamId, OxiQuicError> {
        // Priority is stored as a hint; the current scheduler does not reorder
        // streams by priority. Future work: prioritised stream scheduling.
        self.drv_mut().conn.open_bidi()
    }

    /// Open a bidirectional stream with automatic retry on transient
    /// stream-limit errors (RFC 9000 §4.6 `STREAMS_BLOCKED` back-pressure).
    ///
    /// If the peer's concurrent-stream limit has been reached, this method
    /// retries up to `max_attempts` times, waiting `retry_delay` between each
    /// attempt.  A `STREAMS_BLOCKED` frame is emitted by the transport on each
    /// failed attempt, signalling the peer to raise its `MAX_STREAMS` limit.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if all attempts are exhausted without
    /// success (the peer never raised its limit), or any non-transient error
    /// from the underlying connection.
    pub async fn open_bi_reliable(
        &mut self,
        max_attempts: u32,
        retry_delay: Duration,
    ) -> Result<StreamId, OxiQuicError> {
        let attempts = max_attempts.max(1);
        for attempt in 0..attempts {
            match self.drv_mut().conn.open_bidi() {
                Ok(sid) => return Ok(sid),
                Err(OxiQuicError::Stream(_)) if attempt + 1 < attempts => {
                    // Transient stream-limit: flush any STREAMS_BLOCKED frame
                    // we just queued and wait for the peer to raise its limit.
                    let _ = self.drv_mut().flush().await;
                    tokio::time::sleep(retry_delay).await;
                }
                Err(e) => return Err(e),
            }
        }
        // Exhausted all attempts — return the last error.
        self.drv_mut().conn.open_bidi()
    }

    /// The number of bidirectional streams opened on this connection since
    /// establishment, including streams opened by the local endpoint.
    ///
    /// Derived from the connection-level `streams_opened` counter maintained by
    /// the protocol state machine.
    #[must_use]
    pub fn streams_opened(&self) -> u64 {
        self.drv().conn.stats().streams_opened
    }

    /// The number of streams that have been fully closed.
    ///
    /// Currently returns `0` — the underlying counter is tracked but close
    /// events are not yet plumbed from the stream state machine to the stats
    /// snapshot.  This will be non-zero in a future release.
    #[must_use]
    pub fn streams_closed(&self) -> u64 {
        self.drv().conn.stats().streams_closed
    }

    /// The current smoothed round-trip time estimate for this connection.
    ///
    /// Sourced from the congestion controller's RTT estimator
    /// (RFC 9002 Section 5.3).  The value is updated after each ACK round trip.
    /// Before the first ACK is processed the returned duration is
    /// [`Duration::ZERO`].
    ///
    /// This is the *smoothed* RTT (`srtt`), not the latest single sample.
    /// For the latest sample use [`Self::stats`]`.rtt`.
    #[must_use]
    pub fn ping(&self) -> Duration {
        self.drv().conn.stats().smoothed_rtt
    }

    /// Queue `data` on `stream`, optionally finishing it, then flush.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] if the stream is unknown or sending fails.
    pub async fn send(
        &mut self,
        stream: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<(), OxiQuicError> {
        self.drv_mut().conn.send_stream(stream, data, fin)?;
        self.drv_mut().flush().await
    }

    /// Wait until `stream` has at least one byte of in-order data (or is
    /// finished), returning `(bytes, fin)`. Pumps the socket until data
    /// arrives or the idle timeout fires.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] on I/O failure, connection close or timeout.
    pub async fn read(&mut self, stream: StreamId) -> Result<(Vec<u8>, bool), OxiQuicError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        self.read_with_deadline(stream, deadline).await
    }

    /// Like [`QuicConnection::read`] but with a caller-supplied absolute
    /// deadline. Pumps the socket until data arrives on `stream` or `deadline`
    /// is reached.
    ///
    /// ACKs are flushed before returning data to the caller so that the sender
    /// is not starved of acknowledgements while the application processes a
    /// burst of already-buffered packets. Without this flush, the ACK for a
    /// received batch would be deferred until the read buffer empties and the
    /// next `pump_once` call fires — creating a bursty ACK pattern that keeps
    /// the sender's congestion window artificially small.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] on I/O failure, connection close or timeout.
    pub async fn read_with_deadline(
        &mut self,
        stream: StreamId,
        deadline: Instant,
    ) -> Result<(Vec<u8>, bool), OxiQuicError> {
        loop {
            let (bytes, fin) = self.drv_mut().conn.read_stream(stream)?;
            if !bytes.is_empty() || fin {
                // Flush any pending ACKs before returning so the sender is not
                // starved while the application drains a burst of buffered data.
                self.drv_mut().flush().await?;
                return Ok((bytes, fin));
            }
            if self.drv().conn.is_closed() {
                return Err(self.drv().close_error());
            }
            self.drv_mut().pump_once(deadline).await?;
            if Instant::now() >= deadline {
                return Err(OxiQuicError::Timeout);
            }
        }
    }

    /// Wait for the peer to open a stream and deliver data, returning the
    /// stream id and the first chunk of `(bytes, fin)`. Useful on the server
    /// side of the echo test.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] on I/O failure, connection close or timeout.
    pub async fn accept_uni_or_bidi_data(
        &mut self,
    ) -> Result<(StreamId, Vec<u8>, bool), OxiQuicError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        self.accept_uni_or_bidi_data_with_deadline(deadline).await
    }

    /// Like [`QuicConnection::accept_uni_or_bidi_data`] but with a
    /// caller-supplied absolute deadline.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] on I/O failure, connection close or timeout.
    pub async fn accept_uni_or_bidi_data_with_deadline(
        &mut self,
        deadline: Instant,
    ) -> Result<(StreamId, Vec<u8>, bool), OxiQuicError> {
        loop {
            if let Some(id) = self.drv_mut().conn.poll_readable() {
                let (bytes, fin) = self.drv_mut().conn.read_stream(id)?;
                return Ok((id, bytes, fin));
            }
            if self.drv().conn.is_closed() {
                return Err(self.drv().close_error());
            }
            self.drv_mut().pump_once(deadline).await?;
            if Instant::now() >= deadline {
                return Err(OxiQuicError::Timeout);
            }
        }
    }

    /// Send an unreliable datagram to the peer (RFC 9221).
    ///
    /// # Errors
    /// Returns [`OxiQuicError`] if the peer does not support datagrams or if
    /// the payload exceeds the peer's advertised `max_datagram_frame_size`.
    pub async fn send_datagram(&mut self, data: Vec<u8>) -> Result<(), OxiQuicError> {
        self.drv_mut().conn.send_datagram(data)?;
        self.drv_mut().flush().await
    }

    /// Receive an unreliable datagram from the peer (RFC 9221).
    ///
    /// Pumps the connection until a datagram arrives, the idle timeout fires,
    /// or the connection closes.
    ///
    /// # Errors
    /// Returns [`OxiQuicError`] on I/O failure, connection close or timeout.
    pub async fn recv_datagram(&mut self) -> Result<Vec<u8>, OxiQuicError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(dgram) = self.drv_mut().conn.recv_datagram() {
                return Ok(dgram);
            }
            if self.drv().conn.is_closed() {
                return Err(self.drv().close_error());
            }
            self.drv_mut().pump_once(deadline).await?;
            if Instant::now() >= deadline {
                return Err(OxiQuicError::Timeout);
            }
        }
    }

    /// Returns the maximum DATAGRAM payload the peer will accept, or `None` if
    /// the peer does not support unreliable datagrams (RFC 9221).
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.drv().conn.max_datagram_size()
    }

    /// Takes the address-validation token received from the server via NEW_TOKEN,
    /// if any (RFC 9000 §8.1.3). Available on the client after the handshake
    /// completes.
    pub fn take_received_token(&mut self) -> Option<Vec<u8>> {
        self.drv_mut().conn.take_received_token()
    }

    /// Whether the server accepted 0-RTT early data (RFC 9001 §4.6).
    ///
    /// - `None`: no 0-RTT was attempted (first connection, no cached ticket) or
    ///   the handshake has not yet completed.
    /// - `Some(true)`: server accepted the early data.
    /// - `Some(false)`: server rejected early data; the data was re-sent in 1-RTT.
    #[must_use]
    pub fn zero_rtt_accepted(&self) -> Option<bool> {
        self.drv().conn.zero_rtt_accepted()
    }

    /// Gracefully close the connection with an application error code/reason.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] if flushing the close frame fails.
    pub async fn close(&mut self, error_code: u64, reason: &[u8]) -> Result<(), OxiQuicError> {
        self.drv_mut().conn.close(error_code, reason);
        self.drv_mut().flush().await
    }

    /// Pump the socket once to process any pending inbound datagrams (e.g. a
    /// peer's CONNECTION_CLOSE). Returns when one datagram is handled or the
    /// short timeout elapses.
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] on I/O failure.
    pub async fn drive(&mut self) -> Result<(), OxiQuicError> {
        let deadline = Instant::now() + Duration::from_millis(200);
        let _ = self.drv_mut().pump_once(deadline).await;
        Ok(())
    }

    /// Return a snapshot of connection statistics (RTT estimates, byte and
    /// packet counters, loss count and current congestion window).
    ///
    /// See [`oxiquic_core::ConnectionStats`] for the full set of fields.
    #[must_use]
    pub fn stats(&self) -> oxiquic_core::ConnectionStats {
        self.drv().conn.stats()
    }

    /// Consume this [`QuicConnection`] and return a [`DrivenConnection`] that
    /// services the socket in a background [`tokio::task`].
    ///
    /// After calling `into_driven`, the connection loop runs autonomously.
    /// Streams are opened via [`DrivenConnection::open_bidi_stream`], which
    /// returns [`SendStreamHandle`] / [`RecvStreamHandle`] pairs implementing
    /// [`tokio::io::AsyncWrite`] / [`tokio::io::AsyncRead`].
    #[must_use]
    pub fn into_driven(mut self) -> DrivenConnection {
        // Channel capacities:
        //  - write_tx: 256 — enough to buffer a burst of small writes without
        //    stalling the application.
        //  - open_tx / open_uni_tx: 16 — opening many streams simultaneously is uncommon.
        //  - close_tx: 1 — at most one close is ever sent.
        //  - accept_bidi_tx / accept_uni_tx: 64 — enough to buffer incoming streams
        //    without stalling the protocol loop.
        let (write_tx, write_rx) = mpsc::channel::<(StreamId, WriteCmd)>(256);
        let (open_tx, open_rx) =
            mpsc::channel::<oneshot::Sender<(StreamId, mpsc::Receiver<Vec<u8>>)>>(16);
        let (open_uni_tx, open_uni_rx) =
            mpsc::channel::<oneshot::Sender<(StreamId, mpsc::Receiver<Vec<u8>>)>>(16);
        let (close_tx, close_rx) = mpsc::channel::<(u64, Vec<u8>)>(1);
        let (accept_bidi_tx, accept_bidi_rx) =
            mpsc::channel::<(SendStreamHandle, RecvStreamHandle)>(64);
        let (accept_uni_tx, accept_uni_rx) = mpsc::channel::<RecvStreamHandle>(64);

        let (socket, inbound, conn, peer) = self
            .driver
            .take()
            .expect("QuicConnection driver already consumed by into_driven")
            .into_parts();

        // Capture the negotiated ALPN before `conn` is moved into the
        // background task (handshake is already complete at this point).
        let negotiated_alpn = conn.negotiated_alpn();

        let task = tokio::spawn(run_driven_connection(
            socket,
            inbound,
            conn,
            peer,
            DrivenConnectionChannels {
                write_tx: write_tx.clone(),
                write_rx,
                open_rx,
                open_uni_rx,
                close_rx,
                accept_bidi_tx,
                accept_uni_tx,
            },
        ));

        DrivenConnection {
            write_tx,
            open_tx,
            open_uni_tx,
            close_tx,
            accept_bidi_rx: Arc::new(tokio::sync::Mutex::new(accept_bidi_rx)),
            accept_uni_rx: Arc::new(tokio::sync::Mutex::new(accept_uni_rx)),
            _task: Arc::new(task),
            negotiated_alpn,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Drop for QuicConnection — best-effort graceful close
// ─────────────────────────────────────────────────────────────────────────────

impl Drop for QuicConnection {
    /// Queue a CONNECTION_CLOSE frame in the connection state machine when the
    /// handle is dropped without an explicit [`QuicConnection::close`] call.
    ///
    /// Because `Drop` cannot be `async`, this is best-effort: the
    /// `CONNECTION_CLOSE` frame is written into the connection's output buffer
    /// but **not** flushed to the socket.  If the caller later drives the
    /// connection (or calls [`QuicConnection::close`] before dropping), the
    /// frame will be sent.  If it is not driven again, the peer will rely on
    /// its idle timeout for cleanup.
    ///
    /// Already-closed connections are unaffected.
    fn drop(&mut self) {
        if let Some(d) = self.driver.as_mut() {
            if !d.conn.is_closed() {
                // Application error code 0, empty reason: we are not returning an
                // application-level error, just signalling a clean shutdown.
                d.conn.close(0, b"");
                // Flushing to the socket here would require blocking or spawning
                // (both are wrong in Drop); accept the best-effort limitation.
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use oxiquic_core::ConnectionId;

    /// Build a no-op `ConnTx` backed by a channel whose receiver is
    /// immediately dropped — we never send through it in routing-table tests.
    fn dummy_conn_tx() -> ConnTx {
        let (tx, _rx) = mpsc::channel(1);
        tx
    }

    fn make_cid(bytes: &[u8]) -> ConnectionId {
        ConnectionId::from(bytes)
    }

    // ── InitialRetired removes the initial DCID from initial_map ─────────────

    /// After `apply_cid_route_update` processes an `InitialRetired` event the
    /// corresponding entry must be absent from `initial_map`.  This is the
    /// primary GC path resolved by the TODO at ~line 622.
    #[test]
    fn initial_retired_removes_entry_from_initial_map() {
        let mut initial_map: HashMap<Vec<u8>, ConnTx> = HashMap::new();
        let mut local_cid_map: HashMap<[u8; LOCAL_CID_LEN], ConnTx> = HashMap::new();

        let dcid = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        initial_map.insert(dcid.clone(), dummy_conn_tx());
        assert!(
            initial_map.contains_key(&dcid),
            "entry must be present before GC"
        );

        let update = CidRouteUpdate {
            event: CidEvent::InitialRetired(dcid.clone()),
            conn_tx: dummy_conn_tx(),
        };
        let applied = apply_cid_route_update(&mut initial_map, &mut local_cid_map, update);

        assert!(
            applied,
            "apply_cid_route_update must return true for InitialRetired"
        );
        assert!(
            !initial_map.contains_key(&dcid),
            "initial_map must not retain entry after InitialRetired"
        );
        assert!(local_cid_map.is_empty(), "local_cid_map must be unaffected");
    }

    /// Retiring a DCID that was never in `initial_map` is a no-op (idempotent).
    #[test]
    fn initial_retired_unknown_dcid_is_noop() {
        let mut initial_map: HashMap<Vec<u8>, ConnTx> = HashMap::new();
        let mut local_cid_map: HashMap<[u8; LOCAL_CID_LEN], ConnTx> = HashMap::new();

        let update = CidRouteUpdate {
            event: CidEvent::InitialRetired(vec![0xffu8; 8]),
            conn_tx: dummy_conn_tx(),
        };
        // Must not panic.
        let applied = apply_cid_route_update(&mut initial_map, &mut local_cid_map, update);
        assert!(applied);
        assert!(initial_map.is_empty());
    }

    // ── Register / Unregister still work after the refactor ──────────────────

    #[test]
    fn register_inserts_into_local_cid_map() {
        let mut initial_map: HashMap<Vec<u8>, ConnTx> = HashMap::new();
        let mut local_cid_map: HashMap<[u8; LOCAL_CID_LEN], ConnTx> = HashMap::new();

        let cid_bytes = [0x11u8; LOCAL_CID_LEN];
        let cid = make_cid(&cid_bytes);
        let update = CidRouteUpdate {
            event: CidEvent::Register(cid),
            conn_tx: dummy_conn_tx(),
        };
        let applied = apply_cid_route_update(&mut initial_map, &mut local_cid_map, update);
        assert!(applied);
        assert!(local_cid_map.contains_key(&cid_bytes));
        assert!(initial_map.is_empty());
    }

    #[test]
    fn unregister_removes_from_local_cid_map() {
        let mut initial_map: HashMap<Vec<u8>, ConnTx> = HashMap::new();
        let mut local_cid_map: HashMap<[u8; LOCAL_CID_LEN], ConnTx> = HashMap::new();

        let cid_bytes = [0x22u8; LOCAL_CID_LEN];
        local_cid_map.insert(cid_bytes, dummy_conn_tx());

        let cid = make_cid(&cid_bytes);
        let update = CidRouteUpdate {
            event: CidEvent::Unregister(cid),
            conn_tx: dummy_conn_tx(),
        };
        let applied = apply_cid_route_update(&mut initial_map, &mut local_cid_map, update);
        assert!(applied);
        assert!(!local_cid_map.contains_key(&cid_bytes));
    }

    /// Only the targeted initial DCID is removed; other entries survive.
    #[test]
    fn initial_retired_does_not_remove_other_entries() {
        let mut initial_map: HashMap<Vec<u8>, ConnTx> = HashMap::new();
        let mut local_cid_map: HashMap<[u8; LOCAL_CID_LEN], ConnTx> = HashMap::new();

        let dcid_a = vec![0xaau8; 8];
        let dcid_b = vec![0xbbu8; 8];
        initial_map.insert(dcid_a.clone(), dummy_conn_tx());
        initial_map.insert(dcid_b.clone(), dummy_conn_tx());

        let update = CidRouteUpdate {
            event: CidEvent::InitialRetired(dcid_a.clone()),
            conn_tx: dummy_conn_tx(),
        };
        apply_cid_route_update(&mut initial_map, &mut local_cid_map, update);

        assert!(!initial_map.contains_key(&dcid_a), "dcid_a must be removed");
        assert!(initial_map.contains_key(&dcid_b), "dcid_b must survive");
    }
}
