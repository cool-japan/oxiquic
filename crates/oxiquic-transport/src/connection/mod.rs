//! The synchronous, I/O-free QUIC connection state machine.
//!
//! [`Connection`] owns a `rustls::quic` TLS endpoint, the three packet-number
//! spaces and their CRYPTO streams, and drives the handshake by pumping
//! `write_hs`/`read_hs` and translating between TLS handshake bytes and
//! protected QUIC packets. It performs no I/O: the caller feeds it received
//! datagrams via [`Connection::handle_datagram`] and pulls datagrams to send via
//! [`Connection::poll_transmit`]. The asynchronous [`crate::endpoint`] shell
//! wires those to a UDP socket.
//!
//! Milestone coverage: M1 (handshake), M2 (1-RTT keys, HANDSHAKE_DONE,
//! CONNECTION_CLOSE, idle timeout) and M3 (stream data) are implemented here;
//! see the module-level methods for the per-milestone surface.

pub mod cid;
mod keys_path;
mod recovery;
mod recv;
mod send;
mod streams;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_core::{ConnectionId, OxiQuicError, StreamId, TransportErrorCode, TransportParams};
use rustls::quic::{
    ClientConnection, Connection as TlsConnection, KeyChange, PacketKeySet, Secrets,
    ServerConnection, Version,
};
use rustls::Side;

use crate::cc_dispatch::CongestionController;
use crate::config::CongestionAlgorithm;
use crate::connection::cid::{CidEvent, LocalCidPool, PeerCidPool};
use crate::crypto_stream::CryptoStream;
use crate::flow_control::{RecvFlowControl, SendFlowControl, StreamRecvFlow, StreamSendFlow};
use crate::params_codec::{decode_transport_params, encode_transport_params};
use crate::recovery::{LossDetection, RttEstimator};
use crate::sent_packet::SentPackets;
use crate::space::PacketSpace;
use crate::stream::{RecvStream, SendStream};

/// The QUIC v1 wire version this transport speaks.
pub(super) const QUIC_V1: u32 = 0x0000_0001;
/// Connection IDs OxiQUIC issues are a fixed 8 bytes (RFC 9000 allows 0–20).
pub(super) const LOCAL_CID_LEN: usize = 8;
/// RFC 9000 Section 14.1: a datagram carrying an Initial packet sent by a
/// client must be at least this many bytes.
pub(super) const MIN_INITIAL_DATAGRAM: usize = 1200;
/// Conservative max UDP payload we will emit in a single datagram.
pub(super) const MAX_DATAGRAM: usize = 1200;

/// Which side of the connection this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client (initiator of the handshake).
    Client,
    /// Server (responder).
    Server,
}

/// The TLS encryption level a chunk of handshake bytes belongs to. CRYPTO bytes
/// emitted by `write_hs` before the first `KeyChange` are Initial; bytes after
/// the `Handshake` key change are Handshake (RFC 9001 Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HandshakeLevel {
    Initial,
    Handshake,
}

/// The lifecycle phase of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// The TLS handshake is in progress.
    Handshaking,
    /// The handshake has completed; application data may flow.
    Established,
    /// A `CONNECTION_CLOSE` has been sent or received; closing.
    Closing,
    /// The connection is fully closed (drained).
    Closed,
}

/// MTU-discovery configuration plumbed through from [`crate::TransportConfig`]
/// into the connection state machine (since `new_inner` takes wire-level
/// [`TransportParams`], not the high-level config).
#[derive(Debug, Clone, Copy)]
pub struct MtuConfig {
    /// Maximum MTU to probe for (DPLPMTUD ceiling, RFC 8899).
    pub max_mtu: u16,
    /// Whether path-MTU discovery is enabled.
    pub discovery_enabled: bool,
}

impl Default for MtuConfig {
    fn default() -> Self {
        Self {
            max_mtu: 1452,
            discovery_enabled: true,
        }
    }
}

/// Bundled arguments for [`Connection::new_inner`], grouping identity,
/// addressing and transport parameters to keep the constructor below clippy's
/// `too_many_arguments` threshold.
struct ConnectionParams {
    local_cid: ConnectionId,
    peer_cid: ConnectionId,
    initial_dcid: ConnectionId,
    peer_addr: SocketAddr,
    local_params: TransportParams,
    mtu_config: MtuConfig,
    datagram_recv_buffer_size: usize,
}

/// A synchronous QUIC connection: protocol logic without I/O.
pub struct Connection {
    pub(super) role: Role,
    pub(super) tls: TlsConnection,
    pub(super) state: ConnectionState,

    /// Connection ID this endpoint uses to identify itself (our SCID; the peer
    /// sends to it as its DCID).
    pub(super) local_cid: ConnectionId,
    /// Connection ID we send packets to (the peer's SCID).
    pub(super) peer_cid: ConnectionId,
    /// The original DCID the client chose, which seeds the Initial keys for the
    /// whole Initial space (RFC 9001 Section 5.2).
    pub(super) initial_dcid: ConnectionId,

    /// Initial, Handshake and Application packet-number spaces.
    pub(super) initial: PacketSpace,
    pub(super) handshake: PacketSpace,
    pub(super) application: PacketSpace,

    /// CRYPTO streams for the Initial and Handshake spaces.
    pub(super) initial_crypto: CryptoStream,
    pub(super) handshake_crypto: CryptoStream,

    /// The level the next `write_hs` output should be attributed to.
    pub(super) write_level: HandshakeLevel,
    /// Whether the Handshake-space keys have been installed.
    pub(super) handshake_keys_ready: bool,
    /// Whether 1-RTT (application) keys have been installed.
    pub(super) one_rtt_ready: bool,
    /// Whether we have sent HANDSHAKE_DONE (server) / received it (client).
    pub(super) handshake_done: bool,
    /// Set once the local TLS stack reports the handshake finished.
    pub(super) handshake_complete: bool,

    /// The peer's transport parameters, decoded once available.
    pub(super) peer_params: Option<TransportParams>,

    /// Bidirectional send/recv streams, indexed by stream id.
    pub(super) send_streams: std::collections::BTreeMap<u64, SendStream>,
    pub(super) recv_streams: std::collections::BTreeMap<u64, RecvStream>,
    /// Next bidirectional stream index this endpoint will open.
    pub(super) next_bidi_index: u64,
    /// Next unidirectional stream index this endpoint will open.
    pub(super) next_uni_index: u64,
    /// Stream ids that have received data and not yet been drained by the app.
    pub(super) readable: VecDeque<StreamId>,
    /// Peer-initiated stream IDs seen for the first time (not yet accepted by
    /// the application). Populated in `recv_stream`; drained by
    /// `poll_new_peer_stream`.
    pub(super) new_peer_streams: VecDeque<StreamId>,

    /// The remote address packets are sent to.
    pub(super) peer_addr: SocketAddr,

    /// Idle timeout (RFC 9000 Section 10.1); `None` disables it.
    pub(super) idle_timeout: Option<Duration>,
    /// Deadline after which the connection is considered idle.
    pub(super) idle_deadline: Option<Instant>,

    /// Keep-alive interval: when `Some`, a PING is emitted at this cadence so
    /// the connection (and NAT bindings) stay live even with no application data.
    pub(super) keep_alive_interval: Option<Duration>,
    /// The next instant at which a keep-alive PING should be sent.
    pub(super) next_keep_alive: Option<Instant>,
    /// Whether a keep-alive PING is pending emission in the next 1-RTT packet.
    pub(super) pending_keep_alive_ping: bool,

    /// A pending application close to emit, if any: `(error_code, reason)`.
    pub(super) pending_close: Option<(u64, Vec<u8>)>,
    /// A transport error to emit as CONNECTION_CLOSE.
    pub(super) pending_transport_close: Option<(TransportErrorCode, Vec<u8>)>,
    /// Set when the peer closed the connection; surfaced to the application.
    pub(super) peer_closed: Option<OxiQuicError>,

    // ─── M4: loss detection & recovery (RFC 9002) ───────────────────────────
    /// Per-space record of sent ack-eliciting packets, for ACK processing and
    /// loss detection. Index by [`SpaceKind`] / [`SpaceIndex`].
    pub(super) sent_packets: [SentPackets; 3],
    /// RTT estimator shared across spaces (RFC 9002 Section 5).
    pub(super) rtt: RttEstimator,
    /// Loss-detection / PTO timer coordination (RFC 9002 Section 6).
    pub(super) loss: LossDetection,
    /// The current loss-detection timer deadline (PTO or time-threshold loss).
    pub(super) loss_timer: Option<Instant>,
    /// Number of probe packets owed (sent on PTO expiry, RFC 9002 6.2.4).
    pub(super) probes_owed: u32,
    /// Our peer's `max_ack_delay` (used in the PTO computation once the
    /// handshake is confirmed); zero before then.
    pub(super) peer_max_ack_delay: Duration,

    // ─── M5: congestion & flow control ──────────────────────────────────────
    /// Active congestion controller (NewReno, CUBIC, or BBR v2).
    pub(super) congestion: CongestionController,
    /// Connection-level send-side flow control (RFC 9000 Section 4.1).
    pub(super) send_flow: SendFlowControl,
    /// Connection-level receive-side flow control.
    pub(super) recv_flow: RecvFlowControl,
    /// Per-stream send-side flow control, keyed by stream id.
    pub(super) stream_send_flow: std::collections::BTreeMap<u64, StreamSendFlow>,
    /// Per-stream receive-side flow control, keyed by stream id.
    pub(super) stream_recv_flow: std::collections::BTreeMap<u64, StreamRecvFlow>,
    /// Our advertised initial per-stream flow-control limit (for streams the
    /// peer opens), captured from our local transport parameters.
    pub(super) local_initial_max_stream_data: u64,
    /// Pending connection-level `MAX_DATA` to send, if the limit advanced.
    pub(super) pending_max_data: Option<u64>,
    /// Pending per-stream `MAX_STREAM_DATA` to send.
    pub(super) pending_max_stream_data: std::collections::BTreeMap<u64, u64>,
    /// Pending `DATA_BLOCKED` limit to announce, if blocked.
    pub(super) pending_data_blocked: Option<u64>,
    /// Pending `STREAM_DATA_BLOCKED` `(id, limit)` to announce.
    pub(super) pending_stream_data_blocked: std::collections::BTreeMap<u64, u64>,
    /// Statistics counters surfaced via [`Connection::stats`].
    pub(super) bytes_sent: u64,
    pub(super) bytes_recv: u64,
    pub(super) packets_sent: u64,
    pub(super) packets_recv: u64,
    pub(super) packets_lost: u64,

    // ─── Stream reset / stop-sending (RFC 9000 §19.4, §19.5) ───────────────
    /// RESET_STREAM frames pending emission, keyed by stream ID.
    /// The value is `(error_code, final_size)`.  Entries are kept until the
    /// carrying packet is ACKed; the simple implicit-retransmit approach re-emits
    /// them on each transmit cycle until cleared.
    pub(super) pending_reset_streams: std::collections::BTreeMap<u64, (u64, u64)>,
    /// STOP_SENDING frames pending emission, keyed by stream ID.
    /// The value is the application error code.
    pub(super) pending_stop_sending: std::collections::BTreeMap<u64, u64>,

    // ─── Retry (RFC 9000 §8.1, RFC 9001 §5.8) ───────────────────────────────
    /// Retry token received from the server; included in all subsequent Initials.
    pub(super) retry_token: Option<Vec<u8>>,
    /// Accumulates all Initial-space CRYPTO bytes produced by `write_hs`.
    /// Used to rebuild `initial_crypto` after re-keying on Retry receipt.
    pub(super) cached_initial_hs_bytes: Vec<u8>,
    /// Whether we have already processed one Retry (RFC 9000 §17.2.5.2).
    pub(super) retry_done: bool,
    /// Number of Retry packets received (test observability).
    pub(super) retry_count: u64,

    // ─── Path migration (RFC 9000 §9) ───────────────────────────────────────
    /// Secure RNG borrowed from the crypto provider; used to generate
    /// PATH_CHALLENGE nonces without re-borrowing the config each time.
    pub(super) secure_random: &'static dyn rustls::crypto::SecureRandom,
    /// An 8-byte PATH_RESPONSE nonce queued for transmission: the peer sent us
    /// a PATH_CHALLENGE and we must echo the same bytes on the next 1-RTT packet
    /// (RFC 9000 §8.2.2, §19.17).
    pub(super) pending_path_response: Option<[u8; 8]>,
    /// The 8-byte nonce we sent in a PATH_CHALLENGE, waiting to be echoed back
    /// by the peer. Cleared once a matching PATH_RESPONSE is received.
    pub(super) pending_path_challenge: Option<[u8; 8]>,
    /// Set when `initiate_path_challenge` is called (or when the frame was lost
    /// and needs retransmission); cleared once the frame is placed in a packet.
    /// Separates "needs to send" from "waiting for response" states.
    pub(super) pending_path_challenge_send: bool,
    /// A candidate remote address received from a datagram that arrived from a
    /// different source address than `peer_addr`. Promoted to `peer_addr` once
    /// the path is validated via PATH_CHALLENGE / PATH_RESPONSE.
    pub(super) candidate_peer_addr: Option<std::net::SocketAddr>,
    /// Set to `true` when the most recent locally-initiated path challenge was
    /// answered with a matching PATH_RESPONSE. Reset when a new challenge starts.
    pub(super) path_validated: bool,

    // ─── DPLPMTUD (RFC 8899) ─────────────────────────────────────────────────
    /// The MTU we are currently using for outgoing packets (after confirmed by a
    /// successful probe or the initial configured value).
    pub(super) current_mtu: u16,
    /// The MTU size of the probe currently in-flight (waiting for ACK/loss).
    /// `None` when no probe is pending.
    pub(super) probe_mtu: Option<u16>,
    /// How many consecutive probes we have sent at `probe_mtu` without success.
    pub(super) probe_count: u8,
    /// The maximum MTU ceiling to probe up to (from config).
    pub(super) max_mtu: u16,
    /// Whether path-MTU discovery is enabled (from config).
    pub(super) mtu_discovery_enabled: bool,
    /// Set when a new MTU probe should be built on the next outgoing packet.
    pub(super) pending_mtu_probe: bool,
    /// When to schedule the next probe attempt (after a delay post-handshake
    /// or post-failure back-off).
    pub(super) next_mtu_probe: Option<Instant>,

    // ─── Key update (RFC 9001 §6) ────────────────────────────────────────────
    /// The key phase bit we are currently **sending** with (0 = false, 1 = true).
    pub(super) key_phase: bool,
    /// The rustls `Secrets` for the current 1-RTT epoch, used to derive
    /// `next_1rtt_keys` and future epochs.  `None` before the handshake delivers
    /// `KeyChange::OneRtt`.
    pub(super) one_rtt_secrets: Option<Secrets>,
    /// Packet keys pre-derived for the *next* epoch (next key phase).  Present
    /// once 1-RTT secrets are available so we can accept a peer-initiated update
    /// without delay.
    pub(super) next_1rtt_keys: Option<PacketKeySet>,
    /// Previous epoch remote packet key kept briefly for reordered packets
    /// (RFC 9001 §6.6).  Tuple is `(old_remote_packet_key, retire_after)`.
    pub(super) prev_1rtt_keys: Option<(Box<dyn rustls::quic::PacketKey>, Instant)>,
    /// Set when a key update from the peer was accepted; causes the next
    /// outgoing 1-RTT packet to use the new `key_phase` bit.
    pub(super) key_update_received: bool,
    /// Set when `initiate_key_update()` is called; causes the next outgoing
    /// 1-RTT packet to flip the key phase.
    pub(super) key_update_pending: bool,
    /// Earliest instant at which the next *local* key update is permitted
    /// (RFC 9001 §6.5: must not initiate within 3 PTO of the last update).
    pub(super) key_update_cooldown: Option<Instant>,
    /// Number of completed key updates (test observability).
    pub(super) key_update_count: u64,

    // ─── Stream-concurrency flow control (RFC 9000 §4.6) ────────────────────
    /// Maximum bidirectional streams the peer may open (lifted from peer params).
    pub(super) peer_max_streams_bidi: u64,
    /// Maximum unidirectional streams the peer may open (lifted from peer params).
    pub(super) peer_max_streams_uni: u64,
    /// Maximum bidirectional streams we advertised to the peer.
    pub(super) local_max_streams_bidi: u64,
    /// Maximum unidirectional streams we advertised to the peer.
    pub(super) local_max_streams_uni: u64,
    /// The last MAX_STREAMS bidi value we sent (to detect when we need to re-send).
    pub(super) sent_max_streams_bidi: u64,
    /// The last MAX_STREAMS uni value we sent.
    pub(super) sent_max_streams_uni: u64,
    /// Count of peer-initiated bidirectional streams that have been closed.
    pub(super) closed_peer_bidi: u64,
    /// Count of peer-initiated unidirectional streams that have been closed.
    pub(super) closed_peer_uni: u64,
    /// Pending MAX_STREAMS frame to send for bidirectional streams.
    pub(super) pending_max_streams_bidi: Option<u64>,
    /// Pending MAX_STREAMS frame to send for unidirectional streams.
    pub(super) pending_max_streams_uni: Option<u64>,
    /// Pending STREAMS_BLOCKED frame to send for bidirectional streams.
    pub(super) pending_streams_blocked_bidi: Option<u64>,
    /// Pending STREAMS_BLOCKED frame to send for unidirectional streams.
    pub(super) pending_streams_blocked_uni: Option<u64>,

    // ─── Unreliable datagrams (RFC 9221) ────────────────────────────────────
    /// The peer's max DATAGRAM frame payload size (0 = peer does not support
    /// datagrams).
    pub(super) peer_max_datagram_frame_size: u64,
    /// Our local max DATAGRAM frame payload size (from our transport params).
    pub(super) local_max_datagram_frame_size: u64,
    /// Incoming DATAGRAM frames queued for the application.
    pub(super) datagram_recv_queue: std::collections::VecDeque<Vec<u8>>,
    /// Outgoing DATAGRAM frames queued for transmission.
    pub(super) datagram_send_queue: std::collections::VecDeque<Vec<u8>>,
    /// Maximum total bytes in the receive queue before the oldest is evicted.
    pub(super) datagram_recv_buffer_limit: usize,

    // ─── 0-RTT early data (RFC 9001 §4.6, RFC 9000 §4.6.1) ─────────────────
    /// Early (0-RTT) directional key derived from the resumption secret.
    /// Client uses it to encrypt; server to decrypt.
    pub(super) zero_rtt_keys: Option<rustls::quic::DirectionalKeys>,
    /// Application data buffered to send as 0-RTT before handshake completes.
    /// Replayed in 1-RTT on rejection (RFC 9000 §4.6.1).
    pub(super) early_data_buf: Vec<(oxiquic_core::StreamId, Vec<u8>, bool)>,
    /// True after early data has been emitted in 0-RTT packets.
    pub(super) zero_rtt_sent: bool,
    /// Server acceptance: Some(true) accepted, Some(false) rejected, None pending.
    pub(super) zero_rtt_accepted: Option<bool>,

    // ─── Address-validation tokens (RFC 9000 §8.1.3) ────────────────────────
    /// Token received from the server via NEW_TOKEN (client only); available
    /// for inclusion in a future connection's Initial packet.
    pub(super) received_token: Option<Vec<u8>>,
    /// Token the server will send to the client post-handshake via NEW_TOKEN.
    pub(super) pending_new_token: Option<Vec<u8>>,

    // ─── Connection ID management (RFC 9000 §§5.1, 19.15, 19.16) ─────────────
    /// Pool of CIDs this endpoint issued to the peer; drives NEW_CONNECTION_ID
    /// emission and handles peer RETIRE_CONNECTION_ID.
    pub(super) local_cid_pool: LocalCidPool,
    /// Pool of CIDs the peer issued to us; drives RETIRE_CONNECTION_ID
    /// emission and handles NEW_CONNECTION_ID.
    pub(super) peer_cid_pool: PeerCidPool,
    /// Pending CID routing-table events for the endpoint demux layer.
    pub(super) pending_cid_events: VecDeque<CidEvent>,
    /// Sequence numbers of NEW_CONNECTION_ID frames received **in the current
    /// packet**, used to detect the RFC 9000 §19.16 same-packet violation.
    /// Cleared at the start of each call to `process_frames`.
    pub(super) cids_issued_this_packet: std::collections::HashSet<u64>,
}

impl Connection {
    /// Create a client connection. `initial_dcid`/`local_cid` are freshly
    /// generated; the Initial keys are derived from `initial_dcid`.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Tls`] if rustls rejects the configuration.
    pub fn new_client(
        config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        peer_addr: SocketAddr,
        local_params: TransportParams,
        mtu_config: MtuConfig,
        congestion_algo: CongestionAlgorithm,
    ) -> Result<Self, OxiQuicError> {
        Self::new_client_with_datagram_buf(
            config,
            server_name,
            peer_addr,
            local_params,
            mtu_config,
            congestion_algo,
            65536,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_client_with_datagram_buf(
        config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        peer_addr: SocketAddr,
        local_params: TransportParams,
        mtu_config: MtuConfig,
        congestion_algo: CongestionAlgorithm,
        datagram_recv_buffer_size: usize,
    ) -> Result<Self, OxiQuicError> {
        let rng = config.crypto_provider().secure_random;
        let initial_dcid = random_cid(rng);
        let local_cid = random_cid(rng);
        let params_bytes = encode_transport_params(&local_params);
        let client = ClientConnection::new(config, Version::V1, server_name, params_bytes)
            .map_err(|e| OxiQuicError::Tls(e.to_string()))?;
        let mut conn = Self::new_inner(
            Role::Client,
            TlsConnection::Client(client),
            ConnectionParams {
                local_cid,
                peer_cid: initial_dcid.clone(),
                initial_dcid,
                peer_addr,
                local_params,
                mtu_config,
                datagram_recv_buffer_size,
            },
            rng,
            congestion_algo,
        );
        conn.install_initial_keys();
        Ok(conn)
    }

    /// Create a server connection in response to a client's first Initial
    /// packet. `client_dcid` is the DCID from that packet (seeds Initial keys);
    /// `client_scid` is the client's SCID (our peer CID).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Tls`] if rustls rejects the configuration.
    pub fn new_server(
        config: Arc<rustls::ServerConfig>,
        client_dcid: ConnectionId,
        client_scid: ConnectionId,
        peer_addr: SocketAddr,
        local_params: TransportParams,
        mtu_config: MtuConfig,
        congestion_algo: CongestionAlgorithm,
    ) -> Result<Self, OxiQuicError> {
        Self::new_server_with_datagram_buf(
            config,
            client_dcid,
            client_scid,
            peer_addr,
            local_params,
            mtu_config,
            congestion_algo,
            65536,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_server_with_datagram_buf(
        config: Arc<rustls::ServerConfig>,
        client_dcid: ConnectionId,
        client_scid: ConnectionId,
        peer_addr: SocketAddr,
        local_params: TransportParams,
        mtu_config: MtuConfig,
        congestion_algo: CongestionAlgorithm,
        datagram_recv_buffer_size: usize,
    ) -> Result<Self, OxiQuicError> {
        let rng = config.crypto_provider().secure_random;
        let local_cid = random_cid(rng);
        let params_bytes = encode_transport_params(&local_params);
        let server = ServerConnection::new(config, Version::V1, params_bytes)
            .map_err(|e| OxiQuicError::Tls(e.to_string()))?;
        let mut conn = Self::new_inner(
            Role::Server,
            TlsConnection::Server(server),
            ConnectionParams {
                local_cid,
                peer_cid: client_scid,
                initial_dcid: client_dcid,
                peer_addr,
                local_params,
                mtu_config,
                datagram_recv_buffer_size,
            },
            rng,
            congestion_algo,
        );
        conn.install_initial_keys();
        Ok(conn)
    }

    fn new_inner(
        role: Role,
        tls: TlsConnection,
        params: ConnectionParams,
        secure_random: &'static dyn rustls::crypto::SecureRandom,
        congestion_algo: CongestionAlgorithm,
    ) -> Self {
        let ConnectionParams {
            local_cid,
            peer_cid,
            initial_dcid,
            peer_addr,
            local_params,
            mtu_config,
            datagram_recv_buffer_size,
        } = params;
        let max_mtu = mtu_config.max_mtu;
        let mtu_discovery_enabled = mtu_config.discovery_enabled;
        let idle_timeout = match local_params.max_idle_timeout_ms {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        };
        let local_initial_max_data = local_params.initial_max_data;
        // Streams the peer opens are bounded by our bidi-remote limit.
        let local_initial_max_stream_data = local_params.initial_max_stream_data_bidi_remote;
        // Capture stream concurrency limits from our own params.
        let local_max_streams_bidi = local_params.initial_max_streams_bidi;
        let local_max_streams_uni = local_params.initial_max_streams_uni;
        let local_max_datagram_frame_size = local_params.max_datagram_frame_size;
        // Generate a random server secret for stateless reset token derivation.
        let mut server_secret_bytes = [0u8; 32];
        // Ignore the error: if secure_random.fill fails we fall back to zeros,
        // which is acceptable for stateless reset tokens (degraded security
        // only, not a correctness issue).
        let _ = secure_random.fill(&mut server_secret_bytes);
        let active_cid_limit = local_params.active_connection_id_limit.max(2);
        // Pre-clone for CID pool initialization (pools need the CIDs too).
        let local_cid_for_pool = local_cid.clone();
        let peer_cid_for_pool = peer_cid.clone();
        Self {
            role,
            tls,
            state: ConnectionState::Handshaking,
            local_cid,
            peer_cid,
            initial_dcid,
            initial: PacketSpace::new(),
            handshake: PacketSpace::new(),
            application: PacketSpace::new(),
            initial_crypto: CryptoStream::new(),
            handshake_crypto: CryptoStream::new(),
            write_level: HandshakeLevel::Initial,
            handshake_keys_ready: false,
            one_rtt_ready: false,
            handshake_done: false,
            handshake_complete: false,
            peer_params: None,
            send_streams: std::collections::BTreeMap::new(),
            recv_streams: std::collections::BTreeMap::new(),
            next_bidi_index: 0,
            next_uni_index: 0,
            readable: VecDeque::new(),
            new_peer_streams: VecDeque::new(),
            peer_addr,
            idle_timeout,
            idle_deadline: None,
            keep_alive_interval: None,
            next_keep_alive: None,
            pending_keep_alive_ping: false,
            pending_close: None,
            pending_transport_close: None,
            peer_closed: None,
            sent_packets: [SentPackets::new(), SentPackets::new(), SentPackets::new()],
            rtt: RttEstimator::new(),
            loss: LossDetection::new(),
            loss_timer: None,
            probes_owed: 0,
            peer_max_ack_delay: Duration::ZERO,
            congestion: CongestionController::from_config(congestion_algo),
            // Send-side limits are unknown until the peer's transport params
            // arrive; start at zero and lift them in `refresh_handshake_complete`.
            send_flow: SendFlowControl::new(0),
            recv_flow: RecvFlowControl::new(local_initial_max_data),
            stream_send_flow: std::collections::BTreeMap::new(),
            stream_recv_flow: std::collections::BTreeMap::new(),
            local_initial_max_stream_data,
            pending_max_data: None,
            pending_max_stream_data: std::collections::BTreeMap::new(),
            pending_data_blocked: None,
            pending_stream_data_blocked: std::collections::BTreeMap::new(),
            bytes_sent: 0,
            bytes_recv: 0,
            packets_sent: 0,
            packets_recv: 0,
            packets_lost: 0,
            pending_reset_streams: std::collections::BTreeMap::new(),
            pending_stop_sending: std::collections::BTreeMap::new(),
            retry_token: None,
            cached_initial_hs_bytes: Vec::new(),
            retry_done: false,
            retry_count: 0,
            key_phase: false,
            one_rtt_secrets: None,
            next_1rtt_keys: None,
            prev_1rtt_keys: None,
            secure_random,
            pending_path_response: None,
            pending_path_challenge: None,
            pending_path_challenge_send: false,
            candidate_peer_addr: None,
            path_validated: false,
            key_update_received: false,
            key_update_pending: false,
            key_update_cooldown: None,
            key_update_count: 0,
            // DPLPMTUD: start at 1200, cap at max_mtu from config.
            current_mtu: MIN_INITIAL_DATAGRAM as u16,
            probe_mtu: None,
            probe_count: 0,
            max_mtu: max_mtu.max(MIN_INITIAL_DATAGRAM as u16),
            mtu_discovery_enabled,
            pending_mtu_probe: false,
            next_mtu_probe: None,
            // Stream-concurrency flow control (RFC 9000 §4.6).
            peer_max_streams_bidi: 0,
            peer_max_streams_uni: 0,
            local_max_streams_bidi,
            local_max_streams_uni,
            sent_max_streams_bidi: local_max_streams_bidi,
            sent_max_streams_uni: local_max_streams_uni,
            closed_peer_bidi: 0,
            closed_peer_uni: 0,
            pending_max_streams_bidi: None,
            pending_max_streams_uni: None,
            pending_streams_blocked_bidi: None,
            pending_streams_blocked_uni: None,
            // Unreliable datagrams (RFC 9221).
            peer_max_datagram_frame_size: 0,
            local_max_datagram_frame_size,
            datagram_recv_queue: std::collections::VecDeque::new(),
            datagram_send_queue: std::collections::VecDeque::new(),
            datagram_recv_buffer_limit: datagram_recv_buffer_size,
            // 0-RTT early data (RFC 9001 §4.6).
            zero_rtt_keys: None,
            early_data_buf: Vec::new(),
            zero_rtt_sent: false,
            zero_rtt_accepted: None,
            // Address-validation tokens (RFC 9000 §8.1.3).
            received_token: None,
            pending_new_token: None,
            // Connection ID management.
            local_cid_pool: LocalCidPool::new(
                local_cid_for_pool,
                server_secret_bytes,
                active_cid_limit,
            ),
            peer_cid_pool: PeerCidPool::new(peer_cid_for_pool, active_cid_limit),
            pending_cid_events: VecDeque::new(),
            cids_issued_this_packet: std::collections::HashSet::new(),
        }
    }

    pub(super) fn side(&self) -> Side {
        match self.role {
            Role::Client => Side::Client,
            Role::Server => Side::Server,
        }
    }

    /// Derive and install the Initial-space keys from the original DCID.
    pub(super) fn install_initial_keys(&mut self) {
        let keys = rustls::quic::Keys::initial(
            Version::V1,
            oxiquic_crypto::suites::tls13_aes_128_gcm_sha256_internal(),
            &oxiquic_crypto::quic::AES128_GCM,
            self.initial_dcid.as_bytes(),
            self.side(),
        );
        self.initial.set_keys(keys);
    }

    /// The local connection ID (our SCID).
    #[must_use]
    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Whether this endpoint is the client or the server.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Whether the TLS handshake is still in progress.
    #[must_use]
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_complete
    }

    /// Whether the connection has fully established (handshake complete, not
    /// closing or closed).
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }

    /// Whether the connection has fully closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == ConnectionState::Closed
    }

    /// The current peer address packets are sent to (may change after a
    /// successful path migration).
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// The peer's negotiated transport parameters, once the handshake has
    /// progressed far enough to expose them.
    #[must_use]
    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.peer_params.as_ref()
    }

    /// The error reported if the peer closed the connection.
    #[must_use]
    pub fn peer_close_reason(&self) -> Option<&OxiQuicError> {
        self.peer_closed.as_ref()
    }

    /// Number of Retry packets accepted (client only). Used by tests to confirm
    /// that the Retry round-trip happened.
    #[must_use]
    pub fn retry_count(&self) -> u64 {
        self.retry_count
    }

    /// Drain the next pending CID routing event, if any.
    ///
    /// Called by the endpoint demux layer after processing each datagram to
    /// keep its connection-ID → channel routing table in sync.
    pub fn pop_cid_event(&mut self) -> Option<CidEvent> {
        self.pending_cid_events.pop_front()
    }

    /// The number of active (non-retired) local CIDs issued to the peer.
    /// Primarily for test observability.
    #[must_use]
    pub fn local_cid_pool_active_count(&self) -> usize {
        self.local_cid_pool.active_count()
    }

    /// The number of active (non-retired) peer-issued CIDs we are tracking.
    /// Primarily for test observability.
    #[must_use]
    pub fn peer_cid_pool_active_count(&self) -> usize {
        self.peer_cid_pool.active_count()
    }

    /// Collect all stateless reset tokens stored in this connection's peer CID
    /// pool (RFC 9000 §10.3.1).
    ///
    /// Each token was delivered by the peer in a `NEW_CONNECTION_ID` frame.
    /// The client uses these tokens to detect stateless resets from the server;
    /// this accessor exposes them for integration-test observability.
    #[must_use]
    pub fn peer_stateless_reset_tokens(&self) -> Vec<[u8; 16]> {
        self.peer_cid_pool
            .stateless_reset_tokens()
            .copied()
            .collect()
    }

    /// Returns the ALPN protocol negotiated during the TLS handshake, if any.
    ///
    /// Available once the handshake has completed. For HTTP/3 connections this
    /// should return `Some(b"h3".to_vec())` after a successful handshake with
    /// an HTTP/3 peer.
    #[must_use]
    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.tls.alpn_protocol().map(|p| p.to_vec())
    }

    /// Issue a new connection ID to the peer, generating random CID bytes via
    /// `secure_random`. On success, a [`CidEvent::Register`] is queued.
    ///
    /// Returns without error (and without issuing) if the pool is already at
    /// its limit.
    pub(super) fn maybe_issue_new_cid(&mut self) -> Result<(), OxiQuicError> {
        if !self.local_cid_pool.can_issue() {
            return Ok(());
        }
        let mut raw = [0u8; 8];
        self.secure_random
            .fill(&mut raw)
            .map_err(|_| OxiQuicError::Protocol("secure_random fill failed".to_string()))?;
        let (_seq, new_cid) = self.local_cid_pool.issue_new_cid(raw)?;
        self.pending_cid_events
            .push_back(CidEvent::Register(new_cid));
        Ok(())
    }

    /// Re-key the Initial space after receiving a valid Retry packet (RFC 9001 §5.2).
    ///
    /// * Updates `initial_dcid` to `new_dcid` (the Retry's SCID).
    /// * Derives new Initial keys from `new_dcid`.
    /// * Resets the Initial packet-number space and CRYPTO stream.
    /// * Re-queues the cached ClientHello bytes so they are retransmitted with
    ///   the new keys and the new token in the packet header.
    pub(super) fn rekey_initial_for_retry(&mut self, new_dcid: Vec<u8>, retry_token: Vec<u8>) {
        // Update the ODCID that seeds Initial keys.
        self.initial_dcid = ConnectionId::new(new_dcid);
        // Reset the Initial packet-number space (PN sequence restarts at 0).
        self.initial = crate::space::PacketSpace::new();
        // Re-derive Initial keys from the new ODCID and install them.
        self.install_initial_keys();
        // Reset the Initial CRYPTO stream and re-queue the saved ClientHello bytes
        // so they are retransmitted under the new keys.
        self.initial_crypto = CryptoStream::new();
        let cached = self.cached_initial_hs_bytes.clone();
        self.initial_crypto.enqueue_send(&cached);
        // Store the token for inclusion in future Initial packets (BuildLong.token).
        self.retry_token = Some(retry_token);
        self.retry_count += 1;
    }

    // ─── Handshake driving ──────────────────────────────────────────────────

    /// Pump rustls `write_hs`, queueing produced handshake bytes onto the
    /// CRYPTO stream for the appropriate level and installing key changes.
    pub(super) fn pump_write_hs(&mut self) {
        loop {
            let mut buf = Vec::new();
            let key_change = self.tls.write_hs(&mut buf);
            if !buf.is_empty() {
                match self.write_level {
                    HandshakeLevel::Initial => {
                        // Cache the bytes so we can re-queue them after a Retry
                        // re-keys the Initial space (RFC 9001 §5.2).
                        if self.role == Role::Client {
                            self.cached_initial_hs_bytes.extend_from_slice(&buf);
                        }
                        self.initial_crypto.enqueue_send(&buf);
                        // After ClientHello is buffered, attempt to derive 0-RTT keys.
                        // Only attempt when keys have not yet been installed to avoid
                        // redundant derivation calls after the first successful install.
                        if self.role == Role::Client && self.zero_rtt_keys.is_none() {
                            self.try_install_zero_rtt_keys();
                        }
                    }
                    HandshakeLevel::Handshake => self.handshake_crypto.enqueue_send(&buf),
                }
            }
            match key_change {
                Some(KeyChange::Handshake { keys }) => {
                    self.handshake.set_keys(keys);
                    self.handshake_keys_ready = true;
                    // Subsequent handshake bytes belong to the Handshake level.
                    self.write_level = HandshakeLevel::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    // Derive the next epoch's packet keys now so we can decrypt
                    // a peer-initiated key update immediately (RFC 9001 §6).
                    // Header protection keys never change during key updates.
                    let mut secrets = next;
                    let next_keys = secrets.next_packet_keys();
                    self.one_rtt_secrets = Some(secrets);
                    self.next_1rtt_keys = Some(next_keys);
                    self.application.set_keys(keys);
                    self.one_rtt_ready = true;
                    // Server: install 0-RTT keys once 1-RTT keys arrive so we
                    // can decrypt any coalesced 0-RTT in the same ClientHello datagram.
                    // Only attempt when not already installed.
                    if self.role == Role::Server && self.zero_rtt_keys.is_none() {
                        self.try_install_zero_rtt_keys();
                    }
                }
                None => break,
            }
        }
        self.refresh_handshake_complete();
    }

    /// Attempt to install 0-RTT keys from the TLS connection.
    ///
    /// Called after writing Initial handshake bytes; returns `Some` only
    /// when a resumption ticket is cached and the server allowed early data
    /// (RFC 9001 §4.6).
    pub(super) fn try_install_zero_rtt_keys(&mut self) {
        if self.zero_rtt_keys.is_none() {
            self.zero_rtt_keys = self.tls.zero_rtt_keys();
        }
    }

    /// Whether the server accepted 0-RTT early data.
    ///
    /// - `None`: handshake not yet complete or no 0-RTT was attempted.
    /// - `Some(true)`: server accepted the early data.
    /// - `Some(false)`: server rejected the early data (data was re-sent via 1-RTT).
    #[must_use]
    pub fn zero_rtt_accepted(&self) -> Option<bool> {
        self.zero_rtt_accepted
    }

    pub(super) fn refresh_handshake_complete(&mut self) {
        if !self.handshake_complete && !self.tls.is_handshaking() {
            self.handshake_complete = true;
            let now = Instant::now();
            if self.state == ConnectionState::Handshaking {
                self.state = ConnectionState::Established;
                // Arm the first MTU probe timer now that we are established.
                self.schedule_initial_mtu_probe(now);
                // Issue additional CIDs to give the peer a pool for migration
                // (RFC 9000 §5.1.1: supply active_connection_id_limit - 1
                // additional CIDs beyond the initial seq 0).
                let limit = self.local_cid_pool.limit;
                for _ in 1..limit {
                    // Errors (e.g. secure_random failure or limit reached) are
                    // best-effort: if we cannot issue more CIDs, we stop.
                    if let Err(_e) = self.maybe_issue_new_cid() {
                        break;
                    }
                }
            }
            // Capture the peer's transport parameters.
            if self.peer_params.is_none() {
                if let Some(raw) = self.tls.quic_transport_parameters() {
                    if let Ok(p) = decode_transport_params(raw) {
                        self.apply_peer_params(&p);
                        self.peer_params = Some(p);
                    }
                }
            }
            // Determine 0-RTT acceptance for the client (RFC 9001 §4.6).
            // Only set this if we actually attempted 0-RTT (had early keys or
            // early data buffered). A plain connection without `enable_early_data`
            // leaves `zero_rtt_accepted` as `None`.
            if self.role == Role::Client && self.zero_rtt_accepted.is_none() {
                let attempted_zero_rtt = self.zero_rtt_sent
                    || !self.early_data_buf.is_empty()
                    || self.zero_rtt_keys.is_some();
                if attempted_zero_rtt {
                    if let TlsConnection::Client(ref c) = self.tls {
                        let accepted = c.is_early_data_accepted();
                        self.zero_rtt_accepted = Some(accepted);
                        // On rejection, re-queue early_data_buf through 1-RTT streams.
                        if !accepted && !self.early_data_buf.is_empty() {
                            let buf = std::mem::take(&mut self.early_data_buf);
                            for (stream_id, data, fin) in buf {
                                // Create the stream entry if it doesn't exist yet.
                                let sid = stream_id.as_u64();
                                self.send_streams.entry(sid).or_default();
                                if let Some(s) = self.send_streams.get_mut(&sid) {
                                    s.write(&data, fin);
                                }
                            }
                        } else {
                            // Accepted or no data: clear the buffer.
                            self.early_data_buf.clear();
                        }
                    }
                }
            }
            // Server: schedule a NEW_TOKEN frame for the client (RFC 9000 §8.1.3).
            // Generate a simple pseudo-random token from the connection ID bytes.
            if self.role == Role::Server && self.pending_new_token.is_none() {
                let mut token = Vec::with_capacity(16);
                // XOR connection ID bytes together in pairs for a simple 16-byte value.
                let cid_bytes = self.local_cid.as_bytes();
                for i in 0..16 {
                    let b = cid_bytes.get(i).copied().unwrap_or(0)
                        ^ cid_bytes.get(i.wrapping_add(4)).copied().unwrap_or(0)
                        ^ (i as u8).wrapping_mul(0x9e);
                    token.push(b);
                }
                self.pending_new_token = Some(token);
            }
        }
    }

    /// Adopt the peer's flow-control and ACK-delay parameters once the handshake
    /// exposes them (RFC 9000 Section 4.1, RFC 9002 Section 6.2.1).
    pub(super) fn apply_peer_params(&mut self, params: &TransportParams) {
        // The peer's `initial_max_data` is our connection-level send limit.
        self.send_flow.on_max_data(params.initial_max_data);
        // The peer's `max_ack_delay` enters the PTO once the handshake is
        // confirmed (which, for our purposes, is when 1-RTT is established).
        self.peer_max_ack_delay = Duration::from_millis(params.max_ack_delay_ms);
        // Lift the per-stream send limits we have already opened to the peer's
        // bidi-remote initial limit (streams we open are "bidi-remote" to peer).
        let initial = params.initial_max_stream_data_bidi_remote;
        for flow in self.stream_send_flow.values_mut() {
            flow.on_max_stream_data(initial);
        }
        // Stream concurrency: how many streams the peer lets us open.
        self.peer_max_streams_bidi = params.initial_max_streams_bidi;
        self.peer_max_streams_uni = params.initial_max_streams_uni;
        // Datagram extension: peer's max frame size (0 = disabled).
        self.peer_max_datagram_frame_size = params.max_datagram_frame_size;
    }

    /// The peer's per-stream send limit for a stream this endpoint opens.
    pub(super) fn peer_initial_stream_limit(&self) -> u64 {
        self.peer_params
            .as_ref()
            .map(|p| p.initial_max_stream_data_bidi_remote)
            .unwrap_or(0)
    }

    // ─── Timers ─────────────────────────────────────────────────────────────

    pub(super) fn arm_idle_timer(&mut self, now: Instant) {
        if let Some(timeout) = self.idle_timeout {
            self.idle_deadline = Some(now + timeout);
        }
        self.arm_keep_alive(now);
    }

    /// (Re)arm the keep-alive timer from `now` if a keep-alive interval is set.
    fn arm_keep_alive(&mut self, now: Instant) {
        if let Some(interval) = self.keep_alive_interval {
            self.next_keep_alive = Some(now + interval);
        }
    }

    /// Configure the keep-alive interval at runtime. Pass `None` to disable.
    /// The timer will be armed on the next activity that triggers `arm_idle_timer`.
    pub fn set_keep_alive_interval(&mut self, interval: Option<Duration>) {
        self.keep_alive_interval = interval;
    }

    /// The next instant at which [`Connection::handle_timeout`] should be
    /// invoked, if any: the earliest of the idle timeout, the loss-detection
    /// (PTO / time-threshold) timer, the keep-alive timer, and the MTU probe
    /// timer (RFC 9000 Section 10.1, RFC 9002 Section 6, RFC 8899).
    #[must_use]
    pub fn next_timeout(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        for t in [
            self.idle_deadline,
            self.loss_timer,
            self.next_keep_alive,
            self.next_mtu_probe,
        ]
        .into_iter()
        .flatten()
        {
            earliest = Some(match earliest {
                Some(e) => e.min(t),
                None => t,
            });
        }
        earliest
    }

    /// Process timer expiry at `now`: fire the idle timer (closing the
    /// connection), the keep-alive timer (queuing a PING), and/or the
    /// loss-detection timer (declaring losses or arming PTO probes).
    pub fn handle_timeout(&mut self, now: Instant) {
        if let Some(deadline) = self.idle_deadline {
            if now >= deadline {
                self.state = ConnectionState::Closed;
                self.peer_closed.get_or_insert(OxiQuicError::IdleTimeout);
                return;
            }
        }
        // Keep-alive timer: queue a PING and re-arm for the next interval.
        if let Some(ka) = self.next_keep_alive {
            if now >= ka {
                self.pending_keep_alive_ping = true;
                if let Some(interval) = self.keep_alive_interval {
                    self.next_keep_alive = Some(now + interval);
                }
            }
        }
        if let Some(deadline) = self.loss_timer {
            if now >= deadline {
                self.on_loss_timeout(now);
            }
        }
        // MTU probe timer: schedule a new probe if discovery is enabled and the
        // connection is established (never probe during handshake).
        if let Some(probe_time) = self.next_mtu_probe {
            if now >= probe_time && self.state == ConnectionState::Established {
                self.schedule_mtu_probe();
            }
        }
    }

    /// A snapshot of connection statistics (RFC 9002): RTT estimates, byte and
    /// packet counters, loss count and the current congestion window.
    #[must_use]
    pub fn stats(&self) -> oxiquic_core::ConnectionStats {
        oxiquic_core::ConnectionStats {
            rtt: self.rtt.latest_rtt(),
            min_rtt: self.rtt.min_rtt(),
            smoothed_rtt: self.rtt.smoothed_rtt(),
            rtt_variance: self.rtt.rttvar(),
            bytes_sent: self.bytes_sent,
            bytes_recv: self.bytes_recv,
            packets_sent: self.packets_sent,
            packets_recv: self.packets_recv,
            packets_lost: self.packets_lost,
            congestion_window: self.congestion.congestion_window(),
            streams_opened: self.next_bidi_index,
            streams_closed: 0,
        }
    }

    /// The current congestion window in bytes (RFC 9002 Section 7).
    #[must_use]
    pub fn congestion_window(&self) -> u64 {
        self.congestion.congestion_window()
    }

    /// Diagnostic snapshot of every flag that contributes to
    /// `space_has_output(Application)` plus per-space sent-packet counts.
    ///
    /// Returned as a single-line, greppable string for embedding in panic
    /// messages when the in-process test harness detects a `poll_transmit`
    /// drain that fails to terminate (regression guard for the spin pathology
    /// previously hit on `build_ack`; see the doc comment on
    /// `PacketSpace::build_ack`).
    #[must_use]
    pub fn spin_debug_snapshot(&self) -> String {
        // `any_stream_send_data` on the send-path module is private; replicate
        // its predicate inline so we can also surface the count.
        let stream_send_count = self
            .send_streams
            .values()
            .filter(|s| s.has_pending())
            .count();
        let handshake_done_to_send =
            self.role == Role::Server && self.handshake_complete && !self.handshake_done;
        format!(
            "role={:?} state={:?} \
             app.ack_pending={} handshake_done_to_send={} \
             stream_send_count={} probes_owed={} pending_keep_alive_ping={} \
             pending_mtu_probe={} probe_mtu={:?} \
             pending_max_data={} pending_max_stream_data.len={} \
             pending_data_blocked={} pending_stream_data_blocked.len={} \
             pending_reset_streams.len={} pending_stop_sending.len={} \
             key_update_pending={} pending_path_response={} pending_path_challenge_send={} \
             bytes_in_flight={} congestion_window={} \
             sent_packets=[initial={}, handshake={}, application={}]",
            self.role,
            self.state,
            self.application.ack_pending(),
            handshake_done_to_send,
            stream_send_count,
            self.probes_owed,
            self.pending_keep_alive_ping,
            self.pending_mtu_probe,
            self.probe_mtu,
            self.pending_max_data.is_some(),
            self.pending_max_stream_data.len(),
            self.pending_data_blocked.is_some(),
            self.pending_stream_data_blocked.len(),
            self.pending_reset_streams.len(),
            self.pending_stop_sending.len(),
            self.key_update_pending,
            self.pending_path_response.is_some(),
            self.pending_path_challenge_send,
            self.bytes_in_flight(),
            self.congestion_window(),
            self.sent_packets[0].outstanding(),
            self.sent_packets[1].outstanding(),
            self.sent_packets[2].outstanding(),
        )
    }

    /// The MTU currently confirmed by a successful probe (or the initial 1200
    /// bytes at startup). This is the maximum payload size for outgoing packets.
    #[must_use]
    pub fn current_mtu(&self) -> u16 {
        self.current_mtu
    }

    /// The MTU size of the probe currently in-flight (awaiting ACK or loss
    /// declaration). `None` when no probe is pending.
    #[must_use]
    pub fn probe_mtu(&self) -> Option<u16> {
        self.probe_mtu
    }

    // ─── DPLPMTUD helpers (RFC 8899) ────────────────────────────────────────

    /// Compute the next probe size: binary-search midpoint between
    /// `current_mtu` and `max_mtu`. Returns `None` if already at ceiling.
    pub(super) fn next_probe_size(&self) -> Option<u16> {
        let lo = self.current_mtu;
        let hi = self.max_mtu;
        if lo >= hi {
            return None;
        }
        // Binary search: probe the midpoint, rounded to even bytes.
        let mid = lo + (hi - lo) / 2;
        if mid <= lo {
            None
        } else {
            Some(mid)
        }
    }

    /// Schedule a fresh MTU probe. Called from `handle_timeout` when the probe
    /// timer fires, and also from `on_mtu_probe_acked` to schedule the next step.
    pub(super) fn schedule_mtu_probe(&mut self) {
        // Only probe when connected, discovery enabled, and not already
        // probing or at the ceiling.
        if !self.mtu_discovery_enabled
            || self.state != ConnectionState::Established
            || self.probe_mtu.is_some()
        {
            self.next_mtu_probe = None;
            return;
        }
        if let Some(size) = self.next_probe_size() {
            self.probe_mtu = Some(size);
            self.probe_count = 0;
            self.pending_mtu_probe = true;
        }
        // Whether or not a probe was actually scheduled, clear the timer so we
        // don't re-fire continuously.
        self.next_mtu_probe = None;
    }

    /// Called when a probe for `size` bytes was acknowledged: raise
    /// `current_mtu`, clear probe state, and schedule the next step.
    pub fn on_mtu_probe_acked(&mut self, size: u16, now: Instant) {
        // Raise the confirmed MTU.
        if size > self.current_mtu {
            self.current_mtu = size;
        }
        self.probe_mtu = None;
        self.probe_count = 0;
        self.pending_mtu_probe = false;
        // Schedule next probe after a short inter-probe delay so we don't flood.
        // RFC 8899 §5.3.2: a minimum delay between probes is recommended.
        let next_step = self.next_probe_size();
        if next_step.is_some() {
            // 100 ms between successful probe steps.
            self.next_mtu_probe = Some(now + std::time::Duration::from_millis(100));
        }
    }

    /// Called when a probe for `size` bytes was declared lost: retry once (up
    /// to `MAX_PROBE_RETRIES`), then give up and stop probing (the path cannot
    /// carry this MTU). `current_mtu` is not changed on loss.
    pub fn on_mtu_probe_lost(&mut self, _size: u16) {
        const MAX_PROBE_RETRIES: u8 = 2;
        self.probe_count = self.probe_count.saturating_add(1);
        if self.probe_count < MAX_PROBE_RETRIES {
            // Retry the same probe size.
            self.pending_mtu_probe = true;
        } else {
            // Give up: this probe size is unreachable; stop discovery.
            self.probe_mtu = None;
            self.probe_count = 0;
            self.pending_mtu_probe = false; // must clear so app_space_may_send() is not permanently stuck
            self.mtu_discovery_enabled = false;
        }
    }

    /// Schedule the first MTU probe after handshake completion. Called from
    /// `refresh_handshake_complete` once the connection transitions to
    /// `Established`.
    pub(super) fn schedule_initial_mtu_probe(&mut self, now: Instant) {
        if self.mtu_discovery_enabled && self.max_mtu > self.current_mtu {
            // Wait 200 ms after handshake before first probe to let the
            // connection stabilise and avoid perturbing handshake tests.
            self.next_mtu_probe = Some(now + std::time::Duration::from_millis(200));
        }
    }

    /// The bytes currently in flight (ack-eliciting, unacknowledged).
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.congestion.bytes_in_flight()
    }

    /// Whether any send stream still has buffered data or an unsent FIN.
    ///
    /// Used together with [`bytes_in_flight`] to determine whether a connection
    /// can be dropped safely: when both return `false`/`0`, all stream data has
    /// been emitted and its ACK has been processed by the congestion controller,
    /// so the remote endpoint has durably received everything.
    ///
    /// [`bytes_in_flight`]: Self::bytes_in_flight
    #[must_use]
    pub fn has_pending_stream_data(&self) -> bool {
        self.send_streams.values().any(|s| s.has_pending())
    }

    // ─── Close API ──────────────────────────────────────────────────────────

    /// Queue a graceful application-level close with the given code and reason.
    pub fn close(&mut self, error_code: u64, reason: &[u8]) {
        if self.state == ConnectionState::Closed {
            return;
        }
        self.pending_close = Some((error_code, reason.to_vec()));
        self.state = ConnectionState::Closing;
    }

    // ─── Datagram API (RFC 9221) ─────────────────────────────────────────────

    /// Queue an unreliable DATAGRAM frame for transmission (RFC 9221).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the peer does not support
    /// datagrams or if `data` exceeds the peer's advertised limit.
    pub fn send_datagram(&mut self, data: Vec<u8>) -> Result<(), OxiQuicError> {
        if self.peer_max_datagram_frame_size == 0 {
            return Err(OxiQuicError::Connection(
                "peer does not support datagrams".into(),
            ));
        }
        if data.len() as u64 > self.peer_max_datagram_frame_size {
            return Err(OxiQuicError::Connection(format!(
                "datagram {} bytes exceeds peer max {}",
                data.len(),
                self.peer_max_datagram_frame_size
            )));
        }
        self.datagram_send_queue.push_back(data);
        Ok(())
    }

    /// Return the next received DATAGRAM, or `None` if none are queued.
    pub fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        self.datagram_recv_queue.pop_front()
    }

    /// The maximum DATAGRAM payload the peer will accept, or `None` if the
    /// peer does not support unreliable datagrams.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        if self.peer_max_datagram_frame_size == 0 {
            None
        } else {
            Some(self.peer_max_datagram_frame_size as usize)
        }
    }

    // ─── Address-validation token API (RFC 9000 §8.1.3) ─────────────────────

    /// Take the address-validation token received from the server via NEW_TOKEN,
    /// if any (client only; RFC 9000 §8.1.3).
    pub fn take_received_token(&mut self) -> Option<Vec<u8>> {
        self.received_token.take()
    }

    // ─── 0-RTT early data API (RFC 9001 §4.6) ───────────────────────────────

    /// Queue `data` on `stream` as 0-RTT early data (client only, RFC 9001 §4.6).
    ///
    /// If 0-RTT keys are available (resuming with a cached ticket and the server
    /// allowed early data), the data will be emitted in a 0-RTT long-header packet
    /// coalesced with the Initial.  On rejection, the data is replayed in 1-RTT.
    ///
    /// If called after the handshake completes, queues via the normal stream path.
    pub fn queue_early_data(&mut self, stream: oxiquic_core::StreamId, data: &[u8], fin: bool) {
        if self.handshake_complete {
            // Fall through to normal 1-RTT stream.
            let sid = stream.as_u64();
            self.send_streams.entry(sid).or_default();
            if let Some(s) = self.send_streams.get_mut(&sid) {
                s.write(data, fin);
            }
        } else {
            // Buffer for 0-RTT (or later 1-RTT replay on rejection).
            self.early_data_buf.push((stream, data.to_vec(), fin));
        }
    }
}

/// Internal discriminator for the three spaces (mirrors [`crate::space::SpaceId`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpaceKind {
    Initial,
    Handshake,
    Application,
}

/// Generate a fresh random connection ID from the provider's secure RNG. If the
/// RNG fails (it must not for a correct provider), a zero-length CID is used,
/// which is still valid per RFC 9000.
pub(super) fn random_cid(rng: &dyn rustls::crypto::SecureRandom) -> ConnectionId {
    let mut bytes = [0u8; LOCAL_CID_LEN];
    match rng.fill(&mut bytes) {
        Ok(()) => ConnectionId::new(bytes.to_vec()),
        Err(_) => ConnectionId::new(Vec::new()),
    }
}
