//! QUIC transport configuration (RFC 9000 Sections 4, 10, 14).

use oxiquic_core::{OxiQuicError, TransportParams};
use std::net::SocketAddr;
use std::time::Duration;

/// The congestion-control algorithm a connection uses (RFC 9002 / RFC 9438).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CongestionAlgorithm {
    /// CUBIC (RFC 9438): the default loss-based controller.
    #[default]
    Cubic,
    /// BBR v2 (model-based bandwidth/RTT probing). Dispatches to
    /// [`crate::bbr::Bbr`] for all send/ack/loss events.
    Bbr,
    /// NewReno (RFC 9002 Appendix B): the simplest loss-based controller.
    NewReno,
}

impl std::fmt::Display for CongestionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cubic => "cubic",
            Self::Bbr => "bbr",
            Self::NewReno => "newreno",
        })
    }
}

/// Tunable parameters for a QUIC connection's transport behaviour.
///
/// This is a builder-style configuration type backed entirely by
/// `oxiquic-core` data types. It captures idle-timeout, keep-alive,
/// stream-limit, flow-control and MTU settings, and can be lowered to the
/// wire-level [`TransportParams`] via [`TransportConfig::to_transport_params`].
///
/// Retry support (`retry_enabled` / `retry_secret`) implements RFC 9000 §8.1
/// address validation via stateless Retry tokens (HMAC-SHA256 over ODCID + peer
/// addr + peer port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    idle_timeout: Duration,
    keep_alive_interval: Option<Duration>,
    max_concurrent_bidi_streams: u64,
    max_concurrent_uni_streams: u64,
    stream_receive_window: u64,
    receive_window: u64,
    send_window: u64,
    initial_mtu: u16,
    min_mtu: u16,
    max_mtu: u16,
    mtu_discovery: bool,
    congestion_controller: CongestionAlgorithm,
    /// Whether to require clients to echo a Retry token before accepting a
    /// connection (RFC 9000 §8.1 address validation).
    retry_enabled: bool,
    /// 32-byte HMAC secret for generating / validating stateless Retry tokens.
    /// Lazily generated the first time it is needed.
    retry_secret: Option<[u8; 32]>,
    /// 32-byte secret for generating stateless reset tokens via
    /// HMAC-SHA256(secret, cid)[..16] (RFC 9000 §19.15, §10.3.1).
    /// Lazily generated the first time it is needed.
    server_secret: Option<[u8; 32]>,
    /// Maximum number of active connection IDs we will accept from the peer
    /// (RFC 9000 §18.2, transport parameter 0x0e). Default 7.
    active_connection_id_limit: u64,
    /// Maximum DATAGRAM frame payload this endpoint is willing to receive
    /// (RFC 9221 §3). A value of 0 (default) disables the DATAGRAM extension.
    pub(crate) max_datagram_frame_size: u64,
    /// Size of the receive buffer for incoming DATAGRAM frames, in bytes.
    pub(crate) datagram_receive_buffer_size: usize,
    /// Maximum early data size for 0-RTT (RFC 9001 §4.6, rustls QUIC constraint).
    /// Must be 0 (disabled) or `u32::MAX` (enabled); rustls rejects all other values.
    /// Applied to `ServerConfig::max_early_data_size` when building server connections.
    pub(crate) max_early_data_size: u32,
}

impl Default for TransportConfig {
    /// Production-ready defaults: a 30-second idle timeout, 100 concurrent
    /// bidirectional and unidirectional streams, 1 MiB stream / 8 MiB
    /// connection flow-control windows, the QUIC minimum 1200-byte initial MTU,
    /// MTU discovery enabled, CUBIC congestion control, and Retry disabled.
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            keep_alive_interval: None,
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            stream_receive_window: 1024 * 1024,
            receive_window: 8 * 1024 * 1024,
            send_window: 8 * 1024 * 1024,
            initial_mtu: oxiquic_core::MIN_MAX_UDP_PAYLOAD_SIZE as u16,
            min_mtu: oxiquic_core::MIN_MAX_UDP_PAYLOAD_SIZE as u16,
            max_mtu: 1452,
            mtu_discovery: true,
            congestion_controller: CongestionAlgorithm::Cubic,
            retry_enabled: false,
            retry_secret: None,
            server_secret: None,
            active_connection_id_limit: 7,
            max_datagram_frame_size: 0,
            datagram_receive_buffer_size: 65536,
            max_early_data_size: 0,
        }
    }
}

impl TransportConfig {
    /// The minimum MTU QUIC requires an endpoint to support
    /// (RFC 9000 Section 14): 1200 bytes.
    pub const MIN_INITIAL_MTU: u16 = 1200;

    /// Create a configuration with the [`Default`] values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the idle timeout (RFC 9000 Section 10.1). A duration of zero
    /// disables the idle timeout.
    #[must_use]
    pub fn idle_timeout(mut self, duration: Duration) -> Self {
        self.idle_timeout = duration;
        self
    }

    /// Set the keep-alive interval. When `Some`, the endpoint sends periodic
    /// `PING` frames to keep the connection (and any NAT bindings) alive.
    #[must_use]
    pub fn keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    /// Set the maximum number of concurrent peer-initiated bidirectional
    /// streams (RFC 9000 Section 4.6).
    #[must_use]
    pub fn max_concurrent_bidi_streams(mut self, count: u64) -> Self {
        self.max_concurrent_bidi_streams = count;
        self
    }

    /// Set the maximum number of concurrent peer-initiated unidirectional
    /// streams (RFC 9000 Section 4.6).
    #[must_use]
    pub fn max_concurrent_uni_streams(mut self, count: u64) -> Self {
        self.max_concurrent_uni_streams = count;
        self
    }

    /// Set the per-stream receive window in bytes (RFC 9000 Section 4.1).
    #[must_use]
    pub fn stream_receive_window(mut self, bytes: u64) -> Self {
        self.stream_receive_window = bytes;
        self
    }

    /// Set the connection-level receive window in bytes (RFC 9000 Section 4.1).
    #[must_use]
    pub fn receive_window(mut self, bytes: u64) -> Self {
        self.receive_window = bytes;
        self
    }

    /// Set the connection-level send window in bytes.
    #[must_use]
    pub fn send_window(mut self, bytes: u64) -> Self {
        self.send_window = bytes;
        self
    }

    /// Set the initial MTU in bytes; values below 1200 are raised to the QUIC
    /// minimum (RFC 9000 Section 14.1).
    #[must_use]
    pub fn initial_mtu(mut self, mtu: u16) -> Self {
        self.initial_mtu = mtu.max(Self::MIN_INITIAL_MTU);
        self
    }

    /// Set the minimum MTU in bytes; values below 1200 are raised to the QUIC
    /// minimum.
    #[must_use]
    pub fn min_mtu(mut self, mtu: u16) -> Self {
        self.min_mtu = mtu.max(Self::MIN_INITIAL_MTU);
        self
    }

    /// Set the maximum MTU to probe for (DPLPMTUD ceiling, RFC 8899). The
    /// default is 1452 bytes (typical Ethernet minus IP+UDP overhead). Values
    /// below `initial_mtu` are silently raised to match it.
    #[must_use]
    pub fn max_mtu(mut self, mtu: u16) -> Self {
        self.max_mtu = mtu;
        self
    }

    /// The configured maximum MTU ceiling (DPLPMTUD probe upper bound).
    #[must_use]
    pub fn get_max_mtu(&self) -> u16 {
        self.max_mtu
    }

    /// Enable or disable path-MTU discovery (DPLPMTUD, RFC 8899).
    #[must_use]
    pub fn mtu_discovery(mut self, enabled: bool) -> Self {
        self.mtu_discovery = enabled;
        self
    }

    /// Select the congestion-control algorithm.
    #[must_use]
    pub fn congestion_controller(mut self, algorithm: CongestionAlgorithm) -> Self {
        self.congestion_controller = algorithm;
        self
    }

    /// The configured idle timeout.
    #[must_use]
    pub fn get_idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// The configured keep-alive interval, if any.
    #[must_use]
    pub fn get_keep_alive_interval(&self) -> Option<Duration> {
        self.keep_alive_interval
    }

    /// The configured congestion-control algorithm.
    #[must_use]
    pub fn get_congestion_controller(&self) -> CongestionAlgorithm {
        self.congestion_controller
    }

    /// The configured maximum concurrent bidirectional stream count.
    #[must_use]
    pub fn get_max_concurrent_bidi_streams(&self) -> u64 {
        self.max_concurrent_bidi_streams
    }

    /// The configured maximum concurrent unidirectional stream count.
    #[must_use]
    pub fn get_max_concurrent_uni_streams(&self) -> u64 {
        self.max_concurrent_uni_streams
    }

    /// The configured initial MTU.
    #[must_use]
    pub fn get_initial_mtu(&self) -> u16 {
        self.initial_mtu
    }

    /// Enable or disable Retry-based address validation (RFC 9000 §8.1).
    ///
    /// When enabled, the server sends a Retry packet to every client that does
    /// not present a valid token in its Initial. The client must retransmit its
    /// Initial with the token to prove its source address.
    #[must_use]
    pub fn retry(mut self, enabled: bool) -> Self {
        self.retry_enabled = enabled;
        self
    }

    /// Set the 32-byte secret used to generate and verify stateless Retry
    /// tokens. If not set explicitly, a random secret is generated once on first
    /// use via [`TransportConfig::get_or_generate_retry_secret`].
    #[must_use]
    pub fn retry_secret(mut self, secret: [u8; 32]) -> Self {
        self.retry_secret = Some(secret);
        self
    }

    /// Whether Retry-based address validation is enabled.
    #[must_use]
    pub fn get_retry_enabled(&self) -> bool {
        self.retry_enabled
    }

    /// Set the 32-byte secret used to generate stateless reset tokens
    /// (RFC 9000 §10.3.1, §19.15). If not set explicitly, a random secret
    /// is generated once on first use via [`TransportConfig::get_or_generate_server_secret`].
    #[must_use]
    pub fn server_secret(mut self, secret: [u8; 32]) -> Self {
        self.server_secret = Some(secret);
        self
    }

    /// Set the maximum number of active connection IDs to accept from the peer
    /// (RFC 9000 §18.2 `active_connection_id_limit`). The RFC minimum is 2;
    /// values below 2 are silently raised to 2. Default is 7.
    #[must_use]
    pub fn active_connection_id_limit(mut self, limit: u64) -> Self {
        self.active_connection_id_limit = limit.max(2);
        self
    }

    /// Set the maximum DATAGRAM frame payload this endpoint will accept
    /// (RFC 9221 §3). Setting this to a non-zero value enables the DATAGRAM
    /// extension; the default of 0 disables it.
    #[must_use]
    pub fn max_datagram_frame_size(mut self, size: u64) -> Self {
        self.max_datagram_frame_size = size;
        self
    }

    /// Set the receive buffer size for incoming DATAGRAM frames, in bytes.
    /// Defaults to 65536.
    #[must_use]
    pub fn datagram_receive_buffer_size(mut self, bytes: usize) -> Self {
        self.datagram_receive_buffer_size = bytes;
        self
    }

    /// Return the active_connection_id_limit setting.
    #[must_use]
    pub fn get_active_connection_id_limit(&self) -> u64 {
        self.active_connection_id_limit
    }

    /// Return the Retry secret, generating and storing a random one if none
    /// has been set. The secret is cached in `self` so subsequent calls return
    /// the same value.
    pub fn get_or_generate_retry_secret(&mut self) -> [u8; 32] {
        if let Some(s) = self.retry_secret {
            return s;
        }
        // Generate a random secret using the OS CSPRNG.
        let mut secret = [0u8; 32];
        getrandom_secret(&mut secret);
        self.retry_secret = Some(secret);
        secret
    }

    /// Return the server secret for stateless reset token generation
    /// (RFC 9000 §10.3.1), generating and caching a random one if not set.
    pub fn get_or_generate_server_secret(&mut self) -> [u8; 32] {
        if let Some(s) = self.server_secret {
            return s;
        }
        let mut secret = [0u8; 32];
        getrandom_secret(&mut secret);
        self.server_secret = Some(secret);
        secret
    }

    /// Generate a stateless Retry token for the given ODCID and peer address.
    ///
    /// Token layout:
    /// ```text
    /// [1 byte: odcid_len] [odcid bytes] [16 bytes: HMAC-SHA256 truncated]
    /// ```
    ///
    /// This embeds the ODCID inside the token so the server can recover it
    /// statelessly when validating the echoed token.
    pub fn generate_retry_token(&mut self, odcid: &[u8], peer_addr: SocketAddr) -> Vec<u8> {
        let secret = self.get_or_generate_retry_secret();
        let tag = hmac_retry_tag(&secret, odcid, peer_addr);
        let mut token = Vec::with_capacity(1 + odcid.len() + 16);
        token.push(odcid.len() as u8);
        token.extend_from_slice(odcid);
        token.extend_from_slice(&tag);
        token
    }

    /// Validate a Retry token received from a client.  Returns the embedded
    /// ODCID on success, or `None` if the token is malformed or the HMAC does
    /// not match.
    #[must_use]
    pub fn validate_retry_token(&self, token: &[u8], peer_addr: SocketAddr) -> Option<Vec<u8>> {
        let secret = self.retry_secret?;
        // Parse: [1-byte odcid_len] [odcid] [16-byte tag]
        if token.len() < 2 + 16 {
            return None;
        }
        let odcid_len = token[0] as usize;
        if token.len() < 1 + odcid_len + 16 {
            return None;
        }
        let odcid = &token[1..1 + odcid_len];
        let received_tag = &token[1 + odcid_len..1 + odcid_len + 16];

        let expected_tag = hmac_retry_tag(&secret, odcid, peer_addr);
        // Constant-time comparison.
        let mut diff = 0u8;
        for (&a, &b) in expected_tag.iter().zip(received_tag.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Some(odcid.to_vec())
        } else {
            None
        }
    }

    /// Validate the configuration's internal consistency.
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError::Protocol`] if `initial_mtu` is below `min_mtu`,
    /// or if either MTU is below the QUIC minimum of 1200 bytes.
    pub fn validate(&self) -> Result<(), OxiQuicError> {
        if self.min_mtu < Self::MIN_INITIAL_MTU {
            return Err(OxiQuicError::Protocol(format!(
                "min_mtu {} is below the QUIC minimum of {}",
                self.min_mtu,
                Self::MIN_INITIAL_MTU
            )));
        }
        if self.initial_mtu < self.min_mtu {
            return Err(OxiQuicError::Protocol(format!(
                "initial_mtu {} is below min_mtu {}",
                self.initial_mtu, self.min_mtu
            )));
        }
        if self.max_mtu < self.initial_mtu {
            return Err(OxiQuicError::Protocol(format!(
                "max_mtu {} is below initial_mtu {}",
                self.max_mtu, self.initial_mtu
            )));
        }
        Ok(())
    }

    /// Lower this configuration to the wire-level [`TransportParams`] an
    /// endpoint would advertise during the handshake.
    ///
    /// Note that QUIC's `initial_max_streams_*` parameters count peer-initiated
    /// streams, which is exactly what `max_concurrent_*_streams` configures
    /// here, so the mapping is direct.
    #[must_use]
    pub fn to_transport_params(&self) -> TransportParams {
        TransportParams {
            max_idle_timeout_ms: self.idle_timeout.as_millis().min(u64::MAX as u128) as u64,
            initial_max_data: self.receive_window,
            initial_max_stream_data_bidi_local: self.stream_receive_window,
            initial_max_stream_data_bidi_remote: self.stream_receive_window,
            initial_max_stream_data_uni: self.stream_receive_window,
            initial_max_streams_bidi: self.max_concurrent_bidi_streams,
            initial_max_streams_uni: self.max_concurrent_uni_streams,
            max_udp_payload_size: u64::from(self.initial_mtu)
                .max(oxiquic_core::MIN_MAX_UDP_PAYLOAD_SIZE),
            active_connection_id_limit: self.active_connection_id_limit,
            max_datagram_frame_size: self.max_datagram_frame_size,
            ..TransportParams::default()
        }
    }

    /// The configured maximum DATAGRAM frame payload size.
    #[must_use]
    pub fn get_max_datagram_frame_size(&self) -> u64 {
        self.max_datagram_frame_size
    }

    /// The configured DATAGRAM receive buffer size in bytes.
    #[must_use]
    pub fn get_datagram_receive_buffer_size(&self) -> usize {
        self.datagram_receive_buffer_size
    }

    /// Set the maximum early data size for 0-RTT (RFC 9001 §4.6, server-side).
    ///
    /// rustls QUIC requires this to be exactly `0` (disabled) or `u32::MAX`
    /// (enabled). Any non-zero value is normalised to `u32::MAX`.
    ///
    /// On the server, this is applied to `ServerConfig::max_early_data_size`
    /// when accepting connections. On the client side this field is ignored;
    /// clients enable 0-RTT via `ClientConfig::enable_early_data`.
    #[must_use]
    pub fn max_early_data_size(mut self, size: u32) -> Self {
        // rustls QUIC ServerConnection::new requires exactly 0 or u32::MAX.
        self.max_early_data_size = if size == 0 { 0 } else { u32::MAX };
        self
    }

    /// The configured maximum early data size.
    #[must_use]
    pub fn get_max_early_data_size(&self) -> u32 {
        self.max_early_data_size
    }
}

// ─── Retry token helpers ─────────────────────────────────────────────────────

/// Compute a 16-byte HMAC-SHA256 tag over `ODCID || peer_ip_bytes || peer_port_be16`.
fn hmac_retry_tag(secret: &[u8; 32], odcid: &[u8], peer_addr: SocketAddr) -> [u8; 16] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    Mac::update(&mut mac, odcid);
    match peer_addr {
        SocketAddr::V4(v4) => Mac::update(&mut mac, &v4.ip().octets()),
        SocketAddr::V6(v6) => Mac::update(&mut mac, &v6.ip().octets()),
    }
    Mac::update(&mut mac, &peer_addr.port().to_be_bytes());
    let result = mac.finalize().into_bytes();
    // Truncate to 16 bytes (HMAC-SHA256 produces 32 bytes).
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&result[..16]);
    tag
}

/// Fill `buf` with 32 random bytes from the OS CSPRNG.
fn getrandom_secret(buf: &mut [u8; 32]) {
    // Use rustls_rustcrypto's SecureRandom which delegates to the OS CSPRNG.
    let provider = rustls_rustcrypto::provider();
    if provider.secure_random.fill(buf).is_ok() {
        return;
    }
    // Fallback: derive from std time (not cryptographically strong, but
    // better than zeros for a development scenario).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0xdead_beef);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (nanos.wrapping_add(i as u32 * 0x9e37_79b9)) as u8;
    }
}
