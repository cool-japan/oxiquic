//! QUIC transport parameters (RFC 9000 Section 18.2).

use crate::error::OxiQuicError;

/// The default `max_udp_payload_size` per RFC 9000 Section 18.2: the largest
/// UDP payload the endpoint is willing to receive.
pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65527;
/// The minimum permitted `max_udp_payload_size` (RFC 9000 Section 14): an
/// endpoint must be able to receive datagrams of at least 1200 bytes.
pub const MIN_MAX_UDP_PAYLOAD_SIZE: u64 = 1200;
/// The default `ack_delay_exponent` (RFC 9000 Section 18.2).
pub const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
/// The maximum permitted `ack_delay_exponent` (RFC 9000 Section 18.2).
pub const MAX_ACK_DELAY_EXPONENT: u8 = 20;
/// The default `max_ack_delay`, in milliseconds (RFC 9000 Section 18.2).
pub const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;
/// The exclusive upper bound on `max_ack_delay`, in milliseconds: the field is
/// encoded as a varint and must be less than `2^14` (RFC 9000 Section 18.2).
pub const MAX_ACK_DELAY_MS_LIMIT: u64 = 1 << 14;
/// The default `active_connection_id_limit` (RFC 9000 Section 18.2). The value
/// must be at least 2.
pub const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
/// The minimum permitted `active_connection_id_limit` (RFC 9000 Section 18.2).
pub const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// The set of QUIC transport parameters an endpoint advertises during the
/// handshake (RFC 9000 Section 18.2).
///
/// Fields that default to zero when absent (the flow-control and stream-limit
/// parameters) are represented directly as their integer values;
/// [`TransportParams::default`] yields the RFC-specified protocol defaults for
/// the parameters that have non-zero defaults.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParams {
    /// `max_idle_timeout` in milliseconds; `0` disables the idle timeout.
    pub max_idle_timeout_ms: u64,
    /// `max_udp_payload_size`: largest UDP payload the endpoint will receive.
    pub max_udp_payload_size: u64,
    /// `initial_max_data`: connection-level flow-control limit.
    pub initial_max_data: u64,
    /// `initial_max_stream_data_bidi_local`: flow-control limit for
    /// bidirectional streams this endpoint opens.
    pub initial_max_stream_data_bidi_local: u64,
    /// `initial_max_stream_data_bidi_remote`: flow-control limit for
    /// bidirectional streams the peer opens.
    pub initial_max_stream_data_bidi_remote: u64,
    /// `initial_max_stream_data_uni`: flow-control limit for unidirectional
    /// streams the peer opens.
    pub initial_max_stream_data_uni: u64,
    /// `initial_max_streams_bidi`: number of bidirectional streams the peer may
    /// open.
    pub initial_max_streams_bidi: u64,
    /// `initial_max_streams_uni`: number of unidirectional streams the peer may
    /// open.
    pub initial_max_streams_uni: u64,
    /// `ack_delay_exponent`: scale factor for `ACK` delay fields (default 3).
    pub ack_delay_exponent: u8,
    /// `max_ack_delay` in milliseconds: maximum the endpoint delays sending an
    /// acknowledgement (default 25).
    pub max_ack_delay_ms: u64,
    /// `active_connection_id_limit`: number of connection IDs the endpoint will
    /// store (default 2, minimum 2).
    pub active_connection_id_limit: u64,
    /// `disable_active_migration`: if `true`, the endpoint will not migrate
    /// connections to a new path.
    pub disable_active_migration: bool,
    /// `max_datagram_frame_size` (RFC 9221 §3): the maximum DATAGRAM frame
    /// payload the endpoint is willing to receive. A value of 0 means the
    /// endpoint does not support the DATAGRAM extension.
    pub max_datagram_frame_size: u64,
}

impl Default for TransportParams {
    /// Returns the RFC 9000 Section 18.2 protocol defaults: a disabled idle
    /// timeout, the default UDP payload size, zero flow-control/stream limits,
    /// and the default ACK and connection-ID parameters.
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: 0,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            max_ack_delay_ms: DEFAULT_MAX_ACK_DELAY_MS,
            active_connection_id_limit: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
            disable_active_migration: false,
            max_datagram_frame_size: 0,
        }
    }
}

impl TransportParams {
    /// Validate the parameters against the constraints in RFC 9000 Section 18.2.
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError::TransportError`] with a
    /// `TRANSPORT_PARAMETER_ERROR` code if:
    ///
    /// - `ack_delay_exponent` exceeds 20,
    /// - `max_ack_delay_ms` is `2^14` or greater,
    /// - `max_udp_payload_size` is below 1200, or
    /// - `active_connection_id_limit` is below 2.
    pub fn validate(&self) -> Result<(), OxiQuicError> {
        use crate::transport_error::TransportErrorCode;

        let reject = |reason: String| {
            Err(OxiQuicError::TransportError {
                code: TransportErrorCode::TransportParameterError,
                frame_type: None,
                reason,
            })
        };

        if self.ack_delay_exponent > MAX_ACK_DELAY_EXPONENT {
            return reject(format!(
                "ack_delay_exponent {} exceeds maximum of {MAX_ACK_DELAY_EXPONENT}",
                self.ack_delay_exponent
            ));
        }
        if self.max_ack_delay_ms >= MAX_ACK_DELAY_MS_LIMIT {
            return reject(format!(
                "max_ack_delay {}ms must be less than {MAX_ACK_DELAY_MS_LIMIT}ms",
                self.max_ack_delay_ms
            ));
        }
        if self.max_udp_payload_size < MIN_MAX_UDP_PAYLOAD_SIZE {
            return reject(format!(
                "max_udp_payload_size {} is below the minimum of {MIN_MAX_UDP_PAYLOAD_SIZE}",
                self.max_udp_payload_size
            ));
        }
        if self.active_connection_id_limit < MIN_ACTIVE_CONNECTION_ID_LIMIT {
            return reject(format!(
                "active_connection_id_limit {} is below the minimum of {MIN_ACTIVE_CONNECTION_ID_LIMIT}",
                self.active_connection_id_limit
            ));
        }
        Ok(())
    }
}
