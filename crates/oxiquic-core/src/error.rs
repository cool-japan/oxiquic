//! Unified error type for the OxiQUIC stack.

use crate::frame::FrameType;
use crate::transport_error::TransportErrorCode;
use thiserror::Error;

/// Unified error type for the OxiQUIC stack.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OxiQuicError {
    /// Underlying I/O failure (UDP socket, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS configuration or handshake failure.
    #[error("TLS configuration error: {0}")]
    Tls(String),

    /// QUIC packet-protection / crypto failure.
    #[error("QUIC crypto error: {0}")]
    QuicCrypto(String),

    /// Generic connection-level failure.
    #[error("connection error: {0}")]
    Connection(String),

    /// Generic stream-level failure.
    #[error("stream error: {0}")]
    Stream(String),

    /// A QUIC transport error carrying an RFC 9000 Section 20.1 error code.
    #[error("transport error {code}{}: {reason}", FrameContext(.frame_type))]
    TransportError {
        /// The RFC 9000 transport error code.
        code: TransportErrorCode,
        /// The frame type that triggered the error, if any.
        frame_type: Option<FrameType>,
        /// Human-readable reason phrase.
        reason: String,
    },

    /// A frame could not be encoded or decoded.
    #[error("frame encoding error: {0}")]
    FrameEncoding(String),

    /// A flow-control limit was violated.
    #[error("flow control error: {0}")]
    FlowControl(String),

    /// The peer (or a generic protocol rule) was violated.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// An operation timed out (handshake or generic).
    #[error("operation timed out")]
    Timeout,

    /// The connection idle timer expired (RFC 9000 Section 10.1).
    #[error("connection idle timeout")]
    IdleTimeout,

    /// Version negotiation failed: the server does not support any version we
    /// speak.  The payload lists the versions the server advertised.
    #[error("QUIC version negotiation failed; server supports: {supported:x?}")]
    VersionNegotiation {
        /// Version list the server sent in its Version Negotiation packet.
        supported: Vec<u32>,
    },

    /// The peer sent a stateless reset (RFC 9000 Section 10.3).
    #[error("connection reset by peer (stateless reset)")]
    StatelessReset,

    /// The connection was closed by the application layer.
    #[error("application close (code {code}): {reason}")]
    ApplicationClose {
        /// Application-defined close code.
        code: u64,
        /// Human-readable reason phrase.
        reason: String,
    },

    /// A requested feature is not implemented in this build.
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

impl OxiQuicError {
    /// Returns `true` if this error represents a timeout
    /// (handshake timeout or idle timeout).
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout | Self::IdleTimeout)
    }

    /// Returns `true` if this error represents a closed connection
    /// (graceful transport close or application close).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(
            self,
            Self::ApplicationClose { .. }
                | Self::TransportError { .. }
                | Self::IdleTimeout
                | Self::StatelessReset
        )
    }

    /// Returns `true` if this error represents a reset
    /// (stateless reset or a stream reset reported via [`Self::Stream`]).
    #[must_use]
    pub fn is_reset(&self) -> bool {
        matches!(self, Self::StatelessReset)
    }
}

// ── oxitls TlsError bridge ────────────────────────────────────────────────────

/// Convert an `oxitls_core::TlsError` into an [`OxiQuicError`].
///
/// I/O errors round-trip through their [`std::io::ErrorKind`]; everything else
/// folds into [`OxiQuicError::Tls`] as a human-readable string so the
/// transport layer doesn't take an oxitls dependency at the monomorphisation
/// boundary.
#[cfg(feature = "oxitls")]
impl From<oxitls_core::TlsError> for OxiQuicError {
    fn from(e: oxitls_core::TlsError) -> Self {
        match e {
            oxitls_core::TlsError::Io(kind) => OxiQuicError::Io(std::io::Error::from(kind)),
            other => OxiQuicError::Tls(other.to_string()),
        }
    }
}

/// Helper that renders the optional frame-type context in `TransportError`'s
/// `Display` impl as `" (frame STREAM)"` or the empty string.
struct FrameContext<'a>(&'a Option<FrameType>);

impl std::fmt::Display for FrameContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(ft) => write!(f, " (frame {ft})"),
            None => Ok(()),
        }
    }
}
