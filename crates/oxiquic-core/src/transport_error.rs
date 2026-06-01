//! QUIC transport error codes (RFC 9000 Section 20.1).

use crate::error::OxiQuicError;
use std::fmt;

/// A QUIC transport error code, as carried in a `CONNECTION_CLOSE` frame of
/// type `0x1c` (RFC 9000 Section 20.1).
///
/// The TLS alert range `0x0100`–`0x01ff` is represented by
/// [`TransportErrorCode::CryptoError`], whose payload is the one-byte TLS alert
/// description. Any other unassigned value decodes to
/// [`TransportErrorCode::Unknown`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportErrorCode {
    /// `NO_ERROR` (0x00): graceful close with no error.
    NoError,
    /// `INTERNAL_ERROR` (0x01): the endpoint encountered an internal error.
    InternalError,
    /// `CONNECTION_REFUSED` (0x02): the server refuses to accept the connection.
    ConnectionRefused,
    /// `FLOW_CONTROL_ERROR` (0x03): a flow-control limit was exceeded.
    FlowControlError,
    /// `STREAM_LIMIT_ERROR` (0x04): too many streams were opened.
    StreamLimitError,
    /// `STREAM_STATE_ERROR` (0x05): a frame was received for a stream in an
    /// invalid state.
    StreamStateError,
    /// `FINAL_SIZE_ERROR` (0x06): a stream's final size was changed.
    FinalSizeError,
    /// `FRAME_ENCODING_ERROR` (0x07): a frame was malformed.
    FrameEncodingError,
    /// `TRANSPORT_PARAMETER_ERROR` (0x08): a transport parameter was invalid.
    TransportParameterError,
    /// `CONNECTION_ID_LIMIT_ERROR` (0x09): too many connection IDs were issued.
    ConnectionIdLimitError,
    /// `PROTOCOL_VIOLATION` (0x0a): a generic protocol rule was violated.
    ProtocolViolation,
    /// `INVALID_TOKEN` (0x0b): an invalid Retry/`NEW_TOKEN` token was received.
    InvalidToken,
    /// `APPLICATION_ERROR` (0x0c): the application layer signalled an error.
    ApplicationError,
    /// `CRYPTO_BUFFER_EXCEEDED` (0x0d): more `CRYPTO` data than could be buffered.
    CryptoBufferExceeded,
    /// `KEY_UPDATE_ERROR` (0x0e): an error occurred during a key update.
    KeyUpdateError,
    /// `AEAD_LIMIT_REACHED` (0x0f): the AEAD confidentiality/integrity limit
    /// was reached and the connection must be closed.
    AeadLimitReached,
    /// `NO_VIABLE_PATH` (0x10): no network path validated successfully.
    NoViablePath,
    /// `CRYPTO_ERROR` (0x0100–0x01ff): a TLS alert. The payload is the TLS
    /// alert description (the low byte of the code).
    CryptoError(u8),
    /// Any transport error code not assigned by RFC 9000.
    Unknown(u64),
}

impl TransportErrorCode {
    /// Decode a transport error code from its 62-bit wire value.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        match value {
            0x00 => Self::NoError,
            0x01 => Self::InternalError,
            0x02 => Self::ConnectionRefused,
            0x03 => Self::FlowControlError,
            0x04 => Self::StreamLimitError,
            0x05 => Self::StreamStateError,
            0x06 => Self::FinalSizeError,
            0x07 => Self::FrameEncodingError,
            0x08 => Self::TransportParameterError,
            0x09 => Self::ConnectionIdLimitError,
            0x0a => Self::ProtocolViolation,
            0x0b => Self::InvalidToken,
            0x0c => Self::ApplicationError,
            0x0d => Self::CryptoBufferExceeded,
            0x0e => Self::KeyUpdateError,
            0x0f => Self::AeadLimitReached,
            0x10 => Self::NoViablePath,
            0x0100..=0x01ff => Self::CryptoError((value & 0xff) as u8),
            other => Self::Unknown(other),
        }
    }

    /// The 62-bit wire value for this transport error code.
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        match self {
            Self::NoError => 0x00,
            Self::InternalError => 0x01,
            Self::ConnectionRefused => 0x02,
            Self::FlowControlError => 0x03,
            Self::StreamLimitError => 0x04,
            Self::StreamStateError => 0x05,
            Self::FinalSizeError => 0x06,
            Self::FrameEncodingError => 0x07,
            Self::TransportParameterError => 0x08,
            Self::ConnectionIdLimitError => 0x09,
            Self::ProtocolViolation => 0x0a,
            Self::InvalidToken => 0x0b,
            Self::ApplicationError => 0x0c,
            Self::CryptoBufferExceeded => 0x0d,
            Self::KeyUpdateError => 0x0e,
            Self::AeadLimitReached => 0x0f,
            Self::NoViablePath => 0x10,
            Self::CryptoError(alert) => 0x0100 | (alert as u64),
            Self::Unknown(value) => value,
        }
    }

    /// The uppercase RFC name of the error code, e.g. `"FLOW_CONTROL_ERROR"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoError => "NO_ERROR",
            Self::InternalError => "INTERNAL_ERROR",
            Self::ConnectionRefused => "CONNECTION_REFUSED",
            Self::FlowControlError => "FLOW_CONTROL_ERROR",
            Self::StreamLimitError => "STREAM_LIMIT_ERROR",
            Self::StreamStateError => "STREAM_STATE_ERROR",
            Self::FinalSizeError => "FINAL_SIZE_ERROR",
            Self::FrameEncodingError => "FRAME_ENCODING_ERROR",
            Self::TransportParameterError => "TRANSPORT_PARAMETER_ERROR",
            Self::ConnectionIdLimitError => "CONNECTION_ID_LIMIT_ERROR",
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::InvalidToken => "INVALID_TOKEN",
            Self::ApplicationError => "APPLICATION_ERROR",
            Self::CryptoBufferExceeded => "CRYPTO_BUFFER_EXCEEDED",
            Self::KeyUpdateError => "KEY_UPDATE_ERROR",
            Self::AeadLimitReached => "AEAD_LIMIT_REACHED",
            Self::NoViablePath => "NO_VIABLE_PATH",
            Self::CryptoError(_) => "CRYPTO_ERROR",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

impl fmt::Display for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CryptoError(alert) => write!(f, "CRYPTO_ERROR(TLS alert {alert})"),
            Self::Unknown(value) => write!(f, "UNKNOWN(0x{value:x})"),
            other => f.write_str(other.name()),
        }
    }
}

impl From<TransportErrorCode> for OxiQuicError {
    fn from(code: TransportErrorCode) -> Self {
        Self::TransportError {
            code,
            frame_type: None,
            reason: code.name().to_string(),
        }
    }
}
