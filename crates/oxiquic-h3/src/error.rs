//! HTTP/3 error codes and errors (RFC 9114 Section 8.1).

use std::fmt;

/// An HTTP/3 error code as defined by RFC 9114 Section 8.1.
///
/// These codes appear in `RESET_STREAM`, `STOP_SENDING` and
/// `CONNECTION_CLOSE` frames at the HTTP/3 layer. QPACK defines a separate set
/// of codes (RFC 9204 Section 8.3) which are represented by the
/// `0x0200`–`0x0202` values via [`H3ErrorCode::Qpack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum H3ErrorCode {
    /// `H3_NO_ERROR` (0x0100).
    NoError,
    /// `H3_GENERAL_PROTOCOL_ERROR` (0x0101).
    GeneralProtocolError,
    /// `H3_INTERNAL_ERROR` (0x0102).
    InternalError,
    /// `H3_STREAM_CREATION_ERROR` (0x0103).
    StreamCreationError,
    /// `H3_CLOSED_CRITICAL_STREAM` (0x0104).
    ClosedCriticalStream,
    /// `H3_FRAME_UNEXPECTED` (0x0105).
    FrameUnexpected,
    /// `H3_FRAME_ERROR` (0x0106).
    FrameError,
    /// `H3_EXCESSIVE_LOAD` (0x0107).
    ExcessiveLoad,
    /// `H3_ID_ERROR` (0x0108).
    IdError,
    /// `H3_SETTINGS_ERROR` (0x0109).
    SettingsError,
    /// `H3_MISSING_SETTINGS` (0x010a).
    MissingSettings,
    /// `H3_REQUEST_REJECTED` (0x010b).
    RequestRejected,
    /// `H3_REQUEST_CANCELLED` (0x010c).
    RequestCancelled,
    /// `H3_REQUEST_INCOMPLETE` (0x010d).
    RequestIncomplete,
    /// `H3_MESSAGE_ERROR` (0x010e).
    MessageError,
    /// `H3_CONNECT_ERROR` (0x010f).
    ConnectError,
    /// `H3_VERSION_FALLBACK` (0x0110).
    VersionFallback,
    /// A QPACK error code (RFC 9204 Section 8.3): `QPACK_DECOMPRESSION_FAILED`
    /// (0x0200), `QPACK_ENCODER_STREAM_ERROR` (0x0201) or
    /// `QPACK_DECODER_STREAM_ERROR` (0x0202).
    Qpack(u64),
    /// Any other (unassigned or reserved) HTTP/3 error code.
    Unknown(u64),
}

impl H3ErrorCode {
    /// Decode an HTTP/3 error code from its wire value.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        match value {
            0x0100 => Self::NoError,
            0x0101 => Self::GeneralProtocolError,
            0x0102 => Self::InternalError,
            0x0103 => Self::StreamCreationError,
            0x0104 => Self::ClosedCriticalStream,
            0x0105 => Self::FrameUnexpected,
            0x0106 => Self::FrameError,
            0x0107 => Self::ExcessiveLoad,
            0x0108 => Self::IdError,
            0x0109 => Self::SettingsError,
            0x010a => Self::MissingSettings,
            0x010b => Self::RequestRejected,
            0x010c => Self::RequestCancelled,
            0x010d => Self::RequestIncomplete,
            0x010e => Self::MessageError,
            0x010f => Self::ConnectError,
            0x0110 => Self::VersionFallback,
            0x0200..=0x0202 => Self::Qpack(value),
            other => Self::Unknown(other),
        }
    }

    /// The wire value for this HTTP/3 error code.
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        match self {
            Self::NoError => 0x0100,
            Self::GeneralProtocolError => 0x0101,
            Self::InternalError => 0x0102,
            Self::StreamCreationError => 0x0103,
            Self::ClosedCriticalStream => 0x0104,
            Self::FrameUnexpected => 0x0105,
            Self::FrameError => 0x0106,
            Self::ExcessiveLoad => 0x0107,
            Self::IdError => 0x0108,
            Self::SettingsError => 0x0109,
            Self::MissingSettings => 0x010a,
            Self::RequestRejected => 0x010b,
            Self::RequestCancelled => 0x010c,
            Self::RequestIncomplete => 0x010d,
            Self::MessageError => 0x010e,
            Self::ConnectError => 0x010f,
            Self::VersionFallback => 0x0110,
            Self::Qpack(value) | Self::Unknown(value) => value,
        }
    }

    /// The uppercase RFC name of the error code, e.g. `"H3_FRAME_UNEXPECTED"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoError => "H3_NO_ERROR",
            Self::GeneralProtocolError => "H3_GENERAL_PROTOCOL_ERROR",
            Self::InternalError => "H3_INTERNAL_ERROR",
            Self::StreamCreationError => "H3_STREAM_CREATION_ERROR",
            Self::ClosedCriticalStream => "H3_CLOSED_CRITICAL_STREAM",
            Self::FrameUnexpected => "H3_FRAME_UNEXPECTED",
            Self::FrameError => "H3_FRAME_ERROR",
            Self::ExcessiveLoad => "H3_EXCESSIVE_LOAD",
            Self::IdError => "H3_ID_ERROR",
            Self::SettingsError => "H3_SETTINGS_ERROR",
            Self::MissingSettings => "H3_MISSING_SETTINGS",
            Self::RequestRejected => "H3_REQUEST_REJECTED",
            Self::RequestCancelled => "H3_REQUEST_CANCELLED",
            Self::RequestIncomplete => "H3_REQUEST_INCOMPLETE",
            Self::MessageError => "H3_MESSAGE_ERROR",
            Self::ConnectError => "H3_CONNECT_ERROR",
            Self::VersionFallback => "H3_VERSION_FALLBACK",
            Self::Qpack(_) => "QPACK_ERROR",
            Self::Unknown(_) => "H3_UNKNOWN",
        }
    }
}

impl fmt::Display for H3ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Qpack(value) => write!(f, "QPACK_ERROR(0x{value:x})"),
            Self::Unknown(value) => write!(f, "H3_UNKNOWN(0x{value:x})"),
            other => f.write_str(other.name()),
        }
    }
}

/// An error originating in the HTTP/3 layer (RFC 9114).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum H3Error {
    /// A generic HTTP/3 protocol violation (RFC 9114 Section 8).
    #[error("HTTP/3 protocol error: {0}")]
    Protocol(String),

    /// A QPACK header (de)compression error (RFC 9204).
    #[error("QPACK error: {0}")]
    Qpack(String),

    /// A stream-level HTTP/3 error.
    #[error("HTTP/3 stream error: {0}")]
    Stream(String),

    /// A connection-level HTTP/3 error.
    #[error("HTTP/3 connection error: {0}")]
    Connection(String),

    /// An unexpected frame was received (`H3_FRAME_UNEXPECTED`).
    #[error("unexpected HTTP/3 frame: {0}")]
    FrameUnexpected(String),

    /// An invalid `SETTINGS` frame was received (`H3_SETTINGS_ERROR`).
    #[error("HTTP/3 settings error: {0}")]
    SettingsError(String),

    /// The mandatory `SETTINGS` frame was not the first frame on the control
    /// stream (`H3_MISSING_SETTINGS`).
    #[error("HTTP/3 SETTINGS frame missing")]
    MissingSettings,

    /// An invalid stream/push ID was used (`H3_ID_ERROR`).
    #[error("HTTP/3 ID error: {0}")]
    IdError(String),

    /// A TLS error surfaced at the HTTP/3 layer.
    #[error("TLS error: {0}")]
    Tls(String),

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl H3Error {
    /// The HTTP/3 error code corresponding to this error
    /// (RFC 9114 Section 8.1).
    #[must_use]
    pub const fn code(&self) -> H3ErrorCode {
        match self {
            Self::Protocol(_) => H3ErrorCode::GeneralProtocolError,
            Self::Qpack(_) => H3ErrorCode::Qpack(0x0200),
            Self::Stream(_) => H3ErrorCode::StreamCreationError,
            Self::Connection(_) | Self::Io(_) => H3ErrorCode::InternalError,
            Self::FrameUnexpected(_) => H3ErrorCode::FrameUnexpected,
            Self::SettingsError(_) => H3ErrorCode::SettingsError,
            Self::MissingSettings => H3ErrorCode::MissingSettings,
            Self::IdError(_) => H3ErrorCode::IdError,
            Self::Tls(_) => H3ErrorCode::GeneralProtocolError,
        }
    }
}

impl From<H3Error> for oxiquic_core::OxiQuicError {
    fn from(err: H3Error) -> Self {
        match err {
            H3Error::Io(io) => Self::Io(io),
            H3Error::Tls(msg) => Self::Tls(msg),
            other => Self::Protocol(other.to_string()),
        }
    }
}

/// Map an [`h3::error::Code`] wire value to the corresponding [`H3ErrorCode`]
/// variant (RFC 9114 §8.1, RFC 9204 §8.3).
fn map_h3_code(code: h3::error::Code) -> H3ErrorCode {
    H3ErrorCode::from_u64(code.value())
}

impl From<h3::error::ConnectionError> for H3Error {
    fn from(e: h3::error::ConnectionError) -> Self {
        match &e {
            h3::error::ConnectionError::Local {
                error: h3::error::LocalError::Application { code, .. },
            } => {
                let h3_code = map_h3_code(*code);
                match h3_code {
                    H3ErrorCode::FrameUnexpected => H3Error::FrameUnexpected(e.to_string()),
                    H3ErrorCode::SettingsError => H3Error::SettingsError(e.to_string()),
                    H3ErrorCode::MissingSettings => H3Error::MissingSettings,
                    H3ErrorCode::IdError => H3Error::IdError(e.to_string()),
                    H3ErrorCode::Qpack(_) => H3Error::Qpack(e.to_string()),
                    _ => H3Error::Connection(e.to_string()),
                }
            }
            // Catch all other Local variants (e.g. Closing) and Remote/Timeout
            _ => H3Error::Connection(e.to_string()),
        }
    }
}

impl From<h3::error::StreamError> for H3Error {
    fn from(e: h3::error::StreamError) -> Self {
        match &e {
            h3::error::StreamError::StreamError { code, .. } => {
                let h3_code = map_h3_code(*code);
                match h3_code {
                    H3ErrorCode::FrameUnexpected => H3Error::FrameUnexpected(e.to_string()),
                    H3ErrorCode::SettingsError => H3Error::SettingsError(e.to_string()),
                    H3ErrorCode::MissingSettings => H3Error::MissingSettings,
                    H3ErrorCode::IdError => H3Error::IdError(e.to_string()),
                    H3ErrorCode::Qpack(_) => H3Error::Qpack(e.to_string()),
                    _ => H3Error::Stream(e.to_string()),
                }
            }
            h3::error::StreamError::RemoteTerminate { code } => {
                let h3_code = map_h3_code(*code);
                match h3_code {
                    H3ErrorCode::RequestCancelled => {
                        H3Error::Stream("request cancelled".to_owned())
                    }
                    _ => H3Error::Stream(e.to_string()),
                }
            }
            h3::error::StreamError::ConnectionError(conn_err) => H3Error::from(conn_err.clone()),
            h3::error::StreamError::HeaderTooBig { .. } => H3Error::Protocol(e.to_string()),
            h3::error::StreamError::RemoteClosing => {
                H3Error::Connection("remote is closing".to_owned())
            }
            h3::error::StreamError::Undefined(_) => H3Error::Stream(e.to_string()),
            _ => H3Error::Stream(e.to_string()),
        }
    }
}
