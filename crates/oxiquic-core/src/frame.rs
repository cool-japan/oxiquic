//! QUIC frame types (RFC 9000 Section 12.4 / Table 3).

use crate::error::OxiQuicError;
use std::fmt;

/// A QUIC frame type, classifying the frames defined by RFC 9000 Section 19.
///
/// Several frame types occupy a small range of type values rather than a single
/// value (for example `ACK` is `0x02`–`0x03` and `STREAM` is `0x08`–`0x0f`);
/// those ranges are represented by a single enum variant. The canonical
/// (lowest) type value for each variant is returned by
/// [`FrameType::type_value`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FrameType {
    /// `PADDING` (0x00).
    Padding,
    /// `PING` (0x01).
    Ping,
    /// `ACK` (0x02–0x03); the `0x01` bit signals the presence of ECN counts.
    Ack,
    /// `RESET_STREAM` (0x04).
    ResetStream,
    /// `STOP_SENDING` (0x05).
    StopSending,
    /// `CRYPTO` (0x06).
    Crypto,
    /// `NEW_TOKEN` (0x07).
    NewToken,
    /// `STREAM` (0x08–0x0f); the low 3 bits are the OFF/LEN/FIN flags.
    Stream,
    /// `MAX_DATA` (0x10).
    MaxData,
    /// `MAX_STREAM_DATA` (0x11).
    MaxStreamData,
    /// `MAX_STREAMS` (0x12–0x13); `0x13` applies to unidirectional streams.
    MaxStreams,
    /// `DATA_BLOCKED` (0x14).
    DataBlocked,
    /// `STREAM_DATA_BLOCKED` (0x15).
    StreamDataBlocked,
    /// `STREAMS_BLOCKED` (0x16–0x17); `0x17` applies to unidirectional streams.
    StreamsBlocked,
    /// `NEW_CONNECTION_ID` (0x18).
    NewConnectionId,
    /// `RETIRE_CONNECTION_ID` (0x19).
    RetireConnectionId,
    /// `PATH_CHALLENGE` (0x1a).
    PathChallenge,
    /// `PATH_RESPONSE` (0x1b).
    PathResponse,
    /// `CONNECTION_CLOSE` (0x1c–0x1d); `0x1d` carries an application error code.
    ConnectionClose,
    /// `HANDSHAKE_DONE` (0x1e).
    HandshakeDone,
    /// `DATAGRAM` (0x30 without length, 0x31 with length): unreliable datagram
    /// (RFC 9221).
    Datagram,
}

impl FrameType {
    /// Decode a frame type from its varint type value.
    ///
    /// Values that fall inside a frame's type-value range are accepted (for
    /// example `0x0c` decodes to [`FrameType::Stream`]).
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError::FrameEncoding`] for any value not assigned by
    /// RFC 9000 Section 12.4, which corresponds to a `FRAME_ENCODING_ERROR`.
    pub fn from_varint(value: u64) -> Result<Self, OxiQuicError> {
        let frame = match value {
            0x00 => Self::Padding,
            0x01 => Self::Ping,
            0x02 | 0x03 => Self::Ack,
            0x04 => Self::ResetStream,
            0x05 => Self::StopSending,
            0x06 => Self::Crypto,
            0x07 => Self::NewToken,
            0x08..=0x0f => Self::Stream,
            0x10 => Self::MaxData,
            0x11 => Self::MaxStreamData,
            0x12 | 0x13 => Self::MaxStreams,
            0x14 => Self::DataBlocked,
            0x15 => Self::StreamDataBlocked,
            0x16 | 0x17 => Self::StreamsBlocked,
            0x18 => Self::NewConnectionId,
            0x19 => Self::RetireConnectionId,
            0x1a => Self::PathChallenge,
            0x1b => Self::PathResponse,
            0x1c | 0x1d => Self::ConnectionClose,
            0x1e => Self::HandshakeDone,
            0x30 | 0x31 => Self::Datagram,
            other => {
                return Err(OxiQuicError::FrameEncoding(format!(
                    "unknown frame type 0x{other:02x}"
                )));
            }
        };
        Ok(frame)
    }

    /// The canonical (lowest) varint type value for this frame type.
    #[must_use]
    pub const fn type_value(self) -> u64 {
        match self {
            Self::Padding => 0x00,
            Self::Ping => 0x01,
            Self::Ack => 0x02,
            Self::ResetStream => 0x04,
            Self::StopSending => 0x05,
            Self::Crypto => 0x06,
            Self::NewToken => 0x07,
            Self::Stream => 0x08,
            Self::MaxData => 0x10,
            Self::MaxStreamData => 0x11,
            Self::MaxStreams => 0x12,
            Self::DataBlocked => 0x14,
            Self::StreamDataBlocked => 0x15,
            Self::StreamsBlocked => 0x16,
            Self::NewConnectionId => 0x18,
            Self::RetireConnectionId => 0x19,
            Self::PathChallenge => 0x1a,
            Self::PathResponse => 0x1b,
            Self::ConnectionClose => 0x1c,
            Self::HandshakeDone => 0x1e,
            Self::Datagram => 0x30,
        }
    }

    /// Whether a frame of this type is *ack-eliciting* (RFC 9000 Section 13.2).
    ///
    /// All frames except `ACK`, `PADDING` and `CONNECTION_CLOSE` are
    /// ack-eliciting; receipt of any such frame obliges the peer to acknowledge
    /// the packet.
    #[must_use]
    pub const fn is_ack_eliciting(self) -> bool {
        !matches!(self, Self::Ack | Self::Padding | Self::ConnectionClose)
    }

    /// Whether a frame of this type is a *probing* frame (RFC 9000 Section 9.1).
    ///
    /// Probing frames (`PATH_CHALLENGE`, `PATH_RESPONSE`, `NEW_CONNECTION_ID`
    /// and `PADDING`) are the only frames permitted on a path that is being
    /// validated; a packet containing only probing frames is a probing packet.
    #[must_use]
    pub const fn is_probing(self) -> bool {
        matches!(
            self,
            Self::PathChallenge | Self::PathResponse | Self::NewConnectionId | Self::Padding
        )
    }

    /// The uppercase RFC name of the frame type, e.g. `"RESET_STREAM"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Padding => "PADDING",
            Self::Ping => "PING",
            Self::Ack => "ACK",
            Self::ResetStream => "RESET_STREAM",
            Self::StopSending => "STOP_SENDING",
            Self::Crypto => "CRYPTO",
            Self::NewToken => "NEW_TOKEN",
            Self::Stream => "STREAM",
            Self::MaxData => "MAX_DATA",
            Self::MaxStreamData => "MAX_STREAM_DATA",
            Self::MaxStreams => "MAX_STREAMS",
            Self::DataBlocked => "DATA_BLOCKED",
            Self::StreamDataBlocked => "STREAM_DATA_BLOCKED",
            Self::StreamsBlocked => "STREAMS_BLOCKED",
            Self::NewConnectionId => "NEW_CONNECTION_ID",
            Self::RetireConnectionId => "RETIRE_CONNECTION_ID",
            Self::PathChallenge => "PATH_CHALLENGE",
            Self::PathResponse => "PATH_RESPONSE",
            Self::ConnectionClose => "CONNECTION_CLOSE",
            Self::HandshakeDone => "HANDSHAKE_DONE",
            Self::Datagram => "DATAGRAM",
        }
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
