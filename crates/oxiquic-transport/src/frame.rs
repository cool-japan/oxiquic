//! QUIC frame encoding and decoding (RFC 9000 Section 19).
//!
//! [`Frame`] is the decoded representation of every frame OxiQUIC understands.
//! Frames borrow their payload bytes (`CRYPTO`, `STREAM`) from the packet buffer
//! to avoid copying on the receive path. [`Frame::encode`] writes the wire form,
//! and [`decode_frame`] reads one frame from a [`Buf`].

use crate::coding::{put_varint, Buf, CodecError};
use oxiquic_core::{ConnectionId, Direction, TransportErrorCode};

/// A contiguous run of acknowledged packet numbers, expressed as the gap and
/// length fields of an `ACK` frame (RFC 9000 Section 19.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    /// Gap: count of unacknowledged packets preceding this range.
    pub gap: u64,
    /// Length: count of acknowledged packets in this range, minus one.
    pub range: u64,
}

/// A decoded QUIC frame.
///
/// Variants carry only the fields OxiQUIC acts on; frame types that are decoded
/// but otherwise ignored (e.g. `NEW_CONNECTION_ID`) are represented by
/// [`Frame::Unsupported`] so the receive loop can skip them without error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// `PADDING` (0x00): one or more zero bytes, coalesced into a count.
    Padding(usize),
    /// `PING` (0x01).
    Ping,
    /// `ACK` (0x02): acknowledgement of received packets.
    Ack {
        /// Largest packet number being acknowledged.
        largest: u64,
        /// Peer's `ack_delay`, in the wire (unscaled) units.
        delay: u64,
        /// Count of packets in the range ending at `largest` (the First ACK
        /// Range field).
        first_range: u64,
        /// Additional ranges, walking downward from `largest`.
        ranges: Vec<AckRange>,
    },
    /// `RESET_STREAM` (0x04): abruptly terminate a stream with an error code
    /// and report the final size (RFC 9000 Section 19.4).
    ResetStream {
        /// The stream being reset.
        stream_id: u64,
        /// Application-defined error code.
        error_code: u64,
        /// The final size of the stream's data.
        final_size: u64,
    },
    /// `STOP_SENDING` (0x05): request that the peer cease transmission on a
    /// stream (RFC 9000 Section 19.5).
    StopSending {
        /// The stream to stop.
        stream_id: u64,
        /// Application-defined error code.
        error_code: u64,
    },
    /// `CRYPTO` (0x06): handshake data at a byte offset within its space.
    Crypto {
        /// Byte offset of `data` within the CRYPTO stream for this space.
        offset: u64,
        /// The handshake bytes.
        data: &'a [u8],
    },
    /// `STREAM` (0x08–0x0f): application stream data.
    Stream {
        /// Stream identifier.
        id: u64,
        /// Byte offset of `data` within the stream.
        offset: u64,
        /// Whether this frame carries the final bytes of the stream.
        fin: bool,
        /// The stream data.
        data: &'a [u8],
    },
    /// `MAX_DATA` (0x10): connection-level flow-control limit.
    MaxData(u64),
    /// `MAX_STREAM_DATA` (0x11): per-stream flow-control limit.
    MaxStreamData {
        /// Stream the limit applies to.
        id: u64,
        /// New maximum byte offset the peer may send on the stream.
        max: u64,
    },
    /// `DATA_BLOCKED` (0x14): sender is blocked by the connection limit.
    DataBlocked(u64),
    /// `STREAM_DATA_BLOCKED` (0x15): sender is blocked by a stream limit.
    StreamDataBlocked {
        /// Stream that is blocked.
        id: u64,
        /// The limit at which the sender is blocked.
        limit: u64,
    },
    /// `PATH_CHALLENGE` (0x1a): path validation probe carrying 8 bytes of
    /// random data (RFC 9000 Section 19.17).
    PathChallenge([u8; 8]),
    /// `PATH_RESPONSE` (0x1b): echoes the 8-byte data from a
    /// `PATH_CHALLENGE` (RFC 9000 Section 19.18).
    PathResponse([u8; 8]),
    /// `CONNECTION_CLOSE` (0x1c transport, 0x1d application).
    ConnectionClose {
        /// The error code (transport or application namespace).
        error_code: u64,
        /// For a transport close, the frame type that triggered it.
        frame_type: Option<u64>,
        /// Whether this is an application-level close (type 0x1d).
        application: bool,
        /// UTF-8 reason phrase.
        reason: Vec<u8>,
    },
    /// `HANDSHAKE_DONE` (0x1e): server signals handshake confirmation.
    HandshakeDone,
    /// `NEW_CONNECTION_ID` (0x18): issue a new connection ID to the peer
    /// (RFC 9000 §19.15).
    NewConnectionId {
        /// Sequence number, monotonically increasing per RFC 9000 §19.15.
        seq: u64,
        /// The peer should retire all CIDs with sequence numbers less than
        /// this value.
        retire_prior_to: u64,
        /// The new connection ID being issued.
        cid: ConnectionId,
        /// 16-byte stateless reset token for this CID (RFC 9000 §10.3.1).
        stateless_reset_token: [u8; 16],
    },
    /// `RETIRE_CONNECTION_ID` (0x19): retire a connection ID issued by the peer
    /// (RFC 9000 §19.16).
    RetireConnectionId {
        /// Sequence number of the CID being retired.
        seq: u64,
    },
    /// `MAX_STREAMS` (0x12 bidi, 0x13 uni): maximum streams the peer may open
    /// (RFC 9000 §19.11).
    MaxStreams {
        /// Whether this limit applies to bidirectional or unidirectional streams.
        dir: Direction,
        /// Maximum streams the peer may open.
        max: u64,
    },
    /// `STREAMS_BLOCKED` (0x16 bidi, 0x17 uni): sender at the stream limit
    /// (RFC 9000 §19.14).
    StreamsBlocked {
        /// Whether this applies to bidirectional or unidirectional streams.
        dir: Direction,
        /// The limit at which the sender is blocked.
        limit: u64,
    },
    /// `NEW_TOKEN` (0x07): address-validation token for the client's future
    /// connections (RFC 9000 §19.7).
    NewToken(&'a [u8]),
    /// `DATAGRAM` (0x30 without length, 0x31 with length): unreliable datagram
    /// (RFC 9221).
    Datagram(&'a [u8]),
    /// A frame whose type is recognized but carries no action here; the wire
    /// bytes were consumed. Holds the decoded type value.
    Unsupported(u64),
}

impl Frame<'_> {
    /// Whether this frame is ack-eliciting (RFC 9000 Section 13.2.1): its
    /// receipt obliges the peer to send an acknowledgement.
    #[must_use]
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Padding(_) | Frame::Ack { .. } | Frame::ConnectionClose { .. }
        )
    }

    /// Append this frame's wire encoding to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Padding(n) => out.resize(out.len() + *n, 0),
            Frame::Ping => put_varint(out, 0x01),
            Frame::Ack {
                largest,
                delay,
                first_range,
                ranges,
            } => {
                put_varint(out, 0x02);
                put_varint(out, *largest);
                put_varint(out, *delay);
                put_varint(out, ranges.len() as u64);
                put_varint(out, *first_range);
                for r in ranges {
                    put_varint(out, r.gap);
                    put_varint(out, r.range);
                }
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                put_varint(out, 0x04);
                put_varint(out, *stream_id);
                put_varint(out, *error_code);
                put_varint(out, *final_size);
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                put_varint(out, 0x05);
                put_varint(out, *stream_id);
                put_varint(out, *error_code);
            }
            Frame::Crypto { offset, data } => {
                put_varint(out, 0x06);
                put_varint(out, *offset);
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::NewToken(token) => {
                put_varint(out, 0x07);
                put_varint(out, token.len() as u64);
                out.extend_from_slice(token);
            }
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                // Always encode OFF and LEN bits for simplicity (0x08|0x04|0x02).
                let mut typ = 0x08 | 0x04 | 0x02;
                if *fin {
                    typ |= 0x01;
                }
                put_varint(out, typ);
                put_varint(out, *id);
                put_varint(out, *offset);
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::MaxData(max) => {
                put_varint(out, 0x10);
                put_varint(out, *max);
            }
            Frame::MaxStreamData { id, max } => {
                put_varint(out, 0x11);
                put_varint(out, *id);
                put_varint(out, *max);
            }
            Frame::DataBlocked(limit) => {
                put_varint(out, 0x14);
                put_varint(out, *limit);
            }
            Frame::StreamDataBlocked { id, limit } => {
                put_varint(out, 0x15);
                put_varint(out, *id);
                put_varint(out, *limit);
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                application,
                reason,
            } => {
                put_varint(out, if *application { 0x1d } else { 0x1c });
                put_varint(out, *error_code);
                if !*application {
                    put_varint(out, frame_type.unwrap_or(0));
                }
                put_varint(out, reason.len() as u64);
                out.extend_from_slice(reason);
            }
            Frame::PathChallenge(data) => {
                put_varint(out, 0x1a);
                out.extend_from_slice(data);
            }
            Frame::PathResponse(data) => {
                put_varint(out, 0x1b);
                out.extend_from_slice(data);
            }
            Frame::HandshakeDone => put_varint(out, 0x1e),
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                stateless_reset_token,
            } => {
                put_varint(out, 0x18);
                put_varint(out, *seq);
                put_varint(out, *retire_prior_to);
                let cid_bytes = cid.as_bytes();
                out.push(cid_bytes.len() as u8);
                out.extend_from_slice(cid_bytes);
                out.extend_from_slice(stateless_reset_token);
            }
            Frame::RetireConnectionId { seq } => {
                put_varint(out, 0x19);
                put_varint(out, *seq);
            }
            Frame::MaxStreams { dir, max } => {
                let t = if *dir == Direction::Unidirectional {
                    0x13u64
                } else {
                    0x12u64
                };
                put_varint(out, t);
                put_varint(out, *max);
            }
            Frame::StreamsBlocked { dir, limit } => {
                let t = if *dir == Direction::Unidirectional {
                    0x17u64
                } else {
                    0x16u64
                };
                put_varint(out, t);
                put_varint(out, *limit);
            }
            Frame::Datagram(data) => {
                // Always emit with length field (0x31) — safe and composable.
                put_varint(out, 0x31u64);
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::Unsupported(_) => {}
        }
    }
}

/// A transport-level decode error carrying the RFC 9000 error code to close
/// with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameError {
    /// The transport error code (almost always `FRAME_ENCODING_ERROR`).
    pub code: TransportErrorCode,
    /// Diagnostic detail.
    pub detail: &'static str,
}

impl From<CodecError> for FrameError {
    fn from(_: CodecError) -> Self {
        Self {
            code: TransportErrorCode::FrameEncodingError,
            detail: "truncated frame",
        }
    }
}

/// Decode a single frame from `buf`, advancing past it.
///
/// `PADDING` runs are coalesced: the returned [`Frame::Padding`] count covers
/// the leading zero byte plus any immediately following zero bytes.
///
/// # Errors
/// Returns [`FrameError`] on truncated input or an unknown frame type.
pub fn decode_frame<'a>(buf: &mut Buf<'a>) -> Result<Frame<'a>, FrameError> {
    let typ = buf.get_varint()?;
    let frame = match typ {
        0x00 => {
            // Coalesce a run of PADDING bytes.
            let mut count = 1;
            while buf.remaining() > 0 {
                let mut peek = buf.clone();
                if peek.get_u8().ok() == Some(0x00) {
                    let _ = buf.get_u8();
                    count += 1;
                } else {
                    break;
                }
            }
            Frame::Padding(count)
        }
        0x01 => Frame::Ping,
        0x02 | 0x03 => {
            let largest = buf.get_varint()?;
            let delay = buf.get_varint()?;
            let range_count = buf.get_varint()?;
            let first_range = buf.get_varint()?;
            let mut ranges = Vec::new();
            for _ in 0..range_count {
                let gap = buf.get_varint()?;
                let range = buf.get_varint()?;
                ranges.push(AckRange { gap, range });
            }
            if typ == 0x03 {
                // ECN counts (ECT0, ECT1, CE): decoded and discarded.
                let _ = buf.get_varint()?;
                let _ = buf.get_varint()?;
                let _ = buf.get_varint()?;
            }
            Frame::Ack {
                largest,
                delay,
                first_range,
                ranges,
            }
        }
        0x04 => {
            let stream_id = buf.get_varint()?;
            let error_code = buf.get_varint()?;
            let final_size = buf.get_varint()?;
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            }
        }
        0x05 => {
            let stream_id = buf.get_varint()?;
            let error_code = buf.get_varint()?;
            Frame::StopSending {
                stream_id,
                error_code,
            }
        }
        0x06 => {
            let offset = buf.get_varint()?;
            let len = buf.get_varint()?;
            let data = buf.get_bytes(len as usize)?;
            Frame::Crypto { offset, data }
        }
        0x07 => {
            let len = buf.get_varint()? as usize;
            if len == 0 {
                return Err(FrameError {
                    code: TransportErrorCode::FrameEncodingError,
                    detail: "NEW_TOKEN empty",
                });
            }
            let token = buf.get_bytes(len)?;
            Frame::NewToken(token)
        }
        0x08..=0x0f => {
            let id = buf.get_varint()?;
            let offset = if typ & 0x04 != 0 {
                buf.get_varint()?
            } else {
                0
            };
            let len = if typ & 0x02 != 0 {
                buf.get_varint()? as usize
            } else {
                buf.remaining()
            };
            let fin = typ & 0x01 != 0;
            let data = buf.get_bytes(len)?;
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            }
        }
        0x10 => Frame::MaxData(buf.get_varint()?),
        0x11 => {
            let id = buf.get_varint()?;
            let max = buf.get_varint()?;
            Frame::MaxStreamData { id, max }
        }
        0x12 | 0x13 => {
            let max = buf.get_varint()?;
            if max > (1u64 << 60) {
                return Err(FrameError {
                    code: TransportErrorCode::FrameEncodingError,
                    detail: "MAX_STREAMS exceeds 2^60",
                });
            }
            Frame::MaxStreams {
                dir: if typ == 0x13 {
                    Direction::Unidirectional
                } else {
                    Direction::Bidirectional
                },
                max,
            }
        }
        0x14 => Frame::DataBlocked(buf.get_varint()?),
        0x15 => {
            let id = buf.get_varint()?;
            let limit = buf.get_varint()?;
            Frame::StreamDataBlocked { id, limit }
        }
        0x16 | 0x17 => {
            let limit = buf.get_varint()?;
            Frame::StreamsBlocked {
                dir: if typ == 0x17 {
                    Direction::Unidirectional
                } else {
                    Direction::Bidirectional
                },
                limit,
            }
        }
        0x18 => {
            // NEW_CONNECTION_ID: seq, retire_prior_to, len, cid, 16-byte token.
            let seq = buf.get_varint()?;
            let retire_prior_to = buf.get_varint()?;
            // RFC 9000 §19.15: retire_prior_to MUST be <= seq.
            if retire_prior_to > seq {
                return Err(FrameError {
                    code: TransportErrorCode::FrameEncodingError,
                    detail: "NEW_CONNECTION_ID: retire_prior_to > seq",
                });
            }
            let cid_len = buf.get_u8()? as usize;
            // RFC 9000 §19.15: CID length must be 1–20 bytes.
            if cid_len == 0 || cid_len > 20 {
                return Err(FrameError {
                    code: TransportErrorCode::FrameEncodingError,
                    detail: "NEW_CONNECTION_ID: invalid CID length (must be 1–20)",
                });
            }
            let cid_bytes = buf.get_bytes(cid_len)?;
            let cid = ConnectionId::from(cid_bytes);
            let token_bytes = buf.get_bytes(16)?;
            let mut stateless_reset_token = [0u8; 16];
            stateless_reset_token.copy_from_slice(token_bytes);
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                stateless_reset_token,
            }
        }
        0x19 => {
            let seq = buf.get_varint()?;
            Frame::RetireConnectionId { seq }
        }
        0x1a => {
            let bytes = buf.get_bytes(8)?;
            let mut data = [0u8; 8];
            data.copy_from_slice(bytes);
            Frame::PathChallenge(data)
        }
        0x1b => {
            let bytes = buf.get_bytes(8)?;
            let mut data = [0u8; 8];
            data.copy_from_slice(bytes);
            Frame::PathResponse(data)
        }
        0x1c | 0x1d => {
            let error_code = buf.get_varint()?;
            let frame_type = if typ == 0x1c {
                Some(buf.get_varint()?)
            } else {
                None
            };
            let reason_len = buf.get_varint()? as usize;
            let reason = buf.get_bytes(reason_len)?.to_vec();
            Frame::ConnectionClose {
                error_code,
                frame_type,
                application: typ == 0x1d,
                reason,
            }
        }
        0x1e => Frame::HandshakeDone,
        0x30 => {
            // DATAGRAM without length field — data runs to end of buffer.
            let data = buf.get_bytes(buf.remaining())?;
            Frame::Datagram(data)
        }
        0x31 => {
            // DATAGRAM with length field.
            let len = buf.get_varint()? as usize;
            let data = buf.get_bytes(len)?;
            Frame::Datagram(data)
        }
        _ => {
            return Err(FrameError {
                code: TransportErrorCode::FrameEncodingError,
                detail: "unknown frame type",
            });
        }
    };
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame<'_>) {
        let mut out = Vec::new();
        frame.encode(&mut out);
        let mut buf = Buf::new(&out);
        let decoded = decode_frame(&mut buf).expect("decode");
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn crypto_roundtrip() {
        roundtrip(Frame::Crypto {
            offset: 1234,
            data: b"ClientHello",
        });
    }

    #[test]
    fn ack_roundtrip() {
        roundtrip(Frame::Ack {
            largest: 100,
            delay: 7,
            first_range: 3,
            ranges: vec![AckRange { gap: 1, range: 2 }, AckRange { gap: 0, range: 0 }],
        });
    }

    #[test]
    fn stream_roundtrip() {
        roundtrip(Frame::Stream {
            id: 0,
            offset: 0,
            fin: true,
            data: b"hello",
        });
    }

    #[test]
    fn close_roundtrip() {
        roundtrip(Frame::ConnectionClose {
            error_code: 0,
            frame_type: Some(0),
            application: false,
            reason: b"bye".to_vec(),
        });
        roundtrip(Frame::ConnectionClose {
            error_code: 42,
            frame_type: None,
            application: true,
            reason: Vec::new(),
        });
    }

    #[test]
    fn padding_coalesces() {
        let bytes = [0u8, 0, 0, 0x01];
        let mut buf = Buf::new(&bytes);
        assert_eq!(decode_frame(&mut buf).expect("pad"), Frame::Padding(3));
        assert_eq!(decode_frame(&mut buf).expect("ping"), Frame::Ping);
    }

    #[test]
    fn flow_control_frames() {
        roundtrip(Frame::MaxData(1 << 20));
        roundtrip(Frame::MaxStreamData { id: 4, max: 65536 });
        roundtrip(Frame::DataBlocked(1000));
        roundtrip(Frame::StreamDataBlocked { id: 0, limit: 500 });
        roundtrip(Frame::HandshakeDone);
    }

    #[test]
    fn reset_stream_roundtrip() {
        roundtrip(Frame::ResetStream {
            stream_id: 4,
            error_code: 0x0c,
            final_size: 1024,
        });
        // Verify frame type byte on wire.
        let mut out = Vec::new();
        Frame::ResetStream {
            stream_id: 0,
            error_code: 1,
            final_size: 0,
        }
        .encode(&mut out);
        assert_eq!(out[0], 0x04);
    }

    #[test]
    fn stop_sending_roundtrip() {
        roundtrip(Frame::StopSending {
            stream_id: 8,
            error_code: 0xff,
        });
        // Verify frame type byte on wire.
        let mut out = Vec::new();
        Frame::StopSending {
            stream_id: 0,
            error_code: 0,
        }
        .encode(&mut out);
        assert_eq!(out[0], 0x05);
    }

    #[test]
    fn path_challenge_response_roundtrip() {
        roundtrip(Frame::PathChallenge([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        ]));
        roundtrip(Frame::PathResponse([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]));
        // Zero data
        roundtrip(Frame::PathChallenge([0u8; 8]));
        // Verify frame type byte in wire encoding
        let mut out = Vec::new();
        Frame::PathChallenge([0xaa; 8]).encode(&mut out);
        assert_eq!(out[0], 0x1a);
        assert_eq!(&out[1..], &[0xaa; 8]);
        let mut out2 = Vec::new();
        Frame::PathResponse([0xbb; 8]).encode(&mut out2);
        assert_eq!(out2[0], 0x1b);
        assert_eq!(&out2[1..], &[0xbb; 8]);
    }

    #[test]
    fn new_connection_id_roundtrip() {
        use oxiquic_core::ConnectionId;
        let cid = ConnectionId::from(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..]);
        let token = [0xaau8; 16];
        roundtrip(Frame::NewConnectionId {
            seq: 1,
            retire_prior_to: 0,
            cid: cid.clone(),
            stateless_reset_token: token,
        });
        // Verify wire type byte.
        let mut out = Vec::new();
        Frame::NewConnectionId {
            seq: 5,
            retire_prior_to: 3,
            cid: cid.clone(),
            stateless_reset_token: token,
        }
        .encode(&mut out);
        assert_eq!(out[0], 0x18, "frame type must be 0x18");
        // Verify retire_prior_to <= seq is enforced during decode.
        let bad_cid_bytes = cid.as_bytes();
        let mut bad = Vec::new();
        put_varint(&mut bad, 0x18);
        put_varint(&mut bad, 2); // seq = 2
        put_varint(&mut bad, 5); // retire_prior_to = 5 > seq: invalid
        bad.push(bad_cid_bytes.len() as u8);
        bad.extend_from_slice(bad_cid_bytes);
        bad.extend_from_slice(&[0u8; 16]);
        let mut buf = Buf::new(&bad);
        assert!(
            decode_frame(&mut buf).is_err(),
            "retire_prior_to > seq must be rejected"
        );
        // Verify CID length 0 is rejected.
        let mut bad2 = Vec::new();
        put_varint(&mut bad2, 0x18);
        put_varint(&mut bad2, 1); // seq
        put_varint(&mut bad2, 0); // retire_prior_to
        bad2.push(0); // cid_len = 0: invalid
        bad2.extend_from_slice(&[0u8; 16]);
        let mut buf2 = Buf::new(&bad2);
        assert!(
            decode_frame(&mut buf2).is_err(),
            "cid_len 0 must be rejected"
        );
    }

    #[test]
    fn retire_connection_id_roundtrip() {
        roundtrip(Frame::RetireConnectionId { seq: 0 });
        roundtrip(Frame::RetireConnectionId { seq: 42 });
        // Verify wire type byte.
        let mut out = Vec::new();
        Frame::RetireConnectionId { seq: 7 }.encode(&mut out);
        assert_eq!(out[0], 0x19, "frame type must be 0x19");
    }

    #[test]
    fn max_streams_bidi_roundtrip() {
        roundtrip(Frame::MaxStreams {
            dir: Direction::Bidirectional,
            max: 100,
        });
        // Check wire type byte is 0x12 for bidi.
        let mut out = Vec::new();
        Frame::MaxStreams {
            dir: Direction::Bidirectional,
            max: 100,
        }
        .encode(&mut out);
        assert_eq!(out[0], 0x12, "bidi MAX_STREAMS must use type 0x12");
    }

    #[test]
    fn max_streams_uni_roundtrip() {
        roundtrip(Frame::MaxStreams {
            dir: Direction::Unidirectional,
            max: 50,
        });
        // Check wire type byte is 0x13 for uni.
        let mut out = Vec::new();
        Frame::MaxStreams {
            dir: Direction::Unidirectional,
            max: 50,
        }
        .encode(&mut out);
        assert_eq!(out[0], 0x13, "uni MAX_STREAMS must use type 0x13");
    }

    #[test]
    fn streams_blocked_roundtrip() {
        roundtrip(Frame::StreamsBlocked {
            dir: Direction::Bidirectional,
            limit: 10,
        });
        roundtrip(Frame::StreamsBlocked {
            dir: Direction::Unidirectional,
            limit: 5,
        });
        // Verify type bytes.
        let mut out_bidi = Vec::new();
        Frame::StreamsBlocked {
            dir: Direction::Bidirectional,
            limit: 0,
        }
        .encode(&mut out_bidi);
        assert_eq!(out_bidi[0], 0x16, "bidi STREAMS_BLOCKED must use type 0x16");
        let mut out_uni = Vec::new();
        Frame::StreamsBlocked {
            dir: Direction::Unidirectional,
            limit: 0,
        }
        .encode(&mut out_uni);
        assert_eq!(out_uni[0], 0x17, "uni STREAMS_BLOCKED must use type 0x17");
    }

    #[test]
    fn max_streams_rejects_over_2_60() {
        // Build a wire frame with max = 2^60 + 1.
        let mut wire = Vec::new();
        put_varint(&mut wire, 0x12); // bidi MAX_STREAMS type
        put_varint(&mut wire, (1u64 << 60) + 1);
        let mut buf = Buf::new(&wire);
        assert!(
            decode_frame(&mut buf).is_err(),
            "MAX_STREAMS with max > 2^60 must be rejected"
        );
    }

    #[test]
    fn datagram_with_length_roundtrip() {
        let payload = b"hello datagram";
        roundtrip(Frame::Datagram(payload));
        // Verify wire type byte is 0x31 (with length).
        let mut out = Vec::new();
        Frame::Datagram(payload).encode(&mut out);
        assert_eq!(out[0], 0x31, "DATAGRAM must use type 0x31 (with length)");
    }

    #[test]
    fn datagram_no_length_decode() {
        // Build a 0x30 frame (no length field) manually.
        let payload = b"no-length datagram";
        let mut wire = Vec::new();
        put_varint(&mut wire, 0x30);
        wire.extend_from_slice(payload);
        let mut buf = Buf::new(&wire);
        let decoded = decode_frame(&mut buf).expect("decode 0x30 datagram");
        assert_eq!(decoded, Frame::Datagram(payload));
        assert!(buf.is_empty());
    }

    #[test]
    fn new_token_roundtrip() {
        let token = b"address-validation-token";
        roundtrip(Frame::NewToken(token));
        // Verify wire type byte is 0x07.
        let mut out = Vec::new();
        Frame::NewToken(token).encode(&mut out);
        assert_eq!(out[0], 0x07, "NEW_TOKEN must use type 0x07");
    }

    #[test]
    fn new_token_rejects_empty() {
        // Build a 0x07 frame with len=0.
        let mut wire = Vec::new();
        put_varint(&mut wire, 0x07);
        put_varint(&mut wire, 0u64); // empty token
        let mut buf = Buf::new(&wire);
        assert!(
            decode_frame(&mut buf).is_err(),
            "NEW_TOKEN with empty token must be rejected"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fuzz-style corpus tests: decode_frame must never panic on arbitrary input.
    // The decoder is expected to return Err on malformed/truncated data — it
    // must never panic or cause undefined behaviour.
    // ─────────────────────────────────────────────────────────────────────────

    /// Deterministic corpus of malformed / truncated / boundary-value inputs.
    ///
    /// Every entry is fed to `decode_frame`; the only invariant is that the
    /// function returns *without panicking*.  It may return `Ok` or `Err`.
    #[test]
    fn decode_frame_never_panics_on_malformed_corpus() {
        let corpus: &[&[u8]] = &[
            // Empty — no bytes at all.
            &[],
            // Single-byte edge cases covering every possible first byte value
            // that isn't a valid (complete) frame.
            &[0xff],
            &[0x80],
            &[0x40],
            // Truncated after the frame type byte (no payload).
            &[0x02], // ACK — needs 4 varints
            &[0x04], // RESET_STREAM — needs 3 varints
            &[0x06], // CRYPTO — needs offset + len
            &[0x07], // NEW_TOKEN — needs a length
            &[0x08], // STREAM — needs stream id
            &[0x0f], // STREAM (all flags set)
            &[0x10], // MAX_DATA — needs 1 varint
            &[0x12], // MAX_STREAMS bidi
            &[0x13], // MAX_STREAMS uni
            &[0x18], // NEW_CONNECTION_ID — needs seq + retire + len + cid + token
            &[0x19], // RETIRE_CONNECTION_ID
            &[0x1a], // PATH_CHALLENGE — needs exactly 8 bytes
            &[0x1b], // PATH_RESPONSE — needs exactly 8 bytes
            &[0x1c], // CONNECTION_CLOSE transport
            &[0x1d], // CONNECTION_CLOSE application
            &[0x31], // DATAGRAM with length
            // Unknown / reserved frame type values.
            &[0x1f],
            &[0x20],
            &[0x2f],
            &[0x32],
            &[0xfe],
            // Truncated NEW_TOKEN: has length field but data is cut short.
            &[0x07, 0x10, 0xaa, 0xbb], // claims 16 bytes, has only 2
            // Truncated CRYPTO: large claimed length.
            &[0x06, 0x00, 0x52, 0x08, 0x01, 0x02], // offset=0, len=large, short data
            // MAX_STREAMS with value exceeding 2^60.
            &[0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            // NEW_CONNECTION_ID with retire_prior_to > seq.
            &[
                0x18, 0x01, 0x05, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            // NEW_CONNECTION_ID with CID length 0.
            &[
                0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            // PATH_CHALLENGE with only 7 bytes of data (one short).
            &[0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            // All-zero 1200-byte buffer (looks like PADDING but exercises the
            // coalescing loop).
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            // All-0xff bytes — no valid QUIC varint sequence.
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            // Plausible-looking but semantically invalid: multi-byte varint that
            // claims a huge payload.
            &[0x06, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
        ];

        for &input in corpus {
            // `decode_frame` must return, not panic.  Either Ok or Err is fine.
            let mut buf = Buf::new(input);
            let _ = decode_frame(&mut buf);
        }
    }

    /// Property-based fuzz: `decode_frame` on arbitrary byte sequences never panics.
    ///
    /// Uses `proptest` to generate random inputs up to 1 400 bytes (MTU-sized).
    /// The test is structured so that panics inside `decode_frame` fail the
    /// property; returning `Ok` or `Err` both satisfy it.
    #[cfg(test)]
    mod property {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn arbitrary_bytes_never_panic(
                data in proptest::collection::vec(any::<u8>(), 0..1400_usize)
            ) {
                let mut buf = Buf::new(&data);
                // Must not panic regardless of content.
                let _ = decode_frame(&mut buf);
            }
        }

        proptest! {
            #[test]
            fn valid_frame_roundtrip_is_identity(
                id in 0u64..=0x3fu64,
                offset in 0u64..=0x0fff_ffff_ffff_ffffu64,
                fin in any::<bool>(),
                payload_len in 0usize..256usize,
            ) {
                let payload: Vec<u8> = (0..payload_len).map(|i| (i & 0xff) as u8).collect();
                let frame = Frame::Stream {
                    id,
                    offset,
                    fin,
                    data: &payload,
                };
                let mut wire = Vec::new();
                frame.encode(&mut wire);
                let mut buf = Buf::new(&wire);
                // A validly-encoded frame must always decode successfully.
                prop_assert!(decode_frame(&mut buf).is_ok());
            }
        }
    }
}
