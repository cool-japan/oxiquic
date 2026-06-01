//! Stream management API (RFC 9000 §2–§3).
//!
//! Contains `open_bidi`, `open_uni`, `send_stream`, `read_stream`,
//! `poll_readable`, and `poll_new_peer_stream`.

use oxiquic_core::{Direction, Initiator, OxiQuicError, StreamId};

use crate::flow_control::{StreamRecvFlow, StreamSendFlow};
use crate::stream::{RecvStream, SendStream};

use super::Connection;

impl Connection {
    /// Open a new client/server-initiated bidirectional stream, returning its
    /// id. Data queued on it is flushed by [`Connection::poll_transmit`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if the peer's stream limit has been
    /// reached; a `STREAMS_BLOCKED` frame is queued to signal the peer.
    pub fn open_bidi(&mut self) -> Result<StreamId, OxiQuicError> {
        if self.peer_max_streams_bidi > 0 && self.next_bidi_index >= self.peer_max_streams_bidi {
            // Inform the peer we are blocked.
            self.pending_streams_blocked_bidi = Some(self.peer_max_streams_bidi);
            return Err(OxiQuicError::Stream(format!(
                "bidirectional stream limit reached ({})",
                self.peer_max_streams_bidi
            )));
        }
        let initiator = match self.role {
            super::Role::Client => Initiator::Client,
            super::Role::Server => Initiator::Server,
        };
        let id = StreamId::new(initiator, Direction::Bidirectional, self.next_bidi_index);
        self.next_bidi_index += 1;
        self.send_streams.insert(id.as_u64(), SendStream::new());
        self.recv_streams.insert(id.as_u64(), RecvStream::new());
        // Send-side limit comes from the peer's bidi-remote initial; receive-side
        // from our own advertised stream window (RFC 9000 Section 4.1).
        self.stream_send_flow.insert(
            id.as_u64(),
            StreamSendFlow::new(self.peer_initial_stream_limit()),
        );
        self.stream_recv_flow.insert(
            id.as_u64(),
            StreamRecvFlow::new(self.local_initial_max_stream_data),
        );
        Ok(id)
    }

    /// Open a new client/server-initiated unidirectional (send-only) stream,
    /// returning its id. Data queued on it is flushed by
    /// [`Connection::poll_transmit`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if the peer's stream limit has been
    /// reached; a `STREAMS_BLOCKED` frame is queued to signal the peer.
    pub fn open_uni(&mut self) -> Result<StreamId, OxiQuicError> {
        if self.peer_max_streams_uni > 0 && self.next_uni_index >= self.peer_max_streams_uni {
            self.pending_streams_blocked_uni = Some(self.peer_max_streams_uni);
            return Err(OxiQuicError::Stream(format!(
                "unidirectional stream limit reached ({})",
                self.peer_max_streams_uni
            )));
        }
        let initiator = match self.role {
            super::Role::Client => Initiator::Client,
            super::Role::Server => Initiator::Server,
        };
        let id = StreamId::new(initiator, Direction::Unidirectional, self.next_uni_index);
        self.next_uni_index += 1;
        self.send_streams.insert(id.as_u64(), SendStream::new());
        // Unidirectional streams are send-only on our side; no recv entry.
        self.stream_send_flow.insert(
            id.as_u64(),
            StreamSendFlow::new(self.peer_initial_stream_limit()),
        );
        Ok(id)
    }

    /// Pop the next peer-initiated stream ID that was newly opened, if any.
    /// Returns `None` when no new peer streams are pending acceptance.
    ///
    /// This is used by the driven-connection accept loop to surface new streams
    /// for `h3::quic::Connection::poll_accept_recv` and `poll_accept_bidi`.
    pub fn poll_new_peer_stream(&mut self) -> Option<StreamId> {
        self.new_peer_streams.pop_front()
    }

    /// Queue `data` for transmission on `stream`, optionally marking the end of
    /// the stream with `fin`.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if the stream is unknown.
    pub fn send_stream(
        &mut self,
        stream: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<(), OxiQuicError> {
        let s = self
            .send_streams
            .get_mut(&stream.as_u64())
            .ok_or_else(|| OxiQuicError::Stream(format!("unknown stream {stream}")))?;
        s.write(data, fin);
        Ok(())
    }

    /// Read available in-order bytes from `stream`, returning `(bytes, fin)`.
    /// Returns an empty vector if no new data is available.
    ///
    /// # Errors
    /// - Returns [`OxiQuicError::Stream`] if the stream is unknown.
    /// - Returns [`OxiQuicError::Stream`] with the reset error code if the
    ///   peer sent `RESET_STREAM` on this stream (RFC 9000 §19.4).
    pub fn read_stream(&mut self, stream: StreamId) -> Result<(Vec<u8>, bool), OxiQuicError> {
        let s = self
            .recv_streams
            .get_mut(&stream.as_u64())
            .ok_or_else(|| OxiQuicError::Stream(format!("unknown stream {stream}")))?;
        let (bytes, fin) = s.read_checked().map_err(|e| match e {
            crate::stream::StreamError::Reset(code) => OxiQuicError::Stream(format!(
                "stream {stream} was reset by peer: error_code={code}"
            )),
            crate::stream::StreamError::FinalSize => {
                OxiQuicError::Stream(format!("stream {stream} final-size violation"))
            }
        })?;
        // Account for consumed bytes against receive-side flow control so the
        // window (and our advertised MAX_DATA / MAX_STREAM_DATA) can advance.
        let consumed = bytes.len() as u64;
        if consumed > 0 {
            self.recv_flow.on_data_consumed(consumed);
            if let Some(flow) = self.stream_recv_flow.get_mut(&stream.as_u64()) {
                flow.on_data_consumed(consumed);
            }
        }
        Ok((bytes, fin))
    }

    /// Pop the next stream that has newly-readable data, if any. The endpoint
    /// uses this to notify the application of incoming streams/data.
    pub fn poll_readable(&mut self) -> Option<StreamId> {
        self.readable.pop_front()
    }

    /// Abruptly reset a locally-initiated send stream with an application error
    /// code. Queues a `RESET_STREAM` frame to inform the peer (RFC 9000 §19.4).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if the stream is unknown.
    pub fn reset_stream(&mut self, stream: StreamId, error_code: u64) -> Result<(), OxiQuicError> {
        let s = self
            .send_streams
            .get_mut(&stream.as_u64())
            .ok_or_else(|| OxiQuicError::Stream(format!("unknown stream {stream}")))?;
        let final_size = s.final_size();
        s.reset(error_code);
        self.pending_reset_streams
            .insert(stream.as_u64(), (error_code, final_size));
        Ok(())
    }

    /// Request that the peer stop sending on a stream (RFC 9000 §19.5). Queues
    /// a `STOP_SENDING` frame with the given application error code.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Stream`] if the stream is unknown.
    pub fn stop_sending(&mut self, stream: StreamId, error_code: u64) -> Result<(), OxiQuicError> {
        // Only valid for receive streams.
        let _s = self
            .recv_streams
            .get(&stream.as_u64())
            .ok_or_else(|| OxiQuicError::Stream(format!("unknown stream {stream}")))?;
        self.pending_stop_sending
            .insert(stream.as_u64(), error_code);
        Ok(())
    }
}
