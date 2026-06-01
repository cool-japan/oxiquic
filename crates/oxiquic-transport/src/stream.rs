//! QUIC stream send/receive state machines (RFC 9000 Sections 2–3, 19.8).
//!
//! [`SendStream`] buffers outbound application bytes and hands them out as
//! `STREAM` frame bodies at increasing offsets, tracking the final (FIN)
//! offset. [`RecvStream`] performs ordered reassembly of inbound `STREAM`
//! frames, exposing the contiguous prefix to the application and enforcing the
//! RFC 9000 final-size invariant.

use std::collections::{BTreeMap, VecDeque};

/// An error in stream receive processing that maps to a transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// The peer changed or violated the stream's final size (RFC 9000 4.5).
    FinalSize,
    /// The peer reset the stream with an application error code (RFC 9000 §19.4).
    Reset(u64),
}

/// A segment of stream data that must be retransmitted because the packet that
/// originally carried it was declared lost (RFC 9002 Section 6.2): the original
/// `(offset, bytes, fin)` is re-queued so it is resent at the same offset.
#[derive(Debug, Clone)]
struct ResendSegment {
    offset: u64,
    data: Vec<u8>,
    fin: bool,
}

/// Outbound half of a stream: an ordered byte buffer plus FIN tracking.
///
/// Lost data is fed back via [`SendStream::requeue`] into a retransmit queue
/// that is drained ahead of fresh data, so a retransmitted `STREAM` frame
/// carries the original offset.
#[derive(Debug, Default)]
pub struct SendStream {
    /// Bytes queued but not yet emitted in a STREAM frame.
    buf: Vec<u8>,
    /// Absolute offset of the first byte currently in `buf`.
    base: u64,
    /// Whether the application has signalled FIN.
    fin: bool,
    /// Whether a STREAM frame carrying the FIN has been emitted.
    fin_sent: bool,
    /// Segments awaiting retransmission, drained before `buf` (RFC 9002 6.2).
    resend: VecDeque<ResendSegment>,
    /// Set when the application or peer (via STOP_SENDING) resets the stream.
    /// Once set, `take()` returns `None` and `has_pending()` returns false —
    /// suppressing any further STREAM frames (RFC 9000 §3.5).
    reset_code: Option<u64>,
}

impl SendStream {
    /// Create an empty send stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue `data` for sending; `fin` marks the end of the stream.
    pub fn write(&mut self, data: &[u8], fin: bool) {
        self.buf.extend_from_slice(data);
        if fin {
            self.fin = true;
        }
    }

    /// Whether this stream has data or a FIN still to transmit, including any
    /// segments queued for retransmission. Returns false when the stream has
    /// been reset (no further STREAM frames should be emitted).
    #[must_use]
    pub fn has_pending(&self) -> bool {
        if self.reset_code.is_some() {
            return false;
        }
        !self.resend.is_empty() || !self.buf.is_empty() || (self.fin && !self.fin_sent)
    }

    /// Mark this stream as locally reset with the given application error code.
    /// After this call `take()` returns `None` and `has_pending()` returns
    /// `false`, preventing any further STREAM frames from being emitted.
    pub fn reset(&mut self, error_code: u64) {
        self.reset_code = Some(error_code);
        // Discard buffered data and the retransmit queue; the RESET_STREAM
        // frame replaces the stream's data entirely.
        self.buf.clear();
        self.resend.clear();
    }

    /// Whether this stream has been reset (locally or by the peer's
    /// STOP_SENDING triggering a local reset).
    #[must_use]
    pub fn is_reset(&self) -> bool {
        self.reset_code.is_some()
    }

    /// The reset error code, if the stream has been reset.
    #[must_use]
    pub fn reset_code(&self) -> Option<u64> {
        self.reset_code
    }

    /// The current highest byte offset committed to the send side (used to
    /// supply the `final_size` field of RESET_STREAM).
    #[must_use]
    pub fn final_size(&self) -> u64 {
        self.base + self.buf.len() as u64
    }

    /// Re-queue a lost `STREAM` segment for retransmission at its original
    /// `offset` (RFC 9002 Section 6.2). Retransmitted data is sent before any
    /// fresh buffered data.
    pub fn requeue(&mut self, offset: u64, data: Vec<u8>, fin: bool) {
        self.resend.push_back(ResendSegment { offset, data, fin });
    }

    /// Whether the next data to emit is a retransmission (already-authorised
    /// offsets), which is exempt from flow control (RFC 9000 Section 4.1).
    #[must_use]
    pub fn has_resend(&self) -> bool {
        !self.resend.is_empty()
    }

    /// Take up to `max` bytes as the next STREAM frame body, returning
    /// `(offset, data, fin)`. Retransmittable segments are emitted first (at
    /// their original offset); otherwise fresh buffered data is chunked. A
    /// pure-FIN frame (`data` empty, `fin` true) is produced once the buffer
    /// drains if FIN was requested. Returns `None` when the stream has been
    /// reset (use `RESET_STREAM` instead of further `STREAM` frames).
    #[must_use]
    pub fn take(&mut self, max: usize) -> Option<(u64, Vec<u8>, bool)> {
        // Honour a local reset: suppress all further STREAM frames.
        if self.reset_code.is_some() {
            return None;
        }
        // Retransmit lost segments first, splitting if they exceed `max`.
        if let Some(front) = self.resend.front_mut() {
            if max == 0 {
                return None;
            }
            if front.data.len() <= max {
                let seg = self.resend.pop_front()?;
                return Some((seg.offset, seg.data, seg.fin));
            }
            // Emit a prefix; keep the remainder (FIN stays with the tail).
            let chunk: Vec<u8> = front.data.drain(..max).collect();
            let offset = front.offset;
            front.offset += max as u64;
            return Some((offset, chunk, false));
        }

        if self.buf.is_empty() {
            if self.fin && !self.fin_sent {
                self.fin_sent = true;
                return Some((self.base, Vec::new(), true));
            }
            return None;
        }
        let take = max.min(self.buf.len());
        if take == 0 {
            return None;
        }
        let chunk: Vec<u8> = self.buf.drain(..take).collect();
        let offset = self.base;
        self.base += take as u64;
        let fin = self.fin && self.buf.is_empty();
        if fin {
            self.fin_sent = true;
        }
        Some((offset, chunk, fin))
    }
}

/// Inbound half of a stream: ordered reassembly with final-size enforcement.
#[derive(Debug, Default)]
pub struct RecvStream {
    /// Next contiguous offset not yet delivered to the application.
    read_offset: u64,
    /// Buffered out-of-order segments keyed by start offset.
    pending: BTreeMap<u64, Vec<u8>>,
    /// Contiguous, reassembled bytes ready for the application to read.
    ready: Vec<u8>,
    /// The stream's final size, once known from a FIN frame.
    final_size: Option<u64>,
    /// Whether the FIN has been delivered to the application.
    fin_delivered: bool,
    /// Set when the peer sends RESET_STREAM; the error code is stored here and
    /// surfaced on the next `read_stream` call (RFC 9000 §19.4).
    reset_code: Option<u64>,
}

impl RecvStream {
    /// Create an empty receive stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the peer reset the stream with the given application error
    /// code (RFC 9000 §19.4). Discards any buffered reassembly data; the next
    /// call to `read_checked` will return `Err(StreamError::Reset(code))`.
    pub fn apply_reset(&mut self, error_code: u64) {
        self.reset_code = Some(error_code);
        self.ready.clear();
        self.pending.clear();
    }

    /// Whether the peer has reset this stream.
    #[must_use]
    pub fn is_reset(&self) -> bool {
        self.reset_code.is_some()
    }

    /// Take all currently-readable contiguous bytes, returning `(bytes, fin)`
    /// where `fin` is true once the end of the stream has been reached. Returns
    /// `Err(StreamError::Reset(code))` if the peer reset the stream.
    ///
    /// # Errors
    /// Returns [`StreamError::Reset`] if the peer has sent `RESET_STREAM`.
    pub fn read_checked(&mut self) -> Result<(Vec<u8>, bool), StreamError> {
        if let Some(code) = self.reset_code {
            return Err(StreamError::Reset(code));
        }
        Ok(self.read())
    }

    /// Accept a received `STREAM` frame. Returns `Ok(true)` if new contiguous
    /// data (or the FIN) became available to the application.
    ///
    /// # Errors
    /// Returns [`StreamError::FinalSize`] if `fin` contradicts a previously
    /// observed final size or if data extends beyond the final size.
    pub fn recv(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<bool, StreamError> {
        let end = offset + data.len() as u64;
        if let Some(fsize) = self.final_size {
            if end > fsize {
                return Err(StreamError::FinalSize);
            }
            if fin && end != fsize {
                return Err(StreamError::FinalSize);
            }
        }
        if fin {
            match self.final_size {
                Some(fsize) if fsize != end => return Err(StreamError::FinalSize),
                _ => self.final_size = Some(end),
            }
        }

        let before = self.ready.len();
        let fin_before = self.fin_delivered;

        if end > self.read_offset {
            let (offset, data) = if offset < self.read_offset {
                let skip = (self.read_offset - offset) as usize;
                (self.read_offset, &data[skip..])
            } else {
                (offset, data)
            };
            if !data.is_empty() {
                self.pending.insert(offset, data.to_vec());
            }
            self.flush_contiguous();
        }

        // FIN becomes deliverable once all bytes up to final_size are contiguous.
        if let Some(fsize) = self.final_size {
            if self.read_offset >= fsize {
                self.fin_delivered = true;
            }
        }

        Ok(self.ready.len() > before || (self.fin_delivered && !fin_before))
    }

    fn flush_contiguous(&mut self) {
        while let Some((&start, _)) = self.pending.range(..=self.read_offset).next_back() {
            if start > self.read_offset {
                break;
            }
            let segment = match self.pending.remove(&start) {
                Some(seg) => seg,
                None => break,
            };
            let seg_end = start + segment.len() as u64;
            if seg_end <= self.read_offset {
                continue;
            }
            let skip = (self.read_offset - start) as usize;
            self.ready.extend_from_slice(&segment[skip..]);
            self.read_offset = seg_end;
        }
    }

    /// Take all currently-readable contiguous bytes, returning `(bytes, fin)`
    /// where `fin` is true once the end of the stream has been reached and all
    /// data delivered.
    pub fn read(&mut self) -> (Vec<u8>, bool) {
        let bytes = std::mem::take(&mut self.ready);
        let fin = self.fin_delivered && self.pending.is_empty();
        (bytes, fin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_stream_chunks_with_fin() {
        let mut s = SendStream::new();
        s.write(b"hello", true);
        let (off, data, fin) = s.take(3).expect("chunk");
        assert_eq!((off, &data[..], fin), (0, &b"hel"[..], false));
        let (off, data, fin) = s.take(100).expect("chunk2");
        assert_eq!((off, &data[..], fin), (3, &b"lo"[..], true));
        assert!(!s.has_pending());
    }

    #[test]
    fn send_stream_pure_fin() {
        let mut s = SendStream::new();
        s.write(b"", true);
        let (off, data, fin) = s.take(10).expect("fin frame");
        assert_eq!((off, data.len(), fin), (0, 0, true));
        assert!(!s.has_pending());
    }

    #[test]
    fn recv_in_order() {
        let mut s = RecvStream::new();
        assert!(s.recv(0, b"hello", false).expect("recv"));
        let (bytes, fin) = s.read();
        assert_eq!(bytes, b"hello");
        assert!(!fin);
    }

    #[test]
    fn recv_out_of_order_reassembles() {
        let mut s = RecvStream::new();
        assert!(!s.recv(5, b"world", true).expect("recv tail"));
        // Tail buffered; nothing readable yet (gap at 0..5).
        let (bytes, _) = s.read();
        assert!(bytes.is_empty());
        assert!(s.recv(0, b"hello", false).expect("recv head"));
        let (bytes, fin) = s.read();
        assert_eq!(bytes, b"helloworld");
        assert!(fin);
    }

    #[test]
    fn requeued_segment_sent_before_fresh_data() {
        let mut s = SendStream::new();
        s.write(b"fresh", false);
        // Simulate a lost segment at offset 100 being re-queued.
        s.requeue(100, b"lost".to_vec(), false);
        assert!(s.has_pending());
        // Retransmit drains first, at the original offset.
        let (off, data, _fin) = s.take(100).expect("resend");
        assert_eq!((off, &data[..]), (100, &b"lost"[..]));
        // Then the fresh data.
        let (off, data, _fin) = s.take(100).expect("fresh");
        assert_eq!((off, &data[..]), (0, &b"fresh"[..]));
    }

    #[test]
    fn requeued_segment_splits_under_max() {
        let mut s = SendStream::new();
        s.requeue(10, b"abcdef".to_vec(), true);
        let (off, data, fin) = s.take(4).expect("first half");
        assert_eq!((off, &data[..], fin), (10, &b"abcd"[..], false));
        let (off, data, fin) = s.take(100).expect("tail keeps fin");
        assert_eq!((off, &data[..], fin), (14, &b"ef"[..], true));
    }

    #[test]
    fn recv_final_size_violation() {
        let mut s = RecvStream::new();
        s.recv(0, b"hello", true).expect("fin at 5");
        // Data beyond the final size is a violation.
        assert_eq!(s.recv(5, b"!", false), Err(StreamError::FinalSize));
    }

    // ── reset state accessors ─────────────────────────────────────────────────

    /// `SendStream::is_reset` and `::reset_code` reflect the reset applied via
    /// `SendStream::reset`.  After reset, `take` must return `None`.
    #[test]
    fn send_stream_reset_suppresses_take() {
        let mut s = SendStream::new();
        s.write(b"data", false);
        assert!(!s.is_reset());
        assert_eq!(s.reset_code(), None);

        s.reset(42);
        assert!(s.is_reset());
        assert_eq!(s.reset_code(), Some(42));
        // take must return None after reset (RFC 9000 §3.3).
        assert!(s.take(100).is_none());
    }

    /// `RecvStream::is_reset` reflects the reset applied via `apply_reset`.
    /// After reset, `read_checked` must surface the error code.
    #[test]
    fn recv_stream_reset_surfaces_error_code() {
        let mut s = RecvStream::new();
        s.recv(0, b"partial", false).expect("partial recv");
        assert!(!s.is_reset());

        s.apply_reset(7);
        assert!(s.is_reset());

        let err = s.read_checked().expect_err("should be reset error");
        assert_eq!(err, StreamError::Reset(7));
    }
}
