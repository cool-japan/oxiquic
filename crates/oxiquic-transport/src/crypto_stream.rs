//! CRYPTO-stream buffering for the TLS handshake (RFC 9000 Section 7.5, 19.6).
//!
//! Each packet-number space carries its own ordered byte stream of `CRYPTO`
//! frame data feeding rustls's `read_hs`. [`CryptoStream`] reassembles
//! out-of-order `CRYPTO` frames into the contiguous prefix that can be delivered
//! to TLS, and buffers outgoing handshake bytes produced by `write_hs` so they
//! can be chunked into `CRYPTO` frames as space permits.

use std::collections::{BTreeMap, VecDeque};

/// A CRYPTO segment awaiting retransmission after its carrying packet was lost
/// (RFC 9002 Section 6.2): resent at its original offset.
#[derive(Debug, Clone)]
struct ResendSegment {
    offset: u64,
    data: Vec<u8>,
}

/// Ordered reassembly + send buffering for one space's CRYPTO stream.
#[derive(Debug, Default)]
pub struct CryptoStream {
    /// Next contiguous receive offset that has been delivered to TLS.
    recv_offset: u64,
    /// Buffered out-of-order received segments, keyed by start offset.
    recv_pending: BTreeMap<u64, Vec<u8>>,
    /// Outbound handshake bytes not yet sent in a CRYPTO frame.
    send_buf: Vec<u8>,
    /// Absolute offset of the first byte currently in `send_buf`.
    send_base: u64,
    /// Lost CRYPTO segments to retransmit ahead of fresh data (RFC 9002 6.2).
    resend: VecDeque<ResendSegment>,
}

impl CryptoStream {
    /// Create an empty CRYPTO stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a received `CRYPTO` frame at `offset`, returning the newly
    /// contiguous bytes (if any) to hand to `read_hs`.
    ///
    /// Duplicated or already-delivered data is dropped; gaps are buffered until
    /// the missing prefix arrives.
    #[must_use]
    pub fn recv(&mut self, offset: u64, data: &[u8]) -> Option<Vec<u8>> {
        let end = offset + data.len() as u64;
        if end <= self.recv_offset {
            // Entirely old data.
            return None;
        }
        // Trim any prefix we've already delivered.
        let (offset, data) = if offset < self.recv_offset {
            let skip = (self.recv_offset - offset) as usize;
            (self.recv_offset, &data[skip..])
        } else {
            (offset, data)
        };
        if !data.is_empty() {
            self.recv_pending.insert(offset, data.to_vec());
        }

        // Pop contiguous segments starting at recv_offset.
        let mut delivered = Vec::new();
        while let Some((&start, _)) = self.recv_pending.range(..=self.recv_offset).next_back() {
            if start > self.recv_offset {
                break;
            }
            let segment = match self.recv_pending.remove(&start) {
                Some(seg) => seg,
                None => break,
            };
            let seg_end = start + segment.len() as u64;
            if seg_end <= self.recv_offset {
                continue;
            }
            let skip = (self.recv_offset - start) as usize;
            delivered.extend_from_slice(&segment[skip..]);
            self.recv_offset = seg_end;
        }
        if delivered.is_empty() {
            None
        } else {
            Some(delivered)
        }
    }

    /// Queue outbound handshake bytes produced by `write_hs`.
    pub fn enqueue_send(&mut self, data: &[u8]) {
        self.send_buf.extend_from_slice(data);
    }

    /// Whether there are outbound CRYPTO bytes awaiting transmission, including
    /// segments queued for retransmission.
    #[must_use]
    pub fn has_send_data(&self) -> bool {
        !self.resend.is_empty() || !self.send_buf.is_empty()
    }

    /// Re-queue a lost CRYPTO segment for retransmission at `offset` (RFC 9002
    /// Section 6.2). Retransmitted data is emitted before fresh send data.
    pub fn requeue(&mut self, offset: u64, data: Vec<u8>) {
        self.resend.push_back(ResendSegment { offset, data });
    }

    /// Take up to `max` bytes of outbound data as the next CRYPTO frame body,
    /// returning `(offset, bytes)`. Retransmittable segments are emitted first
    /// at their original offset; otherwise fresh buffered data is chunked,
    /// advancing the send cursor.
    #[must_use]
    pub fn take_send(&mut self, max: usize) -> Option<(u64, Vec<u8>)> {
        if max == 0 {
            return None;
        }
        // Retransmit lost segments first, splitting if larger than `max`.
        if let Some(front) = self.resend.front_mut() {
            if front.data.len() <= max {
                let seg = self.resend.pop_front()?;
                return Some((seg.offset, seg.data));
            }
            let chunk: Vec<u8> = front.data.drain(..max).collect();
            let offset = front.offset;
            front.offset += max as u64;
            return Some((offset, chunk));
        }
        if self.send_buf.is_empty() {
            return None;
        }
        let take = max.min(self.send_buf.len());
        let chunk: Vec<u8> = self.send_buf.drain(..take).collect();
        let offset = self.send_base;
        self.send_base += take as u64;
        Some((offset, chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_delivery() {
        let mut s = CryptoStream::new();
        assert_eq!(s.recv(0, b"hello"), Some(b"hello".to_vec()));
        assert_eq!(s.recv(5, b"world"), Some(b"world".to_vec()));
    }

    #[test]
    fn out_of_order_buffered_then_flushed() {
        let mut s = CryptoStream::new();
        assert_eq!(s.recv(5, b"world"), None);
        assert_eq!(s.recv(0, b"hello"), Some(b"helloworld".to_vec()));
    }

    #[test]
    fn duplicate_dropped() {
        let mut s = CryptoStream::new();
        assert_eq!(s.recv(0, b"hello"), Some(b"hello".to_vec()));
        assert_eq!(s.recv(0, b"hello"), None);
        assert_eq!(s.recv(2, b"llo"), None);
    }

    #[test]
    fn partial_overlap() {
        let mut s = CryptoStream::new();
        assert_eq!(s.recv(0, b"abc"), Some(b"abc".to_vec()));
        // Overlaps delivered prefix, extends past it.
        assert_eq!(s.recv(1, b"bcdef"), Some(b"def".to_vec()));
    }

    #[test]
    fn requeue_drains_before_send_buf() {
        let mut s = CryptoStream::new();
        s.enqueue_send(b"fresh-crypto");
        s.requeue(50, b"lost-crypto".to_vec());
        assert!(s.has_send_data());
        let (off, data) = s.take_send(100).expect("resend first");
        assert_eq!((off, &data[..]), (50, &b"lost-crypto"[..]));
        let (off, data) = s.take_send(100).expect("then fresh");
        assert_eq!((off, &data[..]), (0, &b"fresh-crypto"[..]));
    }

    #[test]
    fn send_chunking() {
        let mut s = CryptoStream::new();
        s.enqueue_send(b"handshake-bytes");
        let (off, chunk) = s.take_send(9).expect("chunk");
        assert_eq!(off, 0);
        assert_eq!(chunk, b"handshake");
        let (off, chunk) = s.take_send(100).expect("chunk2");
        assert_eq!(off, 9);
        assert_eq!(chunk, b"-bytes");
        assert!(s.take_send(10).is_none());
    }
}
