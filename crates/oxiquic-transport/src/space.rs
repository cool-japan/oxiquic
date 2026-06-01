//! Packet-number spaces (RFC 9000 Section 12.3) and per-space ACK state.
//!
//! QUIC maintains three independent packet-number spaces — Initial, Handshake
//! and Application (1-RTT) — each with its own monotonic send counter, its own
//! record of received packet numbers, and its own packet-protection keys. This
//! module owns the per-space bookkeeping the connection state machine drives:
//! allocating outgoing packet numbers, recording received numbers and building
//! the ACK ranges that acknowledge them.

use crate::frame::{AckRange, Frame};
use rustls::quic::{DirectionalKeys, Keys, PacketKeySet};

/// Per-space state: keys, send counter and received-packet tracking.
#[derive(Default)]
pub struct PacketSpace {
    /// Local (sealing) and remote (opening) packet-protection keys; `None`
    /// until the keys for this space are installed.
    keys: Option<Keys>,
    /// Next packet number to assign when sending in this space.
    next_packet_number: u64,
    /// Largest packet number acknowledged by the peer (for PN truncation).
    largest_acked: Option<u64>,
    /// Received packet numbers, kept sorted-descending-friendly in a set.
    received: ReceivedPackets,
    /// Whether at least one ack-eliciting packet has been received since the
    /// last ACK we sent (i.e. an ACK is owed).
    ack_pending: bool,
}

impl PacketSpace {
    /// Create an empty space with no keys.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install this space's packet-protection keys.
    pub fn set_keys(&mut self, keys: Keys) {
        self.keys = Some(keys);
    }

    /// Whether keys have been installed for this space.
    #[must_use]
    pub fn has_keys(&self) -> bool {
        self.keys.is_some()
    }

    /// The local (sealing) directional keys, if installed.
    #[must_use]
    pub fn local_keys(&self) -> Option<&DirectionalKeys> {
        self.keys.as_ref().map(|k| &k.local)
    }

    /// The remote (opening) directional keys, if installed.
    #[must_use]
    pub fn remote_keys(&self) -> Option<&DirectionalKeys> {
        self.keys.as_ref().map(|k| &k.remote)
    }

    /// Allocate the next outgoing packet number for this space.
    pub fn next_pn(&mut self) -> u64 {
        let pn = self.next_packet_number;
        self.next_packet_number += 1;
        pn
    }

    /// The largest packet number the peer has acknowledged in this space.
    #[must_use]
    pub fn largest_acked(&self) -> Option<u64> {
        self.largest_acked
    }

    /// The largest packet number received in this space (for PN recovery).
    #[must_use]
    pub fn largest_received(&self) -> Option<u64> {
        self.received.largest()
    }

    /// Record that the peer acknowledged up to `largest`.
    pub fn on_ack_received(&mut self, largest: u64) {
        self.largest_acked = Some(match self.largest_acked {
            Some(prev) => prev.max(largest),
            None => largest,
        });
    }

    /// Record receipt of a packet numbered `pn`. `ack_eliciting` marks whether
    /// the packet obliges us to acknowledge it.
    pub fn on_packet_received(&mut self, pn: u64, ack_eliciting: bool) {
        self.received.insert(pn);
        if ack_eliciting {
            self.ack_pending = true;
        }
    }

    /// Whether an acknowledgement is owed to the peer in this space.
    #[must_use]
    pub fn ack_pending(&self) -> bool {
        self.ack_pending
    }

    /// Build an `ACK` frame acknowledging everything received so far, clearing
    /// the pending-ack flag. Returns `None` if no acknowledgement is owed
    /// (i.e. no ack-eliciting packet has been received since the last ACK)
    /// or if nothing has been received at all.
    ///
    /// RFC 9000 §13.2: an endpoint MUST NOT send an ACK in a space unless it
    /// owes an acknowledgement for an ack-eliciting packet.  Emitting spurious
    /// ACKs on every `poll_transmit` call would cause `collect()` — the
    /// in-process test harness that loops `poll_transmit` until `None` — to
    /// spin forever whenever stream data is flow-control-blocked, because
    /// `space_has_output` remains true (stream data still pending) while
    /// `build_ack` keeps producing non-empty payload.
    pub fn build_ack(&mut self, ack_delay: u64) -> Option<Frame<'static>> {
        if !self.ack_pending {
            return None;
        }
        let frame = self.received.to_ack_frame(ack_delay)?;
        self.ack_pending = false;
        Some(frame)
    }

    /// Rotate to the next key epoch during a 1-RTT key update (RFC 9001 §6).
    ///
    /// Replaces both the local and remote *packet* keys (only; header
    /// protection keys remain the same, per RFC 9001 §6) with the keys from
    /// `next_epoch`.  Returns the old remote packet key so the caller can keep
    /// it briefly for decrypting reordered pre-update packets (§6.6).
    ///
    /// Does nothing and returns `None` if keys are not yet installed.
    pub fn rotate_to_next_epoch(
        &mut self,
        next_epoch: PacketKeySet,
    ) -> Option<Box<dyn rustls::quic::PacketKey>> {
        let keys = self.keys.as_mut()?;
        // Swap remote packet key; save old one for the caller.
        let old_remote = std::mem::replace(&mut keys.remote.packet, next_epoch.remote);
        // Swap local packet key.
        keys.local.packet = next_epoch.local;
        Some(old_remote)
    }
}

/// A compact record of received packet numbers as inclusive ranges, used to
/// build `ACK` frames (RFC 9000 Section 19.3).
#[derive(Debug, Default)]
struct ReceivedPackets {
    /// Inclusive `(low, high)` ranges, kept sorted ascending and merged.
    ranges: Vec<(u64, u64)>,
}

impl ReceivedPackets {
    fn largest(&self) -> Option<u64> {
        self.ranges.last().map(|&(_, high)| high)
    }

    fn insert(&mut self, pn: u64) {
        // Find insertion point; merge with neighbours where adjacent/overlapping.
        for i in 0..self.ranges.len() {
            let (low, high) = self.ranges[i];
            if pn >= low && pn <= high {
                return; // already present
            }
            if pn + 1 == low {
                self.ranges[i].0 = pn;
                self.maybe_merge_prev(i);
                return;
            }
            if pn == high + 1 {
                self.ranges[i].1 = pn;
                self.maybe_merge_next(i);
                return;
            }
            if pn < low {
                self.ranges.insert(i, (pn, pn));
                return;
            }
        }
        self.ranges.push((pn, pn));
    }

    fn maybe_merge_prev(&mut self, i: usize) {
        if i == 0 {
            return;
        }
        if self.ranges[i - 1].1 + 1 >= self.ranges[i].0 {
            self.ranges[i - 1].1 = self.ranges[i - 1].1.max(self.ranges[i].1);
            self.ranges.remove(i);
        }
    }

    fn maybe_merge_next(&mut self, i: usize) {
        if i + 1 >= self.ranges.len() {
            return;
        }
        if self.ranges[i].1 + 1 >= self.ranges[i + 1].0 {
            self.ranges[i].1 = self.ranges[i].1.max(self.ranges[i + 1].1);
            self.ranges.remove(i + 1);
        }
    }

    /// Encode the received ranges as an `ACK` frame walking downward from the
    /// largest received packet number.
    fn to_ack_frame(&self, ack_delay: u64) -> Option<Frame<'static>> {
        let &(low, high) = self.ranges.last()?;
        let largest = high;
        let first_range = high - low;
        let mut ranges = Vec::new();
        // Walk the remaining ranges high-to-low building Gap/Range pairs.
        let mut prev_low = low;
        for &(rlow, rhigh) in self.ranges.iter().rev().skip(1) {
            // Gap = number of missing packets between this range's high+1 and
            // the previous range's low-1, encoded as (prev_low - rhigh - 2).
            let gap = prev_low - rhigh - 2;
            let range = rhigh - rlow;
            ranges.push(AckRange { gap, range });
            prev_low = rlow;
        }
        Some(Frame::Ack {
            largest,
            delay: ack_delay,
            first_range,
            ranges,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pn_allocation_is_monotonic() {
        let mut space = PacketSpace::new();
        assert_eq!(space.next_pn(), 0);
        assert_eq!(space.next_pn(), 1);
        assert_eq!(space.next_pn(), 2);
    }

    #[test]
    fn contiguous_ack() {
        let mut space = PacketSpace::new();
        for pn in 0..=4 {
            space.on_packet_received(pn, true);
        }
        assert!(space.ack_pending());
        let ack = space.build_ack(0).expect("ack");
        match ack {
            Frame::Ack {
                largest,
                first_range,
                ranges,
                ..
            } => {
                assert_eq!(largest, 4);
                assert_eq!(first_range, 4);
                assert!(ranges.is_empty());
            }
            _ => panic!("expected ACK"),
        }
        assert!(!space.ack_pending());
    }

    #[test]
    fn gapped_ack() {
        let mut space = PacketSpace::new();
        // Receive 0,1,2 then 5,6 (gap at 3,4).
        for pn in [0u64, 1, 2, 5, 6] {
            space.on_packet_received(pn, true);
        }
        let ack = space.build_ack(0).expect("ack");
        match ack {
            Frame::Ack {
                largest,
                first_range,
                ranges,
                ..
            } => {
                assert_eq!(largest, 6);
                assert_eq!(first_range, 1); // 6..=5
                assert_eq!(ranges.len(), 1);
                // Gap between low=5 and high=2: 5 - 2 - 2 = 1 missing (3,4 -> gap encodes 1).
                assert_eq!(ranges[0].gap, 1);
                assert_eq!(ranges[0].range, 2); // 2..=0
            }
            _ => panic!("expected ACK"),
        }
    }

    #[test]
    fn out_of_order_insert_merges() {
        let mut space = PacketSpace::new();
        for pn in [2u64, 0, 1, 4, 3] {
            space.on_packet_received(pn, true);
        }
        let ack = space.build_ack(0).expect("ack");
        match ack {
            Frame::Ack {
                largest,
                first_range,
                ranges,
                ..
            } => {
                assert_eq!(largest, 4);
                assert_eq!(first_range, 4); // single merged range 0..=4
                assert!(ranges.is_empty());
            }
            _ => panic!("expected ACK"),
        }
    }
}
