//! Sent-packet tracking for loss detection and recovery (RFC 9002 Section 3,
//! Appendix A.1).
//!
//! To retransmit data lost on a congested or lossy path, the transport must
//! remember which ack-eliciting frames it placed in each packet it sent. This
//! module records, per packet-number space, every in-flight ack-eliciting
//! packet — its packet number, the time it was sent, its size on the wire, and
//! the retransmittable frames it carried ([`SentFrame`]). When an `ACK`
//! acknowledges a packet the record is removed; when loss detection declares a
//! packet lost the connection re-queues the recorded frames for retransmission.
//!
//! The drained-buffer send path (`CryptoStream::take_send` / `SendStream::take`)
//! is paired with this store: each packet built by the connection is registered
//! here with the frames it carried, so nothing is lost without a record to
//! re-queue it from.

use std::collections::BTreeMap;
use std::time::Instant;

use oxiquic_core::{ConnectionId, Direction};

use crate::bbr::RateSample;

/// A retransmittable frame, captured with enough information to re-queue it onto
/// the originating stream if the packet carrying it is lost.
///
/// Only frames that carry reliable data are retained; ack-only and purely
/// administrative frames are not retransmitted (RFC 9002 Section 2). `PADDING`,
/// `ACK` and `CONNECTION_CLOSE` are never recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentFrame {
    /// A `CRYPTO` frame: handshake bytes at `offset` within its space's CRYPTO
    /// stream. The bytes are retained so they can be re-queued verbatim.
    Crypto {
        /// Byte offset within the CRYPTO stream.
        offset: u64,
        /// The handshake bytes carried by the frame.
        data: Vec<u8>,
    },
    /// A `STREAM` frame: application bytes on stream `id` at `offset`, with the
    /// FIN bit if this frame carried the end of the stream.
    Stream {
        /// Stream identifier.
        id: u64,
        /// Byte offset within the stream.
        offset: u64,
        /// Whether this frame carried the stream's FIN.
        fin: bool,
        /// The stream bytes carried by the frame.
        data: Vec<u8>,
    },
    /// A standalone `PING`: ack-eliciting but carries no retransmittable data.
    /// Recorded so the packet counts as in-flight; on loss it is simply dropped
    /// (a fresh probe is sent instead).
    Ping,
    /// A DPLPMTUD path-MTU probe (RFC 8899 §5.2): a PING padded to exactly
    /// `size` bytes. The probe is `ack_eliciting` but `in_flight = false`
    /// (exempt from the congestion window per RFC 8899 §5.2). On loss the MTU
    /// simply stays at `current_mtu`; on ACK it is raised to `size`.
    MtuProbe(u16),
    /// A `NEW_CONNECTION_ID` frame retained for retransmission if the carrying
    /// packet is lost (RFC 9000 §19.15). Holds enough information to re-emit
    /// the frame verbatim.
    NewConnectionId {
        /// Sequence number of the issued CID.
        seq: u64,
        /// The `retire_prior_to` threshold included in the frame.
        retire_prior_to: u64,
        /// The connection ID that was issued.
        cid: ConnectionId,
        /// The 16-byte stateless reset token for this CID.
        stateless_reset_token: [u8; 16],
    },
    /// A `RETIRE_CONNECTION_ID` frame retained for retransmission if the
    /// carrying packet is lost (RFC 9000 §19.16).
    RetireConnectionId {
        /// Sequence number being retired.
        seq: u64,
    },
    /// A `MAX_STREAMS` frame retained for retransmission (RFC 9000 §19.11).
    MaxStreams {
        /// Whether this applies to bidirectional or unidirectional streams.
        dir: Direction,
        /// The maximum stream count advertised.
        max: u64,
    },
    /// A `STREAMS_BLOCKED` frame retained for retransmission (RFC 9000 §19.14).
    StreamsBlocked {
        /// Whether this applies to bidirectional or unidirectional streams.
        dir: Direction,
        /// The limit at which the sender was blocked.
        limit: u64,
    },
    /// A `NEW_TOKEN` frame retained for retransmission (RFC 9000 §19.7).
    NewToken {
        /// The address-validation token.
        token: Vec<u8>,
    },
    // NOTE: No SentFrame::Datagram — datagrams are NOT retransmitted (RFC 9221 §5.2).
}

/// A record of one sent packet retained for loss detection (RFC 9002
/// Appendix A.1.1 `sent_packets`).
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// The packet number assigned in its space.
    pub packet_number: u64,
    /// The instant the packet was handed to the I/O layer.
    pub time_sent: Instant,
    /// Whether the packet is ack-eliciting (contributes to PTO arming).
    pub ack_eliciting: bool,
    /// Whether the packet counts against the congestion controller's
    /// `bytes_in_flight` (true for ack-eliciting packets carrying data; RFC 9002
    /// Section 2 defines in-flight as ack-eliciting or PADDING-bearing).
    pub in_flight: bool,
    /// The packet's size on the wire, in bytes.
    pub sent_bytes: usize,
    /// The retransmittable frames the packet carried.
    pub frames: Vec<SentFrame>,
    /// Per-packet BBR rate sample captured at send time.  `Some` for packets
    /// sent while the BBR controller was active; `None` for all other algorithms
    /// (NewReno, Cubic) where the delivery-rate estimator is not used.
    pub rate_sample: Option<RateSample>,
}

/// Per-space record of sent-but-unacknowledged packets, keyed by packet number.
#[derive(Debug, Default)]
pub struct SentPackets {
    sent: BTreeMap<u64, SentPacket>,
    /// The largest packet number this space has acknowledged from the peer's
    /// ACKs (i.e. the largest the peer told us it received). Used to drive the
    /// packet-number-threshold loss test.
    largest_acked: Option<u64>,
}

/// The outcome of processing an `ACK` frame against the sent-packet store.
#[derive(Debug, Default)]
pub struct AckOutcome {
    /// The packets newly acknowledged by this ACK (were in-flight, now removed).
    pub newly_acked: Vec<SentPacket>,
    /// Whether any of the newly-acked packets was ack-eliciting (RFC 9002
    /// Appendix A.7: only then is the loss timer / PTO state updated).
    pub acked_ack_eliciting: bool,
    /// The largest newly-acked packet number, if any (for RTT sampling, which is
    /// only valid when the largest acknowledged advances).
    pub largest_newly_acked: Option<u64>,
}

impl SentPackets {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet that has just been sent.
    pub fn on_packet_sent(&mut self, packet: SentPacket) {
        self.sent.insert(packet.packet_number, packet);
    }

    /// The largest packet number the peer has acknowledged in this space
    /// (diagnostics/tests).
    #[cfg(test)]
    #[must_use]
    pub fn largest_acked(&self) -> Option<u64> {
        self.largest_acked
    }

    /// Process an `ACK` frame's acknowledged ranges, removing acknowledged
    /// packets from the store and returning what was newly acknowledged.
    ///
    /// `largest` is the ACK's Largest Acknowledged; `(first_range, ranges)` are
    /// the First ACK Range and subsequent `(gap, range)` pairs decoded from the
    /// frame, walking downward from `largest` exactly as on the wire (RFC 9000
    /// Section 19.3).
    pub fn on_ack(&mut self, largest: u64, first_range: u64, ranges: &[(u64, u64)]) -> AckOutcome {
        self.largest_acked = Some(match self.largest_acked {
            Some(prev) => prev.max(largest),
            None => largest,
        });

        let mut outcome = AckOutcome::default();
        // Iterate each acknowledged inclusive range and pull matching records.
        for (low, high) in ack_ranges(largest, first_range, ranges) {
            // Collect the packet numbers in [low, high] present in the store.
            let pns: Vec<u64> = self.sent.range(low..=high).map(|(&pn, _)| pn).collect();
            for pn in pns {
                if let Some(packet) = self.sent.remove(&pn) {
                    if packet.ack_eliciting {
                        outcome.acked_ack_eliciting = true;
                    }
                    outcome.largest_newly_acked = Some(match outcome.largest_newly_acked {
                        Some(prev) => prev.max(pn),
                        None => pn,
                    });
                    outcome.newly_acked.push(packet);
                }
            }
        }
        outcome
    }

    /// Detect lost packets using the packet-number threshold and an externally
    /// computed `loss_delay` time threshold (RFC 9002 Section 6.1, Appendix
    /// A.10). A packet is lost if a packet `kPacketThreshold` numbers larger has
    /// been acknowledged, or it was sent more than `loss_delay` before the
    /// largest acknowledged packet.
    ///
    /// Returns the lost packets (removed from the store) and the earliest send
    /// time among packets that are *not yet* lost but are older than the largest
    /// acked — that time plus `loss_delay` is when the loss timer should next
    /// fire (`loss_time`); `None` if no such packet remains.
    pub fn detect_lost(
        &mut self,
        now: Instant,
        loss_delay: std::time::Duration,
    ) -> (Vec<SentPacket>, Option<Instant>) {
        let largest_acked = match self.largest_acked {
            Some(l) => l,
            None => return (Vec::new(), None),
        };
        const K_PACKET_THRESHOLD: u64 = 3;
        let mut lost = Vec::new();
        let mut next_loss_time: Option<Instant> = None;

        let lost_send_threshold = now.checked_sub(loss_delay);

        let candidates: Vec<u64> = self
            .sent
            .range(..=largest_acked)
            .map(|(&pn, _)| pn)
            .collect();
        for pn in candidates {
            let packet = match self.sent.get(&pn) {
                Some(p) => p,
                None => continue,
            };
            // Packet-number threshold: at least kPacketThreshold newer acked.
            let pn_lost = largest_acked >= pn + K_PACKET_THRESHOLD;
            // Time threshold: sent before (largest_acked_time - loss_delay).
            // We approximate the reference time with `now` (the time loss
            // detection runs, which is when the triggering ACK arrived).
            let time_lost = match lost_send_threshold {
                Some(threshold) => packet.time_sent <= threshold,
                None => false,
            };
            if pn_lost || time_lost {
                if let Some(p) = self.sent.remove(&pn) {
                    lost.push(p);
                }
            } else {
                // Not lost yet; its time threshold is a future loss-timer point.
                let deadline = packet.time_sent + loss_delay;
                next_loss_time = Some(match next_loss_time {
                    Some(t) => t.min(deadline),
                    None => deadline,
                });
            }
        }
        (lost, next_loss_time)
    }

    /// The send time of the earliest outstanding ack-eliciting packet, used to
    /// arm the PTO timer (RFC 9002 Appendix A.6 `time_of_last_ack_eliciting`).
    #[must_use]
    pub fn earliest_ack_eliciting_time(&self) -> Option<Instant> {
        self.sent
            .values()
            .filter(|p| p.ack_eliciting)
            .map(|p| p.time_sent)
            .min()
    }

    /// The retransmittable frames of the lowest-numbered outstanding
    /// ack-eliciting packet, cloned for re-queueing on a PTO probe (RFC 9002
    /// Section 6.2.4). `None` if no ack-eliciting packet is outstanding.
    #[must_use]
    pub fn oldest_ack_eliciting_frames(&self) -> Option<Vec<SentFrame>> {
        self.sent
            .values()
            .find(|p| p.ack_eliciting && !p.frames.is_empty())
            .map(|p| p.frames.clone())
    }

    /// Number of outstanding (unacknowledged, undeclared-lost) packets
    /// (diagnostics/tests).
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.sent.len()
    }
}

/// Expand an ACK frame's `largest`, First ACK Range and `(gap, range)` pairs
/// into inclusive `(low, high)` packet-number ranges (RFC 9000 Section 19.3.1).
fn ack_ranges(largest: u64, first_range: u64, ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(ranges.len() + 1);
    // First range: [largest - first_range, largest].
    let first_low = largest.saturating_sub(first_range);
    out.push((first_low, largest));
    let mut smallest = first_low;
    for &(gap, range) in ranges {
        // Next range's largest = smallest - gap - 2 (RFC 9000 19.3.1).
        // The two gap encodings: gap counts unacked between ranges.
        let next_largest = match smallest.checked_sub(gap + 2) {
            Some(v) => v,
            None => break,
        };
        let next_low = next_largest.saturating_sub(range);
        out.push((next_low, next_largest));
        smallest = next_low;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pkt(pn: u64, now: Instant, ack_eliciting: bool) -> SentPacket {
        SentPacket {
            packet_number: pn,
            time_sent: now,
            ack_eliciting,
            in_flight: ack_eliciting,
            sent_bytes: 1200,
            frames: vec![SentFrame::Stream {
                id: 0,
                offset: pn * 10,
                fin: false,
                data: vec![0u8; 10],
            }],
            rate_sample: None,
        }
    }

    #[test]
    fn ack_range_expansion_contiguous() {
        // largest=4, first_range=4 -> single [0,4].
        assert_eq!(ack_ranges(4, 4, &[]), vec![(0, 4)]);
    }

    #[test]
    fn ack_range_expansion_gapped() {
        // largest=6, first_range=1 -> [5,6]; then gap=1,range=2 -> [0,2].
        let r = ack_ranges(6, 1, &[(1, 2)]);
        assert_eq!(r, vec![(5, 6), (0, 2)]);
    }

    #[test]
    fn on_ack_removes_and_reports_newly_acked() {
        let now = Instant::now();
        let mut store = SentPackets::new();
        for pn in 0..5 {
            store.on_packet_sent(pkt(pn, now, true));
        }
        let outcome = store.on_ack(4, 4, &[]);
        assert_eq!(outcome.newly_acked.len(), 5);
        assert!(outcome.acked_ack_eliciting);
        assert_eq!(outcome.largest_newly_acked, Some(4));
        assert_eq!(store.outstanding(), 0);
        assert_eq!(store.largest_acked(), Some(4));
    }

    #[test]
    fn loss_by_packet_threshold() {
        let now = Instant::now();
        let mut store = SentPackets::new();
        for pn in 0..5 {
            store.on_packet_sent(pkt(pn, now, true));
        }
        // Ack only packet 4 (and 3 via first_range=1 -> [3,4]); leaves 0,1,2.
        // Packet 1 is >= kPacketThreshold (3) behind largest_acked 4 => lost
        // (4 >= 1+3). Packet 2: 4 >= 2+3 is false (5 != true) -> not lost by pn.
        let _ = store.on_ack(4, 1, &[]);
        let (lost, _next) = store.detect_lost(now, Duration::from_millis(100));
        let lost_pns: Vec<u64> = lost.iter().map(|p| p.packet_number).collect();
        assert!(lost_pns.contains(&0), "pn 0 should be lost");
        assert!(lost_pns.contains(&1), "pn 1 should be lost");
        assert!(!lost_pns.contains(&2), "pn 2 not yet lost by threshold");
    }

    #[test]
    fn loss_by_time_threshold() {
        let base = Instant::now();
        let mut store = SentPackets::new();
        // pn0 sent at base, pn1 at base+200ms.
        store.on_packet_sent(pkt(0, base, true));
        store.on_packet_sent(pkt(1, base + Duration::from_millis(200), true));
        // Ack only pn1 (first_range=0 -> [1,1]); pn0 outstanding.
        let _ = store.on_ack(1, 0, &[]);
        // Run loss detection 300ms after base with loss_delay 100ms:
        // threshold = now-100ms = base+200ms; pn0 sent at base <= threshold -> lost.
        let now = base + Duration::from_millis(300);
        let (lost, _next) = store.detect_lost(now, Duration::from_millis(100));
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].packet_number, 0);
    }
}
