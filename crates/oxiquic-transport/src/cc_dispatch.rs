//! Congestion-controller dispatch enum.
//!
//! [`CongestionController`] is a single type that routes send/ack/loss events
//! to one of three concrete controllers — NewReno (RFC 9002), CUBIC (RFC 9438),
//! or BBR v2 — based on the [`CongestionAlgorithm`] selected in
//! [`crate::config::TransportConfig`].
//!
//! # API reconciliation
//!
//! The three underlying controllers have slightly different signatures:
//!
//! * **NewReno / Cubic**: `on_packet_sent(bytes)` → `()`; no rate sample.
//! * **BBR**: `on_packet_sent(bytes, now)` → `RateSample`.
//!
//! The dispatch layer bridges this by:
//!
//! * returning `Option<RateSample>` from `on_packet_sent` (`Some` for BBR, `None`
//!   otherwise), which callers store in [`crate::sent_packet::SentPacket`];
//! * accepting `&[(usize, Instant, Option<RateSample>)]` from `on_packets_acked`,
//!   re-packaging them as needed by each controller.

use std::time::Instant;

use crate::bbr::{Bbr, RateSample};
use crate::config::CongestionAlgorithm;
use crate::congestion::NewReno;
use crate::cubic::Cubic;

/// A polymorphic congestion controller that routes events to the algorithm
/// chosen at connection creation time.
pub enum CongestionController {
    /// NewReno (RFC 9002 Appendix B).
    NewReno(NewReno),
    /// CUBIC (RFC 9438).
    Cubic(Cubic),
    /// BBR v2 (model-based, bandwidth/RTT probing). Boxed because `Bbr` is large.
    Bbr(Box<Bbr>),
}

impl CongestionController {
    /// Construct the appropriate controller for `algo`.
    #[must_use]
    pub fn from_config(algo: CongestionAlgorithm) -> Self {
        match algo {
            CongestionAlgorithm::NewReno => Self::NewReno(NewReno::new()),
            CongestionAlgorithm::Cubic => Self::Cubic(Cubic::new()),
            CongestionAlgorithm::Bbr => Self::Bbr(Box::default()),
        }
    }

    /// The current congestion window in bytes.
    #[must_use]
    pub fn congestion_window(&self) -> u64 {
        match self {
            Self::NewReno(nr) => nr.congestion_window(),
            Self::Cubic(c) => c.congestion_window(),
            Self::Bbr(b) => b.congestion_window(),
        }
    }

    /// The bytes currently in flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        match self {
            Self::NewReno(nr) => nr.bytes_in_flight(),
            Self::Cubic(c) => c.bytes_in_flight(),
            Self::Bbr(b) => b.bytes_in_flight(),
        }
    }

    /// Whether a packet of `bytes` may be sent without exceeding the window.
    #[must_use]
    pub fn can_send(&self, bytes: usize) -> bool {
        match self {
            Self::NewReno(nr) => nr.can_send(bytes),
            Self::Cubic(c) => c.can_send(bytes),
            Self::Bbr(b) => b.can_send(bytes),
        }
    }

    /// Account for a freshly-sent packet of `bytes` bytes.
    ///
    /// Returns `Some(RateSample)` when the active controller is BBR (the sample
    /// must be stored in the corresponding `SentPacket` so
    /// it can be returned to BBR on ACK). Returns `None` for NewReno and Cubic.
    pub fn on_packet_sent(&mut self, bytes: usize, now: Instant) -> Option<RateSample> {
        match self {
            Self::Bbr(b) => Some(b.on_packet_sent(bytes, now)),
            Self::NewReno(nr) => {
                nr.on_packet_sent(bytes);
                None
            }
            Self::Cubic(c) => {
                c.on_packet_sent(bytes);
                None
            }
        }
    }

    /// Process newly-acknowledged in-flight packets.
    ///
    /// Each element of `acked` is `(wire_bytes, sent_time, rate_sample)`.
    /// BBR uses the rate sample; NewReno and Cubic ignore it.
    /// `now` is the wall-clock time of the ACK arrival.
    pub fn on_packets_acked(
        &mut self,
        acked: &[(usize, Instant, Option<RateSample>)],
        now: Instant,
    ) {
        match self {
            Self::Bbr(b) => {
                let acked_bbr: Vec<(usize, Instant, RateSample)> = acked
                    .iter()
                    .map(|&(bytes, sent_time, ref rs)| {
                        let sample = rs.unwrap_or_else(|| RateSample::sentinel(sent_time, bytes));
                        (bytes, sent_time, sample)
                    })
                    .collect();
                b.on_packets_acked(&acked_bbr, now);
            }
            Self::NewReno(nr) => {
                let simple: Vec<(usize, Instant)> = acked.iter().map(|&(b, t, _)| (b, t)).collect();
                nr.on_packets_acked(&simple);
            }
            Self::Cubic(c) => {
                let simple: Vec<(usize, Instant)> = acked.iter().map(|&(b, t, _)| (b, t)).collect();
                c.on_packets_acked(&simple, now);
            }
        }
    }

    /// React to loss. `lost_bytes` are removed from bytes-in-flight; the window
    /// is reduced at most once per recovery period.
    pub fn on_packets_lost(
        &mut self,
        lost_bytes: u64,
        largest_lost_sent_time: Instant,
        now: Instant,
    ) {
        match self {
            Self::Bbr(b) => b.on_packets_lost(lost_bytes, largest_lost_sent_time, now),
            Self::NewReno(nr) => nr.on_packets_lost(lost_bytes, largest_lost_sent_time, now),
            Self::Cubic(c) => c.on_packets_lost(lost_bytes, largest_lost_sent_time, now),
        }
    }

    /// Collapse the window to the minimum on persistent congestion
    /// (RFC 9002 §7.6). BBR manages its own recovery state internally, so this
    /// is a no-op for that variant.
    pub fn on_persistent_congestion(&mut self) {
        match self {
            Self::Bbr(_) => {
                // BBR manages recovery internally; the window collapses
                // organically through its Startup/ProbeRTT state machine.
            }
            Self::NewReno(nr) => nr.on_persistent_congestion(),
            Self::Cubic(c) => c.on_persistent_congestion(),
        }
    }
}

impl std::fmt::Debug for CongestionController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewReno(_) => write!(f, "CongestionController::NewReno"),
            Self::Cubic(_) => write!(f, "CongestionController::Cubic"),
            Self::Bbr(_) => write!(f, "CongestionController::Bbr"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_returns_correct_variant() {
        let newreno = CongestionController::from_config(CongestionAlgorithm::NewReno);
        assert!(matches!(newreno, CongestionController::NewReno(_)));

        let cubic = CongestionController::from_config(CongestionAlgorithm::Cubic);
        assert!(matches!(cubic, CongestionController::Cubic(_)));

        let bbr = CongestionController::from_config(CongestionAlgorithm::Bbr);
        assert!(matches!(bbr, CongestionController::Bbr(_)));
    }

    #[test]
    fn cubic_dispatch_can_send_after_ack() {
        let mut cc = CongestionController::from_config(CongestionAlgorithm::Cubic);
        let now = Instant::now();

        // Initially can send one packet.
        assert!(cc.can_send(1200));

        // Send a packet.
        let rs = cc.on_packet_sent(1200, now);
        assert!(rs.is_none(), "Cubic does not produce RateSample");

        // Ack it.
        cc.on_packets_acked(&[(1200, now, None)], now);

        // After ACK, bytes_in_flight is zero and can_send is true.
        assert_eq!(cc.bytes_in_flight(), 0);
        assert!(cc.can_send(1200));
        // cwnd must have grown (slow start).
        assert!(cc.congestion_window() > 12000);
    }

    #[test]
    fn bbr_dispatch_returns_some_rate_sample() {
        let mut cc = CongestionController::from_config(CongestionAlgorithm::Bbr);
        let now = Instant::now();
        let rs = cc.on_packet_sent(1200, now);
        assert!(rs.is_some(), "BBR must return a RateSample on send");
    }

    #[test]
    fn loss_reduces_cubic_window() {
        let mut cc = CongestionController::from_config(CongestionAlgorithm::Cubic);
        let before = cc.congestion_window();
        let now = Instant::now();
        cc.on_packets_lost(1200, now, now + std::time::Duration::from_millis(1));
        assert!(cc.congestion_window() < before);
    }
}
