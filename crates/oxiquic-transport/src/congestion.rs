//! NewReno congestion control (RFC 9002 Section 7, Appendix B).
//!
//! [`NewReno`] tracks the congestion window, the bytes currently in flight and
//! the slow-start threshold, growing the window in slow start and congestion
//! avoidance and halving it on a loss (entering a recovery period). The
//! connection gates its data-bearing send path on
//! [`NewReno::can_send`] and reports send/ack/loss events so the window
//! tracks the path's capacity. Persistent congestion (RFC 9002 Section 7.6)
//! collapses the window to the minimum.

use std::time::{Duration, Instant};

/// The largest UDP payload OxiQUIC sends, used as `max_datagram_size` in the
/// RFC 9002 window arithmetic.
pub const MAX_DATAGRAM_SIZE: usize = 1200;

/// Loss reduction factor (RFC 9002 Section 7.3.2, `kLossReductionFactor` = 0.5).
const K_LOSS_REDUCTION_NUM: u64 = 1;
const K_LOSS_REDUCTION_DEN: u64 = 2;
/// Persistent-congestion duration multiplier (RFC 9002 Section 7.6,
/// `kPersistentCongestionThreshold` = 3).
pub const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// Compute the RFC 9002 Section 7.2 initial window: `min(10 * max_datagram, max(2
/// * max_datagram, 14720))`.
#[must_use]
pub const fn initial_window(max_datagram: usize) -> usize {
    let two = 2 * max_datagram;
    let lower = if two > 14720 { two } else { 14720 };
    let ten = 10 * max_datagram;
    if ten < lower {
        ten
    } else {
        lower
    }
}

/// The minimum congestion window (RFC 9002 Section 7.2, `kMinimumWindow` = 2 *
/// max_datagram_size).
#[must_use]
pub const fn minimum_window(max_datagram: usize) -> usize {
    2 * max_datagram
}

/// A NewReno congestion controller.
#[derive(Debug, Clone)]
pub struct NewReno {
    max_datagram: usize,
    /// Current congestion window in bytes (RFC 9002 `congestion_window`).
    congestion_window: u64,
    /// Bytes of ack-eliciting/in-flight data currently outstanding.
    bytes_in_flight: u64,
    /// Slow-start threshold; `u64::MAX` means slow start is unbounded.
    ssthresh: u64,
    /// The send time after which a loss no longer triggers a fresh window
    /// reduction — i.e. the start of the current recovery period (RFC 9002
    /// Section 7.3.2 `congestion_recovery_start_time`). `None` outside recovery.
    recovery_start_time: Option<Instant>,
}

impl NewReno {
    /// Create a controller with the RFC 9002 initial window.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_datagram(MAX_DATAGRAM_SIZE)
    }

    /// Create a controller for a specific `max_datagram_size`.
    #[must_use]
    pub fn with_max_datagram(max_datagram: usize) -> Self {
        Self {
            max_datagram,
            congestion_window: initial_window(max_datagram) as u64,
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            recovery_start_time: None,
        }
    }

    /// The current congestion window in bytes.
    #[must_use]
    pub fn congestion_window(&self) -> u64 {
        self.congestion_window
    }

    /// The bytes currently in flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Whether a packet of `bytes` may be sent now without exceeding the
    /// congestion window (RFC 9002 Section 7: a sender must not send when
    /// `bytes_in_flight >= congestion_window`). ACK-only packets and probes
    /// bypass this check at the call site.
    #[must_use]
    pub fn can_send(&self, bytes: usize) -> bool {
        self.bytes_in_flight + bytes as u64 <= self.congestion_window
    }

    /// Account for a freshly-sent in-flight packet of `bytes` (RFC 9002
    /// Appendix B.4 `OnPacketSent`).
    pub fn on_packet_sent(&mut self, bytes: usize) {
        self.bytes_in_flight += bytes as u64;
    }

    /// Whether `sent_time` falls within the current recovery period.
    fn in_recovery(&self, sent_time: Instant) -> bool {
        match self.recovery_start_time {
            Some(start) => sent_time <= start,
            None => false,
        }
    }

    /// Process newly-acknowledged in-flight packets (RFC 9002 Appendix B.5
    /// `OnPacketsAcked`). `acked` is `(bytes, sent_time)` for each. The window
    /// only grows for packets sent after the current recovery period began.
    pub fn on_packets_acked(&mut self, acked: &[(usize, Instant)]) {
        for &(bytes, sent_time) in acked {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes as u64);
            if self.in_recovery(sent_time) {
                // Do not grow the window during recovery.
                continue;
            }
            if self.congestion_window < self.ssthresh {
                // Slow start: cwnd += acked bytes.
                self.congestion_window += bytes as u64;
            } else {
                // Congestion avoidance: cwnd += max_datagram * acked / cwnd.
                let inc = (self.max_datagram as u64 * bytes as u64) / self.congestion_window;
                self.congestion_window += inc.max(1);
            }
        }
    }

    /// React to a packet being declared lost. `largest_lost_sent_time` is the
    /// send time of the newest lost packet; a window reduction occurs at most
    /// once per recovery period (RFC 9002 Appendix B.6 `OnCongestionEvent` +
    /// `OnPacketsLost`). `lost_bytes` is removed from `bytes_in_flight`.
    pub fn on_packets_lost(
        &mut self,
        lost_bytes: u64,
        largest_lost_sent_time: Instant,
        now: Instant,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        self.on_congestion_event(largest_lost_sent_time, now);
    }

    /// Enter a congestion-recovery period if `sent_time` is newer than the
    /// current one, halving the window (RFC 9002 Appendix B.6).
    fn on_congestion_event(&mut self, sent_time: Instant, now: Instant) {
        // No reduction if already in recovery for a packet sent at/after this.
        if self.in_recovery(sent_time) {
            return;
        }
        self.recovery_start_time = Some(now);
        self.ssthresh = (self.congestion_window * K_LOSS_REDUCTION_NUM / K_LOSS_REDUCTION_DEN)
            .max(minimum_window(self.max_datagram) as u64);
        self.congestion_window = self.ssthresh;
    }

    /// Collapse the window to the minimum on persistent congestion (RFC 9002
    /// Section 7.6). The recovery period is reset so the next ack restarts slow
    /// start from the minimum.
    pub fn on_persistent_congestion(&mut self) {
        self.congestion_window = minimum_window(self.max_datagram) as u64;
        self.recovery_start_time = None;
        // Per RFC 9002 7.6, slow-start restarts; leave ssthresh so cwnd<ssthresh.
        self.ssthresh = u64::MAX;
    }

    /// The slow-start threshold, exposed for diagnostics/tests.
    #[cfg(test)]
    #[must_use]
    pub fn ssthresh_for_test(&self) -> u64 {
        self.ssthresh
    }
}

impl Default for NewReno {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether the gap between the oldest and newest lost ack-eliciting packets
/// exceeds the persistent-congestion duration (RFC 9002 Section 7.6). `pto_base`
/// is the un-backed-off PTO (`smoothed_rtt + 4*rttvar + max_ack_delay`).
#[must_use]
pub fn is_persistent_congestion(
    oldest_lost: Instant,
    newest_lost: Instant,
    pto_base: Duration,
) -> bool {
    let threshold = pto_base * K_PERSISTENT_CONGESTION_THRESHOLD;
    newest_lost.saturating_duration_since(oldest_lost) > threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_window_matches_rfc() {
        // 1200-byte datagrams: min(12000, max(2400, 14720)) = 12000.
        assert_eq!(initial_window(1200), 12000);
        // Large datagrams clamp at 14720 lower bound vs 10*size.
        assert_eq!(initial_window(1500), 14720);
    }

    #[test]
    fn slow_start_grows_by_acked() {
        let mut cc = NewReno::with_max_datagram(1200);
        let start = cc.congestion_window();
        cc.on_packet_sent(1200);
        let now = Instant::now();
        cc.on_packets_acked(&[(1200, now)]);
        assert_eq!(cc.congestion_window(), start + 1200);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn loss_halves_window_into_recovery() {
        let mut cc = NewReno::with_max_datagram(1200);
        let start = cc.congestion_window();
        let t0 = Instant::now();
        cc.on_packet_sent(1200);
        cc.on_packets_lost(1200, t0, t0 + Duration::from_millis(1));
        assert_eq!(cc.congestion_window(), start / 2);
        assert_eq!(cc.ssthresh_for_test(), start / 2);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn single_reduction_per_recovery_period() {
        let mut cc = NewReno::with_max_datagram(1200);
        let start = cc.congestion_window();
        let t0 = Instant::now();
        // Two losses from the same pre-recovery send time only halve once.
        cc.on_packets_lost(1200, t0, t0 + Duration::from_millis(1));
        cc.on_packets_lost(1200, t0, t0 + Duration::from_millis(2));
        assert_eq!(cc.congestion_window(), start / 2);
    }

    #[test]
    fn congestion_avoidance_grows_slowly() {
        let mut cc = NewReno::with_max_datagram(1200);
        // Force into congestion avoidance: ssthresh below current window.
        let t0 = Instant::now();
        cc.on_packets_lost(0, t0, t0 + Duration::from_millis(1));
        let cwnd_after_loss = cc.congestion_window();
        // Ack a full datagram sent after recovery start.
        let later = t0 + Duration::from_millis(100);
        cc.on_packet_sent(1200);
        cc.on_packets_acked(&[(1200, later)]);
        // In CA, growth is ~ max_datagram*acked/cwnd << acked.
        let grew = cc.congestion_window() - cwnd_after_loss;
        assert!((1..1200).contains(&grew), "CA growth small, got {grew}");
    }

    #[test]
    fn cannot_send_when_full() {
        let mut cc = NewReno::with_max_datagram(1200);
        let cwnd = cc.congestion_window();
        cc.on_packet_sent(cwnd as usize);
        assert!(!cc.can_send(1));
        assert_eq!(cc.bytes_in_flight(), cwnd);
    }

    #[test]
    fn persistent_congestion_detection() {
        let t0 = Instant::now();
        let pto = Duration::from_millis(100);
        // 3 * 100ms = 300ms threshold.
        assert!(is_persistent_congestion(
            t0,
            t0 + Duration::from_millis(400),
            pto
        ));
        assert!(!is_persistent_congestion(
            t0,
            t0 + Duration::from_millis(200),
            pto
        ));
    }
}
