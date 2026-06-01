//! CUBIC congestion control (RFC 9438).
//!
//! CUBIC uses a cubic function of the elapsed time since the last loss event
//! to grow the congestion window, producing faster recovery than NewReno on
//! high-bandwidth-delay-product paths while remaining TCP-friendly on low-BDP
//! paths.
//!
//! # Key equations (RFC 9438 §5)
//!
//! ```text
//! W_cubic(t) = C × (t − K)³ + W_max
//! K          = cbrt(W_max × (1 − β_cubic) / C)
//! β_cubic    = 0.7      (window reduction factor, RFC 9438 §5.1)
//! C          = 0.4      (scaling constant,        RFC 9438 §5.1)
//! ```
//!
//! After a loss event the slow-start threshold is set to
//! `max(W_max × β_cubic, min_window)` and the window is set equal to that
//! threshold. The cubic epoch then begins from `t = 0`.

use std::time::Instant;

use crate::congestion::{initial_window, minimum_window, MAX_DATAGRAM_SIZE};

// ─── CUBIC constants (RFC 9438 §5.1) ─────────────────────────────────────────

/// Window reduction factor: β_cubic = 0.7.
const BETA_CUBIC: f64 = 0.7;

/// CUBIC scaling constant: C = 0.4.
const CUBIC_C: f64 = 0.4;

// ─────────────────────────────────────────────────────────────────────────────

/// A CUBIC congestion controller (RFC 9438).
#[derive(Debug, Clone)]
pub struct Cubic {
    max_datagram: usize,
    /// Current congestion window in bytes.
    cwnd: u64,
    /// Slow-start threshold; `u64::MAX` means slow start is unbounded.
    ssthresh: u64,
    /// Bytes of ack-eliciting/in-flight data currently outstanding.
    bytes_in_flight: u64,
    /// Window size at the last congestion event (W_max). Measured in bytes.
    w_max: u64,
    /// Start of the current cubic congestion-avoidance epoch.
    /// `None` means we have not yet entered congestion avoidance.
    epoch_start: Option<Instant>,
    /// The K value (in seconds) for the current epoch, derived from w_max.
    k_secs: f64,
    /// The send time after which a loss no longer triggers a fresh window
    /// reduction — i.e. the start of the current recovery period.
    /// `None` outside recovery.
    recovery_start_time: Option<Instant>,
}

impl Cubic {
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
            cwnd: initial_window(max_datagram) as u64,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            w_max: initial_window(max_datagram) as u64,
            epoch_start: None,
            k_secs: 0.0,
            recovery_start_time: None,
        }
    }

    /// The current congestion window in bytes.
    #[must_use]
    pub fn congestion_window(&self) -> u64 {
        self.cwnd
    }

    /// The bytes currently in flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Whether a packet of `bytes` may be sent without exceeding the window.
    #[must_use]
    pub fn can_send(&self, bytes: usize) -> bool {
        self.bytes_in_flight + bytes as u64 <= self.cwnd
    }

    /// Account for a freshly-sent in-flight packet.
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

    /// Compute W_cubic(t) in bytes for elapsed time `t_secs` seconds.
    ///
    /// RFC 9438's constant C = 0.4 is calibrated against a **segment-based**
    /// window (as in the original TCP CUBIC papers). Operating directly in bytes
    /// produces K ≈ 20 s for a typical 12 000-byte initial window, which makes
    /// CUBIC growth indistinguishable from NewReno for normal RTTs.
    ///
    /// We therefore convert to segments before applying the cubic formula and
    /// scale back to bytes, matching what real implementations (quiche, linux
    /// kernel) do:
    ///
    /// ```text
    /// W_max_segs    = W_max / max_datagram
    /// K             = cbrt(W_max_segs × (1 − β) / C)
    /// W_cubic_segs  = C × (t − K)³ + W_max_segs
    /// W_cubic_bytes = W_cubic_segs × max_datagram
    /// ```
    fn w_cubic(&self, t_secs: f64) -> u64 {
        let max_datagram = self.max_datagram as f64;
        let w_max_segs = self.w_max as f64 / max_datagram;
        let delta = t_secs - self.k_secs;
        let cubic_segs = CUBIC_C * delta * delta * delta + w_max_segs;
        // Guard against negative (before K) and saturate for huge values.
        if cubic_segs <= 0.0 {
            minimum_window(self.max_datagram) as u64
        } else {
            let cubic_bytes = cubic_segs * max_datagram;
            if cubic_bytes >= u64::MAX as f64 {
                u64::MAX
            } else {
                cubic_bytes as u64
            }
        }
    }

    /// Compute K (in seconds) for the given `w_max` (in bytes).
    ///
    /// Uses the segment-scaled formula so that K is on the order of a few
    /// seconds for typical congestion-window sizes:
    ///
    /// ```text
    /// K = cbrt(W_max_segs × (1 − β_cubic) / C)
    /// ```
    fn compute_k_secs(w_max: u64, max_datagram: usize) -> f64 {
        let w_max_segs = w_max as f64 / max_datagram as f64;
        let arg = w_max_segs * (1.0 - BETA_CUBIC) / CUBIC_C;
        arg.cbrt()
    }

    /// Process newly-acknowledged in-flight packets.
    /// `acked` is `(bytes, sent_time)` for each packet; `now` is the wall-clock
    /// time of the ACK arrival, used to advance the CUBIC epoch.
    pub fn on_packets_acked(&mut self, acked: &[(usize, Instant)], now: Instant) {
        for &(bytes, sent_time) in acked {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes as u64);
            if self.in_recovery(sent_time) {
                // Do not grow the window for packets sent during recovery.
                continue;
            }
            if self.cwnd < self.ssthresh {
                // Slow start: cwnd += acked bytes (same as NewReno / RFC 9002).
                self.cwnd += bytes as u64;
            } else {
                // Congestion avoidance: use the CUBIC function.
                //
                // Initialise the epoch start and K the first time we enter CA
                // after a loss (or on the very first time).
                if self.epoch_start.is_none() {
                    self.epoch_start = Some(now);
                    self.k_secs = Self::compute_k_secs(self.w_max, self.max_datagram);
                }
                let epoch = self.epoch_start.expect("set above");
                let t_secs = now.saturating_duration_since(epoch).as_secs_f64();
                let target = self.w_cubic(t_secs);

                if target > self.cwnd {
                    self.cwnd = target;
                } else {
                    // TCP-friendly region: grow at least as fast as NewReno would.
                    // W_est increment: max_datagram * acked / cwnd  (≥ 1).
                    let inc = ((self.max_datagram as u64 * bytes as u64) / self.cwnd).max(1);
                    self.cwnd += inc;
                }
            }
        }
    }

    /// React to a loss event. `largest_lost_sent_time` is the send time of the
    /// newest lost packet; the window is reduced at most once per recovery period.
    pub fn on_packets_lost(
        &mut self,
        lost_bytes: u64,
        largest_lost_sent_time: Instant,
        now: Instant,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if self.in_recovery(largest_lost_sent_time) {
            return;
        }
        // Enter a new recovery period.
        self.recovery_start_time = Some(now);
        // W_max = cwnd before the reduction.
        self.w_max = self.cwnd;
        // ssthresh = max(W_max × β_cubic, min_window) per RFC 9438 §5.4.
        let new_ssthresh =
            ((self.cwnd as f64 * BETA_CUBIC) as u64).max(minimum_window(self.max_datagram) as u64);
        self.ssthresh = new_ssthresh;
        self.cwnd = self.ssthresh;
        // Reset the epoch so the next CA entry recalculates K with the new w_max.
        self.epoch_start = None;
        self.k_secs = 0.0;
    }

    /// Collapse the window to the minimum on persistent congestion
    /// (RFC 9002 Section 7.6 semantics, mirrored in CUBIC).
    pub fn on_persistent_congestion(&mut self) {
        self.cwnd = minimum_window(self.max_datagram) as u64;
        self.recovery_start_time = None;
        // Restart slow start.
        self.ssthresh = u64::MAX;
        self.w_max = self.cwnd;
        self.epoch_start = None;
        self.k_secs = 0.0;
    }

    /// The slow-start threshold, exposed for diagnostics/tests.
    #[cfg(test)]
    #[must_use]
    pub fn ssthresh_for_test(&self) -> u64 {
        self.ssthresh
    }

    /// The w_max before the last loss, exposed for diagnostics/tests.
    #[cfg(test)]
    #[must_use]
    pub fn w_max_for_test(&self) -> u64 {
        self.w_max
    }
}

impl Default for Cubic {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// RFC 9002 §7.2: initial window = min(10×max_datagram, max(2×max_datagram, 14720)).
    /// For max_datagram=1200: min(12000, max(2400, 14720)) = 12000.
    #[test]
    fn cubic_initial_window_matches_rfc() {
        let cc = Cubic::with_max_datagram(1200);
        assert_eq!(cc.congestion_window(), 12000);
    }

    /// During slow start each acked byte increments cwnd by one byte.
    #[test]
    fn cubic_slow_start_grows_by_acked() {
        let mut cc = Cubic::with_max_datagram(1200);
        let start = cc.congestion_window();
        cc.on_packet_sent(1200);
        let now = Instant::now();
        cc.on_packets_acked(&[(1200, now)], now);
        assert_eq!(cc.congestion_window(), start + 1200);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    /// On a loss event: ssthresh = max(cwnd × 0.7, min_window), cwnd = ssthresh.
    #[test]
    fn cubic_loss_reduces_by_beta_cubic() {
        let mut cc = Cubic::with_max_datagram(1200);
        let start = cc.congestion_window();
        let t0 = Instant::now();
        cc.on_packet_sent(1200);
        cc.on_packets_lost(1200, t0, t0 + Duration::from_millis(1));

        let min_w = minimum_window(1200) as u64;
        let expected_ssthresh = ((start as f64 * BETA_CUBIC) as u64).max(min_w);
        assert_eq!(cc.ssthresh_for_test(), expected_ssthresh);
        assert_eq!(cc.congestion_window(), expected_ssthresh);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    /// w_max must capture the congestion window size just before the reduction.
    #[test]
    fn cubic_w_max_tracks_window_before_loss() {
        let mut cc = Cubic::with_max_datagram(1200);
        let window_before = cc.congestion_window();
        let t0 = Instant::now();
        cc.on_packet_sent(1200);
        cc.on_packets_lost(1200, t0, t0 + Duration::from_millis(1));
        assert_eq!(cc.w_max_for_test(), window_before);
    }

    /// Only one reduction per recovery period (same as NewReno).
    #[test]
    fn cubic_single_reduction_per_recovery() {
        let mut cc = Cubic::with_max_datagram(1200);
        let start = cc.congestion_window();
        let t0 = Instant::now();
        cc.on_packets_lost(1200, t0, t0 + Duration::from_millis(1));
        let after_first = cc.congestion_window();
        // Second loss with same send time must NOT reduce further.
        cc.on_packets_lost(1200, t0, t0 + Duration::from_millis(2));
        assert_eq!(cc.congestion_window(), after_first);
        // The first reduction was of the original window.
        let _ = start;
    }

    /// In congestion avoidance the CUBIC window should grow (target > ssthresh).
    #[test]
    fn cubic_avoidance_grows_over_time() {
        let mut cc = Cubic::with_max_datagram(1200);
        // Trigger a loss to drop into ssthresh / CA.
        let t0 = Instant::now();
        cc.on_packets_lost(0, t0, t0 + Duration::from_millis(1));
        let after_loss = cc.congestion_window();

        // Ack many packets simulated 500 ms later so W_cubic(t) > current cwnd.
        let later = t0 + Duration::from_millis(500);
        // Simulate sending and acking a batch of packets.
        for _ in 0..10 {
            cc.on_packet_sent(1200);
        }
        cc.on_packets_acked(&vec![(1200, later); 10], later);
        // cwnd must have grown beyond the post-loss value.
        assert!(
            cc.congestion_window() > after_loss,
            "CUBIC CA should grow cwnd: before={after_loss}, after={}",
            cc.congestion_window()
        );
    }
}
