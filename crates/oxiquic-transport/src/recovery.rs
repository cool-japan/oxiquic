//! RTT estimation, PTO and loss-detection timing (RFC 9002 Sections 5 and 6,
//! Appendix A).
//!
//! [`RttEstimator`] tracks the latest, minimum, smoothed and variance RTT
//! samples from acknowledgements (RFC 9002 Section 5). [`LossDetection`]
//! combines those with per-space timers to compute the probe-timeout (PTO)
//! deadline (Section 6.2) and the time threshold used by the sent-packet store
//! to declare losses (Section 6.1). The connection drives this module when it
//! processes ACKs and when its loss-detection timer fires.

use std::time::{Duration, Instant};

/// Timer granularity (RFC 9002 Section 6.1.2, `kGranularity`): a system-wide
/// minimum below which timers are not meaningful.
pub const K_GRANULARITY: Duration = Duration::from_millis(1);
/// Time-threshold loss multiplier numerator/denominator (RFC 9002 Section 6.1.2,
/// `kTimeThreshold` = 9/8).
const K_TIME_THRESHOLD_NUM: u32 = 9;
const K_TIME_THRESHOLD_DEN: u32 = 8;
/// The initial RTT assumed before any sample is taken (RFC 9002 Section 6.2.2,
/// `kInitialRtt` = 333 ms).
pub const K_INITIAL_RTT: Duration = Duration::from_millis(333);

/// Smoothed/variance round-trip-time estimator (RFC 9002 Section 5).
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Most recent RTT sample.
    latest_rtt: Duration,
    /// Minimum RTT observed over the connection (Section 5.2).
    min_rtt: Duration,
    /// Exponentially-weighted smoothed RTT (Section 5.3).
    smoothed_rtt: Duration,
    /// Mean RTT variation (Section 5.3).
    rttvar: Duration,
    /// Whether at least one sample has been taken.
    have_sample: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            latest_rtt: Duration::ZERO,
            min_rtt: Duration::ZERO,
            // Before the first sample, smoothed_rtt = kInitialRtt and
            // rttvar = kInitialRtt / 2 (RFC 9002 Section 6.2.2).
            smoothed_rtt: K_INITIAL_RTT,
            rttvar: K_INITIAL_RTT / 2,
            have_sample: false,
        }
    }
}

impl RttEstimator {
    /// Create an estimator seeded with the RFC 9002 initial values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The smoothed RTT estimate.
    #[must_use]
    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    /// The latest RTT sample (zero before the first sample).
    #[must_use]
    pub fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    /// The minimum RTT observed (zero before the first sample).
    #[must_use]
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// The RTT variance estimate.
    #[must_use]
    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// Whether any RTT sample has been recorded (diagnostics/tests).
    #[cfg(test)]
    #[must_use]
    pub fn have_sample(&self) -> bool {
        self.have_sample
    }

    /// Incorporate a new RTT sample (RFC 9002 Section 5.3 `UpdateRtt`).
    ///
    /// `rtt_sample` is the raw `now - time_sent` of the largest newly-acked
    /// packet; `ack_delay` is the peer's reported delay (already scaled by its
    /// `ack_delay_exponent`), and `max_ack_delay` caps it once the handshake is
    /// confirmed. `ack_delay` is only subtracted when doing so leaves a sample
    /// at least `min_rtt`.
    pub fn update(&mut self, rtt_sample: Duration, ack_delay: Duration, max_ack_delay: Duration) {
        self.latest_rtt = rtt_sample;
        if !self.have_sample {
            self.min_rtt = rtt_sample;
            self.smoothed_rtt = rtt_sample;
            self.rttvar = rtt_sample / 2;
            self.have_sample = true;
            return;
        }

        // min_rtt ignores ack_delay (RFC 9002 Section 5.2).
        self.min_rtt = self.min_rtt.min(rtt_sample);

        // Cap ack_delay by max_ack_delay (Section 5.3). The handshake-confirmed
        // condition is handled by the caller passing ZERO for max_ack_delay
        // before confirmation.
        let ack_delay = ack_delay.min(max_ack_delay);
        // adjusted_rtt = latest_rtt, minus ack_delay if it stays >= min_rtt.
        let adjusted_rtt = if self.latest_rtt >= self.min_rtt + ack_delay {
            self.latest_rtt - ack_delay
        } else {
            self.latest_rtt
        };

        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|.
        let rttvar_sample = self.smoothed_rtt.abs_diff(adjusted_rtt);
        self.rttvar = (self.rttvar * 3 + rttvar_sample) / 4;
        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt.
        self.smoothed_rtt = (self.smoothed_rtt * 7 + adjusted_rtt) / 8;
    }

    /// The loss time threshold (RFC 9002 Section 6.1.2): `9/8 *
    /// max(latest_rtt, smoothed_rtt)`, floored at `kGranularity`.
    #[must_use]
    pub fn loss_delay(&self) -> Duration {
        let base = self.latest_rtt.max(self.smoothed_rtt);
        let scaled = base * K_TIME_THRESHOLD_NUM / K_TIME_THRESHOLD_DEN;
        scaled.max(K_GRANULARITY)
    }

    /// The base PTO duration (RFC 9002 Section 6.2.1): `smoothed_rtt + max(4 *
    /// rttvar, kGranularity) + max_ack_delay`. `max_ack_delay` should be the
    /// peer's value (or zero for the Initial/Handshake spaces).
    #[must_use]
    pub fn pto_base(&self, max_ack_delay: Duration) -> Duration {
        self.smoothed_rtt + (self.rttvar * 4).max(K_GRANULARITY) + max_ack_delay
    }
}

/// Coordinates the loss-detection and PTO timers across packet-number spaces
/// (RFC 9002 Section 6.2, Appendix A.6–A.8).
#[derive(Debug, Clone, Default)]
pub struct LossDetection {
    /// Consecutive PTO expirations without an intervening ack-eliciting ack
    /// (drives exponential backoff; RFC 9002 Section 6.2.1).
    pub pto_count: u32,
    /// Per-space time at which a packet should be declared lost by the time
    /// threshold, if any (RFC 9002 Appendix A.9 `loss_time`). Indexed by
    /// [`SpaceIndex`].
    loss_time: [Option<Instant>; 3],
}

/// Index into the per-space timer arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceIndex {
    /// Initial packet-number space.
    Initial = 0,
    /// Handshake packet-number space.
    Handshake = 1,
    /// Application (1-RTT) packet-number space.
    Application = 2,
}

impl LossDetection {
    /// Create a fresh loss-detection state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the next time-threshold loss deadline for a space (set by the
    /// sent-packet store's `detect_lost`; `None` clears it).
    pub fn set_loss_time(&mut self, space: SpaceIndex, time: Option<Instant>) {
        self.loss_time[space as usize] = time;
    }

    /// The earliest pending time-threshold loss deadline across all spaces, with
    /// the space it belongs to (RFC 9002 Appendix A.8 `GetLossTimeAndSpace`).
    #[must_use]
    pub fn earliest_loss_time(&self) -> Option<(Instant, SpaceIndex)> {
        let mut best: Option<(Instant, SpaceIndex)> = None;
        for (i, slot) in self.loss_time.iter().enumerate() {
            if let Some(t) = slot {
                let space = match i {
                    0 => SpaceIndex::Initial,
                    1 => SpaceIndex::Handshake,
                    _ => SpaceIndex::Application,
                };
                best = Some(match best {
                    Some((bt, bs)) if bt <= *t => (bt, bs),
                    _ => (*t, space),
                });
            }
        }
        best
    }

    /// Reset the PTO backoff counter (on a valid ack-eliciting acknowledgement).
    pub fn reset_pto_count(&mut self) {
        self.pto_count = 0;
    }

    /// Increment the PTO backoff counter (on PTO expiry).
    pub fn increase_pto_count(&mut self) {
        self.pto_count = self.pto_count.saturating_add(1);
    }

    /// The PTO timeout for an earliest-send-time, applying exponential backoff
    /// `pto_base * 2^pto_count` (RFC 9002 Section 6.2.1).
    #[must_use]
    pub fn pto_deadline(&self, earliest_sent: Instant, pto_base: Duration) -> Instant {
        let backoff = 1u32 << self.pto_count.min(20);
        earliest_sent + pto_base * backoff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_sets_smoothed_and_var() {
        let mut rtt = RttEstimator::new();
        rtt.update(
            Duration::from_millis(100),
            Duration::from_millis(5),
            Duration::from_millis(25),
        );
        assert!(rtt.have_sample());
        assert_eq!(rtt.smoothed_rtt(), Duration::from_millis(100));
        assert_eq!(rtt.min_rtt(), Duration::from_millis(100));
        assert_eq!(rtt.rttvar(), Duration::from_millis(50));
    }

    #[test]
    fn subsequent_sample_smooths() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, Duration::ZERO);
        // Second sample 200ms, no ack delay: smoothed = 7/8*100 + 1/8*200 = 112.5ms.
        rtt.update(Duration::from_millis(200), Duration::ZERO, Duration::ZERO);
        let s = rtt.smoothed_rtt();
        assert!(
            (s.as_millis() as i64 - 112).abs() <= 1,
            "smoothed ~112ms, got {s:?}"
        );
        assert_eq!(rtt.min_rtt(), Duration::from_millis(100));
    }

    #[test]
    fn ack_delay_subtracted_when_safe() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, Duration::ZERO);
        // latest 150ms, ack_delay 20ms (< max 25), min_rtt 100: 150 >= 100+20 ->
        // adjusted = 130ms. smoothed = 7/8*100 + 1/8*130 = 103.75ms.
        rtt.update(
            Duration::from_millis(150),
            Duration::from_millis(20),
            Duration::from_millis(25),
        );
        let s = rtt.smoothed_rtt().as_millis() as i64;
        assert!((s - 103).abs() <= 1, "smoothed ~103ms, got {s}");
    }

    #[test]
    fn loss_delay_is_nine_eighths() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(80), Duration::ZERO, Duration::ZERO);
        // 9/8 * 80ms = 90ms.
        assert_eq!(rtt.loss_delay(), Duration::from_millis(90));
    }

    #[test]
    fn pto_backoff_doubles() {
        let mut ld = LossDetection::new();
        let base = Duration::from_millis(100);
        let t0 = Instant::now();
        assert_eq!(ld.pto_deadline(t0, base), t0 + Duration::from_millis(100));
        ld.increase_pto_count();
        assert_eq!(ld.pto_deadline(t0, base), t0 + Duration::from_millis(200));
        ld.increase_pto_count();
        assert_eq!(ld.pto_deadline(t0, base), t0 + Duration::from_millis(400));
        ld.reset_pto_count();
        assert_eq!(ld.pto_deadline(t0, base), t0 + Duration::from_millis(100));
    }
}
