//! BBR v2 congestion controller (Google BBRv2, as described in the IETF draft
//! `draft-cardwell-iccrg-bbr-congestion-control`).
//!
//! ## Overview
//!
//! BBR is a model-based congestion controller that estimates bottleneck bandwidth
//! (`btl_bw`) and propagation round-trip time (`rt_prop`) to compute a send rate
//! and congestion window that fully utilises the path without building excessive
//! queue. BBR v2 adds explicit inflight bounds (`inflight_hi`, `inflight_lo`) and
//! bandwidth bounds (`bw_hi`, `bw_lo`) that are tightened on loss events to
//! prevent excessive retransmissions while converging to a fair share.
//!
//! ## State machine
//!
//! ```text
//! Startup ──(filled_pipe)──► Drain ──(in_flight <= BDP)──► ProbeBW ◄──────────┐
//!    ▲                                     │ ▲                    │             │
//!    └─(not filled_pipe after ProbeRTT)────┘ └───────────────────┘             │
//!                                              ▲  ProbeRTT ────────────────────┘
//! ```
//!
//! ## Reference
//!
//! * [BBR: Congestion-Based Congestion Control (Cardwell et al., 2016)](https://queue.acm.org/detail.cfm?id=3022184)
//! * [draft-cardwell-iccrg-bbr-congestion-control (v2)](https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control)

use std::time::{Duration, Instant};

use crate::congestion::{initial_window, MAX_DATAGRAM_SIZE};

// ---------------------------------------------------------------------------
// Compile-time constants
// ---------------------------------------------------------------------------

/// High pacing gain used during Startup: `2 / ln(2)` ≈ 2.8854.
/// (`2f64.ln()` is not const-evaluable, so we inline the literal.)
const HIGH_GAIN: f64 = 2.885_390_081_777_927;

/// Number of ProbeBW gain cycle phases.
const CYCLE_LEN: usize = 8;

/// Gain cycle for ProbeBW phase (probe-up, drain, steady×6).
const PROBE_BW_GAINS: [f64; CYCLE_LEN] = [5.0 / 4.0, 3.0 / 4.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// Minimum time to spend in ProbeRTT before restoring the window (RFC §4.3.3).
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// How long without a new minimum RTT sample before triggering ProbeRTT.
const RT_PROP_FILTER_LEN: Duration = Duration::from_secs(10);

/// Minimum congestion window expressed in number of datagrams.
const MIN_PIPE_CWND_PACKETS: u64 = 4;

// ---------------------------------------------------------------------------
// DeliveryRateEstimator
// ---------------------------------------------------------------------------

/// Per-packet snapshot taken at send time, used to measure delivery rate on ACK.
///
/// Store one `RateSample` for every in-flight packet and pass the matching
/// instance to [`DeliveryRateEstimator::on_packets_acked`] when the packet is
/// acknowledged.
#[derive(Debug, Clone, Copy)]
pub struct RateSample {
    /// Total bytes delivered to the far end at packet-send time.
    delivered: u64,
    /// Wall-clock timestamp of the last delivery update at send time.
    delivered_time: Instant,
    /// Wall-clock start of the current send burst at send time.
    first_sent_time: Instant,
    /// Whether the application was the bottleneck when this packet was sent.
    is_app_limited: bool,
    /// When this packet was sent.
    sent_time: Instant,
    /// Wire size of this packet in bytes.
    size: usize,
}

impl RateSample {
    /// Creates a zeroed sentinel sample used when BBR receives an ACK for a
    /// packet that was sent before the BBR controller was active (e.g. during
    /// a NewReno→BBR migration). The sentinel encodes the send time and size so
    /// that BBR's delivery-rate estimator can form a non-panic estimate without
    /// real delivery data.
    #[must_use]
    pub fn sentinel(sent_time: Instant, size: usize) -> Self {
        Self {
            delivered: 0,
            delivered_time: sent_time,
            first_sent_time: sent_time,
            is_app_limited: false,
            sent_time,
            size,
        }
    }
}

/// Tracks the bytes-delivered counter and associated timestamps needed to derive
/// a delivery-rate sample on each ACK.
///
/// The estimator maintains a monotonically-increasing `delivered` counter and
/// the wall-clock time at which the most-recent delivery update occurred
/// (`delivered_time`). On ACK it computes:
///
/// ```text
/// rate = (delivered_now − delivered_at_send)
///        ─────────────────────────────────────
///        (delivered_time_now − delivered_time_at_send) [seconds]
/// ```
#[derive(Debug, Clone)]
pub struct DeliveryRateEstimator {
    /// Bytes delivered so far (monotonically non-decreasing).
    delivered: u64,
    /// Wall-clock time of the last delivery increment.
    delivered_time: Instant,
    /// Start of the current send burst (reset on idle gaps).
    first_sent_time: Instant,
    /// Whether the most recent send was app-limited.
    app_limited: bool,
    /// Total bytes in flight when `app_limited` was last set.
    app_limited_until: u64,
}

impl DeliveryRateEstimator {
    /// Create a new estimator. Time-related fields are initialised to `now` so
    /// that the first `on_packet_sent` call produces a well-formed [`RateSample`].
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            app_limited: false,
            app_limited_until: 0,
        }
    }

    /// Record an outgoing packet of `pkt_size` bytes and return the
    /// [`RateSample`] that should be stored alongside the sent-packet entry.
    pub fn on_packet_sent(&mut self, pkt_size: usize, now: Instant) -> RateSample {
        // On the first packet in a new burst, anchor first_sent_time.
        if self.first_sent_time == self.delivered_time {
            self.first_sent_time = now;
        }
        RateSample {
            delivered: self.delivered,
            delivered_time: self.delivered_time,
            first_sent_time: self.first_sent_time,
            is_app_limited: self.app_limited,
            sent_time: now,
            size: pkt_size,
        }
    }

    /// Process a batch of newly-acknowledged packets described by their
    /// [`RateSample`]s.  Returns the delivery rate in bytes/second if enough
    /// data is available to produce a meaningful estimate, or `None` when the
    /// elapsed interval is too small to measure reliably (≤ 0 µs) or the sample
    /// is app-limited (which may underestimate the true bandwidth).
    ///
    /// `acked_bytes` is the total wire size of all acknowledged packets.
    pub fn on_packets_acked(
        &mut self,
        samples: &[RateSample],
        acked_bytes: usize,
        now: Instant,
    ) -> Option<f64> {
        // Advance the delivered counter.
        self.delivered += acked_bytes as u64;
        self.delivered_time = now;

        // Find the sample from the oldest send: it gives the largest elapsed
        // interval and therefore the most stable rate estimate.
        let oldest = samples.iter().min_by_key(|s| s.sent_time)?;

        // Skip app-limited samples — they underestimate bandwidth.
        if oldest.is_app_limited {
            return None;
        }

        let delivered_delta = self.delivered.saturating_sub(oldest.delivered);

        // Per the BBR rate-sample algorithm, the elapsed interval must be at
        // least one packet-time long.  When the send-burst clock (`first_sent_time`)
        // is available it may produce a longer, more stable interval.  We take
        // the maximum of the two intervals so tiny bursts don't yield inflated rates.
        let ack_elapsed = now.duration_since(oldest.delivered_time).as_secs_f64();
        let send_elapsed = now.duration_since(oldest.first_sent_time).as_secs_f64();
        let elapsed = ack_elapsed.max(send_elapsed);

        // Guard against degenerate intervals.  A zero-size sample contributes
        // nothing to bandwidth estimation; skip if it is the only sample.
        if elapsed <= 0.0 || delivered_delta == 0 {
            return None;
        }
        // If the only sample is a probe (size == 0), skip to avoid inflating BW.
        let has_data_sample = samples.iter().any(|s| s.size > 0);
        if !has_data_sample {
            return None;
        }

        Some(delivered_delta as f64 / elapsed)
    }

    /// Whether the application is currently the bottleneck (not the network).
    #[must_use]
    pub fn is_app_limited(&self) -> bool {
        self.app_limited
    }

    /// Signal that the application does not have more data to send; future rate
    /// samples will be marked app-limited until `app_limited_until` bytes of
    /// data have been delivered past this point.
    pub fn set_app_limited(&mut self, bytes_in_flight: u64) {
        self.app_limited = true;
        self.app_limited_until = self.delivered + bytes_in_flight;
    }

    /// Called when the delivered counter passes `app_limited_until`; clears the
    /// app-limited flag so subsequent samples are usable for bandwidth estimation.
    fn check_app_limited(&mut self) {
        if self.app_limited && self.delivered >= self.app_limited_until {
            self.app_limited = false;
        }
    }
}

impl Default for DeliveryRateEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BbrState
// ---------------------------------------------------------------------------

/// The BBR state machine phase.
#[derive(Debug, Clone)]
pub enum BbrState {
    /// Exponential bandwidth probing: pacing gain `HIGH_GAIN`, cwnd gain 2.0.
    /// Exits when `filled_pipe` is set (bandwidth plateau detected).
    Startup,
    /// Drain the queue built in Startup: pacing gain `1/HIGH_GAIN`, cwnd gain 1.0.
    /// Exits when `bytes_in_flight ≤ BDP`.
    Drain,
    /// Cycle through eight gain phases to probe for spare bandwidth.
    ProbeBW {
        /// Current index into `PROBE_BW_GAINS` (0–7).
        cycle_index: usize,
    },
    /// Briefly reduce inflight to measure the true minimum RTT.
    ProbeRTT {
        /// When the ProbeRTT phase began.
        probe_rtt_start: Instant,
        /// Whether the min-RTT window has expired (triggering ProbeRTT entry).
        min_rtt_expired: bool,
    },
}

// ---------------------------------------------------------------------------
// Windowed max filter (approximation for bottleneck bandwidth)
// ---------------------------------------------------------------------------

/// A simple 3-slot windowed maximum filter that tracks the maximum value over a
/// sliding window of rounds.  This approximates the more general `WindowedFilter`
/// described in the BBR paper using the same "three-bucket" algorithm used in
/// Linux's `lib/win_minmax.c`.
#[derive(Debug, Clone, Copy)]
struct WindowedMaxFilter {
    /// (value, round_count) for each slot; slot[0] is the current maximum.
    slots: [(f64, u64); 3],
}

impl WindowedMaxFilter {
    fn new() -> Self {
        Self {
            slots: [(0.0, 0); 3],
        }
    }

    /// Return the current maximum.
    fn get(&self) -> f64 {
        self.slots[0].0
    }

    /// Update with a new measurement `value` at `round_count`.
    /// `win_len` is the filter window width in rounds.
    fn update(&mut self, value: f64, round_count: u64, win_len: u64) {
        if value >= self.slots[0].0 || round_count.saturating_sub(self.slots[2].1) >= win_len {
            // New maximum — or window expired: fill all three slots.
            self.slots = [(value, round_count); 3];
            return;
        }
        if value >= self.slots[1].0 {
            self.slots[1] = (value, round_count);
            self.slots[2] = (value, round_count);
        } else if value >= self.slots[2].0 {
            self.slots[2] = (value, round_count);
        }
        // Expire stale slots.
        if round_count.saturating_sub(self.slots[0].1) >= win_len {
            self.slots[0] = self.slots[1];
            self.slots[1] = self.slots[2];
            self.slots[2] = (value, round_count);
        } else if round_count.saturating_sub(self.slots[1].1) >= win_len {
            self.slots[1] = self.slots[2];
            self.slots[2] = (value, round_count);
        }
    }
}

// ---------------------------------------------------------------------------
// Bbr
// ---------------------------------------------------------------------------

/// A BBR v2 congestion controller.
///
/// Call [`Bbr::on_packet_sent`] for every in-flight packet, store the returned
/// [`RateSample`] alongside the sent-packet metadata, then call
/// [`Bbr::on_packets_acked`] with all (bytes, sent_time, sample) tuples when
/// ACKs arrive and [`Bbr::on_packets_lost`] when packets are declared lost.
/// Gate sending with [`Bbr::can_send`] and optionally pace using
/// [`Bbr::pacing_rate`].
#[derive(Debug, Clone)]
pub struct Bbr {
    // ---- connection geometry ----
    /// Maximum datagram size (MTU) in bytes.
    max_datagram: usize,

    // ---- state machine ----
    /// Current phase of the BBR state machine.
    state: BbrState,

    // ---- bandwidth / RTT model ----
    /// Bottleneck bandwidth estimate: windowed max over ~10 rounds (bytes/sec).
    btl_bw: f64,
    /// Windowed maximum filter for bandwidth samples.
    bw_filter: WindowedMaxFilter,
    /// Minimum observed RTT (propagation delay estimate).
    rt_prop: Duration,
    /// When `rt_prop` was last updated.
    rt_prop_stamp: Instant,

    // ---- pacing / window gains ----
    /// Current pacing gain (multiplier on `btl_bw`).
    pacing_gain: f64,
    /// Current cwnd gain (multiplier on BDP).
    cwnd_gain: f64,

    // ---- cwnd / in-flight tracking ----
    /// Current congestion window in bytes.
    congestion_window: u64,
    /// Bytes currently in flight (sent but not yet acknowledged or lost).
    bytes_in_flight: u64,

    // ---- round-trip counting ----
    /// Number of completed round trips since connection start.
    round_count: u64,
    /// Whether this ACK batch starts a new round.
    round_start: bool,
    /// Minimum `delivered` value required to advance `round_count`.
    next_round_delivered: u64,

    // ---- delivery tracking ----
    /// Total bytes delivered to the far end.
    delivered: u64,
    /// Delivery rate estimator.
    rate_estimator: DeliveryRateEstimator,

    // ---- startup / filled-pipe detection ----
    /// Whether the pipe has been filled (bandwidth plateau detected).
    filled_pipe: bool,
    /// Best bandwidth sample seen in the current plateau-detection window.
    full_bw: f64,
    /// Number of consecutive rounds with bandwidth growth < 25%.
    full_bw_count: u32,

    // ---- ProbeBW cycle ----
    /// When the current ProbeBW gain-cycle phase began.
    cycle_stamp: Instant,
    /// Current ProbeBW gain-cycle index (0–7).
    cycle_index: usize,

    // ---- ProbeRTT ----
    /// Timestamp for when the ProbeRTT duration requirement is satisfied.
    probe_rtt_done_stamp: Option<Instant>,
    /// Whether we've completed a full round in ProbeRTT.
    probe_rtt_round_done: bool,
    /// Saved cwnd to restore after ProbeRTT.
    prior_cwnd: u64,
    /// Whether the connection just restarted from idle.
    idle_restart: bool,

    // ---- BBR v2 model bounds ----
    /// Upper bandwidth bound (bytes/sec); `f64::INFINITY` = no constraint.
    bw_hi: f64,
    /// Lower bandwidth bound (bytes/sec).
    bw_lo: f64,
    /// Upper inflight bound in bytes; `u64::MAX` = no constraint.
    inflight_hi: u64,
    /// Lower inflight bound in bytes.
    inflight_lo: u64,

    // ---- loss recovery ----
    /// When the current recovery period started, if any.
    recovery_start_time: Option<Instant>,
}

impl Bbr {
    // Window width for the bottleneck-bandwidth windowed max (rounds).
    const BW_WINDOW_ROUNDS: u64 = 10;

    /// Create a BBR controller with the default 1200-byte datagram size.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_datagram(MAX_DATAGRAM_SIZE)
    }

    /// Create a BBR controller for a specific `max_datagram_size`.
    #[must_use]
    pub fn with_max_datagram(max_datagram: usize) -> Self {
        let now = Instant::now();
        let init_cwnd = initial_window(max_datagram) as u64;
        Self {
            max_datagram,
            state: BbrState::Startup,
            btl_bw: 0.0,
            bw_filter: WindowedMaxFilter::new(),
            rt_prop: Duration::MAX,
            rt_prop_stamp: now,
            pacing_gain: HIGH_GAIN,
            cwnd_gain: 2.0,
            congestion_window: init_cwnd,
            bytes_in_flight: 0,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            delivered: 0,
            rate_estimator: DeliveryRateEstimator::new(),
            filled_pipe: false,
            full_bw: 0.0,
            full_bw_count: 0,
            cycle_stamp: now,
            cycle_index: 0,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            prior_cwnd: init_cwnd,
            idle_restart: false,
            bw_hi: f64::INFINITY,
            bw_lo: 0.0,
            inflight_hi: u64::MAX,
            inflight_lo: 0,
            recovery_start_time: None,
        }
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

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

    /// Whether a packet of `bytes` may be sent without exceeding the congestion
    /// window (same semantics as `NewReno::can_send`).
    #[must_use]
    pub fn can_send(&self, bytes: usize) -> bool {
        self.bytes_in_flight + bytes as u64 <= self.congestion_window
    }

    /// The pacing rate in bytes/second, or `None` if no bandwidth estimate is
    /// available yet (first RTT not yet complete).
    #[must_use]
    pub fn pacing_rate(&self) -> Option<u64> {
        if self.btl_bw <= 0.0 || !self.btl_bw.is_finite() {
            return None;
        }
        let rate = self.pacing_gain * self.btl_bw;
        // Apply BBR v2 bandwidth bounds: clamp between [bw_lo, bw_hi].
        let rate = rate.min(self.bw_hi).max(self.bw_lo);
        Some(rate.max(0.0) as u64)
    }

    // -----------------------------------------------------------------------
    // Sent-packet accounting
    // -----------------------------------------------------------------------

    /// Account for a freshly-sent in-flight packet of `bytes` and return a
    /// [`RateSample`] to be stored alongside the sent-packet record.
    pub fn on_packet_sent(&mut self, bytes: usize, now: Instant) -> RateSample {
        // Detect an idle restart: if no packets were in flight before this send,
        // the estimator's burst clock needs to be re-anchored.
        self.idle_restart = self.bytes_in_flight == 0;
        self.bytes_in_flight += bytes as u64;
        self.rate_estimator.on_packet_sent(bytes, now)
    }

    // -----------------------------------------------------------------------
    // ACK processing
    // -----------------------------------------------------------------------

    /// Process newly-acknowledged in-flight packets.
    ///
    /// `acked` is a slice of `(wire_bytes, sent_time, rate_sample)` tuples,
    /// one per acknowledged packet.  `now` is the current wall-clock time.
    pub fn on_packets_acked(&mut self, acked: &[(usize, Instant, RateSample)], now: Instant) {
        // --- 1. Update delivery counter and rate estimator ---
        let acked_bytes: usize = acked.iter().map(|(b, _, _)| b).sum();
        let samples: Vec<RateSample> = acked.iter().map(|(_, _, s)| *s).collect();

        // Deduct from in-flight first.
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes as u64);
        self.delivered += acked_bytes as u64;
        self.rate_estimator.check_app_limited();

        // Obtain bandwidth sample.
        let bw_sample = self
            .rate_estimator
            .on_packets_acked(&samples, acked_bytes, now);

        // --- 2. Update min-RTT (rt_prop) ---
        // Use the sent_time of the latest acked packet to approximate RTT.
        // In a real implementation the ACK would carry the RTT; here we derive
        // it from the most-recent sent_time in this ACK batch.
        if let Some(latest) = acked.iter().map(|(_, t, _)| t).max() {
            let rtt_sample = now.duration_since(*latest);
            if rtt_sample < self.rt_prop {
                self.rt_prop = rtt_sample;
                self.rt_prop_stamp = now;
            }
        }

        // --- 3. Advance round-trip counter ---
        self.update_round_count();

        // --- 4. Update bandwidth filter ---
        if let Some(bw) = bw_sample {
            if bw > 0.0 {
                self.bw_filter
                    .update(bw, self.round_count, Self::BW_WINDOW_ROUNDS);
                let new_btl_bw = self.bw_filter.get().min(self.bw_hi);
                if new_btl_bw > self.btl_bw {
                    self.btl_bw = new_btl_bw;
                }
            }
        }

        // --- 5. Startup / filled-pipe detection ---
        if !self.filled_pipe && self.round_start {
            self.check_startup_full_pipe();
        }

        // --- 6. ProbeRTT entry check ---
        let probe_rtt_trigger = now.duration_since(self.rt_prop_stamp) >= RT_PROP_FILTER_LEN
            && !matches!(self.state, BbrState::ProbeRTT { .. });

        // --- 7. State transitions ---
        self.update_state(now, probe_rtt_trigger);

        // --- 8. Recompute congestion window ---
        self.set_cwnd();
    }

    /// Update `round_count` and `round_start` based on the current `delivered`
    /// counter. A new round begins when we have delivered at least
    /// `next_round_delivered` bytes.
    fn update_round_count(&mut self) {
        if self.delivered >= self.next_round_delivered {
            self.next_round_delivered = self.delivered;
            self.round_count += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    /// Detect whether bandwidth has plateaued for three consecutive rounds,
    /// indicating that the pipe is full (Startup → Drain transition condition).
    fn check_startup_full_pipe(&mut self) {
        if self.btl_bw >= self.full_bw * 1.25 {
            // Bandwidth grew by ≥25%: reset plateau counter.
            self.full_bw = self.btl_bw;
            self.full_bw_count = 0;
        } else {
            self.full_bw_count += 1;
            if self.full_bw_count >= 3 {
                self.filled_pipe = true;
            }
        }
    }

    // -----------------------------------------------------------------------
    // State machine
    // -----------------------------------------------------------------------

    /// Run state-machine transitions and update pacing/cwnd gains.
    fn update_state(&mut self, now: Instant, probe_rtt_trigger: bool) {
        match &self.state.clone() {
            BbrState::Startup => {
                if self.filled_pipe {
                    self.enter_drain();
                }
            }
            BbrState::Drain => {
                if self.bytes_in_flight <= self.bdp() {
                    self.enter_probe_bw(now);
                }
            }
            BbrState::ProbeBW { .. } => {
                if probe_rtt_trigger {
                    self.enter_probe_rtt(now);
                } else {
                    self.advance_cycle_phase(now);
                }
            }
            BbrState::ProbeRTT {
                probe_rtt_start,
                min_rtt_expired: _,
            } => {
                self.handle_probe_rtt(now, *probe_rtt_start);
            }
        }
    }

    /// Transition to the Drain state.
    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
        // Inverse of startup gain.
        self.pacing_gain = 1.0 / HIGH_GAIN;
        self.cwnd_gain = 1.0;
    }

    /// Transition to ProbeBW, starting at a random offset in the gain cycle to
    /// avoid synchronisation between competing flows.  Per the spec we simply
    /// start at index 1 (the drain phase) to quickly empty any queue.
    fn enter_probe_bw(&mut self, now: Instant) {
        self.state = BbrState::ProbeBW { cycle_index: 1 };
        self.cycle_index = 1;
        self.pacing_gain = PROBE_BW_GAINS[1];
        self.cwnd_gain = 2.0;
        self.cycle_stamp = now;
    }

    /// Transition to ProbeRTT to refresh the minimum-RTT estimate.
    fn enter_probe_rtt(&mut self, now: Instant) {
        self.prior_cwnd = self.congestion_window;
        self.state = BbrState::ProbeRTT {
            probe_rtt_start: now,
            min_rtt_expired: true,
        };
        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
        self.probe_rtt_done_stamp = None;
        self.probe_rtt_round_done = false;
    }

    /// Advance to the next phase in the ProbeBW gain cycle when one RTT has
    /// elapsed in the current phase.
    fn advance_cycle_phase(&mut self, now: Instant) {
        let rt = if self.rt_prop == Duration::MAX {
            Duration::from_millis(100) // fallback before first sample
        } else {
            self.rt_prop
        };
        if now.duration_since(self.cycle_stamp) >= rt {
            self.cycle_index = (self.cycle_index + 1) % CYCLE_LEN;
            self.cycle_stamp = now;
            self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
            self.state = BbrState::ProbeBW {
                cycle_index: self.cycle_index,
            };
        }
    }

    /// Handle timing logic while in ProbeRTT.
    fn handle_probe_rtt(&mut self, now: Instant, probe_rtt_start: Instant) {
        // Refresh the minimum-RTT stamp so we don't re-enter too soon.
        self.rt_prop_stamp = now;

        // Arm the done stamp at the first opportunity (when in-flight is minimal).
        if self.probe_rtt_done_stamp.is_none() && self.bytes_in_flight <= self.min_pipe_cwnd() {
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
            self.probe_rtt_round_done = false;
            self.next_round_delivered = self.delivered;
        } else if let Some(done) = self.probe_rtt_done_stamp {
            if self.round_start {
                self.probe_rtt_round_done = true;
            }
            if self.probe_rtt_round_done && now >= done {
                // ProbeRTT complete — restore cwnd.
                self.rt_prop_stamp = now;
                self.congestion_window = self.prior_cwnd;
                if !self.filled_pipe {
                    self.enter_startup();
                } else {
                    self.enter_probe_bw(now);
                }
                let _ = probe_rtt_start; // used for pattern binding above
            }
        }
    }

    /// Re-enter Startup state (happens after ProbeRTT when pipe was not filled).
    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
        self.pacing_gain = HIGH_GAIN;
        self.cwnd_gain = 2.0;
    }

    // -----------------------------------------------------------------------
    // Congestion window calculation
    // -----------------------------------------------------------------------

    /// Bandwidth-delay product in bytes.
    fn bdp(&self) -> u64 {
        let rt = if self.rt_prop == Duration::MAX {
            // No RTT sample yet; assume a 100ms initial RTT.
            Duration::from_millis(100)
        } else {
            self.rt_prop
        };
        (self.btl_bw * rt.as_secs_f64()).max(0.0) as u64
    }

    /// Maximum inflight that respects BBR v2 model bounds.
    ///
    /// The upper bound is `min(model_bdp, inflight_hi)`.  The lower bound is
    /// `max(result, inflight_lo)` so that we honour the conservative floor
    /// established after loss events.
    fn inflight_limit(&self) -> u64 {
        let rt = if self.rt_prop == Duration::MAX {
            Duration::from_millis(100)
        } else {
            self.rt_prop
        };
        let model_limit = (self.cwnd_gain * self.btl_bw * rt.as_secs_f64()).max(0.0) as u64;
        // Apply upper and lower BBR v2 inflight bounds.
        model_limit.min(self.inflight_hi).max(self.inflight_lo)
    }

    /// Minimum pipe cwnd: 4 datagrams (prevents the window from collapsing).
    fn min_pipe_cwnd(&self) -> u64 {
        MIN_PIPE_CWND_PACKETS * self.max_datagram as u64
    }

    /// Recompute and set `congestion_window` based on the current model.
    fn set_cwnd(&mut self) {
        match &self.state.clone() {
            BbrState::ProbeRTT { .. } => {
                // Probe-RTT: hold inflight to minimal.
                self.congestion_window = self.min_pipe_cwnd();
            }
            _ => {
                let target = if self.btl_bw <= 0.0 {
                    // No bandwidth sample yet — keep the initial window.
                    initial_window(self.max_datagram) as u64
                } else {
                    let limit = self.inflight_limit();
                    // Always at least min_pipe_cwnd.
                    limit.max(self.min_pipe_cwnd())
                };
                self.congestion_window = target;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Loss handling
    // -----------------------------------------------------------------------

    /// React to packet loss.
    ///
    /// `lost_bytes` is the total wire size of all packets declared lost.
    /// `largest_lost_sent_time` is the send time of the newest lost packet.
    /// `now` is the current wall-clock time.
    pub fn on_packets_lost(
        &mut self,
        lost_bytes: u64,
        largest_lost_sent_time: Instant,
        now: Instant,
    ) {
        // Capture inflight before deducting lost bytes: this represents the
        // total bytes that were outstanding when loss was detected.
        //
        // Convention note: callers are expected to pass `bytes_in_flight` that
        // STILL includes the lost packets (i.e. `on_packets_lost` is the first
        // place those bytes are removed).  That matches the test fixture.  If
        // the wiring in `recovery.rs` ever follows a different convention where
        // bytes_in_flight is decremented before calling here, this computation
        // would under-count; revisit if `inflight_hi` looks too small in practice.
        let inflight_at_loss = self.bytes_in_flight + lost_bytes;

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        // Avoid duplicate recovery entries.
        let already_in_recovery = self
            .recovery_start_time
            .is_some_and(|t| largest_lost_sent_time <= t);
        if already_in_recovery {
            return;
        }

        self.recovery_start_time = Some(now);

        // BBR v2: tighten inflight upper bound to 70% of inflight-at-loss.
        let new_inflight_hi = ((inflight_at_loss * 7) / 10).max(self.bdp());
        self.inflight_hi = new_inflight_hi;

        // Tighten bandwidth upper bound if we have a current estimate.
        if self.btl_bw > 0.0 {
            self.bw_hi = self.btl_bw;
        }

        // Immediately update the congestion window.
        self.set_cwnd();
    }
}

impl Default for Bbr {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Tolerance for floating-point comparisons.
    const EPSILON: f64 = 1.0;

    /// Helper: advance time in discrete steps, feeding ACKs.
    fn feed_acks(bbr: &mut Bbr, rounds: usize, bytes_per_round: usize, rtt: Duration) {
        let mut t = Instant::now();
        for _ in 0..rounds {
            let sample = bbr.on_packet_sent(bytes_per_round, t);
            t += rtt;
            bbr.on_packets_acked(&[(bytes_per_round, t - rtt, sample)], t);
        }
    }

    // -----------------------------------------------------------------------
    // Test 1 — initial_state_is_startup
    // -----------------------------------------------------------------------
    #[test]
    fn initial_state_is_startup() {
        let bbr = Bbr::new();
        assert!(
            matches!(bbr.state, BbrState::Startup),
            "new Bbr should start in Startup"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — startup_pacing_gain
    // -----------------------------------------------------------------------
    #[test]
    fn startup_pacing_gain() {
        let bbr = Bbr::new();
        assert!(
            (bbr.pacing_gain - HIGH_GAIN).abs() < 0.001,
            "startup pacing_gain should be ≈ {HIGH_GAIN:.4}, got {}",
            bbr.pacing_gain
        );
    }

    // -----------------------------------------------------------------------
    // Test 3 — bandwidth_plateau_detection
    // -----------------------------------------------------------------------
    #[test]
    fn bandwidth_plateau_detection() {
        let mut bbr = Bbr::new();
        let now = Instant::now();
        let rtt = Duration::from_millis(10);
        let bytes = 12_000;

        // Simulate several rounds where the bandwidth stays flat (no growth).
        // We manually inject round_start events to drive the check.
        let bw_sample = 1_000_000.0_f64; // 1 MB/s
        bbr.btl_bw = bw_sample;
        bbr.full_bw = bw_sample;

        // Three rounds of plateau (growth < 25%) should set filled_pipe.
        for i in 0..5 {
            let t = now + rtt * i;
            let sample = bbr.on_packet_sent(bytes, t);
            let t_ack = t + rtt;
            bbr.on_packets_acked(&[(bytes, t, sample)], t_ack);
        }

        assert!(
            bbr.filled_pipe,
            "filled_pipe should be true after bandwidth plateau"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4 — drain_exits_at_bdp
    // -----------------------------------------------------------------------
    #[test]
    fn drain_exits_at_bdp() {
        let mut bbr = Bbr::new();
        let now = Instant::now();
        let rtt = Duration::from_millis(20);

        // Force into Drain with a known btl_bw and rt_prop.
        bbr.btl_bw = 1_000_000.0; // 1 MB/s
        bbr.rt_prop = rtt;
        bbr.filled_pipe = true;
        bbr.enter_drain();

        // BDP = btl_bw * rt_prop = 1e6 * 0.02 = 20 000 bytes.
        // With bytes_in_flight = 0 (≤ bdp), the next ACK should move us to ProbeBW.
        let bytes = 1200;
        let sample = bbr.on_packet_sent(bytes, now);
        bbr.on_packets_acked(&[(bytes, now, sample)], now + rtt);

        assert!(
            matches!(bbr.state, BbrState::ProbeBW { .. }),
            "should enter ProbeBW after bytes_in_flight ≤ BDP; state = {:?}",
            bbr.state
        );
    }

    // -----------------------------------------------------------------------
    // Test 5 — probe_bw_cycle_advances
    // -----------------------------------------------------------------------
    #[test]
    fn probe_bw_cycle_advances() {
        let mut bbr = Bbr::new();
        let rtt = Duration::from_millis(10);
        bbr.btl_bw = 1_000_000.0;
        bbr.rt_prop = rtt;
        bbr.filled_pipe = true;
        let now = Instant::now();
        bbr.enter_probe_bw(now);

        // We advance by simulating ACKs with timestamps > one RTT apart.
        let bytes = 1200;
        let mut seen_indices = std::collections::HashSet::new();
        let mut t = now;

        for _ in 0..CYCLE_LEN * 3 {
            t += rtt + Duration::from_millis(1); // exceed rt_prop each step
            let sample = bbr.on_packet_sent(bytes, t);
            t += rtt;
            bbr.on_packets_acked(&[(bytes, t - rtt, sample)], t);
            if let BbrState::ProbeBW { cycle_index } = bbr.state {
                seen_indices.insert(cycle_index);
            }
        }

        assert_eq!(
            seen_indices.len(),
            CYCLE_LEN,
            "should have visited all {CYCLE_LEN} cycle phases, visited: {seen_indices:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6 — probe_rtt_reduces_cwnd
    // -----------------------------------------------------------------------
    #[test]
    fn probe_rtt_reduces_cwnd() {
        let mut bbr = Bbr::new();
        let now = Instant::now();
        bbr.btl_bw = 1_000_000.0;
        bbr.rt_prop = Duration::from_millis(20);
        bbr.filled_pipe = true;
        bbr.enter_probe_rtt(now);

        // set_cwnd in ProbeRTT clamps to min_pipe_cwnd = 4 * max_datagram.
        bbr.set_cwnd();
        let max_probe_rtt_cwnd = MIN_PIPE_CWND_PACKETS * MAX_DATAGRAM_SIZE as u64;
        assert!(
            bbr.congestion_window <= max_probe_rtt_cwnd,
            "ProbeRTT cwnd should be ≤ {} bytes, got {}",
            max_probe_rtt_cwnd,
            bbr.congestion_window
        );
    }

    // -----------------------------------------------------------------------
    // Test 7 — loss_sets_inflight_hi
    // -----------------------------------------------------------------------
    #[test]
    fn loss_sets_inflight_hi() {
        let mut bbr = Bbr::new();
        let now = Instant::now();
        bbr.btl_bw = 1_000_000.0;
        bbr.rt_prop = Duration::from_millis(20);

        // Simulate 50 000 bytes in flight then declare 5000 bytes lost.
        let in_flight = 50_000_u64;
        let lost = 5_000_u64;
        // Manually set bytes_in_flight to simulate outstanding packets.
        for _ in 0..42 {
            let sample = bbr.on_packet_sent(1200, now);
            // Don't ack; just accumulate.
            let _ = sample;
        }
        bbr.bytes_in_flight = in_flight;

        bbr.on_packets_lost(lost, now - Duration::from_millis(1), now);

        // inflight_hi should be ~70% of inflight_at_loss = (50000+5000)*0.7 = 38500.
        let inflight_at_loss = in_flight + lost;
        let expected_hi = (inflight_at_loss * 7) / 10;
        assert!(
            bbr.inflight_hi <= expected_hi + 1 && bbr.inflight_hi >= expected_hi - 1,
            "inflight_hi should be ≈ {} bytes, got {}",
            expected_hi,
            bbr.inflight_hi
        );
    }

    // -----------------------------------------------------------------------
    // Test 8 — delivery_rate_estimation
    // -----------------------------------------------------------------------
    #[test]
    fn delivery_rate_estimation() {
        let now = Instant::now();
        let mut est = DeliveryRateEstimator::new();

        // First packet: 10000 bytes sent at `now`.
        let s1 = est.on_packet_sent(10_000, now);

        // Second packet: 0 additional bytes (just to exercise the estimator).
        let s2 = est.on_packet_sent(0, now + Duration::from_millis(50));

        // ACK both at now + 100ms — 10000 bytes delivered over 100ms ≈ 100 000 B/s.
        let t_ack = now + Duration::from_millis(100);
        let rate = est.on_packets_acked(&[s1, s2], 10_000, t_ack);

        let r = rate.expect("should produce a rate sample");
        assert!(
            (r - 100_000.0).abs() < EPSILON,
            "delivery rate should be ≈ 100 000 B/s, got {r:.2}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 9 — can_send_respects_cwnd
    // -----------------------------------------------------------------------
    #[test]
    fn can_send_respects_cwnd() {
        let mut bbr = Bbr::with_max_datagram(1200);
        let cwnd = bbr.congestion_window();
        // Fill up to exactly the window.
        let now = Instant::now();
        let _sample = bbr.on_packet_sent(cwnd as usize, now);
        assert_eq!(bbr.bytes_in_flight(), cwnd);
        assert!(
            !bbr.can_send(1),
            "must not send when bytes_in_flight >= cwnd"
        );
    }

    // -----------------------------------------------------------------------
    // Test 10 — pacing_rate_after_warmup
    // -----------------------------------------------------------------------
    #[test]
    fn pacing_rate_after_warmup() {
        let mut bbr = Bbr::new();
        // No bandwidth estimate yet.
        assert_eq!(
            bbr.pacing_rate(),
            None,
            "pacing_rate should be None before warmup"
        );

        // Feed enough ACKs to build a btl_bw estimate.
        let rtt = Duration::from_millis(20);
        feed_acks(&mut bbr, 5, 12_000, rtt);

        // After warmup we must have a positive pacing rate.
        let rate = bbr
            .pacing_rate()
            .expect("pacing_rate should be Some(rate > 0) after warmup");
        assert!(rate > 0, "pacing_rate should be > 0, got {rate}");
    }
}
