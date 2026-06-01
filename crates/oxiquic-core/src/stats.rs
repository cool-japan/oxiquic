//! Connection-level statistics.

use std::fmt;
use std::time::Duration;

/// A snapshot of connection-level statistics, mirroring the metrics a QUIC
/// transport tracks for loss detection, congestion control and diagnostics
/// (RFC 9002).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionStats {
    /// Latest round-trip time sample.
    pub rtt: Duration,
    /// Minimum RTT observed over the connection's lifetime
    /// (RFC 9002 Section 5.2).
    pub min_rtt: Duration,
    /// Smoothed RTT estimate (RFC 9002 Section 5.3).
    pub smoothed_rtt: Duration,
    /// RTT variation estimate (`rttvar`, RFC 9002 Section 5.3).
    pub rtt_variance: Duration,
    /// Total application+protocol bytes sent.
    pub bytes_sent: u64,
    /// Total application+protocol bytes received.
    pub bytes_recv: u64,
    /// Total number of QUIC packets sent.
    pub packets_sent: u64,
    /// Total number of QUIC packets received.
    pub packets_recv: u64,
    /// Total number of packets declared lost (RFC 9002 Section 6).
    pub packets_lost: u64,
    /// Current congestion window, in bytes (RFC 9002 Section 7).
    pub congestion_window: u64,
    /// Number of streams opened over the connection's lifetime.
    pub streams_opened: u64,
    /// Number of streams that have been closed.
    pub streams_closed: u64,
}

impl ConnectionStats {
    /// The packet loss rate, computed as `packets_lost / packets_sent`.
    ///
    /// Returns `0.0` when no packets have been sent, avoiding a division by
    /// zero.
    #[must_use]
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        }
    }

    /// The number of streams currently open, i.e. `streams_opened` minus
    /// `streams_closed` (saturating at zero).
    #[must_use]
    pub fn streams_active(&self) -> u64 {
        self.streams_opened.saturating_sub(self.streams_closed)
    }

    /// Estimated application-level bytes received, after subtracting
    /// per-packet framing overhead.
    ///
    /// Uses ~50 bytes per-packet overhead (QUIC short header ~9 B +
    /// STREAM frame header ~9 B + ACK frame average ~32 B). The result
    /// saturates at zero so it never wraps under-count.
    #[must_use]
    pub fn goodput_bytes(&self) -> u64 {
        self.bytes_recv
            .saturating_sub(self.packets_recv.saturating_mul(50))
    }
}

impl fmt::Display for ConnectionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rtt={:.1}ms smoothed={:.1}ms sent={}B/{}pkt recv={}B/{}pkt lost={}pkt ({:.2}%) cwnd={}B",
            self.rtt.as_secs_f64() * 1e3,
            self.smoothed_rtt.as_secs_f64() * 1e3,
            self.bytes_sent,
            self.packets_sent,
            self.bytes_recv,
            self.packets_recv,
            self.packets_lost,
            self.loss_rate() * 100.0,
            self.congestion_window,
        )
    }
}
