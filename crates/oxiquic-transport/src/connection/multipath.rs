//! Multipath QUIC preview (draft-ietf-quic-multipath-08).
//!
//! This module provides the data structures and connection-level API for
//! tracking multiple simultaneous QUIC paths. The implementation follows the
//! emerging IETF draft (draft-ietf-quic-multipath) and RFC 9000 §9 (path
//! migration foundation).
//!
//! ## What is implemented
//!
//! * [`PathState`] — per-path RTT, congestion window, CID, validation status,
//!   and packet count tracked separately for each known path.
//! * [`MultipathState`] — collection of known paths with an "active path" index.
//! * Connection-level API:
//!   - [`Connection::multipath_state`] — inspect all known paths.
//!   - [`Connection::add_path`] — register a new candidate path with its CID.
//!   - [`Connection::set_preferred_path`] — mark a path as the preferred
//!     active path (packet sending migrates to it on the next `poll_transmit`).
//!   - [`Connection::path_count`] — number of known (validated or candidate) paths.
//!   - [`Connection::active_path_rtt`] — smoothed RTT of the current active path.
//!
//! ## What is deferred
//!
//! Full multipath packet scheduling (sending data across multiple simultaneous
//! paths), per-path ACK processing, and multipath stream mapping are deferred
//! pending stabilisation of the draft RFC. The API surface is designed so these
//! additions slot in without breaking the existing single-path implementation.
//!
//! ## Relationship to RFC 9000 §9
//!
//! RFC 9000 §9 (path migration) is already implemented in `keys_path.rs`:
//! `initiate_path_challenge`, `set_candidate_peer_addr`, `path_validated`.
//! This module extends that foundation to track multiple simultaneous paths
//! and exposes them through the multipath API.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use oxiquic_core::{ConnectionId, OxiQuicError};

use super::Connection;

// ─────────────────────────────────────────────────────────────────────────────
// PathState
// ─────────────────────────────────────────────────────────────────────────────

/// Validation state of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathValidation {
    /// No PATH_CHALLENGE has been sent for this path yet.
    Unknown,
    /// PATH_CHALLENGE sent; waiting for PATH_RESPONSE.
    Pending,
    /// PATH_CHALLENGE acknowledged via PATH_RESPONSE.
    Validated,
    /// Path validation failed (no response within PTO budget).
    Failed,
}

impl std::fmt::Display for PathValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Pending => "pending",
            Self::Validated => "validated",
            Self::Failed => "failed",
        })
    }
}

/// Per-path state for a QUIC connection.
///
/// Each path is identified by (local_addr, remote_addr). The connection
/// maintains one primary path and zero or more candidate / secondary paths.
/// Each path tracks its own RTT estimate, congestion window hint, and
/// validation status independently.
#[derive(Debug, Clone)]
pub struct PathState {
    /// The local socket address for this path.
    pub local_addr: Option<SocketAddr>,
    /// The remote peer address for this path.
    pub remote_addr: SocketAddr,
    /// The connection ID used on this path (RFC 9000 §9.5 requires using a
    /// fresh CID when migrating to prevent linkability).
    pub connection_id: Option<ConnectionId>,
    /// Validation state.
    pub validation: PathValidation,
    /// Smoothed RTT estimate for this path (None until at least one RTT sample).
    pub smoothed_rtt: Option<Duration>,
    /// Minimum RTT observed on this path.
    pub min_rtt: Option<Duration>,
    /// Estimated available bandwidth (bytes/s), updated by ACK events.
    pub bandwidth_estimate: Option<u64>,
    /// Number of packets sent on this path.
    pub packets_sent: u64,
    /// Number of packets received on this path.
    pub packets_received: u64,
    /// Wall-clock time this path was first seen.
    pub first_seen: Instant,
    /// Wall-clock time this path was last used for sending.
    pub last_sent: Option<Instant>,
}

impl PathState {
    /// Create a new path state for `remote_addr`.
    #[must_use]
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            local_addr: None,
            remote_addr,
            connection_id: None,
            validation: PathValidation::Unknown,
            smoothed_rtt: None,
            min_rtt: None,
            bandwidth_estimate: None,
            packets_sent: 0,
            packets_received: 0,
            first_seen: Instant::now(),
            last_sent: None,
        }
    }

    /// Whether this path may be promoted to the active (preferred) path.
    ///
    /// Only fully-validated paths are eligible for promotion. The initial path
    /// is created with [`PathValidation::Validated`] by [`MultipathState::new`].
    /// Candidate paths added via [`MultipathState::add_path`] start as
    /// [`PathValidation::Unknown`] and must be validated via PATH_CHALLENGE /
    /// PATH_RESPONSE before they can become the preferred path.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.validation == PathValidation::Validated
    }

    /// Update the RTT estimate with a new sample.
    ///
    /// Uses the RFC 9002 §5.3 EWMA formula: `smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * sample`.
    pub fn update_rtt(&mut self, sample: Duration) {
        let updated = match self.smoothed_rtt {
            None => sample,
            Some(prev) => {
                // EWMA: 7/8 * prev + 1/8 * sample (integer arithmetic, µs).
                let prev_us = prev.as_micros() as u64;
                let sample_us = sample.as_micros() as u64;
                let new_us = (prev_us * 7 + sample_us) / 8;
                Duration::from_micros(new_us)
            }
        };
        self.smoothed_rtt = Some(updated);
        self.min_rtt = Some(match self.min_rtt {
            None => sample,
            Some(m) => m.min(sample),
        });
    }

    /// Record a packet sent on this path.
    pub fn record_sent(&mut self) {
        self.packets_sent += 1;
        self.last_sent = Some(Instant::now());
    }

    /// Record a packet received on this path.
    pub fn record_received(&mut self) {
        self.packets_received += 1;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultipathState
// ─────────────────────────────────────────────────────────────────────────────

/// Collection of known paths for a QUIC connection.
///
/// At any given time, one path is designated the "active" path — all packets
/// are sent on this path unless a multipath scheduler (not yet implemented)
/// chooses otherwise. The initial path (index 0) is always the active path
/// unless explicitly changed via [`Connection::set_preferred_path`].
///
/// Capacity: up to 8 simultaneous paths (RFC 9000 §9 anti-amplification
/// considerations make more than 4-8 paths unusual in practice).
pub struct MultipathState {
    /// Known paths, in order of registration.
    paths: Vec<PathState>,
    /// Index of the currently active (preferred) path in `paths`.
    active_index: usize,
}

impl MultipathState {
    const MAX_PATHS: usize = 8;

    /// Create a new multipath state with one initial path.
    #[must_use]
    pub fn new(initial_remote: SocketAddr) -> Self {
        let mut initial = PathState::new(initial_remote);
        // The initial path is implicitly validated by the handshake.
        initial.validation = PathValidation::Validated;
        Self {
            paths: vec![initial],
            active_index: 0,
        }
    }

    /// The number of known paths (including candidates not yet validated).
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Immutable slice of all known paths.
    #[must_use]
    pub fn paths(&self) -> &[PathState] {
        &self.paths
    }

    /// Mutable reference to the active path.
    #[must_use]
    pub fn active_path_mut(&mut self) -> &mut PathState {
        &mut self.paths[self.active_index]
    }

    /// Immutable reference to the active path.
    #[must_use]
    pub fn active_path(&self) -> &PathState {
        &self.paths[self.active_index]
    }

    /// The index of the active path in `paths()`.
    #[must_use]
    pub fn active_index(&self) -> usize {
        self.active_index
    }

    /// Register a new candidate path.
    ///
    /// Returns `Ok(path_index)` on success.  Returns `Err` if the path is
    /// already known (same `remote_addr`) or if the capacity limit is reached.
    pub fn add_path(
        &mut self,
        remote_addr: SocketAddr,
        cid: Option<ConnectionId>,
    ) -> Result<usize, OxiQuicError> {
        // Reject duplicates.
        if self.paths.iter().any(|p| p.remote_addr == remote_addr) {
            return Err(OxiQuicError::Connection(format!(
                "path to {remote_addr} is already registered"
            )));
        }
        if self.paths.len() >= Self::MAX_PATHS {
            return Err(OxiQuicError::Connection(format!(
                "multipath capacity exceeded ({} paths max)",
                Self::MAX_PATHS
            )));
        }
        let mut state = PathState::new(remote_addr);
        state.connection_id = cid;
        let idx = self.paths.len();
        self.paths.push(state);
        Ok(idx)
    }

    /// Remove a path by index. The active path cannot be removed.
    pub fn remove_path(&mut self, index: usize) -> Result<(), OxiQuicError> {
        if index >= self.paths.len() {
            return Err(OxiQuicError::Connection(format!(
                "path index {index} out of range"
            )));
        }
        if index == self.active_index {
            return Err(OxiQuicError::Connection(
                "cannot remove the active path".into(),
            ));
        }
        self.paths.remove(index);
        // Adjust active index if necessary.
        if self.active_index > index {
            self.active_index -= 1;
        }
        Ok(())
    }

    /// Promote `index` to the active path.
    pub fn set_preferred_path(&mut self, index: usize) -> Result<(), OxiQuicError> {
        if index >= self.paths.len() {
            return Err(OxiQuicError::Connection(format!(
                "path index {index} out of range"
            )));
        }
        if !self.paths[index].is_usable() {
            return Err(OxiQuicError::Connection(format!(
                "path {index} is not usable (validation: {})",
                self.paths[index].validation
            )));
        }
        self.active_index = index;
        Ok(())
    }

    /// Look up a path by remote address. Returns `None` if not found.
    #[must_use]
    pub fn path_by_addr(&self, addr: SocketAddr) -> Option<(usize, &PathState)> {
        self.paths
            .iter()
            .enumerate()
            .find(|(_, p)| p.remote_addr == addr)
    }

    /// Mutable lookup by remote address.
    #[must_use]
    pub fn path_by_addr_mut(&mut self, addr: SocketAddr) -> Option<(usize, &mut PathState)> {
        self.paths
            .iter_mut()
            .enumerate()
            .find(|(_, p)| p.remote_addr == addr)
    }

    /// Mark path at `index` as validated (PATH_CHALLENGE/PATH_RESPONSE complete).
    pub fn mark_validated(&mut self, index: usize) {
        if let Some(p) = self.paths.get_mut(index) {
            p.validation = PathValidation::Validated;
        }
    }

    /// Mark path at `index` as pending (PATH_CHALLENGE sent, waiting for response).
    pub fn mark_pending(&mut self, index: usize) {
        if let Some(p) = self.paths.get_mut(index) {
            p.validation = PathValidation::Pending;
        }
    }

    /// Mark path at `index` as failed (validation timed out).
    pub fn mark_failed(&mut self, index: usize) {
        if let Some(p) = self.paths.get_mut(index) {
            p.validation = PathValidation::Failed;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection impl
// ─────────────────────────────────────────────────────────────────────────────

impl Connection {
    /// Return a reference to the multipath state for this connection.
    ///
    /// The multipath state contains all known paths (primary + candidates),
    /// each with their own validation status, RTT estimate, and CID.
    ///
    /// This is a preview API — full multipath packet scheduling is deferred
    /// pending the IETF draft RFC stabilising. The primary path (index 0) is
    /// always the current active path unless changed via
    /// [`Connection::set_preferred_path`].
    #[must_use]
    pub fn multipath_state(&self) -> &MultipathState {
        &self.multipath
    }

    /// The number of known paths (primary + candidates).
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.multipath.path_count()
    }

    /// The smoothed RTT of the active (primary) path.
    ///
    /// Falls back to the connection-level RTT estimator (`self.rtt`) if the
    /// per-path estimate is not yet available.
    #[must_use]
    pub fn active_path_rtt(&self) -> Duration {
        self.multipath
            .active_path()
            .smoothed_rtt
            .unwrap_or_else(|| self.rtt.smoothed_rtt())
    }

    /// Register a new candidate path.
    ///
    /// Returns the path index on success. The new path starts with
    /// [`PathValidation::Unknown`]; call [`Connection::initiate_path_challenge`]
    /// to begin the validation handshake before promoting it to preferred.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if:
    /// * The path to `remote_addr` is already registered.
    /// * The multipath capacity limit (8 paths) is reached.
    pub fn add_path(
        &mut self,
        remote_addr: SocketAddr,
        cid: Option<ConnectionId>,
    ) -> Result<usize, OxiQuicError> {
        self.multipath.add_path(remote_addr, cid)
    }

    /// Promote path `index` to the active path.
    ///
    /// Only validated or initially-trusted paths may become active. Call
    /// [`Connection::initiate_path_challenge`] to validate a candidate path
    /// first.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the index is out of range or
    /// the path is not usable.
    pub fn set_preferred_path(&mut self, index: usize) -> Result<(), OxiQuicError> {
        self.multipath.set_preferred_path(index)?;
        // Sync the active peer_addr with the new preferred path's remote addr.
        self.peer_addr = self.multipath.active_path().remote_addr;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("parse addr")
    }

    #[test]
    fn multipath_state_initial_path_is_validated() {
        let mp = MultipathState::new(addr(8000));
        assert_eq!(mp.path_count(), 1);
        assert_eq!(mp.active_index(), 0);
        assert_eq!(mp.active_path().validation, PathValidation::Validated);
    }

    #[test]
    fn multipath_add_path_registers_candidate() {
        let mut mp = MultipathState::new(addr(8000));
        let idx = mp.add_path(addr(9000), None).expect("add path");
        assert_eq!(idx, 1);
        assert_eq!(mp.path_count(), 2);
        assert_eq!(mp.paths()[1].validation, PathValidation::Unknown);
    }

    #[test]
    fn multipath_add_duplicate_path_returns_error() {
        let mut mp = MultipathState::new(addr(8000));
        let result = mp.add_path(addr(8000), None);
        assert!(result.is_err());
    }

    #[test]
    fn multipath_set_preferred_path_rejects_unknown_path() {
        let mut mp = MultipathState::new(addr(8000));
        mp.add_path(addr(9000), None).expect("add path");
        // Path at index 1 is Unknown — cannot be set as preferred.
        let result = mp.set_preferred_path(1);
        assert!(result.is_err());
    }

    #[test]
    fn multipath_set_preferred_path_after_validation() {
        let mut mp = MultipathState::new(addr(8000));
        let idx = mp.add_path(addr(9000), None).expect("add path");
        mp.mark_validated(idx);
        mp.set_preferred_path(idx).expect("promote validated path");
        assert_eq!(mp.active_index(), 1);
        assert_eq!(mp.active_path().remote_addr, addr(9000));
    }

    #[test]
    fn multipath_capacity_limit_enforced() {
        let mut mp = MultipathState::new(addr(8000));
        for port in 9001..=9007 {
            mp.add_path(addr(port), None).expect("add path");
        }
        assert_eq!(mp.path_count(), 8);
        // The 9th add should fail.
        let result = mp.add_path(addr(9999), None);
        assert!(result.is_err());
    }

    #[test]
    fn multipath_remove_non_active_path() {
        let mut mp = MultipathState::new(addr(8000));
        let idx = mp.add_path(addr(9000), None).expect("add path");
        assert_eq!(mp.path_count(), 2);
        mp.remove_path(idx).expect("remove non-active path");
        assert_eq!(mp.path_count(), 1);
    }

    #[test]
    fn multipath_cannot_remove_active_path() {
        let mut mp = MultipathState::new(addr(8000));
        let result = mp.remove_path(0); // active path
        assert!(result.is_err());
    }

    #[test]
    fn path_state_rtt_update_converges() {
        let mut ps = PathState::new(addr(8000));
        assert!(ps.smoothed_rtt.is_none());

        ps.update_rtt(Duration::from_millis(10));
        assert_eq!(ps.smoothed_rtt, Some(Duration::from_millis(10)));
        assert_eq!(ps.min_rtt, Some(Duration::from_millis(10)));

        ps.update_rtt(Duration::from_millis(20));
        // EWMA: (10 * 7 + 20) / 8 = 90/8 = 11ms (integer µs: (10_000*7+20_000)/8 = 11_250µs)
        let expected = Duration::from_micros((10_000u64 * 7 + 20_000) / 8);
        assert_eq!(ps.smoothed_rtt, Some(expected));
        // min_rtt stays at 10ms
        assert_eq!(ps.min_rtt, Some(Duration::from_millis(10)));
    }

    #[test]
    fn path_state_record_send_recv_counts() {
        let mut ps = PathState::new(addr(8000));
        assert_eq!(ps.packets_sent, 0);
        assert_eq!(ps.packets_received, 0);

        ps.record_sent();
        ps.record_sent();
        ps.record_received();

        assert_eq!(ps.packets_sent, 2);
        assert_eq!(ps.packets_received, 1);
        assert!(ps.last_sent.is_some());
    }

    #[test]
    fn path_state_is_usable_only_for_validated() {
        let mut ps = PathState::new(addr(8000));
        // New paths start Unknown — not usable for promotion.
        assert!(!ps.is_usable());

        ps.validation = PathValidation::Validated;
        assert!(ps.is_usable());

        ps.validation = PathValidation::Pending;
        assert!(!ps.is_usable());

        ps.validation = PathValidation::Failed;
        assert!(!ps.is_usable());
    }

    #[test]
    fn path_by_addr_lookup() {
        let mut mp = MultipathState::new(addr(8000));
        mp.add_path(addr(9000), None).expect("add");
        let found = mp.path_by_addr(addr(9000));
        assert!(found.is_some());
        let (idx, _) = found.expect("found path");
        assert_eq!(idx, 1);

        assert!(mp.path_by_addr(addr(9999)).is_none());
    }
}
