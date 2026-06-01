//! Connection ID pool management (RFC 9000 §§5.1, 19.15, 19.16).
//!
//! Tracks CIDs this endpoint issues to the peer ([`LocalCidPool`]) and CIDs
//! the peer issued to us ([`PeerCidPool`]). Both pools maintain
//! sequence-number order and honour `active_connection_id_limit`.
//!
//! # Lifecycle
//!
//! Every connection starts with seq 0 in both pools — the CIDs exchanged in
//! the packet headers during the handshake. Post-handshake, each side issues
//! additional CIDs via NEW_CONNECTION_ID (up to the peer's advertised
//! `active_connection_id_limit`), enabling path migration without re-handshake.
//!
//! When the peer retires one of our CIDs (`RETIRE_CONNECTION_ID`), we remove
//! it from `LocalCidPool` and emit a `CidEvent::Unregister` so the endpoint
//! demux can remove it from its routing table. We then issue a fresh CID
//! (`CidEvent::Register`) to keep the peer's pool replenished.
//!
//! When we decide to retire a peer-issued CID (e.g. because the peer demanded
//! it via `retire_prior_to`), `PeerCidPool` queues a `RETIRE_CONNECTION_ID`
//! frame for transmission.

use std::collections::VecDeque;

use hmac::{Hmac, KeyInit, Mac};
use oxiquic_core::{ConnectionId, FrameType, OxiQuicError, TransportErrorCode};
use sha2::Sha256;

// ─── Public data types ────────────────────────────────────────────────────────

/// One CID that this endpoint issued to the peer, with its sequence number
/// and stateless-reset token.
#[derive(Debug, Clone)]
pub struct IssuedCid {
    /// Sequence number (monotonically increasing, RFC 9000 §19.15).
    pub seq: u64,
    /// The issued connection ID.
    pub cid: ConnectionId,
    /// 16-byte stateless reset token derived from our server secret.
    pub stateless_reset_token: [u8; 16],
}

/// One CID the peer issued to us.
#[derive(Debug, Clone)]
pub struct PeerCid {
    /// Sequence number assigned by the peer.
    pub seq: u64,
    /// The connection ID.
    pub cid: ConnectionId,
    /// The stateless reset token the peer included (RFC 9000 §10.3.1).
    /// Consulted by [`PeerCidPool::matches_stateless_reset`] to detect
    /// stateless reset packets from the peer (RFC 9000 §10.3).
    pub stateless_reset_token: [u8; 16],
}

/// Events emitted to the endpoint demux layer when the routing table must
/// be updated.
///
/// The demux layer maps destination CID → connection channel. When a new
/// local CID is issued it must be added; when one is retired it must be
/// removed.
#[derive(Debug, Clone)]
pub enum CidEvent {
    /// A new local CID has been issued to the peer; the demux must add it to
    /// its routing table so packets carrying it reach this connection.
    Register(ConnectionId),
    /// A local CID has been retired; the demux must remove it from its
    /// routing table.
    Unregister(ConnectionId),
    /// The handshake for this connection has completed (success or failure).
    /// The demux must remove the client's initial DCID from `initial_map`.
    ///
    /// This variant is originated by the endpoint layer (not by the connection
    /// state machine), and is never emitted via [`LocalCidPool`]. The bytes
    /// are the client's original DCID used as the `initial_map` key.
    InitialRetired(Vec<u8>),
}

// ─── LocalCidPool ─────────────────────────────────────────────────────────────

/// Manages CIDs this endpoint has issued to the peer.
///
/// Seq 0 is the initial CID (exchanged in packet headers); it is pre-loaded
/// at construction and never re-emitted via NEW_CONNECTION_ID. Additional
/// CIDs are issued post-handshake up to `limit`.
#[derive(Debug)]
pub struct LocalCidPool {
    /// All active (not retired) issued CIDs, in seq order.
    active: Vec<IssuedCid>,
    /// The next sequence number to assign.
    next_seq: u64,
    /// NEW_CONNECTION_ID frames pending transmission.
    pub(crate) pending_new: VecDeque<IssuedCid>,
    /// 32-byte secret for HMAC-SHA256 stateless reset token derivation.
    secret: [u8; 32],
    /// Maximum number of active CIDs (our advertised
    /// `active_connection_id_limit`).
    pub(crate) limit: u64,
}

impl LocalCidPool {
    /// Create a new pool with `initial_cid` at seq 0. The initial CID is
    /// **not** queued for NEW_CONNECTION_ID emission — it was communicated
    /// during the handshake via packet headers.
    pub fn new(initial_cid: ConnectionId, secret: [u8; 32], limit: u64) -> Self {
        let token = stateless_reset_token(&secret, &initial_cid);
        Self {
            active: vec![IssuedCid {
                seq: 0,
                cid: initial_cid,
                stateless_reset_token: token,
            }],
            next_seq: 1,
            pending_new: VecDeque::new(),
            secret,
            limit,
        }
    }

    /// Issue a new CID using the 8 raw random bytes provided by the caller
    /// (the caller fills them via `secure_random.fill()`; avoids adding a
    /// `rand` dependency).
    ///
    /// Returns `(seq, cid)` on success, or an error if the pool is full.
    pub fn issue_new_cid(&mut self, raw: [u8; 8]) -> Result<(u64, ConnectionId), OxiQuicError> {
        if self.active.len() as u64 >= self.limit {
            return Err(OxiQuicError::Protocol(
                "active_connection_id_limit reached; cannot issue more CIDs".to_string(),
            ));
        }
        let cid = ConnectionId::from(&raw[..]);
        let token = stateless_reset_token(&self.secret, &cid);
        let seq = self.next_seq;
        self.next_seq += 1;
        let issued = IssuedCid {
            seq,
            cid: cid.clone(),
            stateless_reset_token: token,
        };
        self.pending_new.push_back(issued.clone());
        self.active.push(issued);
        Ok((seq, cid))
    }

    /// The peer sent `RETIRE_CONNECTION_ID` for `seq`. Remove the matching CID
    /// from the active set.
    ///
    /// Returns the retired `ConnectionId` so the caller can emit
    /// [`CidEvent::Unregister`], or `None` if `seq` was already retired or
    /// was never issued (idempotent per RFC 9000 §5.1.2).
    pub fn handle_peer_retirement(&mut self, seq: u64) -> Option<ConnectionId> {
        let pos = self.active.iter().position(|c| c.seq == seq)?;
        let removed = self.active.remove(pos);
        Some(removed.cid)
    }

    /// Pop the next `NEW_CONNECTION_ID` frame data to emit, if any.
    pub fn pop_pending_new(&mut self) -> Option<IssuedCid> {
        self.pending_new.pop_front()
    }

    /// Whether there are pending NEW_CONNECTION_ID frames to emit.
    #[must_use]
    pub fn has_pending_new(&self) -> bool {
        !self.pending_new.is_empty()
    }

    /// The number of currently active (non-retired) issued CIDs.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Whether we can issue more CIDs without exceeding the limit.
    #[must_use]
    pub fn can_issue(&self) -> bool {
        (self.active.len() as u64) < self.limit
    }
}

// ─── PeerCidPool ──────────────────────────────────────────────────────────────

/// Manages CIDs the peer has issued to us.
///
/// Seq 0 is the peer's initial CID (their SCID from the handshake). The peer
/// may issue additional CIDs via NEW_CONNECTION_ID and may ask us to retire
/// old ones via the `retire_prior_to` field.
#[derive(Debug)]
pub struct PeerCidPool {
    /// All active peer-issued CIDs not yet retired by us.
    active: Vec<PeerCid>,
    /// The lowest seq we have not yet retired (updated when we process
    /// `retire_prior_to` from a NEW_CONNECTION_ID frame).
    retire_threshold: u64,
    /// RETIRE_CONNECTION_ID frames pending transmission.
    pub(crate) pending_retire: VecDeque<u64>,
    /// Maximum number of peer CIDs we will track (peer's advertised
    /// `active_connection_id_limit`).
    limit: u64,
}

impl PeerCidPool {
    /// Create a new pool with the peer's initial CID at seq 0.
    pub fn new(initial_cid: ConnectionId, limit: u64) -> Self {
        Self {
            active: vec![PeerCid {
                seq: 0,
                cid: initial_cid,
                stateless_reset_token: [0u8; 16],
            }],
            retire_threshold: 0,
            pending_retire: VecDeque::new(),
            limit,
        }
    }

    /// Process a received NEW_CONNECTION_ID frame (RFC 9000 §19.15).
    ///
    /// Validates the `seq`/`retire_prior_to` relationship, stores the new CID,
    /// and queues RETIRE_CONNECTION_ID for any CIDs below `retire_prior_to`.
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError::TransportError`] on protocol violation or
    /// if the new CID would exceed our advertised `active_connection_id_limit`.
    pub fn receive_new_cid(
        &mut self,
        seq: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [u8; 16],
    ) -> Result<(), OxiQuicError> {
        // retire_prior_to <= seq enforced by the frame decoder; double-check
        // here for safety.
        if retire_prior_to > seq {
            return Err(OxiQuicError::TransportError {
                code: TransportErrorCode::FrameEncodingError,
                frame_type: Some(FrameType::NewConnectionId),
                reason: "NEW_CONNECTION_ID: retire_prior_to > seq".to_string(),
            });
        }

        // Duplicate seq: idempotent, nothing to do (RFC 9000 §5.1.1).
        if self.active.iter().any(|c| c.seq == seq) {
            return Ok(());
        }

        // Count active CIDs that will remain after applying retire_prior_to.
        // We must not exceed our advertised active_connection_id_limit.
        let active_after = self
            .active
            .iter()
            .filter(|c| c.seq >= retire_prior_to)
            .count()
            + 1; // +1 for the new CID
        if active_after as u64 > self.limit {
            return Err(OxiQuicError::TransportError {
                code: TransportErrorCode::ConnectionIdLimitError,
                frame_type: Some(FrameType::NewConnectionId),
                reason: "NEW_CONNECTION_ID: would exceed active_connection_id_limit".to_string(),
            });
        }

        // Queue RETIRE_CONNECTION_ID for every CID that retire_prior_to
        // demands we retire (RFC 9000 §5.1.2).
        if retire_prior_to > self.retire_threshold {
            for entry in self.active.iter().filter(|c| c.seq < retire_prior_to) {
                self.pending_retire.push_back(entry.seq);
            }
            self.active.retain(|c| c.seq >= retire_prior_to);
            self.retire_threshold = retire_prior_to;
        }

        // Store the new CID.
        self.active.push(PeerCid {
            seq,
            cid,
            stateless_reset_token,
        });

        Ok(())
    }

    /// Pop the next RETIRE_CONNECTION_ID sequence number to emit, if any.
    pub fn pop_pending_retire(&mut self) -> Option<u64> {
        self.pending_retire.pop_front()
    }

    /// Re-queue a RETIRE_CONNECTION_ID sequence number at the front
    /// (used when the send path had insufficient budget).
    pub fn push_front_retire(&mut self, seq: u64) {
        self.pending_retire.push_front(seq);
    }

    /// Whether there are pending RETIRE_CONNECTION_ID frames to emit.
    #[must_use]
    pub fn has_pending_retire(&self) -> bool {
        !self.pending_retire.is_empty()
    }

    /// The current preferred peer CID (lowest-seq active entry).
    ///
    /// Returns `None` only if the pool is empty, which should not happen in
    /// a live connection.
    #[must_use]
    pub fn preferred_cid(&self) -> Option<&ConnectionId> {
        self.active.iter().min_by_key(|c| c.seq).map(|c| &c.cid)
    }

    /// Check whether `token` matches any stateless reset token stored in this
    /// pool (RFC 9000 §10.3). Returns `true` if an incoming packet's trailing
    /// 16 bytes match a token issued by the peer — signalling a stateless
    /// reset that terminates the connection.
    #[must_use]
    pub fn matches_stateless_reset(&self, token: &[u8; 16]) -> bool {
        self.active
            .iter()
            .any(|c| &c.stateless_reset_token == token)
    }

    /// The number of active (non-retired) peer-issued CIDs.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Return an iterator over all stateless reset tokens stored in this pool.
    ///
    /// Each token is the 16-byte value the peer included in a
    /// `NEW_CONNECTION_ID` frame (RFC 9000 §10.3.1). Used by tests to fabricate
    /// stateless reset packets and verify detection logic.
    pub fn stateless_reset_tokens(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.active.iter().map(|c| &c.stateless_reset_token)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Compute a 16-byte stateless reset token:
/// `HMAC-SHA256(secret, cid_bytes)[0..16]` (RFC 9000 §10.3.1).
///
/// HMAC accepts any key length (per the HMAC RFC), so the `new_from_slice`
/// call here is always infallible for a 32-byte key.
pub fn stateless_reset_token(secret: &[u8; 32], cid: &ConnectionId) -> [u8; 16] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    Mac::update(&mut mac, cid.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut token = [0u8; 16];
    token.copy_from_slice(&result[..16]);
    token
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn cid(n: u8) -> ConnectionId {
        ConnectionId::from(&[n; 8][..])
    }

    // ── LocalCidPool ──────────────────────────────────────────────────────────

    #[test]
    fn local_pool_initial_state() {
        let pool = LocalCidPool::new(cid(1), secret(), 7);
        assert_eq!(pool.active_count(), 1);
        assert!(pool.can_issue());
        assert!(!pool.has_pending_new());
    }

    #[test]
    fn local_pool_issue_and_pop() {
        let mut pool = LocalCidPool::new(cid(1), secret(), 7);
        let (seq, issued_cid) = pool.issue_new_cid([0x02u8; 8]).expect("issue");
        assert_eq!(seq, 1);
        assert_eq!(pool.active_count(), 2);
        assert!(pool.has_pending_new());
        let pending = pool.pop_pending_new().expect("pending");
        assert_eq!(pending.seq, 1);
        assert_eq!(pending.cid, issued_cid);
        assert!(!pool.has_pending_new());
    }

    #[test]
    fn local_pool_limit_enforced() {
        let mut pool = LocalCidPool::new(cid(1), secret(), 2);
        pool.issue_new_cid([0x02u8; 8]).expect("first issue ok");
        let err = pool
            .issue_new_cid([0x03u8; 8])
            .expect_err("should hit limit");
        assert!(err.to_string().contains("active_connection_id_limit"));
    }

    #[test]
    fn local_pool_retirement() {
        let mut pool = LocalCidPool::new(cid(1), secret(), 7);
        pool.issue_new_cid([0x02u8; 8]).expect("issue");
        // Retire seq 0 (the initial CID).
        let retired = pool.handle_peer_retirement(0);
        assert!(retired.is_some());
        assert_eq!(pool.active_count(), 1);
        // Retire seq 0 again: idempotent, returns None.
        let again = pool.handle_peer_retirement(0);
        assert!(again.is_none());
    }

    // ── PeerCidPool ───────────────────────────────────────────────────────────

    #[test]
    fn peer_pool_initial_state() {
        let pool = PeerCidPool::new(cid(1), 7);
        assert_eq!(pool.active_count(), 1);
        assert!(!pool.has_pending_retire());
    }

    #[test]
    fn peer_pool_receive_new_cid() {
        let mut pool = PeerCidPool::new(cid(1), 7);
        pool.receive_new_cid(1, 0, cid(2), [0u8; 16])
            .expect("receive");
        assert_eq!(pool.active_count(), 2);
        assert!(!pool.has_pending_retire());
    }

    #[test]
    fn peer_pool_retire_prior_to() {
        let mut pool = PeerCidPool::new(cid(1), 7);
        pool.receive_new_cid(1, 0, cid(2), [0u8; 16])
            .expect("add seq 1");
        // Now peer issues seq 2 with retire_prior_to=1: seq 0 and 1 must be
        // retired.
        pool.receive_new_cid(2, 1, cid(3), [0u8; 16])
            .expect("add seq 2");
        // seq 0 (< 1) should be queued for retirement.
        assert!(pool.has_pending_retire());
        let r = pool.pop_pending_retire().expect("retire seq 0");
        assert_eq!(r, 0);
        assert!(!pool.has_pending_retire());
        // Active should now be seq 1 and seq 2 (threshold is 1, so seq 0 was removed).
        assert_eq!(pool.active_count(), 2);
    }

    #[test]
    fn peer_pool_limit_enforced() {
        let mut pool = PeerCidPool::new(cid(1), 2);
        pool.receive_new_cid(1, 0, cid(2), [0u8; 16])
            .expect("seq 1 ok");
        // Attempting to add seq 2 would push active count to 3, exceeding limit=2.
        let err = pool
            .receive_new_cid(2, 0, cid(3), [0u8; 16])
            .expect_err("should exceed limit");
        assert!(matches!(
            err,
            OxiQuicError::TransportError {
                code: TransportErrorCode::ConnectionIdLimitError,
                ..
            }
        ));
    }

    #[test]
    fn peer_pool_duplicate_seq_idempotent() {
        let mut pool = PeerCidPool::new(cid(1), 7);
        pool.receive_new_cid(1, 0, cid(2), [0u8; 16])
            .expect("first");
        // Duplicate: must not error and must not add.
        pool.receive_new_cid(1, 0, cid(2), [0u8; 16])
            .expect("duplicate ok");
        assert_eq!(pool.active_count(), 2);
    }

    // ── PeerCidPool: preferred_cid and stateless-reset matching ──────────────

    #[test]
    fn peer_pool_preferred_cid_is_lowest_seq() {
        let mut pool = PeerCidPool::new(cid(1), 7);
        // After adding seq 1 and seq 2, seq 0 (initial) remains the preferred.
        pool.receive_new_cid(1, 0, cid(2), [0xaau8; 16])
            .expect("seq 1");
        pool.receive_new_cid(2, 0, cid(3), [0xbbu8; 16])
            .expect("seq 2");
        let preferred = pool.preferred_cid().expect("non-empty pool");
        assert_eq!(*preferred, cid(1)); // seq 0 has cid(1)
    }

    #[test]
    fn peer_pool_matches_stateless_reset_token() {
        let mut pool = PeerCidPool::new(cid(1), 7);
        let token: [u8; 16] = [0xddu8; 16];
        pool.receive_new_cid(1, 0, cid(2), token)
            .expect("add with token");
        // The stored token must match.
        assert!(pool.matches_stateless_reset(&token));
        // A different token must not match.
        let other: [u8; 16] = [0xeeu8; 16];
        assert!(!pool.matches_stateless_reset(&other));
    }

    // ── stateless_reset_token ─────────────────────────────────────────────────

    #[test]
    fn token_is_16_bytes_and_deterministic() {
        let s = secret();
        let c = cid(0xab);
        let t1 = stateless_reset_token(&s, &c);
        let t2 = stateless_reset_token(&s, &c);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 16);
    }

    #[test]
    fn different_cids_give_different_tokens() {
        let s = secret();
        let t1 = stateless_reset_token(&s, &cid(1));
        let t2 = stateless_reset_token(&s, &cid(2));
        assert_ne!(t1, t2);
    }
}
