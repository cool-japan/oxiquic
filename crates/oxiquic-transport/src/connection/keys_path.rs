//! Key update (RFC 9001 §6) and path migration (RFC 9000 §9) APIs.
//!
//! Key update: `initiate_key_update`, `initiate_key_update_now`,
//! `perform_key_update`, `key_update_count`.
//!
//! Path migration: `initiate_path_challenge`, `set_candidate_peer_addr`,
//! `path_validated`.

use std::time::Instant;

use oxiquic_core::OxiQuicError;

use super::Connection;

impl Connection {
    /// Rotate to the next key epoch after a successful key-update decryption.
    ///
    /// * Promotes `next_1rtt_keys` into `application` (packet keys only;
    ///   header protection keys are unchanged per RFC 9001 §6).
    /// * Saves the old remote packet key in `prev_1rtt_keys` for 3 PTO (§6.6).
    /// * Derives new `next_1rtt_keys` from the advanced secrets.
    /// * Flips `key_phase` and sets `key_update_received`.
    pub(super) fn perform_key_update(&mut self, now: Instant) {
        // Retirement deadline: 3 PTO (RFC 9001 §6.6).
        let pto_base = self.rtt.pto_base(self.peer_max_ack_delay);
        let retire_after = now + pto_base * 3;

        if let Some(ref mut secrets) = self.one_rtt_secrets {
            // Advance the secrets ratchet to derive the generation after next.
            let new_next_keys = secrets.next_packet_keys();
            if let Some(next_epoch) = self.next_1rtt_keys.take() {
                if let Some(old_remote) = self.application.rotate_to_next_epoch(next_epoch) {
                    self.prev_1rtt_keys = Some((old_remote, retire_after));
                }
                self.next_1rtt_keys = Some(new_next_keys);
            }
        }

        self.key_phase = !self.key_phase;
        self.key_update_received = true;
        self.key_update_count += 1;
        self.key_update_cooldown = Some(now + pto_base * 3);
    }

    /// Initiate a key update on the next outgoing 1-RTT packet.
    ///
    /// Per RFC 9001 §6.5, a key update MUST NOT be initiated within 3 PTO of
    /// the previous update. If the cooldown has not elapsed this is a no-op.
    /// Returns `true` if the update was scheduled, `false` if it was refused
    /// due to the cooldown.
    ///
    /// `now` is the caller's notion of the current time, used to evaluate the
    /// 3-PTO cooldown.  Pass a consistent clock value (the same one you pass to
    /// `poll_transmit` / `handle_datagram`) so that logical-clock tests work
    /// correctly without relying on wall-clock advancement.
    pub fn initiate_key_update(&mut self, now: Instant) -> bool {
        if let Some(cooldown) = self.key_update_cooldown {
            if now < cooldown {
                return false;
            }
        }
        if !self.one_rtt_ready || self.next_1rtt_keys.is_none() {
            return false; // no 1-RTT keys yet
        }
        self.key_update_pending = true;
        true
    }

    /// Actually perform the locally-initiated key update at `now`.
    ///
    /// Called from `write_space_packet` just before the first outgoing packet
    /// of the new epoch.
    pub(super) fn initiate_key_update_now(&mut self, now: Instant) {
        self.key_update_pending = false;
        if let Some(ref mut secrets) = self.one_rtt_secrets {
            let new_next_keys = secrets.next_packet_keys();
            if let Some(next_epoch) = self.next_1rtt_keys.take() {
                let pto_base = self.rtt.pto_base(self.peer_max_ack_delay);
                let retire_after = now + pto_base * 3;
                if let Some(old_remote) = self.application.rotate_to_next_epoch(next_epoch) {
                    self.prev_1rtt_keys = Some((old_remote, retire_after));
                }
                self.next_1rtt_keys = Some(new_next_keys);
            }
        }
        self.key_phase = !self.key_phase;
        self.key_update_count += 1;
        let pto_base = self.rtt.pto_base(self.peer_max_ack_delay);
        self.key_update_cooldown = Some(now + pto_base * 3);
    }

    /// The number of completed key updates (including both locally- and
    /// peer-initiated).  For test observability.
    #[must_use]
    pub fn key_update_count(&self) -> u64 {
        self.key_update_count
    }

    // ─── Path migration API (RFC 9000 §9) ────────────────────────────────────

    /// Begin a path challenge toward the current (or candidate) peer address.
    ///
    /// Generates 8 cryptographically random bytes and queues a `PATH_CHALLENGE`
    /// frame for the next outgoing 1-RTT packet (RFC 9000 §9.1, §19.17).
    ///
    /// Returns `Ok(())` on success.  Fails with [`OxiQuicError::Connection`] if
    /// the secure RNG cannot produce random bytes, or if the 1-RTT keys are not
    /// yet available (challenge frames are 1-RTT-only).
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] when:
    /// * The secure RNG fails (extremely unlikely, indicates OS-level failure).
    /// * The connection has not yet completed the handshake.
    pub fn initiate_path_challenge(&mut self) -> Result<(), OxiQuicError> {
        if !self.one_rtt_ready {
            return Err(OxiQuicError::Connection(
                "cannot send PATH_CHALLENGE before 1-RTT keys are ready".into(),
            ));
        }
        let mut nonce = [0u8; 8];
        self.secure_random
            .fill(&mut nonce)
            .map_err(|_| OxiQuicError::Connection("secure RNG failed".into()))?;
        self.pending_path_challenge = Some(nonce);
        self.pending_path_challenge_send = true;
        self.path_validated = false;
        Ok(())
    }

    /// Set a candidate peer address for path migration (RFC 9000 §9.3).
    ///
    /// The connection will send a `PATH_CHALLENGE` toward the current peer;
    /// when the response is validated the connection migrates to `addr`.
    /// Call [`Self::initiate_path_challenge`] after this to start the probe.
    pub fn set_candidate_peer_addr(&mut self, addr: std::net::SocketAddr) {
        self.candidate_peer_addr = Some(addr);
        // A new candidate invalidates any previous challenge state.
        self.pending_path_challenge = None;
        self.pending_path_challenge_send = false;
        self.path_validated = false;
    }

    /// Whether the most recent locally-initiated path challenge was answered
    /// with a matching `PATH_RESPONSE` (RFC 9000 §9.3).
    ///
    /// Remains `true` until the next call to [`Self::initiate_path_challenge`] or
    /// [`Self::set_candidate_peer_addr`].
    #[must_use]
    pub fn path_validated(&self) -> bool {
        self.path_validated
    }
}
