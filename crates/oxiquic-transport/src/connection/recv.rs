//! Receive path: datagram ingestion, packet decryption, frame dispatch.
//!
//! Contains [`Connection::handle_datagram`] and all the helpers it calls:
//! long-header parsing, Retry handling, short-header / key-update decryption,
//! frame dispatch (`process_frames` / `handle_frame`), CRYPTO delivery, and
//! stream data ingestion.

use std::time::Instant;

use crate::flow_control::StreamSendFlow;
use crate::frame::{decode_frame, Frame};
use crate::packet::{decrypt_short_packet_body, parse_long_packet, strip_short_header_protection};
use crate::stream::StreamError;
use oxiquic_core::{
    ConnectionId, Direction, FrameType, Initiator, OxiQuicError, PacketType, StreamId,
    TransportErrorCode,
};

use super::{Connection, ConnectionState, LOCAL_CID_LEN, QUIC_V1};

impl Connection {
    /// Feed a received UDP datagram into the connection. The datagram is
    /// decrypted in place (so it must be mutable and owned by the caller).
    ///
    /// # Errors
    /// Returns an [`OxiQuicError`] only for fatal protocol violations; packets
    /// that cannot yet be decrypted (missing keys) are silently skipped per
    /// RFC 9000 Section 5.2.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        datagram: &mut [u8],
    ) -> Result<(), OxiQuicError> {
        self.arm_idle_timer(now);
        self.packets_recv += 1;
        self.bytes_recv += datagram.len() as u64;
        let mut offset = 0;
        while offset < datagram.len() {
            let first = datagram[offset];
            if first == 0 {
                break; // trailing padding between/after packets
            }
            let consumed = if first & 0x80 != 0 {
                self.recv_long_packet(now, datagram, offset)?
            } else {
                self.recv_short_packet(now, datagram, offset)?
            };
            match consumed {
                Some(end) => offset = end,
                None => break,
            }
            // Drive the handshake forward immediately so that keys installed by
            // a just-processed packet (e.g. Handshake keys after the Initial
            // carrying ServerHello) are available to decrypt the next coalesced
            // packet in this same datagram.
            self.pump_write_hs();
            // Attempt to install 0-RTT keys after each handshake pump so the
            // server can decrypt a coalesced 0-RTT packet in the same datagram.
            // Skip once established (keys already set or not applicable).
            if !self.handshake_complete && self.zero_rtt_keys.is_none() {
                self.try_install_zero_rtt_keys();
            }
        }
        Ok(())
    }

    /// Parse, decrypt and process one long-header packet at `offset`. Returns
    /// the offset of the next coalesced packet, or `None` to stop.
    fn recv_long_packet(
        &mut self,
        now: Instant,
        datagram: &mut [u8],
        offset: usize,
    ) -> Result<Option<usize>, OxiQuicError> {
        let packet_type = match crate::packet::peek_dcid(&datagram[offset..], LOCAL_CID_LEN) {
            Ok((ty, _)) => ty,
            Err(_) => return Ok(None),
        };

        // RFC 9000 §17.2.1 / §6.2: A Version Negotiation packet arriving
        // during the handshake (and before any successful packet has been
        // processed) means the server does not support QUIC v1.  Fail the
        // connection.  If we have already received packets from this server we
        // MUST ignore VN (to prevent spoofed/replayed VN from killing live
        // connections).
        if packet_type == PacketType::VersionNegotiation {
            if self.role == super::Role::Client
                && self.state == ConnectionState::Handshaking
                && self.initial.largest_received().is_none()
            {
                let supported = crate::packet::decode_version_negotiation(&datagram[offset..])
                    .unwrap_or_default();
                return Err(OxiQuicError::VersionNegotiation { supported });
            }
            // Outside the early-handshake window: silently ignore.
            return Ok(None);
        }

        // ── RFC 9000 §17.2.5 / RFC 9001 §5.8: Retry ─────────────────────────
        if packet_type == PacketType::Retry {
            return self.recv_retry_packet(datagram, offset);
        }

        // Handle 0-RTT packets on the server side using the early keys.
        if packet_type == PacketType::ZeroRtt {
            return self.recv_zero_rtt_packet(now, datagram, offset);
        }

        let space = match packet_type {
            PacketType::Initial => &self.initial,
            PacketType::Handshake => &self.handshake,
            _ => return Ok(None),
        };
        let (packet_key, header_key) = match (space.remote_keys(), packet_type) {
            (Some(keys), _) => (keys.packet.as_ref(), keys.header.as_ref()),
            // No keys yet for this space: cannot decrypt; skip remaining.
            (None, _) => return Ok(None),
        };
        let largest = space.largest_received();
        let parsed =
            match parse_long_packet(datagram, offset, QUIC_V1, largest, packet_key, header_key) {
                Ok(p) => p,
                // A packet we cannot decrypt (e.g. keys not yet installed, or a
                // spurious/duplicate) is skipped per RFC 9000 Section 5.2.
                Err(_) => return Ok(None),
            };
        let next = parsed.consumed;

        // The destination connection ID must address us. A peer addresses its
        // early packets to the connection ID that seeds the Initial keys
        // (`initial_dcid`) and switches to our issued `local_cid` once it learns
        // it; accept either. Anything else is not ours (single-connection
        // server), so skip it.
        let dcid = parsed.dcid.as_slice();
        if !dcid.is_empty()
            && dcid != self.local_cid.as_bytes()
            && dcid != self.initial_dcid.as_bytes()
        {
            return Ok(Some(next));
        }

        // On the client, the server's SCID becomes our peer CID and (until the
        // first server packet) we adopt it as the destination for Handshake/1-RTT.
        if self.role == super::Role::Client
            && parsed.packet_type == PacketType::Initial
            && !parsed.scid.is_empty()
        {
            self.peer_cid = ConnectionId::new(parsed.scid.clone());
        }

        let ack_eliciting = self.process_frames(now, parsed.packet_type, &parsed.payload)?;
        let space = match parsed.packet_type {
            PacketType::Initial => &mut self.initial,
            PacketType::Handshake => &mut self.handshake,
            _ => return Ok(Some(next)),
        };
        space.on_packet_received(parsed.packet_number, ack_eliciting);
        Ok(Some(next))
    }

    /// Process a Retry packet (RFC 9000 §17.2.5, RFC 9001 §5.8).
    ///
    /// A valid Retry causes the client to:
    /// 1. Verify the integrity tag.
    /// 2. Store the token.
    /// 3. Re-derive Initial keys from the Retry's SCID.
    /// 4. Reset the Initial PN space and re-queue the ClientHello.
    ///
    /// Returns `Ok(None)` to stop processing the datagram (no further coalesced
    /// packets can follow a Retry since it has no Length field).
    fn recv_retry_packet(
        &mut self,
        datagram: &[u8],
        offset: usize,
    ) -> Result<Option<usize>, OxiQuicError> {
        use crate::packet::{parse_retry_packet, verify_retry_integrity_tag};

        // Only the client processes Retry; only during the handshake; only once.
        if self.role != super::Role::Client
            || self.state != ConnectionState::Handshaking
            || self.retry_done
        {
            return Ok(None);
        }
        // Ignore if we have already received a successful packet from the server
        // (RFC 9000 §17.2.5.2).
        if self.initial.largest_received().is_some() {
            return Ok(None);
        }

        let packet = &datagram[offset..];

        // The ODCID used to verify the tag is the *current* initial_dcid
        // (before re-keying).
        let odcid = self.initial_dcid.as_bytes().to_vec();

        if !verify_retry_integrity_tag(&odcid, packet) {
            // Invalid integrity tag: silently ignore per RFC 9000 §17.2.5.2.
            return Ok(None);
        }

        let (scid, _dcid, token) = match parse_retry_packet(packet) {
            Some(t) => t,
            None => return Ok(None),
        };

        // Update peer CID to Retry's SCID (this becomes the DCID for our
        // retransmitted Initial and all subsequent packets).
        self.peer_cid = ConnectionId::new(scid.clone());
        self.retry_done = true;

        // Re-key the Initial space using the Retry's SCID as the new ODCID.
        self.rekey_initial_for_retry(scid, token);

        // Return None: no further packets are coalesced with a Retry.
        Ok(None)
    }

    /// Decrypt and process a 0-RTT long-header packet (RFC 9001 §4.6).
    ///
    /// Server-only: uses `zero_rtt_keys` (the early opening key). Shares the
    /// Application packet-number space (RFC 9001 §4.1.1). Returns `Ok(None)` if
    /// keys are not yet available (safe to drop — client will retransmit in 1-RTT
    /// per RFC 9000 §5.2).
    fn recv_zero_rtt_packet(
        &mut self,
        now: Instant,
        datagram: &mut [u8],
        offset: usize,
    ) -> Result<Option<usize>, OxiQuicError> {
        // 0-RTT is only processed on the server side.
        if self.role != super::Role::Server {
            return Ok(None);
        }

        // We need to take the keys to avoid borrowing self twice.
        let keys = match self.zero_rtt_keys.take() {
            Some(k) => k,
            // Keys not yet derived: drop safely (RFC 9000 §5.2).
            None => return Ok(None),
        };

        let largest = self.application.largest_received();
        let parsed = match parse_long_packet(
            datagram,
            offset,
            QUIC_V1,
            largest,
            keys.packet.as_ref(),
            keys.header.as_ref(),
        ) {
            Ok(p) => {
                // Put keys back on success.
                self.zero_rtt_keys = Some(keys);
                p
            }
            Err(_) => {
                // Decryption failure: keys back, skip packet (RFC 9000 §5.2).
                self.zero_rtt_keys = Some(keys);
                return Ok(None);
            }
        };
        let next = parsed.consumed;

        // RFC 9001 §4.6: 0-RTT packets must NOT carry ACK, CRYPTO,
        // HANDSHAKE_DONE, NEW_TOKEN, PATH_CHALLENGE, or PATH_RESPONSE.
        // We route them through process_frames using PacketType::ZeroRtt;
        // forbidden frames will be handled gracefully (ACK processing works,
        // CRYPTO would be ignored since ZeroRtt matches no crypto stream).
        let ack_eliciting = self.process_frames(now, PacketType::ZeroRtt, &parsed.payload)?;
        self.application
            .on_packet_received(parsed.packet_number, ack_eliciting);
        Ok(Some(next))
    }

    /// Parse, decrypt and process one short-header (1-RTT) packet at `offset`.
    ///
    /// Implements the key-update receive path (RFC 9001 §6):
    /// 1. Strip header protection with the (unchanged) current header key.
    /// 2. Read the Key Phase bit from the deprotected first byte.
    /// 3. If the key phase matches the current sending phase, decrypt with
    ///    the current packet key.  On failure, try prev keys (reordered pre-update
    ///    packet).
    /// 4. If the key phase does NOT match, this is a peer-initiated key update:
    ///    decrypt with `next_1rtt_keys`.  On success, promote next→current and
    ///    compute a new next epoch.
    ///
    /// If all decryption attempts are exhausted, the raw bytes are examined for
    /// a stateless reset per RFC 9000 §10.3 before returning `Ok(None)`.
    pub(super) fn recv_short_packet(
        &mut self,
        now: Instant,
        datagram: &mut [u8],
        offset: usize,
    ) -> Result<Option<usize>, OxiQuicError> {
        // Capture the length of this packet within the datagram for
        // stateless-reset detection.  We record this before any in-place
        // header-protection stripping so that `check_stateless_reset` can
        // always address the *original* trailing 16 bytes (RFC 9000 §10.3
        // checks the last 16 bytes of the received packet; header protection
        // only modifies the first byte and the packet-number bytes, never the
        // tail, so the token is intact regardless of stripping order).
        let packet_len = datagram[offset..].len();

        // Step 1: strip header protection in-place.  The borrow of
        // `self.application` is limited to this block; NLL drops it before
        // the AEAD step that might need `self.next_1rtt_keys`.
        let incoming_key_phase = {
            let hk = match self.application.remote_keys() {
                Some(keys) => keys.header.as_ref(),
                None => {
                    return self.check_stateless_reset(datagram, offset, packet_len);
                }
            };
            match strip_short_header_protection(datagram, offset, LOCAL_CID_LEN, hk) {
                Ok((kp, _)) => kp,
                Err(_) => {
                    return self.check_stateless_reset(datagram, offset, packet_len);
                }
            }
        }; // <-- borrow of self.application ends here

        let largest = self.application.largest_received();
        let current_key_phase = self.key_phase;

        if incoming_key_phase == current_key_phase {
            // --- Common path: same key phase → decrypt with current keys. ---
            let main_result = {
                let pk = match self.application.remote_keys() {
                    Some(keys) => keys.packet.as_ref(),
                    None => {
                        return self.check_stateless_reset(datagram, offset, packet_len);
                    }
                };
                decrypt_short_packet_body(datagram, offset, LOCAL_CID_LEN, largest, pk)
            }; // <-- borrow ends here

            let parsed = match main_result {
                Ok(p) => p,
                Err(_) => {
                    // Decryption failure with matching key phase: try prev keys
                    // for reordered pre-update packets (RFC 9001 §6.6).
                    let prev_result = match self.prev_1rtt_keys.as_ref() {
                        Some((prev_pk, retire_after)) if now <= *retire_after => {
                            let pk: &dyn rustls::quic::PacketKey = prev_pk.as_ref();
                            Some(decrypt_short_packet_body(
                                datagram,
                                offset,
                                LOCAL_CID_LEN,
                                largest,
                                pk,
                            ))
                        }
                        _ => None,
                    };
                    match prev_result {
                        Some(Ok(p)) => p,
                        _ => {
                            return self.check_stateless_reset(datagram, offset, packet_len);
                        }
                    }
                }
            };
            let consumed = parsed.consumed;
            let ack_eliciting = self.process_frames(now, PacketType::Short, &parsed.payload)?;
            self.application
                .on_packet_received(parsed.packet_number, ack_eliciting);
            Ok(Some(consumed))
        } else {
            // --- Key update path: key phase flipped → peer-initiated update. ---
            // Try to decrypt with the pre-derived next-epoch keys.
            let next_result = match self.next_1rtt_keys.as_ref() {
                Some(next_keys) => {
                    let pk: &dyn rustls::quic::PacketKey = next_keys.remote.as_ref();
                    decrypt_short_packet_body(datagram, offset, LOCAL_CID_LEN, largest, pk)
                }
                None => {
                    return self.check_stateless_reset(datagram, offset, packet_len);
                }
            }; // <-- borrow of self.next_1rtt_keys ends here

            let parsed = match next_result {
                Ok(p) => p,
                Err(_) => {
                    return self.check_stateless_reset(datagram, offset, packet_len);
                }
            };

            // Decryption succeeded → the peer has initiated a key update.
            // Rotate keys: next → current, derive new next, retire old current.
            self.perform_key_update(now);

            let consumed = parsed.consumed;
            let ack_eliciting = self.process_frames(now, PacketType::Short, &parsed.payload)?;
            self.application
                .on_packet_received(parsed.packet_number, ack_eliciting);
            Ok(Some(consumed))
        }
    }

    /// RFC 9000 §10.3: check whether the raw bytes at `datagram[offset..]` with
    /// length `packet_len` constitute a stateless reset.
    ///
    /// A stateless reset is recognised by:
    /// - The packet is at least 21 bytes long (RFC 9000 §10.3.1: the minimum
    ///   stateless reset size is 1 header byte + 4 pseudo-random bytes + 16-byte
    ///   token).
    /// - The last 16 bytes match a stateless reset token stored in our peer CID
    ///   pool (i.e., a token the peer sent us in a NEW_CONNECTION_ID frame).
    ///
    /// Note: `datagram` may have been modified in-place by header-protection
    /// stripping, but the last 16 bytes are never touched by that operation
    /// (header protection only alters the first byte and the packet-number
    /// bytes immediately after the connection ID), so reading from the original
    /// slice positions is always safe.
    fn check_stateless_reset(
        &self,
        datagram: &[u8],
        offset: usize,
        packet_len: usize,
    ) -> Result<Option<usize>, OxiQuicError> {
        // RFC 9000 §10.3: minimum stateless reset packet length is 21 bytes.
        if packet_len >= 21 {
            let end = offset + packet_len;
            // Safety: end is at most datagram.len() because packet_len was
            // computed as datagram[offset..].len() at the start of recv_short_packet.
            debug_assert!(end <= datagram.len());
            if end <= datagram.len() {
                let mut token = [0u8; 16];
                token.copy_from_slice(&datagram[end - 16..end]);
                if self.peer_cid_pool.matches_stateless_reset(&token) {
                    return Err(OxiQuicError::StatelessReset);
                }
            }
        }
        Ok(None)
    }

    /// Decode and act on the frames in a decrypted packet payload. Returns
    /// whether the packet was ack-eliciting.
    pub(super) fn process_frames(
        &mut self,
        now: Instant,
        packet_type: PacketType,
        payload: &[u8],
    ) -> Result<bool, OxiQuicError> {
        // Clear the per-packet scratch set used for RFC 9000 §19.16 same-packet
        // RETIRE_CONNECTION_ID validation.
        self.cids_issued_this_packet.clear();
        let mut buf = crate::coding::Buf::new(payload);
        let mut ack_eliciting = false;
        while !buf.is_empty() {
            let frame = decode_frame(&mut buf).map_err(|e| OxiQuicError::TransportError {
                code: e.code,
                frame_type: None,
                reason: e.detail.to_string(),
            })?;
            if frame.is_ack_eliciting() {
                ack_eliciting = true;
            }
            self.handle_frame(now, packet_type, frame)?;
        }
        Ok(ack_eliciting)
    }

    pub(super) fn handle_frame(
        &mut self,
        now: Instant,
        packet_type: PacketType,
        frame: Frame<'_>,
    ) -> Result<(), OxiQuicError> {
        match frame {
            Frame::Padding(_) | Frame::Ping => {}
            Frame::Ack {
                largest,
                delay,
                first_range,
                ranges,
            } => {
                self.process_ack(now, packet_type, largest, delay, first_range, &ranges);
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                ..
            } => {
                self.recv_reset_stream(stream_id, error_code)?;
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                self.recv_stop_sending(stream_id, error_code);
            }
            Frame::Crypto { offset, data } => {
                self.recv_crypto(packet_type, offset, data)?;
            }
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => self.recv_stream(id, offset, fin, data)?,
            Frame::MaxData(max) => {
                // RFC 9000 Section 4.1: raise our connection-level send limit.
                self.send_flow.on_max_data(max);
            }
            Frame::MaxStreamData { id, max } => {
                let initial = self.peer_initial_stream_limit();
                self.stream_send_flow
                    .entry(id)
                    .or_insert_with(|| StreamSendFlow::new(initial))
                    .on_max_stream_data(max);
            }
            Frame::DataBlocked(_) | Frame::StreamDataBlocked { .. } => {
                // The peer reports it is blocked sending to us; our receive-side
                // limit advances as the application reads (see `advance_flow`),
                // so no immediate action beyond acknowledgement is required.
            }
            Frame::PathChallenge(data) => {
                // RFC 9000 §8.2.2: echo PATH_CHALLENGE data in a PATH_RESPONSE.
                // Always respond regardless of source address.
                self.pending_path_response = Some(data);
            }
            Frame::PathResponse(data) => {
                // Validate against our outstanding challenge; promote candidate
                // address on success (RFC 9000 §9.3).
                if self.pending_path_challenge == Some(data) {
                    self.path_validated = true;
                    self.pending_path_challenge = None;
                    if let Some(addr) = self.candidate_peer_addr.take() {
                        self.peer_addr = addr;
                    }
                }
                // Mismatched PATH_RESPONSE: silently ignored per RFC 9000 §19.18.
            }
            Frame::HandshakeDone => {
                if self.role == super::Role::Client {
                    self.handshake_done = true;
                }
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                stateless_reset_token,
            } => {
                // NEW_CONNECTION_ID is only valid in 1-RTT (Application) space
                // (RFC 9000 §19.15 forbids it in Initial/Handshake).
                if packet_type != PacketType::Short {
                    return Err(OxiQuicError::TransportError {
                        code: TransportErrorCode::ProtocolViolation,
                        frame_type: Some(FrameType::NewConnectionId),
                        reason: "NEW_CONNECTION_ID received in non-1-RTT packet".to_string(),
                    });
                }
                self.peer_cid_pool.receive_new_cid(
                    seq,
                    retire_prior_to,
                    cid,
                    stateless_reset_token,
                )?;
                // Track this seq for same-packet RETIRE_CONNECTION_ID validation.
                self.cids_issued_this_packet.insert(seq);
            }
            Frame::RetireConnectionId { seq } => {
                // RETIRE_CONNECTION_ID is only valid in 1-RTT space.
                if packet_type != PacketType::Short {
                    return Err(OxiQuicError::TransportError {
                        code: TransportErrorCode::ProtocolViolation,
                        frame_type: Some(FrameType::RetireConnectionId),
                        reason: "RETIRE_CONNECTION_ID received in non-1-RTT packet".to_string(),
                    });
                }
                // RFC 9000 §19.16: the peer MUST NOT retire a CID that was
                // issued in the same packet as this RETIRE_CONNECTION_ID.
                if self.cids_issued_this_packet.contains(&seq) {
                    return Err(OxiQuicError::TransportError {
                        code: TransportErrorCode::ProtocolViolation,
                        frame_type: Some(FrameType::RetireConnectionId),
                        reason: "RETIRE_CONNECTION_ID for CID issued in same packet".to_string(),
                    });
                }
                if let Some(retired_cid) = self.local_cid_pool.handle_peer_retirement(seq) {
                    self.pending_cid_events
                        .push_back(crate::connection::cid::CidEvent::Unregister(retired_cid));
                    // Issue a replacement CID to keep the peer's pool replenished
                    // (RFC 9000 §5.1.1: maintain active_connection_id_limit supply).
                    let _ = self.maybe_issue_new_cid();
                }
            }
            Frame::ConnectionClose {
                error_code,
                application,
                reason,
                ..
            } => {
                let reason = String::from_utf8_lossy(&reason).into_owned();
                self.peer_closed = Some(if application {
                    OxiQuicError::ApplicationClose {
                        code: error_code,
                        reason,
                    }
                } else {
                    OxiQuicError::TransportError {
                        code: TransportErrorCode::from_u64(error_code),
                        frame_type: None,
                        reason,
                    }
                });
                self.state = ConnectionState::Closed;
            }
            Frame::MaxStreams { dir, max } => {
                // RFC 9000 §19.11: raise our stream-opening limit for the peer.
                match dir {
                    Direction::Bidirectional => {
                        if max > self.peer_max_streams_bidi {
                            self.peer_max_streams_bidi = max;
                        }
                    }
                    Direction::Unidirectional => {
                        if max > self.peer_max_streams_uni {
                            self.peer_max_streams_uni = max;
                        }
                    }
                }
            }
            Frame::StreamsBlocked { dir, .. } => {
                // Peer wants more streams — proactively raise our advertised limit
                // if we have headroom (RFC 9000 §19.14).
                self.maybe_raise_max_streams(dir);
            }
            Frame::NewToken(token) => {
                // RFC 9000 §19.7: server receiving NEW_TOKEN is a PROTOCOL_VIOLATION.
                if self.role == super::Role::Server {
                    return Err(OxiQuicError::TransportError {
                        code: TransportErrorCode::ProtocolViolation,
                        frame_type: Some(oxiquic_core::FrameType::NewToken),
                        reason: "server received NEW_TOKEN".to_string(),
                    });
                }
                // Only valid in 1-RTT (Short header) space.
                if packet_type != PacketType::Short {
                    return Err(OxiQuicError::TransportError {
                        code: TransportErrorCode::ProtocolViolation,
                        frame_type: Some(oxiquic_core::FrameType::NewToken),
                        reason: "NEW_TOKEN in non-1-RTT packet".to_string(),
                    });
                }
                self.received_token = Some(token.to_vec());
            }
            Frame::Datagram(data) => {
                // RFC 9221 §3: receiving a DATAGRAM when we advertised size 0 is
                // a PROTOCOL_VIOLATION.
                if self.local_max_datagram_frame_size == 0 {
                    return Err(OxiQuicError::TransportError {
                        code: TransportErrorCode::ProtocolViolation,
                        frame_type: None,
                        reason: "received DATAGRAM but local max_datagram_frame_size is 0"
                            .to_string(),
                    });
                }
                if data.len() as u64 > self.local_max_datagram_frame_size {
                    return Err(OxiQuicError::TransportError {
                        code: TransportErrorCode::ProtocolViolation,
                        frame_type: None,
                        reason: format!(
                            "DATAGRAM {} bytes exceeds local max {}",
                            data.len(),
                            self.local_max_datagram_frame_size
                        ),
                    });
                }
                // Enqueue, evicting the oldest datagram if the buffer is full.
                let total: usize = self
                    .datagram_recv_queue
                    .iter()
                    .map(|d| d.len())
                    .sum::<usize>()
                    + data.len();
                if total > self.datagram_recv_buffer_limit {
                    self.datagram_recv_queue.pop_front();
                }
                self.datagram_recv_queue.push_back(data.to_vec());
            }
            Frame::Unsupported(_) => {}
        }
        Ok(())
    }

    /// Proactively raise the MAX_STREAMS limit for `dir` when a STREAMS_BLOCKED
    /// is received from the peer (RFC 9000 §4.6). Uses a simple policy: bump by
    /// the number of peer-initiated streams that have been closed.
    fn maybe_raise_max_streams(&mut self, dir: Direction) {
        match dir {
            Direction::Bidirectional => {
                let new_max = self.local_max_streams_bidi + self.closed_peer_bidi;
                if new_max > self.sent_max_streams_bidi {
                    self.pending_max_streams_bidi = Some(new_max);
                }
            }
            Direction::Unidirectional => {
                let new_max = self.local_max_streams_uni + self.closed_peer_uni;
                if new_max > self.sent_max_streams_uni {
                    self.pending_max_streams_uni = Some(new_max);
                }
            }
        }
    }

    pub(super) fn recv_crypto(
        &mut self,
        packet_type: PacketType,
        offset: u64,
        data: &[u8],
    ) -> Result<(), OxiQuicError> {
        let delivered = match packet_type {
            PacketType::Initial => self.initial_crypto.recv(offset, data),
            PacketType::Handshake => self.handshake_crypto.recv(offset, data),
            _ => None,
        };
        if let Some(bytes) = delivered {
            self.tls
                .read_hs(&bytes)
                .map_err(|e| OxiQuicError::Tls(e.to_string()))?;
        }
        Ok(())
    }

    pub(super) fn recv_stream(
        &mut self,
        id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), OxiQuicError> {
        // Auto-create the recv (and, for a peer-opened bidi stream, send) state.
        let stream_id = StreamId::from(id);
        // Determine whether this stream ID is peer-initiated (i.e., opened by
        // the *remote* endpoint). If the initiator bit matches our role then the
        // stream was opened by us; otherwise it is peer-initiated.
        let peer_initiated = match self.role {
            super::Role::Client => stream_id.initiator() == Initiator::Server,
            super::Role::Server => stream_id.initiator() == Initiator::Client,
        };
        // Track peer-initiated streams the first time we see them so the
        // driven-connection layer can surface them via `poll_new_peer_stream`.
        let is_new = !self.recv_streams.contains_key(&id);
        if is_new && peer_initiated {
            self.new_peer_streams.push_back(stream_id);
        }
        if stream_id.direction() == Direction::Bidirectional {
            self.send_streams.entry(id).or_default();
            let initial = self.peer_initial_stream_limit();
            self.stream_send_flow
                .entry(id)
                .or_insert_with(|| StreamSendFlow::new(initial));
        }
        self.stream_recv_flow.entry(id).or_insert_with(|| {
            crate::flow_control::StreamRecvFlow::new(self.local_initial_max_stream_data)
        });
        let s = self.recv_streams.entry(id).or_default();
        // If the stream has already been reset by the peer, ignore further
        // STREAM frames (RFC 9000 §3.2: "A receiver MUST ignore STREAM frames
        // after receiving RESET_STREAM for the same stream").
        if s.is_reset() {
            return Ok(());
        }
        match s.recv(offset, data, fin) {
            Ok(true) => self.readable.push_back(stream_id),
            Ok(false) => {}
            Err(StreamError::FinalSize) => {
                return Err(OxiQuicError::TransportError {
                    code: TransportErrorCode::FinalSizeError,
                    frame_type: None,
                    reason: "stream final size violation".into(),
                })
            }
            Err(StreamError::Reset(_)) => {
                // `recv()` never returns this variant today; included for
                // exhaustiveness in case StreamError gains new variants.
            }
        }
        Ok(())
    }

    /// Handle a received `RESET_STREAM` frame (RFC 9000 §19.4): mark the
    /// receive stream as reset so the application can observe the error code.
    fn recv_reset_stream(&mut self, stream_id: u64, error_code: u64) -> Result<(), OxiQuicError> {
        let s = match self.recv_streams.get_mut(&stream_id) {
            Some(s) => s,
            // Unknown stream: ignore per RFC 9000 §3.2 (may be a stream we
            // have never seen; create a stub entry to surface the reset).
            None => {
                // Only create a stub for peer-initiated streams; locally-initiated
                // receive streams have no data until we open them so a reset is
                // protocol-level odd but not fatal.
                self.recv_streams.entry(stream_id).or_default()
            }
        };
        s.apply_reset(error_code);
        // Surface to the application so it can observe the reset via read_stream.
        let sid = StreamId::from(stream_id);
        self.readable.push_back(sid);
        Ok(())
    }

    /// Handle a received `STOP_SENDING` frame (RFC 9000 §19.5): per RFC 9000
    /// §3.5, we SHOULD respond with a `RESET_STREAM` on the send side using
    /// the provided error code.
    fn recv_stop_sending(&mut self, stream_id: u64, error_code: u64) {
        if let Some(s) = self.send_streams.get_mut(&stream_id) {
            // If the stream has already been reset (e.g. a concurrent local
            // reset raced with this STOP_SENDING), re-use the existing reset
            // code so the peer receives a consistent RESET_STREAM (RFC 9000 §3.5).
            let effective_code = s.reset_code().unwrap_or(error_code);
            // Capture the final size before (potentially) resetting.
            let final_size = s.final_size();
            if !s.is_reset() {
                s.reset(effective_code);
            }
            // Queue a RESET_STREAM to inform the peer (RFC 9000 §3.5).
            self.pending_reset_streams
                .insert(stream_id, (effective_code, final_size));
        }
        // If the stream is unknown (we never opened it), ignore silently.
    }
}
