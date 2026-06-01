//! Transmit path: packet building, payload filling, flow control, close.
//!
//! Contains [`Connection::poll_transmit`] and all the helpers it calls:
//! `write_space_packet`, `fill_payload`, flow-control frames, stream frames,
//! `emit_close`, `advance_recv_flow`, and send-readiness checks.

use std::net::SocketAddr;
use std::time::Instant;

use crate::coding::varint_size;
use crate::congestion::MAX_DATAGRAM_SIZE;
use crate::frame::Frame;
use crate::packet::{build_long_packet, build_short_packet, BuildLong, BuildShort, LongType};
use crate::recovery::SpaceIndex;
use crate::sent_packet::{SentFrame, SentPacket};
use oxiquic_core::Direction;

use super::{Connection, ConnectionState, SpaceKind, MAX_DATAGRAM, MIN_INITIAL_DATAGRAM};

impl Connection {
    /// Produce the next datagram to send, if any, appending it to `out` and
    /// returning the destination address. Returns `None` when there is nothing
    /// to send right now.
    pub fn poll_transmit(&mut self, now: Instant, out: &mut Vec<u8>) -> Option<SocketAddr> {
        self.pump_write_hs();

        if self.state == ConnectionState::Closed {
            return None;
        }

        // Emit a pending CONNECTION_CLOSE if one is queued.
        if self.pending_transport_close.is_some() || self.pending_close.is_some() {
            if let Some(addr) = self.emit_close(out) {
                self.state = ConnectionState::Closed;
                return Some(addr);
            }
        }

        // Advance our receive-side flow-control limits as the application has
        // consumed data, queueing MAX_DATA / MAX_STREAM_DATA where needed.
        self.advance_recv_flow();

        let start = out.len();
        // Coalesce Initial then Handshake then 1-RTT into a single datagram. The
        // Initial and Handshake spaces are never congestion-gated (they carry
        // the handshake and must make progress; RFC 9002 Section 7).
        let mut wrote_initial = false;
        if self.initial.has_keys() && self.space_has_output(SpaceKind::Initial) {
            wrote_initial = self.write_space_packet(now, SpaceKind::Initial, out, false);
        }
        let mut wrote_any = wrote_initial;
        if self.handshake_keys_ready && self.space_has_output(SpaceKind::Handshake) {
            wrote_any |= self.write_space_packet(now, SpaceKind::Handshake, out, false);
        }
        // Emit a 0-RTT packet coalesced with the Initial (RFC 9001 §4.6).
        // Only the client emits 0-RTT; only when Initial was written and 1-RTT
        // keys are not yet available.
        if wrote_initial && !self.one_rtt_ready {
            wrote_any |= self.write_zero_rtt_packet(now, out);
        }
        // RFC 9000 §12.2: do NOT coalesce 1-RTT packets with Initial packets.
        // When a client Initial is in flight the remote peer may not yet have
        // 1-RTT keys, so a coalesced short-header packet would be silently
        // dropped.  Emit Application-space packets only in their own datagrams
        // (i.e. when no Initial was written in this call).
        if !wrote_initial && self.one_rtt_ready && self.app_space_may_send() {
            wrote_any |= self.write_space_packet(now, SpaceKind::Application, out, true);
        }

        if !wrote_any {
            out.truncate(start);
            return None;
        }

        // RFC 9000 Section 14.1: a client Initial-bearing datagram must be
        // padded to at least 1200 bytes.
        if self.role == super::Role::Client && wrote_initial {
            let len = out.len() - start;
            if len < MIN_INITIAL_DATAGRAM {
                out.resize(start + MIN_INITIAL_DATAGRAM, 0);
            }
        }

        self.arm_idle_timer(now);
        // (Re)arm the loss-detection timer now that send state may have changed.
        self.set_loss_detection_timer(now);
        Some(self.peer_addr)
    }

    /// Whether the Application space has anything to send and is permitted to by
    /// congestion control. ACK-only output, PTO probes and keep-alive PINGs
    /// bypass the congestion window (RFC 9002 Section 7: only ack-eliciting data
    /// is gated).
    fn app_space_may_send(&mut self) -> bool {
        if !self.space_has_output(SpaceKind::Application) {
            return false;
        }
        // Non-data output (ACK / HANDSHAKE_DONE / flow-control / blocked frames),
        // probes, keep-alive PINGs, pending key updates, and path frames bypass
        // the congestion window (PATH_CHALLENGE/PATH_RESPONSE are small and
        // critical for path validation / anti-deadlock).
        if self.application.ack_pending()
            || self.handshake_done_to_send()
            || self.probes_owed > 0
            || self.pending_keep_alive_ping
            || self.pending_mtu_probe // RFC 8899 §5.2: exempt from cwnd
            || self.pending_max_data.is_some()
            || !self.pending_max_stream_data.is_empty()
            || self.pending_data_blocked.is_some()
            || !self.pending_stream_data_blocked.is_empty()
            || !self.pending_reset_streams.is_empty() // RFC 9000 §19.4
            || !self.pending_stop_sending.is_empty()  // RFC 9000 §19.5
            || self.key_update_pending // RFC 9001 §6: key update needs a packet
            || self.pending_path_response.is_some() // RFC 9000 §8.2.2
            || self.pending_path_challenge_send // RFC 9000 §9.1 probe queued
            || self.local_cid_pool.has_pending_new() // RFC 9000 §19.15
            || self.peer_cid_pool.has_pending_retire() // RFC 9000 §19.16
            || self.pending_max_streams_bidi.is_some() // RFC 9000 §4.6
            || self.pending_max_streams_uni.is_some()
            || self.pending_streams_blocked_bidi.is_some()
            || self.pending_streams_blocked_uni.is_some()
            || self.pending_new_token.is_some() // RFC 9000 §8.1.3
            || !self.datagram_send_queue.is_empty()
        // RFC 9221
        {
            return true;
        }
        // Otherwise this would be a data-bearing packet: gate on the window.
        self.congestion.can_send(MAX_DATAGRAM_SIZE)
    }

    pub(super) fn space_has_output(&mut self, kind: SpaceKind) -> bool {
        match kind {
            SpaceKind::Initial => self.initial_crypto.has_send_data() || self.initial.ack_pending(),
            SpaceKind::Handshake => {
                self.handshake_crypto.has_send_data() || self.handshake.ack_pending()
            }
            SpaceKind::Application => {
                self.application.ack_pending()
                    || self.handshake_done_to_send()
                    || self.any_stream_send_data()
                    || self.probes_owed > 0
                    || self.pending_keep_alive_ping
                    || self.pending_mtu_probe // RFC 8899 §5.2
                    || self.pending_max_data.is_some()
                    || !self.pending_max_stream_data.is_empty()
                    || self.pending_data_blocked.is_some()
                    || !self.pending_stream_data_blocked.is_empty()
                    || !self.pending_reset_streams.is_empty() // RFC 9000 §19.4
                    || !self.pending_stop_sending.is_empty()  // RFC 9000 §19.5
                    || self.key_update_pending  // RFC 9001 §6: key update needs a packet
                    || self.pending_path_response.is_some() // RFC 9000 §8.2.2
                    || self.pending_path_challenge_send // RFC 9000 §9.1 probe queued
                    || self.local_cid_pool.has_pending_new() // RFC 9000 §19.15
                    || self.peer_cid_pool.has_pending_retire() // RFC 9000 §19.16
                    || self.pending_max_streams_bidi.is_some() // RFC 9000 §4.6
                    || self.pending_max_streams_uni.is_some()
                    || self.pending_streams_blocked_bidi.is_some()
                    || self.pending_streams_blocked_uni.is_some()
                    || self.pending_new_token.is_some() // RFC 9000 §8.1.3
                    || !self.datagram_send_queue.is_empty() // RFC 9221
            }
        }
    }

    pub(super) fn handshake_done_to_send(&self) -> bool {
        self.role == super::Role::Server && self.handshake_complete && !self.handshake_done
    }

    fn any_stream_send_data(&self) -> bool {
        self.send_streams.values().any(|s| s.has_pending())
    }

    /// Build one packet for `kind` and append it to `out`. `short` selects the
    /// 1-RTT short header. Returns whether a packet was written. On success the
    /// packet is recorded for loss detection with the frames it carried, and
    /// in-flight bytes are charged to the congestion controller (RFC 9002 6.4).
    fn write_space_packet(
        &mut self,
        now: Instant,
        kind: SpaceKind,
        out: &mut Vec<u8>,
        short: bool,
    ) -> bool {
        // For Application space: if a MTU probe is pending, use the probe size
        // as the budget (probe packets may be larger than current_mtu); otherwise
        // use current_mtu. For Initial/Handshake use MAX_DATAGRAM (fixed at 1200).
        let budget = if kind == SpaceKind::Application {
            if self.pending_mtu_probe {
                self.probe_mtu
                    .map(|p| p as usize)
                    .unwrap_or(self.current_mtu as usize)
            } else {
                self.current_mtu as usize
            }
        } else {
            MAX_DATAGRAM
        };

        // Budget for this packet within the datagram.
        let remaining = budget.saturating_sub(out.len());
        if remaining < 64 {
            return false;
        }
        let packet_start = out.len();

        let mut payload = Vec::new();
        let (frames, ack_eliciting) = self.fill_payload(kind, &mut payload, remaining);
        if payload.is_empty() {
            return false;
        }

        // If a locally-initiated key update is pending, perform it now before
        // the first packet of the new epoch (RFC 9001 §6.1 / §6.5).
        if short && self.key_update_pending {
            self.initiate_key_update_now(now);
        }
        // Once we emit a packet with the new phase bit we are done signalling
        // the received update to the peer.
        if short {
            self.key_update_received = false;
        }

        let dcid = self.peer_cid.as_bytes().to_vec();
        let scid = self.local_cid.as_bytes().to_vec();

        let (pn, built) = if short {
            let key_phase = self.key_phase;
            let (pn, largest_acked, packet_key, header_key) = {
                let space = &mut self.application;
                let pn = space.next_pn();
                let la = space.largest_acked();
                match space.local_keys() {
                    Some(k) => (pn, la, k.packet.as_ref(), k.header.as_ref()),
                    None => return false,
                }
            };
            (
                pn,
                build_short_packet(
                    out,
                    &BuildShort {
                        dcid: &dcid,
                        packet_number: pn,
                        largest_acked,
                        key_phase,
                    },
                    &payload,
                    packet_key,
                    header_key,
                )
                .is_ok(),
            )
        } else {
            let long_type = match kind {
                SpaceKind::Initial => LongType::Initial,
                SpaceKind::Handshake => LongType::Handshake,
                SpaceKind::Application => return false,
            };
            let space = match kind {
                SpaceKind::Initial => &mut self.initial,
                SpaceKind::Handshake => &mut self.handshake,
                SpaceKind::Application => return false,
            };
            let pn = space.next_pn();
            let largest_acked = space.largest_acked();
            let (packet_key, header_key) = match space.local_keys() {
                Some(k) => (k.packet.as_ref(), k.header.as_ref()),
                None => return false,
            };
            // Include the retry token when retransmitting after a Retry
            // (RFC 9000 §17.2.2 / §8.1).
            let token = if kind == SpaceKind::Initial {
                self.retry_token.as_deref().unwrap_or(&[])
            } else {
                &[]
            };
            let params = BuildLong {
                long_type,
                version: super::QUIC_V1,
                dcid: &dcid,
                scid: &scid,
                token,
                packet_number: pn,
                largest_acked,
            };
            (
                pn,
                build_long_packet(out, &params, &payload, packet_key, header_key).is_ok(),
            )
        };

        if !built {
            return false;
        }

        // Check if this packet carries a MTU probe frame.
        let is_mtu_probe = frames.iter().any(|f| matches!(f, SentFrame::MtuProbe(_)));

        // Record the packet for loss detection and account for it.
        let sent_bytes = out.len() - packet_start;
        // MTU probe packets are ack-eliciting but NOT in-flight for congestion
        // purposes (RFC 8899 §5.2: probes are exempt from the congestion window).
        let in_flight = if is_mtu_probe {
            false
        } else {
            ack_eliciting // ack-eliciting packets count as in-flight
        };
        self.packets_sent += 1;
        self.bytes_sent += sent_bytes as u64;
        let rate_sample = if in_flight {
            self.congestion.on_packet_sent(sent_bytes, now)
        } else {
            None
        };
        if ack_eliciting || !frames.is_empty() {
            let idx = match kind {
                SpaceKind::Initial => SpaceIndex::Initial as usize,
                SpaceKind::Handshake => SpaceIndex::Handshake as usize,
                SpaceKind::Application => SpaceIndex::Application as usize,
            };
            self.sent_packets[idx].on_packet_sent(SentPacket {
                packet_number: pn,
                time_sent: now,
                ack_eliciting,
                in_flight,
                sent_bytes,
                frames,
                rate_sample,
            });
        }
        true
    }

    /// Fill `payload` with the frames to send for `kind`, up to roughly
    /// `budget` bytes. Returns the retransmittable frames placed (for the
    /// sent-packet record) and whether the packet is ack-eliciting.
    fn fill_payload(
        &mut self,
        kind: SpaceKind,
        payload: &mut Vec<u8>,
        budget: usize,
    ) -> (Vec<SentFrame>, bool) {
        let mut frames = Vec::new();
        let mut ack_eliciting = false;

        // ACK first (cheap, not ack-eliciting).
        let ack = match kind {
            SpaceKind::Initial => self.initial.build_ack(0),
            SpaceKind::Handshake => self.handshake.build_ack(0),
            SpaceKind::Application => self.application.build_ack(0),
        };
        if let Some(frame) = ack {
            frame.encode(payload);
        }

        // CRYPTO data for Initial/Handshake.
        let crypto = match kind {
            SpaceKind::Initial => Some(&mut self.initial_crypto),
            SpaceKind::Handshake => Some(&mut self.handshake_crypto),
            SpaceKind::Application => None,
        };
        if let Some(stream) = crypto {
            // Reserve room for frame header overhead.
            let avail = budget.saturating_sub(payload.len()).saturating_sub(16);
            if let Some((offset, data)) = stream.take_send(avail) {
                Frame::Crypto {
                    offset,
                    data: &data,
                }
                .encode(payload);
                frames.push(SentFrame::Crypto {
                    offset,
                    data: data.clone(),
                });
                ack_eliciting = true;
            }
        }

        // MTU probe: when pending, emit a dedicated PING+PADDING packet (RFC 8899
        // §4.1 / §5.2).  DPLPMTUD probes must NOT carry stream data — they are
        // exempt from the congestion window, so bundling user data would cause
        // those bytes to bypass cwnd accounting: sent but never credited to cwnd
        // growth, slowing the transfer.  Emitting the probe early (before stream
        // data) and returning immediately keeps the probe packet clean.
        //
        // Padding must go into the *plaintext* because short-header packets
        // carry no Length field: the receiver treats every byte from after the
        // header to the end of the datagram as `ciphertext || AEAD-tag`.
        // Appending zeros *after* encryption would shift the tag location,
        // causing the receiver's AEAD verification to fail silently.
        //
        // Short-header overhead on wire:
        //   1  (first byte)
        //   + dcid_len  (our CONNECTION_ID is LOCAL_CID_LEN = 8 bytes)
        //   + pn_len    (1–4 bytes; use 4 as worst-case)
        //   + tag_len   (always 16 bytes for AES-128-GCM / ChaCha20-Poly1305)
        // = 1 + 8 + 4 + 16 = 29 bytes  (conservative upper bound)
        //
        // We target: plaintext.len() == probe_size - overhead.
        // Using 4 for pn_len overshoots overhead by at most 3 bytes, which
        // means the padded datagram may be 1-3 bytes smaller than `probe_size`
        // — acceptable for a network-layer probe.
        if kind == SpaceKind::Application && self.pending_mtu_probe {
            if let Some(probe_size) = self.probe_mtu {
                // Conservative overhead: 1 (first) + 8 (dcid) + 4 (pn) + 16 (tag).
                const SHORT_HDR_OVERHEAD: usize = 1 + super::LOCAL_CID_LEN + 4 + 16;
                // Emit a PING frame (1 byte) first.
                Frame::Ping.encode(payload);
                frames.push(SentFrame::MtuProbe(probe_size));
                ack_eliciting = true;
                self.pending_mtu_probe = false;
                // Now pad the plaintext to `target_payload_len` with PADDING
                // frames (0x00 bytes per RFC 9000 §19.1).
                let target_payload_len = (probe_size as usize).saturating_sub(SHORT_HDR_OVERHEAD);
                if payload.len() < target_payload_len {
                    payload.resize(target_payload_len, 0x00);
                }
                // Return immediately: probe packets must not carry stream data
                // (exempt from cwnd means acked bytes never grow the window).
                return (frames, ack_eliciting);
            } else {
                // probe_mtu cleared (e.g. after give-up): cancel the pending probe
                // so app_space_may_send() is not permanently stuck bypassing cwnd.
                self.pending_mtu_probe = false;
            }
        }

        if kind == SpaceKind::Application {
            // PATH_RESPONSE: echo a peer's PATH_CHALLENGE (9 bytes on wire).
            // Consumed immediately; the peer is responsible for retransmitting
            // its challenge if our response is lost (RFC 9000 §8.2.3).
            if let Some(data) = self.pending_path_response.take() {
                if budget.saturating_sub(payload.len()) >= 9 {
                    Frame::PathResponse(data).encode(payload);
                    ack_eliciting = true;
                } else {
                    // Insufficient budget; re-queue for the next packet.
                    self.pending_path_response = Some(data);
                }
            }
            // PATH_CHALLENGE: send our probe if one is pending (one-shot send;
            // the nonce is retained in `pending_path_challenge` for response
            // matching, but `pending_path_challenge_send` is cleared once sent
            // so we do not re-emit on every subsequent packet).
            if self.pending_path_challenge_send {
                if let Some(data) = self.pending_path_challenge {
                    if budget.saturating_sub(payload.len()) >= 9 {
                        Frame::PathChallenge(data).encode(payload);
                        ack_eliciting = true;
                        self.pending_path_challenge_send = false;
                    }
                }
            }
            // HANDSHAKE_DONE (server only).
            if self.handshake_done_to_send() {
                Frame::HandshakeDone.encode(payload);
                self.handshake_done = true;
                ack_eliciting = true;
            }
            // Flow-control window updates and BLOCKED signalling.
            ack_eliciting |= self.fill_flow_control_frames(payload, budget);
            // RESET_STREAM frames (RFC 9000 §19.4).
            ack_eliciting |= self.fill_reset_stream_frames(payload, budget);
            // STOP_SENDING frames (RFC 9000 §19.5).
            ack_eliciting |= self.fill_stop_sending_frames(payload, budget);
            // NEW_CONNECTION_ID: issue pending CIDs to the peer (RFC 9000 §19.15).
            // A minimal NEW_CONNECTION_ID frame is approximately 28 bytes:
            //   1 (type) + up to 8 (seq varint) + up to 8 (retire_prior_to) +
            //   1 (cid_len) + 8 (cid) + 16 (token) = ~42 bytes worst case.
            while let Some(issued) = self.local_cid_pool.pop_pending_new() {
                let cid_len = issued.cid.as_bytes().len();
                // Conservative frame size: varint overhead + cid + token.
                let frame_size = 1 + 8 + 8 + 1 + cid_len + 16;
                let avail = budget.saturating_sub(payload.len());
                if avail < frame_size {
                    self.local_cid_pool.pending_new.push_front(issued);
                    break;
                }
                let f = crate::frame::Frame::NewConnectionId {
                    seq: issued.seq,
                    retire_prior_to: 0,
                    cid: issued.cid.clone(),
                    stateless_reset_token: issued.stateless_reset_token,
                };
                f.encode(payload);
                frames.push(SentFrame::NewConnectionId {
                    seq: issued.seq,
                    retire_prior_to: 0,
                    cid: issued.cid,
                    stateless_reset_token: issued.stateless_reset_token,
                });
                ack_eliciting = true;
            }
            // RETIRE_CONNECTION_ID: tell peer to retire old CIDs (RFC 9000 §19.16).
            // A RETIRE_CONNECTION_ID frame is: 1 (type) + up to 8 (seq varint) = ~9 bytes.
            while let Some(seq) = self.peer_cid_pool.pop_pending_retire() {
                let avail = budget.saturating_sub(payload.len());
                if avail < 9 {
                    self.peer_cid_pool.push_front_retire(seq);
                    break;
                }
                crate::frame::Frame::RetireConnectionId { seq }.encode(payload);
                frames.push(SentFrame::RetireConnectionId { seq });
                ack_eliciting = true;
            }
            // MAX_STREAMS (RFC 9000 §4.6): advertise new stream limit to peer.
            if let Some(max) = self.pending_max_streams_bidi.take() {
                if budget.saturating_sub(payload.len()) >= 16 {
                    Frame::MaxStreams {
                        dir: Direction::Bidirectional,
                        max,
                    }
                    .encode(payload);
                    frames.push(SentFrame::MaxStreams {
                        dir: Direction::Bidirectional,
                        max,
                    });
                    ack_eliciting = true;
                    self.sent_max_streams_bidi = max;
                } else {
                    self.pending_max_streams_bidi = Some(max);
                }
            }
            if let Some(max) = self.pending_max_streams_uni.take() {
                if budget.saturating_sub(payload.len()) >= 16 {
                    Frame::MaxStreams {
                        dir: Direction::Unidirectional,
                        max,
                    }
                    .encode(payload);
                    frames.push(SentFrame::MaxStreams {
                        dir: Direction::Unidirectional,
                        max,
                    });
                    ack_eliciting = true;
                    self.sent_max_streams_uni = max;
                } else {
                    self.pending_max_streams_uni = Some(max);
                }
            }
            // STREAMS_BLOCKED (RFC 9000 §19.14): notify peer we are blocked.
            if let Some(limit) = self.pending_streams_blocked_bidi.take() {
                if budget.saturating_sub(payload.len()) >= 16 {
                    Frame::StreamsBlocked {
                        dir: Direction::Bidirectional,
                        limit,
                    }
                    .encode(payload);
                    frames.push(SentFrame::StreamsBlocked {
                        dir: Direction::Bidirectional,
                        limit,
                    });
                    ack_eliciting = true;
                } else {
                    self.pending_streams_blocked_bidi = Some(limit);
                }
            }
            if let Some(limit) = self.pending_streams_blocked_uni.take() {
                if budget.saturating_sub(payload.len()) >= 16 {
                    Frame::StreamsBlocked {
                        dir: Direction::Unidirectional,
                        limit,
                    }
                    .encode(payload);
                    frames.push(SentFrame::StreamsBlocked {
                        dir: Direction::Unidirectional,
                        limit,
                    });
                    ack_eliciting = true;
                } else {
                    self.pending_streams_blocked_uni = Some(limit);
                }
            }
            // NEW_TOKEN (server-side post-handshake, RFC 9000 §8.1.3).
            if self.role == super::Role::Server {
                if let Some(token) = self.pending_new_token.take() {
                    // Frame overhead: 1 (type) + varint(len) + token bytes.
                    let need = 1 + varint_size(token.len() as u64) + token.len();
                    if budget.saturating_sub(payload.len()) >= need {
                        Frame::NewToken(&token).encode(payload);
                        frames.push(SentFrame::NewToken {
                            token: token.clone(),
                        });
                        ack_eliciting = true;
                    } else {
                        self.pending_new_token = Some(token);
                    }
                }
            }
            // DATAGRAM frames (RFC 9221 — NOT tracked for retransmission).
            while let Some(front) = self.datagram_send_queue.front() {
                let front_len = front.len();
                let need = 1 + varint_size(front_len as u64) + front_len;
                if budget.saturating_sub(payload.len()) < need {
                    break;
                }
                // pop_front is safe: we just peeked via front()
                let dgram = self
                    .datagram_send_queue
                    .pop_front()
                    .expect("just checked front");
                Frame::Datagram(&dgram).encode(payload);
                ack_eliciting = true;
                // Deliberately NO frames.push() — datagrams are not retransmitted.
            }
            // STREAM data, gated by flow control.
            let placed = self.fill_stream_frames(payload, budget);
            if !placed.is_empty() {
                ack_eliciting = true;
                frames.extend(placed);
            }
        }

        // PTO probe: if we owe a probe and nothing ack-eliciting was placed,
        // emit a PING to elicit an acknowledgement (RFC 9002 Section 6.2.4).
        if self.probes_owed > 0 {
            if !ack_eliciting {
                Frame::Ping.encode(payload);
                frames.push(SentFrame::Ping);
                ack_eliciting = true;
            }
            self.probes_owed -= 1;
        }

        // Keep-alive PING: if flagged and we are in the Application space, emit
        // a single PING frame (RFC 9000 Section 19.2). This keeps the connection
        // and any NAT bindings alive even when no application data is flowing.
        if kind == SpaceKind::Application && self.pending_keep_alive_ping {
            Frame::Ping.encode(payload);
            frames.push(SentFrame::Ping);
            ack_eliciting = true;
            self.pending_keep_alive_ping = false;
        }

        // Key update probe: when a local key update is pending and no
        // ack-eliciting content has been placed, emit a PING to carry the new
        // key phase bit (RFC 9001 §6.1: the peer must acknowledge a packet
        // from the new epoch).
        if kind == SpaceKind::Application && self.key_update_pending && !ack_eliciting {
            Frame::Ping.encode(payload);
            frames.push(SentFrame::Ping);
            ack_eliciting = true;
        }

        (frames, ack_eliciting)
    }

    /// Emit pending `MAX_DATA` / `MAX_STREAM_DATA` and `DATA_BLOCKED` /
    /// `STREAM_DATA_BLOCKED` frames (RFC 9000 Section 4.1, 19.9–19.13).
    /// Returns whether any (ack-eliciting) frame was placed.
    fn fill_flow_control_frames(&mut self, payload: &mut Vec<u8>, budget: usize) -> bool {
        let mut placed = false;
        let room = |payload: &Vec<u8>| budget.saturating_sub(payload.len()) > 16;

        if let Some(max) = self.pending_max_data.take() {
            if room(payload) {
                Frame::MaxData(max).encode(payload);
                placed = true;
            } else {
                self.pending_max_data = Some(max);
            }
        }
        // MAX_STREAM_DATA for each stream whose limit advanced.
        let stream_updates: Vec<(u64, u64)> = self
            .pending_max_stream_data
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();
        for (id, max) in stream_updates {
            if room(payload) {
                Frame::MaxStreamData { id, max }.encode(payload);
                self.pending_max_stream_data.remove(&id);
                placed = true;
            }
        }
        if let Some(limit) = self.pending_data_blocked.take() {
            if room(payload) {
                Frame::DataBlocked(limit).encode(payload);
                placed = true;
            }
        }
        let blocked: Vec<(u64, u64)> = self
            .pending_stream_data_blocked
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();
        for (id, limit) in blocked {
            if room(payload) {
                Frame::StreamDataBlocked { id, limit }.encode(payload);
                self.pending_stream_data_blocked.remove(&id);
                placed = true;
            }
        }
        placed
    }

    /// Emit `STREAM` frames subject to connection- and stream-level flow
    /// control, returning the retransmittable records placed. Retransmitted
    /// segments (which the stream emits first) are not re-charged against flow
    /// control; only fresh data advances the offsets (RFC 9000 Section 4.1).
    fn fill_stream_frames(&mut self, payload: &mut Vec<u8>, budget: usize) -> Vec<SentFrame> {
        let mut placed = Vec::new();
        // Snapshot stream ids to avoid borrowing self.send_streams mutably while
        // also touching flow-control maps.
        let ids: Vec<u64> = self.send_streams.keys().copied().collect();
        for id in ids {
            // Stop if there is no useful room left for another STREAM frame.
            let avail_buf = budget.saturating_sub(payload.len()).saturating_sub(24);
            if avail_buf == 0 {
                break;
            }
            // Skip streams that have been reset: a RESET_STREAM frame is sent
            // instead of further STREAM frames (RFC 9000 §3.3).
            let is_reset = self
                .send_streams
                .get(&id)
                .map(|s| s.is_reset())
                .unwrap_or(false);
            if is_reset {
                continue;
            }
            let has_pending = self
                .send_streams
                .get(&id)
                .map(|s| s.has_pending())
                .unwrap_or(false);
            if !has_pending {
                continue;
            }

            // A retransmission (resend queue non-empty) re-sends already-authorised
            // offsets and is permitted regardless of flow control (RFC 9000
            // Section 4.1). Fresh data is capped by connection + stream credit.
            let is_resend = self
                .send_streams
                .get(&id)
                .map(|s| s.has_resend())
                .unwrap_or(false);
            let initial = self.peer_initial_stream_limit();
            self.stream_send_flow
                .entry(id)
                .or_insert_with(|| crate::flow_control::StreamSendFlow::new(initial));
            let take = if is_resend {
                avail_buf
            } else {
                let conn_credit = self.send_flow.available();
                let stream_credit = self
                    .stream_send_flow
                    .get(&id)
                    .map(|f| f.available())
                    .unwrap_or(0);
                avail_buf.min(conn_credit.min(stream_credit) as usize)
            };
            if take == 0 {
                continue;
            }
            let stream = match self.send_streams.get_mut(&id) {
                Some(s) => s,
                None => continue,
            };
            if let Some((offset, data, fin)) = stream.take(take) {
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data: &data,
                }
                .encode(payload);
                // Advance flow control by the new highest offset only.
                let new_high = offset + data.len() as u64;
                let fresh = self
                    .stream_send_flow
                    .get_mut(&id)
                    .map(|f| f.record_high_offset(new_high))
                    .unwrap_or(0);
                self.send_flow.on_data_sent(fresh);
                placed.push(SentFrame::Stream {
                    id,
                    offset,
                    fin,
                    data: data.clone(),
                });
            }
        }
        // Emit BLOCKED frames if a stream or the connection is now blocked.
        self.note_blocked_streams();
        placed
    }

    /// Queue `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` if the connection or any
    /// stream with pending data is at its flow-control limit (RFC 9000 4.1).
    fn note_blocked_streams(&mut self) {
        if self.any_stream_send_data() {
            if let Some(limit) = self.send_flow.take_blocked() {
                self.pending_data_blocked = Some(limit);
            }
        }
        let ids: Vec<u64> = self.send_streams.keys().copied().collect();
        for id in ids {
            let pending = self
                .send_streams
                .get(&id)
                .map(|s| s.has_pending())
                .unwrap_or(false);
            if !pending {
                continue;
            }
            if let Some(flow) = self.stream_send_flow.get_mut(&id) {
                if let Some(limit) = flow.take_blocked() {
                    self.pending_stream_data_blocked.insert(id, limit);
                }
            }
        }
    }

    /// Advance our receive-side flow-control limits as the application consumes
    /// data, queueing `MAX_DATA` / `MAX_STREAM_DATA` (RFC 9000 Section 4.1).
    fn advance_recv_flow(&mut self) {
        if let Some(max) = self.recv_flow.maybe_update() {
            self.pending_max_data = Some(max);
        }
        let ids: Vec<u64> = self.stream_recv_flow.keys().copied().collect();
        for id in ids {
            if let Some(flow) = self.stream_recv_flow.get_mut(&id) {
                if let Some(max) = flow.maybe_update() {
                    self.pending_max_stream_data.insert(id, max);
                }
            }
        }
    }

    /// Emit pending `RESET_STREAM` frames (RFC 9000 §19.4). Returns true if any
    /// (ack-eliciting) frame was placed.
    fn fill_reset_stream_frames(&mut self, payload: &mut Vec<u8>, budget: usize) -> bool {
        let mut placed = false;
        let room = |payload: &Vec<u8>| budget.saturating_sub(payload.len()) > 24;
        let ids: Vec<u64> = self.pending_reset_streams.keys().copied().collect();
        for id in ids {
            if !room(payload) {
                break;
            }
            if let Some((error_code, final_size)) = self.pending_reset_streams.get(&id).copied() {
                Frame::ResetStream {
                    stream_id: id,
                    error_code,
                    final_size,
                }
                .encode(payload);
                placed = true;
                // Remove once emitted (will be re-inserted if packet is lost;
                // for simplicity we clear on first emission — the peer must be
                // tolerant of missing RESET_STREAM retransmits per RFC 9000 §3.4).
                self.pending_reset_streams.remove(&id);
            }
        }
        placed
    }

    /// Emit pending `STOP_SENDING` frames (RFC 9000 §19.5). Returns true if any
    /// (ack-eliciting) frame was placed.
    fn fill_stop_sending_frames(&mut self, payload: &mut Vec<u8>, budget: usize) -> bool {
        let mut placed = false;
        let room = |payload: &Vec<u8>| budget.saturating_sub(payload.len()) > 16;
        let ids: Vec<u64> = self.pending_stop_sending.keys().copied().collect();
        for id in ids {
            if !room(payload) {
                break;
            }
            if let Some(error_code) = self.pending_stop_sending.get(&id).copied() {
                Frame::StopSending {
                    stream_id: id,
                    error_code,
                }
                .encode(payload);
                placed = true;
                self.pending_stop_sending.remove(&id);
            }
        }
        placed
    }

    /// Emit a 0-RTT long-header packet with early application data (RFC 9001 §4.6).
    ///
    /// Called by `poll_transmit` on the **client** side before 1-RTT keys are ready.
    /// Uses the Application packet-number space (RFC 9001 §4.1.1: 0-RTT shares
    /// Application space).
    ///
    /// Returns `true` if a packet was written.
    pub(super) fn write_zero_rtt_packet(&mut self, _now: Instant, out: &mut Vec<u8>) -> bool {
        // Only client, only before 1-RTT ready, only if we have keys and unsent data.
        if self.role != super::Role::Client {
            return false;
        }
        if self.one_rtt_ready {
            return false;
        }
        if self.early_data_buf.is_empty() || self.zero_rtt_sent {
            return false;
        }
        // Clone keys ref to avoid borrow issues; keys.packet/header are Box<dyn Trait>
        // so we cannot keep the reference across other mutable borrows.
        if self.zero_rtt_keys.is_none() {
            return false;
        }

        // Encode all early STREAM frames into the payload.
        let mut payload = Vec::new();
        for (stream_id, data, fin) in &self.early_data_buf {
            crate::frame::Frame::Stream {
                id: stream_id.as_u64(),
                offset: 0,
                fin: *fin,
                data,
            }
            .encode(&mut payload);
        }
        if payload.is_empty() {
            return false;
        }

        // Use Application PN space (RFC 9001 §4.1.1).
        let pn = self.application.next_pn();
        let largest_acked = self.application.largest_acked();
        let dcid = self.peer_cid.as_bytes().to_vec();
        let scid = self.local_cid.as_bytes().to_vec();

        let packet_start = out.len();

        // We need to call the keys without keeping a borrow alive.
        // Take ownership: replace the keys field temporarily.
        let keys = match self.zero_rtt_keys.take() {
            Some(k) => k,
            None => return false,
        };

        let params = crate::packet::BuildLong {
            long_type: crate::packet::LongType::ZeroRtt,
            version: super::QUIC_V1,
            dcid: &dcid,
            scid: &scid,
            token: &[],
            packet_number: pn,
            largest_acked,
        };

        let built = crate::packet::build_long_packet(
            out,
            &params,
            &payload,
            keys.packet.as_ref(),
            keys.header.as_ref(),
        )
        .is_ok();

        // Put keys back.
        self.zero_rtt_keys = Some(keys);

        if !built {
            return false;
        }

        let sent_bytes = out.len() - packet_start;
        self.packets_sent += 1;
        self.bytes_sent += sent_bytes as u64;
        self.zero_rtt_sent = true;
        true
    }

    pub(super) fn emit_close(&mut self, out: &mut Vec<u8>) -> Option<SocketAddr> {
        // Prefer the most-protected space whose keys are available.
        let (short, _kind) = if self.one_rtt_ready {
            (true, SpaceKind::Application)
        } else if self.handshake_keys_ready {
            (false, SpaceKind::Handshake)
        } else {
            (false, SpaceKind::Initial)
        };

        let frame = if let Some((code, reason)) = self.pending_transport_close.take() {
            Frame::ConnectionClose {
                error_code: code.to_u64(),
                frame_type: Some(0),
                application: false,
                reason,
            }
        } else if let Some((code, reason)) = self.pending_close.take() {
            Frame::ConnectionClose {
                error_code: code,
                frame_type: None,
                application: true,
                reason,
            }
        } else {
            return None;
        };
        let mut payload = Vec::new();
        frame.encode(&mut payload);

        let dcid = self.peer_cid.as_bytes().to_vec();
        let scid = self.local_cid.as_bytes().to_vec();
        if short {
            let key_phase = self.key_phase;
            let space = &mut self.application;
            let pn = space.next_pn();
            let la = space.largest_acked();
            let (pk, hk) = space
                .local_keys()
                .map(|k| (k.packet.as_ref(), k.header.as_ref()))?;
            build_short_packet(
                out,
                &BuildShort {
                    dcid: &dcid,
                    packet_number: pn,
                    largest_acked: la,
                    key_phase,
                },
                &payload,
                pk,
                hk,
            )
            .ok()?;
        } else {
            let (long_type, space) = if self.handshake_keys_ready {
                (LongType::Handshake, &mut self.handshake)
            } else {
                (LongType::Initial, &mut self.initial)
            };
            let pn = space.next_pn();
            let la = space.largest_acked();
            let (pk, hk) = space
                .local_keys()
                .map(|k| (k.packet.as_ref(), k.header.as_ref()))?;
            let params = BuildLong {
                long_type,
                version: super::QUIC_V1,
                dcid: &dcid,
                scid: &scid,
                token: &[],
                packet_number: pn,
                largest_acked: la,
            };
            build_long_packet(out, &params, &payload, pk, hk).ok()?;
        }
        Some(self.peer_addr)
    }
}
