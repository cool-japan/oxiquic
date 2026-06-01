//! ACK processing, loss detection, PTO timers (RFC 9002).
//!
//! Contains [`Connection::process_ack`], loss detection helpers,
//! `set_loss_detection_timer`, `on_loss_timeout`, and retransmission queuing.

use std::time::{Duration, Instant};

use oxiquic_core::{Direction, PacketType};

use crate::frame::AckRange;
use crate::recovery::SpaceIndex;
use crate::sent_packet::SentFrame;

use super::Connection;

impl Connection {
    /// Map a received packet's type to its packet-number-space array index.
    pub(super) fn space_index(packet_type: PacketType) -> usize {
        match packet_type {
            PacketType::Initial => SpaceIndex::Initial as usize,
            PacketType::Handshake => SpaceIndex::Handshake as usize,
            _ => SpaceIndex::Application as usize,
        }
    }

    /// Process an `ACK` frame for `packet_type`'s space: acknowledge packets,
    /// sample the RTT, advance congestion control and run loss detection
    /// (RFC 9002 Section 5, 6, Appendix A.7).
    pub(super) fn process_ack(
        &mut self,
        now: Instant,
        packet_type: PacketType,
        largest: u64,
        delay: u64,
        first_range: u64,
        ranges: &[AckRange],
    ) {
        let idx = Self::space_index(packet_type);
        // Record the largest acknowledged for packet-number truncation length.
        match packet_type {
            PacketType::Initial => self.initial.on_ack_received(largest),
            PacketType::Handshake => self.handshake.on_ack_received(largest),
            _ => self.application.on_ack_received(largest),
        }
        // Capture each newly-acked packet's send time before we knew it was
        // largest, to sample the RTT correctly.
        let range_pairs: Vec<(u64, u64)> = ranges.iter().map(|r| (r.gap, r.range)).collect();
        let outcome = self.sent_packets[idx].on_ack(largest, first_range, &range_pairs);

        if outcome.newly_acked.is_empty() {
            return;
        }

        // RTT sample: only when the largest acked is newly acked (RFC 9002 5.1).
        if outcome.largest_newly_acked == Some(largest) {
            if let Some(sent) = outcome
                .newly_acked
                .iter()
                .find(|p| p.packet_number == largest)
            {
                let rtt_sample = now.saturating_duration_since(sent.time_sent);
                // Decode the peer's ack_delay (scaled by its ack_delay_exponent).
                let ack_delay = self.decode_ack_delay(delay);
                // max_ack_delay applies only once the handshake is confirmed and
                // only in the Application space (RFC 9002 5.3).
                let max_ack_delay =
                    if idx == SpaceIndex::Application as usize && self.handshake_done {
                        self.peer_max_ack_delay
                    } else {
                        Duration::ZERO
                    };
                self.rtt.update(rtt_sample, ack_delay, max_ack_delay);
            }
        }

        // Congestion: release acked bytes; grow the window for non-recovery acks.
        let acked_cc: Vec<(usize, Instant, Option<crate::bbr::RateSample>)> = outcome
            .newly_acked
            .iter()
            .filter(|p| p.in_flight)
            .map(|p| (p.sent_bytes, p.time_sent, p.rate_sample))
            .collect();
        if !acked_cc.is_empty() {
            self.congestion.on_packets_acked(&acked_cc, now);
        }

        // A valid ack-eliciting acknowledgement resets the PTO backoff.
        if outcome.acked_ack_eliciting {
            self.loss.reset_pto_count();
            self.probes_owed = 0;
        }

        // Check for MTU probe ACKs among newly-acked packets.
        for pkt in &outcome.newly_acked {
            for frame in &pkt.frames {
                if let crate::sent_packet::SentFrame::MtuProbe(size) = frame {
                    self.on_mtu_probe_acked(*size, now);
                }
            }
        }

        // Run loss detection for this space.
        self.detect_and_handle_loss(idx, now);
        self.set_loss_detection_timer(now);
    }

    /// Decode the peer's wire `ack_delay` value, scaled by its
    /// `ack_delay_exponent` (RFC 9000 Section 18.2 / 19.3).
    fn decode_ack_delay(&self, delay: u64) -> Duration {
        let exponent = self
            .peer_params
            .as_ref()
            .map(|p| p.ack_delay_exponent)
            .unwrap_or(oxiquic_core::DEFAULT_ACK_DELAY_EXPONENT);
        let micros = delay.saturating_mul(1u64 << exponent.min(20));
        Duration::from_micros(micros)
    }

    /// Detect lost packets in space `idx` and re-queue their retransmittable
    /// frames; feed the loss to congestion control (RFC 9002 Section 6.1, 6.2).
    pub(super) fn detect_and_handle_loss(&mut self, idx: usize, now: Instant) {
        let loss_delay = self.rtt.loss_delay();
        let (lost, next_loss_time) = self.sent_packets[idx].detect_lost(now, loss_delay);
        let space = match idx {
            0 => SpaceIndex::Initial,
            1 => SpaceIndex::Handshake,
            _ => SpaceIndex::Application,
        };
        self.loss.set_loss_time(space, next_loss_time);

        if lost.is_empty() {
            return;
        }

        // Congestion event from the newest lost in-flight packet.
        let mut lost_bytes = 0u64;
        let mut newest_lost: Option<Instant> = None;
        let mut oldest_lost: Option<Instant> = None;
        for p in &lost {
            if p.in_flight {
                lost_bytes += p.sent_bytes as u64;
                newest_lost = Some(match newest_lost {
                    Some(t) => t.max(p.time_sent),
                    None => p.time_sent,
                });
                oldest_lost = Some(match oldest_lost {
                    Some(t) => t.min(p.time_sent),
                    None => p.time_sent,
                });
            }
        }
        self.packets_lost += lost.len() as u64;

        // Re-queue retransmittable frames onto their originating streams. The
        // space index routes CRYPTO retransmission to the correct CRYPTO stream.
        // Also detect lost MTU probes and handle back-off.
        for packet in &lost {
            for frame in &packet.frames {
                if let SentFrame::MtuProbe(size) = frame {
                    self.on_mtu_probe_lost(*size);
                } else {
                    self.requeue_frame(idx, frame);
                }
            }
        }

        if let Some(newest) = newest_lost {
            self.congestion.on_packets_lost(lost_bytes, newest, now);
            // Persistent congestion: if the span of lost packets exceeds the
            // persistent-congestion duration, collapse the window (RFC 9002 7.6).
            if let Some(oldest) = oldest_lost {
                let pto_base = self.rtt.pto_base(self.peer_max_ack_delay);
                if crate::congestion::is_persistent_congestion(oldest, newest, pto_base) {
                    self.congestion.on_persistent_congestion();
                }
            }
        }
    }

    /// Re-queue a single lost frame's data onto the stream it came from. `idx`
    /// is the packet-number-space index the lost packet belonged to, used to
    /// route CRYPTO retransmission to the matching CRYPTO stream.
    pub(super) fn requeue_frame(&mut self, idx: usize, frame: &SentFrame) {
        match frame {
            SentFrame::Crypto { offset, data } => {
                if idx == SpaceIndex::Handshake as usize {
                    self.handshake_crypto.requeue(*offset, data.clone());
                } else {
                    self.initial_crypto.requeue(*offset, data.clone());
                }
            }
            SentFrame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                if let Some(stream) = self.send_streams.get_mut(id) {
                    stream.requeue(*offset, data.clone(), *fin);
                }
            }
            SentFrame::Ping => {
                // PING carries no data; a fresh probe is sent on PTO instead.
            }
            SentFrame::MtuProbe(_) => {
                // MTU probes are handled in detect_and_handle_loss via
                // on_mtu_probe_lost; they are never re-queued as retransmissions.
            }
            SentFrame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                stateless_reset_token,
            } => {
                // On loss, re-queue the NEW_CONNECTION_ID for retransmission.
                use crate::connection::cid::IssuedCid;
                self.local_cid_pool.pending_new.push_back(IssuedCid {
                    seq: *seq,
                    cid: cid.clone(),
                    stateless_reset_token: *stateless_reset_token,
                });
                // retire_prior_to is carried for completeness; the pool state
                // already reflects the correct retire threshold.
                let _ = retire_prior_to;
            }
            SentFrame::RetireConnectionId { seq } => {
                // On loss, re-queue the RETIRE_CONNECTION_ID for retransmission.
                self.peer_cid_pool.pending_retire.push_back(*seq);
            }
            SentFrame::MaxStreams { dir, max } => {
                // On loss, re-queue the MAX_STREAMS update if the value is still
                // current (only keep the highest advertised limit).
                match dir {
                    Direction::Bidirectional => {
                        if self
                            .pending_max_streams_bidi
                            .map_or(true, |existing| *max > existing)
                        {
                            self.pending_max_streams_bidi = Some(*max);
                        }
                    }
                    Direction::Unidirectional => {
                        if self
                            .pending_max_streams_uni
                            .map_or(true, |existing| *max > existing)
                        {
                            self.pending_max_streams_uni = Some(*max);
                        }
                    }
                }
            }
            SentFrame::StreamsBlocked { dir, limit } => match dir {
                Direction::Bidirectional => {
                    self.pending_streams_blocked_bidi = Some(*limit);
                }
                Direction::Unidirectional => {
                    self.pending_streams_blocked_uni = Some(*limit);
                }
            },
            SentFrame::NewToken { token } => {
                // On loss, re-queue the NEW_TOKEN only if none is already pending.
                if self.pending_new_token.is_none() {
                    self.pending_new_token = Some(token.clone());
                }
            }
        }
    }

    /// Recompute the loss-detection timer (RFC 9002 Appendix A.6/A.8): the
    /// earliest pending time-threshold loss deadline if any, otherwise the PTO
    /// armed from the earliest outstanding ack-eliciting packet across spaces.
    pub(super) fn set_loss_detection_timer(&mut self, _now: Instant) {
        // 1. Time-threshold loss timer takes precedence.
        if let Some((loss_time, _space)) = self.loss.earliest_loss_time() {
            self.loss_timer = Some(loss_time);
            return;
        }

        // 2. Otherwise, the PTO from the earliest ack-eliciting packet.
        let earliest = self.earliest_ack_eliciting_across_spaces();
        match earliest {
            Some(sent_time) => {
                // max_ack_delay only applies in the Application space; using the
                // peer value here is a safe upper bound for the combined timer.
                let pto_base = self.rtt.pto_base(self.peer_max_ack_delay);
                self.loss_timer = Some(self.loss.pto_deadline(sent_time, pto_base));
            }
            None => {
                // No ack-eliciting data outstanding: disarm.
                self.loss_timer = None;
            }
        }
    }

    /// The earliest send time of any outstanding ack-eliciting packet across all
    /// packet-number spaces.
    pub(super) fn earliest_ack_eliciting_across_spaces(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        for store in &self.sent_packets {
            if let Some(t) = store.earliest_ack_eliciting_time() {
                earliest = Some(match earliest {
                    Some(e) => e.min(t),
                    None => t,
                });
            }
        }
        earliest
    }

    /// Fire the loss-detection timer at `now` (RFC 9002 Appendix A.9
    /// `OnLossDetectionTimeout`): either declare time-threshold losses, or, if
    /// the PTO fired, schedule probe packets to elicit fresh acknowledgements.
    pub(super) fn on_loss_timeout(&mut self, now: Instant) {
        // If a time-threshold loss is due, process it.
        if let Some((loss_time, space)) = self.loss.earliest_loss_time() {
            if now >= loss_time {
                let idx = space as usize;
                self.detect_and_handle_loss(idx, now);
                self.set_loss_detection_timer(now);
                return;
            }
        }

        // Otherwise this is a PTO expiry: back off and owe probe packets so the
        // next poll_transmit retransmits / sends a PING to elicit an ACK.
        if self.earliest_ack_eliciting_across_spaces().is_some() {
            self.loss.increase_pto_count();
            // Two probes per PTO (RFC 9002 Section 6.2.4), capped.
            self.probes_owed = self.probes_owed.saturating_add(2).min(4);
            self.requeue_for_probe(now);
        }
        self.set_loss_detection_timer(now);
    }

    /// On PTO, re-queue the oldest outstanding data so a probe carries useful
    /// retransmission (RFC 9002 Section 6.2.4). For the Application space this
    /// re-queues stream data; for Initial/Handshake it re-queues CRYPTO. If no
    /// data is outstanding a bare PING is sent by the probe path.
    fn requeue_for_probe(&mut self, _now: Instant) {
        // Re-queue the lowest-numbered outstanding ack-eliciting packet's frames
        // in each space that has outstanding ack-eliciting data. We do not
        // remove them from sent_packets (they remain tracked until acked/lost);
        // the resend queues simply ensure the data is re-emitted. To avoid
        // unbounded duplication we re-queue only the single oldest packet.
        for idx in 0..3 {
            if let Some(frames) = self.sent_packets[idx].oldest_ack_eliciting_frames() {
                for frame in frames {
                    self.requeue_frame(idx, &frame);
                }
            }
        }
    }
}
