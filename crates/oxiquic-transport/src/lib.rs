//! QUIC transport layer for the OxiQUIC stack.
//!
//! `oxiquic-transport` is a Pure-Rust QUIC (RFC 9000 / 9001) implementation
//! built directly on the `rustls::quic` TLS 1.3 handshake API, driven by the
//! `oxiquic-crypto` `CryptoProvider` (no `ring`, no `aws-lc-rs`). It runs over
//! `tokio`'s asynchronous UDP sockets.
//!
//! The crate is split into a synchronous, I/O-free protocol core
//! ([`Connection`]) and a thin asynchronous shell ([`endpoint`]) that pumps
//! datagrams between the core and a UDP socket. A caller drives a client with
//! [`ClientEndpoint::bind`] then [`ClientEndpoint::connect`], a server with
//! [`ServerEndpoint::bind`] then [`ServerEndpoint::accept`]; both yield a
//! [`QuicConnection`] for opening bidirectional streams and reading/writing data.
//!
//! # Implementation status
//!
//! Implemented and proven over real UDP loopback:
//!
//! * **Initial handshake** — long-header packet coding, header protection,
//!   packet protection, coalesced-packet parsing, CRYPTO-frame reassembly
//!   driving the rustls TLS 1.3 handshake, ACKs and per-space packet numbers.
//! * **1-RTT + close** — 1-RTT keys on `KeyChange::OneRtt`, short-header
//!   packets, `HANDSHAKE_DONE`, `CONNECTION_CLOSE` and idle handling.
//! * **Stream data** — bidirectional stream state machines with ordered
//!   reassembly and a send/receive API.
//!
//! * **Loss detection & recovery** (RFC 9002 Sections 5-6) — sent-packet
//!   tracking per space, RTT estimation (latest, min, smoothed, rttvar),
//!   packet-number threshold and time-threshold loss detection, PTO (probe
//!   timeout) with exponential backoff, retransmission of lost CRYPTO/STREAM
//!   frames.
//! * **Congestion control** — CUBIC (RFC 9438, default), NewReno (RFC 9002
//!   Appendix B) and BBR v2 (model-based), selected via
//!   [`TransportConfig::congestion_controller`]. All three share the
//!   [`CongestionController`] dispatch enum; CUBIC tracks W_max, K and the
//!   cubic epoch for RFC 9438 window growth after loss.
//! * **Flow control** (RFC 9000 Section 4) — connection- and stream-level
//!   send/receive limits, MAX_DATA / MAX_STREAM_DATA generation and processing,
//!   DATA_BLOCKED / STREAM_DATA_BLOCKED signalling.
//!
//! * **Version Negotiation** (RFC 9000 §17.2.1) — server sends a VN packet
//!   when an Initial arrives with an unsupported version; client fails the
//!   connection with [`OxiQuicError::VersionNegotiation`] on receiving VN
//!   during the early handshake.
//!
//! * **Retry** (RFC 9000 §17.2.5, RFC 9001 §5.8) — server optionally sends a
//!   Retry packet to force clients to prove their source address. Enable via
//!   [`TransportConfig::retry`]. The client processes the Retry integrity tag,
//!   re-keys the Initial space, and retransmits with the echoed token.
//!
//! * **Connection path migration** (RFC 9000 §9) — PATH_CHALLENGE / PATH_RESPONSE
//!   wire frames (frame types 0x1a / 0x1b), peer-address-change detection in the
//!   endpoint, and `initiate_path_challenge()` / `path_validated()` API on
//!   [`QuicConnection`].  Deferred to a future milestone: anti-amplification
//!   limit enforcement, NEW_CONNECTION_ID issuance for migration, PATH_CHALLENGE
//!   retransmission on PTO, and separate per-path congestion state.
//!
//! * **Key update** (RFC 9001 §6) — key phase bit, per-epoch key derivation,
//!   3-PTO cooldown, `initiate_key_update()` + `key_update_count()` on
//!   [`Connection`] (4 tests in `tests/key_update.rs`).
//!
//! * **DPLPMTUD / path MTU discovery** (RFC 8899) — binary-search probe
//!   scheduling post-handshake, PING frames padded to candidate sizes, ACK and
//!   loss callbacks updating `current_mtu()`; enabled by default, ceiling
//!   configurable via [`TransportConfig::mtu_discovery`] (3 tests in
//!   `tests/mtu_discovery.rs`).
//!
//! Not yet implemented: 0-RTT, stateless reset, ECN, MAX_STREAMS.
//! RESET_STREAM/STOP_SENDING: frame encode/decode plumbed; end-to-end
//! user-facing API stubs remain.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bbr;
mod cc_dispatch;
pub mod coding;
mod config;
mod congestion;
pub mod connection;
mod crypto_stream;
mod cubic;
pub mod endpoint;
mod flow_control;
pub mod frame;
#[cfg(feature = "h3-compat")]
pub mod h3_compat;
pub mod handle;
pub mod packet;
mod params_codec;
mod recovery;
mod sent_packet;
mod space;
mod stream;

pub use bbr::{Bbr, BbrState, DeliveryRateEstimator, RateSample};
pub use cc_dispatch::CongestionController;
pub use config::{CongestionAlgorithm, TransportConfig};
pub use connection::{Connection, ConnectionState, MtuConfig, Role};
pub use endpoint::{
    ClientEndpoint, DrivenConnection, Incoming, QuicConnection, ServerEndpoint,
    ServerEndpointBuilder, ZeroRttAccepted,
};
#[cfg(feature = "h3-compat")]
pub use h3_compat::{
    H3BidiStream, H3RecvStream, H3SendStream, OxiQuicH3Connection, OxiQuicOpenStreams,
};
pub use handle::{BiStream, RecvStreamHandle, SendStreamHandle, UniRecvStream, UniSendStream};
pub use oxiquic_core::{ConnectionStats, OxiQuicError, StreamId, TransportParams};
pub use packet::{
    compute_retry_integrity_tag, decode_version_negotiation, encode_retry_packet,
    encode_version_negotiation, parse_retry_packet, verify_retry_integrity_tag,
};
