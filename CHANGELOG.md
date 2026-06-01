# Changelog

All notable changes to OxiQUIC are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-01

### Added

#### oxiquic-core
- `OxiQuicError` enum (thiserror): `NotImplemented`, `Connect`, `Stream`, `Timeout`, `Tls`,
  `Protocol`, `FrameEncoding`, `FlowControl`, `Io`, `Other` plus `is_timeout()`, `is_closed()`,
  `is_reset()` predicates.
- `StreamId(u64)` newtype: `initiator()`, `direction()`, `index()` per RFC 9000 §2.1.
- `ConnectionId` newtype with variable-length DCID/SCID support.
- `ConnectionStats` struct: RTT (min/smoothed/variance), bytes/packets sent/recv/lost,
  congestion window; `Display` impl with human-readable formatting.
- `TransportParams` struct: all RFC 9000 transport parameters with codec support.
- `FrameType` enum: full RFC 9000 frame type set (PADDING through HANDSHAKE_DONE).
- `QuicVersion` enum: V1 (RFC 9000), V2 (RFC 9369), VersionNegotiation.
- Optional `serde` feature gate for `StreamId`, `ConnectionId`, `ConnectionStats`.
- Optional `oxitls` feature gate for `From<TlsError>` conversion bridge.

#### oxiquic-crypto
- Pure-Rust QUIC crypto provider for `rustls` — no ring, no aws-lc-rs.
- AEAD packet protection: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 via RustCrypto.
- Header protection key derivation and mask application (RFC 9001).
- Initial key derivation: HKDF-SHA256 label expansion per RFC 9001 §5.2.
- HMAC-SHA256/SHA384/SHA512 implementations.
- HKDF-SHA256/SHA384 implementations.
- Three QUIC cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
  TLS_CHACHA20_POLY1305_SHA256 — all with `quic: Some(..)` for packet-key derivation.
- `quic_crypto_provider()` function returning the assembled `rustls::CryptoProvider`.
- Optional `oxitls-provider` feature: `oxitls_quic_provider()` sourced from oxitls.

#### oxiquic-transport
- `ClientEndpoint` / `ServerEndpoint`: tokio UDP-based QUIC endpoints.
- `QuicConnection` / `DrivenConnection`: full connection lifecycle management.
- QUIC 1-RTT TLS 1.3 handshake via `rustls::quic` module.
- QUIC 0-RTT early data: `ClientEndpoint::connect_0rtt()`, `ServerEndpointBuilder::with_max_early_data_size()`.
- `TransportConfig` builder: idle timeout, keep-alive interval, MTU discovery, stream/connection windows, congestion algorithm selection.
- Loss detection: RFC 9002 PTO, ACK-based loss detection, loss recovery state machine.
- Congestion control — Cubic (RFC 9438): slow start, congestion avoidance, fast recovery.
- Congestion control — BBR v2: bandwidth estimation, pacing, ProbeRTT, ProbeBW phases.
- `CongestionAlgorithm` selector: `Cubic | Bbr`.
- Stream multiplexing: bidirectional and unidirectional streams with independent flow control.
- Connection-level and stream-level flow control with MAX_DATA/MAX_STREAM_DATA/STREAMS_BLOCKED.
- `SendStreamHandle` (implements `AsyncWrite`) and `RecvStreamHandle` (implements `AsyncRead`).
- `BiStream`, `UniSendStream`, `UniRecvStream` type-safe direction wrappers.
- `QuicConnection::open_bi_reliable(max_attempts, retry_delay)` with back-pressure retry.
- `QuicConnection::ping() -> Duration` RTT measurement.
- Version negotiation: server sends VN packet for unknown versions; client handles gracefully.
- Stateless retry: HMAC-SHA256 token generation and validation (RFC 9000 §8.1).
- Key update: RFC 9001 §6 key phase bit, per-epoch key derivation, cooldown period.
- Connection migration: PATH_CHALLENGE/PATH_RESPONSE validation, candidate address promotion.
- Multi-connection server demux: DCID-based routing for concurrent clients.
- MTU discovery: DPLPMTUD (RFC 8899) binary-search probe with ACK/loss callbacks.
- Idle timeout enforcement and keep-alive PING frames.
- `ServerEndpoint::local_addr()` accessor.
- `h3-compat` feature: `h3::quic` trait implementations over oxiquic-transport streams.
- `dangerous` feature: `connect_insecure()` for dev/testing.

#### oxiquic-h3
- `H3Client` over in-house oxiquic-transport QUIC streams.
- `H3ClientBuilder`: `with_server_name()`, `with_tls_config()`, ALPN enforcement (`h3`).
- `H3Client::get()`, `post()`, `request()`, `close()` methods.
- `H3Response`: `status()`, `headers()`, `body_bytes()`, `body_text()`, `content_length()`,
  `content_type()`, `is_success()`.
- `RequestStream` for streaming request/response bodies over HTTP/3 DATA frames.
- `H3Server` accepting HTTP/3 connections over oxiquic-transport.
- `H3ServerBuilder`: `with_tls_config()`, `with_ticketer()`, `bind()`, ALPN enforcement.
- `H3Server::new(driven)` performing HTTP/3 SETTINGS exchange.
- `H3Server::accept()` returning `H3RequestContext`.
- `H3RequestContext::body()`, `respond()` for request handling.
- `H3Responder::push_promise()` stub (upstream-limited: h3 0.0.8 has no push API).
- Graceful shutdown: GOAWAY frame via `h3::server::Connection::shutdown()`.
- QPACK configuration fields (stored for forward-compat; h3 0.0.8 is stateless-only).
- `H3Error` enum: `Protocol`, `Qpack`, `Stream`, `Connection`, `Io`, `Tls`,
  `FrameUnexpected`, `SettingsError`, `MissingSettings`, `IdError`.
- `H3Settings`, `H3Request`, `H3Response` message types.
- Optional `serde` and `tracing` feature gates.

#### oxiquic (facade)
- Feature-gated unified re-exports: `transport` (default), `h3`, `dangerous`.
- `prelude` module and `h3_prelude` module.
- `connect(addr, server_name)` convenience function.
- `listen(addr, certs, key)` convenience function.
- `connect_insecure(addr, server_name)` under `dangerous` feature.
- `version()` and `quic_version()` accessors.

### Security
- Zero C/C++/Fortran dependencies in default features (`cargo tree --edges normal`
  contains no ring, aws-lc-rs, aws-lc-sys, openssl, or openssl-sys).
- FFI audit gate: `deny.toml` + `scripts/ffi-audit.sh` enforce ban list.
- Stateless reset token generation per RFC 9000 §10.3.1 (HMAC-SHA256).

### Notes
- Deferred: 0-RTT user-facing API (framing plumbed, round-trip handshake works);
  RESET_STREAM/STOP_SENDING end-to-end user API (framing complete); H3 server push
  (upstream-limited: h3 0.0.8); ALPN enforcement at H3 facade layer; multipath QUIC.
- 321 tests pass (unit + integration); zero clippy warnings; zero `unwrap()`/`panic!`
  in production code.
- ~22 000 SLOC across 5 crates.
