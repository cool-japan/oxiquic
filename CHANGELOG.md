# Changelog

All notable changes to OxiQUIC are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [0.1.4] - 2026-06-19

### Added

#### oxiquic-transport
- `QuicConnection::peer_addr() -> Option<SocketAddr>`: returns the remote peer
  address after a successful handshake. For server-side connections this is the
  client UDP source address; for client-side connections this is the server address
  passed to `ClientEndpoint::connect`. Guaranteed to be `Some` after the handshake
  in normal operation.
- `DrivenConnection::peer_addr() -> Option<SocketAddr>`: peer address preserved
  across `QuicConnection::into_driven()` so callers retain remote address information
  after moving the connection into background I/O mode.
- `DrivenConnection::is_closed() -> bool`: liveness hint backed by an `Arc<AtomicBool>`
  written with `Release` ordering by the driver task immediately before it exits.
  A `true` result is definitive (driver has stopped); `false` means the driver has
  not yet set the flag and may still be running. Reads with `Acquire` ordering so
  callers that observe `true` also observe all connection-state mutations that
  preceded the driver exit.

### Changed
- `oxiquic-transport` crate-level doc comment updated: clarifies that 0-RTT,
  MAX_STREAMS/STREAMS_BLOCKED, RESET_STREAM/STOP_SENDING, and stateless reset are
  all implemented; narrows the "not yet implemented" note to ECN only (RFC 9000 §13.4).
- End-to-end test `lossless_echo_round_trip_demo` comment corrected: the demo
  cannot exercise congestion control or loss detection on lossless loopback, but
  those subsystems are implemented and validated by their own unit tests.

### Fixed
- `into_driven` no longer silently drops the peer address: it now captures the
  driver's `peer` field before moving `conn` into the background task and stores it
  in `DrivenConnection::peer_addr`.

## [0.1.3] - 2026-06-15

### Changed
- Version bump to 0.1.3 across all workspace crates (no functional code changes).

---

## [0.1.2] - 2026-06-10

### Added

#### oxiquic-core
- `alpn` module: well-known ALPN protocol byte-string constants (`H3 = b"h3"`,
  `HTTP_0_9 = b"hq-interop"`) and the `alpn::protocols(&[&[u8]]) -> Vec<Vec<u8>>`
  builder helper for constructing owned ALPN lists from byte-string slices.
  Re-exported from the `oxiquic` facade as `oxiquic::alpn::{H3, HTTP_0_9, protocols}`.

#### oxiquic-transport
- `ServerEndpointBuilder::with_alpn_protocols(&[&[u8]]) -> Self` builder method:
  replaces `alpn_protocols` on the underlying `rustls::ServerConfig`, enabling
  ALPN negotiation on raw QUIC server endpoints without rebuilding the TLS config.
  Supersedes the `config_pair_with_alpn` test-only workaround used previously.

#### oxiquic (facade)
- `connect_with_alpn(addr, server_name, protocols)` convenience function: like
  `connect()` but sets `alpn_protocols` on the client TLS config before performing
  the handshake. After a successful connection, `QuicConnection::negotiated_alpn()`
  returns the protocol selected by the server.
- `listen_with_alpn(addr, cert_chain, private_key, protocols)` convenience function:
  like `listen()` but injects custom `alpn_protocols` into the server TLS config
  before binding the endpoint.
- `alpn` re-export module exposed at the crate root.

### Testing
- 3 new integration tests in `oxiquic-transport/tests/alpn.rs`:
  - `custom_alpn_roundtrip`: both sides advertise the same custom ALPN identifier;
    after the handshake `negotiated_alpn()` returns the identifier on both endpoints.
  - `alpn_not_set_does_not_panic`: no ALPN configured → handshake succeeds, both
    sides return `None` from `negotiated_alpn()`.
  - `server_endpoint_builder_with_alpn_protocols`: `ServerEndpointBuilder::with_alpn_protocols`
    correctly overrides ALPN configured at construction time; client sees the negotiated protocol.
- Total tests: 329 (unit + integration), all passing.

### Fixed
- `oxiquic-h3` `h3_response_status_codes` test: server task now calls
  `h3_server.shutdown(0)` after sending the response, so the driver task exits
  cleanly and the client receives `CONNECTION_CLOSE` before the server drops.
  Matches the pattern applied to `h3_get_roundtrip` in v0.1.1.

## [0.1.1] - 2026-06-04

### Added
- `bench_memory_usage` benchmark in `oxiquic-transport`: measures RSS delta per QUIC connection
  (1 and 10 connections) on Linux (`/proc/self/status`) and macOS (`mach_task_self()` task_info);
  prints a one-time per-connection kilobyte estimate alongside criterion timing data.
- `bench_h3_memory_profile` benchmark in `oxiquic-h3`: same RSS methodology applied to HTTP/3
  connections — reports per-H3-connection heap overhead and measures connection setup rate via
  criterion (`h3_memory/establish_n_h3_connections/{1,5}`).
- `bench_h3_push_overhead` benchmark in `oxiquic-h3`: documents server push stub latency vs an
  equivalent client-initiated GET; confirms the push stub path (always `NotImplemented` in h3
  0.0.8) adds no measurable network overhead (`h3_push_overhead/{client_get_1kb,push_stub_noop}`).
- `bench_h3_vs_h2_throughput` benchmark in `oxiquic-h3`: sustained throughput comparison of H3
  vs H2 at 256 KiB and 1 MiB payload sizes using `criterion::Throughput::Bytes` to report bytes/s
  (`h3_vs_h2_throughput/{h3,h2}_{256kb,1mb}`); exercises flow-control and congestion-window paths.

### Fixed
- `oxiquic-transport` driven connection loop: `io::ErrorKind::ConnectionRefused` (ICMP
  port-unreachable, sent when the peer's socket closes before a `CONNECTION_CLOSE` frame) is now
  treated as non-fatal — the loop continues instead of breaking, letting the QUIC loss-detection
  timer handle recovery per RFC 9000.
- `oxiquic-h3` `h3_get_roundtrip` integration test: server now calls `h3_conn.shutdown(0)` after
  serving the response, so the client receives `CONNECTION_CLOSE` and the driver task exits cleanly
  instead of racing against the QUIC idle-timeout.

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

[0.1.4]: https://github.com/cool-japan/oxiquic/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/cool-japan/oxiquic/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cool-japan/oxiquic/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cool-japan/oxiquic/releases/tag/v0.1.1
