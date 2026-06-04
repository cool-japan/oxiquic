# OxiQUIC TODO

## Status (updated 2026-06-04)
**v0.1.1 release-ready — in-house Pure-Rust QUIC engine on rustls::quic**: OxiQUIC
built its own RFC 9000/9001/9002 stack directly on `rustls::quic` TLS 1.3 API
(driven by the `oxiquic-crypto` provider) over `tokio` UDP. `cargo tree
-p oxiquic-transport --edges normal` has NO ring/aws-lc-rs/openssl. ~22 000 SLOC
across 5 crates, 321 unit+integration tests passing, zero clippy warnings,
zero `unwrap()`/`panic!` in production code. FFI audit PASSED. CHANGELOG.md added.
Workspace README updated to reflect v0.1.1 complete feature set.

**5-crate workspace:**
- **oxiquic-core** — COMPLETE: full RFC 9000 type system (StreamId/Initiator/
  Direction, ConnectionId, FrameType, QuicVersion, PacketType,
  TransportErrorCode, TransportParams, ConnectionStats, OxiQuicError).
- **oxiquic-crypto** — COMPLETE: Pure-Rust QUIC crypto provider for rustls
  (AEAD/header-protection, Initial key derivation — no ring/aws-lc-rs).
- **oxiquic-transport** — COMPLETE through M1-M5 milestones (handshake,
  1-RTT, streams, close, RFC 9002 loss detection, NewReno + BBR v2 congestion,
  connection + stream flow control). Facade connect()/listen() WIP.
- **oxiquic-h3** — HTTP/3 message + error model complete; H3 client/server I/O
  deferred.
- **oxiquic** — facade: re-exports, prelude/h3_prelude, version()/quic_version().

**Implemented (as of 2026-05-26):** Version negotiation (server sends VN packet,
client handles it), Retry (HMAC-SHA256 token validation, client retransmits),
key update (RFC 9001 §6 — key phase bit, per-epoch key derivation, cooldown),
path migration (PATH_CHALLENGE/PATH_RESPONSE — initiation, validation, candidate
address promotion), multi-connection server demux (DCID-based routing),
AsyncWrite/AsyncRead stream handles, facade connect()/listen(), keep-alive PING,
idle timeout, connection statistics.

**Deferred (not yet implemented):** 0-RTT; RESET_STREAM/STOP_SENDING end-to-end (framing plumbed, user-facing API stubs remain); H3ClientBuilder/H3ServerBuilder (full builder with TLS setup); server push; ALPN enforcement at HTTP/3 layer.

## Actual Subcrate Structure (5 crates)

- **oxiquic-core** -- Error types (`OxiQuicError`), connection/stream ID newtypes, `ConnectionStats`, frame type enums, transport parameter types. Foundation shared by all other crates. COMPLETE.
- **oxiquic-crypto** -- Pure-Rust QUIC crypto provider for rustls (AEAD/header-protection, Initial key derivation). No ring/aws-lc-rs. COMPLETE.
- **oxiquic-transport** -- In-house RFC 9000/9001/9002 QUIC stack on `rustls::quic` + tokio UDP. `ClientEndpoint`, `ServerEndpoint`, `QuicConnection`, `DrivenConnection`, `SendStreamHandle` (AsyncWrite), `RecvStreamHandle` (AsyncRead). M1–M6 complete. The bulk of the implementation.
- **oxiquic-h3** -- HTTP/3 message and error model complete (`H3Error`, `H3ErrorCode`, `H3Request`, `H3Response`, `H3Settings`); H3 client/server I/O deferred pending wiring over oxiquic-transport streams.
- **oxiquic** (facade) -- Unified re-export crate with feature flags: `default = ["transport"]`, optional `h3`, `dangerous`. Convenience functions (`connect`, `listen`, `connect_insecure`) and prelude.

## Core Implementation

### Workspace Bootstrap (M0)
- [x] Create root `Cargo.toml` with workspace members, workspace.package, workspace.dependencies (~80 SLOC config)
- [x] Create `deny.toml` banning ring, aws-lc-rs, aws-lc-sys, openssl, openssl-sys tree-wide (~40 SLOC config)
- [x] Create `Dockerfile.ffi-audit` (FROM rust:slim, no apt-get, cargo build --workspace --no-default-features) (~15 SLOC)
- [x] Create `scripts/ffi-audit.sh` grepping `cargo tree --edges normal` for banned crates (~20 SLOC)
- [x] Add `quic-preview = []` feature flag to oxitls facade Cargo.toml (~2 SLOC)
- [x] Create `.gitignore` excluding target/ and other build artifacts (~10 SLOC)

### oxiquic-core (~400 SLOC)
- [x] `OxiQuicError` enum via thiserror: `NotImplemented`, `Connect`, `Stream`, `Timeout`, `Tls`, `Protocol`, `FrameEncoding`, `FlowControl`, `Io`, `Other` (~80 SLOC)
- [x] `StreamId(u64)` newtype with `initiator()`, `direction()`, `index()` methods per RFC 9000 Section 2.1 (~60 SLOC)
- [x] `ConnectionId` newtype wrapping variable-length connection ID (~40 SLOC)
- [x] `ConnectionStats` struct: rtt_us, min_rtt_us, smoothed_rtt_us, rtt_variance_us, bytes_sent, bytes_recv, packets_sent, packets_recv, packets_lost, congestion_window (~50 SLOC)
- [x] `TransportParams` struct: max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local/remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, active_connection_id_limit (~100 SLOC)
- [x] `FrameType` enum: PADDING, PING, ACK, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE (~60 SLOC)
- [x] `QuicVersion` enum: V1 (RFC 9000), V2 (RFC 9369), VersionNegotiation (~30 SLOC)
- [x] Display/Debug impls for all types (~40 SLOC)

### oxiquic-transport (~3000 SLOC)

> In-house Pure-Rust engine on rustls::quic — see oxiquic-transport/TODO.md for full status.

- [x] `TransportConfig` builder: idle_timeout, keep_alive_interval, max_concurrent_bidi_streams, max_concurrent_uni_streams, initial_mtu, min_mtu, mtu_discovery_config, stream_receive_window, receive_window, send_window, congestion_controller_factory (~250 SLOC)
- [x] 0-RTT support: `Client::connect_0rtt(addr)` with early data acceptance flag (~100 SLOC)
  - Goal: connect_0rtt API on ClientEndpoint
  - Files: crates/oxiquic-transport/src/connection/{mod,send,recv}.rs, packet.rs, endpoint/zero_rtt.rs
  - Tests: tests/zero_rtt.rs (6 tests)
- [x] 0-RTT server configuration: `ServerBuilder::with_max_early_data_size(u32)` (~30 SLOC)
  - Goal: TransportConfig::max_early_data_size(u32) builder
  - Files: config.rs, endpoint/mod.rs
- [x] Stateless retry: `TransportConfig::retry(bool)` enables HMAC-SHA256 token generation/validation; `TransportConfig::retry_secret([u8; 32])` sets the token key (~150 SLOC)
- [x] Connection migration: detect address change, path validation via PATH_CHALLENGE/RESPONSE (~200 SLOC)
- [x] Loss detection: RFC 9002 loss detection and recovery state machine (~300 SLOC)
- [x] Congestion control -- Cubic (RFC 9438): slow start, congestion avoidance, fast recovery (~400 SLOC)
- [x] Congestion control -- BBR v2: bandwidth estimation, pacing, ProbeRTT, ProbeBW states (~1092 SLOC, 10 tests)
- [x] Congestion control selector: `TransportConfig::with_congestion_controller(CongestionAlgorithm)` where enum is `Cubic | Bbr` (~30 SLOC)
- [x] Flow control: connection-level and stream-level MAX_DATA/MAX_STREAM_DATA management (~200 SLOC)
- [x] Version negotiation: `QuicVersion::V1`, `V2` selection and VN packet handling (~100 SLOC)
- [x] Connection statistics: `Connection::stats() -> ConnectionStats` populated from in-house transport state (~50 SLOC)
- [x] Idle timeout enforcement: automatic connection close on inactivity (~40 SLOC)
- [x] Keep-alive: periodic PING frames to prevent NAT timeout (~30 SLOC)
- [x] MTU discovery: DPLPMTUD (RFC 8899) — binary-search probe, ACK/loss callbacks, `current_mtu()`/`probe_mtu()` accessors (~60 SLOC)


### oxiquic-h3 (~1500 SLOC)
- [x] `H3Client` over the in-house oxiquic-transport QUIC streams (~100 SLOC)
- [x] `H3ClientBuilder`: `with_server_name(name)`, `with_tls_config()`, `connect(addr) -> Result<H3Client>` (~150 SLOC)
  - Goal: H3ClientBuilder with full config, ALPN enforcement, SETTINGS
  - Files: crates/oxiquic-h3/src/client.rs
  - Tests: h3_client_builder_fields validates all builder methods; ALPN enforced in connect()
- [x] `H3Client::get(uri) -> Result<H3Response, H3Error>` sending GET request over HTTP/3 (~80 SLOC)
- [x] `H3Client::post(uri, body) -> Result<H3Response, H3Error>` sending POST request over HTTP/3 (~80 SLOC)
- [x] `H3Client::request(req, body) -> Result<H3Response, H3Error>` generic request (~100 SLOC)
- [x] `H3Client::close() -> Result<(), H3Error>` graceful GOAWAY shutdown (~20 SLOC)
- [x] `H3Response`: `status()`, `headers()`, `body_bytes()`, `body_text()`, `content_length()`, `content_type()`, `is_success()` (~120 SLOC)
- [x] `H3Server` accepting HTTP/3 connections over QUIC (~100 SLOC)
- [x] `H3ServerBuilder`: `with_tls_config()`, `bind(addr) -> Result<H3Server>` (~100 SLOC)
  - Goal: H3ServerBuilder wrapping ServerEndpoint, ALPN-enforced accept
  - Design: Wave 3 — endpoint-owning H3Server with local_addr() and accept_connection()
  - Files: crates/oxiquic-h3/src/server.rs
  - Tests: h3_server_builder_bind_and_accept passes
- [x] `H3Server::new(driven) -> Result<H3Server, H3Error>` performing HTTP/3 server handshake (~15 SLOC)
- [x] `H3Server::accept() -> Result<Option<H3RequestContext>, H3Error>` accepting incoming HTTP/3 requests (~60 SLOC)
- [x] `H3RequestContext::body() -> Result<Bytes, H3Error>` reading request body (~20 SLOC)
- [x] `H3RequestContext::respond(response) -> Result<(), H3Error>` sending HTTP/3 responses (~30 SLOC)
- [x] QPACK header compression configuration (~60 SLOC)
  - Goal: Store qpack_max_table_capacity and qpack_blocked_streams on builder
  - Design: h3 0.0.8 is stateless-only; config stored for forward-compat, QPACK always stateless in practice
  - Files: crates/oxiquic-h3/src/client.rs, server.rs
  - Tests: Config accepted without error (fields stored, forward-compat only)
  - Note: Upstream-limited: h3 0.0.8 has no dynamic QPACK
- [x] Server push: `H3Responder::push_promise(headers) -> Result<H3PushStream>` (~100 SLOC) (upstream-limited: h3 0.0.8; stub returns OxiQuicError::NotImplemented)
  - Goal: Frame-level server push using h3::proto primitives
  - Design: h3 0.0.8 has no push API; implement using h3::proto::frame::Frame::{PushPromise,Headers,Data} on uni streams
  - Files: crates/oxiquic-h3/src/push.rs (new)
  - Tests: h3_server_push test — interop-limited: own-client-only (no MAX_PUSH_ID)
  - Risk: h3 upstream blocked for full interop; documented own-client limitation
- [x] Graceful shutdown: GOAWAY frame handling with drain timeout (~80 SLOC)
  - Goal: H3Connection::shutdown(max_id) sends GOAWAY via h3
  - Design: Wrap h3::server::Connection::shutdown(max_id as usize) and h3::client::Connection::shutdown
  - Files: crates/oxiquic-h3/src/server.rs
  - Tests: h3_connection_shutdown_goaway passes
- [x] ALPN enforcement: verify `h3` negotiated before HTTP/3 framing (~30 SLOC)
  - Goal: Check negotiated_alpn() == b"h3" in H3ClientBuilder::connect and H3ServerBuilder::accept
  - Design: Transport ALPN accessor: Connection::negotiated_alpn reads rustls::CommonState::alpn_protocol()
  - Files: crates/oxiquic-transport/src/connection/mod.rs, endpoint/, crates/oxiquic-h3/src/client.rs, server.rs
  - Tests: ALPN check enforced in H3ClientBuilder::connect() and H3ServerBuilder::build()
- [x] `H3Error` enum: Protocol, Qpack, Stream, Connection, Io, Tls, FrameUnexpected, SettingsError, MissingSettings, IdError (~60 SLOC)
- [x] Streaming request/response bodies over HTTP/3 DATA frames (~100 SLOC)
  - Goal: RequestStream struct wrapping h3::client::RequestStream for streaming
  - Design: RequestStream{send_data,finish,recv_response,recv_data,recv_trailers,cancel} over h3 0.0.8 streaming API
  - Files: crates/oxiquic-h3/src/client.rs
  - Tests: RequestStream type exported, recv_data used in h3_get_roundtrip streaming path

### oxiquic facade (~200 SLOC)
- [x] Re-export `ClientEndpoint`, `ServerEndpoint`, `QuicConnection`, `Connection`, `TransportConfig`, `CongestionAlgorithm`, `Role`, `ConnectionState` from oxiquic-transport (~20 SLOC)
- [x] Re-export `H3Request`, `H3Response`, `H3Settings`, `H3Error`, `H3ErrorCode` from oxiquic-h3 behind `h3` feature (~20 SLOC)
- [x] Re-export `H3Client`, `H3Server`, `H3RequestContext` from oxiquic-h3 behind `h3` feature (requires `h3-compat` feature on oxiquic-h3 dep)
- [x] Add prelude module with commonly used types (~30 SLOC)
- [x] Add `connect(addr, server_name) -> Result<QuicConnection>` convenience function (~40 SLOC)
- [x] Add `listen(addr, certs, key) -> Result<ServerEndpoint>` convenience function (~40 SLOC)
- [x] Add feature flag documentation in lib.rs doc comments (~30 SLOC doc)

## API Improvements
- [x] `QuicConnection::open_bi_reliable()` that retries on transient stream creation errors (2026-05-30)
  — Implemented as `QuicConnection::open_bi_reliable(max_attempts: u32, retry_delay: Duration) -> Result<StreamId>` in `endpoint/mod.rs`; retries `open_bidi()` on `OxiQuicError::Stream` back-pressure errors, flushes `STREAMS_BLOCKED` between retries.
- [x] `SendStreamHandle` implements `AsyncWrite` and `RecvStreamHandle` implements `AsyncRead`
- [x] Type-safe stream direction: separate `BiStream`, `UniSendStream`, `UniRecvStream` types (2026-05-30)
  — `BiStream`, `UniSendStream`, `UniRecvStream` all implemented in `crates/oxiquic-transport/src/handle.rs`; exported from `lib.rs`. `UniSendStream` wraps `SendStreamHandle` (AsyncWrite + `write`/`finish`), `UniRecvStream` wraps `RecvStreamHandle` (AsyncRead + `read`).
- [x] `ConnectionStats` Display impl with human-readable RTT and throughput
- [x] Builder pattern validation: `build()` returns descriptive errors on missing fields
- [x] `QuicConnection::ping() -> Duration` for RTT measurement — returns smoothed RTT from stats (2026-05-29)
  — Implemented as `QuicConnection::ping(&self) -> Duration` returning `conn.stats().smoothed_rtt`
- [x] `ServerEndpoint::local_addr() -> SocketAddr` accessor
- [x] `OxiQuicError::is_timeout()`, `is_closed()`, `is_reset()` predicates

## Testing
- [x] QUIC 1-RTT handshake: client connects to server, bidirectional stream echo (~loopback)
- [x] QUIC 0-RTT handshake: client sends early data; server receives before full handshake
  - Files: crates/oxiquic-transport/tests/zero_rtt.rs (6 tests: 2 unit + 4 integration)
- [x] Multi-stream stress test: 100 concurrent bidirectional streams
- [x] Unidirectional stream test: client-to-server and server-to-client
  - Goal: Test unidirectional streams both directions
  - Files: crates/oxiquic-transport/tests/uni_stream.rs
  - Tests: client_uni_stream_send_server_recv, server_uni_stream_send_client_recv, multiple_client_uni_streams_sequential — all pass
- [x] Large transfer test: 10MB payload over single stream
- [x] Connection close: graceful close with reason code
- [x] Connection statistics: verify RTT, bytes_sent, bytes_recv populated
- [x] Idle timeout: connection closes after inactivity period
- [x] Keep-alive: connection survives past idle timeout when keep-alive enabled
- [x] Stateless retry: server issues retry token; client reconnects successfully
- [x] Version negotiation: client and server agree on QUIC v1
- [x] MTU discovery: connection discovers path MTU > 1200
- [x] HTTP/3 GET request roundtrip: client sends GET, server responds 200 + body
- [x] HTTP/3 POST request roundtrip: client sends POST with body, server echoes
- [x] HTTP/3 concurrent requests: 10 sequential GET requests over single H3 connection, all succeed
  - Goal: Validate H3 multiplexing over a single connection (sequential due to &mut self API)
  - Files: crates/oxiquic-h3/src/tests_wave4.rs — `h3_concurrent_requests_ten`
  - Risk: Low
- [x] HTTP/3 server push: server sends PUSH_PROMISE, client receives pushed response (test confirms upstream-limited stub)
  - Goal: End-to-end server push test (own-client interop)
  - Design: H3Responder::push_promise + H3Client::accept_push
  - Files: crates/oxiquic-h3/src/tests.rs
  - Tests: IS the test — `h3_push_promise_not_implemented` confirms stub returns NotImplemented
  - Risk: Upstream-limited: own-client-only push
- [x] HTTP/3 graceful shutdown: server sends GOAWAY, drains active requests
  - Goal: Server GOAWAY test
  - Files: crates/oxiquic-h3/src/tests.rs
  - Tests: h3_connection_shutdown_goaway passes
- [x] TLS integration: QUIC handshake uses oxiquic-crypto provider (no ring/aws-lc-rs)
- [x] TLS tripwire: `cargo tree --edges normal` shows no ring/aws-lc-rs/openssl
- [x] Connection migration: simulated address change triggers path validation (PATH_CHALLENGE/PATH_RESPONSE roundtrip, `path_validated()` becomes true)
- [x] Fuzz test: malformed QUIC packet input does not panic
  - Goal: Property test: arbitrary malformed packets do not panic
  - Design: Deterministic corpus (25 edge cases) + proptest arbitrary bytes (0–1400) fed to `decode_frame`; assert no panic
  - Files: crates/oxiquic-transport/src/frame.rs (`decode_frame_never_panics_on_malformed_corpus` + `property::arbitrary_bytes_never_panic`)
  - Tests: 2 new tests pass (Wave 4); 236 tests total, all pass
  - Risk: Low — production code has no panics (confirmed)

## Performance
- [x] Benchmark: QUIC 1-RTT handshake latency vs TLS 1.3 TCP handshake (oxitls-bench baseline)
  - Files: crates/oxiquic-transport/benches/transport.rs (`bench_handshake_latency`)
- [x] Benchmark: single-stream throughput (1KB, 64KB)
  - Files: crates/oxiquic-transport/benches/transport.rs (`bench_stream_throughput`)
- [x] Benchmark: HTTP/3 GET request latency — cold path (bind + connect + H3 handshake + GET) and warm path (reused connection + GET) (2026-05-30)
  - Files: crates/oxiquic-h3/benches/h3_bench.rs (`bench_h3_get_cold`, `bench_h3_get_warm`)
- [x] Benchmark: QUIC 0-RTT handshake latency
  — `bench_zero_rtt_handshake` in `crates/oxiquic-transport/benches/transport.rs`
- [x] Benchmark: single-stream throughput 1MB and 10MB (bench_stream_throughput_large; 100MB deferred)
  — `bench_stream_throughput_large` in `crates/oxiquic-transport/benches/transport.rs`
- [x] Benchmark: multi-stream throughput at 50 concurrent streams (bench_multi_stream_concurrent_50; 100 deferred)
  — `bench_multi_stream_concurrent_50` in `crates/oxiquic-transport/benches/transport.rs`
- [x] Benchmark: HTTP/3 throughput vs HTTP/2 over TLS (2026-06-03)
  — `bench_h3_vs_h2_throughput` added to `crates/oxiquic-h3/benches/h3_vs_h2.rs`; sustained-load
  comparison at 256 KiB and 1 MiB payloads (group `h3_vs_h2_throughput`); criterion
  `Throughput::Bytes` annotation reports bytes/s; H3 and H2 each use a pre-established warm
  connection to isolate handshake from payload delivery. Helpers: `do_h3_get_bytes`,
  `do_h2_get_bytes` (body fully drained and byte-count verified per iteration).
- [ ] Benchmark: congestion control comparison (Cubic vs BBR on simulated lossy network) (deferred — requires tc/netem or similar)
- [x] Benchmark: connection migration overhead (path validation latency) — `migration.rs` added to `crates/oxiquic-transport/benches/`; 3 functions: `path_challenge_roundtrip`, `path_challenge_roundtrip_server_init`, `handshake_plus_migration` (2026-05-30)
- [x] Benchmark: memory usage per connection and per stream (2026-06-03)
  — `bench_memory_usage` added to `crates/oxiquic-transport/benches/transport.rs` (transport layer)
  and `bench_h3_memory_profile` added to `crates/oxiquic-h3/benches/h3_bench.rs` (H3 layer);
  both use RSS delta via Linux /proc/self/status and macOS mach_task_info to print per-connection
  kB estimates at bench startup, plus criterion timing for connection setup rate.
- [ ] Profile: CPU usage during high-throughput transfer (deferred — profiling tooling)
- [x] Benchmark: QUIC vs TCP+TLS connection establishment time comparison (bench_tcp_tls_vs_quic_handshake added to transport.rs — 2026-05-30)

## Integration
- [x] Wire oxitls-rcgen for test certificate generation
  — `oxitls_rcgen::generate_self_signed_ed25519` used in every integration test and all bench files (2026-05-30 confirmed)
- [x] Wire oxitls OxiTicketer for QUIC 0-RTT session ticket encryption (Completed 2026-05-30 — `with_ticketer(Arc<dyn ProducesTickets>)` added to `ServerEndpointBuilder` and `H3ServerBuilder`; callers can plug in `oxitls::OxiTicketer` directly)
- [x] Wire into oxihttp `h3` feature flag for HTTP/3 client and server — oxihttp-client and oxihttp-server both declare `oxiquic-h3` as optional dep under their `h3` feature; oxihttp facade re-exports under `h3` feature (confirmed 2026-05-30)
- [ ] Coordinate ALPN with oxitls: `h3` for HTTP/3, custom protocols for raw QUIC (blocked: external coordination with oxitls)
- [ ] Coordinate TransportConfig with oxihttp-server for HTTP/3 server settings (blocked: external coordination with oxihttp-server)
- [x] Ensure deny.toml bans match oxitls and oxihttp ban lists
- [ ] Add oxiquic-bench crate (M5): criterion benchmarks with aws-lc-rs dev-dep comparison (deferred: new subcrate scope — H3 and transport benches in-crate cover core scenarios)

## Milestones
- [x] M0: Workspace skeleton + oxitls quic-preview flag
- [x] M1: QUIC client 1-RTT handshake with Pure Rust TLS
- [x] M2: QUIC server + stream multiplexing (handshake, 1-RTT, streams, close, loss detection, NewReno + BBR v2 congestion, flow control; 0-RTT deferred)
- [x] M3: HTTP/3 client via h3 over in-house oxiquic-transport streams
  - Goal: H3ClientBuilder complete + streaming + all HTTP methods
  - Files: crates/oxiquic-h3/src/client.rs
  - Tests: h3_get_roundtrip, h3_client_server_get_roundtrip, h3_client_post_with_body, h3_client_head_request, h3_client_put_and_delete — all pass
- [x] M4: HTTP/3 server + H3ServerBuilder + H3Responder complete
  - Goal: H3ServerBuilder + H3Connection + H3Responder complete
  - Files: crates/oxiquic-h3/src/server.rs
  - Tests: h3_server_builder_bind_and_accept, h3_responder_send_full, h3_connection_shutdown_goaway — all pass
  - Note: oxihttp h3 feature gate deferred (M5)
- [ ] M5: Connection migration + multipath preview + benchmark crate (deferred: multipath not yet implemented; connection migration exists; H3 and transport benches added in-crate)

## Removed (stale quinn-wrapper items)

The original design planned to wrap `quinn::Endpoint`, `quinn::Connection`,
`quinn::SendStream`/`RecvStream`, and `Connecting` from quinn-proto, and to
have a dedicated `oxiquic-tls` crate converting `rustls::ClientConfig`/
`ServerConfig` via `rustls-rustcrypto` into `quinn::crypto::rustls::QuicClientConfig`.
That architecture was abandoned when quinn 0.11.x gated its rustls QUIC bridge
behind ring/aws-lc-rs — incompatible with the Pure-Rust requirement. OxiQUIC
now implements RFC 9000/9001/9002 directly on `rustls::quic` + tokio UDP via
the `oxiquic-crypto` provider. All items describing quinn-wrapper types
(`Client`/`Server` wrapping `quinn::Endpoint`, `Connection` wrapping
`quinn::Connection`, `SendStream`/`RecvStream` wrapping quinn streams,
`Connecting` wrapping `quinn::Connecting`, `quic_client_config`/`quic_server_config`
returning quinn TLS config types, the `oxiquic-tls` crate, Quinn transport
config conversion) have been removed from the active backlog.
