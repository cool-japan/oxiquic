# oxiquic-transport TODO

## Status (updated 2026-06-19) — Wave 2: live QUIC transport on rustls

The transport is now a real Pure-Rust QUIC stack built DIRECTLY on the
`rustls::quic` TLS 1.3 API (driven by the `oxiquic-crypto` provider) over
`tokio` UDP — NOT on quinn/quinn-proto (the earlier "quinn 0.11.x gates its
rustls QUIC bridge behind ring/aws-lc-rs" blocker is sidestepped by implementing
RFC 9000/9001 in-house). `cargo tree -p oxiquic-transport --edges normal` has no
ring/aws-lc-rs/openssl; rcgen is dev-only.

### GREEN milestones (verified over real UDP loopback, 127.0.0.1)
- **M1 Initial handshake** — varint + packet-number coding (`coding.rs`),
  long/short header build+parse + header protection + packet protection +
  coalesced parse (`packet.rs`), CRYPTO/ACK/PADDING frames (`frame.rs`), CRYPTO
  reassembly (`crypto_stream.rs`), packet-number spaces + ACK ranges
  (`space.rs`), the sans-io `Connection` state machine (`connection.rs`) and the
  async `endpoint.rs` shell. Both peers reach handshake-complete.
- **M2 1-RTT + close** — 1-RTT keys on `KeyChange::OneRtt`, short-header
  packets, `HANDSHAKE_DONE`, `CONNECTION_CLOSE`, idle timeout.
- **M3 STREAM data** — bidirectional stream state machines + ordered reassembly
  + send/recv API (`stream.rs`). Client sends bytes on a bidi stream, server
  reads them in order. The end-goal echo demo (`tests/e2e.rs`) also passes, but
  only over lossless loopback (it exercises M1–M3, not M4/M5).
- **M4 RFC 9002 recovery** — per-space sent-packet tracking, RTT estimation
  (latest/smoothed/rttvar/min), PTO, packet-threshold + time-threshold loss
  detection, retransmission of lost CRYPTO/STREAM/control frames
  (`recovery.rs`, `sent_packet.rs`).
- **M5 congestion + flow control** — NewReno (RFC 9002 Appendix B: slow start,
  congestion avoidance, recovery, cwnd, ssthresh, bytes_in_flight) and BBR v2
  (~1092 LoC); connection-level and stream-level flow control (MAX_DATA /
  MAX_STREAM_DATA enforcement + DATA_BLOCKED / STREAM_DATA_BLOCKED frames)
  (`congestion.rs`, `flow_control.rs`).
- **M6 Async stream handles** — `DrivenConnection` task loop, `SendStreamHandle`
  (tokio::io::AsyncWrite), `RecvStreamHandle` (tokio::io::AsyncRead); facade
  `connect()` and `listen()` convenience functions wired up.

Public API: `ClientEndpoint::bind`+`connect`, `ServerEndpoint::bind`+`accept`
yield a `QuicConnection` (`open_bidi`, `send`, `read`, `accept_uni_or_bidi_data`,
`close`). `DrivenConnection` + `SendStreamHandle` + `RecvStreamHandle` expose
tokio AsyncWrite/AsyncRead. The sans-io `Connection` is exported for
`oxiquic-h3`.

### ALSO IMPLEMENTED (added since M6)
- **Version negotiation** — server sends VN packet for unknown versions; client
  handles VN response (`endpoint.rs` lines 407–415, `recv.rs` lines 79–90;
  6 tests in `tests/version_negotiation.rs`).
- **Retry** — server-side HMAC-SHA256 token generation/validation, client
  re-keys Initial on Retry receipt and retransmits (`endpoint.rs` lines 418–501,
  `recv.rs` lines 93–207; 7 tests in `tests/retry.rs`).
- **Key update (RFC 9001 §6)** — key phase bit, per-epoch key derivation,
  3-PTO cooldown, `initiate_key_update()` + `key_update_count()` on endpoint
  (`connection/keys_path.rs`; 3 tests in `tests/key_update.rs`).
- **Path migration (RFC 9000 §9)** — PATH_CHALLENGE/PATH_RESPONSE generation,
  validation, and candidate-address promotion (`connection/keys_path.rs`;
  5 tests in `tests/path_migration.rs`).
- **Multi-connection server demux** — DCID-based routing with `initial_map` and
  `local_cid_map`; 10 concurrent clients verified (`tests/multi_conn.rs`).
- **Keep-alive PING** — periodic PING at configurable interval; tested in
  `keep_alive_prevents_idle_close`.
- **100-stream concurrency** — `concurrent_streams_100` test in integration.rs.
- **10 MB payload** — `large_payload_10mb` test in integration.rs.

### NOT YET IMPLEMENTED — next waves
- 0-RTT, stateless reset, ECN.
- Datagram extension: Wave 1 complete (MAX_STREAMS, STREAMS_BLOCKED, NEW_TOKEN, DATAGRAM frames; RFC 9221 send/recv API). Remaining: 0-RTT datagram send.
- RESET_STREAM/STOP_SENDING: frame encode/decode and internal state plumbed;
  end-to-end user-facing API implemented: `SendStreamHandle::reset`, `RecvStreamHandle::stop_sending`,
  `BiStream::reset`/`stop_sending`, `UniSendStream::reset`, `UniRecvStream::stop_sending` are public
  and tested via `reset_stream_via_public_api` / `stop_sending_via_public_api` integration tests.
  (H3SendStream/H3RecvStream wrapper no-ops are an h3-compat concern and tracked separately.)

## Core Implementation (in-house engine — current status above)

### Transport Configuration (~300 SLOC)
- [x] Implement `TransportConfig` builder struct with all quinn transport parameters (~40 SLOC)
- [x] `TransportConfig::idle_timeout(duration: Duration) -> Self` per RFC 9000 Section 10.1 (~8 SLOC)
- [x] `TransportConfig::keep_alive_interval(interval: Option<Duration>) -> Self` for PING-based keepalive (~8 SLOC)
- [x] `TransportConfig::max_concurrent_bidi_streams(n: u64) -> Self` setting initial_max_streams_bidi per RFC 9000 Section 4.6 (~8 SLOC)
- [x] `TransportConfig::max_concurrent_uni_streams(n: u64) -> Self` setting initial_max_streams_uni (~8 SLOC)
- [x] `TransportConfig::stream_receive_window(bytes: u64) -> Self` per-stream flow control per RFC 9000 Section 4.1 (~8 SLOC)
- [x] `TransportConfig::receive_window(bytes: u64) -> Self` connection-level flow control (~8 SLOC)
- [x] `TransportConfig::send_window(bytes: u64) -> Self` (~8 SLOC)
- [x] `TransportConfig::initial_mtu(mtu: u16) -> Self` minimum 1200 per RFC 9000 Section 14.1 (~10 SLOC)
- [x] `TransportConfig::min_mtu(mtu: u16) -> Self` (~8 SLOC)
- [x] `TransportConfig::mtu_discovery(enabled: bool) -> Self` DPLPMTUD per RFC 8899 (~8 SLOC)
- [x] `TransportConfig::congestion_controller(algo: CongestionAlgorithm) -> Self` selecting Cubic or BBR (~10 SLOC)
- [x] Add `CongestionAlgorithm` enum: `Cubic` (RFC 9438), `Bbr` (BBRv2), `NewReno` (RFC 9002 Appendix B) (~15 SLOC)
- [x] Implement `TransportConfig::default()` with production-ready defaults: 30s idle timeout, 100 bidi streams, 100 uni streams, Cubic congestion control (~25 SLOC)

### 0-RTT Support (~150 SLOC)
- [x] Implement `Client::connect_0rtt(addr: SocketAddr) -> Result<(Connection, ZeroRttAccepted), OxiQuicError>` per RFC 9000 Section 4.6.1 (~40 SLOC)
  - **Goal:** `connect_0rtt` returns `(QuicConnection, ZeroRttAccepted)` using rustls `DirectionalKeys` for early data
  - **Files:** `connection/mod.rs`, `connection/send.rs`, `connection/recv.rs`, `packet.rs`, `endpoint/zero_rtt.rs` (new)
- [x] Add `ZeroRttAccepted` future resolving to `bool` indicating whether server accepted early data (~20 SLOC)
  - **Goal:** `ZeroRttAccepted` future backed by `tokio::oneshot` resolves to `bool` after handshake completes
  - **Files:** `endpoint/zero_rtt.rs`
- [x] Handle 0-RTT rejection: re-send data on 1-RTT fallback (~30 SLOC)
  - **Goal:** On 0-RTT rejection, `early_data_buf` replayed in 1-RTT; data always delivered
  - **Files:** `connection/mod.rs`, `connection/send.rs`
- [x] Implement session ticket caching for 0-RTT resumption via rustls `ClientSessionStore` (~40 SLOC)
  - **Goal:** rustls `ClientSessionMemoryCache` wired into `ClientConfig` so tickets cached across connections
  - **Files:** `endpoint/zero_rtt.rs`, `oxiquic/src/lib.rs` (facade `connect_0rtt`)
- [x] Server-side 0-RTT: configure `max_early_data_size` on `ServerBuilder` (~20 SLOC)
  - **Goal:** `TransportConfig::max_early_data_size(u32)` builder + `ServerEndpoint::bind` normalizes to `0` or `0xffff_ffff`
  - **Files:** `config.rs`, `endpoint/mod.rs`

## API Improvements
- [x] Add `ClientEndpoint::connect_timeout(addr, timeout: Duration) -> Result<QuicConnection>` with configurable handshake timeout (2026-05-29)
  - **Goal:** `connect_timeout` wraps `connect` with `tokio::time::timeout`
  - **Design:** `ClientEndpoint::connect_timeout(addr, timeout: Duration) -> Result<QuicConnection, OxiQuicError>`
  - **Files:** `endpoint/mod.rs`
  - **Tests:** test: connect to unreachable address → timeout error within deadline
  - **Risk:** Low
- [x] Add `QuicConnection::open_bidi_with_priority(priority: i32) -> Result<StreamId>` on `QuicConnection`; `DrivenConnection::open_bidi_with_priority` → `BiStream` (2026-05-29)
  - **Goal:** `open_bidi_with_priority` exposes stream priority
  - **Design:** Priority stored as hint; current scheduler does not reorder streams
  - **Files:** `endpoint/mod.rs`, `endpoint/driven.rs`
  - **Risk:** Stream priority not yet used by scheduler — stored only
- [x] Add `QuicConnection::streams_opened() -> u64` and `QuicConnection::streams_closed() -> u64` counters (2026-05-29)
  - **Goal:** accessors on `QuicConnection` for opened/closed streams via `stats()`
  - **Design:** delegates to `ConnectionStats::streams_opened`/`streams_closed`
  - **Files:** `endpoint/mod.rs`
  - **Risk:** Low
- [x] Add `BiStream` wrapper type holding `(SendStreamHandle, RecvStreamHandle)` pair with convenience methods (2026-05-29)
  - **Goal:** `BiStream` convenience wrapper
  - **Design:** `pub struct BiStream { send: SendStreamHandle, recv: RecvStreamHandle }` + write/read/finish/stream_id methods; `DrivenConnection::open_bidi()` returns `BiStream`
  - **Files:** `handle.rs`
  - **Risk:** Low
- [x] Implement `Drop` for `QuicConnection` sending graceful CONNECTION_CLOSE (2026-05-29)
  - **Goal:** `QuicConnection::drop` queues a CONNECTION_CLOSE in the state machine (best-effort; not flushed to socket)
  - **Design:** `impl Drop` with `Option<ConnectionDriver>` field; `into_driven` takes the driver via `Option::take`
  - **Files:** `endpoint/mod.rs`
  - **Risk:** Async in Drop — best-effort only; peer relies on idle timeout if not driven again
- [x] Add `ServerEndpoint::incoming() -> Incoming<'_>` as async iterator alternative to `accept()` (2026-05-29)
  - **Goal:** `ServerEndpoint::incoming` returns `Incoming` struct with `.next().await`
  - **Design:** `Incoming<'a>` struct with `next() -> Option<QuicConnection>`; no futures dep needed
  - **Files:** `endpoint/mod.rs`
  - **Risk:** Low — no Stream trait required

## Testing
- [x] Loopback echo test: client connects to server, opens bidi stream, sends 1KB, server echoes back, client verifies (~60 SLOC) — covered by e2e echo demo in tests/e2e.rs
- [x] Multi-stream concurrency: open 100 bidirectional streams in parallel, each sending/receiving 1KB (~50 SLOC) — `concurrent_streams_100` in integration.rs
- [x] Unidirectional stream: client sends on uni stream, server reads to end (~40 SLOC) — 3 tests in `tests/uni_stream.rs`
- [x] Large payload transfer: 10MB over single bidi stream, verify integrity with SHA-256 (~40 SLOC) — `large_payload_10mb` in integration.rs
- [x] Graceful connection close: client calls `close(0, b"done")`, server observes `ConnectionError::ApplicationClosed` (~30 SLOC) — covered by m2_handshake_then_clean_close
- [x] Connection stats: verify `rtt > 0`, `packets_sent > 0`, `packets_recv > 0` after echo exchange (~25 SLOC) — connection_stats_nonzero_after_exchange test
- [x] Idle timeout: set 1s idle timeout, wait 2s, verify connection closed with `IdleTimeout` error (~30 SLOC) — `idle_timeout_closes_connection` in integration.rs
- [x] Keep-alive: set 500ms keepalive with 2s idle timeout, wait 3s, verify connection still open (~30 SLOC) — `keep_alive_prevents_idle_close` in integration.rs
- [x] 0-RTT handshake: connect, disconnect, reconnect with 0-RTT, verify early data accepted (~50 SLOC)
  - **Goal:** Integration test: connect, close, `connect_0rtt`, verify `ZeroRttAccepted` and early bytes delivered
  - **Files:** `tests/zero_rtt.rs` (new, 6 tests: 2 unit + 4 integration)
- [x] Stateless retry: enable retry on server, verify client reconnects after retry token (~40 SLOC) — `retry_then_stream_data_delivered` in tests/retry.rs
- [x] Stream reset: sender resets stream, receiver observes reset code (~30 SLOC) — 4 state-machine tests + `reset_stream_via_public_api` DrivenConnection end-to-end test in `tests/stream_reset.rs`
- [x] Stop sending: receiver sends STOP_SENDING, sender gets write error (~30 SLOC) — covered in `tests/stream_reset.rs`; `stop_sending_via_public_api` DrivenConnection end-to-end test added
- [x] MTU discovery: verify negotiated MTU > 1200 on loopback (~25 SLOC) — `mtu_discovery_integration` in tests/mtu_discovery.rs
- [x] TLS tripwire: `cargo tree -e normal` contains no ring/aws-lc-rs/openssl crates (~CI script)
- [x] Server concurrent connections: 10 clients connect simultaneously, all exchange data (~50 SLOC) — `ten_clients_concurrent` in tests/multi_conn.rs
- [x] AsyncRead/AsyncWrite: use `tokio::io::copy()` over QUIC streams to verify trait impls (~30 SLOC)
- [x] Datagram send/recv: send unreliable datagram, verify receipt (~30 SLOC)
  - **Goal:** Datagram echo integration test: client sends unreliable DATAGRAM, server receives
  - **Design:** `TransportConfig::max_datagram_frame_size(1200)` on both sides; `QuicConnection::send_datagram` / `recv_datagram` over UDP loopback
  - **Files:** `tests/datagram.rs` (new)
  - **Tests:** `datagram_echo_client_to_server`, `datagram_disabled_peer_returns_error`
  - **Wave 1 also implemented:** MAX_STREAMS, STREAMS_BLOCKED, NEW_TOKEN frame support; stream limit enforcement; NEW_TOKEN post-handshake issuance; `stream_limits.rs` integration tests

## Performance
- [x] Benchmark 1-RTT handshake latency (target: < 5ms loopback) (~criterion bench)
  — `bench_handshake_latency` in `benches/transport.rs` (`handshake/1rtt`)
- [x] Benchmark single-stream throughput for payload sizes: 1KB, 64KB (~criterion bench)
  — `bench_stream_throughput` in `benches/transport.rs` (`stream_throughput/echo/1kb`, `64kb`)
- [x] Benchmark multi-stream throughput: sequential bidi streams on one connection (2026-05-30)
  — `bench_multi_stream_throughput` in `benches/transport.rs` (`multi_stream_throughput/sequential_1kb_per_stream/2`, `/8`); higher values (50, 100) left deferred — slow on CI
- [x] Benchmark 0-RTT handshake latency (target: < 2ms loopback)
  — `bench_zero_rtt_handshake` in `benches/transport.rs` (`zero_rtt/connect_0rtt_warm`)
- [x] Benchmark single-stream throughput for payload sizes 1MB and 10MB (bench_stream_throughput_large in transport.rs; 100MB deferred — too slow on CI)
  — `bench_stream_throughput_large` in `benches/transport.rs` (`stream_throughput_large/echo/1mb`, `/10mb`)
- [x] Benchmark multi-stream throughput at 50 concurrent streams (bench_multi_stream_concurrent_50 in transport.rs; 100-stream deferred — too slow on CI)
  — `bench_multi_stream_concurrent_50` in `benches/transport.rs` (`multi_stream_concurrent/sequential_1kb_per_stream/50`)
- [x] Benchmark connection establishment rate: connections per second to a single server
  — `bench_connection_establishment_rate` in `benches/transport.rs` (`connection_rate/sequential_connects_10`)
- [x] Profile CPU utilization during high-throughput transfer (identify bottlenecks in crypto/framing/syscalls) (2026-06-19)
  — `cpu_profile.rs` bench added: 4 groups covering e2e throughput (1KB/64KB/1MB), raw UDP baseline,
  STREAM frame encode/decode throughput, AES-128-GCM AEAD encrypt/decrypt throughput; prints
  per-phase breakdown at bench startup (UDP ns, codec ns/op, AEAD ns/op, QUIC wall-time overhead).
- [x] Benchmark memory usage per connection and per stream (track allocator stats) (2026-06-03)
  — `bench_memory_usage` added to `crates/oxiquic-transport/benches/transport.rs`; measures RSS
  delta before/after holding N connections (1, 10); prints per-connection kB estimate to stdout
  alongside the criterion timing measurements (N ∈ {1, 10} connections per iteration).
  RSS reader works on Linux (/proc/self/status) and macOS (mach_task_info); prints
  "unavailable" on other platforms and still provides timing data.
- [x] Compare Cubic vs BBR vs NewReno throughput on simulated lossy network (2026-06-19)
  — `congestion_compare.rs` bench added: in-process bidirectional lossy relay (no tc/netem required);
  benchmarks 512 KiB payload throughput at lossless / 1% drop+10ms / 3% drop+30ms per algorithm;
  also benchmarks cwnd growth rate (unit-level, no I/O) for N∈{10,100,1000} ACK events.

## Integration
- [x] Use `oxitls-rcgen` for test certificate generation in integration tests (if available, else `rcgen` directly)
  — `oxitls_rcgen::generate_self_signed_ed25519` is used in every integration test file (stream_reset, version_negotiation, zero_rtt, key_update, retry, etc.)
- [x] Expose `Connection` type for use by `oxiquic-h3` HTTP/3 layer — re-exported in lib.rs
- [x] Ensure `TransportConfig` defaults align with `oxiquic-core::TransportParams` RFC 9000 defaults (2026-05-30 confirmed)
  — `TransportConfig::to_transport_params()` maps all fields; RFC non-zero defaults (ack_delay_exponent=3, max_ack_delay_ms=25, active_connection_id_limit=2) are set via `TransportParams::default()`. Production defaults (30s idle, 100 streams, 1 MiB windows) are intentionally higher than RFC wire minimums (0).
- [x] Wire into `oxiquic` facade crate behind `transport` feature flag
- [ ] Coordinate congestion controller selection with any future `oxiquic-cc` crate (blocked: oxiquic-cc crate does not exist yet — external coordination)
- [x] Ensure `OxiQuicError` mapping from transport errors preserves transport error codes for diagnostic logging (2026-05-30)
  — `ConnectionDriver::close_error()` now reconstructs the full `OxiQuicError::TransportError { code, frame_type, reason }` or `ApplicationClose { code, reason }` from `peer_close_reason()` instead of flattening to `Connection(string)`. `endpoint/mod.rs` line ~1115.

## Removed (stale quinn-wrapper items)

The original design had three sections wrapping quinn types directly: "Client
Side" (constructing `quinn::Endpoint`, `ClientBuilder` calling
`rustls-rustcrypto::provider()`), "Connection" (wrapping `quinn::Connection`),
"Stream Types" (wrapping `quinn::SendStream`/`RecvStream`), "Server Side"
(wrapping `quinn::Endpoint` in server mode, `Connecting` wrapping
`quinn::Connecting`), and "Error Mapping" (mapping `quinn::ConnectionError`,
`quinn::WriteError`, etc.). All of these are superseded by the in-house
implementation (`ClientEndpoint`, `ServerEndpoint`, `QuicConnection`,
`SendStreamHandle`, `RecvStreamHandle` in the live codebase). The
`TransportConfig -> quinn::TransportConfig` conversion item and the
`rustls-rustcrypto` sole-provider wire item have also been removed.
