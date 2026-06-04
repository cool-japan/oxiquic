# OxiQUIC

[![Crates.io](https://img.shields.io/crates/v/oxiquic.svg)](https://crates.io/crates/oxiquic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

OxiQUIC is the COOLJAPAN Pure-Rust QUIC transport and HTTP/3 stack.
It implements RFC 9000/9001/9002 directly on the `rustls::quic` TLS 1.3 API
driven by the `oxiquic-crypto` Pure-Rust crypto provider over `tokio` UDP —
**zero dependency on ring, aws-lc-rs, or any C/C++ cryptographic library**.

## Features

- **No ring, no aws-lc-rs.** `cargo tree --edges normal` contains zero C crypto
  crates. The QUIC crypto provider (`oxiquic-crypto`) implements AEAD, header
  protection and Initial key derivation entirely in Rust (RustCrypto ecosystem:
  AES-GCM, ChaCha20-Poly1305, HKDF-SHA256/384).
- **In-house RFC 9000/9001/9002 stack** on `rustls::quic` + tokio UDP.
  Loss detection (RFC 9002), Cubic (RFC 9438) and BBR v2 congestion control,
  connection and stream flow control are all implemented in-house.
- **Full handshake stack**: 1-RTT TLS 1.3, 0-RTT early data, stateless retry,
  version negotiation, key update (RFC 9001 §6), connection migration
  (PATH_CHALLENGE/PATH_RESPONSE), idle timeout, keep-alive PING.
- **HTTP/3** via the `h3` crate wired over in-house QUIC stream handles.
  Full client (`H3ClientBuilder`) and server (`H3ServerBuilder`) implementations.
- **Type-safe stream API**: `BiStream`, `UniSendStream` (AsyncWrite), `UniRecvStream`
  (AsyncRead) with independent flow control.
- **321 tests** (unit + integration), zero clippy warnings, zero `unwrap()`/`panic!`
  in production code, ~22 000 SLOC.

## Crates

| Crate | Description |
|---|---|
| `oxiquic-core` | RFC 9000 type system: StreamId, ConnectionId, FrameType, TransportParams, OxiQuicError, ConnectionStats |
| `oxiquic-crypto` | Pure-Rust QUIC crypto provider for rustls: AEAD, header protection, Initial key derivation (no ring/aws-lc-rs) |
| `oxiquic-transport` | In-house QUIC stack: ClientEndpoint, ServerEndpoint, QuicConnection, streams, loss/cc/flow-control |
| `oxiquic-h3` | HTTP/3 client and server (H3Client, H3Server, H3ClientBuilder, H3ServerBuilder, H3RequestContext) |
| `oxiquic` | Facade: unified re-exports with feature flags `transport`, `h3`, `dangerous` |

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
oxiquic = "0.1"
```

### QUIC client

```rust
use oxiquic::prelude::*;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "93.184.216.34:443".parse()?;
    let conn = oxiquic::connect(addr, "example.com").await?;
    // open a bidirectional stream
    let (stream_id, mut send, mut recv) = conn.open_bidi().await?;
    // ... write/read via AsyncWrite / AsyncRead
    Ok(())
}
```

### HTTP/3 client

```rust
use oxiquic::h3_prelude::*;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "93.184.216.34:443".parse()?;
    let mut client = H3ClientBuilder::new()
        .with_server_name("example.com")
        .connect(addr)
        .await?;
    let response = client.get("https://example.com/").await?;
    println!("{}", response.status());
    Ok(())
}
```

## Feature Flags (`oxiquic` facade)

| feature     | default | enables |
|-------------|---------|---------|
| `transport` | yes     | QUIC transport (ClientEndpoint, ServerEndpoint, QuicConnection, TransportConfig) |
| `h3`        | no      | HTTP/3 client and server (H3Client, H3Server, H3ClientBuilder, H3ServerBuilder) |
| `dangerous` | no      | `connect_insecure()` for dev/testing (skips certificate verification) |

## Transport Configuration

```rust
use oxiquic::TransportConfig;
use oxiquic::CongestionAlgorithm;
use std::time::Duration;

let config = TransportConfig::builder()
    .idle_timeout(Duration::from_secs(30))
    .keep_alive_interval(Duration::from_secs(10))
    .max_concurrent_bidi_streams(100)
    .max_concurrent_uni_streams(100)
    .with_congestion_controller(CongestionAlgorithm::Bbr)
    .build()?;
```

## FFI Audit

The workspace enforces zero C/C++/Fortran in normal dependency edges:

```bash
bash scripts/ffi-audit.sh
```

Must print `FFI audit PASSED`. The `deny.toml` bans ring, aws-lc-rs, aws-lc-sys,
openssl, and openssl-sys tree-wide.

## Milestones

| Milestone | Status | Description |
|-----------|--------|-------------|
| M0 | COMPLETE | Workspace skeleton, FFI audit gate, deny.toml |
| M1 | COMPLETE | QUIC 1-RTT client + Pure-Rust TLS handshake |
| M2 | COMPLETE | QUIC server, stream multiplexing, loss detection, Cubic + BBR v2, flow control |
| M3 | COMPLETE | HTTP/3 client via h3 over in-house QUIC streams |
| M4 | COMPLETE | HTTP/3 server, H3ServerBuilder, H3Responder, graceful shutdown |
| M5 | COMPLETE | 0-RTT, stateless retry, version negotiation, key update, connection migration, MTU discovery, keep-alive, connection statistics |

## Implementation Status (2026-06-04)

**Implemented:**
- QUIC 1-RTT handshake over Pure-Rust TLS 1.3 (oxiquic-crypto provider)
- QUIC 0-RTT early data: `connect_0rtt()` API with early data acceptance flag
- Stateless retry: HMAC-SHA256 token generation/validation (RFC 9000 §8.1)
- Version negotiation: server sends VN packet, client handles gracefully
- Key update: RFC 9001 §6 key phase bit, per-epoch derivation, cooldown
- Connection migration: PATH_CHALLENGE/PATH_RESPONSE, candidate address promotion
- Multi-connection server demux (DCID-based routing)
- RFC 9002 loss detection and recovery (PTO + ACK-based)
- Cubic congestion control (RFC 9438)
- BBR v2 congestion control (bandwidth estimation, pacing, ProbeRTT, ProbeBW)
- Connection + stream flow control (MAX_DATA, MAX_STREAM_DATA, STREAMS_BLOCKED)
- MTU discovery: DPLPMTUD (RFC 8899) binary-search probe
- AsyncWrite/AsyncRead stream handles (BiStream, UniSendStream, UniRecvStream)
- HTTP/3 client and server via `h3` crate
- ALPN enforcement at HTTP/3 layer (`h3`)
- Streaming request/response bodies over HTTP/3 DATA frames
- GOAWAY graceful shutdown
- Connection statistics (RTT, bytes/packets sent/recv/lost, congestion window)

**Deferred:**
- 0-RTT user-facing session resumption API (handshake works; session-ticket reuse across process restarts deferred)
- RESET_STREAM/STOP_SENDING end-to-end user API (framing complete; user-facing stubs remain)
- H3 server push (upstream-limited: h3 0.0.8 has no push API)
- Multipath QUIC
- HTTP/3 throughput benchmark vs HTTP/2 (latency comparison done; sustained-load deferred)

## License

Apache-2.0 — Copyright COOLJAPAN OU (Team Kitasan)
