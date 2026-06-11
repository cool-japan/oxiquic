# oxiquic-transport — Pure-Rust QUIC transport (RFC 9000/9001/9002) over tokio UDP

[![Crates.io](https://img.shields.io/crates/v/oxiquic-transport.svg)](https://crates.io/crates/oxiquic-transport)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxiquic-transport` is a Pure-Rust QUIC (RFC 9000 / 9001 / 9002) implementation
built directly on the `rustls::quic` TLS 1.3 handshake API, driven by the
`oxiquic-crypto` `CryptoProvider` (no `ring`, no `aws-lc-rs`, no C/C++ crypto).
It runs over `tokio`'s asynchronous UDP sockets.

The crate is split into a synchronous, I/O-free protocol core (`Connection`) and
a thin asynchronous shell (`endpoint`) that pumps datagrams between the core and
a UDP socket. A caller drives a client with `ClientEndpoint::bind` then
`ClientEndpoint::connect`, a server with `ServerEndpoint::bind` then
`ServerEndpoint::accept`; both yield a `QuicConnection` for opening
bidirectional streams and reading/writing data. The crate is
`#![forbid(unsafe_code)]`.

## Installation

```toml
[dependencies]
oxiquic-transport = "0.1.1"
oxiquic-crypto    = "0.1.1"  # provides quic_crypto_provider()
rustls            = "0.23"
tokio             = { version = "1", features = ["full"] }
```

### Optional features

```toml
# h3 adapter types (implements the `h3` crate's quic traits over OxiQUIC)
oxiquic-transport = { version = "0.1.1", features = ["h3-compat"] }

# connect_insecure-style helpers for dev/testing
oxiquic-transport = { version = "0.1.1", features = ["dangerous"] }
```

## Quick Start

Echo round-trip over real UDP loopback. The rustls configs must be built from
`oxiquic_crypto::quic_crypto_provider()` so the suites are QUIC-enabled.

```rust,no_run
use std::sync::Arc;
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Self-signed Ed25519 cert for `localhost`, Pure-Rust crypto provider.
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])?;
    let cert = CertificateDer::from(ck.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots.add(cert.clone())?;
    let client_cfg = Arc::new(
        ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_cfg = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?,
    );

    let transport = TransportConfig::default();
    let loopback = "127.0.0.1:0".parse()?;

    // Server: accept one connection, echo one stream payload back.
    let server = ServerEndpoint::bind(loopback, server_cfg, transport.clone()).await?;
    let server_addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await?;
        let (id, bytes, _fin) = conn.accept_uni_or_bidi_data().await?;
        conn.send(id, &bytes, false).await?;
        for _ in 0..20 { conn.drive().await?; }
        Ok::<(), oxiquic_core::OxiQuicError>(())
    });

    // Client: connect, open a bidi stream, send, read the echo.
    let client = ClientEndpoint::bind(loopback, client_cfg, transport).await?;
    let mut conn = client.connect(server_addr, "localhost").await?;
    let s = conn.open_bidi()?;
    conn.send(s, b"hello quic", false).await?;
    let (echo, _fin) = conn.read(s).await?;
    assert_eq!(echo, b"hello quic");

    server_task.await??;
    Ok(())
}
```

## API Overview

### Endpoints

| Item | Description |
|------|-------------|
| `ClientEndpoint::bind(addr, ClientConfig, TransportConfig)` | Bind a client UDP socket |
| `ClientEndpoint::connect(addr, server_name)` | Connect, validate cert, drive handshake → `QuicConnection` |
| `ClientEndpoint::connect_timeout(addr, server_name, dur)` | `connect` wrapped in a deadline → `OxiQuicError::Timeout` on elapse |
| `ClientEndpoint::local_addr()` | Bound local address |
| `ServerEndpoint::bind(addr, ServerConfig, TransportConfig)` | Bind a server UDP socket with DCID demux |
| `ServerEndpoint::accept()` | Await the next established `QuicConnection` |
| `ServerEndpoint::incoming()` | `Incoming<'_>` async iterator (`.next().await`) over connections |
| `ServerEndpoint::local_addr()` | Bound local address |
| `ServerEndpointBuilder::new(...)` / `.with_ticketer(..)` / `.build()` | Bind with a custom `rustls::server::ProducesTickets` (e.g. for 0-RTT resumption) |
| `Incoming::next()` | Await the next accepted connection, `None` when the endpoint tears down |

### `QuicConnection` — the high-level connection handle

| Method | Description |
|--------|-------------|
| `open_bidi()` / `open_bidi_with_priority(prio)` | Open a bidirectional stream → `StreamId` |
| `open_bi_reliable(..)` | Open a bidirectional stream with explicit reliability handling |
| `send(stream, data, fin)` | Write bytes (and optional FIN) to a stream |
| `read(stream)` / `read_with_deadline(stream, deadline)` | Read `(Vec<u8>, fin)` from a stream |
| `accept_uni_or_bidi_data()` / `..._with_deadline(..)` | Await the next stream that has inbound data → `(StreamId, Vec<u8>, fin)` |
| `send_datagram(data)` / `recv_datagram()` | RFC 9221 unreliable datagrams |
| `max_datagram_size()` | Largest DATAGRAM payload the peer accepts |
| `initiate_key_update()` / `key_update_count()` | RFC 9001 §6 key update |
| `initiate_path_challenge()` / `path_validated()` | RFC 9000 §9 path migration |
| `current_mtu()` / `probe_mtu()` | DPLPMTUD path-MTU state (RFC 8899) |
| `negotiated_alpn()` | Negotiated ALPN protocol, if any |
| `peer_transport_params()` | Peer's advertised `TransportParams` |
| `retry_count()` / `take_received_token()` | RFC 9000 §8.1 Retry state |
| `zero_rtt_accepted()` | Whether 0-RTT early data was accepted |
| `role()` / `is_closed()` / `ping()` | Role, close state, latest RTT |
| `streams_opened()` / `streams_closed()` | Lifetime stream counters |
| `bytes_in_flight()` / `has_pending_stream_data()` | Congestion/queue state |
| `stats()` | `oxiquic_core::ConnectionStats` snapshot |
| `drive()` | Pump the socket I/O loop one iteration |
| `close(error_code, reason)` | Close the connection |
| `into_driven()` | Consume into a background-driven `DrivenConnection` |

### `DrivenConnection` — background-driven I/O with `AsyncRead`/`AsyncWrite` streams

Obtained from `QuicConnection::into_driven()`. Runs the socket loop in a
`tokio::task`; its stream handles expose `tokio::io::AsyncRead`/`AsyncWrite`.

| Method | Description |
|--------|-------------|
| `open_bidi()` / `open_bidi_with_priority(prio)` | Open a bidi stream → `BiStream` |
| `open_bidi_stream(..)` | Open a bidi stream with explicit options |
| `open_uni_stream()` | Open a uni send stream → `SendStreamHandle` |
| `accept_bidi_stream(..)` | Accept an inbound bidi stream |
| `accept_uni_stream()` | Accept an inbound uni stream → `RecvStreamHandle` |
| `negotiated_alpn()` | Negotiated ALPN bytes |
| `write_tx()` | Clone the internal write channel (`WriteTx`) |
| `close(error_code, reason)` | Close the connection |

### Stream handles (`handle` module)

| Item | Description |
|------|-------------|
| `BiStream` | Bidirectional stream: `write`, `read`, `finish`, `reset`, `stop_sending`, `stream_id` |
| `SendStreamHandle` | Send half: `reset(error_code)`; implements `AsyncWrite` |
| `RecvStreamHandle` | Recv half: `stop_sending(error_code)`, `stream_id`; implements `AsyncRead` |
| `UniSendStream` | Unidirectional send: `write`, `finish`, `reset`, `stream_id` |
| `UniRecvStream` | Unidirectional recv: `read`, `stop_sending`, `stream_id` |
| `WriteCmd` / `WriteTx` | Internal write-command enum and `mpsc::Sender` alias |

### `Connection` — synchronous, I/O-free protocol core (`connection` module)

The state machine `QuicConnection` and `DrivenConnection` wrap. Exposed for
advanced/embedding use.

| Item | Description |
|------|-------------|
| `Connection::new_client(..)` / `new_server(..)` | Construct a client/server protocol core |
| `Role` | `Client` / `Server` |
| `ConnectionState` | Handshake/established/closed lifecycle enum |
| `MtuConfig` | `{ max_mtu, discovery_enabled }` MTU configuration |
| `state()` / `is_handshaking()` / `is_established()` / `is_closed()` | Lifecycle queries |
| `local_cid()` / `peer_addr()` / `negotiated_alpn()` | Identity / path / ALPN |
| `peer_transport_params()` / `peer_close_reason()` | Peer parameters and close reason |
| `next_timeout()` / `handle_timeout(now)` | Drive the loss/idle/PTO timers |
| `stats()` / `congestion_window()` / `bytes_in_flight()` | Metrics |
| `current_mtu()` / `probe_mtu()` / `on_mtu_probe_acked(..)` / `on_mtu_probe_lost(..)` | DPLPMTUD callbacks |
| `send_datagram(..)` / `recv_datagram()` / `max_datagram_size()` | RFC 9221 datagrams |
| `set_keep_alive_interval(..)` / `close(..)` | Keep-alive and close |

### Congestion control

| Item | Description |
|------|-------------|
| `CongestionController` | Dispatch enum over CUBIC / NewReno / BBR; `from_config`, `congestion_window`, `bytes_in_flight`, `can_send`, `on_packet_sent`, `on_packets_acked`, `on_packets_lost`, `on_persistent_congestion` |
| `Bbr`, `BbrState` | BBR v2 model-based controller and its state machine |
| `DeliveryRateEstimator`, `RateSample` | BBR delivery-rate estimation |

### `TransportConfig` and `CongestionAlgorithm` (`config` module)

Builder-style connection tuning. `CongestionAlgorithm` is `Cubic` (default),
`Bbr`, or `NewReno`. Defaults: 30 s idle timeout, 100 concurrent bidi/uni
streams, 1 MiB stream / 8 MiB connection windows, 1200-byte initial MTU, MTU
discovery on, CUBIC, Retry off.

Builders include `idle_timeout`, `keep_alive_interval`,
`max_concurrent_bidi_streams`, `max_concurrent_uni_streams`,
`stream_receive_window`, `receive_window`, `send_window`, `initial_mtu`,
`min_mtu`, `max_mtu`, `mtu_discovery`, `congestion_controller`, `retry`,
`retry_secret`, `server_secret`, `active_connection_id_limit`,
`max_datagram_frame_size`, `datagram_receive_buffer_size`, `max_early_data_size`,
plus matching `get_*` accessors. Service methods:
`generate_retry_token`/`validate_retry_token`, `to_transport_params`, and
`validate`. Constant: `TransportConfig::MIN_INITIAL_MTU` (1200).

### Re-exported `oxiquic-core` types

`ConnectionStats`, `OxiQuicError`, `StreamId`, `TransportParams` are re-exported
at the crate root for convenience.

### Wire codecs (`coding` and `packet` modules)

Lower-level helpers for QUIC framing. `coding` exposes the varint codec (`Buf`,
`put_varint`, `varint_size`, `VARINT_MAX`, `CodecError`) and packet-number
coding (`packet_number_len`, `encode_packet_number`, `decode_packet_number`).
`packet` exposes long/short packet build & parse, header-protection stripping,
and — re-exported at the crate root — the Version Negotiation and Retry helpers:

| Item | Description |
|------|-------------|
| `encode_version_negotiation` / `decode_version_negotiation` | VN packet codec (RFC 9000 §17.2.1) |
| `encode_retry_packet` / `parse_retry_packet` | Retry packet codec (RFC 9000 §17.2.5) |
| `compute_retry_integrity_tag` / `verify_retry_integrity_tag` | Retry integrity tag (RFC 9001 §5.8) |

### h3 adapter (feature `h3-compat`)

Implements the [`h3`] crate's QUIC abstraction over OxiQUIC, re-exported from
`oxiquic-h3`: `OxiQuicH3Connection`, `OxiQuicOpenStreams`, `H3BidiStream`,
`H3SendStream`, `H3RecvStream`.

[`h3`]: https://crates.io/crates/h3

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `dangerous` | off | Dev/testing helpers that relax security checks |
| `h3-compat` | off | h3-crate QUIC adapter types; pulls in `h3` and `bytes` |

## Implementation Status

Implemented and proven over real UDP loopback:

- **Initial + Handshake** — long-header coding, header/packet protection,
  coalesced-packet parsing, CRYPTO-frame reassembly driving the rustls TLS 1.3
  handshake, ACKs and per-space packet numbers.
- **1-RTT + close** — 1-RTT keys on `KeyChange::OneRtt`, short-header packets,
  `HANDSHAKE_DONE`, `CONNECTION_CLOSE`, idle handling.
- **Stream data** — bidirectional stream state machines with ordered reassembly
  and a send/receive API.
- **Loss detection & recovery** (RFC 9002 §5–6) — per-space sent-packet
  tracking, RTT estimation, packet-number and time-threshold loss detection, PTO
  with exponential backoff, CRYPTO/STREAM retransmission.
- **Congestion control** — CUBIC (RFC 9438, default), NewReno (RFC 9002 App. B)
  and BBR v2, selected via `TransportConfig::congestion_controller`.
- **Flow control** (RFC 9000 §4) — connection- and stream-level limits,
  `MAX_DATA` / `MAX_STREAM_DATA`, `DATA_BLOCKED` / `STREAM_DATA_BLOCKED`.
- **Version Negotiation** (RFC 9000 §17.2.1).
- **Retry** (RFC 9000 §17.2.5, RFC 9001 §5.8) — opt-in via `TransportConfig::retry`.
- **Connection path migration** (RFC 9000 §9) — `PATH_CHALLENGE` / `PATH_RESPONSE`
  and the `initiate_path_challenge()` / `path_validated()` API.
- **Key update** (RFC 9001 §6).
- **DPLPMTUD / path-MTU discovery** (RFC 8899) — enabled by default.

Not yet implemented: 0-RTT (end-to-end), stateless reset, ECN, `MAX_STREAMS`.
For `RESET_STREAM` / `STOP_SENDING` the frame encode/decode is plumbed but the
end-to-end user-facing API stubs remain. Path migration defers anti-amplification
limits, `NEW_CONNECTION_ID` issuance for migration, `PATH_CHALLENGE` PTO
retransmission, and per-path congestion state to a future milestone.

## Cross-references

- [`oxiquic`](../oxiquic) — the top-level facade crate
- [`oxiquic-core`](../oxiquic-core) — RFC 9000 core types
- [`oxiquic-crypto`](../oxiquic-crypto) — the QUIC-enabled `CryptoProvider` this crate consumes
- [`oxiquic-h3`](../oxiquic-h3) — HTTP/3 client and server over this transport

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
