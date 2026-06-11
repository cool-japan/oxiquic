# oxiquic-core — Core types for the OxiQUIC Pure-Rust QUIC stack

[![Crates.io](https://img.shields.io/crates/v/oxiquic-core.svg)](https://crates.io/crates/oxiquic-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxiquic-core` is the dependency-free foundation of the COOLJAPAN Pure-Rust QUIC
implementation. It provides the RFC 9000 type system — stream and connection
identifiers, frame and packet classification, transport parameters, version and
error codes, and connection statistics — without pulling in any transport,
async runtime or cryptography dependency.

Within OxiQUIC, `oxiquic-core` is the shared vocabulary layer:
`oxiquic-crypto` adds QUIC packet protection and TLS keys, `oxiquic-transport`
implements the connection/stream state machine on top of these types, and
`oxiquic-h3` carries them up into HTTP/3. Every value here is a self-contained
data type that can be constructed, inspected and validated without a network,
which makes the crate trivial to test and reuse. It is `#![forbid(unsafe_code)]`
and 100% Pure Rust (no `ring`, `aws-lc-rs`, or any C/C++ dependency).

## Installation

```toml
[dependencies]
oxiquic-core = "0.1.1"
```

### Optional features

```toml
# Derive serde Serialize/Deserialize on the public types
oxiquic-core = { version = "0.1.1", features = ["serde"] }

# Enable the From<oxitls_core::TlsError> conversion bridge into OxiQuicError
oxiquic-core = { version = "0.1.1", features = ["oxitls"] }
```

## Quick Start

```rust
use oxiquic_core::{Direction, Initiator, StreamId};

// The first client-initiated bidirectional stream is StreamId(0)
// per RFC 9000 Table 1.
let id = StreamId::new(Initiator::Client, Direction::Bidirectional, 0);
assert_eq!(id, StreamId(0));
assert_eq!(id.initiator(), Initiator::Client);
assert_eq!(id.direction(), Direction::Bidirectional);
assert_eq!(id.index(), 0);
```

### Classifying packets and frames off the wire

```rust
use oxiquic_core::{FrameType, PacketType, QuicVersion};

// Long-header Initial packet, QUIC v1.
let pkt = PacketType::from_first_byte_and_version(0xc0, QuicVersion::V1_VALUE);
assert_eq!(pkt, PacketType::Initial);
assert!(pkt.is_long_header());

// 0x08–0x0f all decode to STREAM; the canonical type value is 0x08.
let frame = FrameType::from_varint(0x0c)?;
assert_eq!(frame, FrameType::Stream);
assert_eq!(frame.type_value(), 0x08);
assert!(frame.is_ack_eliciting());
# Ok::<(), oxiquic_core::OxiQuicError>(())
```

## API Overview

### `StreamId` and stream classification

A QUIC stream identifier (RFC 9000 Section 2.1). The 62-bit value encodes the
initiator (bit `0x1`), direction (bit `0x2`) and the stream index (`>> 2`).

| Item | Description |
|------|-------------|
| `StreamId(pub u64)` | Newtype over the raw 62-bit stream-ID value |
| `StreamId::MAX_INDEX` | Largest legal stream index, `2^60 - 1` |
| `StreamId::new(initiator, direction, index)` | Compose an ID; `index` masked to 60 bits |
| `id.as_u64()` | The raw 62-bit value |
| `id.initiator()` | `Initiator` from bit `0x1` |
| `id.direction()` | `Direction` from bit `0x2` |
| `id.index()` | Index within the `(initiator, direction)` class |
| `Initiator` | `Client` (bit `0`) / `Server` (bit `1`) |
| `Direction` | `Bidirectional` (bit `0`) / `Unidirectional` (bit `1`) |

`StreamId` implements `Display`, `Ord`, `From<u64>` and `Into<u64>`. `Initiator`
and `Direction` implement `Display`.

### `ConnectionId`

A variable-length (0–20 byte) opaque routing label (RFC 9000 Section 5.1). The
inner bytes use a `SmallVec<[u8; 20]>` so the full legal size range never heap-allocates.

| Item | Description |
|------|-------------|
| `MAX_CONNECTION_ID_LEN` | Constant `20` — maximum length in a long header |
| `ConnectionId::new(bytes)` | Construct without validating length |
| `ConnectionId::try_new(bytes)` | Construct, rejecting inputs longer than 20 bytes |
| `cid.len()` / `cid.is_empty()` | Length in bytes / zero-length check |
| `cid.as_bytes()` | Borrow the raw bytes |
| `cid.validate()` | Verify length ≤ 20, else `OxiQuicError::Protocol` |

Implements `Display` (lowercase hex), `Debug`, `Default`, `AsRef<[u8]>`,
`From<Vec<u8>>` and `From<&[u8]>`.

### `FrameType` — RFC 9000 Section 19 frames

Classifies all 21 frame families. Type-value ranges (e.g. `ACK` `0x02`–`0x03`,
`STREAM` `0x08`–`0x0f`) collapse to a single variant.

| Method | Description |
|--------|-------------|
| `FrameType::from_varint(value)` | Decode from a varint type value (range-aware); `OxiQuicError::FrameEncoding` on unknown |
| `frame.type_value()` | Canonical (lowest) varint type value |
| `frame.is_ack_eliciting()` | True for all frames except `ACK`, `PADDING`, `CONNECTION_CLOSE` |
| `frame.is_probing()` | True for `PATH_CHALLENGE`, `PATH_RESPONSE`, `NEW_CONNECTION_ID`, `PADDING` |
| `frame.name()` | Uppercase RFC name, e.g. `"RESET_STREAM"` |

Variants: `Padding`, `Ping`, `Ack`, `ResetStream`, `StopSending`, `Crypto`,
`NewToken`, `Stream`, `MaxData`, `MaxStreamData`, `MaxStreams`, `DataBlocked`,
`StreamDataBlocked`, `StreamsBlocked`, `NewConnectionId`, `RetireConnectionId`,
`PathChallenge`, `PathResponse`, `ConnectionClose`, `HandshakeDone`, `Datagram`
(RFC 9221). The enum is `#[non_exhaustive]` and implements `Display`.

### `PacketType` — RFC 9000 Section 17 packets

| Method | Description |
|--------|-------------|
| `PacketType::from_first_byte(b)` | Classify from the first byte (cannot detect Version Negotiation) |
| `PacketType::from_first_byte_and_version(b, version)` | Classify with the long-header `Version` field; `version == 0` ⇒ `VersionNegotiation` |
| `pkt.is_long_header()` | True for everything except `Short` |

Variants: `Initial`, `ZeroRtt`, `Handshake`, `Retry`, `VersionNegotiation`,
`Short`. `#[non_exhaustive]`, implements `Display`.

### `QuicVersion` — RFC 9000 / RFC 9369

| Item | Description |
|------|-------------|
| `QuicVersion::V1_VALUE` | `0x0000_0001` (RFC 9000) |
| `QuicVersion::V2_VALUE` | `0x6b33_43cf` (RFC 9369) |
| `QuicVersion::NEGOTIATION_VALUE` | `0x0000_0000` |
| `QuicVersion::from_u32(v)` | Decode from the 32-bit wire value |
| `version.to_u32()` | The 32-bit wire value |
| `version.is_supported()` | True for `V1` and `V2` |
| `version.is_negotiation()` | True for the reserved Version Negotiation value |

Variants: `V1`, `V2`, `Negotiation`, `Unknown(u32)`. `#[non_exhaustive]`,
implements `Display`, `From<u32>`, `Into<u32>`.

### `TransportErrorCode` — RFC 9000 Section 20.1

The transport error codes carried in a `CONNECTION_CLOSE` (type `0x1c`) frame.

| Method | Description |
|--------|-------------|
| `TransportErrorCode::from_u64(v)` | Decode from the 62-bit wire value |
| `code.to_u64()` | The 62-bit wire value |
| `code.name()` | Uppercase RFC name, e.g. `"FLOW_CONTROL_ERROR"` |

Variants: `NoError`, `InternalError`, `ConnectionRefused`, `FlowControlError`,
`StreamLimitError`, `StreamStateError`, `FinalSizeError`, `FrameEncodingError`,
`TransportParameterError`, `ConnectionIdLimitError`, `ProtocolViolation`,
`InvalidToken`, `ApplicationError`, `CryptoBufferExceeded`, `KeyUpdateError`,
`AeadLimitReached`, `NoViablePath`, `CryptoError(u8)` (TLS alert range
`0x0100`–`0x01ff`), `Unknown(u64)`. `#[non_exhaustive]`, implements `Display`
and `From<TransportErrorCode> for OxiQuicError`.

### `TransportParams` — RFC 9000 Section 18.2

The set of transport parameters an endpoint advertises during the handshake.
`TransportParams::default()` yields the RFC-specified protocol defaults.

| Field | Meaning |
|-------|---------|
| `max_idle_timeout_ms` | Idle timeout in ms; `0` disables |
| `max_udp_payload_size` | Largest UDP payload the endpoint will receive |
| `initial_max_data` | Connection-level flow-control limit |
| `initial_max_stream_data_bidi_local` | Limit for bidi streams this endpoint opens |
| `initial_max_stream_data_bidi_remote` | Limit for bidi streams the peer opens |
| `initial_max_stream_data_uni` | Limit for uni streams the peer opens |
| `initial_max_streams_bidi` | Bidi streams the peer may open |
| `initial_max_streams_uni` | Uni streams the peer may open |
| `ack_delay_exponent` | Scale factor for `ACK` delay fields (default 3) |
| `max_ack_delay_ms` | Max delay before sending an ACK (default 25) |
| `active_connection_id_limit` | Connection IDs the endpoint stores (default/min 2) |
| `disable_active_migration` | Disable migration to a new path |
| `max_datagram_frame_size` | RFC 9221 DATAGRAM payload cap; `0` disables the extension |

`params.validate()` enforces the Section 18.2 constraints (returns
`OxiQuicError::TransportError` with a `TRANSPORT_PARAMETER_ERROR` code).

Associated constants: `DEFAULT_MAX_UDP_PAYLOAD_SIZE` (65527),
`MIN_MAX_UDP_PAYLOAD_SIZE` (1200), `DEFAULT_ACK_DELAY_EXPONENT` (3),
`MAX_ACK_DELAY_EXPONENT` (20), `DEFAULT_MAX_ACK_DELAY_MS` (25),
`MAX_ACK_DELAY_MS_LIMIT` (`1 << 14`), `DEFAULT_ACTIVE_CONNECTION_ID_LIMIT` (2),
`MIN_ACTIVE_CONNECTION_ID_LIMIT` (2).

### `ConnectionStats` — RFC 9002 metrics snapshot

A `Default`-able snapshot of per-connection metrics tracked for loss detection,
congestion control and diagnostics.

| Field | Meaning |
|-------|---------|
| `rtt`, `min_rtt`, `smoothed_rtt`, `rtt_variance` | RTT samples (`Duration`) |
| `bytes_sent`, `bytes_recv` | Application+protocol byte counters |
| `packets_sent`, `packets_recv`, `packets_lost` | Packet counters |
| `congestion_window` | Current congestion window in bytes |
| `streams_opened`, `streams_closed` | Lifetime stream counters |

| Method | Description |
|--------|-------------|
| `stats.loss_rate()` | `packets_lost / packets_sent` (0.0 when none sent) |
| `stats.streams_active()` | `streams_opened - streams_closed` (saturating) |
| `stats.goodput_bytes()` | Bytes received minus ~50 B/packet framing overhead |

Implements `Display` (compact one-line summary), `Clone`, `Default`, `PartialEq`.

### `OxiQuicError` — unified error type

See the error-variants table below.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `serde` | off | Derive `Serialize`/`Deserialize` on the public types (also enables `smallvec/serde`) |
| `oxitls` | off | Enable `From<oxitls_core::TlsError> for OxiQuicError`; pulls in `oxitls-core` |

## `OxiQuicError` variants

`#[non_exhaustive]`, derives `thiserror::Error`.

| Variant | Description |
|---------|-------------|
| `Io(std::io::Error)` | Underlying I/O failure (UDP socket, etc.); has `#[from]` |
| `Tls(String)` | TLS configuration or handshake failure |
| `QuicCrypto(String)` | QUIC packet-protection / crypto failure |
| `Connection(String)` | Generic connection-level failure |
| `Stream(String)` | Generic stream-level failure |
| `TransportError { code, frame_type, reason }` | RFC 9000 §20.1 transport error |
| `FrameEncoding(String)` | A frame could not be encoded/decoded |
| `FlowControl(String)` | A flow-control limit was violated |
| `Protocol(String)` | A protocol rule was violated |
| `Timeout` | A handshake or generic operation timed out |
| `IdleTimeout` | The connection idle timer expired (RFC 9000 §10.1) |
| `VersionNegotiation { supported }` | Version negotiation failed; lists peer-advertised versions |
| `StatelessReset` | The peer sent a stateless reset (RFC 9000 §10.3) |
| `ApplicationClose { code, reason }` | Closed by the application layer |
| `NotImplemented(String)` | A feature is not implemented in this build |

Helper predicates: `err.is_timeout()` (`Timeout` / `IdleTimeout`), `err.is_closed()`
(`ApplicationClose` / `TransportError` / `IdleTimeout` / `StatelessReset`),
`err.is_reset()` (`StatelessReset`). With the `oxitls` feature, `From<oxitls_core::TlsError>`
is also implemented.

## Cross-references

- [`oxiquic`](../oxiquic) — the top-level facade crate
- [`oxiquic-crypto`](../oxiquic-crypto) — QUIC packet protection and the rustls Pure-Rust `CryptoProvider`
- [`oxiquic-transport`](../oxiquic-transport) — connection/stream state machine over `tokio` UDP
- [`oxiquic-h3`](../oxiquic-h3) — HTTP/3 client and server

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
