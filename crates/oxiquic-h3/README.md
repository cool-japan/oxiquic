# oxiquic-h3 — HTTP/3 (RFC 9114) client and server for the OxiQUIC stack

[![Crates.io](https://img.shields.io/crates/v/oxiquic-h3.svg)](https://crates.io/crates/oxiquic-h3)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxiquic-h3` is the HTTP/3 layer of the COOLJAPAN Pure-Rust QUIC stack
(RFC 9114 / RFC 9204). It provides an ergonomic request/response client and
server on top of `oxiquic-transport`'s `DrivenConnection`, plus the HTTP/3
message model and error taxonomy. With the default `h3-compat` feature it bridges
to the [`h3`] crate's QUIC abstraction, so the battle-tested `h3` framing/QPACK
engine runs over OxiQUIC's Pure-Rust QUIC transport — no `ring` / `aws-lc-rs`.

Within OxiQUIC: `oxiquic-core` supplies the shared types, `oxiquic-crypto`
provides QUIC-enabled TLS keys, `oxiquic-transport` runs the connection/stream
state machine over `tokio` UDP, and `oxiquic-h3` carries HTTP semantics on top.
The crate is `#![forbid(unsafe_code)]`.

[`h3`]: https://crates.io/crates/h3

## Installation

```toml
[dependencies]
# h3-compat is on by default and enables the client/server.
oxiquic-h3 = "0.1.1"
```

### Optional features

```toml
oxiquic-h3 = { version = "0.1.1", features = [
    "serde",    # H3Response::body_json / typed JSON request helpers
    "tracing",  # tracing spans around requests
] }
```

## Quick Start

The high-level `H3ClientBuilder` performs the UDP bind, QUIC handshake, ALPN
enforcement (`h3`) and the HTTP/3 SETTINGS exchange for you.

```rust,no_run
use oxiquic_h3::H3ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), oxiquic_h3::H3Error> {
    let addr = "127.0.0.1:4433".parse().expect("addr");

    let mut client = H3ClientBuilder::new()
        .with_server_name("localhost")
        .with_tls_config(my_rustls_client_config()) // built from quic_crypto_provider()
        .connect(addr)
        .await?;

    let resp = client.get("/").await?;
    println!("status {}", resp.status());
    println!("body {}", resp.body_text()?);

    client.close().await?;
    Ok(())
}
# fn my_rustls_client_config() -> rustls::ClientConfig { unimplemented!() }
```

### Server

```rust,no_run
use oxiquic_h3::{H3Response, H3ServerBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = H3ServerBuilder::new("127.0.0.1:4433".parse()?)
        .with_tls_config(my_rustls_server_config()) // built from quic_crypto_provider()
        .build()
        .await?;

    let mut conn = endpoint.accept_connection().await?;
    while let Some(ctx) = conn.accept().await? {
        let resp = H3Response::new(200)
            .with_header("content-type", "text/plain")
            .with_body("hello h3");
        ctx.respond(resp).await?;
    }
    Ok(())
}
# fn my_rustls_server_config() -> rustls::ServerConfig { unimplemented!() }
```

## API Overview

### HTTP/3 message model (`message` module)

| Item | Description |
|------|-------------|
| `H3Request::new(method, uri)` / `get(uri)` / `post(uri)` | Construct a request |
| `H3Request::with_header(name, value)` | Append a header (name lowercased per RFC 9114 §4.2) |
| `H3Request::method()` / `uri()` / `headers()` | Read accessors |
| `H3Response::new(status)` | Construct a response |
| `H3Response::with_header(..)` / `with_body(..)` | Builder setters |
| `H3Response::status()` / `headers()` / `header(name)` | Read accessors |
| `H3Response::body_bytes()` / `into_body()` / `body_text()` | Body accessors (UTF-8 decode is fallible) |
| `H3Response::content_length()` / `content_type()` | Common header parsers |
| `H3Response::is_success()` / `ok()` / `error_for_status()` | 2xx helpers |
| `H3Response::body_json::<T>()` | (feature `serde`) deserialize body as JSON |
| `H3Settings` | `max_field_section_size`, `qpack_max_table_capacity`, `qpack_blocked_streams` |
| `DEFAULT_MAX_FIELD_SECTION_SIZE` | Constant `16_384` (conservative cap) |

### High-level client (feature `h3-compat`)

| Item | Description |
|------|-------------|
| `H3ClientBuilder::new()` | Builder for `H3Client` |
| `.with_server_name(name)` | TLS server name (**required**) |
| `.with_tls_config(cfg)` | rustls `ClientConfig` (**required**); `h3` ALPN injected if absent |
| `.with_transport_config(cfg)` | Override the QUIC `TransportConfig` |
| `.with_max_field_section_size(n)` | RFC 9114 §4.2.2 setting |
| `.with_qpack_config(table, blocked)` | RFC 9204 §5 (stored; stateless QPACK in practice) |
| `.with_default_headers(headers)` | Headers prepended to every request |
| `.connect(addr)` | Bind, handshake, enforce ALPN, HTTP/3 SETTINGS → `H3Client` |
| `H3Client::new(driven)` / `new_with_config(..)` | Wrap an existing `DrivenConnection` |
| `H3Client::request(req, body)` | Send a request, collect the full `H3Response` |
| `H3Client::get` / `post` / `head` / `put` / `delete` | Convenience verbs |
| `H3Client::get_json` / `post_json` | (feature `serde`) typed JSON helpers |
| `H3Client::send_streaming(req)` | Open a streaming request → `RequestStream` |
| `H3Client::peer_settings()` | The peer's `H3Settings` |
| `H3Client::close()` | Graceful shutdown |
| `RequestStream` | `send_data`, `finish`, `recv_response`, `recv_data`, `recv_trailers`, `cancel` |

### High-level server (feature `h3-compat`)

| Item | Description |
|------|-------------|
| `H3ServerBuilder::new(addr)` | Builder for `H3ServerEndpoint` |
| `.with_tls_config(cfg)` / `.with_bind_address(addr)` / `.with_transport_config(cfg)` | Core setup |
| `.with_ticketer(..)` | Custom `ProducesTickets` for 0-RTT resumption |
| `.with_max_field_section_size(n)` / `.with_qpack_max_table_capacity(n)` / `.with_qpack_blocked_streams(n)` | HTTP/3 / QPACK settings |
| `.with_server_push(enabled)` | Toggle server push |
| `.build()` | Bind the UDP socket → `H3ServerEndpoint` |
| `H3ServerEndpoint::accept_connection()` | Await the next `H3Connection` |
| `H3ServerEndpoint::incoming()` | `H3Incoming<'_>` async iterator |
| `H3ServerEndpoint::local_addr()` / `server_push_enabled()` | Endpoint queries |
| `H3Connection` (`H3Server` alias) | `new`, `new_with_config`, `accept`, `peer_settings`, `shutdown(max_id)`, `close` |
| `H3RequestContext` | `request()`, `body()`, `respond(resp)`, `into_responder()` |
| `H3Responder` | `body_bytes`, `send_response`, `send_data`, `send_trailers`, `send_full`, `finish`, `push_promise` |
| `H3Incoming::next()` | Await the next incoming connection |

### Connection-pooling (feature `h3-compat`, `pool` module)

| Item | Description |
|------|-------------|
| `H3Pool::new(PoolConfig)` | Origin-keyed connection pool |
| `H3Pool::request(..)` / `get(origin, uri)` / `post(..)` | Pooled requests |
| `H3Pool::idle_count(origin)` / `evict(origin)` | Pool introspection / eviction |
| `OriginKey` | Pool key (scheme/host/port) |
| `PoolConfig` | Pool tuning |
| `TlsFactory` | `Arc<dyn Fn(&str) -> Result<rustls::ClientConfig, H3Error>>` per-origin TLS builder |

### Low-level `h3`-crate bridge (feature `h3-compat`)

For callers who want the raw `h3` connection objects rather than the
`H3Client` / `H3Server` wrappers:

| Item | Description |
|------|-------------|
| `connect_h3(driven)` | → `(h3::client::Connection, h3::client::SendRequest)` after the HTTP/3 handshake |
| `accept_h3(driven)` | → `h3::server::Connection` after the HTTP/3 handshake |
| `connect_h3_with(..)` / `accept_h3_with(..)` | As above, threading `max_field_section_size` |
| `connect_h3_client(driven)` / `accept_h3_server(driven)` | Convenience wrappers around `H3Client::new` / `H3Server::new` |
| `OxiQuicH3Connection`, `OxiQuicOpenStreams`, `H3BidiStream`, `H3SendStream`, `H3RecvStream` | The `h3::quic` adapter types (re-exported from `oxiquic-transport`) |
| `DrivenConnection` | Re-exported from `oxiquic-transport` so callers need not import it directly |

### Server push (feature `h3-compat`, `push` module)

| Item | Description |
|------|-------------|
| `H3PushStream` | A server-push stream: `push_id`, `send_response`, `send_data`, `finish` |
| `accept_push_stub(..)` | Client-side push acceptance (stub — see Status / Limitations) |

### Re-exports

`OxiQuicError` is re-exported from `oxiquic-core` at the crate root.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `h3-compat` | **on** | The HTTP/3 client/server and the `h3`-crate bridge; pulls in `h3`, `bytes`, `http`, `rustls`, `tokio`, and enables `oxiquic-transport/h3-compat` |
| `serde` | off | `H3Response::body_json` and typed JSON request/response helpers; pulls in `serde`, `serde_json` |
| `tracing` | off | `tracing` spans around request/response operations |

## `H3Error` variants

`#[non_exhaustive]`, derives `thiserror::Error`.

| Variant | HTTP/3 code (via `H3Error::code()`) |
|---------|--------------------------------------|
| `Protocol(String)` | `H3_GENERAL_PROTOCOL_ERROR` |
| `Qpack(String)` | `QPACK` error |
| `Stream(String)` | `H3_STREAM_CREATION_ERROR` |
| `Connection(String)` | `H3_INTERNAL_ERROR` |
| `FrameUnexpected(String)` | `H3_FRAME_UNEXPECTED` |
| `SettingsError(String)` | `H3_SETTINGS_ERROR` |
| `MissingSettings` | `H3_MISSING_SETTINGS` |
| `IdError(String)` | `H3_ID_ERROR` |
| `Tls(String)` | `H3_GENERAL_PROTOCOL_ERROR` |
| `Io(std::io::Error)` | `H3_INTERNAL_ERROR` (has `#[from]`) |

`From<H3Error> for oxiquic_core::OxiQuicError` is implemented, and `H3Error`
converts from `h3::error::ConnectionError` / `StreamError`.

`H3ErrorCode` is the full RFC 9114 §8.1 / RFC 9204 §8.3 code enum, with
`from_u64`, `to_u64`, `name`, `Display` and a `Qpack(u64)` / `Unknown(u64)`
catch-all. `#[non_exhaustive]`.

## Status / Limitations

The HTTP/3 framing, QPACK and stream handling are provided by the mature `h3`
crate running over OxiQUIC's Pure-Rust transport; the client and server
request/response paths are end-to-end functional over UDP loopback. Server push
support is early — `H3Responder::push_promise` issues a PUSH_PROMISE, but the
client-side `accept_push_stub` and parts of `H3PushStream::send_data` are stubs
pending a future milestone. QPACK uses the `h3` crate's stateless mode, so the
QPACK dynamic-table settings are stored for forward-compatibility but the table
is effectively disabled.

## Cross-references

- [`oxiquic`](../oxiquic) — the top-level facade crate
- [`oxiquic-core`](../oxiquic-core) — RFC 9000 core types
- [`oxiquic-crypto`](../oxiquic-crypto) — QUIC-enabled TLS `CryptoProvider`
- [`oxiquic-transport`](../oxiquic-transport) — the QUIC transport this layer runs on

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
