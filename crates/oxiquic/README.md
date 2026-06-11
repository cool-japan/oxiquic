# OxiQUIC

OxiQUIC is the COOLJAPAN Pure-Rust QUIC transport and HTTP/3 stack.
It implements RFC 9000/9001/9002 directly on the `rustls::quic` TLS 1.3 API
driven by the `oxiquic-crypto` Pure-Rust crypto provider over `tokio` UDP —
with **no dependency on ring, aws-lc-rs, or any C/C++ cryptographic libraries**.

## Feature Flags

| feature     | default | enables |
|-------------|---------|---------|
| `transport` | yes     | QUIC transport (`ClientEndpoint`, `ServerEndpoint`, `QuicConnection`, `TransportConfig`) |
| `h3`        | no      | HTTP/3 client and server (`H3Client`, `H3Server`, `H3ClientBuilder`, `H3ServerBuilder`) |
| `dangerous` | no      | `connect_insecure()` for dev/testing (skips certificate verification) |

## Quick Start

```toml
[dependencies]
oxiquic = { version = "0.1.1", features = ["transport"] }
```

```rust
use oxiquic::QuicVersion;

assert_eq!(oxiquic::quic_version(), QuicVersion::V1);
```

## Pure-Rust Status

`cargo tree --edges normal` contains zero C crypto crates.
The `deny.toml` at the workspace root bans `ring`, `aws-lc-rs`, `aws-lc-sys`,
`openssl`, and `openssl-sys` tree-wide.

See the [workspace README](../../README.md) for full documentation.
