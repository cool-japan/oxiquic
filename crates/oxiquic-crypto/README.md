# oxiquic-crypto — Pure-Rust rustls ↔ OxiCrypto bridge with QUIC packet protection

[![Crates.io](https://img.shields.io/crates/v/oxiquic-crypto.svg)](https://crates.io/crates/oxiquic-crypto)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxiquic-crypto` implements the [`rustls`] crypto-provider traits over
[`oxicrypto`] (and the RustCrypto primitives OxiCrypto wraps), adds QUIC
packet/header protection per RFC 9001 §5, and assembles a `CryptoProvider`
whose TLS 1.3 cipher suites are **QUIC-enabled** (`quic: Some(..)`). This is the
crypto layer that drives the TLS 1.3 handshake and packet-key derivation for
`oxiquic-transport`.

The COOLJAPAN Pure-Rust policy forbids `ring`, `aws-lc-rs` and `openssl`;
nothing in this crate pulls them in. The provider reuses
`rustls_rustcrypto::provider()`'s key-exchange groups, signature-verification
algorithms, secure random source and key provider, replacing only the cipher
suites with the three QUIC-capable suites so a `rustls::quic::ClientConnection`
or `ServerConnection` built from it can complete a handshake and derive packet
keys. The crate is `#![forbid(unsafe_code)]`.

[`rustls`]: https://docs.rs/rustls
[`oxicrypto`]: https://crates.io/crates/oxicrypto

## What it provides

| rustls trait | Implemented for | Module |
|--------------|-----------------|--------|
| `crypto::hash::Hash` | SHA-256, SHA-384 | `hash` |
| `crypto::hmac::Hmac` | HMAC-SHA-256/384 | `hmac` |
| `crypto::tls13::Hkdf` | SHA-256/384 (via `HkdfUsingHmac`) | `hkdf` |
| `crypto::cipher::Tls13AeadAlgorithm` | AES-128/256-GCM, ChaCha20-Poly1305 | `aead` |
| `quic::Algorithm` + `PacketKey` + `HeaderProtectionKey` | all three suites | `quic` |

## Installation

```toml
[dependencies]
oxiquic-crypto = "0.1.1"
```

### Optional features

```toml
# Expose oxitls_quic_provider(), an alternative provider sourced from oxitls
oxiquic-crypto = { version = "0.1.1", features = ["oxitls-provider"] }
```

## Quick Start

Build a QUIC-enabled `CryptoProvider` and use it for a rustls config:

```rust
let provider = oxiquic_crypto::quic_crypto_provider();
assert_eq!(provider.cipher_suites.len(), 3);
```

### Deriving QUIC Initial keys (RFC 9001 §5.2)

`rustls::quic::Keys::initial` derives Initial keys entirely through the suite's
`hkdf_provider` and the `quic::Algorithm` — both of which are this crate's
implementations. There is no independent `ring` / `aws-lc-rs` derivation path:

```rust,no_run
use oxiquic_crypto::suites::tls13_aes_128_gcm_sha256_internal;
use oxiquic_crypto::quic::AES128_GCM;
use rustls::quic::{Keys, Version};
use rustls::Side;

let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
let keys = Keys::initial(
    Version::V1,
    tls13_aes_128_gcm_sha256_internal(),
    &AES128_GCM,
    &dcid,
    Side::Client,
);
# let _ = keys;
```

## API Overview

### Crate-level entry points

| Item | Description |
|------|-------------|
| `quic_crypto_provider() -> CryptoProvider` | A `CryptoProvider` with the three QUIC-enabled suites; reuses rustls-rustcrypto's kx/sig/rng/key provider |
| `all_quic_cipher_suites() -> Vec<SupportedCipherSuite>` | The three QUIC-enabled suites as an owned `Vec` (clone of `suites::ALL_QUIC_SUITES`) |
| `oxitls_quic_provider() -> Arc<CryptoProvider>` | (feature `oxitls-provider`) the Pure-Rust provider from the oxitls facade — see Status / Limitations |

### `suites` module — QUIC-enabled TLS 1.3 cipher suites

Each suite is a `rustls::Tls13CipherSuite` literal built from this crate's
`hash`, `hkdf`, `aead` and `quic` providers, with `quic: Some(..)`.

| Item | Description |
|------|-------------|
| `TLS_AES_128_GCM_SHA256` | `SupportedCipherSuite`, QUIC-enabled (the Initial-keys suite) |
| `TLS_AES_256_GCM_SHA384` | `SupportedCipherSuite`, QUIC-enabled |
| `TLS_CHACHA20_POLY1305_SHA256` | `SupportedCipherSuite`, QUIC-enabled |
| `ALL_QUIC_SUITES` | `&[SupportedCipherSuite]` of all three, in preference order |
| `tls13_aes_128_gcm_sha256_internal() -> &'static Tls13CipherSuite` | The inner suite to pass to `rustls::quic::Keys::initial` |

### `quic` module — QUIC packet-key algorithms (RFC 9001 §5)

| Item | Description |
|------|-------------|
| `QuicAlgorithm` | Implements `rustls::quic::Algorithm`; holds AEAD kind, header-protection primitive and key length |
| `AES128_GCM` | `QuicAlgorithm` static for `TLS_AES_128_GCM_SHA256` (16-byte key) |
| `AES256_GCM` | `QuicAlgorithm` static for `TLS_AES_256_GCM_SHA384` (32-byte key) |
| `CHACHA20_POLY1305` | `QuicAlgorithm` static for `TLS_CHACHA20_POLY1305_SHA256` (32-byte key) |

Internally these produce `PacketKey` / `HeaderProtectionKey` implementations and
enforce the RFC 9001 §6.6 AEAD integrity limits (`2^52` for AES-GCM, `2^36` for
ChaCha20-Poly1305).

### `hash` module — `rustls::crypto::hash::Hash`

| Item | Description |
|------|-------------|
| `Sha256Hash`, `Sha384Hash` | Unit structs implementing `Hash` |
| `SHA256`, `SHA384` | `&dyn Hash` statics |

### `hmac` module — `rustls::crypto::hmac::Hmac`

| Item | Description |
|------|-------------|
| `HmacSha256Provider`, `HmacSha384Provider` | Unit structs implementing `Hmac` |
| `HMAC_SHA256`, `HMAC_SHA384` | `&dyn Hmac` statics |

### `hkdf` module — `rustls::crypto::tls13::Hkdf`

| Item | Description |
|------|-------------|
| `HKDF_SHA256`, `HKDF_SHA384` | `HkdfUsingHmac<'static>` statics over the HMAC providers |
| `hkdf_sha256() -> &'static dyn Hkdf` | Borrow the SHA-256 HKDF as a trait object |
| `hkdf_sha384() -> &'static dyn Hkdf` | Borrow the SHA-384 HKDF as a trait object |

### `aead` module — `rustls::crypto::cipher::Tls13AeadAlgorithm`

| Item | Description |
|------|-------------|
| `Tls13Aes128Gcm` | AES-128-GCM TLS 1.3 record protection |
| `Tls13Aes256Gcm` | AES-256-GCM TLS 1.3 record protection |
| `Tls13ChaCha20Poly1305` | ChaCha20-Poly1305 TLS 1.3 record protection |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `oxitls-provider` | off | Exposes `oxitls_quic_provider()`, sourced from `oxitls::quic_preview::pure_quic_provider()`. Pulls in `oxitls`. |

## Status / Limitations

`quic_crypto_provider()` is the production entry point: its suites carry
`quic: Some(..)` wired to this crate's AEAD/HKDF implementations and are suitable
for deriving QUIC packet/header-protection keys.

The feature-gated `oxitls_quic_provider()` returns the provider from the oxitls
facade — essentially `rustls_rustcrypto::provider()` wrapped in an `Arc`. Its
cipher suites have `quic: None` and are **not** suitable for QUIC packet-key
derivation; it exists as an additive hook for callers that want a unified
"Pure-Rust `CryptoProvider` from oxitls" without importing `oxitls` directly.
For actual QUIC connections, use `quic_crypto_provider()`.

## Cross-references

- [`oxiquic`](../oxiquic) — the top-level facade crate
- [`oxiquic-core`](../oxiquic-core) — RFC 9000 core types
- [`oxiquic-transport`](../oxiquic-transport) — consumes `quic_crypto_provider()` to drive the handshake
- [`oxiquic-h3`](../oxiquic-h3) — HTTP/3 client and server

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
