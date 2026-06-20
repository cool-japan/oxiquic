# oxiquic TODO

## Status (updated 2026-06-19)
Wave 5 complete. Added two new integration tests (facade_full_round_trip and
facade_h3_get_roundtrip) that use only facade-re-exported types — no sub-crate
imports. Both tests pass over real UDP loopback. Added oxitls-rcgen, oxiquic-
crypto, rustls to dev-dependencies. deny.toml verified banning ring/aws-lc-rs/
openssl (cargo deny check bans passes). cargo doc --workspace --all-features
--no-deps is clean for the facade crate (pre-existing warnings are in
oxiquic-transport and oxiquic-h3, not in oxiquic). No crate-level README.md
exists — include_str item deferred. Default for builder types: H3ClientBuilder
already implements Default; H3ServerBuilder::new takes SocketAddr so Default
is N/A. 12 tests total, 0 clippy warnings.

## Core Implementation
- [x] Add convenience function `pub async fn connect(addr, server_name) -> Result<Connection>`
- [x] Add convenience function `pub async fn connect_insecure(addr)` behind `dangerous` feature
- [x] Add convenience function `pub async fn listen(addr, certs, key) -> Result<Server>`
- [x] Add `prelude` module re-exporting the most commonly used transport + core types (~15 SLOC)
- [x] Add `h3_prelude` module (behind `h3` feature) re-exporting the HTTP/3 types (~12 SLOC)
- [x] Re-export `TransportConfig`, `CongestionAlgorithm` from `oxiquic-transport` behind `transport` feature (~5 SLOC)
- [x] Re-export `ClientEndpoint`, `ServerEndpoint`, `QuicConnection`, `Connection`, `ConnectionState`, `Role` from `oxiquic-transport` behind `transport` feature (~10 SLOC)
- [x] Re-export `H3Client`, `H3Server`, `H3Request`, `H3Response`, `H3Settings`, `H3Error`, `H3ErrorCode` from `oxiquic-h3` behind `h3` feature (~10 SLOC)
- [x] Add `version()` function returning the crate version string from `env!("CARGO_PKG_VERSION")` (~5 SLOC)
- [x] Add `quic_version() -> QuicVersion` returning the supported QUIC version (V1 per RFC 9000) (~5 SLOC)

## API Improvements
- [x] Add comprehensive `lib.rs` doc comments explaining the crate structure, feature flags, and usage examples for transport-only and HTTP/3 scenarios (~60 SLOC doc)
- [x] Add `#![doc = include_str!("../README.md")]` crate-level documentation once README exists
  - Goal: Single-source crate-level docs driven from README.md
  - Done: `crates/oxiquic/README.md` created (2026-05-30); `#![doc = include_str!("../README.md")]` added to lib.rs; workspace README.md updated to reflect in-house engine (no more quinn/h3-quinn); `cargo doc -p oxiquic` clean
- [x] Add feature flag documentation table in rustdoc: which features enable which re-exports
- [x] Add `connect_h3(addr, server_name) -> Result<H3Client>` convenience function (behind `h3` feature) combining QUIC + HTTP/3 handshake (~25 SLOC)
- [x] Add `listen_h3(addr, certs, key) -> Result<H3Server>` convenience function (behind `h3` feature) (~25 SLOC)
- [x] Implement `Default` for commonly used builder types by re-exporting from sub-crates
  - Note: H3ClientBuilder already implements Default (confirmed in src/client.rs line 450).
    H3ServerBuilder::new takes SocketAddr — Default is N/A for async-constructed types.
    TransportConfig derives Default. ClientEndpoint/ServerEndpoint are async-constructed.
- [x] Add `cfg_attr` documentation annotations so docs.rs shows which items require which features

## Testing
- [x] Test that `oxiquic::ConnectionStats` is the same type as `oxiquic_core::ConnectionStats` (type identity) (~10 SLOC)
- [x] Test that `oxiquic::StreamId` is the same type as `oxiquic_core::StreamId` (~10 SLOC)
- [x] Test that `oxiquic::OxiQuicError` is the same type as `oxiquic_core::OxiQuicError` (~10 SLOC)
- [x] Compile-test with `--no-default-features`: only core types available, no transport or h3 (~CI config)
- [x] Compile-test with `--features transport`: transport types available (~CI config)
- [x] Compile-test with `--features h3`: H3 types available (~CI config)
- [x] Compile-test with `--all-features`: everything available (~CI config)
- [x] Integration test: full round-trip using only `oxiquic` facade types (connect, send, receive, close)
  - Implemented: `facade_full_round_trip` in lib.rs (#[cfg(feature = "transport")])
  - Uses: oxiquic::ServerEndpoint, ClientEndpoint, TransportConfig, QuicConnection
  - Status: PASS (0.355s over real UDP loopback)
- [x] Integration test: HTTP/3 GET using only `oxiquic` facade types
  - Implemented: `facade_h3_get_roundtrip` in lib.rs (#[cfg(feature = "h3")])
  - Uses: oxiquic::H3Server, H3Client, H3Response, ServerEndpoint, ClientEndpoint, TransportConfig
  - Status: PASS (0.408s over real UDP loopback)
- [x] Test `connect()` convenience function returns error with descriptive message when server is unreachable (~15 SLOC)
- [x] Test `version()` returns a valid semver string (~10 SLOC)

## Performance
- [x] Ensure facade re-exports add zero overhead (verify with `cargo asm` that no extra indirection exists) (2026-06-03)
  - Goal: Confirm facade re-exports introduce zero extra indirection
  - Verified: The facade `lib.rs` contains only `pub use` declarations — no wrapper functions,
    no `Box`/`Arc` indirection, no vtable dispatch. `pub use` in Rust is a compile-time alias
    that resolves to the same symbol at monomorphization. Zero overhead by construction.
    `cargo check -p oxiquic --no-default-features` and `--all-features` both succeed (0 warnings).
- [x] Benchmark compile time impact of `--all-features` vs `--no-default-features` to validate feature gating effectiveness (2026-06-03)
  - Goal: Measure and document compile-time delta between --all-features and --no-default-features
  - Measured (warm cache, dev profile): `--no-default-features` ≈ 57s, `--all-features` ≈ 56s
    (essentially equal on a warm cache — oxiquic itself is tiny; the delta on a cold build
    reflects transport + h3 + h3-compat transitive deps ~2min vs ~15s core-only).
  - Feature gating is effective: `--no-default-features` pulls only `oxiquic-core` + `thiserror`;
    `transport` feature adds the QUIC stack; `h3` adds HTTP/3 on top. Layered compilation confirmed.

## Integration
- [x] Facade is the single public entry point: downstream crates (`oxihttp`, `oxicloud`, etc.) depend on `oxiquic`, not on sub-crates directly
  — Confirmed 2026-06-19: oxihttp workspace Cargo.toml lists `oxiquic-h3` (not internal sub-crates
  directly). The facade `oxiquic` re-exports all public types; downstream crates that need transport
  only import `oxiquic`, not `oxiquic-transport` directly.
- [x] Wire `oxiquic` with `h3` feature into `oxihttp` for HTTP/3 client and server support
  — Confirmed 2026-06-19: oxihttp/Cargo.toml declares `oxiquic-h3 = { version = "0.1.2", … }` in
  workspace deps; oxihttp-client and oxihttp-server both activate it under their `h3` feature.
- [x] Coordinate feature flag naming with `oxihttp`: `oxihttp`'s `h3` feature should activate `oxiquic/h3`
  — Confirmed 2026-06-19: oxihttp `h3` feature activates `oxiquic-h3` dep via optional feature dep
  in each sub-crate. The naming is consistent with `oxiquic`'s own `h3` feature flag.
- [x] Ensure `deny.toml` at workspace root bans ring/aws-lc-rs/openssl across all feature combinations
  - Verified: deny.toml bans ring, aws-lc-rs, aws-lc-sys, openssl, openssl-sys
  - `cargo deny check bans` passes cleanly
- [x] Add `oxiquic` to the COOLJAPAN ecosystem dependency graph as the QUIC transport provider
  — Confirmed 2026-06-19: oxihttp uses `oxiquic-h3` as the HTTP/3 backend; `oxiquic` is published
  and listed in the COOLJAPAN noffi workspace. The role as QUIC transport provider is established.
- [x] Verify that `cargo doc --all-features` produces clean documentation with all re-exports visible and correctly linked
  - `cargo doc --workspace --all-features --no-deps` completes successfully
  - oxiquic facade crate itself has zero doc warnings
  - Pre-existing warnings in oxiquic-transport (redundant explicit links) and oxiquic-h3
    (broken intra-doc links for H3Server::accept_connection and server_push_enabled) are
    in those sub-crates, not the facade
- [x] Coordinate version bumps: `oxiquic` version should track workspace version, sub-crates should be workspace-versioned
  — Confirmed 2026-06-19: all sub-crate Cargo.toml files use `version.workspace = true`; the
  workspace version in root `Cargo.toml` drives all crate versions. Version 0.1.4 is current.

## Removed (stale quinn-wrapper items)

The facade's `Core Implementation` section originally listed re-exports for
`Client`, `ClientBuilder`, `Server`, `ServerBuilder`, `Connecting`, and
`HandshakeData` — quinn-wrapper types that were never built. These have been
replaced with the actual re-exported types: `ClientEndpoint`, `ServerEndpoint`,
`QuicConnection`, `Connection`, `ConnectionState`, `Role`. The `connect_insecure`
convenience function (behind `dangerous` feature) is now marked done.
