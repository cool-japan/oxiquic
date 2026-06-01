//! QUIC connection migration overhead benchmark.
//!
//! Measures PATH_CHALLENGE/PATH_RESPONSE round-trip latency as a proxy
//! for the overhead added by connection migration vs. stable connections.
//! Run with: `cargo bench -p oxiquic-transport --bench migration`
//!
//! # Design
//!
//! All benchmarks drive the synchronous [`Connection`] state machine directly
//! — no tokio, no real UDP sockets.  This isolates the pure protocol overhead
//! (nonce generation, frame encoding, path validation bookkeeping) from any
//! I/O or scheduling noise, giving a clean lower-bound on the state-machine
//! cost of a path-migration exchange.
//!
//! ## Benchmark groups
//!
//! - `migration/path_challenge_roundtrip` — after a completed 1-RTT handshake,
//!   trigger one PATH_CHALLENGE from the client and run `exchange_all` until
//!   the server returns a PATH_RESPONSE.  Measures the full state-machine cost
//!   of a single probe including nonce generation, frame encode/decode, and
//!   path-validated state update.
//!
//! - `migration/path_challenge_roundtrip_server_init` — same as above but the
//!   server initiates the PATH_CHALLENGE toward the client.  Validates that
//!   the overhead is symmetric.
//!
//! - `migration/handshake_plus_migration` — a full 1-RTT handshake followed by
//!   one PATH_CHALLENGE/PATH_RESPONSE exchange.  Measures total cost of
//!   "establish + migrate" to compare with stable connection establishment.
//!
//! ## Note on loopback vs. in-memory
//!
//! RFC 9000 §9 path migration is designed for real address changes.  On a real
//! network, path-validation latency would include 1 network RTT.  Here we
//! measure the state-machine overhead only; real-network migration latency
//! would add ~1 RTT on top of these numbers.

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{Connection, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — mirrored from tests/path_migration.rs (no shared library)
// ─────────────────────────────────────────────────────────────────────────────

fn make_rustls_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed Ed25519 cert for migration bench");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("trust self-signed cert for migration bench");

    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("build client TLS 1.3 config")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("build server TLS 1.3 config")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build server single-cert config");

    (Arc::new(client), Arc::new(server))
}

fn addr(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], port))
}

/// Extract `(dcid, scid)` from the first Initial datagram.
fn parse_initial_cids(datagram: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let dcid_len = *datagram.get(5)? as usize;
    let dcid = datagram.get(6..6 + dcid_len)?.to_vec();
    let scid_len = *datagram.get(6 + dcid_len)? as usize;
    let scid = datagram
        .get(7 + dcid_len..7 + dcid_len + scid_len)?
        .to_vec();
    Some((dcid, scid))
}

/// Build a matched client + server [`Connection`] pair ready for handshake.
fn make_pair() -> (Connection, Connection) {
    let (client_cfg, server_cfg) = make_rustls_configs();
    let params = TransportConfig::default()
        .idle_timeout(Duration::from_secs(30))
        .to_transport_params();

    let client = Connection::new_client(
        client_cfg,
        ServerName::try_from("localhost").expect("server name"),
        addr(4433),
        params.clone(),
        Default::default(),
        Default::default(),
    )
    .expect("create client connection");

    let now = Instant::now();
    let mut first = Vec::new();
    let mut client = client;
    client
        .poll_transmit(now, &mut first)
        .expect("client initial transmit");
    let (dcid, scid) = parse_initial_cids(&first).expect("parse initial CIDs");

    let server = Connection::new_server(
        server_cfg,
        oxiquic_core::ConnectionId::new(dcid),
        oxiquic_core::ConnectionId::new(scid),
        addr(40000),
        params,
        Default::default(),
        Default::default(),
    )
    .expect("create server connection");

    let mut server = server;
    let mut owned = first.clone();
    server
        .handle_datagram(now, &mut owned)
        .expect("server handle first datagram");

    (client, server)
}

/// Exchange all pending datagrams between `client` and `server` until quiescent.
fn exchange_all(client: &mut Connection, server: &mut Connection, now: Instant) {
    for _ in 0..200 {
        let mut any = false;
        loop {
            let mut buf = Vec::new();
            if client.poll_transmit(now, &mut buf).is_some() && !buf.is_empty() {
                server.handle_datagram(now, &mut buf).ok();
                any = true;
            } else {
                break;
            }
        }
        loop {
            let mut buf = Vec::new();
            if server.poll_transmit(now, &mut buf).is_some() && !buf.is_empty() {
                client.handle_datagram(now, &mut buf).ok();
                any = true;
            } else {
                break;
            }
        }
        if !any {
            break;
        }
    }
}

/// Complete the TLS 1-RTT handshake for the given pair.
fn complete_handshake(client: &mut Connection, server: &mut Connection) {
    let now = Instant::now();
    for _ in 0..100 {
        exchange_all(client, server, now);
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("handshake did not complete in migration bench setup");
}

// ─────────────────────────────────────────────────────────────────────────────
// Core measurement helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Perform one PATH_CHALLENGE / PATH_RESPONSE exchange initiated by `challenger`.
///
/// Returns `true` when `challenger.path_validated()` is true after the exchange,
/// which must happen on every call.  Wrapped in `black_box` so the compiler
/// cannot eliminate the work.
fn do_path_challenge_roundtrip(
    challenger: &mut Connection,
    responder: &mut Connection,
    now: Instant,
) -> bool {
    challenger
        .initiate_path_challenge()
        .expect("initiate PATH_CHALLENGE");
    exchange_all(challenger, responder, now);
    black_box(challenger.path_validated())
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark functions
// ─────────────────────────────────────────────────────────────────────────────

/// Benchmark: PATH_CHALLENGE/PATH_RESPONSE round-trip initiated by the client.
///
/// The handshake is performed once per `b.iter` call so the measurement
/// includes only the path-migration state-machine cost, not connection setup.
///
/// Setup phase (outside the hot loop):
/// - Build a fresh client + server pair.
/// - Complete the 1-RTT handshake.
///
/// Hot loop:
/// - Client calls `initiate_path_challenge()`.
/// - `exchange_all` runs until quiescent (server echoes PATH_RESPONSE,
///   client sets `path_validated = true`).
/// - Assert `path_validated()` and black-box the result.
fn bench_path_challenge_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("migration");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("path_challenge_roundtrip", |b| {
        b.iter_with_setup(
            || {
                let (mut client, mut server) = make_pair();
                complete_handshake(&mut client, &mut server);
                (client, server)
            },
            |(mut client, mut server)| {
                let now = Instant::now();
                let validated = do_path_challenge_roundtrip(&mut client, &mut server, now);
                assert!(
                    validated,
                    "path must be validated after PATH_CHALLENGE/RESPONSE"
                );
                (client, server)
            },
        );
    });

    group.finish();
}

/// Benchmark: PATH_CHALLENGE/PATH_RESPONSE initiated by the **server**.
///
/// Verifies that the overhead is symmetric: server-initiated migration incurs
/// essentially the same state-machine cost as client-initiated migration.
fn bench_path_challenge_roundtrip_server_init(c: &mut Criterion) {
    let mut group = c.benchmark_group("migration");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("path_challenge_roundtrip_server_init", |b| {
        b.iter_with_setup(
            || {
                let (mut client, mut server) = make_pair();
                complete_handshake(&mut client, &mut server);
                (client, server)
            },
            |(mut client, mut server)| {
                let now = Instant::now();
                // Server initiates; client echoes PATH_RESPONSE back.
                let validated = do_path_challenge_roundtrip(&mut server, &mut client, now);
                assert!(
                    validated,
                    "server path must be validated after PATH_CHALLENGE/RESPONSE"
                );
                (client, server)
            },
        );
    });

    group.finish();
}

/// Benchmark: full 1-RTT handshake + one PATH_CHALLENGE/PATH_RESPONSE exchange.
///
/// Measures the combined cost of "establish + migrate" so callers can estimate
/// the migration fraction of total connection lifetime cost.
fn bench_handshake_plus_migration(c: &mut Criterion) {
    let mut group = c.benchmark_group("migration");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(45));

    group.bench_function("handshake_plus_migration", |b| {
        b.iter(|| {
            let (mut client, mut server) = make_pair();
            complete_handshake(&mut client, &mut server);
            let now = Instant::now();
            let validated = do_path_challenge_roundtrip(&mut client, &mut server, now);
            black_box(validated)
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    migration_benches,
    bench_path_challenge_roundtrip,
    bench_path_challenge_roundtrip_server_init,
    bench_handshake_plus_migration,
);
criterion_main!(migration_benches);
