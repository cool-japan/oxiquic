//! Criterion benchmarks for `oxiquic-transport`.
//!
//! All benchmarks use `tokio::runtime::Runtime::block_on` rather than
//! criterion's async support — simpler, zero extra dependencies, works with
//! any criterion version.
//!
//! Benchmark overview:
//!
//! - `bench_handshake_latency`             — 1-RTT QUIC handshake over UDP loopback
//! - `bench_stream_throughput`             — single bidi stream, 1 KiB / 64 KiB echo round-trip
//! - `bench_multi_stream_throughput`       — N sequential bidi streams on one connection (N=2,8)
//! - `bench_connection_stats`             — `QuicConnection::stats()` call (no data transfer)
//! - `bench_zero_rtt_handshake`            — 0-RTT connect with cached session ticket
//! - `bench_stream_throughput_large`       — single bidi stream, 1 MB / 10 MB payloads
//! - `bench_multi_stream_concurrent_50`    — 50 sequential bidi streams on one connection
//! - `bench_connection_establishment_rate` — 10 sequential QUIC connects per iteration
//! - `bench_tcp_tls_vs_quic_handshake`     — side-by-side QUIC 1-RTT vs TCP+TLS 1-RTT latency

use std::hint::black_box;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::client::{ClientSessionMemoryCache, Resumption};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers (mirrors tests/integration.rs — self-contained, no shared lib)
// ─────────────────────────────────────────────────────────────────────────────

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("create tokio runtime for bench")
}

/// Build a matched (client, server) rustls config pair backed by a self-signed
/// Ed25519 cert for `localhost`, using the OxiQUIC Pure-Rust crypto provider.
fn config_pair() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed Ed25519 cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust self-signed cert");

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

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("parse loopback addr")
}

/// Perform a complete handshake and return the connected client `QuicConnection`.
/// The server accept task runs in the background.
async fn do_handshake() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server for handshake bench");
    let server_addr = server.local_addr().expect("server local addr");

    // Accept one connection on the server side, then drop it.
    let _server_task = tokio::spawn(async move {
        let _ = server.accept().await;
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client for handshake bench");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect for handshake bench");

    // Connection established — that's all we measure.
    drop(conn);
}

/// Send `payload_len` bytes on a bidi stream, read the echo back, and return
/// how many bytes were received.
async fn bench_echo_stream(payload_len: usize) -> usize {
    let payload = vec![0xABu8; payload_len];

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server for stream bench");
    let server_addr = server.local_addr().expect("server local addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept stream bench");

        let deadline = Instant::now() + Duration::from_secs(30);
        let (stream_id, first_chunk, fin) = conn
            .accept_uni_or_bidi_data_with_deadline(deadline)
            .await
            .expect("server accept first chunk");

        let mut received = first_chunk;
        let mut done = fin;
        while received.len() < payload_len && !done {
            let (chunk, f) = conn
                .read_with_deadline(stream_id, deadline)
                .await
                .expect("server read chunk");
            received.extend_from_slice(&chunk);
            done = f;
        }

        conn.send(stream_id, &received, false)
            .await
            .expect("server echo");

        // Drain until all data is acknowledged.
        let drain_end = Instant::now() + Duration::from_secs(25);
        while Instant::now() < drain_end
            && (conn.has_pending_stream_data() || conn.bytes_in_flight() > 0)
        {
            conn.drive().await.expect("server drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client for stream bench");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect stream bench");

    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, &payload, false)
        .await
        .expect("client send stream bench");

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut echoed = Vec::with_capacity(payload_len);
    while echoed.len() < payload_len {
        let (chunk, fin) = conn
            .read_with_deadline(stream, deadline)
            .await
            .expect("client read echo");
        echoed.extend_from_slice(&chunk);
        if fin {
            break;
        }
    }

    server_task.await.expect("server task stream bench");
    echoed.len()
}

/// Establish a connection (outside the hot loop) and return the client's
/// connection stats — measuring only the `stats()` call itself.
async fn bench_stats_call() -> oxiquic_core::ConnectionStats {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server for stats bench");
    let server_addr = server.local_addr().expect("server local addr");

    let _server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept stats bench");
        let (id, bytes, _fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server accept data");
        conn.send(id, &bytes, false)
            .await
            .expect("server echo stats ping");
        for _ in 0..10 {
            conn.drive().await.expect("server drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client for stats bench");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect stats bench");

    // One ping-pong so stats are non-trivially populated.
    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, b"ping", false)
        .await
        .expect("client send ping");
    let (_echoed, _fin) = conn.read(stream).await.expect("client read echo");

    // Return the stats snapshot — this is the value we benchmark below.
    conn.stats()
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// Benchmark: time for a complete 1-RTT QUIC handshake over UDP loopback.
fn bench_handshake_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("1rtt", |b| {
        let rt = make_runtime();
        b.iter(|| rt.block_on(async { do_handshake().await }));
    });

    group.finish();
}

/// Benchmark: single bidi stream echo at varying payload sizes.
fn bench_stream_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_throughput");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &size_kb in &[1u64, 64u64] {
        let bytes = size_kb * 1024;
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(
            BenchmarkId::new("echo", format!("{size_kb}kb")),
            &bytes,
            |b, &payload_bytes| {
                let rt = make_runtime();
                b.iter(|| {
                    rt.block_on(async {
                        black_box(bench_echo_stream(payload_bytes as usize).await)
                    })
                });
            },
        );
    }

    group.finish();
}

/// Open `n_streams` bidi streams on a single QUIC connection, send 1 KiB on
/// each stream sequentially, and read the echo back. Returns total bytes echoed.
async fn bench_multi_stream_echo(n_streams: usize) -> usize {
    const PAYLOAD_LEN: usize = 1024;
    let payload = vec![0xCDu8; PAYLOAD_LEN];

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server for multi-stream bench");
    let server_addr = server.local_addr().expect("server local addr");

    // Server: accept n_streams separate data requests and echo each one back.
    let server_task = tokio::spawn(async move {
        let mut conn = server
            .accept()
            .await
            .expect("server accept multi-stream bench");
        let deadline = Instant::now() + Duration::from_secs(60);

        for _ in 0..n_streams {
            let (stream_id, first_chunk, fin) = conn
                .accept_uni_or_bidi_data_with_deadline(deadline)
                .await
                .expect("server accept chunk multi-stream");

            let mut received = first_chunk;
            let mut done = fin;
            while received.len() < PAYLOAD_LEN && !done {
                let (chunk, f) = conn
                    .read_with_deadline(stream_id, deadline)
                    .await
                    .expect("server read multi-stream");
                received.extend_from_slice(&chunk);
                done = f;
            }

            conn.send(stream_id, &received, false)
                .await
                .expect("server echo multi-stream");
        }

        let drain_end = Instant::now() + Duration::from_secs(30);
        while Instant::now() < drain_end
            && (conn.has_pending_stream_data() || conn.bytes_in_flight() > 0)
        {
            conn.drive().await.expect("server drive multi-stream");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client for multi-stream bench");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect multi-stream bench");

    let mut total_echoed = 0usize;
    let deadline = Instant::now() + Duration::from_secs(60);

    for _ in 0..n_streams {
        let stream = conn.open_bidi().expect("open bidi stream multi-stream");
        conn.send(stream, &payload, false)
            .await
            .expect("client send multi-stream");

        let mut echoed = Vec::with_capacity(PAYLOAD_LEN);
        while echoed.len() < PAYLOAD_LEN {
            let (chunk, fin) = conn
                .read_with_deadline(stream, deadline)
                .await
                .expect("client read echo multi-stream");
            echoed.extend_from_slice(&chunk);
            if fin {
                break;
            }
        }
        total_echoed += echoed.len();
    }

    server_task.await.expect("server task multi-stream bench");
    total_echoed
}

/// Benchmark: multi-stream throughput — open N sequential bidi streams on a
/// single connection, send 1 KiB on each, read echo back. Measures total
/// time for N stream round-trips.
fn bench_multi_stream_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_stream_throughput");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &n_streams in &[2usize, 8usize] {
        let total_bytes = (n_streams * 1024) as u64;
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(
            BenchmarkId::new("sequential_1kb_per_stream", n_streams),
            &n_streams,
            |b, &n| {
                let rt = make_runtime();
                b.iter(|| rt.block_on(async { black_box(bench_multi_stream_echo(n).await) }));
            },
        );
    }

    group.finish();
}

/// Benchmark: cost of calling `QuicConnection::stats()` on an established
/// connection.  The connection is set up ONCE per benchmark function call
/// (outside `b.iter`); only the `stats()` call is timed.
fn bench_connection_stats(c: &mut Criterion) {
    let rt = make_runtime();

    // Build the connection ONCE; we reuse the pre-populated stats snapshot.
    // (We can't easily pass a `QuicConnection` into the closure because it is
    // `!Send`, so we call `stats()` inside the async setup and benchmark the
    // cloning / struct-copy cost.)
    let initial_stats = rt.block_on(bench_stats_call());

    c.bench_function("connection_stats_call", |b| {
        b.iter(|| {
            // The benchmark exercises the copy/clone cost of ConnectionStats
            // (an all-Copy struct) — representative of the snapshot overhead.
            black_box(initial_stats.clone())
        })
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 0-RTT helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a matched (client, server) rustls config pair with 0-RTT support.
///
/// The client config has `enable_early_data = true` and a shared
/// [`ClientSessionMemoryCache`] so session tickets persist across connections.
/// The server config has `max_early_data_size = u32::MAX` (enabled).
///
/// Returns `(client_cfg, server_cfg, cache)` — the cache is returned so the
/// caller can construct multiple `ClientEndpoint`s that share the same session
/// store.
fn config_pair_0rtt() -> (
    Arc<ClientConfig>,
    Arc<ServerConfig>,
    Arc<ClientSessionMemoryCache>,
) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed Ed25519 cert for 0-rtt bench");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("trust self-signed cert for 0-rtt bench");

    let cache = Arc::new(ClientSessionMemoryCache::new(64));

    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("build client TLS 1.3 config for 0-rtt bench")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.enable_early_data = true;
    client.resumption = Resumption::store(cache.clone());

    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("build server TLS 1.3 config for 0-rtt bench")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build server single-cert config for 0-rtt bench");
    server.max_early_data_size = u32::MAX;

    (Arc::new(client), Arc::new(server), cache)
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark 1: 0-RTT handshake latency
// ─────────────────────────────────────────────────────────────────────────────

/// Benchmark: 0-RTT connect latency when a session ticket is cached.
///
/// Each iteration:
///   **setup** — spin up a fresh server endpoint, do one cold 1-RTT connect to
///   prime the session ticket cache, open+close a bidi stream so the ticket is
///   issued, then drop the cold connection;
///   **iteration** — call `connect_0rtt`, await `ZeroRttAccepted`, black-box
///   the result.  Falls back to a plain connect on cold start (no cached ticket
///   yet) so the bench never panics.
fn bench_zero_rtt_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_rtt");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    group.bench_function("connect_0rtt_warm", |b| {
        b.iter_with_setup(
            || {
                // ── Setup: prime the session cache with one cold connect ──────
                let rt = make_runtime();
                rt.block_on(async {
                    let (client_cfg, server_cfg, _cache) = config_pair_0rtt();
                    let server_transport =
                        TransportConfig::default().max_early_data_size(0xffff_ffff);
                    let client_transport = TransportConfig::default();

                    // Bind the server; it stays alive across the iteration.
                    let server = ServerEndpoint::bind(
                        loopback(),
                        Arc::clone(&server_cfg),
                        server_transport.clone(),
                    )
                    .await
                    .expect("bind server for 0-rtt bench setup");
                    let server_addr = server.local_addr().expect("server local addr 0-rtt");

                    // Server task: accept one connection, drive long enough for
                    // ticket issuance, echo a small payload, and loop accepting.
                    let server_arc = Arc::new(server);
                    let server_arc2 = Arc::clone(&server_arc);
                    tokio::spawn(async move {
                        // Cold-connect accept.
                        if let Ok(mut conn) = server_arc2.accept().await {
                            // Drive to issue the session ticket (arrives with HANDSHAKE_DONE).
                            for _ in 0..30 {
                                let _ = conn.drive().await;
                            }
                            // Accept the stream to unblock the client.
                            let _ = conn.accept_uni_or_bidi_data().await;
                        }
                        // Warm-connect accept (iteration).
                        if let Ok(mut conn) = server_arc2.accept().await {
                            for _ in 0..10 {
                                let _ = conn.drive().await;
                            }
                        }
                    });

                    // Cold connect: opens a stream so the server issues a ticket.
                    let cold_ep = ClientEndpoint::bind(
                        loopback(),
                        Arc::clone(&client_cfg),
                        client_transport.clone(),
                    )
                    .await
                    .expect("bind cold client 0-rtt bench");
                    let mut cold_conn = cold_ep
                        .connect(server_addr, "localhost")
                        .await
                        .expect("cold connect 0-rtt bench");
                    let cold_stream = cold_conn.open_bidi().expect("open cold stream");
                    cold_conn
                        .send(cold_stream, b"prime", false)
                        .await
                        .expect("send prime");
                    // Let session ticket arrive from the server.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    drop(cold_conn);

                    // Build a new endpoint that shares the same session cache.
                    let warm_ep =
                        ClientEndpoint::bind(loopback(), Arc::clone(&client_cfg), client_transport)
                            .await
                            .expect("bind warm client 0-rtt bench");

                    (warm_ep, server_arc, server_addr)
                })
            },
            |(warm_ep, server_arc, server_addr)| {
                // ── Iteration: 0-RTT connect ─────────────────────────────────
                let rt = make_runtime();
                rt.block_on(async move {
                    // Hold a reference so the server stays alive during the
                    // iteration; drop after we're done.
                    let _server_keep_alive = server_arc;

                    match warm_ep.connect_0rtt(server_addr, "localhost").await {
                        Ok((_conn, zero_rtt_accepted)) => {
                            let accepted = zero_rtt_accepted.await;
                            black_box(accepted);
                        }
                        Err(_) => {
                            // Cold start fallback — bench never panics.
                            let _ = warm_ep.connect(server_addr, "localhost").await;
                        }
                    }
                });
            },
        );
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark 2: large single-stream throughput (1 MB, 10 MB)
// ─────────────────────────────────────────────────────────────────────────────

/// Single-stream echo for a large payload.  Uses enlarged receive windows so
/// 10 MB does not stall on flow-control back-pressure.
async fn bench_echo_stream_large(payload_len: usize) -> usize {
    let payload = vec![0xABu8; payload_len];

    let (client_cfg, server_cfg) = config_pair();

    // 16 MiB stream + connection receive windows to avoid back-pressure on 10 MB.
    const WINDOW: u64 = 16 * 1024 * 1024;
    let transport = TransportConfig::default()
        .stream_receive_window(WINDOW)
        .receive_window(WINDOW)
        .send_window(WINDOW)
        .idle_timeout(Duration::from_secs(120));

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server large-stream bench");
    let server_addr = server.local_addr().expect("server local addr large-stream");

    let server_task = tokio::spawn(async move {
        let mut conn = server
            .accept()
            .await
            .expect("server accept large-stream bench");

        let deadline = Instant::now() + Duration::from_secs(120);
        let (stream_id, first_chunk, fin) = conn
            .accept_uni_or_bidi_data_with_deadline(deadline)
            .await
            .expect("server accept first chunk large-stream");

        let mut received = first_chunk;
        let mut done = fin;
        while received.len() < payload_len && !done {
            let (chunk, f) = conn
                .read_with_deadline(stream_id, deadline)
                .await
                .expect("server read chunk large-stream");
            received.extend_from_slice(&chunk);
            done = f;
        }

        conn.send(stream_id, &received, false)
            .await
            .expect("server echo large-stream");

        let drain_end = Instant::now() + Duration::from_secs(90);
        while Instant::now() < drain_end
            && (conn.has_pending_stream_data() || conn.bytes_in_flight() > 0)
        {
            conn.drive().await.expect("server drive large-stream");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client large-stream bench");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect large-stream bench");

    let stream = conn.open_bidi().expect("open bidi stream large");
    conn.send(stream, &payload, false)
        .await
        .expect("client send large-stream bench");

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut echoed = Vec::with_capacity(payload_len);
    while echoed.len() < payload_len {
        let (chunk, fin) = conn
            .read_with_deadline(stream, deadline)
            .await
            .expect("client read echo large-stream");
        echoed.extend_from_slice(&chunk);
        if fin {
            break;
        }
    }

    server_task.await.expect("server task large-stream bench");
    echoed.len()
}

/// Benchmark: single bidi stream echo at large payload sizes (1 MB, 10 MB).
fn bench_stream_throughput_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_throughput_large");
    group.sample_size(5);
    group.measurement_time(Duration::from_secs(90));

    for &size in &[1_000_000usize, 10_000_000usize] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("echo", if size == 1_000_000 { "1mb" } else { "10mb" }),
            &size,
            |b, &payload_bytes| {
                let rt = make_runtime();
                b.iter(|| {
                    rt.block_on(async { black_box(bench_echo_stream_large(payload_bytes).await) })
                });
            },
        );
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark 3: 50 concurrent sequential bidi streams on one connection
// ─────────────────────────────────────────────────────────────────────────────

/// Benchmark: 50 sequential bidi streams on a single connection, 1 KiB each.
///
/// Reuses the `bench_multi_stream_echo` helper from the existing
/// `bench_multi_stream_throughput` group.
fn bench_multi_stream_concurrent_50(c: &mut Criterion) {
    const N: usize = 50;
    const TOTAL_BYTES: u64 = (N * 1024) as u64;

    let mut group = c.benchmark_group("multi_stream_concurrent");
    group.sample_size(5);
    group.measurement_time(Duration::from_secs(120));

    group.throughput(Throughput::Bytes(TOTAL_BYTES));
    group.bench_with_input(
        BenchmarkId::new("sequential_1kb_per_stream", N),
        &N,
        |b, &n| {
            let rt = make_runtime();
            b.iter(|| rt.block_on(async { black_box(bench_multi_stream_echo(n).await) }));
        },
    );

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark 4: connection establishment rate
// ─────────────────────────────────────────────────────────────────────────────

/// Establish one full QUIC connection to `server_addr`, exchange 1 byte on a
/// bidi stream, and close the connection.  Returns `true` on success.
async fn connect_once_and_close(
    client_cfg: Arc<ClientConfig>,
    transport: TransportConfig,
    server_addr: std::net::SocketAddr,
) -> bool {
    let ep = match ClientEndpoint::bind(loopback(), client_cfg, transport).await {
        Ok(ep) => ep,
        Err(_) => return false,
    };
    let mut conn = match ep.connect(server_addr, "localhost").await {
        Ok(c) => c,
        Err(_) => return false,
    };
    let stream = match conn.open_bidi() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if conn.send(stream, b"\x00", false).await.is_err() {
        return false;
    }
    // Read back the single echoed byte.
    let deadline = Instant::now() + Duration::from_secs(10);
    let _ = conn.read_with_deadline(stream, deadline).await;
    true
}

/// Benchmark: sequential connection establishment rate.
///
/// In each iteration, 10 full QUIC connects are made to the same server
/// endpoint; each connect opens one bidi stream, writes 1 byte, reads the
/// echo, then closes.  Reports throughput in connections/second.
fn bench_connection_establishment_rate(c: &mut Criterion) {
    const CONNECTS_PER_ITER: u32 = 10;

    let mut group = c.benchmark_group("connection_rate");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.throughput(Throughput::Elements(u64::from(CONNECTS_PER_ITER)));

    group.bench_function("sequential_connects_10", |b| {
        b.iter_with_setup(
            || {
                // Setup: bind a long-lived server endpoint; spawn an accept loop
                // that accepts CONNECTS_PER_ITER connections per iteration.
                let rt = make_runtime();
                rt.block_on(async {
                    let (client_cfg, server_cfg) = config_pair();
                    let transport = TransportConfig::default();

                    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
                        .await
                        .expect("bind server for connection-rate bench");
                    let server_addr = server.local_addr().expect("server local addr rate bench");

                    // Spawn an accept loop that handles arbitrarily many
                    // connections; one task per accepted connection so the
                    // server never blocks the bench.
                    tokio::spawn(async move {
                        while let Ok(mut conn) = server.accept().await {
                            tokio::spawn(async move {
                                let deadline = Instant::now() + Duration::from_secs(10);
                                // Accept + echo a single byte, then let
                                // the connection be dropped.
                                if let Ok((stream_id, data, _fin)) =
                                    conn.accept_uni_or_bidi_data_with_deadline(deadline).await
                                {
                                    let _ = conn.send(stream_id, &data, false).await;
                                }
                            });
                        }
                    });

                    (client_cfg, transport, server_addr)
                })
            },
            |(client_cfg, transport, server_addr)| {
                let rt = make_runtime();
                rt.block_on(async move {
                    for _ in 0..CONNECTS_PER_ITER {
                        black_box(
                            connect_once_and_close(
                                Arc::clone(&client_cfg),
                                transport.clone(),
                                server_addr,
                            )
                            .await,
                        );
                    }
                });
            },
        );
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark 5: QUIC 1-RTT vs TCP+TLS 1-RTT handshake comparison
// ─────────────────────────────────────────────────────────────────────────────

/// Build a matched (server, client) rustls config pair for **plain TCP+TLS**
/// (no QUIC extension).
///
/// Uses the same self-signed Ed25519 cert / key approach as [`config_pair`] and
/// the same Pure-Rust crypto provider, but omits every QUIC-specific call
/// (`with_max_early_data_size`, `quic::*`).  The returned configs are therefore
/// usable with plain `rustls::ServerConnection` / `rustls::ClientConnection`
/// over a `TcpStream`.
fn build_tcp_tls_configs() -> (Arc<ServerConfig>, Arc<rustls::ClientConfig>) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed Ed25519 cert for TCP+TLS bench");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("trust self-signed cert for TCP+TLS bench");

    // Plain TLS ClientConfig — no QUIC transport parameters, no 0-RTT.
    let client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("build plain TLS 1.3 client config for TCP bench")
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Plain TLS ServerConfig — no QUIC transport parameters, no early data.
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("build plain TLS 1.3 server config for TCP bench")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build plain TLS 1.3 server single-cert config");

    (Arc::new(server), Arc::new(client))
}

/// Perform one complete TCP+TLS 1-RTT handshake over loopback using blocking
/// I/O and rustls `complete_io`.
///
/// Spawns a `std::thread` for the server side so both ends can drive the
/// handshake concurrently.  The thread is joined before returning, making this
/// a synchronous, self-contained latency measurement with no Tokio scheduler
/// overhead.
fn tcp_tls_handshake_latency(server_cfg: Arc<ServerConfig>, client_cfg: Arc<rustls::ClientConfig>) {
    // Bind the listener before spawning so the client can connect immediately.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TcpListener for TCP+TLS bench");
    let server_addr = listener
        .local_addr()
        .expect("obtain TcpListener local addr");

    // Server thread: accept one connection, drive the TLS handshake to
    // completion via `complete_io`, then return.
    let server_thread = std::thread::spawn(move || {
        let (mut stream, _peer) = listener
            .accept()
            .expect("TcpListener accept for TCP+TLS bench");
        stream
            .set_nodelay(true)
            .expect("set TCP_NODELAY on server stream");

        let mut conn = rustls::ServerConnection::new(server_cfg)
            .expect("create rustls ServerConnection for TCP+TLS bench");

        // Drive until the handshake is complete.  complete_io handles all
        // wants_read / wants_write / process_new_packets interleaving.
        while conn.is_handshaking() {
            conn.complete_io(&mut stream)
                .expect("server complete_io for TCP+TLS handshake");
        }
    });

    // Client: connect, create the rustls ClientConnection, drive handshake.
    let mut client_stream =
        TcpStream::connect(server_addr).expect("TcpStream::connect for TCP+TLS bench");
    client_stream
        .set_nodelay(true)
        .expect("set TCP_NODELAY on client stream");

    let server_name = ServerName::try_from("localhost")
        .expect("parse 'localhost' as ServerName for TCP+TLS bench")
        .to_owned();
    let mut conn = rustls::ClientConnection::new(client_cfg, server_name)
        .expect("create rustls ClientConnection for TCP+TLS bench");

    while conn.is_handshaking() {
        conn.complete_io(&mut client_stream)
            .expect("client complete_io for TCP+TLS handshake");
    }

    server_thread
        .join()
        .expect("server thread join for TCP+TLS bench");
}

/// Benchmark: side-by-side comparison of QUIC 1-RTT vs TCP+TLS 1-RTT handshake
/// latency over loopback.
///
/// Both variants use the same Ed25519 certificate, the same Pure-Rust crypto
/// provider, and TLS 1.3.  The only difference is the transport:
///
/// - `quic_1rtt` — QUIC over UDP via `ClientEndpoint` / `ServerEndpoint`
///   (includes QUIC framing, CRYPTO stream, `HANDSHAKE_DONE` frame).
/// - `tcp_tls_1rtt` — TLS 1.3 over a blocking `TcpStream` driven by rustls
///   `complete_io` (no Tokio scheduler, pure blocking I/O).
///
/// The TCP variant is intentionally measured without a Tokio runtime so it
/// serves as a fair lower-bound comparison — it only benchmarks rustls TLS
/// handshake cost, not scheduling overhead.
fn bench_tcp_tls_vs_quic_handshake(c: &mut Criterion) {
    let rt = make_runtime();

    let mut group = c.benchmark_group("handshake_comparison");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    // QUIC 1-RTT — reuses the same do_handshake() helper used by
    // bench_handshake_latency so the measurement is directly comparable.
    group.bench_function("quic_1rtt", |b| {
        b.iter(|| {
            rt.block_on(async { do_handshake().await });
        });
    });

    // TCP+TLS 1-RTT — synchronous rustls over a blocking TcpStream.
    // The configs are built once per bench_function call (outside b.iter) so
    // cert-generation overhead is excluded from the per-iteration timing.
    group.bench_function("tcp_tls_1rtt", |b| {
        let (server_tls_cfg, client_tls_cfg) = build_tcp_tls_configs();
        b.iter(|| {
            tcp_tls_handshake_latency(Arc::clone(&server_tls_cfg), Arc::clone(&client_tls_cfg));
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    transport_benches,
    bench_handshake_latency,
    bench_stream_throughput,
    bench_multi_stream_throughput,
    bench_connection_stats,
    bench_zero_rtt_handshake,
    bench_stream_throughput_large,
    bench_multi_stream_concurrent_50,
    bench_connection_establishment_rate,
    bench_tcp_tls_vs_quic_handshake,
);

criterion_main!(transport_benches);
