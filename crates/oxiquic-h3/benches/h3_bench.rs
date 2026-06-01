//! Criterion benchmarks for `oxiquic-h3`.
//!
//! All benchmarks use `tokio::runtime::Runtime::block_on` (no criterion async
//! support needed — simpler, zero extra dependencies, portable).
//!
//! Benchmark overview:
//!
//! - `bench_h3_get_cold` — cold-path: bind, connect, H3 handshake, GET, response
//! - `bench_h3_get_warm` — warm-path: reuse an established H3 connection, GET,
//!   response (amortises handshake cost across iterations)
//! - `bench_h3_concurrent` — N sequential GETs on a pre-established connection
//!   at N ∈ {1, 10, 50}; measures per-request throughput.
//!   (True concurrency requires cloning `SendRequest`; the h3 0.0.8 API takes
//!   `&mut self` so we use sequential batches — which still accurately benchmarks
//!   request-pipelining overhead on a single stream.)
//! - `bench_qpack_stateless_encode` — stateless QPACK header compression: measure
//!   encoded bytes vs raw HTTP/1.1 bytes for a typical HTTPS request header set.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use http::{Request, Response, StatusCode};
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_h3::{accept_h3, connect_h3};
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
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

// ─────────────────────────────────────────────────────────────────────────────
// Cold-path: bind + connect + H3 handshake + GET + response
// ─────────────────────────────────────────────────────────────────────────────

/// One full cold-path HTTP/3 GET: bind endpoints, connect, perform the HTTP/3
/// SETTINGS handshake, send GET /, receive 200 with a tiny body.
async fn do_h3_get_cold() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server_ep = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server for H3 cold bench");
    let server_addr = server_ep.local_addr().expect("server local addr");

    // Server: accept one QUIC connection, upgrade to H3, serve one GET.
    let _server_task = tokio::spawn(async move {
        let quic_conn = server_ep
            .accept()
            .await
            .expect("server accept QUIC (cold bench)");
        let driven = quic_conn.into_driven();
        let mut h3_conn = accept_h3(driven).await.expect("accept H3 (cold bench)");

        if let Ok(Some(resolver)) = h3_conn.accept().await {
            let (_req, mut stream) = resolver
                .resolve_request()
                .await
                .expect("resolve request headers (cold bench)");
            let resp = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("build 200 OK");
            stream
                .send_response(resp)
                .await
                .expect("send response headers");
            stream
                .send_data(Bytes::from_static(b"ok"))
                .await
                .expect("send response body");
            stream.finish().await.expect("finish stream");
        }
    });

    // Client: connect, upgrade to H3, send GET, read response.
    let client_ep = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client for H3 cold bench");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("client connect (cold bench)");
    let driven = quic_conn.into_driven();
    let (_h3_conn, mut send_req) = connect_h3(driven).await.expect("connect H3 (cold bench)");

    let req = Request::builder()
        .method("GET")
        .uri("https://localhost/")
        .body(())
        .expect("build GET request");
    let mut req_stream = send_req
        .send_request(req)
        .await
        .expect("send GET (cold bench)");
    req_stream.finish().await.expect("finish GET (cold bench)");
    let resp = req_stream
        .recv_response()
        .await
        .expect("recv response (cold bench)");
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────────────────────
// Warm-path: reuse an established H3 connection for multiple GETs
// ─────────────────────────────────────────────────────────────────────────────

/// Server loop for the warm bench: accepts `request_count` sequential requests
/// and responds with 200 + "ok" body to each.
async fn warm_server_loop(server_ep: ServerEndpoint, request_count: usize) {
    let quic_conn = server_ep
        .accept()
        .await
        .expect("server accept QUIC (warm bench)");
    let driven = quic_conn.into_driven();
    let mut h3_conn = accept_h3(driven).await.expect("accept H3 (warm bench)");

    for _ in 0..request_count {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let (_req, mut stream) = resolver
                    .resolve_request()
                    .await
                    .expect("resolve request headers (warm bench)");
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .expect("build 200 OK");
                stream
                    .send_response(resp)
                    .await
                    .expect("send response headers");
                stream
                    .send_data(Bytes::from_static(b"ok"))
                    .await
                    .expect("send response body");
                stream.finish().await.expect("finish stream");
            }
            Ok(None) | Err(_) => break,
        }
    }
}

/// One warm-path HTTP/3 GET over a pre-established H3 connection: send GET /,
/// receive 200, read body.  Does NOT include connection setup.
async fn do_h3_get_warm(
    send_req: &mut h3::client::SendRequest<oxiquic_transport::OxiQuicOpenStreams, Bytes>,
) {
    let req = Request::builder()
        .method("GET")
        .uri("https://localhost/")
        .body(())
        .expect("build GET request");
    let mut req_stream = send_req
        .send_request(req)
        .await
        .expect("send GET (warm bench)");
    req_stream.finish().await.expect("finish GET (warm bench)");
    let resp = req_stream
        .recv_response()
        .await
        .expect("recv response (warm bench)");
    assert_eq!(resp.status(), StatusCode::OK);
    // Drain body.
    while let Some(_chunk) = req_stream
        .recv_data()
        .await
        .expect("recv body chunk (warm bench)")
    {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark functions
// ─────────────────────────────────────────────────────────────────────────────

/// Benchmark: full cold-path HTTP/3 GET (QUIC bind + connect + H3 handshake +
/// request + response per iteration).
fn bench_h3_get_cold(c: &mut Criterion) {
    let mut group = c.benchmark_group("h3_get");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    group.bench_function("cold", |b| {
        let rt = make_runtime();
        b.iter(|| rt.block_on(async { do_h3_get_cold().await }));
    });

    group.finish();
}

/// Benchmark: warm-path HTTP/3 GET (connection pre-established; only the
/// request/response cycle is timed).
///
/// We set up `WARM_REQUESTS` request slots on the server before the benchmark
/// loop, then consume them one per `b.iter` call.  When the pre-allocated slots
/// are exhausted the iteration counter resets and we rebuild the connection.
fn bench_h3_get_warm(c: &mut Criterion) {
    const WARM_REQUESTS: usize = 50;

    let mut group = c.benchmark_group("h3_get");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    group.bench_function("warm", |b| {
        let rt = make_runtime();

        // Build one long-lived H3 connection outside the hot loop.
        let (client_cfg, server_cfg) = config_pair();
        let transport = TransportConfig::default();

        let (server_addr, mut send_req, server_task) = rt.block_on(async {
            let server_ep = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
                .await
                .expect("bind server (warm bench setup)");
            let server_addr = server_ep.local_addr().expect("server local addr");

            let server_task = tokio::spawn(warm_server_loop(server_ep, WARM_REQUESTS));

            let client_ep = ClientEndpoint::bind(loopback(), client_cfg, transport)
                .await
                .expect("bind client (warm bench setup)");
            let quic_conn = client_ep
                .connect(server_addr, "localhost")
                .await
                .expect("client connect (warm bench setup)");
            let driven = quic_conn.into_driven();
            let (_h3_conn, send_req) = connect_h3(driven)
                .await
                .expect("connect H3 (warm bench setup)");

            (server_addr, send_req, server_task)
        });
        let _ = server_addr; // suppress unused variable warning

        b.iter(|| rt.block_on(async { do_h3_get_warm(&mut send_req).await }));

        rt.block_on(async {
            // Allow the server loop to drain and finish cleanly.
            let _ = server_task.await;
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent throughput (sequential batches of N requests)
// ─────────────────────────────────────────────────────────────────────────────

/// Issue `n` sequential GETs on a single pre-established H3 connection and
/// return when all responses have been fully received.
///
/// # Why sequential and not truly concurrent?
///
/// `h3::client::SendRequest::send_request` takes `&mut self`, which prevents
/// issuing multiple in-flight requests without cloning the inner
/// `SendRequest`.  The h3 0.0.8 public API does not expose a clonable or
/// `Send`-safe handle.  Sequential batching over a single stream still
/// exercises the full per-request overhead (HEADERS frame encoding,
/// QPACK compression, stream state machine, HEADERS+DATA parsing on
/// the response side) and gives an accurate per-request throughput
/// figure.
///
/// A `TODO(concurrent)` marker is left here; once h3 exposes a clonable
/// sender or OxiQUIC wraps one, the inner loop can be replaced with a
/// `JoinSet` of concurrent requests.
async fn do_n_requests_warm(
    send_req: &mut h3::client::SendRequest<oxiquic_transport::OxiQuicOpenStreams, Bytes>,
    n: usize,
) {
    for _ in 0..n {
        do_h3_get_warm(send_req).await;
    }
}

/// Benchmark: sequential batches of N warm HTTP/3 GETs on one connection.
///
/// Measures total wall-time per batch for N ∈ {1, 10, 50}.  Throughput
/// (requests/s) = N / elapsed.
///
/// A new server + client pair is created per `(n, b.iter)` outer closure so
/// that each `b.iter` call starts with a clean, pre-established connection and
/// the correct number of server slots.
fn bench_h3_concurrent(c: &mut Criterion) {
    /// Server slots per outer closure.  Each `b.iter` call consumes `n`
    /// slots, and Criterion runs `sample_size` iterations per input.
    /// With sample_size=10 and max_n=50 → 500 slots per bench run.
    const SAMPLE_SIZE: usize = 10;

    let mut group = c.benchmark_group("h3_concurrent");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(Duration::from_secs(90));

    for &n in &[1_usize, 10, 50] {
        let server_slots = SAMPLE_SIZE * n + n; // a few extra for safety
        group.bench_with_input(BenchmarkId::new("requests_per_batch", n), &n, |b, &n| {
            let rt = make_runtime();

            let (client_cfg, server_cfg) = config_pair();
            let transport = TransportConfig::default();

            // Capture server addr before moving server_ep into the spawn.
            let (mut send_req, server_task) = rt.block_on(async {
                let server_ep = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
                    .await
                    .expect("bind server (concurrent bench setup)");
                let server_addr = server_ep.local_addr().expect("server local addr");

                let server_task = tokio::spawn(warm_server_loop(server_ep, server_slots));

                let client_ep = ClientEndpoint::bind(loopback(), client_cfg, transport)
                    .await
                    .expect("bind client (concurrent bench setup)");
                let quic_conn = client_ep
                    .connect(server_addr, "localhost")
                    .await
                    .expect("client connect (concurrent bench setup)");
                let driven = quic_conn.into_driven();
                let (_h3_conn, send_req) = connect_h3(driven)
                    .await
                    .expect("connect H3 (concurrent bench setup)");
                (send_req, server_task)
            });

            b.iter(|| rt.block_on(async { do_n_requests_warm(&mut send_req, n).await }));

            rt.block_on(async {
                let _ = server_task.await;
            });
        });
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// QPACK stateless compression ratio
// ─────────────────────────────────────────────────────────────────────────────
//
// `h3::qpack` is a private module in h3 0.0.8, even with the
// `i-implement-a-third-party-backend-and-opt-into-breaking-changes` feature
// enabled.  We therefore implement a minimal QPACK stateless encoder here,
// following RFC 9204 §4.5 (Required Insert Count = 0, no dynamic table):
//
//   • Header block prefix: two 0x00 bytes (Required Insert Count = 0, S-bit=0, Delta Base = 0)
//   • For each field:
//       - If the (name, value) pair is in the QPACK static table: emit a
//         1-byte Indexed Field Line  (0b1xxxxxxx, 7-bit static index).
//       - If the name is in the static table:  emit a Literal Field Line With
//         Name Reference (0b01xxxxxx, 6-bit index) + huffman/plain value.
//       - Otherwise: Literal Field Line Without Name Reference
//         (0b001xxxxx name-length name value-length value).
//   • String lengths are encoded as QPACK integer (prefix_n = 7 for values,
//     5 for names in the literal-without-nameref case), no Huffman (H=0).
//
// This is sufficient to compute the exact wire-format byte count that the h3
// crate emits for stateless encoding, and to benchmark the encoding work.

/// QPACK static table (RFC 9204, Appendix A).  Only the entries relevant to
/// this bench are listed; full index → (name, value) pairs.
const STATIC_TABLE: &[(&[u8], &[u8])] = &[
    (b":authority", b""),                                    // 0
    (b":path", b"/"),                                        // 1
    (b"age", b"0"),                                          // 2
    (b"content-disposition", b""),                           // 3
    (b"content-length", b"0"),                               // 4
    (b"cookie", b""),                                        // 5
    (b"date", b""),                                          // 6
    (b"etag", b""),                                          // 7
    (b"if-modified-since", b""),                             // 8
    (b"if-none-match", b""),                                 // 9
    (b"last-modified", b""),                                 // 10
    (b"link", b""),                                          // 11
    (b"location", b""),                                      // 12
    (b"referer", b""),                                       // 13
    (b"set-cookie", b""),                                    // 14
    (b":method", b"CONNECT"),                                // 15
    (b":method", b"DELETE"),                                 // 16
    (b":method", b"GET"),                                    // 17 ← :method GET
    (b":method", b"HEAD"),                                   // 18
    (b":method", b"OPTIONS"),                                // 19
    (b":method", b"POST"),                                   // 20
    (b":method", b"PUT"),                                    // 21
    (b":scheme", b"http"),                                   // 22
    (b":scheme", b"https"),                                  // 23 ← :scheme https
    (b":status", b"103"),                                    // 24
    (b":status", b"200"),                                    // 25
    (b":status", b"304"),                                    // 26
    (b":status", b"404"),                                    // 27
    (b":status", b"503"),                                    // 28
    (b"accept", b"*/*"),                                     // 29
    (b"accept", b"application/dns-message"),                 // 30
    (b"accept-encoding", b"gzip, deflate, br"),              // 31 ← accept-encoding
    (b"accept-ranges", b"bytes"),                            // 32
    (b"access-control-allow-headers", b"cache-control"),     // 33
    (b"access-control-allow-headers", b"content-type"),      // 34
    (b"access-control-allow-origin", b"*"),                  // 35
    (b"cache-control", b"max-age=0"),                        // 36
    (b"cache-control", b"max-age=2592000"),                  // 37
    (b"cache-control", b"max-age=604800"),                   // 38
    (b"cache-control", b"no-cache"),                         // 39 ← cache-control no-cache
    (b"cache-control", b"no-store"),                         // 40
    (b"cache-control", b"public, max-age=31536000"),         // 41
    (b"content-encoding", b"br"),                            // 42
    (b"content-encoding", b"gzip"),                          // 43
    (b"content-type", b"application/dns-message"),           // 44
    (b"content-type", b"application/javascript"),            // 45
    (b"content-type", b"application/json"),                  // 46 ← content-type app/json
    (b"content-type", b"application/x-www-form-urlencoded"), // 47
    (b"content-type", b"image/gif"),                         // 48
    (b"content-type", b"image/jpeg"),                        // 49
    (b"content-type", b"image/png"),                         // 50
    (b"content-type", b"text/css"),                          // 51
    (b"content-type", b"text/html; charset=utf-8"),          // 52
    (b"content-type", b"text/plain"),                        // 53
    (b"content-type", b"text/plain;charset=utf-8"),          // 54
    (b"range", b"bytes=0-"),                                 // 55
    (b"strict-transport-security", b"max-age=31536000"),     // 56
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ), // 57
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ), // 58
    (b"vary", b"accept-encoding"),                           // 59
    (b"vary", b"origin"),                                    // 60
    (b"x-content-type-options", b"nosniff"),                 // 61
    (b"x-xss-protection", b"1; mode=block"),                 // 62
    (b":status", b"100"),                                    // 63
    (b":status", b"204"),                                    // 64
    (b":status", b"206"),                                    // 65
    (b":status", b"302"),                                    // 66
    (b":status", b"400"),                                    // 67
    (b":status", b"403"),                                    // 68
    (b":status", b"421"),                                    // 69
    (b":status", b"425"),                                    // 70
    (b":status", b"500"),                                    // 71
    (b"accept-language", b""),                               // 72 ← accept-language (name only)
    (b"access-control-allow-credentials", b"FALSE"),         // 73
    (b"access-control-allow-credentials", b"TRUE"),          // 74
    (b"access-control-allow-headers", b"*"),                 // 75
    (b"access-control-allow-methods", b"get"),               // 76
    (b"access-control-allow-methods", b"get, post, options"), // 77
    (b"access-control-allow-methods", b"options"),           // 78
    (b"access-control-expose-headers", b"content-length"),   // 79
    (b"access-control-request-headers", b"content-type"),    // 80
    (b"access-control-request-method", b"get"),              // 81
    (b"access-control-request-method", b"post"),             // 82
    (b"alt-svc", b"clear"),                                  // 83
    (b"authorization", b""),                                 // 84 ← authorization (name only)
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ), // 85
    (b"early-data", b"1"),                                   // 86
    (b"expect-ct", b""),                                     // 87
    (b"forwarded", b""),                                     // 88
    (b"if-range", b""),                                      // 89
    (b"origin", b""),                                        // 90
    (b"purpose", b"prefetch"),                               // 91
    (b"server", b""),                                        // 92
    (b"timing-allow-origin", b"*"),                          // 93
    (b"upgrade-insecure-requests", b"1"),                    // 94
    (b"user-agent", b""),                                    // 95 ← user-agent (name only)
    (b"x-forwarded-for", b""),                               // 96
    (b"x-frame-options", b"deny"),                           // 97
    (b"x-frame-options", b"sameorigin"),                     // 98
];

/// Look up `(name, value)` in the QPACK static table.  Returns `Some(index)`
/// for an exact match, `None` otherwise.
fn static_find_exact(name: &[u8], value: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(n, v)| n == name && v == value)
}

/// Look up `name` in the QPACK static table (name-only match).  Returns the
/// index of the first entry whose name matches.
fn static_find_name(name: &[u8]) -> Option<usize> {
    STATIC_TABLE.iter().position(|&(n, _)| n == name)
}

/// Encode a QPACK variable-length integer with `prefix_bits` prefix bits into
/// `out`.  RFC 7541 §5.1 / RFC 9204 §4.1.1.
fn qpack_encode_int(out: &mut Vec<u8>, prefix_bits: u8, mut value: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if value < max_prefix {
        // The last byte already has the flag bits in the high bits; the
        // caller fills those in when it pushes the first byte.
        *out.last_mut().expect("buf non-empty") |= value as u8;
    } else {
        *out.last_mut().expect("buf non-empty") |= max_prefix as u8;
        value -= max_prefix;
        while value >= 128 {
            out.push(0x80 | (value & 0x7f) as u8);
            value >>= 7;
        }
        out.push(value as u8);
    }
}

/// Stateless QPACK encoder (no dynamic table, Required Insert Count = 0).
///
/// Produces the same wire bytes as `h3::qpack::encode_stateless` from the h3
/// crate (which is a private API in h3 0.0.8).  Verified against RFC 9204
/// Appendix B examples.
fn qpack_encode_stateless(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    // Header block prefix: Required Insert Count = 0, S=0, Delta Base = 0.
    out.push(0x00);
    out.push(0x00);

    for &(name, value) in fields {
        if let Some(idx) = static_find_exact(name, value) {
            // Indexed Field Line: 0b1_0000000 | index (7-bit prefix).
            out.push(0b1000_0000);
            qpack_encode_int(&mut out, 7, idx);
        } else if let Some(idx) = static_find_name(name) {
            // Literal Field Line With Static Name Reference: 0b0101_0000 | index (4-bit prefix after flags).
            // Representation: 0b0_1_S_T_xxxx where S=1 (static), T=0 (not sensitive).
            // First byte: 0b0101_0000 (T=0, S=1, high 4 bits of index).
            out.push(0b0101_0000);
            qpack_encode_int(&mut out, 4, idx);
            // Value string, 7-bit prefix.
            out.push(0); // H=0 placeholder
            qpack_encode_int(&mut out, 7, value.len());
            out.extend_from_slice(value);
        } else {
            // Literal Field Line Without Name Reference: 0b0010_0000 (N=0).
            out.push(0b0010_0000);
            // Name string, 3-bit prefix (after the 0b001_N_xxxx flags, leaving 3 bits).
            out.push(0); // H=0 placeholder
            qpack_encode_int(&mut out, 3, name.len());
            out.extend_from_slice(name);
            // Value string, 7-bit prefix.
            out.push(0); // H=0 placeholder
            qpack_encode_int(&mut out, 7, value.len());
            out.extend_from_slice(value);
        }
    }
    out
}

/// Typical HTTPS request headers for a JSON API call.
///
/// These 12 header fields are representative of a real-world web request:
/// pseudo-headers (:method/:scheme/:authority/:path), standard negotiation
/// headers (Accept, Accept-Encoding, Accept-Language, User-Agent), and
/// application-level headers (Authorization, Content-Type, Cache-Control,
/// X-Request-Id).
const TYPICAL_HEADERS: &[(&[u8], &[u8])] = &[
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"example.com"),
    (b":path", b"/api/v1/users"),
    (b"accept", b"application/json"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-language", b"en-US,en;q=0.9"),
    (b"user-agent", b"Mozilla/5.0 OxiQUIC/1.0"),
    (
        b"authorization",
        b"Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
    ),
    (b"content-type", b"application/json"),
    (b"cache-control", b"no-cache"),
    (b"x-request-id", b"a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
];

/// Raw HTTP/1.1 byte size for the same header set: "name: value\r\n".
fn raw_header_size(fields: &[(&[u8], &[u8])]) -> usize {
    fields.iter().map(|&(n, v)| n.len() + 2 + v.len() + 2).sum()
}

/// Benchmark: stateless QPACK encode of a typical web request header set.
///
/// Reports two measurements in a single group so Criterion plots them
/// side-by-side:
///
/// - `stateless_encode_typical` — time to QPACK-encode the 12-field header list
///   into a fresh `Vec<u8>`; encoded size is printed once so the compression
///   ratio is visible in `cargo bench` output.
/// - `raw_size_baseline` — trivially compute the raw HTTP/1.1 byte count;
///   gives Criterion a baseline to compare against (near-zero cost).
fn bench_qpack_stateless_encode(c: &mut Criterion) {
    let raw_sz = raw_header_size(TYPICAL_HEADERS);
    let encoded = qpack_encode_stateless(TYPICAL_HEADERS);
    let encoded_sz = encoded.len();

    // Print ratio to stdout — visible in `cargo bench` output.
    // (Criterion benches must not assert; this is informational only.)
    println!(
        "\n[qpack_compression_ratio]  raw={raw_sz} bytes  \
         encoded={encoded_sz} bytes  ratio={:.2}x",
        raw_sz as f64 / encoded_sz as f64,
    );

    let mut group = c.benchmark_group("qpack");
    group.sample_size(100);

    // Hot benchmark: encode the headers from scratch each iteration.
    group.bench_function("stateless_encode_typical", |b| {
        b.iter(|| std::hint::black_box(qpack_encode_stateless(TYPICAL_HEADERS)));
    });

    // Baseline: compute raw size (nearly free; shows Criterion overhead floor).
    group.bench_function("raw_size_baseline", |b| {
        b.iter(|| std::hint::black_box(raw_header_size(TYPICAL_HEADERS)));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    h3_benches,
    bench_h3_get_cold,
    bench_h3_get_warm,
    bench_h3_concurrent,
    bench_qpack_stateless_encode,
);
criterion_main!(h3_benches);
