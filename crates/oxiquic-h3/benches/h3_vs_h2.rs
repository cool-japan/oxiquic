//! HTTP/3 vs HTTP/2 latency comparison benchmark.
//!
//! Expected behavior:
//! - H3 typically shows lower latency for small requests on stable loopback (no HOL blocking)
//! - H2 may show comparable or lower latency on very stable local connections (less UDP overhead)
//! - Real-world H3 advantage appears on packet loss and mobile networks
//! - Run with: `cargo bench -p oxiquic-h3 --bench h3_vs_h2`
//!
//! # Design
//!
//! The H2 server is built with raw `hyper` (HTTP/2 over TLS via `tokio-rustls`)
//! so the comparison does not introduce a cross-workspace dependency on
//! `oxihttp-client`.  The H3 server uses `oxiquic-transport` + `oxiquic-h3`
//! with the same self-signed Ed25519 certificate.
//!
//! ## Benchmark groups
//!
//! - `h3_vs_h2/h3_get_1kb`   — H3 GET returning 1 KiB body
//! - `h3_vs_h2/h3_get_64kb`  — H3 GET returning 64 KiB body
//! - `h3_vs_h2/h2_get_1kb`   — H2 GET returning 1 KiB body
//! - `h3_vs_h2/h2_get_64kb`  — H2 GET returning 64 KiB body
//!
//! Each iteration measures one complete request-response round trip (connection
//! pre-established outside the hot loop for warm-path measurements).
//!
//! ## Sustained throughput group
//!
//! - `h3_vs_h2_throughput/h3_256kb` — H3: transfer 256 KiB payload, report bytes/s
//! - `h3_vs_h2_throughput/h3_1mb`   — H3: transfer 1 MiB payload, report bytes/s
//! - `h3_vs_h2_throughput/h2_256kb` — H2: transfer 256 KiB payload, report bytes/s
//! - `h3_vs_h2_throughput/h2_1mb`   — H2: transfer 1 MiB payload, report bytes/s
//!
//! The sustained-throughput group uses larger payloads than the latency group so
//! it exercises the flow-control and congestion-window paths that a single small
//! GET does not stress.  Both H3 and H2 use a single pre-established connection
//! per `(protocol, size)` pair; each iteration transfers the full payload once.

use std::convert::Infallible;
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_h3::{accept_h3, connect_h3};
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("create tokio runtime for h3_vs_h2 bench")
}

/// Build self-signed Ed25519 cert + matched client/server rustls configs.
/// Returns `(client_cfg, server_cfg, cert_der)`.
fn config_pair() -> (Arc<ClientConfig>, Arc<ServerConfig>, Vec<u8>) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed Ed25519 cert for h3_vs_h2 bench");
    let cert_der_bytes = ck.cert_der.clone();
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("trust self-signed cert for h3_vs_h2 bench");

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

    (Arc::new(client), Arc::new(server), cert_der_bytes)
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("parse loopback addr")
}

// ─────────────────────────────────────────────────────────────────────────────
// H3 server helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn an H3 server that responds to each incoming request with a fixed
/// `body_size`-byte payload.  Returns the bound address.
async fn spawn_h3_server(server_cfg: Arc<ServerConfig>, body_size: usize) -> SocketAddr {
    let transport = TransportConfig::default();
    let server_ep = ServerEndpoint::bind(loopback(), server_cfg, transport)
        .await
        .expect("bind H3 server for h3_vs_h2 bench");
    let server_addr = server_ep.local_addr().expect("H3 server local addr");

    tokio::spawn(async move {
        loop {
            let conn = match server_ep.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let body_size = body_size;
            tokio::spawn(async move {
                let driven = conn.into_driven();
                let mut h3_conn = match accept_h3(driven).await {
                    Ok(c) => c,
                    Err(_) => return,
                };

                loop {
                    let resolver = match h3_conn.accept().await {
                        Ok(Some(r)) => r,
                        _ => break,
                    };
                    let body = Bytes::from(vec![0xABu8; body_size]);
                    tokio::spawn(async move {
                        let (_req, mut stream) = match resolver.resolve_request().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .expect("build H3 200 response");
                        if stream.send_response(resp).await.is_err() {
                            return;
                        }
                        let _ = stream.send_data(body).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });

    server_addr
}

// ─────────────────────────────────────────────────────────────────────────────
// H2 server helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn a hyper HTTP/2 server over TLS, responding with a fixed-size body.
/// Returns `(server_addr, cert_der)`.
async fn spawn_h2_server(server_cfg: Arc<ServerConfig>, body_size: usize) -> SocketAddr {
    // Set ALPN to negotiate h2 for HTTP/2.
    let mut server_cfg_inner = (*server_cfg).clone();
    server_cfg_inner.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg_inner));

    let listener = TcpListener::bind(loopback())
        .await
        .expect("bind H2 server for h3_vs_h2 bench");
    let server_addr = listener.local_addr().expect("H2 server local addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let body_size = body_size;
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        io,
                        service_fn(move |_req: hyper::Request<Incoming>| async move {
                            let body = Full::new(Bytes::from(vec![0xABu8; body_size]));
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(body)
                                    .expect("build H2 200 response"),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    server_addr
}

// ─────────────────────────────────────────────────────────────────────────────
// H3 client helpers — warm (connection pre-established outside hot loop)
// ─────────────────────────────────────────────────────────────────────────────

/// One warm-path H3 GET: send a request, receive headers + body, assert 200.
async fn do_h3_get_warm(
    send_req: &mut h3::client::SendRequest<oxiquic_transport::OxiQuicOpenStreams, Bytes>,
) {
    let req = Request::builder()
        .method("GET")
        .uri("https://localhost/")
        .body(())
        .expect("build H3 GET request");
    let mut req_stream = send_req.send_request(req).await.expect("H3 send_request");
    req_stream.finish().await.expect("H3 finish request");
    let resp = req_stream.recv_response().await.expect("H3 recv_response");
    assert_eq!(resp.status(), StatusCode::OK);
    // Drain body.
    while let Some(_chunk) = req_stream.recv_data().await.expect("H3 recv_data") {}
}

// ─────────────────────────────────────────────────────────────────────────────
// H2 client helpers — warm (hyper connection pre-established outside hot loop)
// ─────────────────────────────────────────────────────────────────────────────

/// Connect a hyper HTTP/2 client to `server_addr` using `client_cfg` for TLS.
/// Returns the `SendRequest` handle.
async fn connect_h2_client(
    client_cfg: Arc<ClientConfig>,
    server_addr: SocketAddr,
) -> hyper::client::conn::http2::SendRequest<Empty<Bytes>> {
    use tokio_rustls::TlsConnector;

    let connector = TlsConnector::from(client_cfg);
    let tcp = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("H2 TCP connect");
    let domain = rustls::pki_types::ServerName::try_from("localhost")
        .expect("parse server name")
        .to_owned();
    let tls = connector
        .connect(domain, tcp)
        .await
        .expect("H2 TLS connect");
    let io = TokioIo::new(tls);
    let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("H2 handshake");
    tokio::spawn(conn);
    sender
}

/// Build a rustls `ClientConfig` that trusts `cert_der` and advertises `h2` via ALPN.
///
/// Uses the same `quic_crypto_provider` as the H3 path (pure-Rust, no ring/aws-lc-rs).
fn make_h2_client_cfg(cert_der: &[u8]) -> Arc<ClientConfig> {
    let provider = Arc::new(quic_crypto_provider());
    let cert = CertificateDer::from(cert_der.to_vec());
    let mut roots = RootCertStore::empty();
    roots
        .add(cert)
        .expect("trust self-signed cert for H2 client");

    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("build H2 client TLS 1.3 config")
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Advertise h2 so the server negotiates HTTP/2.
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

/// One warm-path H2 GET: send a request on a pre-established hyper connection,
/// read all body bytes, assert 200.
async fn do_h2_get_warm(
    send_req: &mut hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    url: &str,
) {
    let uri: hyper::Uri = url.parse().expect("parse H2 request URI");
    let req = hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .body(Empty::<Bytes>::new())
        .expect("build H2 GET request");
    let resp = send_req.send_request(req).await.expect("H2 send_request");
    assert_eq!(resp.status(), 200u16);
    // Drain body.
    let mut body = resp.into_body();
    while let Some(frame) = body.frame().await {
        let _ = frame.expect("H2 body frame");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark group: h3_vs_h2
// ─────────────────────────────────────────────────────────────────────────────

fn bench_h3_vs_h2(c: &mut Criterion) {
    let mut group = c.benchmark_group("h3_vs_h2");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &size_label in &["1kb", "64kb"] {
        let body_size: usize = if size_label == "1kb" { 1024 } else { 64 * 1024 };
        group.throughput(Throughput::Bytes(body_size as u64));

        // ── H3 warm bench ────────────────────────────────────────────────────

        let h3_id = BenchmarkId::new("h3_get", size_label);
        group.bench_with_input(h3_id, &body_size, |b, &body_size| {
            let rt = make_runtime();

            let (client_cfg, server_cfg, _cert_der) = config_pair();
            let transport = TransportConfig::default();

            // Set up server + pre-establish H3 connection.
            // The server loop accepts unbounded requests via per-request
            // tokio::spawn, so no iteration cap is needed.
            let (server_addr, mut send_req) = rt.block_on(async {
                let server_addr = spawn_h3_server(server_cfg, body_size).await;

                let client_ep = ClientEndpoint::bind(loopback(), client_cfg, transport)
                    .await
                    .expect("bind H3 client for h3_vs_h2 bench");
                let quic_conn = client_ep
                    .connect(server_addr, "localhost")
                    .await
                    .expect("H3 client connect");
                let driven = quic_conn.into_driven();
                let (_h3_conn, send_req) = connect_h3(driven).await.expect("connect_h3");

                (server_addr, send_req)
            });

            let _ = server_addr; // suppress unused warning

            b.iter(|| {
                rt.block_on(async { do_h3_get_warm(&mut send_req).await });
            });
        });

        // ── H2 warm bench ────────────────────────────────────────────────────

        let h2_id = BenchmarkId::new("h2_get", size_label);
        group.bench_with_input(h2_id, &body_size, |b, &body_size| {
            let rt = make_runtime();

            let (_client_cfg, server_cfg, cert_der) = config_pair();
            let h2_client_cfg = make_h2_client_cfg(&cert_der);

            // Set up H2 server + pre-establish hyper h2 connection.
            let (server_addr, mut send_req) = rt.block_on(async {
                let server_addr = spawn_h2_server(server_cfg, body_size).await;
                let send_req = connect_h2_client(h2_client_cfg, server_addr).await;
                (server_addr, send_req)
            });

            let h2_url = format!("https://localhost:{}/", server_addr.port());

            b.iter(|| {
                rt.block_on(async { do_h2_get_warm(&mut send_req, &h2_url).await });
            });
        });
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Sustained throughput: H3 vs H2 — larger payloads, measures bytes/s
//
// The latency bench (`bench_h3_vs_h2`) uses 1 KiB and 64 KiB payloads to
// measure per-request round-trip latency.  This bench uses 256 KiB and 1 MiB
// payloads to measure *sustained* throughput — i.e. how many bytes per second
// each protocol can deliver on a single pre-established connection over loopback.
//
// The Throughput::Bytes annotation instructs criterion to compute and display
// bytes/s automatically.
// ─────────────────────────────────────────────────────────────────────────────

/// Issue one H3 GET that returns `body_size` bytes; drain all body bytes.
/// Returns the number of bytes received.
async fn do_h3_get_bytes(
    send_req: &mut h3::client::SendRequest<oxiquic_transport::OxiQuicOpenStreams, Bytes>,
    body_size: usize,
) -> usize {
    let req = Request::builder()
        .method("GET")
        .uri("https://localhost/data")
        .body(())
        .expect("build H3 GET throughput bench");
    let mut stream = send_req
        .send_request(req)
        .await
        .expect("H3 send_request throughput bench");
    stream.finish().await.expect("H3 finish throughput bench");
    let resp = stream
        .recv_response()
        .await
        .expect("H3 recv_response throughput bench");
    assert_eq!(resp.status(), StatusCode::OK);
    let mut total = 0usize;
    while let Some(chunk) = stream
        .recv_data()
        .await
        .expect("H3 recv_data throughput bench")
    {
        use bytes::Buf as _;
        total += chunk.remaining();
    }
    assert_eq!(
        total, body_size,
        "H3 throughput: received {} bytes, expected {}",
        total, body_size
    );
    total
}

/// Issue one H2 GET that returns `body_size` bytes; drain all body bytes.
/// Returns the number of bytes received.
async fn do_h2_get_bytes(
    send_req: &mut hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    url: &str,
    body_size: usize,
) -> usize {
    let uri: hyper::Uri = url.parse().expect("parse H2 throughput bench URI");
    let req = hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .body(Empty::<Bytes>::new())
        .expect("build H2 GET throughput bench");
    let resp = send_req
        .send_request(req)
        .await
        .expect("H2 send_request throughput bench");
    assert_eq!(resp.status(), 200u16);
    let mut body = resp.into_body();
    let mut total = 0usize;
    while let Some(frame) = body.frame().await {
        if let Ok(f) = frame {
            if let Ok(data) = f.into_data() {
                total += data.len();
            }
        }
    }
    assert_eq!(
        total, body_size,
        "H2 throughput: received {} bytes, expected {}",
        total, body_size
    );
    total
}

/// Benchmark: sustained throughput comparison of H3 vs H2.
///
/// Payload sizes: 256 KiB (`256kb`) and 1 MiB (`1mb`).  For each size, a
/// long-lived server is spun up once outside `b.iter`, and a single
/// pre-established connection is reused for every iteration — so each
/// `b.iter` call transfers exactly one payload (no handshake cost).
///
/// `criterion::Throughput::Bytes` is set so criterion reports bytes/s.
fn bench_h3_vs_h2_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("h3_vs_h2_throughput");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(90));

    for &(size_label, body_size) in &[("256kb", 256 * 1024usize), ("1mb", 1024 * 1024usize)] {
        group.throughput(Throughput::Bytes(body_size as u64));

        // ── H3 sustained throughput ──────────────────────────────────────────

        let h3_id = BenchmarkId::new("h3", size_label);
        group.bench_with_input(h3_id, &body_size, |b, &body_size| {
            let rt = make_runtime();

            let (client_cfg, server_cfg, _cert_der) = config_pair();
            let transport = TransportConfig::default();

            let (server_addr, mut send_req) = rt.block_on(async {
                let server_addr = spawn_h3_server(server_cfg, body_size).await;

                let client_ep = ClientEndpoint::bind(loopback(), client_cfg, transport)
                    .await
                    .expect("bind H3 client for throughput bench");
                let quic_conn = client_ep
                    .connect(server_addr, "localhost")
                    .await
                    .expect("H3 client connect throughput bench");
                let driven = quic_conn.into_driven();
                let (_h3_conn, send_req) = connect_h3(driven)
                    .await
                    .expect("connect_h3 throughput bench");

                (server_addr, send_req)
            });

            let _ = server_addr; // suppress unused warning

            b.iter(|| {
                rt.block_on(async {
                    let n = do_h3_get_bytes(&mut send_req, body_size).await;
                    black_box(n)
                });
            });
        });

        // ── H2 sustained throughput ──────────────────────────────────────────

        let h2_id = BenchmarkId::new("h2", size_label);
        group.bench_with_input(h2_id, &body_size, |b, &body_size| {
            let rt = make_runtime();

            let (_client_cfg, server_cfg, cert_der) = config_pair();
            let h2_client_cfg = make_h2_client_cfg(&cert_der);

            let (server_addr, mut send_req) = rt.block_on(async {
                let server_addr = spawn_h2_server(server_cfg, body_size).await;
                let send_req = connect_h2_client(h2_client_cfg, server_addr).await;
                (server_addr, send_req)
            });

            let h2_url = format!("https://localhost:{}/data", server_addr.port());

            b.iter(|| {
                rt.block_on(async {
                    let n = do_h2_get_bytes(&mut send_req, &h2_url, body_size).await;
                    black_box(n)
                });
            });
        });
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(h3_vs_h2_benches, bench_h3_vs_h2, bench_h3_vs_h2_throughput);
criterion_main!(h3_vs_h2_benches);
