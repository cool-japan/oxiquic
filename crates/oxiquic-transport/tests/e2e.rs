//! End-to-end tests for the OxiQUIC transport over real UDP loopback.
//!
//! These exercise the full Pure-Rust stack — long/short-header packet coding,
//! header + packet protection, CRYPTO-frame-driven rustls TLS 1.3 handshake,
//! ACKs, 1-RTT keys, streams and connection close — across genuine
//! `tokio::net::UdpSocket` datagrams on `127.0.0.1`. The crypto runs entirely
//! through `oxiquic_crypto::quic_crypto_provider` (no ring / aws-lc-rs).

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// Build a matched (client, server) rustls config pair backed by a self-signed
/// Ed25519 cert for `localhost`, using the OxiQUIC Pure-Rust crypto provider.
fn config_pair() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust self-signed cert");

    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("client TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("server TLS1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server single cert");

    (Arc::new(client), Arc::new(server))
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

/// M1: client and server complete the QUIC/TLS handshake exchanging real UDP
/// datagrams on 127.0.0.1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m1_handshake_completes_over_udp() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        assert!(!conn.is_closed(), "server connection should be open");
        // The server must have learned the client's transport parameters.
        assert!(
            conn.peer_transport_params().is_some(),
            "server has client transport params"
        );
        conn
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    assert!(!conn.is_closed(), "client connection should be open");
    assert!(
        conn.peer_transport_params().is_some(),
        "client has server transport params"
    );

    let server_conn = server_task.await.expect("server task");
    drop((conn, server_conn));
}

/// M2: a full handshake followed by a clean application-level close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m2_handshake_then_clean_close() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        // Give the client time to send its CONNECTION_CLOSE, then observe it.
        for _ in 0..10 {
            conn.drive().await.expect("drive");
            if conn.is_closed() {
                break;
            }
        }
        conn.is_closed()
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    conn.close(0, b"bye").await.expect("close");

    let server_saw_close = server_task.await.expect("server task");
    assert!(server_saw_close, "server observed the connection close");
}

/// M3: client opens a bidirectional stream and sends bytes; the server receives
/// them in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m3_stream_data_delivered_in_order() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        let (_id, bytes, _fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server reads stream data");
        bytes
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, b"hello", false)
        .await
        .expect("send stream data");

    let received = server_task.await.expect("server task");
    assert_eq!(received, b"hello", "server received the bytes in order");
}

/// End-goal echo demo: client opens a stream, sends "hello", the server echoes
/// it back on the same stream, and the client reads it.
///
/// NOTE: this is the project's nominal "M5" demo, but it runs over lossless
/// loopback and therefore exercises the M1–M3 path only (handshake, 1-RTT,
/// streams). It is NOT a validation of M4 loss detection/retransmission or M5
/// NewReno congestion control / flow-control enforcement — those subsystems are
/// not implemented (see the crate docs and TODO). The demo passing here means
/// the public API composes end to end, not that congestion control works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lossless_echo_round_trip_demo() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        let (id, bytes, _fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server reads request");
        // Echo the bytes back on the same (bidirectional) stream.
        conn.send(id, &bytes, false).await.expect("server echoes");
        // Keep the connection alive long enough for the echo to be delivered.
        for _ in 0..10 {
            conn.drive().await.expect("drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, b"hello", false)
        .await
        .expect("client sends hello");

    let (echoed, _fin) = conn.read(stream).await.expect("client reads echo");
    assert_eq!(echoed, b"hello", "client read back the echoed bytes");

    server_task.await.expect("server task");
}
