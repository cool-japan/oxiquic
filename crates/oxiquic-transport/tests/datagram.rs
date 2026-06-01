//! Integration tests for unreliable DATAGRAM frames (RFC 9221).
//!
//! Tests verify that:
//! 1. A client with `max_datagram_frame_size > 0` can send a datagram to a
//!    server that also advertises support, and the server receives it.
//! 2. A client attempting to send a datagram to a peer that advertised
//!    `max_datagram_frame_size = 0` gets a `Connection` error.

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (self-contained; mirrors uni_stream.rs)
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: datagram_echo_client_to_server
// ─────────────────────────────────────────────────────────────────────────────

/// Client sends a DATAGRAM to the server; the server receives it via
/// `recv_datagram`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_echo_client_to_server() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default().max_datagram_frame_size(1200);

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("server bind");
    let server_addr = server.local_addr().expect("server addr");

    let payload = b"hello datagram payload".to_vec();
    let payload_clone = payload.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("accept");
        // Pump until a datagram arrives.
        let dgram = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(dgram) = conn.recv_datagram().await {
                    return dgram;
                }
            }
        })
        .await
        .expect("datagram arrived within 5 seconds");
        assert_eq!(
            dgram, payload_clone,
            "received datagram must match sent payload"
        );
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("client bind");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("connect");

    conn.send_datagram(payload)
        .await
        .expect("send datagram succeeded");

    server_task
        .await
        .expect("server task completed without error");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: datagram_disabled_peer_returns_error
// ─────────────────────────────────────────────────────────────────────────────

/// Sending a datagram to a peer that did NOT advertise datagram support
/// (`max_datagram_frame_size = 0`) must return an error immediately.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_disabled_peer_returns_error() {
    let (client_cfg, server_cfg) = config_pair();
    // Server has datagrams disabled (default).
    let server_transport = TransportConfig::default();
    // Client advertises datagram support.
    let client_transport = TransportConfig::default().max_datagram_frame_size(1200);

    let server = ServerEndpoint::bind(loopback(), server_cfg, server_transport)
        .await
        .expect("server bind");
    let server_addr = server.local_addr().expect("server addr");

    // Accept in background (we need the handshake to complete).
    let _server_task = tokio::spawn(async move {
        // Just accept; we don't assert anything server-side.
        let _ = server.accept().await;
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, client_transport)
        .await
        .expect("client bind");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("connect");

    // The server advertised max_datagram_frame_size=0 → send_datagram must fail.
    let result = conn.send_datagram(b"test payload".to_vec()).await;
    assert!(
        result.is_err(),
        "sending to a datagram-disabled peer must return an error"
    );
}
