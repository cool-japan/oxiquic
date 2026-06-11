//! Tests for custom ALPN protocol negotiation on raw QUIC connections.
//!
//! Verifies that:
//! * both sides report the negotiated protocol via `QuicConnection::negotiated_alpn()`.
//! * raw QUIC connections without ALPN work correctly and return `None`.
//! * `ServerEndpointBuilder::with_alpn_protocols` correctly sets the protocol list.

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, ServerEndpointBuilder, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a matched (client, server) rustls config pair with the given ALPN
/// protocols set on both sides.
fn config_pair_with_alpn(protocols: &[&[u8]]) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust self-signed cert");

    let alpn: Vec<Vec<u8>> = protocols.iter().map(|p| p.to_vec()).collect();

    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("client TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn.clone();

    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("server TLS1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server single cert");
    server.alpn_protocols = alpn;

    (Arc::new(client), Arc::new(server))
}

/// Build a matched config pair with no ALPN set on either side.
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

/// Custom ALPN protocol identifier used throughout these tests.
const TEST_PROTO: &[u8] = b"test-proto/1.0";

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Both sides advertise the same custom ALPN identifier; after the handshake
/// `negotiated_alpn()` must return that identifier on both the client and
/// server connections.
///
/// Uses `ServerEndpointBuilder::with_alpn_protocols` to set the server ALPN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_alpn_roundtrip() {
    let (client_cfg, server_cfg) = config_pair_with_alpn(&[TEST_PROTO]);
    let transport = TransportConfig::default();

    // Use ServerEndpointBuilder::with_alpn_protocols to configure the server.
    // The server_cfg already has alpn_protocols set (via config_pair_with_alpn),
    // but calling with_alpn_protocols again exercises the builder method and
    // verifies idempotent behaviour.
    let server = ServerEndpointBuilder::new(loopback(), server_cfg, transport.clone())
        .with_alpn_protocols(&[TEST_PROTO])
        .build()
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        conn.negotiated_alpn()
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let client_alpn = conn.negotiated_alpn();
    let server_alpn = server_task.await.expect("server task");

    assert_eq!(
        client_alpn.as_deref(),
        Some(TEST_PROTO),
        "client must report the negotiated ALPN protocol"
    );
    assert_eq!(
        server_alpn.as_deref(),
        Some(TEST_PROTO),
        "server must report the same negotiated ALPN protocol"
    );
}

/// A raw QUIC connection where neither side sets ALPN must complete the
/// handshake successfully and `negotiated_alpn()` must return `None` on both
/// endpoints — no panic, no error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alpn_not_set_does_not_panic() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        conn.negotiated_alpn()
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let client_alpn = conn.negotiated_alpn();
    let server_alpn = server_task.await.expect("server task");

    assert!(
        client_alpn.is_none(),
        "no ALPN should be negotiated when neither side sets protocols"
    );
    assert!(
        server_alpn.is_none(),
        "server should also report no ALPN when none was configured"
    );
}

/// `ServerEndpointBuilder::with_alpn_protocols` correctly overrides ALPN
/// configured at construction time.  Builds a server config with no initial
/// ALPN then adds the protocol via the builder; the client must see it
/// negotiated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_endpoint_builder_with_alpn_protocols() {
    let (client_cfg, server_cfg_base) = config_pair();
    let transport = TransportConfig::default();

    // Client must advertise the protocol too, otherwise there's nothing to
    // negotiate.  Set it directly on the client config.
    let mut client_cfg_inner = (*client_cfg).clone();
    client_cfg_inner.alpn_protocols = vec![TEST_PROTO.to_vec()];
    let client_cfg_with_alpn = Arc::new(client_cfg_inner);

    // Server uses the builder method exclusively (no ALPN in server_cfg_base).
    let server = ServerEndpointBuilder::new(loopback(), server_cfg_base, transport.clone())
        .with_alpn_protocols(&[TEST_PROTO])
        .build()
        .await
        .expect("bind server via builder");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        conn.negotiated_alpn()
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg_with_alpn, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let client_alpn = conn.negotiated_alpn();
    let server_alpn = server_task.await.expect("server task");

    assert_eq!(
        client_alpn.as_deref(),
        Some(TEST_PROTO),
        "builder with_alpn_protocols must set protocol visible to client"
    );
    assert_eq!(
        server_alpn.as_deref(),
        Some(TEST_PROTO),
        "builder with_alpn_protocols must set protocol visible to server"
    );
}
