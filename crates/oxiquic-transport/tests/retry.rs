//! Retry packet (RFC 9000 §17.2.5, RFC 9001 §5.8) end-to-end tests.
//!
//! These tests verify the full Retry flow end-to-end: the server sends Retry
//! when `retry_enabled`, the client processes it and retransmits its Initial
//! with the token, and the handshake completes successfully.

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─── Shared helpers ──────────────────────────────────────────────────────────

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

// ─── Unit tests (no I/O) ─────────────────────────────────────────────────────

/// RFC 9001 §5.8: computing and verifying the Retry Integrity Tag must round-trip.
#[test]
fn retry_integrity_tag_roundtrip() {
    use oxiquic_transport::packet::{compute_retry_integrity_tag, verify_retry_integrity_tag};

    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    // Minimal Retry-like bytes (just checking the tag API).
    let pseudo_packet = b"\xff\x00\x00\x00\x01\x00\x08hello-token";

    let tag = compute_retry_integrity_tag(&odcid, pseudo_packet).expect("compute tag");
    assert_eq!(tag.len(), 16, "tag must be 16 bytes");

    // Build the "full" packet = pseudo_packet + tag.
    let mut full = pseudo_packet.to_vec();
    full.extend_from_slice(&tag);

    assert!(
        verify_retry_integrity_tag(&odcid, &full),
        "tag should verify against the same odcid"
    );
}

/// A tag computed with a different ODCID must NOT verify.
#[test]
fn retry_integrity_tag_wrong_odcid_fails() {
    use oxiquic_transport::packet::{compute_retry_integrity_tag, verify_retry_integrity_tag};

    let odcid = [1u8; 8];
    let wrong_odcid = [2u8; 8];
    let pkt = b"\xff\x00\x00\x00\x01\x00token-data";

    let tag = compute_retry_integrity_tag(&odcid, pkt).expect("tag");
    let mut full = pkt.to_vec();
    full.extend_from_slice(&tag);

    assert!(
        !verify_retry_integrity_tag(&wrong_odcid, &full),
        "tag must not verify with wrong odcid"
    );
}

/// `encode_retry_packet` should produce a packet whose integrity tag verifies.
#[test]
fn retry_packet_encodes_valid_tag() {
    use oxiquic_transport::packet::{encode_retry_packet, verify_retry_integrity_tag};

    let scid = [0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04];
    let dcid = [0x11, 0x22, 0x33, 0x44]; // client SCID echoed as our DCID
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let token = b"test-retry-token";

    let pkt = encode_retry_packet(&scid, &dcid, &odcid, token)
        .expect("encode_retry_packet returned None");

    // Integrity tag verification uses the ODCID as pseudo-packet prefix.
    assert!(
        verify_retry_integrity_tag(&odcid, &pkt),
        "encoded Retry packet's integrity tag should verify"
    );

    // The first byte should have Header Form=1, Fixed=1, Type=0b11 (Retry).
    assert_eq!(
        pkt[0] & 0xF0,
        0xF0,
        "first byte: Header Form + Fixed + Retry type"
    );
}

/// Token generation + validation round-trips correctly.
#[test]
fn retry_token_roundtrip() {
    let mut config = TransportConfig::new().retry(true).retry_secret([42u8; 32]);
    let odcid = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().expect("addr");

    let token = config.generate_retry_token(&odcid, peer);
    let recovered = config
        .validate_retry_token(&token, peer)
        .expect("token should be valid");
    assert_eq!(recovered, odcid, "recovered ODCID should match original");
}

/// A token produced for one peer address must NOT validate for a different peer.
#[test]
fn retry_token_wrong_addr_fails() {
    let mut config = TransportConfig::new().retry(true).retry_secret([7u8; 32]);
    let odcid = [0xABu8; 8];
    let peer1: std::net::SocketAddr = "127.0.0.1:5000".parse().expect("addr");
    let peer2: std::net::SocketAddr = "127.0.0.2:5000".parse().expect("addr");

    let token = config.generate_retry_token(&odcid, peer1);
    assert!(
        config.validate_retry_token(&token, peer2).is_none(),
        "token for peer1 must not validate for peer2"
    );
}

/// An empty token must not validate.
#[test]
fn retry_token_empty_is_invalid() {
    let config = TransportConfig::new().retry(true).retry_secret([99u8; 32]);
    let peer: std::net::SocketAddr = "127.0.0.1:7777".parse().expect("addr");
    assert!(
        config.validate_retry_token(&[], peer).is_none(),
        "empty token must not validate"
    );
}

// ─── Integration test: full Retry round-trip ─────────────────────────────────

/// The key end-to-end test: server has `retry_enabled`, client connects.
/// Sequence:
///   1. Client sends Initial without token.
///   2. Server sends Retry.
///   3. Client processes Retry, re-keys Initial space, re-sends with token.
///   4. Server validates token, creates connection, completes handshake.
///   5. Client's `retry_count()` is 1 (proves the Retry actually happened).
///   6. Handshake succeeds end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_sends_retry_without_token() {
    let (client_cfg, server_cfg) = config_pair();

    // Server transport with Retry enabled.
    let server_transport = TransportConfig::default()
        .retry(true)
        .retry_secret([0xAB; 32]);

    // Client transport has default settings (no retry-specific config needed).
    let client_transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, server_transport)
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Accept in background.
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        assert!(!conn.is_closed(), "server connection should be open");
        assert!(
            conn.peer_transport_params().is_some(),
            "server has client transport params"
        );
        conn
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, client_transport)
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

    // Confirm that the Retry actually happened (retry_count is exposed for
    // testing purposes).
    assert_eq!(
        conn.retry_count(),
        1,
        "client should have processed exactly one Retry packet"
    );

    let _server_conn = server_task.await.expect("server task");
}

/// Stream data still flows correctly after a Retry-gated handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_then_stream_data_delivered() {
    let (client_cfg, server_cfg) = config_pair();

    let server_transport = TransportConfig::default()
        .retry(true)
        .retry_secret([0xCD; 32]);
    let client_transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, server_transport)
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

    let client = ClientEndpoint::bind(loopback(), client_cfg, client_transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    assert_eq!(conn.retry_count(), 1, "Retry round-trip happened");

    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, b"hello-after-retry", false)
        .await
        .expect("send stream data");

    let received = server_task.await.expect("server task");
    assert_eq!(received, b"hello-after-retry");
}
