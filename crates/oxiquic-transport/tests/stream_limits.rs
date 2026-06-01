//! Tests for MAX_STREAMS, STREAMS_BLOCKED, and NEW_TOKEN functionality
//! (RFC 9000 §4.6, §19.11, §19.14, §8.1.3).

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_core::TransportParams;
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, Connection, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (self-contained; mirrors stream_reset.rs)
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

fn addr(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], port))
}

/// Extract `(dcid, scid)` bytes from a long-header Initial datagram.
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

/// Build a matched client+server `Connection` pair (TLS handshake not yet done).
fn make_pair_with_params(
    client_params: TransportParams,
    server_params: TransportParams,
) -> (Connection, Connection) {
    let (client_cfg, server_cfg) = config_pair();

    let client = Connection::new_client(
        client_cfg,
        ServerName::try_from("localhost").expect("server name"),
        addr(4433),
        client_params,
        Default::default(),
        Default::default(),
    )
    .expect("client conn");

    let now = Instant::now();
    let mut first = Vec::new();
    let mut client = client;
    client
        .poll_transmit(now, &mut first)
        .expect("client initial");
    let (dcid, scid) = parse_initial_cids(&first).expect("parse initial cids");

    let server = Connection::new_server(
        server_cfg,
        oxiquic_core::ConnectionId::new(dcid),
        oxiquic_core::ConnectionId::new(scid),
        addr(40000),
        server_params,
        Default::default(),
        Default::default(),
    )
    .expect("server conn");

    let mut server = server;
    let mut owned = first.clone();
    server
        .handle_datagram(now, &mut owned)
        .expect("server first datagram");

    (client, server)
}

/// Exchange all pending datagrams in both directions until quiescent.
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

/// Run the TLS handshake to completion.
fn complete_handshake(client: &mut Connection, server: &mut Connection) {
    let now = Instant::now();
    for _ in 0..100 {
        exchange_all(client, server, now);
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("handshake did not complete");
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// When `peer_max_streams_bidi` is reached, `open_bidi` must return an error
/// and queue a `STREAMS_BLOCKED` frame for transmission.
#[test]
fn streams_blocked_emitted_at_limit() {
    // Build params where the client only allows the server to open 1 bidi stream.
    // The client is the one opening streams to the server, so we limit
    // server's initial_max_streams_bidi (how many bidi streams the *client* may open).
    let client_params = TransportConfig::default()
        .idle_timeout(Duration::from_secs(30))
        .to_transport_params();
    // Server advertises that it will let client open at most 1 bidi stream.
    let mut server_params = client_params.clone();
    server_params.initial_max_streams_bidi = 1;

    let (mut client, mut server) = make_pair_with_params(client_params.clone(), server_params);
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    // First stream should succeed (limit is 1, index 0 is OK).
    let result1 = client.open_bidi();
    assert!(
        result1.is_ok(),
        "first bidi stream should open successfully (within limit 1)"
    );

    // Second stream should fail (index 1 >= limit 1).
    let result2 = client.open_bidi();
    assert!(
        result2.is_err(),
        "second bidi stream must fail when limit is 1"
    );

    // After the failure, the STREAMS_BLOCKED flag should be set.
    // We verify this by confirming the connection has something to send.
    let mut buf = Vec::new();
    let sent = client.poll_transmit(now, &mut buf);
    assert!(
        sent.is_some() && !buf.is_empty(),
        "connection must have output after STREAMS_BLOCKED is queued"
    );
}

/// A server issues a NEW_TOKEN post-handshake; the client must receive and store it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_issues_new_token_client_stores_it() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(
        "127.0.0.1:0".parse().expect("loopback"),
        server_cfg,
        transport.clone(),
    )
    .await
    .expect("server bind");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept");
        // Server should NOT have received a NEW_TOKEN (only client gets them).
        // Just hold the connection alive briefly.
        drop(conn);
    });

    let client = ClientEndpoint::bind(
        "127.0.0.1:0".parse().expect("loopback"),
        client_cfg,
        transport,
    )
    .await
    .expect("client bind");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("connect");

    // Drive the connection to give NEW_TOKEN time to arrive.
    for _ in 0..10 {
        let _ = conn.drive().await;
    }

    // The client should have received a NEW_TOKEN from the server.
    let token = conn.take_received_token();
    assert!(
        token.is_some(),
        "client must have received a NEW_TOKEN from the server post-handshake"
    );
    let token_bytes = token.expect("token must be Some");
    assert!(
        !token_bytes.is_empty(),
        "NEW_TOKEN payload must not be empty"
    );

    server_task.await.expect("server task completed");
}
