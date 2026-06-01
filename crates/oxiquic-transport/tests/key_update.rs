//! Key update (RFC 9001 §6) tests.
//!
//! Two test scenarios driven entirely in memory via the synchronous
//! [`Connection`] state machine:
//!
//! 1. `key_phase_bit_changes_after_update` — verifies that after
//!    `initiate_key_update()` the `key_update_count` advances and both sides
//!    continue to communicate successfully.
//!
//! 2. `key_update_roundtrip` — full integration test: client initiates a key
//!    update, both sides adopt the new keys, data continues to flow without
//!    interruption.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{Connection, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
    // first(1) version(4) dcid_len(1) dcid scid_len(1) scid
    let dcid_len = *datagram.get(5)? as usize;
    let dcid = datagram.get(6..6 + dcid_len)?.to_vec();
    let scid_len = *datagram.get(6 + dcid_len)? as usize;
    let scid = datagram
        .get(7 + dcid_len..7 + dcid_len + scid_len)?
        .to_vec();
    Some((dcid, scid))
}

/// Build a matched client and server connection pair.
fn make_pair() -> (Connection, Connection) {
    let (client_cfg, server_cfg) = config_pair();
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
        params,
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

// ─── Tests ────────────────────────────────────────────────────────────────────

/// After `initiate_key_update()`, the key phase bit changes and both sides
/// continue to decrypt each other's packets successfully (RFC 9001 §6).
///
/// We verify this via `key_update_count()`:
/// * Client counter increments on `initiate_key_update_now` (the first send).
/// * Server counter increments when it receives a packet with the new phase
///   and successfully decrypts it using its pre-derived next-epoch keys.
#[test]
fn key_phase_bit_changes_after_update() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    assert_eq!(client.key_update_count(), 0, "no updates before initiation");
    assert_eq!(server.key_update_count(), 0);

    // Initiate a key update on the client.
    let accepted = client.initiate_key_update(now);
    assert!(accepted, "key update accepted after handshake");

    // Exchange datagrams: the first client packet carries the new key phase bit.
    // The server detects the phase flip, successfully decrypts using pre-derived
    // next-epoch keys, and updates its own epoch.
    exchange_all(&mut client, &mut server, now);

    assert_eq!(client.key_update_count(), 1, "client completed one update");
    assert_eq!(server.key_update_count(), 1, "server completed one update");
}

/// Full key update roundtrip: client initiates a key update; both sides adopt
/// the new keys; stream data continues to flow correctly before and after the
/// update.
#[test]
fn key_update_roundtrip() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();
    let stream = client.open_bidi().expect("open bidi stream");

    // Deliver data before the update.
    client
        .send_stream(stream, b"before update", false)
        .expect("send before");
    exchange_all(&mut client, &mut server, now);

    let (pre_data, _fin) = server.read_stream(stream).expect("read before");
    assert_eq!(pre_data, b"before update", "pre-update data");

    // Initiate the key update.
    assert!(client.initiate_key_update(now), "update accepted");
    exchange_all(&mut client, &mut server, now);
    assert_eq!(client.key_update_count(), 1, "client count after update");
    assert_eq!(server.key_update_count(), 1, "server count after update");

    // Send data under the new keys.
    client
        .send_stream(stream, b"after update", true)
        .expect("send after");
    exchange_all(&mut client, &mut server, now);

    let (post_data, fin) = server.read_stream(stream).expect("read after");
    assert_eq!(post_data, b"after update", "post-update data");
    assert!(fin, "stream should be finished");
}

/// Multiple sequential key updates between client and server both succeed.
#[test]
fn multiple_sequential_key_updates() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let stream = client.open_bidi().expect("open bidi stream");
    let now = Instant::now();

    // First update: client-initiated.
    assert!(client.initiate_key_update(now), "first update");
    exchange_all(&mut client, &mut server, now);
    assert_eq!(client.key_update_count(), 1, "after first update (client)");
    assert_eq!(server.key_update_count(), 1, "after first update (server)");

    // Advance the clock well past the 3-PTO cooldown.
    let now2 = now + Duration::from_secs(10);

    // Second update: server-initiated.
    assert!(
        server.initiate_key_update(now2),
        "server update after cooldown"
    );
    exchange_all(&mut client, &mut server, now2);
    assert_eq!(client.key_update_count(), 2, "after second update (client)");
    assert_eq!(server.key_update_count(), 2, "after second update (server)");

    // Data must still flow correctly after two updates.
    client
        .send_stream(stream, b"still works", true)
        .expect("send");
    exchange_all(&mut client, &mut server, now2);
    let (data, fin) = server.read_stream(stream).expect("read");
    assert_eq!(data, b"still works", "data after 2 updates");
    assert!(fin, "stream finished");
}

/// `initiate_key_update` returns `false` during the 3-PTO cooldown.
#[test]
fn key_update_cooldown_prevents_rapid_updates() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    // First update succeeds.
    assert!(client.initiate_key_update(now), "first update");
    exchange_all(&mut client, &mut server, now);
    assert_eq!(client.key_update_count(), 1);

    // Immediate second attempt is rejected (cooldown still active).
    assert!(
        !client.initiate_key_update(now),
        "second update rejected during cooldown"
    );
    assert_eq!(client.key_update_count(), 1, "no spurious update");
}
