//! Integration tests for RFC 9000 §10.3 stateless reset detection.
//!
//! A stateless reset is recognised by the receiving endpoint when:
//!   (a) the packet is ≥ 21 bytes long, and
//!   (b) the last 16 bytes match a stateless reset token for one of the
//!       active connection IDs the peer issued to us via NEW_CONNECTION_ID.
//!
//! After a completed handshake the server has issued additional CIDs (each
//! with its own token) via NEW_CONNECTION_ID; the client stores these in its
//! `peer_cid_pool`.  A fake packet whose trailing 16 bytes equal any one of
//! those tokens must cause `client.handle_datagram` to return
//! `Err(OxiQuicError::StatelessReset)`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_core::OxiQuicError;
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{Connection, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─── Helpers (identical pattern to other integration tests) ──────────────────

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

/// Build a matched client+server connection pair (after the first Initial
/// exchange, before the handshake completes).
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
    let mut client = client;
    let mut first = Vec::new();
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

/// RFC 9000 §10.3: after a completed handshake the client has received at least
/// one `NEW_CONNECTION_ID` from the server and therefore has at least one
/// non-zero stateless reset token in its peer CID pool.  A fake short-header
/// packet whose last 16 bytes equal that token (and whose total length is ≥ 21)
/// must be identified as a stateless reset and cause
/// `handle_datagram` to return `Err(OxiQuicError::StatelessReset)`.
#[test]
fn stateless_reset_detected() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    assert!(client.is_established(), "client must be established");
    assert!(server.is_established(), "server must be established");

    // After handshake the server issues additional CIDs (NEW_CONNECTION_ID)
    // each with a stateless reset token.  The client stores these in its
    // peer_cid_pool.  There must be at least two entries: the initial seq-0
    // placeholder (all-zeros) and at least one real token.
    let tokens = client.peer_stateless_reset_tokens();
    assert!(
        tokens.len() >= 2,
        "expected at least 2 peer CID pool entries after handshake, got {}",
        tokens.len()
    );

    // Find the first non-zero token (the server's real stateless reset token
    // delivered in a NEW_CONNECTION_ID frame; seq-0 has a zero placeholder).
    let real_token = tokens
        .iter()
        .find(|t| **t != [0u8; 16])
        .copied()
        .expect("at least one non-zero stateless reset token must exist after handshake");

    // Build a fake stateless reset packet: ≥ 21 bytes of pseudo-random header
    // garbage followed by the 16-byte token (RFC 9000 §10.3.1).
    // The first byte must have the Fixed Bit (0x40) set and the Header Form
    // bit (0x80) clear so the dispatcher routes it through recv_short_packet.
    let mut fake_packet = vec![0u8; 64];
    // Set the first byte to a plausible short-header value (Fixed Bit set,
    // short header, arbitrary Key Phase / Packet Number Length bits).
    fake_packet[0] = 0x40;
    // Overwrite the last 16 bytes with the real stateless reset token.
    let len = fake_packet.len();
    fake_packet[len - 16..].copy_from_slice(&real_token);

    let now = Instant::now();
    let result = client.handle_datagram(now, &mut fake_packet);

    match result {
        Err(OxiQuicError::StatelessReset) => {
            // Correct: RFC 9000 §10.3 stateless reset detected.
        }
        Err(other) => panic!("expected StatelessReset, got a different error: {other}"),
        Ok(()) => panic!("expected StatelessReset error, but handle_datagram returned Ok(())"),
    }
}

/// A fake packet that is too short (< 21 bytes) must NOT be identified as a
/// stateless reset, even if its last 16 bytes happen to match a known token.
#[test]
fn stateless_reset_too_short_ignored() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let tokens = client.peer_stateless_reset_tokens();
    let real_token = tokens
        .iter()
        .find(|t| **t != [0u8; 16])
        .copied()
        .expect("at least one non-zero stateless reset token after handshake");

    // Build a short packet: exactly 20 bytes (below the 21-byte threshold).
    // The last 16 bytes match the token.
    let mut short_packet = vec![0u8; 20];
    short_packet[0] = 0x40;
    short_packet[4..].copy_from_slice(&real_token);

    let now = Instant::now();
    let result = client.handle_datagram(now, &mut short_packet);

    // Must NOT be a StatelessReset — the packet is too short.
    assert!(
        !matches!(result, Err(OxiQuicError::StatelessReset)),
        "packet shorter than 21 bytes must not trigger stateless reset detection"
    );
}

/// A fake packet of adequate length but with an unrecognised token must NOT
/// trigger stateless reset detection.
#[test]
fn stateless_reset_unknown_token_ignored() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    // Build a 64-byte fake packet whose last 16 bytes are all 0xFF, which is
    // extremely unlikely to match any real token.
    let mut fake_packet = vec![0u8; 64];
    fake_packet[0] = 0x40;
    let len = fake_packet.len();
    fake_packet[len - 16..].fill(0xFF);

    let now = Instant::now();
    let result = client.handle_datagram(now, &mut fake_packet);

    assert!(
        !matches!(result, Err(OxiQuicError::StatelessReset)),
        "packet with unknown token must not trigger stateless reset detection"
    );
}
