//! Path migration (RFC 9000 §9) tests.
//!
//! Two scenarios driven entirely in memory via the synchronous [`Connection`]
//! state machine:
//!
//! 1. `path_challenge_frame_encode_decode` — unit test confirming that
//!    `Frame::PathChallenge` / `Frame::PathResponse` round-trip through the
//!    wire encoder and decoder unchanged.
//!
//! 2. `path_challenge_response_roundtrip` — integration test: after the
//!    handshake the client initiates a PATH_CHALLENGE, both sides exchange
//!    packets, and the client's `path_validated()` becomes `true`.  Stream
//!    data continues to flow without interruption after the probe.
//!
//! Note: the following RFC 9000 §9 items are **not** tested here (known
//! limitations to address in a later milestone):
//! * Anti-amplification limits for unvalidated paths.
//! * NEW_CONNECTION_ID issuance during migration.
//! * PATH_CHALLENGE retransmission on packet loss.
//! * Separate congestion state per path.
//! * Abandoned-path detection / challenge timeout.

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

/// PATH_CHALLENGE and PATH_RESPONSE frames round-trip through the wire encoder
/// and decoder with the correct frame-type byte and data payload preserved.
#[test]
fn path_challenge_frame_encode_decode() {
    use oxiquic_transport::coding::Buf;
    use oxiquic_transport::frame::{decode_frame, Frame};

    // PATH_CHALLENGE round-trip.
    let data: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    let mut wire = Vec::new();
    Frame::PathChallenge(data).encode(&mut wire);
    assert_eq!(wire.len(), 9, "PATH_CHALLENGE wire length must be 9");
    assert_eq!(wire[0], 0x1a, "frame type byte");
    assert_eq!(&wire[1..], &data, "data bytes");
    let mut buf = Buf::new(&wire);
    match decode_frame(&mut buf).expect("decode PATH_CHALLENGE") {
        Frame::PathChallenge(d) => assert_eq!(d, data),
        other => panic!("expected PathChallenge, got {other:?}"),
    }
    assert!(buf.is_empty(), "buffer fully consumed");

    // PATH_RESPONSE round-trip.
    let resp: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut wire2 = Vec::new();
    Frame::PathResponse(resp).encode(&mut wire2);
    assert_eq!(wire2.len(), 9, "PATH_RESPONSE wire length must be 9");
    assert_eq!(wire2[0], 0x1b, "frame type byte");
    assert_eq!(&wire2[1..], &resp, "data bytes");
    let mut buf2 = Buf::new(&wire2);
    match decode_frame(&mut buf2).expect("decode PATH_RESPONSE") {
        Frame::PathResponse(d) => assert_eq!(d, resp),
        other => panic!("expected PathResponse, got {other:?}"),
    }
    assert!(buf2.is_empty(), "buffer fully consumed");

    // Zero data round-trips correctly.
    let mut wire3 = Vec::new();
    Frame::PathChallenge([0u8; 8]).encode(&mut wire3);
    let mut buf3 = Buf::new(&wire3);
    match decode_frame(&mut buf3).expect("decode zero PathChallenge") {
        Frame::PathChallenge(d) => assert_eq!(d, [0u8; 8]),
        other => panic!("expected PathChallenge, got {other:?}"),
    }
}

/// After a handshake the client initiates a PATH_CHALLENGE. After one round
/// of `exchange_all`, the server has echoed back a PATH_RESPONSE and the
/// client's `path_validated()` returns `true`. Stream data also continues
/// to flow correctly before and after the probe.
#[test]
fn path_challenge_response_roundtrip() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    // Send some data before the path probe to confirm baseline works.
    let stream = client.open_bidi().expect("open bidi stream");
    client
        .send_stream(stream, b"before probe", false)
        .expect("send before probe");
    exchange_all(&mut client, &mut server, now);

    let (pre_data, _fin) = server.read_stream(stream).expect("read before probe");
    assert_eq!(pre_data, b"before probe", "pre-probe data delivered");

    // Client initiates a PATH_CHALLENGE; should succeed post-handshake.
    client
        .initiate_path_challenge()
        .expect("initiate_path_challenge accepted");

    // PATH_CHALLENGE arrives at server; server queues PATH_RESPONSE.
    // PATH_RESPONSE arrives at client; client sets path_validated = true.
    exchange_all(&mut client, &mut server, now);

    assert!(
        client.path_validated(),
        "path must be validated after a full PATH_CHALLENGE / PATH_RESPONSE exchange"
    );

    // Data must still flow correctly after the probe.
    client
        .send_stream(stream, b"after probe", true)
        .expect("send after probe");
    exchange_all(&mut client, &mut server, now);

    let (post_data, fin) = server.read_stream(stream).expect("read after probe");
    assert_eq!(post_data, b"after probe", "post-probe data delivered");
    assert!(fin, "stream should be finished");
}

/// A PATH_CHALLENGE from the server is echoed back by the client (RFC 9000
/// §8.2.2: every PATH_CHALLENGE must be answered with PATH_RESPONSE).
#[test]
fn server_challenge_echoed_by_client() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    // Server initiates the challenge this time.
    server
        .initiate_path_challenge()
        .expect("server initiate_path_challenge");

    exchange_all(&mut client, &mut server, now);

    assert!(
        server.path_validated(),
        "server path must be validated after client echoes PATH_RESPONSE"
    );
}

/// `initiate_path_challenge` returns an error before 1-RTT keys are ready.
#[test]
fn path_challenge_requires_1rtt_keys() {
    let (mut client, _server) = make_pair();
    // Client is still in the handshaking state — no 1-RTT keys yet.
    assert!(
        client.is_handshaking(),
        "client should be handshaking at this point"
    );
    let err = client
        .initiate_path_challenge()
        .expect_err("must fail before 1-RTT keys");
    // Verify the error message is meaningful.
    let msg = err.to_string();
    assert!(
        msg.contains("1-RTT") || msg.contains("connection error"),
        "error message should mention 1-RTT: {msg}"
    );
}
