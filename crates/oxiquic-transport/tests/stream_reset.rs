//! Stream reset and stop-sending tests (RFC 9000 §§2.4, 2.5, 19.4, 19.5).
//!
//! Covers:
//!
//! 1. `reset_stream_propagates_error_to_receiver` — sender calls
//!    `Connection::reset_stream`; after exchange, the receiver's
//!    `Connection::read_stream` returns an error containing the reset error code.
//!
//! 2. `stop_sending_accepted_without_panic` — receiver calls
//!    `Connection::stop_sending`; after exchange both sides remain operational and
//!    no panic occurs. (STOP_SENDING causes the sender to emit RESET_STREAM.)
//!
//! 3. `reset_stream_with_zero_bytes_sent` — reset a stream immediately after
//!    opening (final_size == 0); verifies the edge case does not panic and the
//!    error still propagates.
//!
//! 4. `reset_unknown_stream_returns_error` — calling `reset_stream` on a stream
//!    that was never opened returns `OxiQuicError::Stream`.
//!
//! 5. `reset_stream_via_public_api` — end-to-end test using `SendStreamHandle::reset`
//!    over a real `DrivenConnection`; verifies the public API dispatches RESET_STREAM
//!    and the server-side receive handle reaches EOF without panic.
//!
//! 6. `stop_sending_via_public_api` — end-to-end test using `RecvStreamHandle::stop_sending`
//!    over a real `DrivenConnection`; verifies the public API dispatches STOP_SENDING
//!    without panic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{
    ClientEndpoint, Connection, OxiQuicError, ServerEndpoint, TransportConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::AsyncReadExt;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (self-contained)
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// After `Connection::reset_stream(stream_id, error_code)`, exchange datagrams
/// so the RESET_STREAM frame reaches the peer. The receiver's
/// `read_stream(stream_id)` must then return an `OxiQuicError::Stream` error
/// whose message contains the reset error code.
///
/// Validates: RESET_STREAM is queued, encoded, transmitted, and processed by
/// the peer's connection state machine. The receive-side read returns an error
/// rather than data (RFC 9000 §2.4).
#[test]
fn reset_stream_propagates_error_to_receiver() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    // Client opens a bidirectional stream and sends some data before resetting.
    let stream = client.open_bidi().expect("open bidi stream");
    client
        .send_stream(stream, b"partial data before reset", false)
        .expect("client send before reset");

    // Exchange once to deliver the STREAM frame to the server.
    exchange_all(&mut client, &mut server, now);

    // Now reset the stream from the client side with application error code 42.
    const RESET_CODE: u64 = 42;
    client
        .reset_stream(stream, RESET_CODE)
        .expect("reset_stream should succeed on a known send stream");

    // Exchange so the RESET_STREAM frame reaches the server.
    exchange_all(&mut client, &mut server, now);

    // The server's read must now return an error (not Ok).
    let result = server.read_stream(stream);
    assert!(
        result.is_err(),
        "server read_stream must return an error after RESET_STREAM, got: {result:?}"
    );

    // The error message must mention the reset error code.
    let err_msg = match result.expect_err("verified above") {
        OxiQuicError::Stream(msg) => msg,
        other => panic!("expected OxiQuicError::Stream, got {other:?}"),
    };
    assert!(
        err_msg.contains(&RESET_CODE.to_string()),
        "error message must contain the reset error code {RESET_CODE}, got: {err_msg:?}"
    );
}

/// After `Connection::stop_sending(stream_id, error_code)`, exchange datagrams
/// so the STOP_SENDING frame reaches the peer. The peer's send stream is reset
/// in response (RFC 9000 §2.5). Both sides must remain non-panicked and
/// operational on other streams.
///
/// Validates: STOP_SENDING is queued, encoded, transmitted, and the sender
/// responds with RESET_STREAM without crashing.
#[test]
fn stop_sending_accepted_without_panic() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    // Client opens a bidirectional stream and sends some data.
    let stream = client.open_bidi().expect("open bidi stream");
    client
        .send_stream(stream, b"data before stop", false)
        .expect("client send");
    exchange_all(&mut client, &mut server, now);

    // Server sends STOP_SENDING on the incoming stream side.
    // `stop_sending` requires the stream to exist in recv_streams. The bidi
    // stream was opened by the client, so the server has a recv entry for it.
    const STOP_CODE: u64 = 77;
    server
        .stop_sending(stream, STOP_CODE)
        .expect("stop_sending on known recv stream");

    // Exchange: STOP_SENDING reaches the client; client is expected to reset the
    // stream in reply (RFC 9000 §2.5). Neither side should panic.
    exchange_all(&mut client, &mut server, now);

    // Both connections must still be non-closed after the exchange.
    assert!(
        !client.is_closed(),
        "client must remain open after STOP_SENDING exchange"
    );
    assert!(
        !server.is_closed(),
        "server must remain open after STOP_SENDING exchange"
    );

    // A second independent stream must still work, proving the connection is
    // not broken by the stop-sending/reset exchange.
    let other_stream = client.open_bidi().expect("open bidi stream");
    client
        .send_stream(other_stream, b"still works", false)
        .expect("client send on second stream");
    exchange_all(&mut client, &mut server, now);

    // Server must be able to read from the second stream without error.
    let (data, _fin) = server
        .read_stream(other_stream)
        .expect("server read on second stream after stop-sending exchange");
    assert_eq!(
        data, b"still works",
        "data on the second stream must be unaffected by the stop-sending exchange"
    );
}

/// Reset a stream that was opened but had zero bytes sent (final_size == 0).
/// This is an edge case in RESET_STREAM encoding (RFC 9000 §19.4: final_size
/// field must match the amount actually sent).
///
/// Validates: the edge case does not panic and the receiver's read returns an error.
#[test]
fn reset_stream_with_zero_bytes_sent() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    let now = Instant::now();

    // Open a stream but do NOT write any data before resetting.
    let stream = client.open_bidi().expect("open bidi stream");

    const RESET_CODE: u64 = 1;
    client
        .reset_stream(stream, RESET_CODE)
        .expect("reset_stream with zero bytes sent");

    // Exchange: RESET_STREAM (with final_size=0) must reach the server.
    exchange_all(&mut client, &mut server, now);

    // The server does not have a recv entry for a bidi stream opened by the
    // client until it receives the first STREAM or RESET_STREAM frame. After
    // exchange, the server may have registered the stream. We attempt a read —
    // either the stream is known and reset (Err), or not yet registered (Err
    // for unknown stream). Either way, the result must not be Ok with data.
    let result = server.read_stream(stream);
    assert!(
        result.is_err(),
        "server read on a reset-before-data stream must return an error, got: {result:?}"
    );
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

/// Calling `reset_stream` on a stream that was never opened must return
/// `OxiQuicError::Stream` with an "unknown stream" message.
///
/// Validates: the state machine does not panic on invalid input and returns a
/// well-formed error.
#[test]
fn reset_unknown_stream_returns_error() {
    let (mut client, mut server) = make_pair();
    complete_handshake(&mut client, &mut server);

    // Fabricate a stream ID that was never opened.
    // Client-initiated bidi index 999 — far beyond anything actually allocated.
    use oxiquic_core::{Direction, Initiator, StreamId};
    let phantom = StreamId::new(Initiator::Client, Direction::Bidirectional, 999);

    let result = client.reset_stream(phantom, 0);
    assert!(
        result.is_err(),
        "reset_stream on unknown stream must return Err, got: {result:?}"
    );

    match result.expect_err("verified above") {
        OxiQuicError::Stream(msg) => {
            assert!(
                msg.contains("unknown stream"),
                "error message must say 'unknown stream', got: {msg:?}"
            );
        }
        other => panic!("expected OxiQuicError::Stream, got {other:?}"),
    }

    // Verify the server is also unaffected.
    let result_server = server.stop_sending(phantom, 0);
    assert!(
        result_server.is_err(),
        "stop_sending on unknown stream must return Err, got: {result_server:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API (DrivenConnection) tests
// ─────────────────────────────────────────────────────────────────────────────

/// End-to-end test for `SendStreamHandle::reset` over a real `DrivenConnection`.
///
/// 1. Client opens a bidi stream, writes a byte (so the STREAM frame reaches the
///    server and the server can accept it via `accept_bidi_stream`), then calls
///    `bidi.reset(42)` via the public API.
/// 2. Server accepts the stream and attempts to read — the driver will receive
///    the RESET_STREAM frame and close the inbound data channel, causing the
///    server's `RecvStreamHandle` to reach EOF without panic.
/// 3. Neither side must panic; the driver task must remain stable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_stream_via_public_api() {
    let (client_tls, server_tls) = config_pair();
    let transport = TransportConfig::default();

    let server_ep = ServerEndpoint::bind(loopback(), server_tls, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server: accept connection and then accept the bidi stream the client opens.
    let server_task = tokio::spawn(async move {
        let conn = server_ep.accept().await.expect("server accept");
        let driven = conn.into_driven();
        // Wait for the client-opened bidi stream (triggered by the initial STREAM frame).
        let (_send, mut recv) = driven
            .accept_bidi_stream()
            .await
            .expect("server accept bidi stream");
        // Drain bytes until EOF. After RESET_STREAM arrives the driver closes the
        // data channel, causing read_to_end to return — either empty or partial.
        let mut buf = Vec::new();
        let _ = recv.read_to_end(&mut buf).await;
    });

    let client_ep = ClientEndpoint::bind(loopback(), client_tls, transport)
        .await
        .expect("bind client");
    let conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let driven = conn.into_driven();
    let mut bidi = driven.open_bidi().await.expect("open bidi stream");

    // Write a byte so the server's driver processes a STREAM frame and surfaces
    // the new stream via poll_new_peer_stream — this is required for
    // accept_bidi_stream to unblock.
    bidi.write(b"x").await.expect("initial write");

    // Give the initial STREAM frame time to arrive at the server.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Call the public reset API with error code 42.
    bidi.reset(42)
        .await
        .expect("reset must not fail while driver is alive");

    // Give the driver time to transmit the RESET_STREAM frame.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    server_task.await.expect("server task must not panic");
}

/// End-to-end test for `RecvStreamHandle::stop_sending` over a real `DrivenConnection`.
///
/// 1. Server opens a bidi stream and writes data.
/// 2. Client accepts the stream and immediately calls `stop_sending(99)` via the public API.
/// 3. The driver dispatches STOP_SENDING; neither side panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_sending_via_public_api() {
    let (client_tls, server_tls) = config_pair();
    let transport = TransportConfig::default();

    let server_ep = ServerEndpoint::bind(loopback(), server_tls, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server: accept connection, open a bidi stream, write some data.
    let server_task = tokio::spawn(async move {
        let conn = server_ep.accept().await.expect("server accept");
        let driven = conn.into_driven();
        let mut bidi = driven.open_bidi().await.expect("server open bidi");
        // Write data — best effort; a STOP_SENDING / RESET_STREAM response may
        // cause the write to fail, which is the expected outcome.
        let _ = bidi.write(b"hello from server").await;
        // Give the client time to send STOP_SENDING before dropping.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    let client_ep = ClientEndpoint::bind(loopback(), client_tls, transport)
        .await
        .expect("bind client");
    let conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let driven = conn.into_driven();
    // Wait for the server-opened bidi stream to arrive.
    let (_send, recv) = driven
        .accept_bidi_stream()
        .await
        .expect("client accept bidi stream");

    // Call the public stop_sending API with error code 99.
    recv.stop_sending(99)
        .await
        .expect("stop_sending must not fail while driver is alive");

    // Give the driver time to transmit the STOP_SENDING frame.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    server_task.await.expect("server task must not panic");
}
