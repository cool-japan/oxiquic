//! Tests for the background-driven connection API (`DrivenConnection`,
//! `SendStreamHandle`, `RecvStreamHandle`).
//!
//! Each test performs a real QUIC handshake over UDP loopback, then exercises
//! the [`tokio::io::AsyncWrite`] / [`tokio::io::AsyncRead`] interfaces.

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (mirrors e2e.rs helpers to keep this file self-contained)
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
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Full handshake → `into_driven` → `open_bidi_stream` → write bytes from
/// client → read on server side using `accept_uni_or_bidi_data` (old API on
/// server side, driven API on client side).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driven_async_read_write() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept connection, receive data via old API, echo back.
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        let (_sid, received, _fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server reads data");
        received
    });

    // Client: connect, convert to DrivenConnection, open a stream, send bytes.
    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let driven = conn.into_driven();
    let (mut send, _recv) = driven.open_bidi_stream().await.expect("open bidi stream");

    let payload = b"driven hello from async write";
    send.write_all(payload).await.expect("write_all");
    send.flush().await.expect("flush");

    let received = server_task.await.expect("server task");
    assert_eq!(
        received, payload,
        "server received the exact bytes sent by the driven client"
    );
}

/// Verify that `tokio::io::AsyncWriteExt::write_all` works end-to-end on a
/// `SendStreamHandle` across a real QUIC connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn use_tokio_io_copy() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        let (_sid, data, _fin) = conn.accept_uni_or_bidi_data().await.expect("server reads");
        data
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = conn.into_driven();
    let (mut send, _recv) = driven.open_bidi_stream().await.expect("open bidi stream");

    // Use tokio::io::copy to pipe from a Cursor into the stream handle.
    let src_data: Vec<u8> = (0u8..=127).collect();
    let mut cursor = std::io::Cursor::new(src_data.clone());
    tokio::io::copy(&mut cursor, &mut send)
        .await
        .expect("tokio::io::copy");
    send.flush().await.expect("flush after copy");

    let received = server_task.await.expect("server task");
    assert_eq!(
        received, src_data,
        "all bytes from tokio::io::copy arrived in order"
    );
}

/// Verify the three new 0.1.3 additions:
///   (a) `QuicConnection::peer_addr()` — server-side accepted connection reports
///       the client's local address as its peer address.
///   (b) `DrivenConnection::peer_addr()` — value survives the `into_driven()`
///       transition.
///   (c) `DrivenConnection::is_closed()` — flips from `false` to `true` after
///       the connection is closed and the driver task exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_addr_and_is_closed() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server task: accept, check peer_addr, convert to driven, return addresses.
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");

        // (a) QuicConnection::peer_addr() on the server side should be Some(_).
        let server_side_peer_addr = conn
            .peer_addr()
            .expect("server QuicConnection::peer_addr() must be Some after handshake");

        // Convert to driven and verify peer_addr survives.
        let driven = conn.into_driven();

        // (b) DrivenConnection::peer_addr() must equal the address we read above.
        let driven_peer_addr = driven
            .peer_addr()
            .expect("DrivenConnection::peer_addr() must be Some after into_driven");
        assert_eq!(
            server_side_peer_addr, driven_peer_addr,
            "peer_addr must be identical before and after into_driven"
        );

        // (c) is_closed must be false right after construction.
        assert!(
            !driven.is_closed(),
            "is_closed must be false on a live connection"
        );

        // Close and drain so the driver task exits.
        driven.close(0, b"").await.expect("close");
        // Give the driver task a moment to exit.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            driven.is_closed(),
            "is_closed must be true after close + driver exit"
        );

        (server_side_peer_addr, driven_peer_addr)
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let client_local_addr = client.local_addr().expect("client local addr");

    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    // (a) Client QuicConnection::peer_addr() should equal the server address.
    let client_peer = conn
        .peer_addr()
        .expect("client QuicConnection::peer_addr() must be Some");
    assert_eq!(
        client_peer, server_addr,
        "client peer_addr must equal the server bind address"
    );

    let (server_side_peer_addr, driven_peer_addr) = server_task.await.expect("server task");

    // The server's peer address for this connection must equal the client's local address.
    assert_eq!(
        server_side_peer_addr, client_local_addr,
        "server-side peer_addr must equal client local_addr"
    );
    assert_eq!(
        driven_peer_addr, client_local_addr,
        "DrivenConnection::peer_addr must equal client local_addr"
    );

    // (c) Client side: is_closed after close.
    let driven_client = conn.into_driven();
    assert!(
        !driven_client.is_closed(),
        "client is_closed must be false initially"
    );
    driven_client.close(0, b"").await.expect("close");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        driven_client.is_closed(),
        "client is_closed must be true after close + driver exit"
    );
}

/// Verify that after `into_driven`, the server can also use `DrivenConnection`
/// and both sides exchange data through `AsyncRead`/`AsyncWrite` handles.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driven_both_sides_echo() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        // Server waits for a stream to arrive, then converts to driven mode to
        // reply. We read the first message via the legacy API (which is simpler
        // here because the client opens the stream) then echo it back.
        let (sid, request, _fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server reads request");
        // Echo back on the same stream.
        conn.send(sid, &request, false)
            .await
            .expect("server echoes");
        // Keep connection alive.
        for _ in 0..20 {
            conn.drive().await.expect("drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let driven = conn.into_driven();
    let (mut send, mut recv) = driven.open_bidi_stream().await.expect("open bidi stream");

    let payload = b"ping from driven client";
    send.write_all(payload).await.expect("write_all");
    send.flush().await.expect("flush");

    // Read the echo back via the AsyncRead handle.
    let mut echo_buf = vec![0u8; payload.len()];
    recv.read_exact(&mut echo_buf)
        .await
        .expect("read echo from server");

    assert_eq!(
        echo_buf.as_slice(),
        payload.as_ref(),
        "client received the echoed bytes via AsyncRead"
    );

    server_task.await.expect("server task");
}
