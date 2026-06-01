//! Integration tests for unidirectional QUIC streams (RFC 9000 §2.1).
//!
//! QUIC stream-ID type bits (RFC 9000 Table 1):
//!   bit 0 = initiator (0 = client, 1 = server)
//!   bit 1 = direction (0 = bidirectional, 1 = unidirectional)
//!
//! So:
//!   0x00 / type 0 → client-initiated bidirectional
//!   0x01 / type 1 → server-initiated bidirectional
//!   0x02 / type 2 → client-initiated unidirectional
//!   0x03 / type 3 → server-initiated unidirectional
//!
//! All tests use real QUIC handshakes over UDP loopback and the `DrivenConnection`
//! high-level API (`open_uni_stream` / `accept_uni_stream`).
//!
//! Note: `SendStreamHandle` does not expose a public `stream_id()` method; stream ID
//! type verification is done from the receive side via `RecvStreamHandle::stream_id()`.

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (self-contained; mirrors integration.rs — no shared helper crate)
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
// Test 1: client_uni_stream_send_server_recv
// ─────────────────────────────────────────────────────────────────────────────

/// Client opens a unidirectional (send-only) stream, writes a payload, then
/// shuts it down with FIN. The server accepts the incoming uni stream with
/// `accept_uni_stream` and reads all bytes until EOF.
///
/// Validates:
/// - `DrivenConnection::open_uni_stream` returns a `SendStreamHandle`.
/// - `DrivenConnection::accept_uni_stream` surfaces the stream as a `RecvStreamHandle`.
/// - The resulting stream ID on the receive side has type bits `0x2` (client-initiated uni).
/// - All bytes arrive in order; EOF is signalled when the sender shuts down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_uni_stream_send_server_recv() {
    const PAYLOAD: &[u8] = b"hello from client uni stream";

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept connection, then accept the incoming uni stream and read it.
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        let driven = conn.into_driven();

        // Accept the uni-directional stream from the client.
        let mut recv = driven
            .accept_uni_stream()
            .await
            .expect("accept_uni_stream on server");

        // Client-initiated uni-streams have type bits 0x2 (bit-0 = initiator 0=client,
        // bit-1 = direction 1=unidirectional).
        let sid = recv.stream_id();
        assert_eq!(
            sid.as_u64() & 0x3,
            2,
            "client-initiated uni stream must have type bits 0x2 (got stream_id {:#x})",
            sid.as_u64()
        );

        // Read until EOF (sender shut down signals FIN).
        let mut received = Vec::new();
        recv.read_to_end(&mut received)
            .await
            .expect("server read_to_end on uni stream");
        received
    });

    // Client: connect, convert to driven, open a uni stream, send and shutdown.
    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = conn.into_driven();

    let mut send = driven
        .open_uni_stream()
        .await
        .expect("client open_uni_stream");

    send.write_all(PAYLOAD).await.expect("client write_all");
    // Shut down the stream to send FIN; this signals EOF to the receiver.
    send.shutdown().await.expect("client shutdown uni stream");

    // Collect server result with a 10-second safety timeout.
    let received = timeout(Duration::from_secs(10), server_task)
        .await
        .expect("client_uni_stream_send_server_recv: test timed out after 10 s")
        .expect("server task panicked");

    assert_eq!(
        received, PAYLOAD,
        "server must receive exactly the bytes sent by the client uni stream"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: server_uni_stream_send_client_recv
// ─────────────────────────────────────────────────────────────────────────────

/// Server opens a unidirectional (send-only) stream, writes a payload, and
/// shuts it down. The client accepts the stream with `accept_uni_stream` and
/// reads all bytes until EOF.
///
/// Validates:
/// - Server-initiated uni streams have type bits `0x3` (bit-0=1=server, bit-1=1=uni).
/// - The driven API works symmetrically: either side can open or accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_uni_stream_send_client_recv() {
    const PAYLOAD: &[u8] = b"hello from server uni stream";

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept connection, open a uni stream, write data, shut down.
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        let driven = conn.into_driven();

        let mut send = driven
            .open_uni_stream()
            .await
            .expect("server open_uni_stream");

        send.write_all(PAYLOAD).await.expect("server write_all");
        // FIN: signal EOF to the client.
        send.shutdown().await.expect("server shutdown uni stream");

        // Keep the driven connection alive while the client reads.
        tokio::time::sleep(Duration::from_millis(800)).await;
    });

    // Client: connect, convert to driven, accept the incoming uni stream.
    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = conn.into_driven();

    // Accept the server-initiated uni stream.
    let mut recv = timeout(Duration::from_secs(10), driven.accept_uni_stream())
        .await
        .expect("server_uni_stream_send_client_recv: timed out waiting for server uni stream")
        .expect("client accept_uni_stream failed");

    // Server-initiated uni streams have type bits 0x3 (bit-0=1=server, bit-1=1=uni).
    let sid = recv.stream_id();
    assert_eq!(
        sid.as_u64() & 0x3,
        3,
        "server-initiated uni stream must have type bits 0x3 on the receive end (got {:#x})",
        sid.as_u64()
    );

    let mut received = Vec::new();
    recv.read_to_end(&mut received)
        .await
        .expect("client read_to_end on server uni stream");

    assert_eq!(
        received, PAYLOAD,
        "client must receive exactly the bytes sent by the server uni stream"
    );

    // Wait for the server task to finish cleanly.
    timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server_uni_stream_send_client_recv: server task timed out")
        .expect("server task panicked");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: multiple_client_uni_streams_sequential
// ─────────────────────────────────────────────────────────────────────────────

/// Client opens three uni streams in sequence, each with a unique payload.
/// The server accepts all three and verifies data integrity and stream ID ordering.
///
/// Validates:
/// - Each successive uni stream gets a new stream ID with the same type bits (0x2).
/// - Stream IDs are monotonically increasing (index field advances).
/// - No data cross-contamination between streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_client_uni_streams_sequential() {
    const N: usize = 3;
    let payloads: [&[u8]; N] = [b"first-uni", b"second-uni", b"third-uni"];

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept N uni streams, read each to completion.
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accept");
        let driven = conn.into_driven();

        let mut all_received: Vec<(u64, Vec<u8>)> = Vec::with_capacity(N);
        for i in 0..N {
            let mut recv = driven
                .accept_uni_stream()
                .await
                .expect("server accept_uni_stream");

            // Every client-initiated uni stream must have type bits 0x2.
            let sid_val = recv.stream_id().as_u64();
            assert_eq!(
                sid_val & 0x3,
                2,
                "stream {i}: type bits must be 0x2 (got {sid_val:#x})"
            );

            let mut data = Vec::new();
            recv.read_to_end(&mut data).await.expect("read_to_end");
            all_received.push((sid_val, data));
        }
        all_received
    });

    // Client: open N uni streams one after another.
    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = conn.into_driven();

    for (i, payload) in payloads.iter().enumerate() {
        let mut send = driven.open_uni_stream().await.expect("open_uni_stream");
        send.write_all(payload).await.expect("write_all");
        send.shutdown().await.expect("shutdown");
        // Small yield between opens to avoid saturating the channel.
        if i < N - 1 {
            tokio::task::yield_now().await;
        }
    }

    // Collect with a 10-second safety timeout.
    let all_received = timeout(Duration::from_secs(10), server_task)
        .await
        .expect("multiple_client_uni_streams_sequential: test timed out after 10 s")
        .expect("server task panicked");

    assert_eq!(
        all_received.len(),
        N,
        "server must have received {N} streams"
    );

    // Stream IDs must be strictly monotonically increasing.
    let sids: Vec<u64> = all_received.iter().map(|(id, _)| *id).collect();
    for window in sids.windows(2) {
        assert!(
            window[1] > window[0],
            "stream IDs must be strictly increasing: {:#x} must be < {:#x}",
            window[0],
            window[1]
        );
    }

    // Payloads must match (streams arrive in order of creation since they are
    // sequential — open, write, shutdown — one at a time).
    for (i, ((_, got), want)) in all_received.iter().zip(payloads.iter()).enumerate() {
        assert_eq!(
            got.as_slice(),
            *want,
            "stream {i}: expected {:?}, got {:?}",
            String::from_utf8_lossy(want),
            String::from_utf8_lossy(got)
        );
    }
}
