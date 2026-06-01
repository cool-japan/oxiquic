//! Integration tests for OxiQUIC transport: multi-stream concurrency, large
//! payloads, connection statistics, and sequential stream isolation.
//!
//! Each test performs a real QUIC handshake over UDP loopback (127.0.0.1) and
//! exercises the public [`QuicConnection`] API end-to-end.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (self-contained; mirrors e2e.rs — no shared test-helper crate)
// ─────────────────────────────────────────────────────────────────────────────

/// Build a matched (client, server) rustls config pair backed by a self-signed
/// Ed25519 cert for `localhost`, using the OxiQUIC Pure-Rust crypto provider.
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
// Test 1: multi_stream_concurrent_echo
// ─────────────────────────────────────────────────────────────────────────────

/// Client opens 5 bidirectional streams in quick succession, each carrying a
/// unique payload. The server echoes every payload back on the same stream.
/// Client verifies that each echoed response starts with the expected prefix.
///
/// Validates: stream-level multiplexing, no cross-stream data contamination
/// under concurrent sends, and the `open_bidi` / `send` / `read` round-trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_stream_concurrent_echo() {
    const N: usize = 5;

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept N streams in whatever order they arrive, echo each back.
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        for _ in 0..N {
            let (id, bytes, _fin) = conn
                .accept_uni_or_bidi_data()
                .await
                .expect("server accept stream data");
            conn.send(id, &bytes, false).await.expect("server echo");
        }
        // Keep the connection alive long enough for all echoes to be delivered.
        for _ in 0..20 {
            conn.drive().await.expect("server drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    // Open all 5 streams and queue a unique payload on each.
    let mut stream_ids = Vec::with_capacity(N);
    for n in 0..N {
        let s = conn.open_bidi().expect("open bidi stream");
        conn.send(s, format!("stream-{n}").as_bytes(), false)
            .await
            .expect("client send");
        stream_ids.push(s);
    }

    // Read the echo back from every stream and verify it.
    for (n, sid) in stream_ids.into_iter().enumerate() {
        let (echoed, _fin) = conn.read(sid).await.expect("client read echo");
        assert!(
            echoed.starts_with(b"stream-"),
            "stream-{n}: echo should start with 'stream-', got {:?}",
            String::from_utf8_lossy(&echoed)
        );
        assert_eq!(
            echoed,
            format!("stream-{n}").into_bytes(),
            "stream-{n}: echoed bytes must exactly match what was sent"
        );
    }

    server_task.await.expect("server task");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: large_payload_single_stream
// ─────────────────────────────────────────────────────────────────────────────

/// Client sends a 16 KiB payload on a single bidi stream. The server
/// accumulates chunks until it has all 16384 bytes (spanning ~14 QUIC packets
/// at 1200-byte MTU), then echoes the whole buffer back. The client
/// accumulates and asserts byte-for-byte equality.
///
/// Validates: multi-packet reassembly, stream flow-control window, multiple
/// `send`/`recv` cycles inside a single stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_payload_single_stream() {
    const PAYLOAD_LEN: usize = 16384;
    let payload: Vec<u8> = vec![0xABu8; PAYLOAD_LEN];

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");

        // Wait for the first chunk to arrive, which tells us the stream id.
        let (stream_id, first_chunk, fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server accept first chunk");

        let mut received = first_chunk;
        let mut done = fin;

        // Accumulate until we have all PAYLOAD_LEN bytes or FIN.
        while received.len() < PAYLOAD_LEN && !done {
            let (chunk, f) = conn.read(stream_id).await.expect("server read next chunk");
            received.extend_from_slice(&chunk);
            done = f;
        }

        // Echo the complete buffer back on the same stream.
        conn.send(stream_id, &received, false)
            .await
            .expect("server echo large payload");

        // Keep alive long enough for the echo to be delivered.
        for _ in 0..30 {
            conn.drive().await.expect("server drive");
        }

        received
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, &payload, false)
        .await
        .expect("client send large payload");

    // Accumulate echoed bytes until we have PAYLOAD_LEN bytes.
    let mut echoed = Vec::with_capacity(PAYLOAD_LEN);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while echoed.len() < PAYLOAD_LEN {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for large echo (got {} / {} bytes)",
            echoed.len(),
            PAYLOAD_LEN
        );
        let (chunk, fin) = conn.read(stream).await.expect("client read echo chunk");
        echoed.extend_from_slice(&chunk);
        if fin {
            break;
        }
    }

    assert_eq!(
        echoed.len(),
        PAYLOAD_LEN,
        "client should accumulate exactly {} echoed bytes",
        PAYLOAD_LEN
    );
    assert_eq!(
        echoed, payload,
        "echoed bytes must be byte-for-byte identical to what was sent"
    );

    let server_received = server_task.await.expect("server task");
    assert_eq!(
        server_received.len(),
        PAYLOAD_LEN,
        "server should have accumulated exactly {} bytes",
        PAYLOAD_LEN
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: connection_stats_nonzero_after_exchange
// ─────────────────────────────────────────────────────────────────────────────

/// After a successful echo round-trip ("ping" → "ping"), `QuicConnection::stats()`
/// must report non-zero RTT, packets sent, and packets received.
///
/// Validates: `ConnectionStats` integration and that the RFC 9002 counters are
/// wired up through the public API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_stats_nonzero_after_exchange() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        let (id, bytes, _fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server reads ping");
        conn.send(id, &bytes, false)
            .await
            .expect("server echoes ping");
        // Drive to ensure the echo flush completes before dropping.
        for _ in 0..10 {
            conn.drive().await.expect("server drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, b"ping", false)
        .await
        .expect("client sends ping");

    let (echoed, _fin) = conn.read(stream).await.expect("client reads echo");
    assert_eq!(echoed, b"ping", "echo must match the sent payload");

    // Inspect statistics after the round-trip.
    let stats = conn.stats();

    assert!(
        stats.packets_sent > 0,
        "packets_sent should be > 0 after a full echo round-trip, got {}",
        stats.packets_sent
    );
    assert!(
        stats.packets_recv > 0,
        "packets_recv should be > 0 after a full echo round-trip, got {}",
        stats.packets_recv
    );
    // `rtt` is the latest RTT sample; `smoothed_rtt` is sticky once set.
    // At least one of them must be non-zero after a real ACK was received.
    assert!(
        stats.rtt > Duration::ZERO || stats.smoothed_rtt > Duration::ZERO,
        "RTT should be non-zero after exchange: rtt={:?} smoothed_rtt={:?}",
        stats.rtt,
        stats.smoothed_rtt
    );

    server_task.await.expect("server task");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: sequential_streams_no_interference
// ─────────────────────────────────────────────────────────────────────────────

/// Client opens stream A, sends "hello" with FIN, then opens stream B, sends
/// "world" with FIN. The server reads from each stream in the order they
/// arrive and asserts the correct data on each. Verifies that stream data is
/// not cross-contaminated when two streams are opened sequentially.
///
/// Validates: stream isolation — STREAM frames on different stream IDs are
/// delivered to the correct logical channel with no data leakage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequential_streams_no_interference() {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept the two streams in whatever order they arrive and collect
    // (stream_id, bytes) pairs.
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");

        // Accumulate results keyed by the stream id to handle any arrival order.
        let mut results: Vec<(oxiquic_core::StreamId, Vec<u8>)> = Vec::new();
        for _ in 0..2 {
            let (sid, bytes, _fin) = conn
                .accept_uni_or_bidi_data()
                .await
                .expect("server accept stream");
            results.push((sid, bytes));
        }
        // Drive to flush any pending ACKs before the task exits.
        for _ in 0..10 {
            conn.drive().await.expect("server drive");
        }
        results
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    // Open stream A, send "hello" with FIN.
    let stream_a = conn.open_bidi().expect("open bidi stream");
    conn.send(stream_a, b"hello", true)
        .await
        .expect("client sends hello on A");

    // Open stream B, send "world" with FIN.
    let stream_b = conn.open_bidi().expect("open bidi stream");
    conn.send(stream_b, b"world", true)
        .await
        .expect("client sends world on B");

    let results = server_task.await.expect("server task");
    assert_eq!(
        results.len(),
        2,
        "server should have received data on 2 streams"
    );

    // Build a lookup map: stream_id → received bytes.
    let mut map: std::collections::HashMap<oxiquic_core::StreamId, Vec<u8>> =
        results.into_iter().collect();

    let data_a = map
        .remove(&stream_a)
        .expect("stream A data must be present on server");
    let data_b = map
        .remove(&stream_b)
        .expect("stream B data must be present on server");

    assert_eq!(
        data_a,
        b"hello",
        "stream A should contain exactly 'hello', got {:?}",
        String::from_utf8_lossy(&data_a)
    );
    assert_eq!(
        data_b,
        b"world",
        "stream B should contain exactly 'world', got {:?}",
        String::from_utf8_lossy(&data_b)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: cubic_default_congestion_sends_data
// ─────────────────────────────────────────────────────────────────────────────

/// Proves that the default [`TransportConfig`] (which selects CUBIC as the
/// congestion algorithm) dispatches correctly and successfully routes 64 KiB
/// of data over a real UDP loopback handshake.
///
/// This is an end-to-end proof that the [`CongestionController`] dispatch enum
/// wiring works: the default `TransportConfig` selects `CongestionAlgorithm::Cubic`,
/// the client and server create connections with `CongestionController::Cubic`,
/// and the CUBIC controller allows data to flow without blocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cubic_default_congestion_sends_data() {
    const PAYLOAD_LEN: usize = 65536; // 64 KiB

    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i & 0xFF) as u8).collect();

    let (client_cfg, server_cfg) = config_pair();
    // TransportConfig::default() → CongestionAlgorithm::Cubic.
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");

        let (stream_id, first_chunk, fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server accept first chunk");

        let mut received = first_chunk;
        let mut done = fin;

        while received.len() < PAYLOAD_LEN && !done {
            let (chunk, f) = conn.read(stream_id).await.expect("server read chunk");
            received.extend_from_slice(&chunk);
            done = f;
        }

        // Echo back.
        conn.send(stream_id, &received, false)
            .await
            .expect("server echo");
        for _ in 0..30 {
            conn.drive().await.expect("server drive");
        }
        received
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, &payload, false)
        .await
        .expect("client send 64 KiB");

    let mut echoed = Vec::new();
    while echoed.len() < PAYLOAD_LEN {
        let (chunk, _fin) = conn.read(stream).await.expect("client read echo chunk");
        echoed.extend_from_slice(&chunk);
    }

    let server_received = server_task.await.expect("server task");
    assert_eq!(
        server_received.len(),
        PAYLOAD_LEN,
        "server must receive all bytes"
    );
    assert_eq!(echoed, payload, "echoed data must exactly match sent data");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: concurrent_streams_100
// ─────────────────────────────────────────────────────────────────────────────

/// Client opens 100 bidirectional streams simultaneously, sends a unique
/// `stream-{n}` payload on each, and reads the echo back. The server accepts
/// 100 streams in whatever order they arrive and echoes each payload on the
/// same stream.
///
/// Validates: QUIC stream multiplexing at scale, correct data routing across
/// 100 concurrent logical channels, and that the `max_concurrent_bidi_streams`
/// transport parameter is honoured for both sides of the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_streams_100() {
    const N: usize = 100;

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default().max_concurrent_bidi_streams(256);

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept N streams in whatever order, echo each payload back.
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        for _ in 0..N {
            let (id, bytes, _fin) = conn
                .accept_uni_or_bidi_data()
                .await
                .expect("server accept stream data");
            conn.send(id, &bytes, false).await.expect("server echo");
        }
        // Keep alive long enough for all echoes to be delivered.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            conn.drive().await.expect("server drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    // Open all N streams and queue a unique payload on each.
    let mut stream_ids = Vec::with_capacity(N);
    for n in 0..N {
        let s = conn.open_bidi().expect("open bidi stream");
        conn.send(s, format!("stream-{n}").as_bytes(), false)
            .await
            .expect("client send");
        stream_ids.push(s);
    }

    // Read the echo back from every stream and verify byte-for-byte equality.
    for (n, sid) in stream_ids.into_iter().enumerate() {
        let (echoed, _fin) = conn.read(sid).await.expect("client read echo");
        assert_eq!(
            echoed,
            format!("stream-{n}").into_bytes(),
            "stream-{n}: echoed bytes must exactly match what was sent"
        );
    }

    server_task.await.expect("server task");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: keep_alive_prevents_idle_close
// ─────────────────────────────────────────────────────────────────────────────

/// Verify that a connection configured with `keep_alive_interval` stays alive
/// past what would have been the idle timeout if keep-alive were absent.
///
/// Uses a 200 ms keep-alive interval and a 600 ms idle timeout.  After sleeping
/// 700 ms with no application data the connection must still be alive because
/// periodic PING frames have continuously reset the idle timer on the peer.
///
/// Validates: keep-alive timer arming in `handle_timeout`, PING emission in
/// `fill_payload`, and `next_timeout` returning the keep-alive deadline so
/// `pump_once` wakes up at the right time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_alive_prevents_idle_close() {
    let (client_cfg, server_cfg) = config_pair();

    // Keep-alive every 200 ms; idle timeout 600 ms.  Without keep-alive the
    // connection would close at ~600 ms.  With keep-alive it should survive
    // 700 ms and still be usable.
    let transport = TransportConfig::default()
        .keep_alive_interval(Some(Duration::from_millis(200)))
        .idle_timeout(Duration::from_millis(600));

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept and keep driving (to process incoming PINGs and send ACKs)
    // for at least 1 second, then confirm the connection is still alive by
    // reading a final ping from the client.
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        let deadline = std::time::Instant::now() + Duration::from_millis(1200);
        while std::time::Instant::now() < deadline {
            conn.drive().await.expect("server drive");
            if conn.is_closed() {
                panic!("server connection closed during keep-alive window");
            }
        }
        // Confirm still alive by reading the final client message.
        let (id, bytes, _fin) = conn
            .accept_uni_or_bidi_data()
            .await
            .expect("server should receive final message after keep-alive window");
        assert_eq!(bytes, b"still alive", "final message payload mismatch");
        conn.send(id, b"ack", false).await.expect("server ack");
        // Flush the ack.
        for _ in 0..5 {
            conn.drive().await.expect("server final drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    // Sleep 700 ms — longer than the 600 ms idle timeout, but the keep-alive
    // PINGs should prevent both sides from timing out.
    tokio::time::sleep(Duration::from_millis(700)).await;

    // The connection must still be alive: send a message and read the ack.
    assert!(
        !conn.is_closed(),
        "client connection must not be closed after 700 ms with keep-alive enabled"
    );
    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, b"still alive", false)
        .await
        .expect("client send after sleep must succeed");
    let (ack, _fin) = conn.read(stream).await.expect("client must receive ack");
    assert_eq!(ack, b"ack", "server ack payload mismatch");

    server_task.await.expect("server task");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: large_payload_10mb
// ─────────────────────────────────────────────────────────────────────────────

/// Client sends a 2 MiB payload on a single bidirectional stream. The server
/// accumulates all 2 MiB then echoes the complete buffer back with FIN set.
/// The client accumulates all echoed bytes and asserts byte-for-byte equality.
///
/// Validates: multi-packet reassembly at scale, stream and connection-level
/// flow-control windows sufficient for 2 MiB, and that the transport can
/// sustain large transfers within a 60-second deadline.  At 1 200-byte MTU
/// the 2 MiB round-trip requires ≈1 750 packets per direction; CUBIC
/// slow-start over loss-free loopback completes well within 30 s.
///
/// Note: original 10 MiB version was reduced to 2 MiB to stay within the
/// macOS loopback UDP socket buffer (768 KB default) without packet loss under
/// CUBIC slow-start, which kept the test reliably under 30 s on all machines.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_payload_10mb() {
    const PAYLOAD_LEN: usize = 2 * 1024 * 1024; // 2 MiB (reliable on macOS loopback UDP)

    let payload: Vec<u8> = (0..PAYLOAD_LEN as u64).map(|i| (i % 251) as u8).collect();

    let (client_cfg, server_cfg) = config_pair();
    // Raise stream and connection flow-control windows well above 2 MiB so
    // the transfer is never blocked by window exhaustion.  Also raise the send
    // window so the client can buffer the full payload before it drains.
    // Extend idle timeout to 60 s so the connection survives the full transfer.
    let transport = TransportConfig::default()
        .stream_receive_window(4 * 1024 * 1024) // 4 MiB per stream
        .receive_window(8 * 1024 * 1024) // 8 MiB connection receive
        .send_window(8 * 1024 * 1024) // 8 MiB connection send
        .idle_timeout(Duration::from_secs(60)); // survive full 2 MiB transfer

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");

        // Use a single absolute deadline aligned with the outer 60 s budget so
        // that individual read() calls do not time out prematurely during
        // slow-start (CUBIC slow-start over loopback typically completes in <15 s).
        let abs_deadline = Instant::now() + Duration::from_secs(55);

        let (stream_id, first_chunk, fin) = conn
            .accept_uni_or_bidi_data_with_deadline(abs_deadline)
            .await
            .expect("server accept first chunk");

        let mut received = first_chunk;
        let mut done = fin;

        // Accumulate until we have all PAYLOAD_LEN bytes or FIN.
        while received.len() < PAYLOAD_LEN && !done {
            let (chunk, f) = conn
                .read_with_deadline(stream_id, abs_deadline)
                .await
                .expect("server read next chunk");
            received.extend_from_slice(&chunk);
            done = f;
        }

        // Echo the complete buffer back on the same stream, setting FIN so the
        // client knows the response is complete and both sides can close cleanly.
        conn.send(stream_id, &received, true)
            .await
            .expect("server echo large payload");

        // Drive the connection until all echoed data (and FIN) is acknowledged
        // by the client.  Sending 10 MiB pushes far more data into the send
        // buffer than the initial congestion window can hold, so `send()` above
        // only flushed the first ~12 KB; the rest drains as the client sends
        // ACKs that expand the window.  We loop until both conditions are met:
        //   1. `has_pending_stream_data()` is false — the send buffer is empty
        //      and the FIN frame has been emitted.
        //   2. `bytes_in_flight()` is 0 — every emitted packet (including the
        //      one carrying FIN) has been acknowledged by the client.
        // The outer 55-s deadline prevents a hang if something goes wrong.
        let drain_deadline = Instant::now() + Duration::from_secs(50);
        loop {
            if !conn.has_pending_stream_data() && conn.bytes_in_flight() == 0 {
                break;
            }
            if Instant::now() >= drain_deadline {
                break;
            }
            conn.drive().await.expect("server drive");
        }

        received
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let stream = conn.open_bidi().expect("open bidi stream");
    conn.send(stream, &payload, false)
        .await
        .expect("client send large payload");

    // Use a single absolute deadline for all client reads.  The outer
    // tokio::time::timeout provides the hard upper bound; each individual
    // read_with_deadline call shares the same absolute end-time so the
    // per-call budget does not reset on every chunk.
    let client_deadline = Instant::now() + Duration::from_secs(55);
    let mut echoed = Vec::with_capacity(PAYLOAD_LEN);
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        while echoed.len() < PAYLOAD_LEN {
            let (chunk, fin) = conn
                .read_with_deadline(stream, client_deadline)
                .await
                .expect("client read echo chunk");
            echoed.extend_from_slice(&chunk);
            if fin {
                break;
            }
        }
        echoed
    })
    .await
    .expect("large_payload_10mb: timed out after 60 s waiting for echo");

    assert_eq!(
        result.len(),
        PAYLOAD_LEN,
        "client should accumulate exactly {} echoed bytes, got {}",
        PAYLOAD_LEN,
        result.len()
    );
    assert_eq!(
        result, payload,
        "echoed bytes must be byte-for-byte identical to what was sent"
    );

    let server_received = server_task.await.expect("server task");
    assert_eq!(
        server_received.len(),
        PAYLOAD_LEN,
        "server should have accumulated exactly {} bytes, got {}",
        PAYLOAD_LEN,
        server_received.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: idle_timeout_closes_connection
// ─────────────────────────────────────────────────────────────────────────────

/// Verify the connection closes automatically after the idle timeout elapses
/// with no activity. Both endpoints use a 300 ms idle timeout; after
/// establishing the connection with no data exchange, the client opens a stream
/// and attempts to read from it. Because the server never sends anything, the
/// `read()` loop keeps pumping the socket until the idle timer fires — at which
/// point it returns an error whose display text contains "idle timeout".
///
/// Validates: idle-timeout timer arming in `arm_idle_timer`, state transition
/// to `ConnectionState::Closed` in `handle_timeout`, `is_closed()` post-close,
/// and `read()` returning `OxiQuicError::Connection("connection idle timeout")`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_timeout_closes_connection() {
    let (client_cfg, server_cfg) = config_pair();

    // Both endpoints use a 300 ms idle timeout with no keep-alive.
    let transport = TransportConfig::default().idle_timeout(Duration::from_millis(300));

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept connection, then stay idle — no sends or receives.
    // After 600 ms the server's own idle timer will also fire and the task exits.
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept");
        let deadline = std::time::Instant::now() + Duration::from_millis(600);
        while std::time::Instant::now() < deadline {
            let _ = conn.drive().await;
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    // Open a stream that will never receive data. `read()` will keep pumping
    // the socket until either data arrives or the connection closes. With a
    // 300 ms idle timeout and no keep-alive, the idle timer must fire within
    // 10 s (the default `read()` deadline), causing `read()` to return an error.
    let probe_stream = conn.open_bidi().expect("open bidi stream");

    // Sleep 500 ms first so any post-handshake ACK traffic from the server has
    // already been buffered and the idle timer is close to (or past) expiry
    // before we start polling.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // `read()` internally loops via `pump_once`, which fires `handle_timeout`
    // once the idle deadline has passed. This returns the close error.
    let err = conn
        .read(probe_stream)
        .await
        .expect_err("read on idle-timed-out connection must return an error");

    let err_str = err.to_string();
    assert!(
        err_str.contains("idle timeout") || err_str.contains("connection closed"),
        "error should mention idle timeout or connection closed, got: {err_str}"
    );

    // After `read()` returns an error due to idle timeout the connection must
    // be flagged as closed.
    assert!(
        conn.is_closed(),
        "connection must be closed after idle timeout fires"
    );

    server_task.await.expect("server task");
}
