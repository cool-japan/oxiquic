//! Multi-connection server demux integration tests.
//!
//! These tests verify that a single [`ServerEndpoint`] can handle many
//! concurrent client connections on one UDP socket via DCID-based routing.
//! Each test performs real QUIC handshakes over UDP loopback (127.0.0.1).

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (self-contained; no shared test-helper crate)
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
// Test: ten_clients_concurrent
// ─────────────────────────────────────────────────────────────────────────────

/// Ten clients connect to a single server endpoint simultaneously.  Each
/// client opens one bidirectional stream and sends a unique payload of the
/// form `"client-{n}"`.  The server echoes every payload back on the same
/// stream.  All clients verify their echoed response exactly matches what was
/// sent.
///
/// Validates: DCID-based demux, per-connection channel routing, concurrent
/// handshake tasks completing independently on a shared UDP socket, and
/// absence of cross-connection data contamination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_clients_concurrent() {
    const N: usize = 10;

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Server: accept N connections (in any order) and echo the single stream
    // payload back on each.
    let server_task = tokio::spawn(async move {
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let mut conn = server.accept().await.expect("server accept");
            let handle = tokio::spawn(async move {
                let (sid, bytes, _fin) = conn
                    .accept_uni_or_bidi_data()
                    .await
                    .expect("server accept stream data");
                conn.send(sid, &bytes, false).await.expect("server echo");
                // Drive briefly to ensure echo is delivered before the task exits.
                for _ in 0..20 {
                    conn.drive().await.expect("server drive");
                }
            });
            handles.push(handle);
        }
        // Wait for all per-connection echo tasks to complete.
        for h in handles {
            h.await.expect("server per-conn task");
        }
    });

    // Clients: connect concurrently, send a unique payload, read the echo.
    let mut client_tasks = Vec::with_capacity(N);
    for n in 0..N {
        let client_cfg = Arc::clone(&client_cfg);
        let transport = transport.clone();
        let task = tokio::spawn(async move {
            let endpoint = ClientEndpoint::bind(loopback(), client_cfg, transport)
                .await
                .expect("bind client");
            let mut conn = endpoint
                .connect(server_addr, "localhost")
                .await
                .expect("client connect");

            let payload = format!("client-{n}");
            let stream = conn.open_bidi().expect("open bidi stream");
            conn.send(stream, payload.as_bytes(), false)
                .await
                .expect("client send");

            let (echoed, _fin) = conn.read(stream).await.expect("client read echo");
            assert_eq!(
                echoed,
                payload.as_bytes(),
                "client-{n}: echoed bytes must exactly match sent payload, got {:?}",
                String::from_utf8_lossy(&echoed)
            );
        });
        client_tasks.push(task);
    }

    // Wait for every client to complete successfully.
    for (n, task) in client_tasks.into_iter().enumerate() {
        task.await
            .unwrap_or_else(|e| panic!("client-{n} task panicked: {e:?}"));
    }

    server_task.await.expect("server task");
}
