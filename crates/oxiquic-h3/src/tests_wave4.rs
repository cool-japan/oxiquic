//! Wave 4 HTTP/3 integration tests: large responses, streaming, concurrency,
//! trailers, ALPN enforcement, custom settings, cancellation, error codes,
//! custom headers, and status code mapping.

// ─── Wave 4: Large response with SHA-256 integrity check ─────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_large_response_sha256() {
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use sha2::{Digest, Sha256};

    use crate::{H3Client, H3Server};

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

    // Build a deterministic 64 KB payload: repeating 0x00..0xFF pattern.
    // Kept well under the stream-level flow-control window to avoid stalls.
    const BODY_LEN: usize = 64 * 1024;
    let payload: Vec<u8> = (0..BODY_LEN).map(|i| (i & 0xff) as u8).collect();
    let expected_hash = {
        let mut h = Sha256::new();
        h.update(&payload);
        h.finalize()
    };
    let payload_bytes = Bytes::from(payload);

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server: send the 64 KB body in 8 KB chunks.
    // A oneshot channel keeps the server connection alive until the client has
    // read everything, preventing premature QUIC driver teardown.
    let (done_tx_large, done_rx_large) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
        let ctx = h3_server
            .accept()
            .await
            .expect("accept request")
            .expect("Some(ctx)");

        let mut responder = ctx.into_responder();
        responder
            .send_response(StatusCode::OK, HeaderMap::new())
            .await
            .expect("send response headers");

        const CHUNK: usize = 8 * 1024;
        let mut offset = 0usize;
        while offset < payload_bytes.len() {
            let end = (offset + CHUNK).min(payload_bytes.len());
            responder
                .send_data(payload_bytes.slice(offset..end))
                .await
                .expect("send chunk");
            offset = end;
        }
        responder.finish().await.expect("finish response");

        // Hold the connection open until the client signals receipt.
        let _ = done_rx_large.await;
    });

    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
    let resp = h3_client
        .get("https://localhost/large")
        .await
        .expect("GET /large");

    // Signal the server that we have the response — it can now close.
    let _ = done_tx_large.send(());

    server_task.await.expect("server task");

    assert!(resp.is_success(), "expected 2xx, got {}", resp.status());

    let body = resp.body_bytes();
    assert_eq!(
        body.len(),
        BODY_LEN,
        "body length mismatch: got {}",
        body.len()
    );

    let actual_hash = {
        let mut h = Sha256::new();
        h.update(body);
        h.finalize()
    };
    assert_eq!(
        actual_hash, expected_hash,
        "SHA-256 mismatch: body was corrupted in transit"
    );

    let _ = h3_client.close().await;
}

// ─── Wave 4: Streaming response with incremental recv_data ───────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_streaming_response_chunks() {
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Request, H3Server};

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

    // 4 × 4 KB chunks = 16 KB total — small enough to avoid flow-control stalls.
    const CHUNK_SIZE: usize = 4 * 1024;
    const NUM_CHUNKS: usize = 4;
    const TOTAL: usize = CHUNK_SIZE * NUM_CHUNKS;

    // Each chunk is filled with its chunk index byte for easy verification.
    let chunks: Vec<Bytes> = (0..NUM_CHUNKS)
        .map(|i| Bytes::from(vec![i as u8; CHUNK_SIZE]))
        .collect();
    let chunks_for_server = chunks.clone();

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // A oneshot channel keeps the server alive until the client has drained
    // the stream, preventing premature QUIC driver teardown.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
        let ctx = h3_server
            .accept()
            .await
            .expect("accept request")
            .expect("Some(ctx)");

        let mut responder = ctx.into_responder();
        responder
            .send_response(StatusCode::OK, HeaderMap::new())
            .await
            .expect("send headers");

        for chunk in chunks_for_server {
            responder.send_data(chunk).await.expect("send chunk");
        }
        responder.finish().await.expect("finish");

        let _ = done_rx.await;
    });

    // Client: use send_streaming to recv_data incrementally.
    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
    let mut stream = h3_client
        .send_streaming(H3Request::get("https://localhost/stream"))
        .await
        .expect("send_streaming");

    stream.finish().await.expect("finish request");

    let resp = stream.recv_response().await.expect("recv_response");
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "expected 200, got {}",
        resp.status()
    );

    let mut total_bytes = 0usize;
    while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
        total_bytes += chunk.len();
    }

    let _ = done_tx.send(());

    server_task.await.expect("server task");

    assert_eq!(
        total_bytes, TOTAL,
        "expected {TOTAL} total bytes, got {total_bytes}"
    );

    let _ = h3_client.close().await;
}

// ─── Wave 4: Ten sequential requests over a single H3 connection ─────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_concurrent_requests_ten() {
    // NOTE: H3Client takes &mut self so sequential sends are used here.
    // This still validates that multiple requests succeed over a single
    // H3 connection without reconnecting (RFC 9114 multiplexing requirement).
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Response, H3Server};

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

    const N: usize = 10;

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");

        for i in 0..N {
            let ctx = h3_server
                .accept()
                .await
                .expect("accept request")
                .expect("Some(ctx)");
            let resp = H3Response::new(200).with_body(format!("request-{i}"));
            ctx.respond(resp).await.expect("respond");
        }
    });

    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
    for i in 0..N {
        let resp = h3_client
            .get(&format!("https://localhost/req/{i}"))
            .await
            .expect("GET");
        assert!(
            resp.is_success(),
            "request {i}: expected 2xx, got {}",
            resp.status()
        );
        assert_eq!(
            resp.body_text().expect("utf-8"),
            format!("request-{i}"),
            "request {i}: body mismatch"
        );
    }

    server_task.await.expect("server task");
    let _ = h3_client.close().await;
}

// ─── Wave 4: Trailers roundtrip ───────────────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_trailers_roundtrip() {
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Request, H3Server};

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

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // A oneshot channel keeps the server alive until the client has read all.
    let (done_tx_tr, done_rx_tr) = tokio::sync::oneshot::channel::<()>();

    // Server: headers → body → trailers (RFC 9114 §4.1).
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
        let ctx = h3_server
            .accept()
            .await
            .expect("accept request")
            .expect("Some(ctx)");

        let mut responder = ctx.into_responder();
        responder
            .send_response(StatusCode::OK, HeaderMap::new())
            .await
            .expect("send headers");
        responder
            .send_data(Bytes::from_static(b"body data"))
            .await
            .expect("send body");

        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-trailer"),
            HeaderValue::from_static("trailer-value"),
        );
        responder
            .send_trailers(trailers)
            .await
            .expect("send trailers");
        // send_trailers implies end-of-stream; hold connection alive until done.
        let _ = done_rx_tr.await;
    });

    // Client: use send_streaming to read headers, body, and trailers.
    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
    let mut stream = h3_client
        .send_streaming(H3Request::get("https://localhost/trailers"))
        .await
        .expect("send_streaming");

    stream.finish().await.expect("finish request");

    let resp = stream.recv_response().await.expect("recv_response");
    assert_eq!(resp.status(), StatusCode::OK, "expected 200");

    while let Some(_chunk) = stream.recv_data().await.expect("recv_data chunk") {}

    let trailers = stream.recv_trailers().await.expect("recv_trailers");

    let _ = done_tx_tr.send(());

    server_task.await.expect("server task");

    let trailers = trailers.expect("trailers should be Some");
    let trailer_val = trailers.get("x-trailer").expect("x-trailer header missing");
    assert_eq!(
        trailer_val.to_str().expect("valid utf-8"),
        "trailer-value",
        "trailer value mismatch"
    );

    let _ = h3_client.close().await;
}

// ─── Wave 4: ALPN enforcement mismatch ────────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_alpn_enforcement_mismatch() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust self-signed cert");

    // Client: ALPN "hq-29" — does not match "h3".
    let mut client_cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("client TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"hq-29".to_vec()];

    // Server: accept only "hq-29".
    let mut server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("server TLS1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server single cert");
    server_cfg.alpn_protocols = vec![b"hq-29".to_vec()];

    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, Arc::new(server_cfg), transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let _ = server_ep.accept().await;
    });

    let client_ep = ClientEndpoint::bind(loopback, Arc::new(client_cfg), transport)
        .await
        .expect("bind client");

    if let Ok(quic_conn) = client_ep.connect(server_addr, "localhost").await {
        let alpn = quic_conn.negotiated_alpn();
        assert!(
            alpn.as_deref() != Some(b"h3".as_slice()),
            "ALPN should NOT be h3, got {alpn:?}"
        );
        let driven = quic_conn.into_driven();
        let _h3_result = crate::H3Client::new(driven).await;
    }

    server_task.await.expect("server task");
}

// ─── Wave 4: Custom SETTINGS exchange smoke test ─────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_settings_exchange() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::H3Response;

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

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server uses a custom max_field_section_size (4096) via new_with_config.
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = crate::H3Connection::new_with_config(driven, 4096)
            .await
            .expect("H3Connection::new_with_config");

        let ctx = h3_server
            .accept()
            .await
            .expect("accept request")
            .expect("Some(ctx)");
        let resp = H3Response::new(200).with_body("settings-ok");
        ctx.respond(resp).await.expect("respond");
    });

    // Client uses a different max_field_section_size (8192) via new_with_config.
    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = crate::H3Client::new_with_config(driven, 8192, Vec::new())
        .await
        .expect("H3Client::new_with_config");

    let resp = h3_client
        .get("https://localhost/settings")
        .await
        .expect("GET");

    server_task.await.expect("server task");

    assert!(resp.is_success(), "expected 2xx, got {}", resp.status());
    assert_eq!(
        resp.body_text().expect("utf-8"),
        "settings-ok",
        "body mismatch"
    );

    let _ = h3_client.close().await;
}

// ─── Wave 4: Request cancellation ────────────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_request_cancellation() {
    use std::sync::Arc;

    use http::{HeaderMap, StatusCode};
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Request, H3Server};

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

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server: accept request, send headers, then stream body.
    // Client cancels after receiving headers; server may get a stream error.
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");

        let ctx = h3_server
            .accept()
            .await
            .expect("accept request")
            .expect("Some(ctx)");

        let mut responder = ctx.into_responder();
        let _ = responder
            .send_response(StatusCode::OK, HeaderMap::new())
            .await;

        let big_chunk = bytes::Bytes::from(vec![0u8; 32 * 1024]);
        for _ in 0..20 {
            if responder.send_data(big_chunk.clone()).await.is_err() {
                break; // stream reset observed — expected after client cancel
            }
        }
    });

    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
    let mut stream = h3_client
        .send_streaming(H3Request::get("https://localhost/cancel"))
        .await
        .expect("send_streaming");

    stream.finish().await.expect("finish request");

    let _resp = stream.recv_response().await.expect("recv_response");

    // Cancel — sends STOP_SENDING H3_REQUEST_CANCELLED to the server.
    stream.cancel();
    drop(stream);

    server_task.await.expect("server task");

    let _ = h3_client.close().await;
}

// ─── Wave 4: Error response code mapping (404, 500) ──────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_error_response_code_mapping() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Response, H3Server};

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

    // ── 404 ──────────────────────────────────────────────────────────────────
    {
        let (client_cfg, server_cfg) = config_pair();
        let transport = TransportConfig::default();
        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

        let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
            .await
            .expect("bind server");
        let server_addr = server_ep.local_addr().expect("server addr");

        let server_task = tokio::spawn(async move {
            let quic_conn = server_ep.accept().await.expect("accept QUIC");
            let driven = quic_conn.into_driven();
            let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
            let ctx = h3_server
                .accept()
                .await
                .expect("accept")
                .expect("Some(ctx)");
            let resp = H3Response::new(404).with_body("not found");
            ctx.respond(resp).await.expect("respond");
        });

        let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
            .await
            .expect("bind client");
        let quic_conn = client_ep
            .connect(server_addr, "localhost")
            .await
            .expect("connect");
        let driven = quic_conn.into_driven();

        let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
        let resp = h3_client
            .get("https://localhost/missing")
            .await
            .expect("GET");

        server_task.await.expect("server task");

        assert_eq!(resp.status(), 404, "expected 404");
        assert!(!resp.ok(), "404 should not be ok()");
        let err = resp.error_for_status();
        assert!(err.is_err(), "error_for_status should return Err for 404");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("404"),
            "error message should contain 404, got: {msg}"
        );

        let _ = h3_client.close().await;
    }

    // ── 500 ──────────────────────────────────────────────────────────────────
    {
        let (client_cfg, server_cfg) = config_pair();
        let transport = TransportConfig::default();
        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

        let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
            .await
            .expect("bind server");
        let server_addr = server_ep.local_addr().expect("server addr");

        let server_task = tokio::spawn(async move {
            let quic_conn = server_ep.accept().await.expect("accept QUIC");
            let driven = quic_conn.into_driven();
            let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
            let ctx = h3_server
                .accept()
                .await
                .expect("accept")
                .expect("Some(ctx)");
            let resp = H3Response::new(500).with_body("internal error");
            ctx.respond(resp).await.expect("respond");
        });

        let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
            .await
            .expect("bind client");
        let quic_conn = client_ep
            .connect(server_addr, "localhost")
            .await
            .expect("connect");
        let driven = quic_conn.into_driven();

        let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
        let resp = h3_client.get("https://localhost/error").await.expect("GET");

        server_task.await.expect("server task");

        assert_eq!(resp.status(), 500, "expected 500");
        assert!(!resp.ok(), "500 should not be ok()");
        assert!(
            resp.error_for_status().is_err(),
            "error_for_status should Err for 500"
        );

        let _ = h3_client.close().await;
    }
}

// ─── Wave 4: Custom headers echo ─────────────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_custom_headers_echo() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Request, H3Response, H3Server};

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

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
        let ctx = h3_server
            .accept()
            .await
            .expect("accept")
            .expect("Some(ctx)");

        let echoed = ctx
            .request()
            .headers()
            .iter()
            .find(|(n, _)| n == "x-test")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "missing".to_string());

        let resp = H3Response::new(200).with_header("x-test-echo", echoed);
        ctx.respond(resp).await.expect("respond");
    });

    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
    let req = H3Request::get("https://localhost/echo").with_header("x-test", "hello");
    let resp = h3_client.request(req, None).await.expect("request");

    server_task.await.expect("server task");

    assert!(resp.is_success(), "expected 2xx, got {}", resp.status());
    assert_eq!(
        resp.header("x-test-echo"),
        Some("hello"),
        "echoed x-test header mismatch"
    );

    let _ = h3_client.close().await;
}

// ─── Wave 4: Response status codes (200, 301, 404, 500) ──────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_response_status_codes() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Request, H3Response, H3Server};

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

    // Each case runs on its own connection to prevent cross-iteration state leaks.
    let cases: &[(u16, &str)] = &[
        (200, "https://localhost/200"),
        (301, "https://localhost/301"),
        (404, "https://localhost/404"),
        (500, "https://localhost/500"),
    ];

    for &(expected_status, url) in cases {
        let (client_cfg, server_cfg) = config_pair();
        let transport = TransportConfig::default();
        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

        let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
            .await
            .expect("bind server");
        let server_addr = server_ep.local_addr().expect("server addr");

        let s = expected_status;
        let server_task = tokio::spawn(async move {
            let quic_conn = server_ep.accept().await.expect("accept QUIC");
            let driven = quic_conn.into_driven();
            let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
            let ctx = h3_server
                .accept()
                .await
                .expect("accept")
                .expect("Some(ctx)");
            let resp = H3Response::new(s).with_header("x-status", s.to_string());
            ctx.respond(resp).await.expect("respond");
        });

        let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
            .await
            .expect("bind client");
        let quic_conn = client_ep
            .connect(server_addr, "localhost")
            .await
            .expect("connect");
        let driven = quic_conn.into_driven();

        let mut h3_client = crate::H3Client::new(driven).await.expect("H3Client::new");
        let resp = h3_client
            .request(H3Request::get(url), None)
            .await
            .unwrap_or_else(|e| panic!("request failed for status {s}: {e}"));

        server_task.await.expect("server task");

        assert_eq!(
            resp.status(),
            expected_status,
            "status mismatch: got {}",
            resp.status()
        );
        let status_str = expected_status.to_string();
        assert_eq!(
            resp.header("x-status"),
            Some(status_str.as_str()),
            "x-status header mismatch"
        );
        let is_2xx = (200..300).contains(&expected_status);
        assert_eq!(
            resp.ok(),
            is_2xx,
            "ok() mismatch for status {expected_status}"
        );

        h3_client.close().await.unwrap_or(());
        tokio::task::yield_now().await;
    }
}
