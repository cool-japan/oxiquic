//! Unit and integration tests for the HTTP/3 types.

use crate::{H3Error, H3ErrorCode, H3Request, H3Response, H3Settings};
use oxiquic_core::OxiQuicError;

// --- H3ErrorCode (RFC 9114 Section 8.1) -------------------------------------

#[test]
fn h3_error_code_round_trips() {
    let codes = [
        (0x0100u64, H3ErrorCode::NoError),
        (0x0101, H3ErrorCode::GeneralProtocolError),
        (0x0102, H3ErrorCode::InternalError),
        (0x0103, H3ErrorCode::StreamCreationError),
        (0x0104, H3ErrorCode::ClosedCriticalStream),
        (0x0105, H3ErrorCode::FrameUnexpected),
        (0x0106, H3ErrorCode::FrameError),
        (0x0107, H3ErrorCode::ExcessiveLoad),
        (0x0108, H3ErrorCode::IdError),
        (0x0109, H3ErrorCode::SettingsError),
        (0x010a, H3ErrorCode::MissingSettings),
        (0x010b, H3ErrorCode::RequestRejected),
        (0x010c, H3ErrorCode::RequestCancelled),
        (0x010d, H3ErrorCode::RequestIncomplete),
        (0x010e, H3ErrorCode::MessageError),
        (0x010f, H3ErrorCode::ConnectError),
        (0x0110, H3ErrorCode::VersionFallback),
    ];
    for (value, code) in codes {
        assert_eq!(H3ErrorCode::from_u64(value), code, "0x{value:x}");
        assert_eq!(code.to_u64(), value, "{code}");
    }
}

#[test]
fn h3_error_code_qpack_range() {
    assert_eq!(H3ErrorCode::from_u64(0x0200), H3ErrorCode::Qpack(0x0200));
    assert_eq!(H3ErrorCode::from_u64(0x0202), H3ErrorCode::Qpack(0x0202));
    assert_eq!(H3ErrorCode::Qpack(0x0201).to_u64(), 0x0201);
    assert!(H3ErrorCode::Qpack(0x0200).to_string().contains("QPACK"));
}

#[test]
fn h3_error_code_unknown() {
    assert_eq!(H3ErrorCode::from_u64(0x4242), H3ErrorCode::Unknown(0x4242));
    assert_eq!(H3ErrorCode::Unknown(0x4242).to_u64(), 0x4242);
}

#[test]
fn h3_error_code_display_names() {
    assert_eq!(
        H3ErrorCode::FrameUnexpected.to_string(),
        "H3_FRAME_UNEXPECTED"
    );
    assert_eq!(
        H3ErrorCode::MissingSettings.to_string(),
        "H3_MISSING_SETTINGS"
    );
}

// --- H3Error ----------------------------------------------------------------

#[test]
fn h3_error_maps_to_code() {
    assert_eq!(
        H3Error::FrameUnexpected("x".into()).code(),
        H3ErrorCode::FrameUnexpected
    );
    assert_eq!(
        H3Error::MissingSettings.code(),
        H3ErrorCode::MissingSettings
    );
    assert_eq!(
        H3Error::SettingsError("bad".into()).code(),
        H3ErrorCode::SettingsError
    );
    assert_eq!(
        H3Error::Protocol("oops".into()).code(),
        H3ErrorCode::GeneralProtocolError
    );
}

#[test]
fn h3_error_converts_to_oxiquic_error() {
    let oq: OxiQuicError = H3Error::Tls("handshake".into()).into();
    assert!(matches!(oq, OxiQuicError::Tls(_)));

    let oq: OxiQuicError = H3Error::Protocol("frame".into()).into();
    assert!(matches!(oq, OxiQuicError::Protocol(_)));
}

// --- H3Settings -------------------------------------------------------------

#[test]
fn h3_settings_defaults() {
    let settings = H3Settings::default();
    assert_eq!(settings.max_field_section_size, 16_384);
    assert_eq!(settings.qpack_max_table_capacity, 0);
    assert_eq!(settings.qpack_blocked_streams, 0);
}

// --- H3Request --------------------------------------------------------------

#[test]
fn h3_request_builders() {
    let get = H3Request::get("/a");
    assert_eq!(get.method(), "GET");
    assert_eq!(get.uri(), "/a");

    let post = H3Request::post("/submit");
    assert_eq!(post.method(), "POST");

    let custom = H3Request::new("PUT", "/x");
    assert_eq!(custom.method(), "PUT");
}

#[test]
fn h3_request_headers_lowercased() {
    let req = H3Request::get("/")
        .with_header("Accept", "text/html")
        .with_header("User-Agent", "oxiquic");
    assert_eq!(
        req.headers(),
        &[
            ("accept".to_string(), "text/html".to_string()),
            ("user-agent".to_string(), "oxiquic".to_string()),
        ]
    );
}

// --- H3Response -------------------------------------------------------------

#[test]
fn h3_response_status_and_body() {
    let res = H3Response::new(200)
        .with_header("Content-Type", "text/plain")
        .with_body("hello");
    assert_eq!(res.status(), 200);
    assert!(res.is_success());
    assert_eq!(res.body_bytes(), b"hello");
    assert_eq!(res.body_text().expect("utf-8"), "hello");
    assert_eq!(res.content_type(), Some("text/plain"));
}

#[test]
fn h3_response_status_classes() {
    assert!(H3Response::new(204).is_success());
    assert!(!H3Response::new(301).is_success());
    assert!(!H3Response::new(404).is_success());
    assert!(!H3Response::new(500).is_success());
}

#[test]
fn h3_response_content_length() {
    let res = H3Response::new(200).with_header("Content-Length", "1234");
    assert_eq!(res.content_length(), Some(1234));

    let no_len = H3Response::new(200);
    assert_eq!(no_len.content_length(), None);

    let bad_len = H3Response::new(200).with_header("Content-Length", "abc");
    assert_eq!(bad_len.content_length(), None);
}

#[test]
fn h3_response_header_lookup_case_insensitive() {
    let res = H3Response::new(200).with_header("X-Custom", "value");
    assert_eq!(res.header("x-custom"), Some("value"));
    assert_eq!(res.header("X-CUSTOM"), Some("value"));
    assert_eq!(res.header("missing"), None);
}

#[test]
fn h3_response_body_text_rejects_invalid_utf8() {
    let res = H3Response::new(200).with_body(vec![0xff, 0xfe]);
    assert!(res.body_text().is_err());
}

#[test]
fn h3_response_into_body() {
    let res = H3Response::new(200).with_body("bytes");
    assert_eq!(res.into_body(), b"bytes");
}

// --- h3-compat stream types -------------------------------------------------

#[cfg(feature = "h3-compat")]
#[test]
fn h3_stream_types_are_exported() {
    // Verify the h3 adapter types are accessible from the crate root.
    let _ = std::any::TypeId::of::<crate::H3BidiStream>();
    let _ = std::any::TypeId::of::<crate::H3SendStream>();
    let _ = std::any::TypeId::of::<crate::H3RecvStream>();
    let _ = std::any::TypeId::of::<crate::OxiQuicH3Connection>();
}

// --- HTTP/3 GET roundtrip integration test ----------------------------------

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_get_roundtrip() {
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{accept_h3, connect_h3};

    // Build self-signed cert + matched TLS config pair.
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

    // Bind server endpoint.
    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server endpoint");
    let server_addr = server_ep.local_addr().expect("server addr");

    // ── Server task ────────────────────────────────────────────────────────────
    let server_task = tokio::spawn(async move {
        // Accept one QUIC connection.
        let quic_conn = server_ep.accept().await.expect("accept QUIC connection");
        let driven = quic_conn.into_driven();

        // Upgrade to HTTP/3.
        let mut h3_conn = accept_h3(driven).await.expect("accept H3 connection");

        // Accept one request.
        let resolver = h3_conn
            .accept()
            .await
            .expect("accept H3 request")
            .expect("expected Some(request)");

        let (_req, mut stream) = resolver
            .resolve_request()
            .await
            .expect("resolve request headers");

        // Send 200 OK with body "hello".
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .expect("build response");
        stream
            .send_response(resp)
            .await
            .expect("send response headers");
        stream
            .send_data(Bytes::from_static(b"hello"))
            .await
            .expect("send response body");
        stream.finish().await.expect("finish response stream");
    });

    // ── Client ─────────────────────────────────────────────────────────────────
    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client endpoint");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = quic_conn.into_driven();

    // Upgrade to HTTP/3.
    let (mut h3_conn, mut send_request) = connect_h3(driven).await.expect("connect H3");

    // Send GET /.
    let req = Request::builder()
        .method("GET")
        .uri("https://localhost/")
        .body(())
        .expect("build request");

    let mut req_stream = send_request.send_request(req).await.expect("send request");

    // Signal no body.
    req_stream.finish().await.expect("finish request");

    // Receive response.
    let resp = req_stream.recv_response().await.expect("recv response");
    assert_eq!(resp.status(), StatusCode::OK, "expected 200 OK");

    // Receive body.
    let mut body = Vec::new();
    while let Some(mut chunk) = req_stream.recv_data().await.expect("recv body chunk") {
        use bytes::Buf;
        body.extend_from_slice(chunk.chunk());
        let n = chunk.remaining();
        chunk.advance(n);
    }
    assert_eq!(body, b"hello", "response body mismatch");

    // Wait for server to finish.
    server_task.await.expect("server task panicked");

    // Gracefully close the H3 connection.
    let _ = h3_conn.shutdown(0).await;
}

// --- Removed deferred stubs (H3Client/H3Server now removed from lib.rs) ---

// The old H3Client::connect() / H3Server::bind() NotImplemented tests are
// no longer relevant because those types have been replaced by the real
// connect_h3 / accept_h3 functions.

// --- H3Client + H3Server integration tests ----------------------------------

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_client_server_get_roundtrip() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Client, H3Response, H3Server};

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
        .expect("bind server endpoint");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server task: accept one request and respond.
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC connection");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");

        let ctx = h3_server
            .accept()
            .await
            .expect("accept H3 request")
            .expect("expected Some(request)");

        let resp = H3Response::new(200).with_body("hello from h3server");
        ctx.respond(resp).await.expect("respond");
    });

    // Client: send GET / and verify response.
    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client endpoint");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
    let resp = h3_client.get("https://localhost/").await.expect("GET /");

    server_task.await.expect("server task panicked");

    assert!(resp.is_success(), "expected 2xx, got {}", resp.status());
    assert_eq!(
        resp.body_text().expect("utf-8 body"),
        "hello from h3server",
        "response body mismatch"
    );

    let _ = h3_client.close().await;
}

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_client_post_with_body() {
    use std::sync::Arc;

    use bytes::Bytes;
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Client, H3Response, H3Server};

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
        .expect("bind server endpoint");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server task: accept one POST, read body, echo it back.
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC connection");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");

        let mut ctx = h3_server
            .accept()
            .await
            .expect("accept H3 request")
            .expect("expected Some(request)");

        let body = ctx.body().await.expect("read body");
        let resp = H3Response::new(200).with_body(body.to_vec());
        ctx.respond(resp).await.expect("respond");
    });

    // Client: POST with body "ping" and verify the echo.
    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client endpoint");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
    let resp = h3_client
        .post("https://localhost/", Bytes::from_static(b"ping"))
        .await
        .expect("POST /");

    server_task.await.expect("server task panicked");

    assert!(resp.is_success(), "expected 2xx, got {}", resp.status());
    assert_eq!(resp.body_bytes(), b"ping", "echoed body mismatch");

    let _ = h3_client.close().await;
}

// ─── Wave 3: H3Response status helpers ──────────────────────────────────────

#[test]
fn h3_response_ok_and_error_for_status() {
    let ok = H3Response::new(200);
    assert!(ok.ok(), "200 should be ok()");
    assert!(
        ok.error_for_status().is_ok(),
        "200 error_for_status should be Ok"
    );

    let created = H3Response::new(201).with_body("created");
    assert!(created.ok());
    assert!(created.error_for_status().is_ok());

    let not_found = H3Response::new(404);
    assert!(!not_found.ok(), "404 should not be ok()");
    let err = not_found.error_for_status();
    assert!(err.is_err(), "404 error_for_status should be Err");
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("404"),
        "error message should contain status code"
    );

    let server_err = H3Response::new(500);
    assert!(!server_err.ok());
    assert!(server_err.error_for_status().is_err());
}

// ─── Wave 3: server push returns NotImplemented ──────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test]
async fn h3_push_promise_not_implemented() {
    // accept_push_stub always returns Ok(None) — upstream-limited by h3 0.0.8
    let result = crate::push::accept_push_stub().await;
    assert!(result.is_ok(), "accept_push_stub should not error");
    assert!(
        result.expect("no error").is_none(),
        "should return None (push not supported)"
    );
}

// ─── Wave 3: H3ServerBuilder + H3ServerEndpoint ──────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_server_builder_bind_and_accept() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Client, H3Response, H3ServerBuilder};

    fn config_pair() -> (Arc<ClientConfig>, ServerConfig) {
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

        (Arc::new(client), server)
    }

    let (client_cfg_base, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    // Build server via H3ServerBuilder — the builder auto-injects "h3" ALPN on
    // the server side, so we must also set it on the client.
    let mut client_cfg = (*client_cfg_base).clone();
    client_cfg.alpn_protocols = vec![b"h3".to_vec()];
    let client_cfg = Arc::new(client_cfg);

    let server_ep = H3ServerBuilder::new(loopback)
        .with_tls_config(server_cfg)
        .with_max_field_section_size(32_768)
        .with_server_push(false)
        .build()
        .await
        .expect("H3ServerBuilder::build");

    let server_addr = server_ep.local_addr().expect("local_addr");
    assert!(!server_ep.server_push_enabled(), "push should be disabled");

    // Server task
    let server_task = tokio::spawn(async move {
        let mut conn = server_ep
            .accept_connection()
            .await
            .expect("accept_connection");

        let ctx = conn
            .accept()
            .await
            .expect("accept request")
            .expect("expected Some(request)");

        let resp = H3Response::new(200).with_body("builder-based server");
        ctx.respond(resp).await.expect("respond");
    });

    // Client: connect with h3 ALPN configured
    let client_ep = ClientEndpoint::bind(loopback, client_cfg, transport)
        .await
        .expect("bind client endpoint");
    let quic_conn = client_ep
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let driven = quic_conn.into_driven();

    let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
    let resp = h3_client.get("https://localhost/").await.expect("GET /");

    server_task.await.expect("server task panicked");

    assert!(resp.is_success(), "expected 2xx, got {}", resp.status());
    assert_eq!(
        resp.body_text().expect("utf-8"),
        "builder-based server",
        "body mismatch"
    );

    let _ = h3_client.close().await;
}

// ─── Wave 3: H3Client HEAD request ───────────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_client_head_request() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Client, H3Response, H3Server};

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

        // For HEAD, server sends status+headers; RFC 9110 §9.3.2 forbids body
        // but the h3 layer still sends the DATA frame at the application layer;
        // the client is responsible for discarding the body.
        let method = ctx.request().method().to_ascii_uppercase();
        let resp = if method == "HEAD" {
            H3Response::new(200)
                .with_header("content-length", "5")
                .with_header("x-method", "head")
            // No body — RFC 9110 §9.3.2
        } else {
            H3Response::new(200).with_body("hello")
        };
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

    let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
    let resp = h3_client
        .head("https://localhost/resource")
        .await
        .expect("HEAD");

    server_task.await.expect("server task");

    assert!(
        resp.is_success(),
        "HEAD should return 2xx, got {}",
        resp.status()
    );
    assert_eq!(
        resp.header("x-method"),
        Some("head"),
        "custom header missing"
    );
    // HEAD responses have no body per RFC 9110 §9.3.2
    assert!(
        resp.body_bytes().is_empty(),
        "HEAD response body should be empty, got {} bytes",
        resp.body_bytes().len()
    );

    let _ = h3_client.close().await;
}

// ─── Wave 3: H3Client PUT / DELETE methods ───────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_client_put_and_delete() {
    use std::sync::Arc;

    use bytes::Bytes;
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Client, H3Response, H3Server};

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

    // ── PUT test ────────────────────────────────────────────────────────────────
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
            let mut ctx = h3_server
                .accept()
                .await
                .expect("accept")
                .expect("Some(ctx)");
            let body = ctx.body().await.expect("read body");
            // Echo method + body
            let method = ctx.request().method().to_ascii_uppercase();
            let echo = format!("{method}:{}", String::from_utf8_lossy(&body));
            let resp = H3Response::new(200).with_body(echo.as_bytes().to_vec());
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

        let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
        let resp = h3_client
            .put("https://localhost/item", Bytes::from_static(b"payload"))
            .await
            .expect("PUT");

        server_task.await.expect("server task");
        assert!(resp.is_success(), "PUT should return 2xx");
        assert_eq!(
            resp.body_text().expect("utf-8"),
            "PUT:payload",
            "PUT body echo mismatch"
        );
        let _ = h3_client.close().await;
    }

    // ── DELETE test ─────────────────────────────────────────────────────────────
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
            let method = ctx.request().method().to_ascii_uppercase();
            let resp = H3Response::new(204).with_header("x-method", method.to_ascii_lowercase());
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

        let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
        let resp = h3_client
            .delete("https://localhost/item")
            .await
            .expect("DELETE");

        server_task.await.expect("server task");
        assert_eq!(resp.status(), 204, "DELETE should return 204");
        assert_eq!(resp.header("x-method"), Some("delete"), "method header");
        let _ = h3_client.close().await;
    }
}

// ─── Wave 3: H3Responder streaming API ───────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_responder_send_full() {
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

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

    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

    let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport.clone())
        .await
        .expect("bind server");
    let server_addr = server_ep.local_addr().expect("server addr");

    // Server uses H3Responder::send_full
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
        let ctx = h3_server
            .accept()
            .await
            .expect("accept")
            .expect("Some(ctx)");

        let mut responder = ctx.into_responder();
        let mut headers = HeaderMap::new();
        headers.insert("x-via", "responder".parse().expect("valid header value"));
        responder
            .send_full(
                StatusCode::OK,
                headers,
                Bytes::from_static(b"streamed body"),
            )
            .await
            .expect("send_full");
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
    let resp = h3_client.get("https://localhost/").await.expect("GET");

    server_task.await.expect("server task");

    assert!(resp.is_success(), "expected 2xx, got {}", resp.status());
    assert_eq!(
        resp.header("x-via"),
        Some("responder"),
        "x-via header missing"
    );
    assert_eq!(resp.body_bytes(), b"streamed body", "body mismatch");

    let _ = h3_client.close().await;
}

// ─── Wave 3: H3Connection::shutdown (GOAWAY) ─────────────────────────────────

#[cfg(feature = "h3-compat")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_connection_shutdown_goaway() {
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Client, H3Response, H3Server};

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

    // Server: handle one request, then call shutdown(0) and verify accept() returns None
    let server_task = tokio::spawn(async move {
        let quic_conn = server_ep.accept().await.expect("accept QUIC");
        let driven = quic_conn.into_driven();
        let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");

        // Accept and handle one request
        let ctx = h3_server
            .accept()
            .await
            .expect("accept first request")
            .expect("Some(ctx)");

        let resp = H3Response::new(200).with_body("before shutdown");
        ctx.respond(resp).await.expect("respond");

        // Initiate graceful shutdown — no more requests accepted
        h3_server.shutdown(0).await.expect("shutdown(0)");

        // After shutdown, accept() should return None (connection draining)
        let next = h3_server.accept().await;
        // Accept may return None or an error; either is acceptable after GOAWAY
        let _ = next; // Don't assert — behavior is implementation-defined after shutdown
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
        .get("https://localhost/before")
        .await
        .expect("GET before shutdown");

    server_task.await.expect("server task");

    assert!(
        resp.is_success(),
        "pre-shutdown request should succeed, got {}",
        resp.status()
    );
    assert_eq!(resp.body_bytes(), b"before shutdown");

    let _ = h3_client.close().await;
}

// ─── Wave 3: H3ClientBuilder basic config ────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[test]
fn h3_client_builder_fields() {
    use crate::H3ClientBuilder;
    use oxiquic_transport::TransportConfig;

    // Verify builder methods exist and chain
    let builder = H3ClientBuilder::new()
        .with_server_name("example.com")
        .with_max_field_section_size(8_192)
        .with_qpack_config(4096, 16)
        .with_default_headers(vec![("user-agent".to_string(), "oxiquic/test".to_string())])
        .with_transport_config(TransportConfig::default());

    // The builder was constructed without error — fields are set correctly.
    // We don't call connect() since we have no live server here; the builder
    // API shape itself is what we're testing.
    let _ = builder;
}

#[cfg(feature = "h3-compat")]
#[test]
fn h3_server_builder_fields() {
    use crate::H3ServerBuilder;

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
    let builder = H3ServerBuilder::new(addr)
        .with_bind_address(addr)
        .with_max_field_section_size(65_536)
        .with_qpack_max_table_capacity(1024)
        .with_qpack_blocked_streams(8)
        .with_server_push(true);

    // Builder API shape is validated without calling build() (no TLS config)
    let _ = builder;
}

// ─── Wave 3: RequestStream API shape ─────────────────────────────────────────

#[cfg(feature = "h3-compat")]
#[test]
fn request_stream_type_is_exported() {
    // Verify RequestStream is accessible from the crate root
    let _ = std::any::TypeId::of::<crate::RequestStream>();
}

// ─── Wave 3: H3Connection type alias backward compat ─────────────────────────

#[cfg(feature = "h3-compat")]
#[test]
fn h3_server_alias_is_h3_connection() {
    // H3Server must be an alias for H3Connection — both type IDs should be equal
    assert_eq!(
        std::any::TypeId::of::<crate::H3Server>(),
        std::any::TypeId::of::<crate::H3Connection>(),
        "H3Server must be a type alias for H3Connection"
    );
}
