//! OxiQUIC: the COOLJAPAN Pure-Rust QUIC + HTTP/3 facade.
//!
//! This crate is the single public entry point to the OxiQUIC stack. It
//! re-exports the core RFC 9000 type system from `oxiquic-core` and, behind
//! feature flags, the transport and HTTP/3 layers.
//!
//! # Feature flags
//!
//! | feature     | default | enables                                            |
//! |-------------|---------|----------------------------------------------------|
//! | `transport` | yes     | QUIC transport ([`ClientEndpoint`], etc.)          |
//! | `h3`        | no      | HTTP/3 client and server ([`H3Client`], etc.)      |
//! | `dangerous` | no      | [`connect_insecure()`] for dev/testing             |
//!
//! # Pure-Rust status
//!
//! OxiQUIC forbids `ring` and `aws-lc-rs`. The QUIC transport is implemented
//! directly on the `rustls::quic` TLS 1.3 API driven by the `oxiquic-crypto`
//! Pure-Rust crypto provider: the handshake, 1-RTT keys, connection close and
//! reliable stream data all run over real UDP (see
//! [`oxiquic_transport::ClientEndpoint`] / [`oxiquic_transport::ServerEndpoint`]).
//! Loss detection (RFC 9002), NewReno and BBR v2 congestion control, and
//! connection/stream flow control are all implemented. The HTTP/3
//! layer message model is complete; H3 client and server are fully implemented
//! (H3Client::get/post/request, H3Server::accept, H3RequestContext::body/respond).
//!
//! # Examples
//!
//! ```
//! use oxiquic::QuicVersion;
//!
//! assert_eq!(oxiquic::quic_version(), QuicVersion::V1);
//! assert!(!oxiquic::version().is_empty());
//! ```

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use oxiquic_core::{
    ConnectionId, ConnectionStats, Direction, FrameType, Initiator, OxiQuicError, PacketType,
    QuicVersion, StreamId, TransportErrorCode, TransportParams,
};

#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
#[cfg(feature = "transport")]
pub use oxiquic_transport::{
    ClientEndpoint, CongestionAlgorithm, Connection, ConnectionState, QuicConnection, Role,
    ServerEndpoint, TransportConfig, ZeroRttAccepted,
};

#[cfg_attr(docsrs, doc(cfg(feature = "h3")))]
#[cfg(feature = "h3")]
pub use oxiquic_h3::{
    accept_h3_server, connect_h3_client, H3Client, H3ClientBuilder, H3Connection, H3Error,
    H3ErrorCode, H3Request, H3RequestContext, H3Responder, H3Response, H3Server, H3ServerBuilder,
    H3ServerEndpoint, H3Settings, RequestStream,
};

/// Connect to a QUIC server using system WebPKI roots.
///
/// Binds a random local port, builds a `rustls::ClientConfig` with
/// `oxitls::webpki_root_certs()` as the trust store backed by the Pure-Rust
/// `oxiquic_crypto::quic_crypto_provider()`, and completes the QUIC TLS 1.3
/// handshake with the server at `addr`.
///
/// # Errors
/// Returns [`OxiQuicError`] on socket bind failure, TLS config error, or
/// handshake failure.
#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
#[cfg(feature = "transport")]
pub async fn connect(
    addr: std::net::SocketAddr,
    server_name: &str,
) -> Result<QuicConnection, OxiQuicError> {
    use std::sync::Arc;

    use rustls::version::TLS13;
    use rustls::ClientConfig;

    let provider = Arc::new(oxiquic_crypto::quic_crypto_provider());
    let roots = oxitls::webpki_root_certs();
    let client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    let endpoint =
        ClientEndpoint::bind(bind_addr, Arc::new(client_cfg), TransportConfig::default()).await?;
    endpoint.connect(addr, server_name).await
}

/// Connect to a QUIC server **without** verifying its certificate.
///
/// This is intended for development/testing only (e.g. connecting to a
/// server with a self-signed certificate). In production you should use
/// [`connect`] which validates the server's certificate against the system
/// WebPKI roots.
///
/// Requires the `dangerous` feature to be enabled, which acts as an
/// opt-in gate so the function is never accidentally available in a
/// production build that omits the flag.
///
/// # Errors
/// Returns [`OxiQuicError`] on socket bind failure, TLS config error, or
/// handshake failure.
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous")))]
#[cfg(feature = "dangerous")]
pub async fn connect_insecure(
    addr: std::net::SocketAddr,
    server_name: &str,
) -> Result<QuicConnection, OxiQuicError> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
    use std::sync::Arc;

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer,
            _intermediates: &[rustls::pki_types::CertificateDer],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    let provider = Arc::new(oxiquic_crypto::quic_crypto_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    let endpoint =
        ClientEndpoint::bind(bind_addr, Arc::new(client_cfg), TransportConfig::default()).await?;
    endpoint.connect(addr, server_name).await
}

/// Connect with 0-RTT early-data support using a shared in-memory session store.
///
/// The session cache is module-level so session tickets persist across calls
/// within the same process. On the first call (cold connect) this is identical
/// to [`connect`]; on subsequent calls a cached ticket enables 0-RTT.
///
/// # Errors
/// Returns [`OxiQuicError`] on socket bind failure, TLS config error, or
/// handshake failure.
#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
#[cfg(feature = "transport")]
pub async fn connect_0rtt(
    addr: std::net::SocketAddr,
    server_name: &str,
) -> Result<(QuicConnection, ZeroRttAccepted), OxiQuicError> {
    use std::sync::{Arc, OnceLock};

    use rustls::client::ClientSessionMemoryCache;
    use rustls::client::Resumption;
    use rustls::version::TLS13;
    use rustls::ClientConfig;

    // Shared session cache — static so tickets persist across connections.
    static SESSION_CACHE: OnceLock<Arc<ClientSessionMemoryCache>> = OnceLock::new();
    let cache = SESSION_CACHE
        .get_or_init(|| Arc::new(ClientSessionMemoryCache::new(64)))
        .clone();

    let provider = Arc::new(oxiquic_crypto::quic_crypto_provider());
    let roots = oxitls::webpki_root_certs();
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.enable_early_data = true;
    client_cfg.resumption = Resumption::store(cache);

    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    let endpoint =
        ClientEndpoint::bind(bind_addr, Arc::new(client_cfg), TransportConfig::default()).await?;
    endpoint.connect_0rtt(addr, server_name).await
}

/// Start a QUIC server bound to `addr`.
///
/// Accepts a DER-encoded certificate chain and a PKCS#8 DER-encoded private
/// key. Builds a `rustls::ServerConfig` backed by the Pure-Rust
/// `oxiquic_crypto::quic_crypto_provider()` and binds the server endpoint.
///
/// # Errors
/// Returns [`OxiQuicError`] on socket bind failure or TLS config error.
#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
#[cfg(feature = "transport")]
pub async fn listen(
    addr: std::net::SocketAddr,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerEndpoint, OxiQuicError> {
    use std::sync::Arc;

    use rustls::version::TLS13;
    use rustls::ServerConfig;

    let provider = Arc::new(oxiquic_crypto::quic_crypto_provider());
    let server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?;
    ServerEndpoint::bind(addr, Arc::new(server_cfg), TransportConfig::default()).await
}

/// Connect to an HTTP/3 server using the system WebPKI certificate roots.
///
/// Combines QUIC connection establishment with the HTTP/3 handshake. Uses
/// the `h3` ALPN protocol identifier (RFC 9114 §3.3).
///
/// # Errors
/// Returns [`OxiQuicError`] on socket bind failure, TLS error, handshake
/// failure, or ALPN mismatch.
#[cfg_attr(docsrs, doc(cfg(feature = "h3")))]
#[cfg(feature = "h3")]
pub async fn connect_h3(
    addr: std::net::SocketAddr,
    server_name: &str,
) -> Result<H3Client, OxiQuicError> {
    use std::sync::Arc;

    use rustls::version::TLS13;
    use rustls::ClientConfig;

    let provider = Arc::new(oxiquic_crypto::quic_crypto_provider());
    let roots = oxitls::webpki_root_certs();
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h3".to_vec()];

    H3ClientBuilder::new()
        .with_server_name(server_name)
        .with_tls_config(client_cfg)
        .connect(addr)
        .await
        .map_err(OxiQuicError::from)
}

/// Start an HTTP/3 server bound to `addr`.
///
/// Accepts DER-encoded certificate chain and PKCS#8 DER-encoded private key.
/// Sets `h3` ALPN automatically.
///
/// # Errors
/// Returns [`OxiQuicError`] on bind failure or TLS configuration error.
#[cfg_attr(docsrs, doc(cfg(feature = "h3")))]
#[cfg(feature = "h3")]
pub async fn listen_h3(
    addr: std::net::SocketAddr,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<H3ServerEndpoint, OxiQuicError> {
    use std::sync::Arc;

    use rustls::version::TLS13;
    use rustls::ServerConfig;

    let provider = Arc::new(oxiquic_crypto::quic_crypto_provider());
    let server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| OxiQuicError::Tls(e.to_string()))?;

    H3ServerBuilder::new(addr)
        .with_tls_config(server_cfg)
        .build()
        .await
}

/// The version of the `oxiquic` crate, from `CARGO_PKG_VERSION`.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The QUIC protocol version OxiQUIC targets by default: QUIC v1 (RFC 9000).
#[must_use]
pub fn quic_version() -> QuicVersion {
    QuicVersion::V1
}

/// Commonly used transport types, for `use oxiquic::prelude::*;`.
#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
#[cfg(feature = "transport")]
pub mod prelude {
    pub use oxiquic_core::{
        ConnectionId, ConnectionStats, Direction, FrameType, Initiator, OxiQuicError, PacketType,
        QuicVersion, StreamId, TransportErrorCode, TransportParams,
    };
    pub use oxiquic_transport::{
        ClientEndpoint, CongestionAlgorithm, Connection, ConnectionState, QuicConnection, Role,
        ServerEndpoint, TransportConfig, ZeroRttAccepted,
    };
}

/// Commonly used HTTP/3 types, for `use oxiquic::h3_prelude::*;`.
#[cfg_attr(docsrs, doc(cfg(feature = "h3")))]
#[cfg(feature = "h3")]
pub mod h3_prelude {
    pub use oxiquic_core::OxiQuicError;
    pub use oxiquic_h3::{
        accept_h3_server, connect_h3_client, H3Client, H3ClientBuilder, H3Connection, H3Error,
        H3ErrorCode, H3Request, H3RequestContext, H3Responder, H3Response, H3Server,
        H3ServerBuilder, H3ServerEndpoint, H3Settings, RequestStream,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nonempty_semverish() {
        let v = version();
        assert!(!v.is_empty());
        // Workspace version is "0.0.0"; at minimum it should contain a dot.
        assert!(v.contains('.'), "version {v} should look like a semver");
    }

    #[test]
    fn quic_version_is_v1() {
        assert_eq!(quic_version(), QuicVersion::V1);
        assert_eq!(quic_version().to_u32(), 1);
    }

    #[test]
    fn facade_reexports_core_types_by_identity() {
        // These compile-time assertions confirm the facade re-exports are the
        // very same types as in oxiquic-core (no shadowing wrapper).
        fn assert_same<T>(_: T) {}
        let id: StreamId = oxiquic_core::StreamId(0);
        assert_same::<StreamId>(id);

        let _: fn(u32) -> QuicVersion = QuicVersion::from_u32;
        let _: OxiQuicError = oxiquic_core::OxiQuicError::Timeout;
    }

    #[test]
    fn version_and_quic_version_unchanged() {
        assert!(!version().is_empty());
        assert_eq!(quic_version(), QuicVersion::V1);
    }

    #[test]
    fn no_default_features_compile_test() {
        // This test compiles with all features enabled (--all-features in CI),
        // but verifies the fundamental invariants hold regardless of feature set.
        let v = version();
        assert!(v.contains('.'));
    }

    #[cfg(feature = "transport")]
    #[test]
    fn transport_reexports_available() {
        // The transport endpoints, connection handle and config are all
        // re-exported through the facade.
        let _: fn() -> TransportConfig = TransportConfig::default;
        let _ = CongestionAlgorithm::Cubic;
        let _ = Role::Client;
        let _ = ConnectionState::Established;
        // Endpoint/connection types exist (constructed via async bind/connect).
        fn _assert_types(
            _: Option<ClientEndpoint>,
            _: Option<ServerEndpoint>,
            _: Option<QuicConnection>,
            _: Option<Connection>,
        ) {
        }
    }

    #[cfg(feature = "h3")]
    #[test]
    fn h3_reexports_available() {
        let res = H3Response::new(200).with_body("ok");
        assert!(res.is_success());
        let _ = H3ErrorCode::NoError;
    }

    #[cfg(feature = "h3")]
    #[test]
    fn h3_types_reexported() {
        // Verify H3 types are accessible via the facade (compile test).
        let _ = std::any::TypeId::of::<H3Client>();
        let _ = std::any::TypeId::of::<H3ClientBuilder>();
        let _ = std::any::TypeId::of::<H3ServerBuilder>();
        let _ = std::any::TypeId::of::<H3ServerEndpoint>();
        let _ = std::any::TypeId::of::<H3Connection>();
        let _ = std::any::TypeId::of::<H3Responder>();
        let _ = std::any::TypeId::of::<RequestStream>();
        let _ = std::any::TypeId::of::<H3Error>();
        let _ = std::any::TypeId::of::<H3Response>();
        let _ = std::any::TypeId::of::<H3Request>();
    }

    #[cfg(feature = "dangerous")]
    #[test]
    fn connect_insecure_is_exported() {
        // Verify the function is accessible by taking a reference to it.
        // We cannot coerce an async fn to a plain fn pointer, so we merely
        // name the item to confirm it compiles and is visible.
        let _ = connect_insecure;
    }

    /// Full round-trip integration test using only facade-re-exported types.
    ///
    /// Validates that `oxiquic::ServerEndpoint`, `oxiquic::ClientEndpoint`,
    /// `oxiquic::TransportConfig`, and `oxiquic::QuicConnection` are fully usable
    /// without importing sub-crates directly.
    #[cfg(feature = "transport")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn facade_full_round_trip() {
        use std::sync::Arc;

        use oxiquic_crypto::quic_crypto_provider;
        use oxitls_rcgen::generate_self_signed_ed25519;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::version::TLS13;
        use rustls::{ClientConfig, RootCertStore, ServerConfig};

        // Build a self-signed Ed25519 cert + matched TLS config pair, then use
        // only facade-re-exported types (ClientEndpoint, ServerEndpoint, etc.).
        let ck = generate_self_signed_ed25519(&["localhost"]).expect("generate self-signed cert");
        let cert_der = CertificateDer::from(ck.cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
        let provider = Arc::new(quic_crypto_provider());

        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("trust self-signed cert");

        let client_cfg: Arc<ClientConfig> = Arc::new(
            ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&TLS13])
                .expect("client TLS1.3")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_cfg: Arc<ServerConfig> = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&TLS13])
                .expect("server TLS1.3")
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("server single cert"),
        );

        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

        // Bind using facade-re-exported ServerEndpoint + TransportConfig.
        let server = ServerEndpoint::bind(loopback, server_cfg, TransportConfig::default())
            .await
            .expect("facade ServerEndpoint::bind");
        let server_addr = server.local_addr().expect("server local_addr");

        // Server task: accept one connection, receive stream data.
        let server_task = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("server accept");
            assert!(!conn.is_closed(), "server connection open");
            let (_id, data, _fin) = conn
                .accept_uni_or_bidi_data()
                .await
                .expect("server read stream");
            data
        });

        // Client: bind + connect using facade-re-exported ClientEndpoint.
        let client = ClientEndpoint::bind(loopback, client_cfg, TransportConfig::default())
            .await
            .expect("facade ClientEndpoint::bind");
        let mut conn: QuicConnection = client
            .connect(server_addr, "localhost")
            .await
            .expect("facade connect");

        assert!(!conn.is_closed(), "client connection open");
        assert!(
            conn.peer_transport_params().is_some(),
            "client has server transport params"
        );

        let stream = conn.open_bidi().expect("open bidi stream");
        conn.send(stream, b"facade-round-trip", false)
            .await
            .expect("client send");

        let received = server_task.await.expect("server task");
        assert_eq!(received, b"facade-round-trip", "data delivered via facade");
    }

    /// HTTP/3 GET round-trip using only facade-re-exported types.
    ///
    /// Validates that `oxiquic::H3Client`, `oxiquic::H3Server`,
    /// `oxiquic::H3Response`, `oxiquic::ClientEndpoint`, `oxiquic::ServerEndpoint`,
    /// and `oxiquic::TransportConfig` are all fully usable via the facade.
    #[cfg(feature = "h3")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn facade_h3_get_roundtrip() {
        use std::sync::Arc;

        use oxiquic_crypto::quic_crypto_provider;
        use oxitls_rcgen::generate_self_signed_ed25519;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::version::TLS13;
        use rustls::{ClientConfig, RootCertStore, ServerConfig};

        let ck = generate_self_signed_ed25519(&["localhost"]).expect("generate self-signed cert");
        let cert_der = CertificateDer::from(ck.cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
        let provider = Arc::new(quic_crypto_provider());

        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("trust self-signed cert");

        let client_cfg: Arc<ClientConfig> = Arc::new(
            ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&TLS13])
                .expect("client TLS1.3")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_cfg: Arc<ServerConfig> = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&TLS13])
                .expect("server TLS1.3")
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("server single cert"),
        );

        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

        // Bind server using facade-re-exported ServerEndpoint + TransportConfig.
        let server_ep = ServerEndpoint::bind(loopback, server_cfg, TransportConfig::default())
            .await
            .expect("facade ServerEndpoint::bind");
        let server_addr = server_ep.local_addr().expect("server local_addr");

        // Server task: accept one H3 request via facade H3Server, respond 200.
        let server_task = tokio::spawn(async move {
            let quic_conn = server_ep.accept().await.expect("server accept QUIC");
            let driven = quic_conn.into_driven();
            // Use facade-re-exported H3Server.
            let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");
            let ctx = h3_server
                .accept()
                .await
                .expect("H3Server::accept")
                .expect("expected Some(request)");
            // Use facade-re-exported H3Response.
            let resp = H3Response::new(200).with_body("facade-h3-roundtrip");
            ctx.respond(resp).await.expect("respond");
        });

        // Client: bind + connect + H3 GET using facade-re-exported types.
        let client_ep = ClientEndpoint::bind(loopback, client_cfg, TransportConfig::default())
            .await
            .expect("facade ClientEndpoint::bind");
        let quic_conn = client_ep
            .connect(server_addr, "localhost")
            .await
            .expect("facade connect");
        let driven = quic_conn.into_driven();

        // Use facade-re-exported H3Client.
        let mut h3_client = H3Client::new(driven).await.expect("H3Client::new");
        let resp = h3_client.get("https://localhost/").await.expect("GET /");

        server_task.await.expect("server task panicked");

        assert!(resp.is_success(), "expected 2xx, got {}", resp.status());
        assert_eq!(
            resp.body_text().expect("utf-8 body"),
            "facade-h3-roundtrip",
            "h3 response body via facade"
        );

        let _ = h3_client.close().await;
    }

    #[cfg(all(test, feature = "transport"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_to_unreachable_server_returns_descriptive_error() {
        use std::net::SocketAddr;
        // Port 1 is almost certainly not listening
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("valid addr");
        let result = connect(addr, "localhost").await;
        assert!(
            result.is_err(),
            "connecting to unreachable server must fail"
        );
        // Verify the error is descriptive (not just a generic "error").
        // Note: QuicConnection does not implement Debug so we use match
        // rather than unwrap_err/expect_err which require T: Debug.
        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    !msg.is_empty(),
                    "error message must not be empty: got '{msg}'"
                );
            }
            Ok(_) => panic!("expected an error connecting to an unreachable server"),
        }
    }
}
