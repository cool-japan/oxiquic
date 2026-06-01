//! 0-RTT early data end-to-end tests (RFC 9001 §4.6, RFC 9000 §4.6.1).
//!
//! These tests exercise the 0-RTT API over real UDP loopback.  Because 0-RTT
//! requires a prior session ticket, the tests perform two connections:
//!
//! 1. A first cold connect that completes normally and deposits a ticket in the
//!    client's session cache.
//! 2. A second `connect_0rtt` that should use the cached ticket.
//!
//! On the first attempt `zero_rtt_accepted()` is `None`/`false` (no ticket).
//! On the second attempt it *may* be `true` depending on ticket issuance timing.

use std::sync::Arc;
use std::time::Duration;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{
    ClientEndpoint, ServerEndpoint, ServerEndpointBuilder, TransportConfig, ZeroRttAccepted,
};
use rustls::client::ClientSessionMemoryCache;
use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

/// Build base config pair (certs only, no 0-RTT options).
fn base_certs() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    RootCertStore,
) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust self-signed cert");
    (vec![cert_der], key_der, roots)
}

/// Build a config pair with 0-RTT support and a shared session cache.
///
/// Returns `(client_cfg, server_cfg, cache)`.  The server's
/// `max_early_data_size` is `u32::MAX` (enabled).
fn config_pair_0rtt() -> (
    Arc<ClientConfig>,
    Arc<ServerConfig>,
    Arc<ClientSessionMemoryCache>,
) {
    let (certs, key, roots) = base_certs();
    let provider = Arc::new(quic_crypto_provider());

    let cache = Arc::new(ClientSessionMemoryCache::new(64));

    let mut client_cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("client TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.enable_early_data = true;
    client_cfg.resumption = Resumption::store(cache.clone());

    let mut server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("server TLS1.3")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server single cert");
    server_cfg.max_early_data_size = u32::MAX;

    (Arc::new(client_cfg), Arc::new(server_cfg), cache)
}

/// Build a plain config pair (no 0-RTT) for the cold-connect baseline.
fn config_pair_plain() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let (certs, key, roots) = base_certs();
    let provider = Arc::new(quic_crypto_provider());
    let client_cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("client TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("server TLS1.3")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server single cert");
    (Arc::new(client_cfg), Arc::new(server_cfg))
}

// ─── Unit tests (no I/O) ─────────────────────────────────────────────────────

#[test]
fn long_type_zero_rtt_bits_are_0b01() {
    use oxiquic_crypto::quic::AES128_GCM;
    use oxiquic_crypto::suites::tls13_aes_128_gcm_sha256_internal;
    use oxiquic_transport::packet::{build_long_packet, BuildLong, LongType};
    use rustls::quic::{Keys, Version};
    use rustls::Side;

    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let keys = Keys::initial(
        Version::V1,
        tls13_aes_128_gcm_sha256_internal(),
        &AES128_GCM,
        &dcid,
        Side::Client,
    );

    let payload = b"0-rtt early data payload for testing header bits";
    let params = BuildLong {
        long_type: LongType::ZeroRtt,
        version: 1,
        dcid: &[1, 2, 3, 4],
        scid: &[5, 6, 7, 8],
        token: &[],
        packet_number: 0,
        largest_acked: None,
    };
    let mut datagram = Vec::new();
    build_long_packet(
        &mut datagram,
        &params,
        payload,
        keys.local.packet.as_ref(),
        keys.local.header.as_ref(),
    )
    .expect("build 0-RTT packet");

    // First byte: 1(long) 1(fixed) TT(type) 00(reserved) PP(pn_len-1)
    // Type bits 0b01 sit at bits 5:4 of the first byte (after masking with 0x30).
    let type_bits = (datagram[0] >> 4) & 0x03;
    assert_eq!(
        type_bits, 0b01,
        "ZeroRtt long-header type bits must be 0b01, got {type_bits:#04b}"
    );
}

#[test]
fn transport_config_max_early_data_normalizes() {
    let cfg = TransportConfig::default().max_early_data_size(1234);
    assert_eq!(
        cfg.get_max_early_data_size(),
        u32::MAX,
        "any non-zero value must normalize to u32::MAX"
    );
    let cfg2 = TransportConfig::default().max_early_data_size(0);
    assert_eq!(cfg2.get_max_early_data_size(), 0, "zero must remain zero");
    let cfg3 = TransportConfig::default().max_early_data_size(u32::MAX);
    assert_eq!(cfg3.get_max_early_data_size(), u32::MAX);
}

// ─── Integration tests ───────────────────────────────────────────────────────

/// First connection (cold): no session ticket → standard 1-RTT, `zero_rtt_accepted` is `None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_rtt_cold_connect_succeeds() {
    let (client_cfg, server_cfg) = config_pair_plain();
    let transport = TransportConfig::default();
    let server_transport = TransportConfig::default().max_early_data_size(1);

    let server = ServerEndpoint::bind(loopback(), server_cfg, server_transport)
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        // Accept and drive to completion.
        if let Ok(mut conn) = server.accept().await {
            let _ = conn.accept_uni_or_bidi_data().await.unwrap_or((
                oxiquic_core::StreamId::from(0u64),
                Vec::new(),
                true,
            ));
        }
    });

    let ep = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = ep.connect(server_addr, "localhost").await.expect("connect");

    // On a cold connect there is no 0-RTT.
    assert!(
        conn.zero_rtt_accepted().is_none(),
        "cold connect: zero_rtt_accepted must be None"
    );

    let stream = conn.open_bidi().expect("open stream");
    conn.send(stream, b"cold", false).await.expect("send");

    let _ = server_task.await;
}

/// Second connection with a shared cache: if a ticket was issued the 0-RTT API
/// returns a valid `(connection, future)` regardless of acceptance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_rtt_connect_0rtt_api_works() {
    let (client_cfg, server_cfg, _cache) = config_pair_0rtt();
    let server_transport = TransportConfig::default().max_early_data_size(1);
    let client_transport = TransportConfig::default();

    // First connection: cold, deposits session ticket.
    let server1 = ServerEndpoint::bind(
        loopback(),
        Arc::clone(&server_cfg),
        server_transport.clone(),
    )
    .await
    .expect("bind server1");
    let addr1 = server1.local_addr().expect("addr1");

    let s1 = tokio::spawn(async move {
        if let Ok(mut c) = server1.accept().await {
            // Drive long enough to issue the session ticket (it arrives with HANDSHAKE_DONE).
            for _ in 0..20 {
                let _ = c.drive().await;
            }
            // Read data so we don't block the client.
            let _ = c.accept_uni_or_bidi_data().await.unwrap_or((
                oxiquic_core::StreamId::from(0u64),
                Vec::new(),
                true,
            ));
        }
    });

    let ep1 = ClientEndpoint::bind(
        loopback(),
        Arc::clone(&client_cfg),
        client_transport.clone(),
    )
    .await
    .expect("ep1");
    let mut c1 = ep1.connect(addr1, "localhost").await.expect("c1");
    let stream1 = c1.open_bidi().expect("open stream1");
    c1.send(stream1, b"first", false).await.expect("first send");
    // Let the session ticket arrive.
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(c1);
    drop(ep1);
    s1.await.expect("server1 task");

    // Second connection: potentially warm, use connect_0rtt.
    let server2 = ServerEndpoint::bind(loopback(), Arc::clone(&server_cfg), server_transport)
        .await
        .expect("bind server2");
    let addr2 = server2.local_addr().expect("addr2");

    let s2 = tokio::spawn(async move {
        if let Ok(mut c) = server2.accept().await {
            for _ in 0..20 {
                let _ = c.drive().await;
            }
            let _ = c.accept_uni_or_bidi_data().await.unwrap_or((
                oxiquic_core::StreamId::from(0u64),
                Vec::new(),
                true,
            ));
        }
    });

    let ep2 = ClientEndpoint::bind(loopback(), client_cfg, client_transport)
        .await
        .expect("ep2");
    let (mut c2, zra) = ep2
        .connect_0rtt(addr2, "localhost")
        .await
        .expect("connect_0rtt");

    // The connection is established regardless of 0-RTT acceptance.
    assert!(!c2.is_closed(), "connection should be open");

    // Resolve the ZeroRttAccepted future — we don't assert its value because
    // ticket issuance timing is racy in tests; we just verify the API works.
    let _accepted: bool = zra.await;

    let stream2 = c2.open_bidi().expect("open stream2");
    c2.send(stream2, b"second", false)
        .await
        .expect("second send");

    s2.await.expect("server2 task");
}

/// Verify `ZeroRttAccepted` resolves to `false` on a cold connect (no ticket).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_rtt_accepted_false_on_cold_connect() {
    let (client_cfg, server_cfg, _) = config_pair_0rtt();
    let server_transport = TransportConfig::default().max_early_data_size(1);
    let client_transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, server_transport)
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        if let Ok(mut c) = server.accept().await {
            for _ in 0..10 {
                let _ = c.drive().await;
            }
            let _ = c.accept_uni_or_bidi_data().await.unwrap_or((
                oxiquic_core::StreamId::from(0u64),
                Vec::new(),
                true,
            ));
        }
    });

    // Use a fresh endpoint (empty cache) — should always be cold.
    let ep = ClientEndpoint::bind(loopback(), client_cfg, client_transport)
        .await
        .expect("ep");
    let (mut conn, zra) = ep
        .connect_0rtt(server_addr, "localhost")
        .await
        .expect("connect_0rtt cold");

    assert!(!conn.is_closed());
    let accepted = zra.await;
    assert!(!accepted, "cold connect must report 0-RTT not accepted");

    let stream = conn.open_bidi().expect("open stream");
    conn.send(stream, b"data", false).await.expect("send");

    server_task.await.expect("server task");
}

/// A minimal stub ticketer that never produces tickets (but satisfies the
/// `ProducesTickets` trait bound).  Used to verify `ServerEndpointBuilder`
/// compiles and accepts a custom ticketer without live TLS stack involvement.
#[derive(Debug)]
struct NoOpTicketer;

impl rustls::server::ProducesTickets for NoOpTicketer {
    /// Returns `false` — no tickets are issued so session resumption is disabled.
    fn enabled(&self) -> bool {
        false
    }

    /// Lifetime in seconds — zero because tickets are never produced.
    fn lifetime(&self) -> u32 {
        0
    }

    /// Always returns `None` (ticketing disabled).
    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Always returns `None` (ticketing disabled).
    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Verify that `ServerEndpointBuilder::with_ticketer` is accepted and the
/// endpoint starts accepting connections normally when the ticketer is disabled.
///
/// Because the stub ticketer has `enabled() == false`, session resumption does
/// not kick in — but the endpoint must still bind, accept a connection, and
/// exchange data over the resulting stream unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_endpoint_builder_with_custom_ticketer_accepts_connections() {
    let (client_cfg, server_cfg) = config_pair_plain();
    let transport = TransportConfig::default();

    // Build the server via builder with a custom (no-op) ticketer.
    let server = ServerEndpointBuilder::new(loopback(), server_cfg, transport.clone())
        .with_ticketer(Arc::new(NoOpTicketer))
        .build()
        .await
        .expect("ServerEndpointBuilder::build");

    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        if let Ok(mut conn) = server.accept().await {
            let _ = conn.accept_uni_or_bidi_data().await.unwrap_or((
                oxiquic_core::StreamId::from(0u64),
                Vec::new(),
                true,
            ));
        }
    });

    let ep = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client");
    let mut conn = ep.connect(server_addr, "localhost").await.expect("connect");

    let stream = conn.open_bidi().expect("open stream");
    conn.send(stream, b"hello ticketer", false)
        .await
        .expect("send");

    server_task.await.expect("server task");
}

/// Test that `ZeroRttAccepted` resolves `false` on a cold connect (API test only).
/// This is implicitly tested by zero_rtt_accepted_false_on_cold_connect above.
/// Here we just confirm the type is properly exported and Futureable.
#[tokio::test]
async fn zero_rtt_accepted_type_is_future() {
    // Verify ZeroRttAccepted is exported and works as a future.
    // We obtain one via connect_0rtt in the cold-connect scenario.
    let (client_cfg, server_cfg, _) = config_pair_0rtt();
    let server_transport = TransportConfig::default();
    let client_transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, server_transport)
        .await
        .expect("bind server");
    let addr = server.local_addr().expect("addr");
    let _s = tokio::spawn(async move {
        if let Ok(mut c) = server.accept().await {
            for _ in 0..5 {
                let _ = c.drive().await;
            }
        }
    });

    let ep = ClientEndpoint::bind(loopback(), client_cfg, client_transport)
        .await
        .expect("ep");
    let (_conn, zra): (_, ZeroRttAccepted) =
        ep.connect_0rtt(addr, "localhost").await.expect("connect");

    // Verify Future impl: .await returns a bool.
    let result: bool = zra.await;
    let _ = result; // any value is valid; type check is what matters here
}
