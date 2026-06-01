//! DPLPMTUD (RFC 8899) tests.
//!
//! Three test scenarios:
//!
//! 1. `mtu_starts_at_1200` — freshly-created connection reports 1200-byte MTU.
//!
//! 2. `mtu_probe_advances_after_ack` — directly call the internal probe
//!    callbacks to verify that `current_mtu` advances on ACK and stays put on
//!    loss.
//!
//! 3. `mtu_discovery_integration` — run a real in-memory handshake, then pump
//!    timeout events until a probe advances. On loopback (where the path can
//!    carry any size), `current_mtu` must exceed 1200 after probing succeeds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{Connection, MtuConfig, TransportConfig};
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
    let dcid_len = *datagram.get(5)? as usize;
    let dcid = datagram.get(6..6 + dcid_len)?.to_vec();
    let scid_len = *datagram.get(6 + dcid_len)? as usize;
    let scid = datagram
        .get(7 + dcid_len..7 + dcid_len + scid_len)?
        .to_vec();
    Some((dcid, scid))
}

/// Build a matched client and server connection pair with a given `MtuConfig`.
fn make_pair_with_mtu(mtu_config: MtuConfig) -> (Connection, Connection) {
    let (client_cfg, server_cfg) = config_pair();
    let params = TransportConfig::default()
        .idle_timeout(Duration::from_secs(30))
        .to_transport_params();

    let mut client = Connection::new_client(
        client_cfg,
        ServerName::try_from("localhost").expect("server name"),
        addr(4433),
        params.clone(),
        mtu_config,
        Default::default(),
    )
    .expect("client conn");

    let now = Instant::now();
    let mut first = Vec::new();
    client
        .poll_transmit(now, &mut first)
        .expect("client initial");
    let (dcid, scid) = parse_initial_cids(&first).expect("parse initial cids");

    let mut server = Connection::new_server(
        server_cfg,
        oxiquic_core::ConnectionId::new(dcid),
        oxiquic_core::ConnectionId::new(scid),
        addr(40000),
        params,
        mtu_config,
        Default::default(),
    )
    .expect("server conn");

    server
        .handle_datagram(now, &mut first)
        .expect("server handle initial");
    (client, server)
}

/// Exchange all pending datagrams in both directions until quiescent at `now`.
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

// ─── Tests ───────────────────────────────────────────────────────────────────

/// A freshly-created connection always starts at the QUIC minimum 1200-byte MTU
/// regardless of the configured `max_mtu` ceiling.
#[test]
fn mtu_starts_at_1200() {
    let mtu_config = MtuConfig {
        max_mtu: 1452,
        discovery_enabled: true,
    };
    let (client_cfg, _) = config_pair();
    let params = TransportConfig::default().to_transport_params();
    let conn = Connection::new_client(
        client_cfg,
        ServerName::try_from("localhost").expect("server name"),
        addr(4433),
        params,
        mtu_config,
        Default::default(),
    )
    .expect("new_client");

    assert_eq!(
        conn.current_mtu(),
        1200,
        "connection should start at QUIC minimum 1200-byte MTU"
    );
    assert!(
        conn.probe_mtu().is_none(),
        "no probe should be in-flight before handshake"
    );
}

/// When a probe is ACK'd, `current_mtu` advances to the probe size; when a
/// probe is lost, `current_mtu` stays unchanged.
#[test]
fn mtu_probe_advances_after_ack() {
    let mtu_config = MtuConfig {
        max_mtu: 1452,
        discovery_enabled: true,
    };
    let (mut client, mut server) = make_pair_with_mtu(mtu_config);
    complete_handshake(&mut client, &mut server);
    assert!(client.is_established(), "client should be established");

    let initial_mtu = client.current_mtu();
    assert_eq!(initial_mtu, 1200, "should start at 1200");

    // Directly simulate a probe ACK at 1326 bytes (midpoint of [1200, 1452]).
    let probe_size: u16 = 1326;
    let now = Instant::now();
    client.on_mtu_probe_acked(probe_size, now);

    assert_eq!(
        client.current_mtu(),
        probe_size,
        "current_mtu should advance to acked probe size"
    );
    assert!(
        client.probe_mtu().is_none(),
        "probe_mtu should be cleared after ACK"
    );

    // Simulate a probe loss: MTU should not regress.
    let larger_probe: u16 = 1389;
    client.on_mtu_probe_lost(larger_probe);
    assert_eq!(
        client.current_mtu(),
        probe_size,
        "current_mtu must not decrease on probe loss"
    );
}

/// Integration test: run a full in-memory handshake, then advance time and pump
/// until a probe fires and gets ACK'd on the loopback path.
/// On loopback (which accepts any datagram size), MTU should exceed 1200.
#[test]
fn mtu_discovery_integration() {
    let mtu_config = MtuConfig {
        max_mtu: 1452,
        discovery_enabled: true,
    };
    let (mut client, mut server) = make_pair_with_mtu(mtu_config);
    complete_handshake(&mut client, &mut server);

    assert!(client.is_established(), "client must be established");
    assert!(server.is_established(), "server must be established");

    assert_eq!(client.current_mtu(), 1200, "should start at 1200");

    // The probe timer is armed with `Instant::now() + 200ms` inside
    // `refresh_handshake_complete`. Advance past it and pump until the probe
    // fires, gets ACK'd, and `current_mtu` advances.
    let mut now = Instant::now() + Duration::from_millis(300);
    let mut mtu_advanced = false;
    let mut probe_sent_count = 0u32;

    for round in 0..400 {
        // Fire timeout events: this may schedule the probe (first call with
        // now >= next_mtu_probe), or trigger loss-detection timers.
        let probe_mtu_before = client.probe_mtu();
        client.handle_timeout(now);
        let probe_mtu_after = client.probe_mtu();
        if probe_mtu_before.is_none() && probe_mtu_after.is_some() {
            eprintln!("round {round}: probe scheduled at {:?}", probe_mtu_after);
        }
        server.handle_timeout(now);

        // Flush all datagrams client → server (probe packet travels here).
        loop {
            let mut buf = Vec::new();
            if client.poll_transmit(now, &mut buf).is_some() && !buf.is_empty() {
                if buf.len() > 1200 {
                    probe_sent_count += 1;
                    eprintln!("round {round}: client sent oversized packet: {} bytes (probe_sent_count={})", buf.len(), probe_sent_count);
                }
                server.handle_datagram(now, &mut buf).ok();
            } else {
                break;
            }
        }
        // Flush all datagrams server → client (ACK for the probe travels here).
        let mut server_pkt_count = 0u32;
        loop {
            let mut buf = Vec::new();
            if server.poll_transmit(now, &mut buf).is_some() && !buf.is_empty() {
                server_pkt_count += 1;
                client.handle_datagram(now, &mut buf).ok();
            } else {
                break;
            }
        }
        if server_pkt_count > 0 && round < 10 {
            eprintln!(
                "round {round}: server sent {server_pkt_count} pkts, client mtu now={}",
                client.current_mtu()
            );
        }

        if client.current_mtu() > 1200 {
            mtu_advanced = true;
            eprintln!("round {round}: MTU advanced to {}", client.current_mtu());
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        mtu_advanced,
        "MTU should have advanced above 1200 on loopback path; final mtu = {}",
        client.current_mtu()
    );
    assert!(
        client.current_mtu() <= 1452,
        "MTU must not exceed configured max_mtu=1452; got {}",
        client.current_mtu()
    );
}
