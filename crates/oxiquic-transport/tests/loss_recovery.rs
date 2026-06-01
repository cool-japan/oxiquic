//! M4 loss-detection & recovery end-to-end test (RFC 9002 Sections 5–6).
//!
//! Rather than rely on a real lossy network (loopback rarely drops, and PTO
//! timing under a real clock is non-deterministic), this drives two
//! [`oxiquic_transport`] connections through a deterministic in-memory pump with
//! a manually advanced clock and an injectable per-datagram loss hook. Dropping
//! one 1-RTT datagram forces loss detection (packet/time threshold or PTO) to
//! re-queue the lost STREAM data, which is retransmitted and ultimately
//! delivered in order — proving the echo still succeeds despite the drop.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{Connection, Role, StreamId, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// Build a matched (client, server) rustls config pair over the Pure-Rust
/// OxiQUIC crypto provider, mirroring the e2e test harness.
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

/// A datagram in flight between the two endpoints.
struct Datagram {
    from_client: bool,
    bytes: Vec<u8>,
}

/// Deterministic in-memory driver for two connections with a manual clock and a
/// loss predicate. `drop_predicate(from_client, app_datagram_index)` returns
/// true to drop a datagram before delivery.
struct Pump {
    client: Connection,
    server: Connection,
    clock: Instant,
    /// Number of 1-RTT (application) datagrams the client has emitted, used to
    /// target a specific datagram for dropping.
    client_app_dgrams: u32,
    dropped: u32,
}

impl Pump {
    fn new(client: Connection, server: Connection) -> Self {
        Self {
            client,
            server,
            clock: Instant::now(),
            client_app_dgrams: 0,
            dropped: 0,
        }
    }

    /// Drain every datagram a side currently wants to send.
    fn collect(conn: &mut Connection, now: Instant, from_client: bool) -> Vec<Datagram> {
        let mut out = Vec::new();
        for _ in 0..10_000 {
            let mut buf = Vec::new();
            match conn.poll_transmit(now, &mut buf) {
                Some(_addr) if !buf.is_empty() => out.push(Datagram {
                    from_client,
                    bytes: buf,
                }),
                _ => return out,
            }
        }
        panic!(
            "Pump::collect: poll_transmit drain exceeded 10_000 iterations (runaway). \
             from_client={}, last_state: {}",
            from_client,
            conn.spin_debug_snapshot(),
        );
    }

    /// Run the handshake to completion (no loss during handshake).
    fn complete_handshake(&mut self) {
        for _ in 0..50 {
            if !self.client.is_handshaking() && !self.server.is_handshaking() {
                break;
            }
            self.exchange(|_, _| false);
        }
        assert!(
            !self.client.is_handshaking(),
            "client handshake should complete"
        );
        assert!(
            !self.server.is_handshaking(),
            "server handshake should complete"
        );
    }

    /// One exchange round: collect from both sides, apply the drop predicate,
    /// deliver survivors. Returns the number of datagrams actually delivered.
    fn exchange<F: Fn(bool, u32) -> bool>(&mut self, drop_predicate: F) -> usize {
        let now = self.clock;
        let mut datagrams = Vec::new();
        datagrams.extend(Self::collect(&mut self.client, now, true));
        datagrams.extend(Self::collect(&mut self.server, now, false));

        let mut delivered = 0;
        for dg in datagrams {
            // Track / target client application datagrams for dropping. A 1-RTT
            // packet has a short header: top bit of the first byte is clear.
            let is_app = dg.bytes.first().map(|b| b & 0x80 == 0).unwrap_or(false);
            let index = if dg.from_client && is_app {
                let i = self.client_app_dgrams;
                self.client_app_dgrams += 1;
                i
            } else {
                u32::MAX
            };
            if dg.from_client && is_app && drop_predicate(true, index) {
                self.dropped += 1;
                continue; // dropped in transit
            }
            let mut owned = dg.bytes;
            if dg.from_client {
                self.server
                    .handle_datagram(now, &mut owned)
                    .expect("server handle");
            } else {
                self.client
                    .handle_datagram(now, &mut owned)
                    .expect("client handle");
            }
            delivered += 1;
        }
        delivered
    }

    /// Advance the clock to the earliest pending timer and fire it on both
    /// sides, so PTO / loss-detection timers can elapse deterministically.
    fn advance_to_next_timer(&mut self) -> bool {
        let next = [self.client.next_timeout(), self.server.next_timeout()]
            .into_iter()
            .flatten()
            .min();
        match next {
            Some(deadline) => {
                // Jump just past the deadline.
                self.clock = deadline.max(self.clock) + Duration::from_millis(1);
                self.client.handle_timeout(self.clock);
                self.server.handle_timeout(self.clock);
                true
            }
            None => false,
        }
    }
}

/// Build a client and server connection sharing transport params with a finite
/// idle timeout and generous flow-control windows.
fn make_pair() -> (Connection, Connection) {
    make_pair_with(
        TransportConfig::default()
            .idle_timeout(Duration::from_secs(30))
            .to_transport_params(),
    )
}

/// Build a client and server connection sharing the given transport params.
fn make_pair_with(params: oxiquic_core::TransportParams) -> (Connection, Connection) {
    let (client_cfg, server_cfg) = config_pair();

    let client = Connection::new_client(
        client_cfg,
        ServerName::try_from("localhost").expect("server name"),
        addr(4433),
        params.clone(),
        Default::default(),
        Default::default(),
    )
    .expect("client conn");

    // The server connection is created from the client's first Initial packet's
    // CIDs. Drive a single client poll to obtain its Initial, parse the CIDs.
    let mut client = client;
    let now = Instant::now();
    let mut first = Vec::new();
    client
        .poll_transmit(now, &mut first)
        .expect("client initial");
    let (dcid, scid) = parse_initial_cids(&first).expect("client initial CIDs");

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

    // Feed the captured first Initial into the server before the pump starts.
    let mut server = server;
    let mut owned = first;
    server
        .handle_datagram(now, &mut owned)
        .expect("server first datagram");
    (client, server)
}

/// Extract `(dcid, scid)` from a client's first long-header Initial datagram.
fn parse_initial_cids(datagram: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    // first(1) version(4) dcid_len(1) dcid scid_len(1) scid
    let dcid_len = *datagram.get(5)? as usize;
    let dcid = datagram.get(6..6 + dcid_len)?.to_vec();
    let scid_len = *datagram.get(6 + dcid_len)? as usize;
    let scid = datagram
        .get(7 + dcid_len..7 + dcid_len + scid_len)?
        .to_vec();
    Some((dcid, scid))
}

/// M4: a dropped 1-RTT datagram carrying stream data is recovered (via PTO
/// probe retransmission) and ultimately delivered in order, so the transfer
/// succeeds despite the drop. This targets the single-packet case where the
/// PTO timer drives retransmission (RFC 9002 Section 6.2).
#[test]
fn m4_dropped_datagram_recovered_via_pto() {
    let _ = make_pair_handshake_only_smoke();

    let (client, server) = make_pair();
    let mut pump = Pump::new(client, server);
    pump.complete_handshake();

    let stream = pump.client.open_bidi().expect("open bidi stream");
    pump.client
        .send_stream(stream, b"hello-with-loss", true)
        .expect("queue stream data");

    // index 0 is the first STREAM-bearing 1-RTT datagram; drop exactly it.
    pump.client_app_dgrams = 0;

    let mut server_received = Vec::new();
    for round in 0..60 {
        pump.exchange(|from_client, idx| from_client && idx == 0);
        if let Some(id) = pump.server.poll_readable() {
            let (bytes, _fin) = pump.server.read_stream(id).expect("server read");
            server_received.extend_from_slice(&bytes);
            if server_received == b"hello-with-loss" {
                break;
            }
        }
        // Elapse PTO / loss timers so the dropped data is retransmitted.
        if round % 2 == 1 {
            pump.advance_to_next_timer();
        }
    }

    assert!(pump.dropped >= 1, "the test must have dropped a datagram");
    assert_eq!(
        server_received, b"hello-with-loss",
        "retransmitted data delivered in order despite the drop"
    );
}

/// M5 smoke: verify the in-memory harness can deliver a small payload with tiny
/// flow-control windows (sanity that the window-advance plumbing works at all).
#[test]
fn m5_flow_control_smoke() {
    let params = TransportConfig::default()
        .idle_timeout(Duration::from_secs(30))
        .stream_receive_window(4000)
        .receive_window(8000)
        .to_transport_params();
    let (client, server) = make_pair_with(params);
    let mut pump = Pump::new(client, server);
    pump.complete_handshake();

    let stream = pump.client.open_bidi().expect("open bidi stream");
    pump.client
        .send_stream(stream, b"hello-fc", false)
        .expect("send");

    let mut received: Vec<u8> = Vec::new();
    for _ in 0..20 {
        pump.exchange(|_, _| false);
        while let Some(id) = pump.server.poll_readable() {
            let (bytes, _fin) = pump.server.read_stream(id).expect("read");
            received.extend_from_slice(&bytes);
        }
        if received == b"hello-fc" {
            break;
        }
    }
    assert_eq!(received, b"hello-fc", "small payload delivered with FC");
}

/// M5: a transfer larger than the initial flow-control window must block, then
/// resume as the receiver consumes data and grants more credit via MAX_DATA /
/// MAX_STREAM_DATA (RFC 9000 Section 4.1). Verifies the full payload is
/// delivered in order despite the windows being smaller than the payload.
#[test]
fn m5_flow_control_blocks_then_resumes() {
    // Stream window 2000 bytes, connection window 3000 bytes: the 4000-byte
    // payload requires at least two window-advance cycles to deliver.
    let params = TransportConfig::default()
        .idle_timeout(Duration::from_secs(30))
        .stream_receive_window(2000)
        .receive_window(3000)
        .to_transport_params();
    let (client, server) = make_pair_with(params);
    let mut pump = Pump::new(client, server);
    pump.complete_handshake();

    let total = 4000usize;
    let payload: Vec<u8> = (0..total as u32).map(|i| (i % 251) as u8).collect();
    let stream = pump.client.open_bidi().expect("open bidi stream");
    pump.client
        .send_stream(stream, &payload, true)
        .expect("queue stream");

    let mut received: Vec<u8> = Vec::new();
    for round in 0..100 {
        pump.exchange(|_, _| false);
        // Server reads each round → window advances → MAX_DATA/MAX_STREAM_DATA.
        while let Some(id) = pump.server.poll_readable() {
            let (bytes, _fin) = pump.server.read_stream(id).expect("server read");
            received.extend_from_slice(&bytes);
        }
        if received.len() >= total {
            break;
        }
        assert!(
            round < 99,
            "flow-control stalled: received {} of {} after {} rounds",
            received.len(),
            total,
            round + 1
        );
    }

    assert_eq!(
        received.len(),
        total,
        "all bytes delivered after unblocking"
    );
    assert_eq!(received, payload, "payload intact and in order");
}

/// M5: NewReno congestion accounting — bytes in flight rise as data-bearing
/// packets are sent and fall to zero once everything is acknowledged, and the
/// congestion window never drops below the RFC 9002 minimum (RFC 9002 §7).
#[test]
fn m5_congestion_window_and_bytes_in_flight() {
    let (client, server) = make_pair();
    let mut pump = Pump::new(client, server);
    pump.complete_handshake();

    let stream = pump.client.open_bidi().expect("open bidi stream");
    let payload = vec![1u8; 4000];
    pump.client
        .send_stream(stream, &payload, true)
        .expect("send");

    // After the first send round (before any ACK), bytes are in flight and the
    // window is the RFC initial window (>= 2 * max_datagram).
    pump.exchange(|_, _| false);
    let in_flight_peak = pump.client.bytes_in_flight();
    assert!(in_flight_peak > 0, "data is in flight after sending");
    assert!(
        pump.client.congestion_window() >= 2 * 1200,
        "cwnd at least the minimum window"
    );

    // Drive to completion; once everything is acked, nothing remains in flight.
    let mut received = Vec::new();
    for _ in 0..80 {
        pump.exchange(|_, _| false);
        while let Some(id) = pump.server.poll_readable() {
            let (bytes, _fin) = pump.server.read_stream(id).expect("read");
            received.extend_from_slice(&bytes);
        }
        if received.len() >= payload.len() && pump.client.bytes_in_flight() == 0 {
            break;
        }
    }
    assert_eq!(received.len(), payload.len(), "payload delivered");
    assert_eq!(
        pump.client.bytes_in_flight(),
        0,
        "all in-flight bytes acknowledged"
    );
    // The congestion window should have grown in slow start as acks arrived.
    assert!(
        pump.client.congestion_window() >= 12000,
        "cwnd grew or held at the initial window, got {}",
        pump.client.congestion_window()
    );
}

/// M4: with several packets in flight, dropping one early packet is detected by
/// the packet-number threshold (RFC 9002 Section 6.1) once three later packets
/// are acknowledged, the lost STREAM data is re-queued, retransmitted, and the
/// full payload is delivered in order. Asserts a packet was *declared lost*.
#[test]
fn m4_packet_threshold_loss_detection_and_retransmit() {
    let (client, server) = make_pair();
    let mut pump = Pump::new(client, server);
    pump.complete_handshake();

    // A payload large enough to span several 1-RTT datagrams (~1200B each).
    let payload: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
    let stream = pump.client.open_bidi().expect("open bidi stream");
    pump.client
        .send_stream(stream, &payload, true)
        .expect("queue large stream");

    // Drop the SECOND application datagram (index 1) so later datagrams (2,3,4…)
    // can be acknowledged past it, triggering the packet-number threshold.
    pump.client_app_dgrams = 0;

    let mut received: Vec<u8> = Vec::new();
    for round in 0..120 {
        pump.exchange(|from_client, idx| from_client && idx == 1);
        if let Some(id) = pump.server.poll_readable() {
            let (bytes, _fin) = pump.server.read_stream(id).expect("server read");
            received.extend_from_slice(&bytes);
        }
        if received.len() >= payload.len() {
            break;
        }
        if round % 3 == 2 {
            pump.advance_to_next_timer();
        }
    }

    assert!(pump.dropped >= 1, "a datagram must have been dropped");
    assert_eq!(received.len(), payload.len(), "all bytes delivered");
    assert_eq!(received, payload, "payload delivered intact and in order");

    let client_stats = pump.client.stats();
    assert!(
        client_stats.packets_lost >= 1,
        "client declared the dropped packet lost (got {})",
        client_stats.packets_lost
    );
    assert!(
        client_stats.packets_sent > client_stats.packets_recv,
        "client sent more than it received (retransmissions occurred)"
    );
}

/// A small smoke helper that simply completes a handshake, used to ensure the
/// harness itself is sound independent of the loss scenario.
fn make_pair_handshake_only_smoke() -> StreamId {
    let (client, server) = make_pair();
    let mut pump = Pump::new(client, server);
    pump.complete_handshake();
    assert_eq!(pump.client.role(), Role::Client);
    assert_eq!(pump.server.role(), Role::Server);
    // Return a throwaway stream id to keep the smoke self-contained.
    pump.client.open_bidi().expect("open bidi stream")
}

/// M4: with no loss, the in-memory echo round-trip completes (sanity that the
/// recovery machinery does not perturb the lossless path).
#[test]
fn m4_lossless_echo_in_memory_round_trip() {
    let (client, server) = make_pair();
    let mut pump = Pump::new(client, server);
    pump.complete_handshake();

    let stream = pump.client.open_bidi().expect("open bidi stream");
    pump.client
        .send_stream(stream, b"ping", false)
        .expect("send");

    let mut echoed: Option<Vec<u8>> = None;
    for _ in 0..40 {
        pump.exchange(|_, _| false);
        // Server echoes whatever it reads back on the same stream.
        if let Some(id) = pump.server.poll_readable() {
            let (bytes, _fin) = pump.server.read_stream(id).expect("server read");
            if !bytes.is_empty() {
                pump.server.send_stream(id, &bytes, false).expect("echo");
            }
        }
        // Client reads the echo.
        let (bytes, _fin) = pump.client.read_stream(stream).expect("client read");
        if !bytes.is_empty() {
            echoed = Some(bytes);
            break;
        }
    }
    assert_eq!(echoed.expect("client read echo"), b"ping");
}
