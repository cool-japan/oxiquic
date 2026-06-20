//! Congestion control comparison: Cubic vs BBR vs NewReno on a simulated
//! in-process lossy network.
//!
//! Because `tc`/`netem` requires root + Linux kernel modules, we implement
//! a self-contained lossy network simulator using `tokio::sync::mpsc` channels
//! with deterministic packet-drop injection. Each "drop profile" specifies:
//!
//! - A random-drop probability (uniform i.i.d. Bernoulli drops).
//! - An added round-trip delay (simulated by sleeping before forwarding each
//!   datagram in each direction).
//!
//! The simulator wraps the real loopback socket so that:
//!
//! 1. All datagrams pass through the channel pair.
//! 2. The *lossy relay tasks* drop packets according to the configured profile
//!    and add delay (if > 0) before forwarding.
//! 3. The QUIC stack observes the simulated network conditions and responds
//!    with its congestion controller.
//!
//! Benchmark groups:
//!
//! - `cc_compare/lossless`     — 0% drop, 0 ms added RTT (baseline sanity check)
//! - `cc_compare/light_loss`   — 1% drop, 10 ms added per-packet delay each way
//! - `cc_compare/medium_loss`  — 3% drop, 30 ms delay
//!
//! Each group runs Cubic, BBR, and NewReno back-to-back so the criterion HTML
//! report shows a side-by-side comparison.
//!
//! Benchmark overview:
//!
//! - `bench_cc_compare` — throughput (bytes/s) for 512 KiB payload under each
//!   profile × algorithm, using a fresh connection per iteration.
//! - `bench_cc_cwnd_growth` — congestion window growth (unit test via
//!   CongestionController directly), measuring Cubic vs BBR cwnd after N acks.
//!
//! The lossy relay is purely in-process (no kernel tc/netem); all packets go
//! through loopback but are intercepted and optionally dropped before being
//! forwarded to the far endpoint's socket.

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, CongestionAlgorithm, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers shared with transport.rs but duplicated here for self-containment
// ─────────────────────────────────────────────────────────────────────────────

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("tokio runtime for cc-compare bench")
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("parse loopback addr")
}

fn config_pair(
    algo: CongestionAlgorithm,
) -> (Arc<ClientConfig>, Arc<ServerConfig>, TransportConfig) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate Ed25519 cert for cc-compare");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust self-signed cert");

    let client_cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3 client config")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3 server config")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("single-cert server config");

    let transport = TransportConfig::default().congestion_controller(algo);

    (Arc::new(client_cfg), Arc::new(server_cfg), transport)
}

// ─────────────────────────────────────────────────────────────────────────────
// In-process lossy network simulation
//
// The strategy:
//   1. Bind two additional UDP sockets as "relay ingress" points.
//   2. Client connects to the relay-client-ingress address (not the server
//      directly).
//   3. Relay tasks:
//      - client→server relay: read from relay-client-ingress, maybe drop,
//        maybe delay, forward to server's real address.
//      - server→client relay: read from relay-server-ingress, maybe drop,
//        maybe delay, forward to client's real address.
//   4. The server is configured to send back to relay-server-ingress so that
//      replies also pass through the relay.
//
// Because QUIC endpoints bind to fixed local addresses, we intercept packets
// by injecting relay sockets that forward to the real endpoints. The relay
// task remembers the client's source address on the first packet (since the
// client binds to a random ephemeral port).
//
// IMPORTANT: The QUIC stack will see packets arriving from the relay's address,
// which is different from the peer's real address — this causes path-migration
// probes in some implementations. For our benchmarks the important thing is
// that the congestion controller experiences the configured loss and delay.
//
// Simplified architecture (lossless baseline uses direct connection, no relay):
//
//   [Client UDP :X] ──sent──▶ [relay-c-ingress :R1] ──drop?/delay──▶ [Server UDP :S]
//                                                                              │
//   [Client UDP :X] ◀──recv── [relay-s-ingress :R2] ◀──drop?/delay── [Server UDP :S]
//
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the in-process lossy relay.
#[derive(Clone, Copy)]
struct LossProfile {
    /// Bernoulli drop probability in millipercent (0 = lossless, 1000 = 1%).
    drop_millipct: u32,
    /// Additional one-way delay added to each forwarded datagram.
    one_way_delay: Duration,
}

impl LossProfile {
    const LOSSLESS: Self = Self {
        drop_millipct: 0,
        one_way_delay: Duration::ZERO,
    };
    const LIGHT: Self = Self {
        drop_millipct: 1_000,
        one_way_delay: Duration::from_millis(10),
    };
    const MEDIUM: Self = Self {
        drop_millipct: 3_000,
        one_way_delay: Duration::from_millis(30),
    };

    /// Decide whether to drop a packet based on a sequential counter
    /// (deterministic pseudo-random: drop every 1/prob-th packet).
    fn should_drop(self, seq: u64) -> bool {
        if self.drop_millipct == 0 {
            return false;
        }
        // Drop approximately `drop_millipct / 100_000` fraction of packets.
        // Use a simple modular schedule: drop if seq % period == 0.
        let period = 100_000u64 / (self.drop_millipct as u64);
        period > 0 && (seq % period) == 0
    }
}

/// Payload bytes to transfer in each benchmark iteration.
const PAYLOAD_LEN: usize = 512 * 1024; // 512 KiB

/// Run one benchmark iteration: transfer PAYLOAD_LEN bytes through the QUIC
/// connection configured with `algo` and the given `profile`.
///
/// For the lossless profile we use direct loopback (no relay overhead).
/// For lossy profiles we set up the relay chain.
async fn run_cc_bench(algo: CongestionAlgorithm, profile: LossProfile) -> usize {
    let (client_cfg, server_cfg, transport) = config_pair(algo);
    let payload = vec![0xABu8; PAYLOAD_LEN];

    if profile.drop_millipct == 0 && profile.one_way_delay.is_zero() {
        // ── Lossless: direct connection ──────────────────────────────────────
        let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
            .await
            .expect("bind server cc-compare lossless");
        let server_addr = server.local_addr().expect("server addr lossless");

        let server_task = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("server accept cc lossless");
            let deadline = Instant::now() + Duration::from_secs(120);
            let (stream_id, first_chunk, fin) = conn
                .accept_uni_or_bidi_data_with_deadline(deadline)
                .await
                .expect("server accept data lossless");
            let mut received = first_chunk;
            let mut done = fin;
            while received.len() < PAYLOAD_LEN && !done {
                let (chunk, f) = conn
                    .read_with_deadline(stream_id, deadline)
                    .await
                    .expect("server read lossless");
                received.extend_from_slice(&chunk);
                done = f;
            }
            conn.send(stream_id, &received, false)
                .await
                .expect("server echo lossless");
            let drain_end = Instant::now() + Duration::from_secs(60);
            while Instant::now() < drain_end
                && (conn.has_pending_stream_data() || conn.bytes_in_flight() > 0)
            {
                conn.drive().await.expect("server drive lossless");
            }
        });

        let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
            .await
            .expect("bind client cc lossless");
        let mut conn = client
            .connect(server_addr, "localhost")
            .await
            .expect("client connect cc lossless");

        let stream = conn.open_bidi().expect("open bidi cc lossless");
        conn.send(stream, &payload, false)
            .await
            .expect("send payload lossless");

        let deadline = Instant::now() + Duration::from_secs(120);
        let mut echoed = Vec::with_capacity(PAYLOAD_LEN);
        while echoed.len() < PAYLOAD_LEN {
            let (chunk, fin) = conn
                .read_with_deadline(stream, deadline)
                .await
                .expect("client read echo lossless");
            echoed.extend_from_slice(&chunk);
            if fin {
                break;
            }
        }

        server_task.await.expect("server task lossless");
        echoed.len()
    } else {
        // ── Lossy: relay interception ────────────────────────────────────────
        //
        // Architecture:
        //   Client ──UDP──▶ relay_c2s_in ──drop/delay──▶ server
        //   Server ──UDP──▶ relay_s2c_in ──drop/delay──▶ client  [via relay_fwd]
        //
        // The client-to-server path:
        //   - Client binds to a real socket and connects to relay_c2s_in.addr.
        //   - relay_c2s_in receives from client, maybe drops, forwards to server.
        //
        // The server-to-client path:
        //   - Server sends responses back to relay_c2s_in.addr (the peer it saw).
        //   - But relay_c2s_in is a receive-only socket we used to intercept C→S.
        //   - So we need a bidirectional relay socket pair that makes the server
        //     think it's talking directly to the client.
        //
        // Simplest correct approach for benchmark purposes:
        // Use a stateless bidirectional relay with two sockets for each direction:
        //   - relay_a: forwards C→S and remembers client's real port.
        //   - relay_b: forwards S→C back to client.
        //   - Server sees relay_a as its "client"; relay_a returns server replies to client.
        //
        // Since QUIC connections depend on consistent DCID routing, we use a
        // simpler architecture where relay_a handles the full bidirectionality:
        //   relay_a receives from client and forwards to server (c2s direction).
        //   relay_a also receives from server and forwards back to client (s2c direction).
        //   Both with independent drop schedules.

        use tokio::net::UdpSocket;

        // Bind server
        let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
            .await
            .expect("bind server cc lossy");
        let server_addr = server.local_addr().expect("server addr lossy");

        // Bind a relay socket that the client will connect to.
        // relay_a: receives from client on c2s side; receives from server on s2c side.
        let relay_socket = Arc::new(
            UdpSocket::bind(loopback())
                .await
                .expect("bind relay socket"),
        );
        let relay_addr = relay_socket.local_addr().expect("relay local addr");

        // Forward socket: used by relay tasks to send packets to server/client.
        let fwd_socket = Arc::new(UdpSocket::bind(loopback()).await.expect("bind fwd socket"));

        let stop = Arc::new(tokio::sync::Notify::new());

        // Relay task: reads from relay_socket; if packet came from client→forward to server;
        // if packet came from server→forward to client's real source addr.
        // We track the client's real source addr from the first packet.
        let relay_sock2 = Arc::clone(&relay_socket);
        let fwd_sock2 = Arc::clone(&fwd_socket);
        let profile2 = profile;
        let relay_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut client_real_addr: Option<SocketAddr> = None;
            let mut c2s_seq: u64 = 0;
            let mut s2c_seq: u64 = 0;

            loop {
                let result =
                    tokio::time::timeout(Duration::from_secs(120), relay_sock2.recv_from(&mut buf))
                        .await;
                let (n, src) = match result {
                    Ok(Ok(r)) => r,
                    _ => break,
                };
                let pkt = buf[..n].to_vec();

                if src == server_addr {
                    // Server→Client direction
                    if let Some(cli_addr) = client_real_addr {
                        if !profile2.should_drop(s2c_seq) {
                            let delay = profile2.one_way_delay;
                            let s = Arc::clone(&relay_sock2);
                            tokio::spawn(async move {
                                if !delay.is_zero() {
                                    tokio::time::sleep(delay).await;
                                }
                                let _ = s.send_to(&pkt, cli_addr).await;
                            });
                        }
                        s2c_seq += 1;
                    }
                } else {
                    // Client→Server direction (first packet reveals client's real addr)
                    client_real_addr = Some(src);
                    if !profile2.should_drop(c2s_seq) {
                        let delay = profile2.one_way_delay;
                        let s = Arc::clone(&fwd_sock2);
                        tokio::spawn(async move {
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            let _ = s.send_to(&pkt, server_addr).await;
                        });
                    }
                    c2s_seq += 1;
                }
            }
        });

        // Fwd task: reads server replies from fwd_socket; forwards to relay_socket addr
        // (so relay can route them back to the client).
        let fwd_sock3 = Arc::clone(&fwd_socket);
        let relay_addr2 = relay_addr;
        let fwd_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let result =
                    tokio::time::timeout(Duration::from_secs(120), fwd_sock3.recv_from(&mut buf))
                        .await;
                let (n, _src) = match result {
                    Ok(Ok(r)) => r,
                    _ => break,
                };
                let pkt = buf[..n].to_vec();
                let _ = fwd_sock3.send_to(&pkt, relay_addr2).await;
            }
        });

        // Server task
        let server_task = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("server accept cc lossy");
            let deadline = Instant::now() + Duration::from_secs(120);
            let (stream_id, first_chunk, fin) = conn
                .accept_uni_or_bidi_data_with_deadline(deadline)
                .await
                .expect("server accept data lossy");
            let mut received = first_chunk;
            let mut done = fin;
            while received.len() < PAYLOAD_LEN && !done {
                let (chunk, f) = conn
                    .read_with_deadline(stream_id, deadline)
                    .await
                    .expect("server read lossy");
                received.extend_from_slice(&chunk);
                done = f;
            }
            conn.send(stream_id, &received, false)
                .await
                .expect("server echo lossy");
            let drain_end = Instant::now() + Duration::from_secs(120);
            while Instant::now() < drain_end
                && (conn.has_pending_stream_data() || conn.bytes_in_flight() > 0)
            {
                conn.drive().await.expect("server drive lossy");
            }
        });

        // Client: connect to relay_addr
        let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
            .await
            .expect("bind client cc lossy");
        let mut conn = client
            .connect(relay_addr, "localhost")
            .await
            .expect("client connect cc lossy");

        let stream = conn.open_bidi().expect("open bidi cc lossy");
        conn.send(stream, &payload, false)
            .await
            .expect("send payload lossy");

        let deadline = Instant::now() + Duration::from_secs(120);
        let mut echoed = Vec::with_capacity(PAYLOAD_LEN);
        while echoed.len() < PAYLOAD_LEN {
            let (chunk, fin) = conn
                .read_with_deadline(stream, deadline)
                .await
                .expect("client read echo lossy");
            echoed.extend_from_slice(&chunk);
            if fin {
                break;
            }
        }

        server_task.await.expect("server task lossy");
        stop.notify_waiters();
        relay_task.abort();
        fwd_task.abort();

        echoed.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CWND growth comparison (unit-level, no network)
// ─────────────────────────────────────────────────────────────────────────────

/// Measure how quickly each algorithm grows its congestion window during slow
/// start (N sequential ack events, each ACKing 1200 bytes).
fn cwnd_after_n_acks(algo: CongestionAlgorithm, n_acks: usize) -> u64 {
    use oxiquic_transport::CongestionController;
    let mut cc = CongestionController::from_config(algo);
    let now = Instant::now();
    for i in 0..n_acks {
        let t = now + Duration::from_micros(i as u64 * 100);
        cc.on_packet_sent(1200, t);
        cc.on_packets_acked(&[(1200, t, None)], t + Duration::from_millis(1));
    }
    cc.congestion_window()
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// Benchmark: 512 KiB throughput per algorithm per loss profile.
///
/// This is the primary congestion-control comparison bench.  The criterion
/// HTML report groups results by profile, with each algorithm side by side.
fn bench_cc_compare(c: &mut Criterion) {
    let profiles: &[(LossProfile, &str)] = &[
        (LossProfile::LOSSLESS, "lossless"),
        // Note: lossy profiles add real delay and are slow; kept at low
        // sample counts.
        (LossProfile::LIGHT, "light_loss_1pct_10ms"),
        (LossProfile::MEDIUM, "medium_loss_3pct_30ms"),
    ];
    let algos: &[(CongestionAlgorithm, &str)] = &[
        (CongestionAlgorithm::Cubic, "cubic"),
        (CongestionAlgorithm::Bbr, "bbr"),
        (CongestionAlgorithm::NewReno, "newreno"),
    ];

    let mut group = c.benchmark_group("cc_compare");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));
    group.sample_size(10);
    // Lossy profiles can be slow (up to ~2s/iter due to added delay);
    // allow enough measurement time.
    group.measurement_time(Duration::from_secs(120));

    let rt = make_runtime();

    for &(profile, prof_name) in profiles {
        for &(algo, algo_name) in algos {
            let id = BenchmarkId::new(prof_name.to_string(), algo_name);
            group.bench_with_input(id, &(profile, algo), |b, &(prof, alg)| {
                b.iter(|| rt.block_on(async { black_box(run_cc_bench(alg, prof).await) }));
            });
        }
    }

    group.finish();
}

/// Benchmark: CWND growth rate for each algorithm (unit-level, no I/O).
///
/// Measures how fast each algorithm grows the congestion window in slow start
/// given N sequential ACK events.  The result is the cwnd value in bytes after
/// N acks at N = 10, 100, 1000.
fn bench_cc_cwnd_growth(c: &mut Criterion) {
    let mut group = c.benchmark_group("cc_cwnd_growth");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));

    let algos: &[(CongestionAlgorithm, &str)] = &[
        (CongestionAlgorithm::Cubic, "cubic"),
        (CongestionAlgorithm::Bbr, "bbr"),
        (CongestionAlgorithm::NewReno, "newreno"),
    ];

    for &n_acks in &[10usize, 100usize, 1000usize] {
        // Print cwnd values once for observability.
        if n_acks == 100 {
            for &(algo, name) in algos {
                let cwnd = cwnd_after_n_acks(algo, n_acks);
                println!("[cwnd_after_{n_acks}_acks] {name}: {cwnd} bytes");
            }
        }

        for &(algo, name) in algos {
            group.bench_with_input(
                BenchmarkId::new(format!("cwnd_after_{n_acks}_acks"), name),
                &(n_acks, algo),
                |b, &(n, alg)| {
                    b.iter(|| black_box(cwnd_after_n_acks(alg, n)));
                },
            );
        }
    }

    group.finish();
}

criterion_group!(cc_benches, bench_cc_compare, bench_cc_cwnd_growth,);
criterion_main!(cc_benches);
