//! CPU utilization profiling benchmark for `oxiquic-transport`.
//!
//! This benchmark measures per-phase CPU time during a high-throughput
//! transfer, breaking down the cost into:
//!
//! - **TLS/Crypto phase** — AEAD encryption/decryption cost per packet.
//! - **Framing phase** — QUIC frame encode/decode, varint coding.
//! - **I/O scheduling phase** — tokio `UdpSocket::send`/`recv` latency
//!   (baseline without QUIC overhead).
//! - **End-to-end throughput** — bytes per second at various payload sizes.
//!
//! All measurements use `std::time::Instant` for high-resolution wall-clock
//! measurement. All benchmarks run on real UDP loopback — no mocking.
//!
//! ## Design
//!
//! The benchmark uses criterion's `iter` interface. Per-phase timing is printed
//! once at bench startup (before criterion begins its measurement loop) so it
//! appears in `cargo bench` output alongside the criterion tables.
//!
//! Benchmark groups:
//! - `cpu_profile/e2e_throughput`            — end-to-end bytes/s (1 KB, 64 KB, 1 MB)
//! - `cpu_profile/udp_echo_round_trip_ns`    — raw UDP datagram round-trip (baseline)
//! - `cpu_profile/frame_encode_decode_x1000` — frame encode+decode throughput (no I/O)
//! - `cpu_profile/aead_enc_dec_1kb_x1000`    — AEAD AES-128-GCM throughput (no I/O)

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{ClientEndpoint, ServerEndpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("tokio runtime for cpu-profile bench")
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("parse loopback")
}

fn config_pair() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate Ed25519 cert for cpu-profile bench");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust cert");

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

    (Arc::new(client_cfg), Arc::new(server_cfg))
}

/// Transfer `payload_len` bytes over QUIC and return (elapsed, bytes_echoed).
async fn timed_transfer(payload_len: usize) -> (Duration, usize) {
    let (client_cfg, server_cfg) = config_pair();
    let transport = TransportConfig::default();

    let server = ServerEndpoint::bind(loopback(), server_cfg, transport.clone())
        .await
        .expect("bind server cpu-profile");
    let server_addr = server.local_addr().expect("server local addr");

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("server accept cpu-profile");
        let deadline = Instant::now() + Duration::from_secs(120);
        let (stream_id, first_chunk, fin) = conn
            .accept_uni_or_bidi_data_with_deadline(deadline)
            .await
            .expect("server accept data");
        let mut received = first_chunk;
        let mut done = fin;
        while received.len() < payload_len && !done {
            let (chunk, f) = conn
                .read_with_deadline(stream_id, deadline)
                .await
                .expect("server read");
            received.extend_from_slice(&chunk);
            done = f;
        }
        conn.send(stream_id, &received, false)
            .await
            .expect("server echo");
        let drain_end = Instant::now() + Duration::from_secs(60);
        while Instant::now() < drain_end
            && (conn.has_pending_stream_data() || conn.bytes_in_flight() > 0)
        {
            conn.drive().await.expect("server drive");
        }
    });

    let client = ClientEndpoint::bind(loopback(), client_cfg, transport)
        .await
        .expect("bind client cpu-profile");
    let mut conn = client
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let stream = conn.open_bidi().expect("open bidi");
    let payload = vec![0xABu8; payload_len];

    let t0 = Instant::now();
    conn.send(stream, &payload, false)
        .await
        .expect("send payload");

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut echoed = Vec::with_capacity(payload_len);
    while echoed.len() < payload_len {
        let (chunk, fin) = conn
            .read_with_deadline(stream, deadline)
            .await
            .expect("client read echo");
        echoed.extend_from_slice(&chunk);
        if fin {
            break;
        }
    }

    let elapsed = t0.elapsed();
    server_task.await.expect("server task");

    (elapsed, echoed.len())
}

/// Measure single-datagram round-trip latency via raw UDP loopback (no QUIC).
/// This provides the baseline UDP cost that the QUIC stack adds on top of.
async fn udp_echo_round_trip_ns() -> u64 {
    use tokio::net::UdpSocket;

    let server_sock = UdpSocket::bind(loopback()).await.expect("udp server sock");
    let server_addr = server_sock.local_addr().expect("udp server addr");
    let client_sock = UdpSocket::bind(loopback()).await.expect("udp client sock");

    let payload = [0xFFu8; 64];

    let srv = Arc::new(server_sock);
    let srv2 = Arc::clone(&srv);
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 128];
        let (n, src) = srv2.recv_from(&mut buf).await.expect("udp server recv");
        srv2.send_to(&buf[..n], src).await.expect("udp server echo");
    });

    let t0 = Instant::now();
    client_sock
        .send_to(&payload, server_addr)
        .await
        .expect("udp client send");
    let mut buf = [0u8; 128];
    client_sock
        .recv_from(&mut buf)
        .await
        .expect("udp client recv");
    let elapsed_ns = t0.elapsed().as_nanos() as u64;

    server_task.await.expect("udp server task");
    elapsed_ns
}

// ─────────────────────────────────────────────────────────────────────────────
// Frame codec throughput (no I/O — pure CPU)
// ─────────────────────────────────────────────────────────────────────────────

/// Encode + decode STREAM frames in a tight loop. Returns the number of
/// successful encode/decode round-trips.
///
/// Uses `oxiquic_transport::frame` directly to isolate framing CPU cost
/// from I/O and TLS overhead.
fn frame_codec_round_trip_n(n: usize) -> usize {
    use oxiquic_transport::coding::Buf;
    use oxiquic_transport::frame::{decode_frame, Frame};

    // Fixed 1 KiB stream payload for realistic framing work.
    let payload = vec![0x42u8; 1024];
    let mut buf = Vec::with_capacity(1500);
    let mut decoded_count = 0usize;

    for seq in 0..n {
        let stream_id: u64 = (seq as u64) & 0x3FFF_FFFF;
        let offset: u64 = (seq as u64) * 1024;

        // Encode.
        buf.clear();
        let frame = Frame::Stream {
            id: stream_id,
            offset,
            fin: false,
            data: &payload,
        };
        frame.encode(&mut buf);

        // Decode: create a borrowed Buf over the encoded bytes.
        let encoded = buf.clone();
        let mut decode_buf = Buf::new(&encoded);
        if decode_frame(&mut decode_buf).is_ok() {
            decoded_count += 1;
        }
    }

    decoded_count
}

// ─────────────────────────────────────────────────────────────────────────────
// AEAD overhead (no I/O — pure crypto CPU)
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt + decrypt a 1 KiB payload using AES-128-GCM (the AEAD suite for
/// QUIC packet protection in the default crypto suite). Returns the number of
/// successful encrypt+decrypt pairs.
fn aead_encrypt_decrypt_n(n: usize) -> usize {
    use aes_gcm::{
        aead::{Aead, KeyInit, Nonce, Payload},
        Aes128Gcm, Key,
    };

    let key_bytes = [0x01u8; 16];
    let key = Key::<Aes128Gcm>::try_from(key_bytes.as_slice()).expect("fixed-size 16-byte key");
    let cipher = Aes128Gcm::new(&key);

    let plaintext = vec![0xABu8; 1024];
    let aad = b"quic-aead-aad";

    let mut count = 0usize;

    for seq in 0..n {
        // 12-byte nonce built from the sequence counter.
        let mut nonce_bytes = [0u8; 12];
        let seq_be = (seq as u64).to_be_bytes();
        nonce_bytes[4..].copy_from_slice(&seq_be);
        let nonce =
            Nonce::<Aes128Gcm>::try_from(nonce_bytes.as_slice()).expect("fixed-size 12-byte nonce");

        let enc_payload = Payload {
            msg: &plaintext,
            aad: aad.as_ref(),
        };
        if let Ok(ciphertext) = cipher.encrypt(&nonce, enc_payload) {
            let dec_payload = Payload {
                msg: &ciphertext,
                aad: aad.as_ref(),
            };
            if cipher.decrypt(&nonce, dec_payload).is_ok() {
                count += 1;
            }
        }
    }

    count
}

// ─────────────────────────────────────────────────────────────────────────────
// CPU phase breakdown: printed once at bench startup for observability
// ─────────────────────────────────────────────────────────────────────────────

fn print_cpu_breakdown(rt: &tokio::runtime::Runtime) {
    println!("\n[cpu_phase_breakdown]");

    // 1. UDP baseline round-trip latency.
    let udp_ns = rt.block_on(udp_echo_round_trip_ns());
    println!(
        "  UDP loopback echo latency:       {} ns  ({:.1} µs)",
        udp_ns,
        udp_ns as f64 / 1_000.0
    );

    // 2. Frame codec throughput.
    let n = 10_000;
    let t0 = Instant::now();
    let codec_count = frame_codec_round_trip_n(n);
    let codec_elapsed = t0.elapsed();
    let codec_ns_per_op = codec_elapsed.as_nanos() as f64 / codec_count.max(1) as f64;
    println!(
        "  Frame encode+decode 1 KiB:       {:.0} ns/op  ({:.1} Mops/s)",
        codec_ns_per_op,
        1_000.0 / codec_ns_per_op
    );

    // 3. AEAD AES-128-GCM overhead.
    let t0 = Instant::now();
    let aead_count = aead_encrypt_decrypt_n(n);
    let aead_elapsed = t0.elapsed();
    let aead_ns_per_op = aead_elapsed.as_nanos() as f64 / aead_count.max(1) as f64;
    println!(
        "  AEAD AES-128-GCM enc+dec 1 KiB: {:.0} ns/op  ({:.1} Mops/s)",
        aead_ns_per_op,
        1_000.0 / aead_ns_per_op
    );

    // 4. QUIC end-to-end at 64 KiB.
    let (quic_elapsed, bytes_echoed) = rt.block_on(timed_transfer(64 * 1024));
    let mbps = bytes_echoed as f64 / quic_elapsed.as_secs_f64() / 1_000_000.0;
    println!(
        "  QUIC echo 64 KiB end-to-end:     {:.2} ms  ({:.1} MB/s)",
        quic_elapsed.as_secs_f64() * 1_000.0,
        mbps
    );

    // 5. Estimated QUIC stack overhead vs raw UDP.
    let quic_ns = quic_elapsed.as_nanos() as u64;
    if quic_ns > udp_ns {
        let overhead_us = (quic_ns - udp_ns) / 1_000;
        println!(
            "  Estimated QUIC stack overhead:   {} µs  \
             (framing + crypto + scheduling on top of UDP)",
            overhead_us
        );
    }
    println!();
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// Benchmark: end-to-end QUIC echo throughput at 1 KB, 64 KB, and 1 MB.
fn bench_e2e_throughput(c: &mut Criterion) {
    let rt = make_runtime();

    // Print per-phase CPU breakdown once before criterion begins timing.
    print_cpu_breakdown(&rt);

    let mut group = c.benchmark_group("cpu_profile");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &(size_kb, label) in &[(1u64, "1kb"), (64u64, "64kb"), (1024u64, "1mb")] {
        let bytes = size_kb * 1024;
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(
            BenchmarkId::new("e2e_throughput", label),
            &bytes,
            |b, &payload_bytes| {
                b.iter(|| {
                    rt.block_on(async {
                        let (elapsed, echoed) = timed_transfer(payload_bytes as usize).await;
                        black_box((elapsed, echoed))
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: raw UDP datagram round-trip latency (no QUIC stack overhead).
fn bench_udp_baseline(c: &mut Criterion) {
    let rt = make_runtime();

    let mut group = c.benchmark_group("cpu_profile");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(20));

    group.bench_function("udp_echo_round_trip_ns", |b| {
        b.iter(|| rt.block_on(async { black_box(udp_echo_round_trip_ns().await) }));
    });

    group.finish();
}

/// Benchmark: STREAM frame encode+decode throughput (no I/O, no TLS).
fn bench_frame_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu_profile");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(10));
    // Each iteration encodes + decodes 1000 frames × 1 KiB each.
    group.throughput(Throughput::Bytes(1000 * 1024));

    group.bench_function("frame_encode_decode_1kb_x1000", |b| {
        b.iter(|| black_box(frame_codec_round_trip_n(1000)));
    });

    group.finish();
}

/// Benchmark: AEAD AES-128-GCM encrypt+decrypt throughput (no I/O, no framing).
fn bench_aead_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu_profile");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(10));
    // Each iteration encrypts + decrypts 1000 × 1 KiB payloads.
    group.throughput(Throughput::Bytes(1000 * 1024));

    group.bench_function("aead_enc_dec_1kb_x1000", |b| {
        b.iter(|| black_box(aead_encrypt_decrypt_n(1000)));
    });

    group.finish();
}

criterion_group!(
    cpu_profile_benches,
    bench_e2e_throughput,
    bench_udp_baseline,
    bench_frame_codec,
    bench_aead_overhead,
);
criterion_main!(cpu_profile_benches);
