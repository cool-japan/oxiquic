//! Focused throughput benchmark for `FrameType::from_varint`.
//!
//! Measures the decode throughput of the frame-type lookup across the full
//! set of valid type values.  The match expression should compile to a
//! near-branchless lookup; the target is >100 M ops/sec on modern hardware.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use oxiquic_core::FrameType;

/// All valid frame-type varint values (per RFC 9000 Section 12.4 / RFC 9221).
///
/// The array covers the complete canonical + range members so that the bench
/// exercises every arm of `from_varint`'s match.
const ALL_VALID: &[u64] = &[
    // PADDING, PING
    0x00, 0x01, // ACK (two variants)
    0x02, 0x03, // RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN
    0x04, 0x05, 0x06, 0x07, // STREAM (full range 0x08–0x0f)
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    // MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS (bidi, uni)
    0x10, 0x11, 0x12, 0x13,
    // DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED (bidi, uni)
    0x14, 0x15, 0x16, 0x17, // NEW_CONNECTION_ID, RETIRE_CONNECTION_ID
    0x18, 0x19, // PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE (transport, app)
    0x1a, 0x1b, 0x1c, 0x1d, // HANDSHAKE_DONE
    0x1e, // DATAGRAM (no-length, with-length)
    0x30, 0x31,
];

/// Benchmark decoding the entire set of valid frame type values in a tight loop.
fn bench_from_varint_all(c: &mut Criterion) {
    c.bench_function("FrameType::from_varint all valid", |b| {
        b.iter(|| {
            let mut ok_count = 0u64;
            for &v in ALL_VALID {
                if FrameType::from_varint(black_box(v)).is_ok() {
                    ok_count += 1;
                }
            }
            black_box(ok_count)
        })
    });
}

/// Benchmark decoding a single hot-path value (STREAM mid-range).
///
/// This isolates the cost of a single call, making it easier to measure
/// per-call latency in nanoseconds.
fn bench_from_varint_stream(c: &mut Criterion) {
    c.bench_function("FrameType::from_varint STREAM(0x0a)", |b| {
        b.iter(|| black_box(FrameType::from_varint(black_box(0x0au64))))
    });
}

/// Benchmark an unknown (error) frame type — exercises the fallthrough arm.
fn bench_from_varint_unknown(c: &mut Criterion) {
    c.bench_function("FrameType::from_varint unknown(0x1f)", |b| {
        b.iter(|| black_box(FrameType::from_varint(black_box(0x1fu64))))
    });
}

/// Benchmark `is_ack_eliciting` — a `matches!` expression, should be ~1 ns.
fn bench_is_ack_eliciting(c: &mut Criterion) {
    let ft = FrameType::Stream;
    c.bench_function("FrameType::is_ack_eliciting", |b| {
        b.iter(|| black_box(black_box(ft).is_ack_eliciting()))
    });
}

/// Benchmark `is_probing` — also a `matches!` expression.
fn bench_is_probing(c: &mut Criterion) {
    let ft = FrameType::PathChallenge;
    c.bench_function("FrameType::is_probing", |b| {
        b.iter(|| black_box(black_box(ft).is_probing()))
    });
}

criterion_group!(
    frame_benches,
    bench_from_varint_all,
    bench_from_varint_stream,
    bench_from_varint_unknown,
    bench_is_ack_eliciting,
    bench_is_probing,
);
criterion_main!(frame_benches);
