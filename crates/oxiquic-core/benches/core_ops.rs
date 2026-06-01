//! Criterion micro-benchmarks for `oxiquic-core` pure-data types.
//!
//! These benchmarks exercise the construction and accessor paths of the core
//! RFC 9000 types without any I/O or async overhead.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use oxiquic_core::{ConnectionId, Direction, FrameType, Initiator, StreamId, TransportParams};

// ─────────────────────────────────────────────────────────────────────────────
// StreamId
// ─────────────────────────────────────────────────────────────────────────────

fn bench_streamid_construction(c: &mut Criterion) {
    c.bench_function("streamid_construction", |b| {
        b.iter(|| {
            black_box(StreamId::new(
                black_box(Initiator::Client),
                black_box(Direction::Bidirectional),
                black_box(0u64),
            ))
        })
    });
}

fn bench_streamid_accessors(c: &mut Criterion) {
    let sid = StreamId::new(Initiator::Server, Direction::Unidirectional, 42);
    c.bench_function("streamid_accessors", |b| {
        b.iter(|| {
            let s = black_box(sid);
            let _ = black_box(s.initiator());
            let _ = black_box(s.direction());
            black_box(s.index())
        })
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectionId
// ─────────────────────────────────────────────────────────────────────────────

fn bench_connectionid_from_slice(c: &mut Criterion) {
    let bytes: &[u8] = &[1u8, 2, 3, 4, 5, 6, 7, 8];
    c.bench_function("connectionid_from_slice", |b| {
        b.iter(|| {
            // ConnectionId::from(&[u8]) uses SmallVec::from_slice — no heap alloc
            // for slices up to 20 bytes.
            black_box(ConnectionId::from(black_box(bytes)))
        })
    });
}

fn bench_connectionid_clone(c: &mut Criterion) {
    let cid = ConnectionId::from(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04][..]);
    c.bench_function("connectionid_clone", |b| {
        b.iter(|| black_box(black_box(&cid).clone()))
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// TransportParams
// ─────────────────────────────────────────────────────────────────────────────

fn bench_transport_params_default(c: &mut Criterion) {
    c.bench_function("transport_params_default", |b| {
        b.iter(|| black_box(TransportParams::default()))
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// FrameType
// ─────────────────────────────────────────────────────────────────────────────

fn bench_frametype_from_varint(c: &mut Criterion) {
    // Use a STREAM frame type value (0x0a — mid-range of 0x08..=0x0f).
    c.bench_function("frametype_from_varint", |b| {
        b.iter(|| {
            // from_varint returns Result; let criterion observe the full value.
            black_box(FrameType::from_varint(black_box(0x0au64)))
        })
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    core_benches,
    bench_streamid_construction,
    bench_streamid_accessors,
    bench_connectionid_from_slice,
    bench_connectionid_clone,
    bench_transport_params_default,
    bench_frametype_from_varint,
);

criterion_main!(core_benches);
