//! Focused latency benchmark for `TransportParams::validate()`.
//!
//! `TransportParams::validate()` is called on every incoming QUIC handshake to
//! ensure peer-supplied parameters satisfy RFC 9000 Section 7.4 constraints.
//! This benchmark quantifies the per-call cost so regressions are caught early.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use oxiquic_core::TransportParams;

/// Benchmark `TransportParams::validate()` on the default (always-valid) params.
///
/// This is the common fast path: all fields are within RFC-prescribed bounds.
fn bench_validate_default(c: &mut Criterion) {
    let params = TransportParams::default();
    c.bench_function("TransportParams::validate default", |b| {
        b.iter(|| {
            let _ = black_box(&params).validate();
        })
    });
}

/// Benchmark construction of `TransportParams::default()`.
///
/// The struct is stack-allocated; this measures the cost of zeroing/setting
/// all RFC 9000 Section 18.2 fields to their initial values.
fn bench_default_construction(c: &mut Criterion) {
    c.bench_function("TransportParams::default", |b| {
        b.iter(|| black_box(TransportParams::default()))
    });
}

/// Benchmark `validate()` in a tight loop to measure amortised throughput.
///
/// Simulates a server validating parameters for 64 incoming connections in
/// rapid succession (e.g. during a handshake burst).
fn bench_validate_burst(c: &mut Criterion) {
    const BURST: usize = 64;
    let params = TransportParams::default();
    c.bench_function("TransportParams::validate burst×64", |b| {
        b.iter(|| {
            let mut ok = 0u32;
            for _ in 0..BURST {
                if black_box(&params).validate().is_ok() {
                    ok += 1;
                }
            }
            black_box(ok)
        })
    });
}

criterion_group!(
    params_benches,
    bench_validate_default,
    bench_default_construction,
    bench_validate_burst,
);
criterion_main!(params_benches);
