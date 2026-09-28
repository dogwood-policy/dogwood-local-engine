//! Durable-record JSON codec latency and throughput.
//!
//! This benchmark is intended to compare two complete implementations:
//!
//! - the original: `json!` encoding and `RecordWire`/`serde_json::from_value`
//!   decoding.
//! - the current implementation: explicit JSON-map encoding and
//!   direct strict decoding.
//!
//! Apply this same benchmark source to both revisions. Save the original as a
//! Criterion baseline, then compare the current implementation against it:
//!
//! ```text
//! cargo bench -p dogwood-performance --bench record_codec -- \
//!     --save-baseline original
//! cargo bench -p dogwood-performance --bench record_codec -- \
//!     --baseline original
//! ```
//!
//! Inputs are constructed and encoded outside the timed loops. Decode therefore
//! measures parsing plus record reconstruction, while encode measures JSON value
//! construction plus serialization. Allocation counting lives in the separate
//! `record_codec_allocations` benchmark so its allocator instrumentation cannot
//! perturb these timings.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dogwood_local_engine::Record;

#[path = "support/record_codec_cases.rs"]
mod record_codec_cases;

use record_codec_cases::cases;

fn bench(c: &mut Criterion) {
    let cases = cases();

    let mut encode = c.benchmark_group("record_codec/encode");
    encode.sample_size(20);
    encode.warm_up_time(Duration::from_millis(500));
    encode.measurement_time(Duration::from_secs(1));
    for case in &cases {
        encode.throughput(Throughput::Bytes(case.encoded.len() as u64));
        encode.bench_with_input(
            BenchmarkId::from_parameter(&case.name),
            &case.record,
            |b, record| {
                b.iter(|| black_box(record.encode()));
            },
        );
    }
    encode.finish();

    let mut decode = c.benchmark_group("record_codec/decode");
    decode.sample_size(20);
    decode.warm_up_time(Duration::from_millis(500));
    decode.measurement_time(Duration::from_secs(1));
    for case in &cases {
        decode.throughput(Throughput::Bytes(case.encoded.len() as u64));
        decode.bench_with_input(
            BenchmarkId::from_parameter(&case.name),
            &case.encoded,
            |b, encoded| {
                b.iter(|| {
                    black_box(Record::decode(black_box(encoded)).expect("benchmark record decodes"))
                });
            },
        );
    }
    decode.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
