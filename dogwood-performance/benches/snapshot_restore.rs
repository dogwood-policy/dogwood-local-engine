//! Snapshot decode/restore latency, isolated from snapshot construction.
//!
//! `snapshot_latency` measures checkpoint capture, commit, and pruning. This
//! benchmark measures the other half of the lifecycle: loading already-encoded
//! monitor state into a freshly prepared [`LocalTemporalEngine`]. That is the
//! path whose collection allocation strategy matters during recovery.
//!
//! The source engine grows once per mode and snapshots are captured at powers of
//! two through 65,536 retained records. Event timestamps advance in 1,024-record
//! bursts, keeping the complete trace inside the policies' one-hour windows.
//! Both global and 16-session partitioned modes are measured because their
//! snapshot envelopes and collection nesting differ.
//!
//! Criterion keeps named baselines, so a decoder change can be compared with:
//!
//! ```text
//! cargo bench -p dogwood-performance --bench snapshot_restore -- \
//!     --save-baseline before
//! # apply the decoder change
//! cargo bench -p dogwood-performance --bench snapshot_restore -- \
//!     --baseline before
//! ```

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dogwood_language::{LoweredPolicySet, TemporalEngine};
use dogwood_local_engine::LocalTemporalEngine;
use dogwood_performance::driver::to_wire;
use dogwood_performance::workload::{Pinning, PredicateShape, event_stream, lower_shaped};
use dogwood_server::codec::to_event_builder;

const POLICIES: usize = 6;
const PARTITIONED_SESSIONS: usize = 16;
const SERVERS: usize = 49;
const LOGIN_EVERY: usize = 5;
const FROZEN_BURST: usize = 1024;
const RECORD_COUNTS: &[usize] = &[0, 64, 1024, 4096, 16_384, 65_536];

fn prepared(lowered: &LoweredPolicySet) -> LocalTemporalEngine {
    let leaves = lowered
        .nonrelativized_temporal_fields()
        .cloned()
        .collect::<Vec<_>>();
    let signatures = lowered.event_signatures().collect::<Vec<_>>();
    let mut engine = LocalTemporalEngine::new();
    engine.set_partition_keys(lowered.partition_keys());
    engine
        .prepare(&leaves, lowered.cedar_schema(), &signatures)
        .expect("benchmark engine prepares");
    engine
}

fn snapshots(lowered: &LoweredPolicySet, sessions: usize) -> Vec<(usize, Vec<u8>)> {
    let max_records = *RECORD_COUNTS.last().expect("non-empty record-count sweep");
    let events = event_stream(max_records, sessions, SERVERS, LOGIN_EVERY);
    let mut engine = prepared(lowered);
    let mut observed = 0usize;
    let mut snapshots = Vec::with_capacity(RECORD_COUNTS.len());

    for &target in RECORD_COUNTS {
        while observed < target {
            let event = to_event_builder(&to_wire(&events[observed]))
                .timestamp((observed / FROZEN_BURST) as i64)
                .build();
            engine.observe(&event);
            observed += 1;
        }
        let encoded = engine.save_snapshot();
        eprintln!(
            "snapshot_restore: {target} records, {sessions} session(s) -> {} bytes",
            encoded.len()
        );
        snapshots.push((target, encoded));
    }
    snapshots
}

fn bench_mode(c: &mut Criterion, pinning: Pinning, sessions: usize) {
    let lowered = lower_shaped(POLICIES, pinning, PredicateShape::Selective);
    let snapshots = snapshots(&lowered, sessions);
    let mut group = c.benchmark_group(format!("snapshot_restore/{}", pinning.label()));
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    for (records, encoded) in &snapshots {
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("records", records),
            encoded,
            |b, encoded| {
                b.iter_batched(
                    || prepared(&lowered),
                    |mut engine| {
                        assert!(
                            engine.load_snapshot(std::hint::black_box(encoded)),
                            "valid benchmark snapshot must restore"
                        );
                        std::hint::black_box(engine)
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench(c: &mut Criterion) {
    bench_mode(c, Pinning::Unpinned, 1);
    bench_mode(c, Pinning::PinnedSession, PARTITIONED_SESSIONS);
}

criterion_group!(benches, bench);
criterion_main!(benches);
