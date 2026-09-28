//! How long does a snapshot (`DurableTemporalEngine::checkpoint`) take, and how
//! does it scale with **N = events accumulated since the last checkpoint** — the
//! `snapshot_interval` knob an operator actually tunes (checkpoint latency vs.
//! replay depth on restart)?
//!
//! # What a checkpoint spends time on
//!
//! Three phases with independent drivers:
//!   - **capture** — serialize every monitor's in-window state (no fsync);
//!   - **commit** — one fsync of the snapshot payload;
//!   - **prune** — reclaim the log below the watermark, one redb write
//!     transaction (an fsync) per `PRUNE_CHUNK` (= 1000) records.
//!
//! So prune does `⌈records / 1000⌉` fsyncs; capture cost tracks how much *state*
//! the monitors hold. N drives both — more events means both a longer log to
//! prune and (if they fall in-window) more state to serialize.
//!
//! # Isolating capture from prune (the experimental design)
//!
//! N conflates the two. We separate them with the engine's injectable clock
//! (the store assigns timestamps, so a test controls the event
//! clock without touching the events):
//!
//!   - **`in_window`** — step the clock by 1 ms per event, so all N events fall
//!     inside the rules' `within 1h` window and the monitors retain them. Both
//!     capture *and* prune grow with N.
//!   - **`aged_out`** — step the clock by 2 h per event, so each event is more than
//!     a window past the previous one; the monitors front-prune to ~nothing while
//!     the *log* still holds all N records. Capture stays tiny — this is almost
//!     pure prune.
//!
//! The `aged_out` curve is the prune floor; the gap up to `in_window` is the cost
//! of serializing the accumulated state. Both are measured against
//! [`fsync_floor`], printed once at the start, so a reader can see how much of
//! either is just fsyncs.
//!
//! Checkpoint is **destructive** (it prunes and resets the counter), so each
//! measured iteration gets a freshly-built engine via `iter_batched`; only the
//! `checkpoint()` call is timed. Building N fsync'd events per iteration is
//! expensive, so the sample size is small and N is capped at 10 000.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

use dogwood_local_engine::{Clock, DurableConfig, DurableTemporalEngine};
use dogwood_performance::driver::{fsync_floor, to_wire};
use dogwood_performance::workload::{ACTION_SCHEMA, Pinning, event_stream, policy_set};
use dogwood_server::codec::to_event_builder;

/// Fixed policy count for the N sweep: enough leaves that serializing them is not
/// free, few enough that N — not policy count — is the axis under test.
const POLICIES: usize = 10;

/// Events accumulated before the single timed checkpoint. Capped at 10 000: the
/// per-iteration setup fsyncs every one of these, so a larger N would dominate the
/// run without changing the story (prune scales linearly beyond here).
const N_SWEEP: &[usize] = &[0, 100, 1_000, 10_000];

/// A starting instant, in epoch nanoseconds, well clear of zero so the clamp
/// never has to reach for `last + 1`.
const BASE_NS: i64 = 1_800_000_000_000_000_000;

/// `in_window`: 1 ms between events — 10 000 events span 10 s, far inside `1h`,
/// so every one is retained by the monitors.
const IN_WINDOW_STEP_NS: i64 = 1_000_000;

/// `aged_out`: 2 h between events — each event is a full window past the last, so
/// the monitors keep ~nothing and the checkpoint is almost pure prune.
const AGED_OUT_STEP_NS: i64 = 2 * 3_600 * 1_000_000_000;

/// A clock a benchmark drives by hand: cloned into the engine while the setup keeps
/// a handle to advance it between submits.
#[derive(Clone)]
struct BenchClock(Arc<AtomicI64>);

impl BenchClock {
    fn new(start_nanos: i64) -> Self {
        BenchClock(Arc::new(AtomicI64::new(start_nanos)))
    }
    fn set(&self, nanos: i64) {
        self.0.store(nanos, Ordering::SeqCst);
    }
}

impl Clock for BenchClock {
    fn now_nanos(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A ready-to-checkpoint engine plus its store directory, cleaned up on drop so a
/// long sweep does not leave a temp file per iteration behind.
struct Fixture {
    engine: DurableTemporalEngine,
    dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Build an engine with `POLICIES` rules installed and `n` events submitted, each
/// stamped `step_ns` after the previous via the injected clock. The returned engine
/// has an un-checkpointed log of `n` events (plus the install record).
fn ready(n: usize, step_ns: i64) -> Fixture {
    // A unique directory per call: `iter_batched` invokes this once per timed
    // iteration, and reusing a path would race the previous fixture's still-open
    // redb file.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let id = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("dogwood_snap_{}_{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create bench dir");

    let clock = BenchClock::new(BASE_NS);
    // snapshot_interval 0: no automatic checkpoint fires mid-setup — the only
    // checkpoint is the one the benchmark times.
    let mut engine = DurableTemporalEngine::open_with_config(
        dir.join("store.redb"),
        DurableConfig::new(0).with_clock(Box::new(clock.clone())),
    )
    .expect("engine opens");
    engine
        .install(
            &policy_set(POLICIES),
            ACTION_SCHEMA,
            // Unpinned (global) — the N sweep is about event count, not shards.
            Some(Pinning::Unpinned.event_schema()),
            None,
        )
        .expect("policy installs");

    // A realistic mixed stream (the same shape the decide benchmarks use); the
    // server assigns timestamps from the clock, so `GenEvent.ts` is ignored and the
    // spacing below is what determines window occupancy.
    let events = event_stream(n, 1, 49, 5);
    for (i, e) in events.iter().enumerate() {
        clock.set(BASE_NS + (i as i64 + 1) * step_ns);
        engine
            .submit(to_event_builder(&to_wire(e)))
            .expect("event submits");
    }

    Fixture { engine, dir }
}

fn bench(c: &mut Criterion) {
    // The fsync cost of the underlying store, so a reader can tell how much of a
    // checkpoint is fsyncs (one for the commit, one per pruned 1000-record chunk)
    // versus real serialize work.
    eprintln!(
        "snapshot_latency: single-fsync floor for this store ≈ {:?}",
        fsync_floor(64)
    );

    let mut group = c.benchmark_group("checkpoint");
    // The setup builds (and fsyncs) N events per iteration, so keep the sample
    // count at criterion's floor and the warm-up short — the routine itself
    // (`checkpoint`) is cheap next to its setup.
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(500));

    for &n in N_SWEEP {
        // All N events in-window: capture serializes them, then prune reclaims them.
        group.bench_with_input(BenchmarkId::new("in_window", n), &n, |b, &n| {
            b.iter_batched(
                || ready(n, IN_WINDOW_STEP_NS),
                |mut f| {
                    f.engine.checkpoint().expect("checkpoint");
                    f // returned so its Drop (dir cleanup) runs outside the timing
                },
                BatchSize::PerIteration,
            );
        });

        // Events aged past the window: monitors hold ~nothing, so this is the prune
        // floor — dominated by ⌈n / 1000⌉ fsyncs.
        group.bench_with_input(BenchmarkId::new("aged_out", n), &n, |b, &n| {
            b.iter_batched(
                || ready(n, AGED_OUT_STEP_NS),
                |mut f| {
                    f.engine.checkpoint().expect("checkpoint");
                    f
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
