//! Policy-set **installation** cost: parse → macro-expand → lower → validate →
//! prepare monitors, across policy count and pinning.
//!
//! # Why this is a separate benchmark
//!
//! A decision benchmark never sees this work, and it is where policy *count*
//! actually dominates. Installation is also the one path an operator waits on
//! synchronously: `dogwood-server policy apply` validates and swaps in one call,
//! so this is the latency of a policy change — a real operational number, distinct
//! from steady-state decision cost.
//!
//! Two things are measured separately because they scale differently and a single
//! number would conflate them:
//!
//! - **`lower`** — the frontend pipeline, shared by every engine.
//! - **`install`** — what the server additionally does: validation (Cedar's
//!   validator over every lowered policy) plus building and preparing the
//!   incremental monitors. This is the number that bounds how fast a policy set can
//!   be swapped.
//!
//! # The history-depth axis
//!
//! Everything above installs into an **empty** store, which never exercises the
//! parts of an apply whose cost tracks accumulated history rather than policy
//! count: transplanting each retained leaf's window into the replacement engine,
//! and releasing the previous set's state.
//!
//! Those parts mattered. Before the engine shared leaf state by refcount instead of
//! serializing it, and before it stopped retaining every observed event, a re-apply
//! against 20 000 events cost ~397 ms and then ~33.9 ms, against ~4 ms empty — a
//! slope of 1.50 ms per 1000 retained events that no benchmark here would have
//! shown, because none of them re-applied over a history. `reapply` closes that:
//! two depths at one policy count, so the *difference* is the measurement.
//!
//! One policy count rather than the whole sweep, deliberately. The cost being
//! measured belongs to the engine's transplant-and-release path, which is
//! per-*leaf* and per-*event*, not per-policy — and preloading history is O(depth ×
//! evaluation cost), so at 10 000 policies the setup alone would run for minutes per
//! sample while measuring the same thing.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use criterion::BatchSize;
use dogwood_performance::driver::ServerHarness;
use dogwood_performance::workload::{POLICY_COUNTS, Pinning, event_stream, lower, policy_set};

/// The policy count the depth axis is measured at. Representative rather than
/// extreme: §A.5 found 100 policies the size that sustains a realistic rate.
const DEPTH_POLICIES: usize = 100;

/// Empty, and deep enough for a linear slope to be visible against a ~4 ms floor.
/// At the 1.50 ms/1000 slope this path once had, 1000 events was ~1.5 ms — small,
/// which is the point: the check is that it stays small.
const DEPTHS: [usize; 2] = [0, 1000];

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("install");
    // Installation at 1000 policies takes appreciable wall time, so keep the
    // sample count low; the operation is deterministic and low-variance, so a
    // small sample is adequate here in a way it would not be for a latency tail.
    group.sample_size(10);

    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        for count in POLICY_COUNTS {
            let id = format!("{}/{}p", pinning.label(), count);

            // Generating the source text is part of neither engine; measure it once
            // so the reader can see it is negligible relative to lowering.
            group.bench_with_input(BenchmarkId::new("generate_source", &id), &count, |b, &n| {
                b.iter(|| std::hint::black_box(policy_set(n)));
            });

            // The shared frontend pipeline.
            group.bench_with_input(
                BenchmarkId::new("lower", &id),
                &(count, pinning),
                |b, &(n, p)| {
                    b.iter(|| std::hint::black_box(lower(n, p)));
                },
            );

            // Lower + validate + prepare monitors + durably persist the bundle —
            // i.e. what `policy apply` actually costs.
            group.bench_with_input(
                BenchmarkId::new("server_apply", &id),
                &(count, pinning),
                |b, &(n, p)| {
                    b.iter(|| {
                        std::hint::black_box(ServerHarness::new("install", n, p));
                    });
                },
            );
        }
    }
    group.finish();
}

/// Re-apply a policy set over an accumulated history: the axis `bench` above holds
/// at zero.
fn bench_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("install_over_history");
    // Each sample rebuilds a server and preloads `depth` events through the real
    // `submit` path, so a sample is expensive; the operation itself is
    // deterministic and low-variance.
    group.sample_size(10);

    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        for depth in DEPTHS {
            let id = format!("{}/{}p/{}ev", pinning.label(), DEPTH_POLICIES, depth);
            group.bench_function(BenchmarkId::new("reapply", &id), |b| {
                b.iter_batched(
                    // Setup is NOT measured: build the server and accumulate the
                    // history, so the timed routine is one re-apply and nothing else.
                    || {
                        let mut h = ServerHarness::new("install_depth", DEPTH_POLICIES, pinning);
                        if depth > 0 {
                            h.run(&event_stream(depth, 8, 4, 16));
                        }
                        h
                    },
                    |mut h| {
                        let retained = h.reapply();
                        // Guard against measuring the wrong thing: re-lowering the
                        // identical set (the keep-window path) must retain every
                        // leaf, so the transplant is what gets timed. If a future
                        // change to `leaf_key` made these count as different
                        // formulas, the transplant would carry nothing and this
                        // would quietly measure far less work.
                        assert!(
                            retained > 0,
                            "re-lowering an identical policy set must retain its leaves"
                        );
                        std::hint::black_box(retained);
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench, bench_depth);
criterion_main!(benches);
