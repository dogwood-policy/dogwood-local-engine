//! Per-decision latency of an **aggregate over `formerly`**, driven through the
//! local engine directly — no `fsync`, no reference. This isolates the engine's
//! aggregate fold, which the durable `decide_latency` bench buries under the
//! storage floor and the reference-vs-server framing.
//!
//! # Why this shape, this way
//!
//! The workload's [`PredicateShape::Broad`] rule is
//! `count for (t) . where (formerly within 1h Login{ user:_, server:_ } && tp(t))
//! == c && c > 100000` — a count over the whole retained window, with a threshold
//! no stream reaches, so every decision evaluates the *full* fold rather than
//! short-circuiting. That fold is where the aggregate's cost lives.
//!
//! The measured axis is **history length**: the count folds every in-window
//! match, and the number of in-window matches grows with how many events have
//! been observed, so a quadratic term in the fold shows as history grows.
//! Sweeping history length — rather than policy count or sessions — is what
//! exposes it.
//!
//! Driven through `Authorizer::builder().temporal_engine(LocalTemporalEngine)`,
//! the same wiring the correctness tests use, so this measures exactly the code
//! path a decision takes — with no durable write in it.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use dogwood_language::Authorizer;
use dogwood_local_engine::LocalTemporalEngine;
use dogwood_performance::driver::to_event;
use dogwood_performance::workload::{Pinning, PredicateShape, event_stream, lower_shaped};

/// Warm-up history lengths to sweep (events observed before the timed decision).
/// The window is `1h`; at `LOGIN_EVERY = 5` these lengths keep tens-to-hundreds
/// of logins in the window, the regime where the fold's per-decision cost
/// dominates. Growth across these points is the signal: linear work grows ~2×
/// per doubling, a quadratic term grows ~4×.
const HISTORY_LENGTHS: [usize; 3] = [200, 400, 800];

/// Rules per set. A handful of aggregate rules, matching the "100 policies +
/// aggregate" regime that motivates this bench without letting policy count
/// dominate the history-length signal.
const POLICIES: usize = 100;

const SESSIONS: usize = 8;
const SERVERS: usize = 49;
const LOGIN_EVERY: usize = 5;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate_decide");

    for history_len in HISTORY_LENGTHS {
        let events = event_stream(history_len, SESSIONS, SERVERS, LOGIN_EVERY);
        // The measured event: the first decision after the warm-up history (index
        // `history_len` is a multiple of `LOGIN_EVERY`, hence a history-only
        // `Login`).
        let probe = event_stream(history_len + LOGIN_EVERY, SESSIONS, SERVERS, LOGIN_EVERY)
            .into_iter()
            .skip(history_len)
            .find(|e| e.decides)
            .expect("a decision after the history");

        // Longer histories build slower per sample; keep the run bounded.
        group.sample_size(if history_len >= 800 { 10 } else { 20 });

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("broad/{history_len}")),
            &history_len,
            |b, _| {
                b.iter_batched_ref(
                    || {
                        let mut a = Authorizer::builder(lower_shaped(
                            POLICIES,
                            Pinning::Unpinned,
                            PredicateShape::Broad,
                        ))
                        .temporal_engine(LocalTemporalEngine::new())
                        .build()
                        .expect("local-engine authorizer builds");
                        for e in &events {
                            let _ = a.is_authorized(&to_event(e));
                        }
                        a
                    },
                    |authorizer| {
                        let event = to_event(&probe);
                        std::hint::black_box(authorizer.is_authorized(&event));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
