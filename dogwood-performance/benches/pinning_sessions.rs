//! **Does pinning help?** Sweeping session count against predicate shape.
//!
//! The first version of this harness reported "pinning has no measurable effect"
//! across every policy count. That result was real but its scope was wrong: it held
//! for the *particular* policy shape being benchmarked, and reading it as a general
//! claim about pinning would have been a mistake.
//!
//! # The mechanism, and why the shape decides it
//!
//! A session pin filters other sessions' events out of a `formerly` scan. That only
//! saves work if those rows would otherwise have been examined — so the benefit
//! depends on what *else* the predicate filters:
//!
//! - **Selective** predicates (`Login{ input.user: "blocked7" }`) reject nearly
//!   every history row on the literal alone. The pin then removes rows that were
//!   already being rejected, so it costs a comparison and saves nothing.
//! - **Broad** predicates (`count … Login{ input.user: _, input.server: _ }`) scan
//!   *all* logins. Here the pin is the only thing confining the scan, and it is
//!   worth multiples.
//!
//! # What this benchmark shows
//!
//! Sweeping balanced sessions at a fixed history, the broad speedup grows with
//! session count and saturates:
//!
//! | sessions | broad: unpinned | broad: pinned | speedup |
//! |---|---|---|---|
//! | 1 | 4.57 ms | 5.22 ms | **0.88×** (pin is pure overhead) |
//! | 2 | 4.62 ms | 3.46 ms | 1.34× |
//! | 4 | 4.54 ms | 2.34 ms | 1.94× |
//! | 8 | 4.57 ms | 1.91 ms | 2.40× |
//! | 16 | 4.51 ms | 1.74 ms | 2.60× |
//! | 32 | 4.62 ms | 1.62 ms | **2.84×** |
//!
//! Selective predicates, by contrast, are flat at ~0.92–0.95 ms whether pinned or
//! not, at every session count.
//!
//! Two things worth reading off the table. At **one** session the pin is measurably
//! *slower* — there is nothing to filter, so only its cost remains, which is the
//! clearest possible confirmation that the win is filtering and not something else.
//! And the growth is **sub-linear** (32 sessions give 2.84×, not 32×): filtering
//! removes candidate rows but not the per-timepoint walk over the retained window,
//! so a floor remains that no amount of filtering removes.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use dogwood_language::Authorizer;
use dogwood_performance::driver::to_event;
use dogwood_performance::workload::{Pinning, PredicateShape, event_stream, lower_shaped};

/// History depth. Deep enough that a scan is the dominant cost (so filtering can
/// show up), shallow enough to keep the sweep quick.
const HISTORY: usize = 400;

/// Rules per set. Small: this benchmark varies *sessions*, and a large policy count
/// would multiply every cell without changing the ratio under study.
const POLICIES: usize = 20;

const SERVERS: usize = 49;
const LOGIN_EVERY: usize = 5;

/// Balanced session counts. "Balanced" matters: events are round-robined across
/// sessions, so each holds an equal share of history and the expected filtering
/// factor is a clean `1/sessions`. A skewed distribution would still benefit, but
/// by an amount that depends on which session is asking.
const SESSION_COUNTS: [usize; 6] = [1, 2, 4, 8, 16, 32];

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning");
    group.sample_size(20);

    for shape in [PredicateShape::Selective, PredicateShape::Broad] {
        for sessions in SESSION_COUNTS {
            let events = event_stream(HISTORY, sessions, SERVERS, LOGIN_EVERY);
            let probe = event_stream(HISTORY + LOGIN_EVERY, sessions, SERVERS, LOGIN_EVERY)
                .into_iter()
                .skip(HISTORY)
                .find(|e| e.decides)
                .expect("a decision after the history");

            for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
                let id = format!("{}/{}sess/{}", shape.label(), sessions, pinning.label());
                group.bench_function(BenchmarkId::from_parameter(&id), |b| {
                    b.iter_batched_ref(
                        || {
                            let mut a = Authorizer::new(lower_shaped(POLICIES, pinning, shape));
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
                });
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
