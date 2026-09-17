//! Sequential per-decision latency: reference vs. server, across policy count
//! (10 / 100 / 1000) and session pinning.
//!
//! # How a decision is measured
//!
//! Each iteration submits **one** event to an engine that has already been warmed
//! with a fixed history, so the reported time is the marginal cost of one decision
//! against that history — not an amortized average over a replay, which would hide
//! the reference implementation's growth (its cost rises *with* history, so an
//! average over a growing trace understates the steady-state cost).
//!
//! The history is rebuilt per batch rather than per iteration, because building it
//! costs far more than one decision and would swamp the signal. That means the
//! measured engine keeps growing across a batch; criterion's per-iteration mean is
//! therefore a mean over a window of history lengths, which is the honest
//! compromise and is why [`HISTORY`] is held fixed across all variants.
//!
//! # Why the verdict cross-check comes first
//!
//! Before any timing, the two engines are run over the same stream and their
//! verdict *shapes* compared. A benchmark of two implementations that disagree is
//! measuring two different computations — and the most likely cause of divergence
//! here is a workload bug (a field written to one bag but not the other), which
//! would silently make every correlation fail and turn this into a benchmark of the
//! non-matching path. The check makes that failure loud.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use dogwood_language::Authorizer;
use dogwood_performance::driver::{ServerHarness, fsync_floor, run_reference, to_event, to_wire};
use dogwood_performance::workload::{POLICY_COUNTS, Pinning, event_stream, lower};

/// Events of history each engine is warmed with before the measured decision.
///
/// Chosen so the reference implementation's rescan is visible but the benchmark
/// still finishes: at 1000 policies its per-decision cost is roughly
/// `policies × history`, so a larger history would make the 1000-policy variant
/// dominate the whole run.
const HISTORY: usize = 200;

/// Distinct sessions in the workload. Load-bearing for the pinning axis: a pin
/// only filters if there is something to filter out, so with one session the
/// pinned variant pays the extra correlation for no benefit, and with many it
/// rejects most of history immediately.
const SESSIONS: usize = 10;

/// Distinct server values. MUST be coprime to `LOGIN_EVERY` — see
/// `workload::event_stream`, where a common factor makes login servers and read
/// servers disjoint and every decision allow.
const SERVERS: usize = 49;

/// One `Login` (history) per this many events; the rest are `Read` decisions.
const LOGIN_EVERY: usize = 5;

/// Report the durability floor once, up front. Without it, the server's numbers
/// invite attributing storage cost to the policy engine.
fn report_floor() {
    let floor = fsync_floor(200);
    let per_ms = floor.as_secs_f64() * 1000.0;
    eprintln!("\n─── durability floor on this machine ───");
    eprintln!("  one fsync'd redb append: {per_ms:.3} ms");
    eprintln!("  => server per-event latency cannot go below this,");
    eprintln!(
        "     and its single-instance throughput ceiling is ~{:.0} events/s.",
        1.0 / floor.as_secs_f64()
    );
    eprintln!("  The reference implementation performs NO durable write, so any");
    eprintln!("  server-vs-reference gap smaller than this is storage, not engine.\n");
}

/// Assert the two implementations agree on the workload, so the timings below
/// describe the same computation.
fn cross_check(pinning: Pinning) {
    let events = event_stream(60, SESSIONS, SERVERS, LOGIN_EVERY);
    let reference = run_reference(lower(10, pinning), &events);

    let mut server = ServerHarness::new("xcheck", 10, pinning);
    let server_verdicts = server.run(&events);

    // Compare shape: which events decided, and how many allows. Exact per-event
    // equality is not required because the server assigns its own timestamps
    // (`DESIGN.md` §3.3) while the reference uses the generated ones, so
    // window-edge cases can legitimately differ. Shape equality still catches the
    // failure that matters — a correlation that never matches at all.
    let ref_decided: Vec<bool> = reference.iter().map(|v| v.is_some()).collect();
    let srv_decided: Vec<bool> = server_verdicts.iter().map(|v| v.is_some()).collect();
    assert_eq!(
        ref_decided,
        srv_decided,
        "{}: the two engines disagree about WHICH events decide — the workload is \
         malformed, not the engines",
        pinning.label()
    );

    let ref_allows = reference.iter().filter(|v| **v == Some(true)).count();
    let srv_allows = server_verdicts.iter().filter(|v| **v == Some(true)).count();
    assert_eq!(
        ref_allows,
        srv_allows,
        "{}: allow counts differ (reference {ref_allows}, server {srv_allows}) — \
         the engines are computing different things",
        pinning.label()
    );

    // A workload where nothing ever matches would measure only the failure path,
    // and a workload where everything matches would never exercise the scan. Both
    // are silent failures, so require a genuine mix.
    let decisions = reference.iter().filter(|v| v.is_some()).count();
    assert!(
        ref_allows > 0 && ref_allows < decisions,
        "{}: workload must produce a MIX of allow/deny (got {ref_allows} allows of \
         {decisions} decisions); a uniform workload measures one code path only",
        pinning.label()
    );
}

/// Confirm the pinned variant really is pinned — that the schema registers a
/// partition key rather than merely correlating predicates.
fn assert_pin_is_real() {
    use dogwood_server::ShardPlan;
    assert_eq!(
        ShardPlan::from_policies(&lower(10, Pinning::Unpinned)),
        ShardPlan::Unshardable,
        "the unpinned variant must declare no partition key"
    );
    assert!(
        matches!(
            ShardPlan::from_policies(&lower(10, Pinning::PinnedSession)),
            ShardPlan::Sharded { .. }
        ),
        "the pinned variant must register a universal symmetric pin — otherwise \
         the `pinned` axis is measuring nothing"
    );
}

fn bench(c: &mut Criterion) {
    report_floor();
    assert_pin_is_real();
    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        cross_check(pinning);
    }

    let events = event_stream(HISTORY, SESSIONS, SERVERS, LOGIN_EVERY);
    // The measured event: the first *decision* after the warm-up history. Taking
    // the stream's last element does not work — index `HISTORY` is a multiple of
    // `LOGIN_EVERY`, hence a history-only `Login`, which yields no verdict and would
    // benchmark the append path instead of the decision path.
    let probe = event_stream(HISTORY + LOGIN_EVERY, SESSIONS, SERVERS, LOGIN_EVERY)
        .into_iter()
        .skip(HISTORY)
        .find(|e| e.decides)
        .expect("a decision event after the history");
    assert!(probe.decides, "the probe event must be a decision point");

    let mut group = c.benchmark_group("decide");

    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        for count in POLICY_COUNTS {
            let id = format!("{}/{}p", pinning.label(), count);

            // Sample count scales down with policy count. Each sample rebuilds the
            // warm-up history, and at 10k policies that setup costs the reference
            // ~14s — so a flat 20 samples would spend ~10 minutes on those cells
            // alone. The measurements are low-variance (well under 5% spread at every
            // size), so a smaller sample at the large end loses little; the
            // alternative is a benchmark nobody runs.
            group.sample_size(if count >= 10_000 { 10 } else { 20 });

            // ── reference: in-memory, non-durable, rescans history ──
            group.bench_with_input(
                BenchmarkId::new("reference", &id),
                &(count, pinning),
                |b, &(count, pinning)| {
                    b.iter_batched_ref(
                        || {
                            // Fresh authorizer warmed with the history.
                            let mut a = Authorizer::new(lower(count, pinning));
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

            // ── server: durable (fsync per event), incremental ──
            group.bench_with_input(
                BenchmarkId::new("server", &id),
                &(count, pinning),
                |b, &(count, pinning)| {
                    b.iter_batched_ref(
                        || {
                            let mut h = ServerHarness::new("decide", count, pinning);
                            h.run(&events);
                            h
                        },
                        |harness| {
                            std::hint::black_box(harness.submit(&probe));
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

// Keep `to_wire` referenced: it is the server driver's renderer, exercised through
// `ServerHarness`, and naming it here documents that both drivers derive from one
// `GenEvent`.
#[allow(dead_code)]
fn _renderers_share_one_source(e: &dogwood_performance::workload::GenEvent) {
    let _ = to_wire(e);
    let _ = to_event(e);
}
