//! Corpus differential for verdict slicing.
//!
//! The oracle disables slicing; the SUT uses the default leaf map. At every
//! decision they must return identical decisions and diagnostics, while the SUT
//! computes no more leaves and strictly fewer over the complete corpus.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dogwood_language::cedar::Schema;
use dogwood_language::corpus::{TemporalCase, TemporalCategory, temporal_cases};
use dogwood_language::{
    Authorizer, Decision, Error, Event, EventSignature, LoweredPolicySet, PartitionKey,
    PolicySchema, Response, ServiceSchema, TemporalBindings, TemporalEngine, TemporalField,
    parse_trace,
};
use dogwood_local_engine::LocalTemporalEngine;

/// The unpinned event schema (global-trace semantics). The corpus predates the
/// pinned default and relies on cross-principal matching — the same harness
/// `corpus_diff` uses, so the two differentials compare on identical terms.
const UNPINNED_EVENT_SCHEMA: &str = r#"
decision event <A>::request {
    ...inputs(A),
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
    sessionId:         String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
    sessionId:         String,
}
event <A>::error {
    ...inputs(A),
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
    sessionId:         String,
}
"#;

fn unpinned_service() -> ServiceSchema {
    ServiceSchema::builder()
        .event_schema_str(UNPINNED_EVENT_SCHEMA)
        .build()
        .expect("unpinned event schema builds")
}

/// Lower the case's policy against the unpinned corpus service schema.
/// `LoweredPolicySet` is not `Clone` and `Authorizer` consumes it by value, so
/// each authorizer re-lowers from source (cheap relative to event replay).
fn lower(case: &TemporalCase) -> Option<LoweredPolicySet> {
    let schema = PolicySchema::from_cedarschema_str(&case.schema_src).expect("schema builds");
    LoweredPolicySet::from_str(&case.policy_src, &unpinned_service(), &schema).ok()
}

/// Map `f` over `cases` across worker threads, returning the results in corpus
/// order. Verbatim the helper `tests/corpus_diff.rs` uses (mainline `604b61b`),
/// duplicated rather than shared because integration tests are separate crates:
/// the (already corpus-ordered) slice is split into contiguous per-thread chunks,
/// so concatenating the per-chunk results in chunk order reproduces corpus order
/// and anything folded from the output — the difference list, the running totals —
/// is deterministic regardless of thread scheduling.
///
/// This sweep replays every case twice (oracle and SUT), so it is the more
/// expensive of the two corpus differentials; running it on one thread was the
/// single largest contributor to the engine's test wall clock.
fn map_cases_parallel<T: Send>(
    cases: &[TemporalCase],
    f: impl Fn(&TemporalCase) -> T + Sync,
) -> Vec<T> {
    let nthreads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(cases.len().max(1));
    let chunk_size = cases.len().div_ceil(nthreads).max(1);
    let f = &f;
    std::thread::scope(|scope| {
        let handles: Vec<_> = cases
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(f).collect::<Vec<T>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker thread panicked"))
            .collect()
    })
}

// ─── The counter seam ────────────────────────────────────────────────

/// A [`LocalTemporalEngine`] that publishes its slicing observables where the
/// test can read them.
///
/// `Authorizer` takes its temporal engine by value as a `Box<dyn
/// TemporalEngine>` and never hands it back, so `verdicts_computed()` is
/// unreachable once an engine is installed. Rather than widen the frontend's
/// trait for a test's benefit, this delegating wrapper copies the inner engine's
/// counters into shared atomics. Everything else forwards verbatim: the engine
/// under test is the real one.
///
/// (`Arc<AtomicU64>` rather than `Rc<Cell<_>>` because `TemporalEngine: Send`.)
struct CountingEngine {
    inner: LocalTemporalEngine,
    computed: Arc<AtomicU64>,
    unresolved: Arc<AtomicU64>,
}

/// The two handles onto one side of the differential.
struct Counters {
    /// Cumulative leaf verdicts computed, refreshed after every evaluation.
    computed: Arc<AtomicU64>,
    /// How many of this policy set's leaves have an action scope the map could
    /// not resolve, so are computed on every decision. Set at `prepare`.
    unresolved: Arc<AtomicU64>,
}

impl CountingEngine {
    /// An engine and its counters. `slicing` off calls
    /// [`LocalTemporalEngine::disable_slicing`] *before* `prepare`, so no map is
    /// ever built and every decision computes every leaf — the oracle.
    fn new(slicing: bool) -> (Self, Counters) {
        let mut inner = LocalTemporalEngine::new();
        if !slicing {
            inner.disable_slicing();
        }
        let counters = Counters {
            computed: Arc::new(AtomicU64::new(0)),
            unresolved: Arc::new(AtomicU64::new(0)),
        };
        let engine = CountingEngine {
            inner,
            computed: Arc::clone(&counters.computed),
            unresolved: Arc::clone(&counters.unresolved),
        };
        (engine, counters)
    }

    fn publish(&self) {
        self.computed
            .store(self.inner.verdicts_computed(), Ordering::Relaxed);
    }
}

impl TemporalEngine for CountingEngine {
    fn prepare(
        &mut self,
        leaves: &[TemporalField],
        schema: &Schema,
        events: &[EventSignature],
    ) -> Result<(), Error> {
        let prepared = self.inner.prepare(leaves, schema, events);
        self.unresolved.store(
            self.inner.unresolved_action_scopes().len() as u64,
            Ordering::Relaxed,
        );
        prepared
    }

    fn observe(&mut self, event: &Event) {
        self.inner.observe(event);
    }

    fn evaluate(&mut self) -> Result<TemporalBindings, String> {
        let bindings = self.inner.evaluate();
        self.publish();
        bindings
    }

    fn supports_partitioning(&self) -> bool {
        self.inner.supports_partitioning()
    }

    fn set_partition_keys(&mut self, keys: &[PartitionKey]) {
        self.inner.set_partition_keys(keys);
    }
}

/// Build one side of the differential: an authorizer over `policies` with a
/// `LocalTemporalEngine`, slicing on or off, plus the handles onto its counters.
fn side(policies: LoweredPolicySet, slicing: bool) -> (Authorizer, Counters) {
    let (engine, counters) = CountingEngine::new(slicing);
    let authorizer = Authorizer::builder(policies)
        .temporal_engine(engine)
        .build()
        .expect("local engine prepares");
    (authorizer, counters)
}

// ─── What "the same answer" means ────────────────────────────────────

/// One timepoint's observable outcome. `reason` and `errors` are normalized by
/// sorting: Cedar's determining-policy set has no meaningful order, so a
/// difference in order is not a difference in answer (and would make the
/// differential flaky rather than strict).
#[derive(Debug, PartialEq, Eq)]
enum Timepoint {
    /// A history-only event: observed, but not a decision point.
    NoDecision,
    Decided {
        decision: Decision,
        /// The determining rules, by source rule index.
        reason: Vec<usize>,
        errors: Vec<String>,
    },
}

fn timepoint(response: Option<Response>) -> Timepoint {
    let Some(response) = response else {
        return Timepoint::NoDecision;
    };
    let mut reason: Vec<usize> = response
        .diagnostics()
        .reason()
        .map(|rule| rule.rule_index)
        .collect();
    reason.sort_unstable();
    let mut errors: Vec<String> = response
        .diagnostics()
        .errors()
        .map(str::to_string)
        .collect();
    errors.sort();
    Timepoint::Decided {
        decision: response.decision(),
        reason,
        errors,
    }
}

/// Running totals over the sweep, so the assertions can be about the corpus as a
/// whole and a failure message can say how much was actually exercised. Also the
/// aggregate slicing numbers, printed on every green run so
/// they cannot drift silently.
#[derive(Default, Debug)]
struct Totals {
    cases: usize,
    traces: usize,
    decisions: usize,
    /// Leaf verdicts the unsliced oracle computed.
    unsliced_leaves: u64,
    /// Leaf verdicts the sliced SUT computed.
    sliced_leaves: u64,
    /// Decision points where the sliced run computed strictly fewer leaves.
    sliced_decisions: usize,
    /// Decision points where the sliced run computed **nothing** — an action no
    /// temporal rule is scoped to, the mechanism's best case.
    zero_leaf_decisions: usize,
    /// Cases holding at least one leaf whose action scope the map could not
    /// resolve (a bare `action` scope), so every decision computes it. The
    /// conservative path, exercised by real corpus policies.
    cases_with_unresolved_scopes: usize,
}

impl Totals {
    /// Accumulate one case's contribution. Every field is a plain sum, so folding
    /// the per-case results in corpus order gives the same answer a single-threaded
    /// sweep would.
    fn add(&mut self, other: &Totals) {
        self.cases += other.cases;
        self.traces += other.traces;
        self.decisions += other.decisions;
        self.unsliced_leaves += other.unsliced_leaves;
        self.sliced_leaves += other.sliced_leaves;
        self.sliced_decisions += other.sliced_decisions;
        self.zero_leaf_decisions += other.zero_leaf_decisions;
        self.cases_with_unresolved_scopes += other.cases_with_unresolved_scopes;
    }
}

/// One case's contribution to the sweep. Returned rather than accumulated in
/// place so `diff_case` is **pure** (no shared state) and cases can be diffed
/// concurrently — the same shape `corpus_diff`'s `diff_case`/`scan_case` take.
#[derive(Default)]
struct CaseOutcome {
    differences: Vec<String>,
    totals: Totals,
}

/// Diff one case's traces: unsliced oracle vs sliced SUT, at every timepoint.
/// Pure, so cases can be diffed concurrently.
fn diff_case(case: &TemporalCase) -> CaseOutcome {
    let mut out = CaseOutcome::default();
    let CaseOutcome {
        differences,
        totals,
    } = &mut out;
    if lower(case).is_none() {
        differences.push(format!("{}: policy failed to lower", case.name));
        return out;
    }
    totals.cases += 1;
    let mut unresolved_scopes = false;

    for trace in &case.traces {
        let events = match parse_trace(&trace.trace_log) {
            Ok(evts) => evts,
            Err(e) => {
                differences.push(format!(
                    "{}/trace_{}: trace parse error: {e:?}",
                    case.name, trace.index
                ));
                continue;
            }
        };
        totals.traces += 1;

        let (mut oracle, oracle_counters) = side(lower(case).expect("re-lowers"), false);
        let (mut sut, sut_counters) = side(lower(case).expect("re-lowers"), true);
        // A property of the policy, so identical on every trace of the case:
        // recorded once, at whichever trace happens to be first.
        if sut_counters.unresolved.load(Ordering::Relaxed) > 0 {
            unresolved_scopes = true;
        }

        for (i, event) in events.iter().enumerate() {
            let (before_oracle, before_sut) = (
                oracle_counters.computed.load(Ordering::Relaxed),
                sut_counters.computed.load(Ordering::Relaxed),
            );
            let want = timepoint(oracle.is_authorized(event));
            let got = timepoint(sut.is_authorized(event));
            // Work done at this decision point. `<=` is the invariant: slicing
            // may compute every leaf (an action the map cannot answer for, or one
            // every rule is scoped to), but never more than the unsliced path —
            // that would mean it invented a leaf.
            let all = oracle_counters.computed.load(Ordering::Relaxed) - before_oracle;
            let some = sut_counters.computed.load(Ordering::Relaxed) - before_sut;

            let at = format!("{}/trace_{} tp {i}", case.name, trace.index);
            if want != got {
                differences.push(format!(
                    "{at}: unsliced {want:?} ({all} leaf verdict(s) computed) \
                     vs sliced {got:?} ({some} computed)"
                ));
            }

            if want == Timepoint::NoDecision {
                continue;
            }
            totals.decisions += 1;
            totals.unsliced_leaves += all;
            totals.sliced_leaves += some;
            if some > all {
                differences.push(format!(
                    "{at}: sliced computed {some} leaf verdict(s), unsliced computed only {all}"
                ));
            } else if some < all {
                totals.sliced_decisions += 1;
            }
            if some == 0 && all > 0 {
                totals.zero_leaf_decisions += 1;
            }
        }
    }
    totals.cases_with_unresolved_scopes += usize::from(unresolved_scopes);
    out
}

/// The full sweep: slicing changes no decision and no diagnostic, and computes no
/// more work than not slicing, on every passing corpus case.
#[test]
fn slicing_changes_no_corpus_decision_or_diagnostic() {
    let passing: Vec<TemporalCase> = temporal_cases()
        .into_iter()
        .filter(|c| c.category == TemporalCategory::Passing)
        .collect();
    let total = passing.len();
    assert!(
        total > 0,
        "corpus feature must be enabled — no passing cases"
    );

    let mut differences = Vec::new();
    let mut totals = Totals::default();
    // Folded in corpus order (`map_cases_parallel` preserves it), so the
    // difference list and every total are identical to a single-threaded sweep's.
    for outcome in map_cases_parallel(&passing, diff_case) {
        differences.extend(outcome.differences);
        totals.add(&outcome.totals);
    }

    // Reported, never silent: the skip rate is visible in the build log even on a
    // green run, so a change that quietly stops slicing shows up as a number
    // rather than as nothing at all.
    eprintln!("leaf-map corpus differential: {totals:?}");

    assert!(
        differences.is_empty(),
        "{} sliced-vs-unsliced difference(s) over {total} passing cases — slicing \
         must change NO decision and NO diagnostic:\n{}",
        differences.len(),
        differences
            .iter()
            .take(60)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Non-vacuity. Without these the test would pass just as happily if slicing
    // were a no-op, or if the corpus reached no decision point at all — the two
    // ways a differential goes quietly green.
    assert!(
        totals.decisions > 0,
        "no decision points were compared: {totals:?}"
    );
    assert!(
        totals.sliced_leaves < totals.unsliced_leaves,
        "slicing skipped no leaf anywhere in the corpus, so this differential \
         proved nothing: {totals:?}"
    );
    assert!(
        totals.sliced_decisions > 0,
        "no single decision point was sliced: {totals:?}"
    );
    assert!(
        totals.zero_leaf_decisions > 0,
        "no decision point skipped EVERY leaf, so the map's best case — an action \
         no temporal rule is scoped to — went unexercised: {totals:?}"
    );
}
