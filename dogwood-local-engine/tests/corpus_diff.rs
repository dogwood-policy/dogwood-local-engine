//! Differential test: [`LocalTemporalEngine`] must produce the SAME
//! per-decision-point verdicts as Dogwood's in-memory interpreter oracle.
//!
//! For each passing corpus case we build two authorizers over the same policy
//! — one with the default `InMemoryTemporalEngine` (oracle), one with
//! `LocalTemporalEngine` (system under test) — feed the same event stream, and
//! assert the decisions match at every timepoint.
//!
//! This is the referee for the incremental rewrite: it is
//! green today because the engine delegates to the oracle, and it must *stay*
//! green as the delegation is replaced by the window-bounded incremental
//! operators. It needs no database — it is a plain
//! in-process comparison, so it runs on every build.
//!
//! Requires the `corpus` feature on `dogwood-language` (enabled as a
//! dev-dependency feature).

use dogwood_language::cedar::Schema;
use dogwood_language::corpus::{TemporalCase, TemporalCategory, temporal_cases};
use dogwood_language::{
    Authorizer, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, parse_trace,
};
use dogwood_local_engine::LocalTemporalEngine;

/// The unpinned event schema (global-trace semantics). The corpus predates the
/// pinned default and relies on cross-principal matching, so the two engines are
/// compared under it on identical terms.
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

fn case_service(case: &TemporalCase) -> ServiceSchema {
    ServiceSchema::builder()
        .event_schema_str(
            case.event_schema_src
                .as_deref()
                .unwrap_or(UNPINNED_EVENT_SCHEMA),
        )
        .build()
        .expect("case event schema builds")
}

/// Lower the case's policy against the unpinned corpus service schema.
/// `LoweredPolicySet` is not `Clone` and `Authorizer` consumes it by value, so
/// each authorizer re-lowers from source (cheap relative to event replay).
fn lower(case: &TemporalCase) -> Option<LoweredPolicySet> {
    let schema = PolicySchema::from_cedarschema_str(&case.schema_src).expect("schema builds");
    LoweredPolicySet::from_str(&case.policy_src, &unpinned_service(), &schema).ok()
}

fn lower_with_case_service(case: &TemporalCase) -> LoweredPolicySet {
    let schema = PolicySchema::from_cedarschema_str(&case.schema_src).expect("schema builds");
    LoweredPolicySet::from_str(&case.policy_src, &case_service(case), &schema)
        .expect("case policy lowers")
}

/// Map `f` over `cases` across worker threads, returning the results in corpus
/// order. The (already corpus-ordered) slice is split into contiguous per-thread
/// chunks; concatenating the per-chunk results in chunk order reproduces corpus
/// order, so anything folded from the output — in particular a failure list — is
/// deterministic regardless of thread scheduling. Pure `std::thread::scope`, no
/// dependency; mirrors the `dogwood-language` temporal-corpus harness
/// (`tests/passing/temporal_only/harness.rs`).
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

/// Diff one case's traces: oracle (`InMemoryTemporalEngine`) vs SUT
/// (`LocalTemporalEngine`), returning any per-timepoint decision mismatches.
/// Pure (no shared state) so cases can be diffed concurrently.
fn diff_case(case: &TemporalCase) -> Vec<String> {
    let mut mismatches = Vec::new();
    if lower(case).is_none() {
        mismatches.push(format!("{}: policy failed to lower", case.name));
        return mismatches;
    }

    for trace in &case.traces {
        let events = match parse_trace(&trace.trace_log) {
            Ok(evts) => evts,
            Err(e) => {
                mismatches.push(format!(
                    "{}/trace_{}: trace parse error: {e:?}",
                    case.name, trace.index
                ));
                continue;
            }
        };

        let mut oracle = Authorizer::new(lower(case).expect("re-lowers"));
        let mut sut = Authorizer::builder(lower(case).expect("re-lowers"))
            .temporal_engine(LocalTemporalEngine::new())
            .build()
            .expect("local engine prepares");

        for (i, event) in events.iter().enumerate() {
            let want = oracle.is_authorized(event).map(|r| r.decision());
            let got = sut.is_authorized(event).map(|r| r.decision());
            if want != got {
                mismatches.push(format!(
                    "{}/trace_{} tp {i}: oracle {want:?} vs local {got:?}",
                    case.name, trace.index
                ));
            }
        }
    }
    mismatches
}

/// The full sweep: every passing corpus case must agree with the oracle.
#[test]
fn local_engine_matches_oracle_on_full_passing_corpus() {
    let passing: Vec<TemporalCase> = temporal_cases()
        .into_iter()
        .filter(|c| c.category == TemporalCategory::Passing)
        .collect();
    let total = passing.len();
    assert!(
        total > 0,
        "corpus feature must be enabled — no passing cases"
    );

    let mismatches: Vec<String> = map_cases_parallel(&passing, diff_case)
        .into_iter()
        .flatten()
        .collect();

    assert!(
        mismatches.is_empty(),
        "{} verdict mismatch(es) vs the oracle over {total} passing cases:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(60)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// End-to-end regression for a (decimal, tenant) native partition key. The
/// corpus case supplies both universal context pins; equivalent Cedar decimal
/// spellings share history within one tenant, while another tenant remains
/// isolated. The global oracle correlates through `dom_eq`, while
/// LocalTemporalEngine must route to the matching physical shard.
#[test]
fn decimal_pin_corpus_case_matches_under_native_partitioning() {
    let case = temporal_cases()
        .into_iter()
        .find(|case| case.name == "1215_decimal_pin_dom_eq")
        .expect("decimal pin regression case is embedded");
    assert!(
        case.event_schema_src.is_some(),
        "regression case must carry its local service schema"
    );
    assert_eq!(
        lower_with_case_service(&case).partition_keys().len(),
        2,
        "regression service schema must derive the decimal and tenant keys"
    );
    assert_eq!(
        case.traces.len(),
        4,
        "all regression traces must be embedded"
    );

    for trace in &case.traces {
        let events = parse_trace(&trace.trace_log).expect("trace parses");
        let mut oracle = Authorizer::new(lower_with_case_service(&case));
        let mut local = Authorizer::builder(lower_with_case_service(&case))
            .temporal_engine(LocalTemporalEngine::new())
            .partition_temporal()
            .build()
            .expect("local engine prepares in partition mode");

        let mut want = Vec::new();
        let mut got = Vec::new();
        for (i, event) in events.iter().enumerate() {
            if let Some(response) = oracle.is_authorized(event) {
                want.push(format!(
                    "@{} (time point {i}): {}",
                    event.timestamp(),
                    response.decision() == dogwood_language::Decision::Allow
                ));
            }
            if let Some(response) = local.is_authorized(event) {
                got.push(format!(
                    "@{} (time point {i}): {}",
                    event.timestamp(),
                    response.decision() == dogwood_language::Decision::Allow
                ));
            }
        }

        let expected: Vec<_> = trace
            .expected
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        assert_eq!(
            expected.len(),
            2,
            "{}/trace_{} must contain both decision verdicts",
            case.name,
            trace.index
        );
        assert_eq!(
            want, expected,
            "{}/trace_{}: global corpus oracle drifted",
            case.name, trace.index
        );
        assert_eq!(
            got, want,
            "{}/trace_{}: LocalTemporalEngine split a dom-equal decimal partition",
            case.name, trace.index
        );
    }
}

/// One case's contribution to the incremental-coverage sweep: how many temporal
/// leaves it has, and a fallback report iff any of them missed the incremental
/// path. Pure, so cases can be scanned concurrently.
struct LeafScan {
    leaves: usize,
    fallback: Option<String>,
}

fn scan_case(case: &TemporalCase) -> LeafScan {
    let Some(policies) = lower(case) else {
        return LeafScan {
            leaves: 0,
            fallback: None,
        };
    };
    let leaves: Vec<_> = policies.temporal_fields().cloned().collect();
    if leaves.is_empty() {
        return LeafScan {
            leaves: 0,
            fallback: None,
        };
    }
    // Drive the engine directly so we can read the incremental count.
    let mut engine = LocalTemporalEngine::new();
    let schema: Schema = lower(case).expect("re-lowers").cedar_schema().clone();
    let sigs: Vec<_> = policies.event_signatures().collect();
    engine.prepare(&leaves, &schema, &sigs).expect("prepares");
    let inc = engine.incremental_leaf_count();
    let fallback = (inc != leaves.len())
        .then(|| format!("{}: {}/{} incremental", case.name, inc, leaves.len()));
    LeafScan {
        leaves: leaves.len(),
        fallback,
    }
}

/// Every temporal leaf in the passing corpus runs on the INCREMENTAL path —
/// the scan fallback is dead code for prepared policies. Proves the "do it all"
/// completeness claim: `Monitor::build` returns `Some` for every real leaf
/// (only transient macro nodes, which never survive lowering, fall back).
#[test]
fn every_passing_corpus_leaf_is_incremental() {
    let passing: Vec<TemporalCase> = temporal_cases()
        .into_iter()
        .filter(|c| c.category == TemporalCategory::Passing)
        .collect();

    let mut total_leaves = 0usize;
    let mut fallback = Vec::new();
    for scan in map_cases_parallel(&passing, scan_case) {
        total_leaves += scan.leaves;
        if let Some(report) = scan.fallback {
            fallback.push(report);
        }
    }

    assert!(total_leaves > 0, "corpus feature must be enabled");
    assert!(
        fallback.is_empty(),
        "{} case(s) have leaves on the scan fallback (expected zero — all \
         supported constructs are incremental):\n{}",
        fallback.len(),
        fallback.join("\n")
    );
}
