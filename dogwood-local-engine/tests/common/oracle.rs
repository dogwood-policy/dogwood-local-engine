//! Does a recovered store still *decide* correctly?
//!
//! The structural invariants can tell that a store is well-formed — dense
//! offsets, ordered timestamps, acknowledged records present. They cannot tell
//! whether the monitor state recovery rebuilt is the *right* state, because that
//! state is an opaque blob with nothing inspectable to compare against.
//!
//! So ask it a question instead, and check the answer against an independent
//! implementation. `dogwood_language`'s `InMemoryTemporalEngine` — the reference
//! interpreter, and the definition of what the language means — is that
//! implementation; `Authorizer::new` installs it. `dogwood-local-engine`'s
//! `corpus_diff` already plays the two against each other for the no-crash case,
//! and this is the same differential with a crashed-and-recovered server as the
//! subject:
//!
//! 1. run a workload, recording it ([`super::workload`]);
//! 2. crash, recover;
//! 3. ask the recovered server one more question — submit a probe, take the
//!    verdict;
//! 4. ask the reference the same question: fresh interpreter, same policy, fed the
//!    same events, then the probe;
//! 5. the two answers must match.
//!
//! # The one hard part: where history begins
//!
//! The server *keeps* a rule's accumulated window across a policy change when the
//! rule is unchanged (`DESIGN.md` §9.1). A freshly built reference has no history
//! at all. So a faithful comparison has to feed the reference from the same point
//! the server's leaves started from — and a single reference has one shared
//! history, so it can only represent one start point for all leaves.
//!
//! That is sufficient exactly when every leaf shares a start point, and the
//! condition for that is precise: a leaf's start moves only when that leaf is
//! reset by an apply, an all-reset apply moves every leaf to the same point, and
//! an all-kept apply moves none. **So starts diverge if and only if some apply was
//! mixed.** Refusing mixed installs is therefore not conservative — it is exactly
//! the boundary, which is why [`super::workload::Transition`] makes them
//! unrepresentable unless a workload asks for one on purpose.
//!
//! The cost is real and worth stating: "add a rule, keep the others" is mixed, and
//! it is the most ordinary policy edit there is. Those workloads get the structural
//! invariants only.
//!
//! # The other precondition: the cut must be quiescent
//!
//! History is reconstructed from [`Promises`], which records an operation only once
//! it returned `Ok`. So the oracle assumes **nothing was in flight** when the store
//! was frozen. That holds today because the harness freezes the byte image after the
//! workload returns, never mid-call — and [`assert_agrees`] now checks it rather
//! than trusting it.
//!
//! It stops holding the moment a crash can land *inside* a commit. A record can be
//! durable before its caller is told, so the log would hold an event `Promises` has
//! never heard of; the reference would then be fed less history than the recovered
//! server actually has, and the comparison would report
//! `MISMATCH (recovery)` — sending a reader after a recovery bug that does not
//! exist. That window is precisely what fault injection aims at, so the check below
//! exists to fail as a *harness* limit instead.
//!
//! ## Why this is not fixed by "just include the pending operation too"
//!
//! An unacknowledged operation has no known timestamp, so it has no known
//! **position** — and position is what the reference needs. Sequentially that is
//! recoverable: there is at most one, it was the last thing attempted, and after
//! rescaling to seconds its exact value cannot change any window. Concurrently it is
//! not: several in-flight operations have unknown order relative to each other and
//! to concurrently-acknowledged ones, which is factorial in the pending set and
//! reintroduces exactly the linearization *search* this design avoids by having the
//! server publish its own order.
//!
//! The way out, when it is needed, is to stop inferring the order and read it: the
//! recovered log carries real timestamps in real order for everything that survived.
//! `Promises` would then answer only "what must survive" — one-directional, needing
//! no order — and the log would answer "what history does the server have".
//!
//! That has its own boundary, and it is the snapshot: records below the watermark
//! are gone, so if an operation whose acknowledgement was lost sits below a later
//! prune, its effect is in the snapshot, the server has it, and *neither* source can
//! tell the harness it existed. So the sound rule is that the uncertain window must
//! not overlap a prune — oracle tests either avoid checkpointing or take a quiescent
//! cut.
//!
//! ## It is a symptom, not an accident
//!
//! The harness's difficulty is the client's difficulty. A real caller that loses its
//! response cannot tell whether its event landed either — which is why the log
//! offset was no use to it. Both are fixed by the same missing feature: a
//! client-supplied idempotency token recorded in the record, which would let a
//! crashed caller ask "did mine land?" and let this harness match records to
//! intended operations instead of inferring.

#![allow(dead_code)] // Each consuming test uses a subset.

use dogwood_language::{Authorizer, EventBuilder, LoweredPolicySet, PolicySchema, ServiceSchema};
use dogwood_local_engine::{DurableTemporalEngine, Installed, Outcome};

use super::invariants::LogFacts;
use super::workload::{Op, Promises, Retention};

/// Why no comparison could be made. **None of these is a correctness failure** —
/// each says the harness was asked for something outside what it can check, and
/// the fix is to the test rather than to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// Some leaves kept their windows while others reset, so leaves have
    /// different history start points and one reference cannot represent them.
    MixedInstall { ts: i64, retention: Retention },
    /// No policy was ever applied, so there is nothing to compare under.
    NoPolicy,
    /// The bundle would not lower — the workload's own policy is malformed.
    BundleWillNotLower(String),
    /// The probe is a history-kind event, so neither side produces a verdict.
    ProbeIsNotADecision { kind: String },
    /// The probe's verdict is the same with and without the recorded history, so
    /// agreement between the two sides would prove nothing.
    ProbeDoesNotDiscriminate { verdict: bool },
    /// The recovered log holds a record the harness never learned about, so an
    /// operation was in flight when the store was frozen. History reconstructed
    /// from `Promises` is therefore incomplete and any comparison is unsound.
    NonQuiescentCut { offset: u64, ts: i64 },
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unavailable::MixedInstall { ts, retention } => write!(
                f,
                "HARNESS: the apply at {ts} was a {retention:?} install, so its \
                 leaves have different history start points and one reference \
                 interpreter cannot represent them. This is a limit of the check, \
                 not a fault in the server: use `Transition::KeepingAllWindows` or \
                 `ResettingAllWindows`, or accept the structural invariants alone"
            ),
            Unavailable::NoPolicy => write!(
                f,
                "HARNESS: no policy was ever applied, so there is nothing to \
                 compare under"
            ),
            Unavailable::BundleWillNotLower(e) => write!(
                f,
                "HARNESS: the workload's own bundle does not lower ({e}), so the \
                 reference cannot be built"
            ),
            Unavailable::ProbeIsNotADecision { kind } => write!(
                f,
                "HARNESS: the probe's kind `{kind}` is not a decision point, so \
                 neither side yields a verdict to compare"
            ),
            Unavailable::NonQuiescentCut { offset, ts } => write!(
                f,
                "HARNESS: the recovered log holds a record at offset {offset} \
                 (ts {ts}) that was never acknowledged, so an operation was in \
                 flight when the store was frozen. The reference would be fed less \
                 history than the server has and the comparison would blame \
                 recovery for it. Freeze the store only between calls, or take \
                 history from the log rather than from what was promised"
            ),
            Unavailable::ProbeDoesNotDiscriminate { verdict } => write!(
                f,
                "HARNESS: the probe decides `{verdict}` both with and without the \
                 recorded history, so agreement would prove nothing. Choose a probe \
                 whose verdict depends on the history the workload built"
            ),
        }
    }
}

/// Nanoseconds, as the reference interpreter's second-based comparison needs them.
///
/// The frontend's interpreter measures windows in **seconds** — one line in
/// `interpreter/eval.rs`, `delta <= within.seconds()` — while the server assigns
/// epoch **nanoseconds**. Handing it nanosecond timestamps makes every pair of
/// events look more than an hour apart, so `formerly within 1h` never holds, the
/// reference permits everything, and the comparison is worse than useless:
/// agreement is vacuous and disagreement points at the wrong thing.
///
/// `tick.rs` records this divergence as a migration seam — the engine converts
/// each declared window into its own unit for exactly this reason. Rescaling the
/// trace is the same conversion applied from the other side.
///
/// The consequence worth knowing: the oracle adjudicates *semantics*, not window
/// edges finer than a second. Since `within` has second granularity, nothing the
/// language can express is lost — but a test that wants boundary behaviour has to
/// separate its events by real seconds.
fn reference_ts(nanos: i64) -> i64 {
    nanos / 1_000_000_000
}

/// Where the running set's history begins, per the rule above.
fn history_start(ops: &[Op]) -> Result<(&Installed, i64), Unavailable> {
    let mut policy: Option<&Installed> = None;
    let mut from = i64::MIN;
    for op in ops {
        if let Op::Applied {
            ts,
            policy: p,
            retention,
            ..
        } = op
        {
            match retention {
                // No leaf's start moves.
                Retention::AllKept => {}
                // Every leaf's start moves to here, together.
                Retention::AllReset => from = *ts,
                Retention::Mixed => {
                    return Err(Unavailable::MixedInstall {
                        ts: *ts,
                        retention: *retention,
                    });
                }
            }
            policy = Some(p);
        }
    }
    policy.map(|p| (p, from)).ok_or(Unavailable::NoPolicy)
}

/// Lower a bundle from its own source, independently of the engine's own rebuild.
///
/// The service schema (event schema + macros) is store config now
/// (`POLICY_INSTALL_SEMANTICS.md` §2.7), no longer carried in `Installed`. Every
/// oracle-driven workload configures the store with the **default** service
/// schema, so the reference lowers against the defaults too; a workload that
/// wanted a custom event schema would have to thread its config in here.
fn lower(installed: &Installed) -> Result<LoweredPolicySet, Unavailable> {
    let service = ServiceSchema::builder()
        .build()
        .map_err(|e| Unavailable::BundleWillNotLower(format!("service schema: {e}")))?;
    let policy_schema = PolicySchema::from_cedarschema_str(&installed.action_schema)
        .map_err(|e| Unavailable::BundleWillNotLower(format!("action schema: {e}")))?;
    let source = installed.combined_source();
    LoweredPolicySet::from_str(&source, &service, &policy_schema)
        .map_err(|e| Unavailable::BundleWillNotLower(format!("policy: {e}")))
}

/// The reference's verdict for `probe` at `probe_ts`, after replaying the recorded
/// history under the running policy.
///
/// `feed_history` false replays nothing, which is how [`assert_agrees`] checks
/// that the probe is actually sensitive to history.
pub fn reference_verdict(
    ops: &[Op],
    probe: &EventBuilder,
    probe_ts: i64,
    feed_history: bool,
) -> Result<bool, Unavailable> {
    let (installed, from) = history_start(ops)?;
    let mut reference = Authorizer::new(lower(installed)?);

    if feed_history {
        for op in ops {
            if let Op::Submitted { ts, event, .. } = op
                && *ts >= from
            {
                // History-kind events too: they yield no verdict but they are what
                // builds the window the probe will be judged against. The stored
                // builder is un-timestamped; re-stamp it at the reference's
                // (second) resolution — the same conversion `reference_ts` names.
                reference.is_authorized(&event.clone().timestamp(reference_ts(*ts)).build());
            }
        }
    }

    let probe_event = probe.clone().timestamp(reference_ts(probe_ts)).build();
    reference
        .is_authorized(&probe_event)
        .map(|r| r.allowed())
        .ok_or_else(|| Unavailable::ProbeIsNotADecision {
            kind: probe_event.kind().to_string(),
        })
}

/// How a caller establishes that its probe can distinguish a correct recovery from
/// a broken one. A probe whose verdict no leaf state could change makes agreement
/// meaningless, so this is never left implicit.
#[derive(Debug, Clone, Copy)]
pub enum Sensitivity {
    /// The reference's verdict must differ with and without the recorded history.
    /// Checked automatically. The right choice when the policy in force is about
    /// history the workload actually built.
    HistoryDependent,
    /// The test has established sensitivity itself, and says how.
    ///
    /// Needed when the *correct* answer is history-insensitive while a faulty
    /// state would still differ — which is exactly the stale-snapshot case: the
    /// installed policy watches `Login`, no `Login` ever happened, so a correct
    /// store permits whatever the history contains, and only a store that
    /// inherited another formula's matches denies. Automatic checking would reject
    /// the one test that matters.
    AssertedByTest(&'static str),
}

/// Submit `probe` to a recovered store and require the reference to agree.
///
/// Distinguishes four outcomes, because each sends the reader somewhere different:
///
/// * `HARNESS:` — the check could not be made. Fix the test.
/// * `MISMATCH (recovery):` — live agreed with the reference and the recovered
///   store does not. **The bug this exists for.**
/// * `MISMATCH (pre-existing):` — live already disagreed, so recovery is not the
///   culprit and the evaluation path is where to look.
/// * agreement — nothing printed.
#[track_caller]
pub fn assert_agrees(
    recovered: &mut DurableTemporalEngine,
    facts: &LogFacts,
    promises: &Promises,
    probe: &EventBuilder,
    sensitivity: Sensitivity,
) {
    let ops = &promises.ops;
    // The probe's kind/action, for diagnostics and the decision-point check. The
    // timestamp is irrelevant to either, so a placeholder is fine here.
    let probe_event = probe.clone().timestamp(0).build();

    // Structural checks first, always: a malformed store makes a verdict
    // comparison meaningless rather than informative, and the structural violation
    // is the more precise error. Ordering this here rather than asking each test to
    // remember it.
    super::invariants::assert_all(facts, promises);

    // Then the quiescence precondition (see the module docs). Every surviving
    // record must be one the harness knows about; one it does not means an
    // operation committed without being acknowledged, and history rebuilt from
    // `Promises` is missing it.
    // An apply now spans a *range* of contiguous offsets (§2.6: per-verb records
    // + preamble records), so expand `Op::Applied` into every offset it wrote.
    let known: std::collections::BTreeSet<u64> = ops
        .iter()
        .flat_map(|op| -> Box<dyn Iterator<Item = u64>> {
            match op {
                Op::Applied {
                    first_offset,
                    offset,
                    ..
                } => Box::new(*first_offset..=*offset),
                Op::Submitted { offset, .. } => Box::new(std::iter::once(*offset)),
            }
        })
        .collect();
    for &(offset, ts, _) in &facts.records {
        if !known.contains(&offset) {
            panic!("{}", Unavailable::NonQuiescentCut { offset, ts });
        }
    }

    let submitted = recovered
        .submit(probe.clone())
        .expect("the probe must submit against a recovered store");
    let got = match &submitted.outcome {
        Outcome::Decision(r) => r.allowed(),
        Outcome::Recorded => panic!(
            "{}",
            Unavailable::ProbeIsNotADecision {
                kind: probe_event.kind().to_string()
            }
        ),
    };

    let want = match reference_verdict(ops, probe, submitted.ts, true) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };

    // A probe no leaf state could sway makes agreement meaningless.
    match sensitivity {
        Sensitivity::HistoryDependent => match reference_verdict(ops, probe, submitted.ts, false) {
            Ok(bare) if bare == want => panic!(
                "{}",
                Unavailable::ProbeDoesNotDiscriminate { verdict: want }
            ),
            Ok(_) => {}
            Err(e) => panic!("{e}"),
        },
        // The test owns the argument; its own assertions carry it.
        Sensitivity::AssertedByTest(_) => {}
    }

    if got == want {
        return;
    }

    // Attribute the disagreement. If the live server already differed from the
    // reference on the same question, this is not a recovery fault.
    let live_disagreed = ops.iter().any(|op| match op {
        Op::Submitted {
            ts,
            event,
            live: Some(live),
            ..
        } => reference_verdict(ops, event, *ts, true).is_ok_and(|r| r != *live),
        _ => false,
    });

    let (_, from) = history_start(ops).expect("checked above");
    let fed = ops
        .iter()
        .filter(|op| matches!(op, Op::Submitted { ts, .. } if *ts >= from))
        .count();
    let label = if live_disagreed {
        "MISMATCH (pre-existing): the live server already disagreed with the \
         reference before any crash, so this is not a recovery fault — look at the \
         evaluation path"
    } else {
        "MISMATCH (recovery): the live server agreed with the reference and the \
         recovered store does not, so recovery rebuilt the wrong state"
    };
    panic!(
        "{label}\n  \
         recovered store: {got}\n  \
         reference:       {want}\n  \
         probe:           kind `{}` action `{}`\n  \
         history fed:     {fed} event(s) at or after ts {from}\n  \
         operations:      {} recorded\n  \
         policy in force: {} byte(s)",
        probe_event.kind(),
        probe_event.action(),
        ops.len(),
        history_start(ops)
            .map(|(p, _)| p.combined_source().len())
            .unwrap_or(0),
    );
}
