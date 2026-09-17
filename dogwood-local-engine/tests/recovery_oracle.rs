//! The behavioural half of recovery testing: after a crash, does the store still
//! *decide* the same way the reference interpreter does?
//!
//! Every test here is a crash-and-recover cycle whose verdict is compared against
//! `dogwood_language`'s in-memory interpreter. The bug this exists for is one no
//! structural invariant can see, and it has a name in the repository's history —
//! see `a_stale_snapshot_cannot_hand_one_formula_anothers_history`.

mod common;

use common::invariants::{self as inv, LogFacts};
use common::oracle::{self, Sensitivity, Unavailable};
use common::workload::{Promises, Recorder, Retention};
use dogwood_language::{Event, EventBuilder, ParsedPolicySet, ServiceSchema, Value};
use dogwood_local_engine::{
    DurableLog, DurableTemporalEngine, Installed, Record, Snapshot, SnapshotPayload, Verb, Write,
};

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Login appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

/// Gated on a past `Read`. One leaf, one predicate.
const WATCHING_READ: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

/// Gated on a past `Login`. Also one leaf with one predicate — the *same arity* as
/// `WATCHING_READ`, which is what made the stale-snapshot bug invisible to every
/// positional and structural check.
const WATCHING_LOGIN: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Login"::response{} };
"#;

/// A **non-temporal** rule to `Add` over `WATCHING_READ`. It introduces no
/// temporal leaf, so every existing window is kept (`Retention::AllKept`) — the
/// verb form of a keep-every-window edit.
const LOGIN_FORBID_NONTEMPORAL: &str =
    r#"forbid (principal, action == Action::"Login", resource) when { principal has dept };"#;

/// A second **temporal** rule to `Add` over `WATCHING_READ`. It introduces a
/// fresh leaf while the existing one is kept — a genuinely `Retention::Mixed`
/// change (one leaf kept, one reset), which the oracle refuses by design.
const LOGIN_FORBID_TEMPORAL: &str = r#"forbid (principal, action == Action::"Login", resource) when temporal { formerly within 1h Action::"Login"::response{} };"#;

/// A NEGATED leaf: forbid `Export` unless a `Login` response is in window. The
/// `!(formerly …)` compiles to a `Node::Not`, so checkpointing this bundle
/// snapshots a `Not` node — the arm `save_state`/`load_state` are otherwise
/// never driven over (the corpus never checkpoints, and the hand-authored
/// recovery policies are all `formerly`/aggregate-based).
const FORBID_UNLESS_LOGIN: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { !(formerly within 1h Action::"Login"::response{}) };
"#;

/// A `previous` leaf: forbid `Export` if a `Read` response was the immediately
/// preceding timepoint. Compiles to a `Node::Previous`, whose "did the child
/// hold last timepoint" state must survive a snapshot — exactly the round-trip
/// this exercises.
const FORBID_AFTER_PREVIOUS_READ: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { previous within 1h Action::"Read"::response{} };
"#;

fn bundle(policy: &str) -> Installed {
    let parsed =
        ParsedPolicySet::parse(policy, &ServiceSchema::defaults()).expect("fixture policy parses");
    let statements = parsed.policies().map(|policy| policy.expanded_source());
    Installed {
        policies: dogwood_local_engine::PolicySet::from_statements(statements, 0),
        action_schema: ACTION_SCHEMA.to_string(),
    }
}

fn ev(action: &str, kind: &str) -> EventBuilder {
    // Principal, resource and context all matter: without them Cedar cannot build
    // a request, the decision fails closed, and every probe denies regardless of
    // history — which the discriminating-probe guard catches, loudly, rather than
    // letting the comparison pass on a verdict that means nothing. This mirrors the
    // event the server's `to_event` would build from the equivalent wire event:
    // logged `input.doc` (the temporal record) and the request context both set.
    Event::builder(&format!("Action::{action}"), kind)
        .principal("User::\"alice\"")
        .resource("Doc::\"d1\"")
        .field("input", "doc", Value::String("d1".to_string()))
        .request_context("input", "doc", Value::String("d1".to_string()))
}

fn path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_oracle_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Run `workload`, freeze the store, and hand back the frozen copy plus what was
/// promised — the shape every test here shares.
fn crash_after(tag: &str, workload: impl FnOnce(&mut Recorder)) -> (std::path::PathBuf, Promises) {
    let live = path(&format!("{tag}_live"));
    let frozen = path(&format!("{tag}_frozen"));
    let promises = {
        let mut rec = Recorder::new(DurableTemporalEngine::open(&live, 0).expect("opens"));
        workload(&mut rec);
        rec.finish()
    };
    std::fs::copy(&live, &frozen).expect("freeze");
    let _ = std::fs::remove_file(&live);
    (frozen, promises)
}

#[test]
fn a_recovered_store_decides_as_the_reference_does() {
    let (frozen, promises) = crash_after("healthy", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("submit");
        rec.checkpoint().expect("checkpoint");
        rec.submit(ev("Read", "response")).expect("submit");
    });

    // Structural checks first: a malformed store would make a verdict comparison
    // meaningless rather than informative.
    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    // `assert_agrees` runs the structural checks first, so they are not repeated.
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn history_that_survives_only_in_the_snapshot_still_decides() {
    // The test that makes the snapshot path load-bearing. The `Read` is submitted
    // and then checkpointed, so the checkpoint prunes its record from the log and
    // the *only* remaining trace of it is inside the snapshot. Nothing is submitted
    // afterwards, so a replay of the surviving tail cannot reconstruct it.
    //
    // If recovery loses or mis-loads the snapshot, the recovered store believes no
    // `Read` ever happened and permits an Export the rule forbids. No structural
    // invariant can see that: the store is perfectly well-formed, and the record
    // is legitimately absent because a snapshot summarises it.
    let (frozen, promises) = crash_after("snapshot_only", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("the Read");
        rec.checkpoint().expect("snapshot, and prune the Read away");
    });

    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    // The premise: the Read's record really is gone, folded into the snapshot.
    assert!(
        facts.base_offset > 0 && facts.snapshot_up_to.is_some(),
        "the checkpoint must have pruned and snapshotted, or this proves nothing: \
         {facts:?}"
    );
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_stale_snapshot_cannot_hand_one_formula_anothers_history() {
    // The shape of the bug b6a0838 fixed, and the reason this file exists.
    //
    // Bundle A watches `Read`; bundle B watches `Login`. Both have exactly one
    // leaf with one predicate, so a positional snapshot load cannot tell them
    // apart — and every structural invariant passes either way: same arity, same
    // fingerprint length, dense offsets, monotone timestamps.
    //
    // The checkpoint takes a snapshot under A. The apply of B then replaces the
    // policy. If recovery restored A's monitor state into B's leaf, the recovered
    // store believes a `Login` occurred when only a `Read` ever did, and denies an
    // Export that must be permitted.
    let (frozen, promises) = crash_after("stale_snapshot", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA)
            .expect("applies A");
        rec.submit(ev("Read", "response"))
            .expect("the Read A watches");
        rec.checkpoint().expect("snapshot taken under A");
        // Different formula, so every window resets — B's leaf must start empty.
        rec.install(WATCHING_LOGIN, ACTION_SCHEMA)
            .expect("applies B");
    });

    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    // Stated separately because it is the whole point: every structural check
    // passes on this store. `assert_agrees` runs them again, harmlessly.
    inv::assert_all(&facts, &promises);

    // Sensitivity, argued rather than inferred: under B the reference permits the
    // Export whatever the recorded history holds, because no `Login` ever
    // occurred. What distinguishes a correct store from one that inherited A's
    // matches is that the latter denies — so establish that B's rule *can* deny,
    // by showing the reference denies once a `Login` is in its history.
    let mut with_login = promises.ops.clone();
    let login_ts = promises.ops.last().expect("ops").ts() + 1_000_000_000;
    with_login.push(common::workload::Op::Submitted {
        ts: login_ts,
        offset: u64::MAX,
        event: ev("Login", "response"),
        live: None,
    });
    let probe = ev("Export", "request");
    assert!(
        !oracle::reference_verdict(&with_login, &probe, login_ts + 1_000_000_000, true)
            .expect("reference"),
        "B's rule must be able to deny, or this probe cannot distinguish anything"
    );

    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &probe,
        Sensitivity::AssertedByTest(
            "under B the correct verdict is history-insensitive; only a store \
             holding A's matches denies",
        ),
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn history_carries_across_a_change_that_keeps_every_window() {
    // The other half of §9.1: an edit that leaves the temporal clause untouched
    // must preserve the accumulated window, so the reference is fed everything.
    let (frozen, promises) = crash_after("kept", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("submit");
        // Adds a non-temporal rule: no new leaf, so every window is kept.
        rec.batch(
            vec![Verb::Add {
                policy: LOGIN_FORBID_NONTEMPORAL.to_string(),
            }],
            Retention::AllKept,
        )
        .expect("applies the edit");
    });

    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_mixed_install_is_refused_as_a_harness_limit_not_a_mismatch() {
    // The distinction has to be real, not merely claimed: a workload outside the
    // oracle's domain must be reported as a limit of the check, so nobody goes
    // hunting a recovery bug that does not exist.
    let (frozen, promises) = crash_after("mixed", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("submit");
        // Keeps the Read leaf, adds a Login leaf: one kept, one reset.
        rec.batch(
            vec![Verb::Add {
                policy: LOGIN_FORBID_TEMPORAL.to_string(),
            }],
            Retention::Mixed,
        )
        .expect("applies the mixed change");
    });

    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    let probe = ev("Export", "request");
    let submitted = recovered.submit(probe.clone()).expect("probe submits");

    let err = oracle::reference_verdict(&promises.ops, &probe, submitted.ts, true)
        .expect_err("a mixed install must be refused rather than compared");
    assert!(
        matches!(
            err,
            Unavailable::MixedInstall {
                retention: Retention::Mixed,
                ..
            }
        ),
        "expected a mixed-install refusal, got {err:?}"
    );
    // And the message must send the reader to the test, not to the server.
    let text = err.to_string();
    assert!(
        text.starts_with("HARNESS:"),
        "the refusal must be labelled as a harness limit: {text}"
    );
    assert!(
        text.contains("not a fault in the server"),
        "the refusal must say so explicitly: {text}"
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_probe_whose_verdict_ignores_history_is_refused() {
    // A probe that decides the same way with or without the recorded history
    // proves nothing when the two sides agree. Guarding this is what stops the
    // check from silently becoming decorative.
    let (frozen, promises) = crash_after("blind_probe", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("submit");
    });

    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    // A `Read` request is permitted regardless of what came before — no rule
    // forbids it — so its verdict carries no information about the history.
    let probe = ev("Read", "request");
    let submitted = recovered.submit(probe.clone()).expect("probe submits");

    let with = oracle::reference_verdict(&promises.ops, &probe, submitted.ts, true).expect("with");
    let without =
        oracle::reference_verdict(&promises.ops, &probe, submitted.ts, false).expect("without");
    assert_eq!(
        with, without,
        "this probe is supposed to be history-independent"
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
#[should_panic(expected = "HARNESS: the recovered log holds a record at offset")]
fn a_record_the_harness_never_learned_about_is_a_harness_limit() {
    // Simulates the window the oracle's quiescence precondition is about: a commit
    // that became durable before its caller was told, so the log holds an event
    // `Promises` has never heard of. Fault injection will produce this for real;
    // here it is produced by appending a record behind the recorder's back.
    //
    // Without the check, the reference is fed less history than the server has, and
    // the mismatch is reported as `MISMATCH (recovery)` — sending a reader after a
    // recovery bug that does not exist.
    let (frozen, promises) = crash_after("non_quiescent", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("submit");
    });

    // The unacknowledged record: durable, dense, decodable, and unknown to anyone.
    {
        let log = DurableLog::open(&frozen).expect("read frozen");
        let ts = promises.ops.last().expect("ops").ts() + 1_000_000_000;
        let event = ev("Read", "response").timestamp(ts).build();
        log.append(&Record::Event(event).encode())
            .expect("append behind the recorder's back");
    }

    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );
}

#[test]
fn a_refused_snapshot_over_an_intact_log_degrades_to_full_replay() {
    // `recover`'s `base == 0` arm: a snapshot the engine REFUSES to load — a
    // serialization/mode change across a binary upgrade, or corruption — while
    // NOTHING has been pruned. Because the complete log survives from offset 0,
    // recovery must discard the snapshot, replay the whole log, and decide exactly
    // as a store that never had a snapshot would.
    //
    // This state cannot be produced by `checkpoint`: a checkpoint snapshots and
    // prunes below the snapshot in the same operation, so a present snapshot
    // normally implies `base > 0` (which is why a refused snapshot then fails
    // closed instead). The `base == 0` degrade is reachable only when a snapshot
    // became durable but the log was never pruned — an interrupted or failed
    // first prune. We reproduce that directly: write a refused snapshot over the
    // intact log via the raw `DurableLog`, leaving `base == 0`.
    //
    // The history must be reconstructible only by that full replay: a `Read`
    // within the window makes the `Export` probe history-dependent, so a recovery
    // that lost the history would wrongly permit it.
    let (frozen, promises) = crash_after("refused_snapshot", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("the Read");
        // Deliberately no checkpoint: every record stays and `base` stays 0.
    });

    // Inject a snapshot the engine will refuse, WITHOUT pruning. The envelope is
    // well-formed (it names a real bundle) so `SnapshotPayload::decode` succeeds
    // and `recover` reaches `rebuild`; the engine payload is garbage, so
    // `load_snapshot` returns false — the refusal the degrade path handles.
    {
        let log = DurableLog::open(&frozen).expect("reopen frozen log");
        let up_to = log.next_offset();
        let refused = SnapshotPayload {
            bundle: bundle(WATCHING_READ),
            last_ts: promises.ops.last().expect("at least one op").ts(),
            engine: b"snapshot from an incompatible build".to_vec(),
        }
        .encode()
        .expect("encode refused snapshot");
        log.commit(&[Write::Snapshot(&Snapshot {
            up_to_offset: up_to,
            payload: refused,
        })])
        .expect("write a snapshot without pruning");
    }

    // Precondition: the trap is set exactly as intended — a snapshot IS present,
    // yet the log was never pruned (`base == 0`). Without this the test could pass
    // by testing the wrong arm.
    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    assert!(
        facts.snapshot_up_to.is_some() && facts.base_offset == 0,
        "needs a present snapshot over an unpruned log (base==0): {facts:?}"
    );

    // Recovery must SUCCEED (degrade to replay), not fail closed...
    let mut recovered =
        DurableTemporalEngine::open(&frozen, 0).expect("degrades to full replay, does not refuse");
    // ...and the full replay must reconstruct the history, so the recovered store
    // decides the Export exactly as the reference interpreter does.
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_refused_snapshot_over_a_pruned_log_fails_closed() {
    // `recover`'s `base > 0` arm, the counterpart to the degrade test: the log has
    // been pruned, so the pre-`base` history survives ONLY in the snapshot — but
    // the snapshot is refused (serialization/mode change across an upgrade, or
    // corruption). A replay of the surviving tail cannot reconstruct the pruned
    // history, so opening the store would serve a silent hole (a history-gated
    // `forbid` with missing history just passes). Recovery must FAIL CLOSED.
    //
    // Unlike the `base == 0` case, this state is reachable through a real
    // checkpoint: `checkpoint` snapshots and prunes below the watermark, leaving
    // `base > 0` with a snapshot covering the gap. We take a real checkpoint to
    // establish exactly that, then overwrite the (valid) snapshot with a refused
    // one at the SAME watermark — the log stays pruned, and the store still looks
    // structurally recoverable, so the refusal is an engine-level rejection of the
    // payload rather than a missing or short snapshot.
    let (frozen, _promises) = crash_after("refused_pruned", |rec| {
        rec.install(WATCHING_READ, ACTION_SCHEMA).expect("applies");
        rec.submit(ev("Read", "response")).expect("the Read");
        // Snapshots the Read and prunes its record away: `base` advances past it,
        // and the only surviving trace of the Read is inside the snapshot.
        rec.checkpoint()
            .expect("checkpoint prunes the Read into the snapshot");
    });

    // Overwrite the valid snapshot with a refused one at the same watermark,
    // without un-pruning: the pruned history now survives only in an unloadable
    // snapshot.
    let base = {
        let log = DurableLog::open(&frozen).expect("reopen frozen log");
        let base = log.base_offset();
        assert!(base > 0, "the checkpoint must have pruned; base={base}");
        let refused = SnapshotPayload {
            bundle: bundle(WATCHING_READ),
            last_ts: 0,
            engine: b"snapshot from an incompatible build".to_vec(),
        }
        .encode()
        .expect("encode refused snapshot");
        log.commit(&[Write::Snapshot(&Snapshot {
            up_to_offset: base,
            payload: refused,
        })])
        .expect("overwrite the snapshot with a refused one");
        base
    };

    // Precondition: the log is pruned AND a snapshot structurally covers the gap —
    // i.e. the store passes the structural recoverability check. The refusal must
    // therefore come from the engine rejecting the payload, not from the structure.
    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    assert!(
        facts.base_offset == base && facts.snapshot_up_to.is_some_and(|u| u >= facts.base_offset),
        "needs a pruned log with a snapshot covering base: {facts:?}"
    );

    // Recovery must refuse rather than open a store with a silent history hole.
    let err = DurableTemporalEngine::open(&frozen, 0)
        .err()
        .expect("recovery must fail closed, not open an unrecoverable store");
    assert!(
        err.to_string().contains("refused by the engine"),
        "must fail closed for the right reason (a refused snapshot): {err}"
    );
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_negated_leaf_survives_a_snapshot() {
    // save_state/load_state's `Node::Not` arm: a `!(formerly …)` leaf is
    // checkpointed (snapshotting a Not node) and must still decide correctly
    // after recover. With a Login in history the negation is false, the forbid
    // does not fire, and the Export is permitted; without the Login it denies —
    // so the probe is history-dependent.
    let (frozen, promises) = crash_after("negated_snapshot", |rec| {
        rec.install(FORBID_UNLESS_LOGIN, ACTION_SCHEMA)
            .expect("applies");
        rec.submit(ev("Login", "response")).expect("the Login");
        rec.checkpoint()
            .expect("checkpoint snapshots the Not leaf's state");
    });

    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_previous_leaf_survives_a_snapshot() {
    // save_state/load_state's `Node::Previous` arm: a `previous …` leaf's
    // "did the child hold at the last timepoint" state is folded into the
    // snapshot when the Read is checkpointed away, and recovery must restore it
    // so the immediately-following Export still sees the Read as its previous.
    let (frozen, promises) = crash_after("previous_snapshot", |rec| {
        rec.install(FORBID_AFTER_PREVIOUS_READ, ACTION_SCHEMA)
            .expect("applies");
        rec.submit(ev("Read", "response")).expect("the Read");
        rec.checkpoint()
            .expect("checkpoint snapshots the Previous leaf's state");
    });

    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );
    drop(recovered);
    let _ = std::fs::remove_file(&frozen);
}
