//! The `(policy id, clause index)` transplant soundness claims
//! — the properties that distinguish the
//! new retention model from the content-keyed one it replaces. Each test is
//! written to **fail under content-only keying**, so it pins the actual benefit
//! of scoping retention to the policy id rather than the clause text:
//!
//! - **No cross-policy sharing.** Two policies with byte-identical temporal
//!   clauses have independent windows; resetting one does not touch the other.
//! - **Delete + re-add starts fresh.** A policy removed and re-added with
//!   identical content gets a new id and an empty window — its old history does
//!   not resurrect.
//! - **Position-shift survival.** A policy keeps its window when another policy
//!   ahead of it is deleted and its own source position (`policy_N`) shifts —
//!   because retention keys on the stable id, not the position.
//!
//! Everything is asserted behaviourally, through decisions a carried-vs-reset
//! window flips.
//!
//! It also covers two batch-level guarantees that share the same harness: that
//! `DeleteAll` is **terminal and fail-closed** and that a **rejected
//! batch mutates nothing** — no durable record, and no live window cleared even
//! by a `Reset` that preceded the failing verb.

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{
    DurableTemporalEngine, Outcome, PolicyId, PolicyToken, Submitted, Verb,
};

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Delete appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Login appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

const PERMIT_ALL: &str = r#"permit (principal, action in [Action::"Read", Action::"Export", Action::"Delete", Action::"Login"], resource);"#;

/// Forbid `Export` of a doc formerly `Read`. Its temporal leaf is
/// `formerly … Read::request{ doc }`.
const FORBID_EXPORT_ON_READ: &str = r#"forbid (principal, action == Action::"Export", resource) when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } };"#;

/// Forbid `Delete` of a doc formerly `Read`. Its temporal leaf is the **same
/// clause text** as [`FORBID_EXPORT_ON_READ`] — only the forbidden action (the
/// Cedar scope, not the temporal condition) differs. Under content-only keying
/// these two leaves collide; under `(id, index)` they do not.
const FORBID_DELETE_ON_READ: &str = r#"forbid (principal, action == Action::"Delete", resource) when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } };"#;

/// Forbid `Delete` of a doc formerly `Login`ed — a *different* clause, used for
/// the position-shift test.
const FORBID_DELETE_ON_LOGIN: &str = r#"forbid (principal, action == Action::"Delete", resource) when temporal { formerly within 1h Action::"Login"::request{ input.doc: context.input.doc } };"#;

/// One policy with **two** temporal clauses (a conjunction): forbid `Delete`
/// only when the doc was *both* formerly `Read` and formerly `Login`ed. Its two
/// leaves get within-policy ordinals 0 and 1 — the `m` component of the
/// composite key that no single-clause policy exercises.
const FORBID_DELETE_ON_READ_AND_LOGIN: &str = r#"forbid (principal, action == Action::"Delete", resource) when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } } when temporal { formerly within 1h Action::"Login"::request{ input.doc: context.input.doc } };"#;

fn ev(action: &str, doc: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), "request")
        .principal("User::\"alice\"")
        .resource("Doc::\"d\"")
        .field("input", "doc", Value::String(doc.to_string()))
        .request_context("input", "doc", Value::String(doc.to_string()))
}

fn decide(engine: &mut DurableTemporalEngine, action: &str, doc: &str) -> bool {
    match engine.submit(ev(action, doc)).expect("submit") {
        Submitted {
            outcome: Outcome::Decision(r),
            ..
        } => r.allowed(),
        other => panic!("expected a decision, got {other:?}"),
    }
}

fn store(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_retention_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn open(tag: &str) -> (DurableTemporalEngine, std::path::PathBuf) {
    let dir = store(tag);
    let engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    (engine, dir)
}

/// The opaque handle of the policy at internal ordinal `ordinal` — how a test
/// names a policy now that the handle is opaque (ordinals stay observable via
/// `list()` for ordering assertions).
fn tok(engine: &DurableTemporalEngine, ordinal: u64) -> PolicyToken {
    engine
        .list()
        .into_iter()
        .find(|e| e.id == PolicyId(ordinal))
        .unwrap_or_else(|| panic!("no policy at ordinal {ordinal}"))
        .token
}

/// **No cross-policy sharing**: two policies whose temporal clauses are
/// byte-identical still have independent windows. Resetting one must not clear
/// the other.
///
/// Content-only keying would file both leaves' state under the same key, so a
/// `Reset` of one — dropping that key — would strand the other too; this test
/// denies that.
#[test]
fn identical_clauses_in_different_policies_do_not_share_a_window() {
    let (mut engine, dir) = open("no_share");
    // ids: 0 permit, 1 forbid-Export-on-Read, 2 forbid-Delete-on-Read.
    // The two forbids carry the *same* `formerly Read{doc}` leaf.
    engine
        .install(
            &format!("{PERMIT_ALL}\n\n{FORBID_EXPORT_ON_READ}\n\n{FORBID_DELETE_ON_READ}"),
            ACTION_SCHEMA,
            None,
            None,
        )
        .expect("installs");

    // Arm both leaves with one Read of "t".
    assert!(decide(&mut engine, "Read", "t"));
    assert!(
        !decide(&mut engine, "Export", "t"),
        "export denied by policy 1"
    );
    assert!(
        !decide(&mut engine, "Delete", "t"),
        "delete denied by policy 2"
    );

    // Reset only policy 1 (the Export forbid).
    let h1 = tok(&engine, 1);
    engine.batch(vec![Verb::Reset { id: h1 }]).expect("reset");

    // Policy 1's window is cleared; policy 2's — the identical clause in a
    // different policy — is untouched.
    assert!(
        decide(&mut engine, "Export", "t"),
        "policy 1 was reset, so export is now allowed"
    );
    assert!(
        !decide(&mut engine, "Delete", "t"),
        "policy 2 shares policy 1's clause text but NOT its window — it must \
         still deny (content-only keying would wrongly clear it too)"
    );

    let _ = std::fs::remove_file(&dir);
}

/// **Delete + re-add starts fresh**: removing a policy and adding
/// one with identical content mints a new id and an empty window — the old
/// history does not resurrect.
///
/// Content-only keying would match the re-added identical clause to the removed
/// policy's stored state and carry it; this test denies that.
#[test]
fn delete_then_readd_identical_content_starts_fresh() {
    let (mut engine, dir) = open("readd");
    // ids: 0 permit, 1 forbid-Export-on-Read.
    engine
        .install(
            &format!("{PERMIT_ALL}\n\n{FORBID_EXPORT_ON_READ}"),
            ACTION_SCHEMA,
            None,
            None,
        )
        .expect("installs");

    assert!(decide(&mut engine, "Read", "t"));
    assert!(!decide(&mut engine, "Export", "t"), "baseline denies");

    // Delete the forbid and re-add byte-identical content in one batch: the new
    // policy gets a fresh ordinal (2), not id 1's window.
    let h1 = tok(&engine, 1);
    let result = engine
        .batch(vec![
            Verb::Delete { id: h1 },
            Verb::Add {
                policy: FORBID_EXPORT_ON_READ.to_string(),
            },
        ])
        .expect("delete + re-add");
    assert_eq!(result.minted.len(), 1);
    assert_eq!(
        engine.get_policy(&result.minted[0]).unwrap().id,
        PolicyId(2),
        "re-added at a new ordinal"
    );

    assert!(
        decide(&mut engine, "Export", "t"),
        "the re-added policy is born fresh — the earlier Read must not carry to \
         a new id, even though the clause text is identical"
    );

    let _ = std::fs::remove_file(&dir);
}

/// **Position-shift survival**: a policy keeps its window when another
/// policy *ahead of it in the source* is deleted, shifting its own `policy_N`
/// source position — because retention keys on the stable id, not the position.
///
/// This is the soundness crux of the id↔position mapping. Keying by raw source
/// position (`policy_N`) would misroute the shifted policy's window on the
/// rebuild and lose it; this test denies that.
#[test]
fn a_policy_keeps_its_window_when_an_earlier_policy_is_deleted() {
    let (mut engine, dir) = open("shift");
    // ids: 0 permit, 1 forbid-Export-on-Read, 2 forbid-Delete-on-Login.
    engine
        .install(
            &format!("{PERMIT_ALL}\n\n{FORBID_EXPORT_ON_READ}\n\n{FORBID_DELETE_ON_LOGIN}"),
            ACTION_SCHEMA,
            None,
            None,
        )
        .expect("installs");

    // Arm policy 2 (the Login-gated Delete forbid).
    assert!(decide(&mut engine, "Login", "t"));
    assert!(
        !decide(&mut engine, "Delete", "t"),
        "baseline: a formerly-logged-in doc is denied delete"
    );

    // Delete policy 1. Policy 2's source position shifts (it was the 3rd policy,
    // now the 2nd), so its leaf's `policy_N` id changes — but its stable id (2)
    // does not, so its window must carry across the rebuild.
    let h1 = tok(&engine, 1);
    engine
        .batch(vec![Verb::Delete { id: h1 }])
        .expect("delete the earlier policy");

    assert!(
        !decide(&mut engine, "Delete", "t"),
        "policy 2 kept its window despite its source position shifting when \
         policy 1 was deleted — retention keys on the stable id, not position"
    );
    // Sanity: the window is still discriminating (a never-logged-in doc is fine).
    assert!(
        decide(&mut engine, "Delete", "never"),
        "a doc never logged in is still allowed (the forbid is not vacuous)"
    );

    let _ = std::fs::remove_file(&dir);
}

/// **Multi-clause-per-policy retention by clause ordinal**: a policy with
/// two temporal clauses keeps *both* windows across a rebuild, matched by the
/// within-policy ordinal `m` in the composite key. A bug that keyed both leaves
/// identically (ignoring `m`) or dropped one would surface here and nowhere else
/// — every other policy in the suite has a single temporal clause.
#[test]
fn a_policy_with_two_clauses_keeps_both_windows_across_a_rebuild() {
    let (mut engine, dir) = open("two_clause");
    // ids: 0 permit, 1 the two-clause Delete forbid.
    engine
        .install(
            &format!("{PERMIT_ALL}\n\n{FORBID_DELETE_ON_READ_AND_LOGIN}"),
            ACTION_SCHEMA,
            None,
            None,
        )
        .expect("installs");

    // Arm BOTH clauses for doc "t": a past Read and a past Login.
    assert!(decide(&mut engine, "Read", "t"));
    assert!(decide(&mut engine, "Login", "t"));
    assert!(
        !decide(&mut engine, "Delete", "t"),
        "both clauses hold for t (past Read AND past Login), so delete is denied"
    );
    // A doc that satisfied only ONE clause is allowed — the conjunction needs
    // both, so the two ordinals are genuinely distinct, not merged.
    assert!(decide(&mut engine, "Read", "u"));
    assert!(
        decide(&mut engine, "Delete", "u"),
        "u was read but never logged in, so the two-clause forbid does not fire"
    );

    // Force a rebuild+transplant that leaves the two-clause policy *unnamed*
    // (retained): add an unrelated policy that forbids Export (never submitted
    // here, so it cannot itself affect a Delete verdict). Both of the retained
    // policy's leaves must carry.
    engine
        .batch(vec![Verb::Add {
            policy: FORBID_EXPORT_ON_READ.to_string(),
        }])
        .expect("add an unrelated policy");

    assert!(
        !decide(&mut engine, "Delete", "t"),
        "both clause windows (ordinals 0 and 1) must survive the rebuild — a \
         dropped or mis-keyed ordinal would let delete through"
    );
    // And the one-clause-only doc is still allowed (no cross-contamination
    // between the two ordinals introduced by the transplant).
    assert!(
        decide(&mut engine, "Delete", "u"),
        "u still satisfies only the Read clause, so it stays allowed"
    );

    let _ = std::fs::remove_file(&dir);
}

/// **`DeleteAll` is terminal and fail-closed**: it leaves an *empty set
/// installed* — not the never-configured `NoPolicy` state — so `submit` still
/// runs and denies, rather than erroring.
#[test]
fn delete_all_leaves_an_empty_set_that_denies() {
    let (mut engine, dir) = open("delete_all");
    engine
        .install(PERMIT_ALL, ACTION_SCHEMA, None, None)
        .expect("installs");
    assert!(
        decide(&mut engine, "Read", "t"),
        "permitted before DeleteAll"
    );

    engine.batch(vec![Verb::DeleteAll]).expect("delete all");

    // The store is still configured — `submit` succeeds and returns a decision,
    // and with no policies the decision is deny (default-deny). It must NOT be a
    // NoPolicy error.
    match engine.submit(ev("Read", "t")) {
        Ok(Submitted {
            outcome: Outcome::Decision(r),
            ..
        }) => assert!(
            !r.allowed(),
            "an empty installed set fails closed — every decision denies"
        ),
        other => panic!("DeleteAll must leave a deciding (empty) set, got {other:?}"),
    }

    let _ = std::fs::remove_file(&dir);
}

/// **An `Add` slices a multi-policy source into independently-addressable
/// entries**: each policy gets its own id and its own `(id, index)`-keyed
/// window, so a later `Reset` of one clears exactly that one.
///
/// This is the corrected form of a bug that used to lurk here: a multi-policy
/// `Add` once collapsed into a *single* entry holding several Cedar policies,
/// whose leaves fell to a content-only key so a later `Reset` of it silently
/// failed to clear the window. Slicing makes every stored entry exactly one
/// policy, restoring the `(id, index)` guarantee.
#[test]
fn a_sliced_add_yields_independently_resettable_entries() {
    let (mut engine, dir) = open("sliced_add");
    engine
        .install(PERMIT_ALL, ACTION_SCHEMA, None, None)
        .expect("installs"); // id 0

    // One Add carrying a permit AND the Export-on-Read forbid — sliced into two
    // entries (ids 1 and 2), the forbid being the second.
    let r = engine
        .batch(vec![Verb::Add {
            policy: format!("{PERMIT_ALL}\n\n{FORBID_EXPORT_ON_READ}"),
        }])
        .expect("add");
    assert_eq!(
        r.minted.len(),
        2,
        "the multi-policy Add sliced into two entries"
    );
    let forbid_id = r.minted[1].clone();

    assert!(decide(&mut engine, "Read", "t"));
    assert!(!decide(&mut engine, "Export", "t"), "armed");

    // Reset just the sliced forbid entry — its window must clear.
    engine
        .batch(vec![Verb::Reset { id: forbid_id }])
        .expect("reset");
    assert!(
        decide(&mut engine, "Export", "t"),
        "Reset of the sliced forbid entry must clear its window (it is its own \
         (id, index)-keyed entry now, not a content-fallback blob)"
    );

    let _ = std::fs::remove_file(&dir);
}

/// **`ResetAll` clears every window while keeping every policy**.
#[test]
fn reset_all_clears_every_window() {
    let (mut engine, dir) = open("reset_all");
    // ids: 0 permit, 1 forbid-Export-on-Read, 2 forbid-Delete-on-Read.
    engine
        .install(
            &format!("{PERMIT_ALL}\n\n{FORBID_EXPORT_ON_READ}\n\n{FORBID_DELETE_ON_READ}"),
            ACTION_SCHEMA,
            None,
            None,
        )
        .expect("installs");
    assert!(decide(&mut engine, "Read", "t"));
    assert!(
        !decide(&mut engine, "Export", "t"),
        "export denied before reset"
    );
    assert!(
        !decide(&mut engine, "Delete", "t"),
        "delete denied before reset"
    );

    engine.batch(vec![Verb::ResetAll]).expect("reset all");

    // Every window cleared — both forbids now allow — but the policies remain.
    assert!(
        decide(&mut engine, "Export", "t"),
        "ResetAll cleared policy 1"
    );
    assert!(
        decide(&mut engine, "Delete", "t"),
        "ResetAll cleared policy 2"
    );
    assert_eq!(
        engine.list().iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![PolicyId(0), PolicyId(1), PolicyId(2)],
        "ResetAll keeps every policy at its id"
    );

    let _ = std::fs::remove_file(&dir);
}

/// **Checkpoint → incremental batch (retain one, reset another) → restart**:
/// recovery loads the snapshot's folded bundle and state, then
/// folds the post-snapshot verb records forward — carrying the unnamed policy's
/// window across the *snapshot boundary* and starting the updated one fresh.
///
/// This composes the two recovery sources the other tests exercise separately:
/// `replay_control_records.rs` replays incremental records but never checkpoints
/// (so `base` stays 0), and `recovery_oracle.rs` checkpoints but only over a
/// whole-set apply. Here a real `checkpoint()` (pruned log) precedes an
/// incremental `Update`, and both must land correctly after a restart.
#[test]
fn checkpoint_then_incremental_batch_then_restart() {
    let dir = store("checkpoint_batch");
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        // ids: 0 permit, 1 export-forbid, 2 delete-forbid (both gated on Read).
        engine
            .install(
                &format!("{PERMIT_ALL}\n\n{FORBID_EXPORT_ON_READ}\n\n{FORBID_DELETE_ON_READ}"),
                ACTION_SCHEMA,
                None,
                None,
            )
            .expect("installs");
        assert!(decide(&mut engine, "Read", "t")); // arms both windows
        assert!(!decide(&mut engine, "Export", "t"));
        assert!(!decide(&mut engine, "Delete", "t"));

        // Snapshot the armed state and prune the log below it.
        engine.checkpoint().expect("checkpoint");

        // A post-snapshot incremental batch: Update policy 1 (resets it) and
        // leave policy 2 untouched (retained).
        let h1 = tok(&engine, 1);
        engine
            .batch(vec![Verb::Update {
                id: h1,
                policy: FORBID_EXPORT_ON_READ.to_string(),
            }])
            .expect("update");
    }

    // Recover: snapshot (both armed) + replayed Update (resets policy 1).
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
    assert!(
        decide(&mut engine, "Export", "t"),
        "policy 1 was Updated after the checkpoint — reset, so export is allowed"
    );
    assert!(
        !decide(&mut engine, "Delete", "t"),
        "policy 2 was untouched — its window must carry across the snapshot \
         boundary and the incremental replay"
    );

    let _ = std::fs::remove_file(&dir);
}

/// **`DeleteAll`'s empty-but-installed set survives a restart still denying**:
/// recovery must reproduce a deciding (deny) empty set, not the
/// never-configured `NoPolicy` error state.
#[test]
fn delete_all_survives_a_restart_still_denying() {
    let dir = store("delete_all_restart");
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(PERMIT_ALL, ACTION_SCHEMA, None, None)
            .expect("installs");
        assert!(decide(&mut engine, "Read", "t"));
        engine.batch(vec![Verb::DeleteAll]).expect("delete all");
    }

    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
    match engine.submit(ev("Read", "t")) {
        Ok(Submitted {
            outcome: Outcome::Decision(r),
            ..
        }) => assert!(
            !r.allowed(),
            "a recovered empty set must still decide (deny), not error"
        ),
        other => panic!("expected a deny decision after recovery, got {other:?}"),
    }

    let _ = std::fs::remove_file(&dir);
}

/// **A rejected batch mutates nothing**: it writes zero durable records,
/// and a `Reset` earlier in the same batch does not clear any live window —
/// because a batch is applied by building a candidate and swapping only on full
/// success, never by mutating live state in place.
#[test]
fn a_rejected_batch_writes_nothing_and_clears_no_window() {
    let (mut engine, dir) = open("reject_atomic");
    engine
        .install(
            &format!("{PERMIT_ALL}\n\n{FORBID_EXPORT_ON_READ}"),
            ACTION_SCHEMA,
            None,
            None,
        )
        .expect("installs");
    assert!(decide(&mut engine, "Read", "t"));
    assert!(!decide(&mut engine, "Export", "t"), "baseline denies");

    let offset_before = engine.log_offset();

    // A batch that resets policy 1 and then fails on an unparseable Add. The
    // whole batch must reject.
    let h1 = tok(&engine, 1);
    let err = engine.batch(vec![
        Verb::Reset { id: h1 },
        Verb::Add {
            policy: "this will not parse {{{".to_string(),
        },
    ]);
    assert!(err.is_err(), "the batch must reject");

    // Zero durable records: the log did not advance.
    assert_eq!(
        engine.log_offset(),
        offset_before,
        "a rejected batch must write no records"
    );
    // And the live window was not cleared by the Reset that preceded the failure
    // — the Read history still counts, so Export is still denied.
    assert!(
        !decide(&mut engine, "Export", "t"),
        "a Reset in a rejected batch must not have cleared the live window"
    );

    let _ = std::fs::remove_file(&dir);
}
