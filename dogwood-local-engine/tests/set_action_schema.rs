//! The `SetActionSchema` verb.
//!
//! The action schema is the **mutable** half of the bundle: unlike the event
//! schema and macros (store config, immutable through the verbs — see
//! `shard_routing.rs` and the store-config slot), a `SetActionSchema` verb
//! revalidates and re-lowers the whole set in place. The contract is precise:
//!
//! - the action schema drives *validation* and a rule's scope / `target_actions`
//!   — **not** how a leaf's temporal condition lowers (that keys on the event
//!   schema + pins). So re-lowering under a new action schema produces the *same*
//!   leaves, and **all accumulated history carries** — no reset, no per-leaf
//!   guard;
//! - if the retained set no longer **lowers or validates** under the new schema
//!   (a referenced action removed, a comparison that no longer typechecks, a
//!   schema that will not even parse), the whole batch is **rejected** and the
//!   running set keeps serving;
//! - the **additive subset** — new entities / actions / groups — is always
//!   compatible, which is exactly the "grow the action surface lazily" workflow
//!   `[SetActionSchema(augmented); Add(policy about the new action)]`.
//!
//! These tests exercise that behaviourally — what validates, what decides, what
//! survives a restart — since the engine exposes no schema getter (a `GetSchema`
//! read verb is a later wire concern). Each is written to fail if
//! `SetActionSchema` were a no-op, reset history, or leaked a rejected change.
//!
//! **Deliberately out of scope:** the "it still typechecks" caveat — a
//! `context` field type change (e.g. `String → Long`) that keeps every predicate
//! valid, so re-lowering carries a window whose stored values then go *inert*
//! against the new type. This is no less sound than the reset it
//! replaces, and it is a property of the frontend interpreter's variant-strict
//! evaluation (`value.rs` `dom_eq`), not of this engine's verb handling. Testing
//! it belongs with the language, not here.

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{
    DurableTemporalEngine, Outcome, PolicyId, PolicyToken, Submitted, Verb,
};

// ─── Schemas ─────────────────────────────────────────────────────────
//
// Three action schemas over the same entities, differing only in which actions
// they declare — so a schema change is purely a change to the action surface,
// the thing that is safe to re-lower under.

/// Base: `Read` + `Export`. The temporal fixtures below reference both.
const SCHEMA_RE: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

/// Base **plus** `Login` — the additive superset (the "grow the surface" case).
const SCHEMA_REL: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Login appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

/// `Read` only — **drops `Export`**, which the fixtures reference, so re-lowering
/// the retained set under it must fail (the incompatible case).
const SCHEMA_R: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

// ─── Policies ────────────────────────────────────────────────────────

/// Permits the actions the fixtures decide on. `Login` is included so the same
/// permit works under `SCHEMA_REL`; under `SCHEMA_RE` the `Login` arm is unused
/// but still validates (the action set is only checked for known actions).
const PERMIT: &str =
    r#"permit (principal, action in [Action::"Read", Action::"Export"], resource);"#;

/// Forbids `Export` of a doc formerly `Read` — a history-gated rule correlated on
/// `doc`, so its *state* (not just structure) decides. This is the leaf whose
/// window must survive a `SetActionSchema`.
const FORBID_EXPORT_ON_READ: &str = r#"forbid (principal, action == Action::"Export", resource) when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } };"#;

/// A policy that references `Login`, so it only validates once the schema
/// declares that action — the probe for "did the surface widen?".
const LOGIN_POLICY: &str = r#"permit (principal, action == Action::"Login", resource);"#;

fn base() -> String {
    format!("{PERMIT}\n\n{FORBID_EXPORT_ON_READ}")
}

fn ev(action: &str, doc: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), "request")
        .principal("User::\"alice\"")
        .resource("Doc::\"d\"")
        .field("input", "doc", Value::String(doc.to_string()))
        .request_context("input", "doc", Value::String(doc.to_string()))
}

/// Submit a decision event and return whether it was allowed.
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
    p.push(format!(
        "dogwood_set_action_schema_{tag}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn open(tag: &str) -> (DurableTemporalEngine, std::path::PathBuf) {
    let dir = store(tag);
    let engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    (engine, dir)
}

/// The opaque handle of the policy at internal ordinal `ordinal`.
fn tok(engine: &DurableTemporalEngine, ordinal: u64) -> PolicyToken {
    engine
        .list()
        .into_iter()
        .find(|e| e.id == PolicyId(ordinal))
        .unwrap_or_else(|| panic!("no policy at ordinal {ordinal}"))
        .token
}

// ─── Acceptance & effect ─────────────────────────────────────────────

/// A `SetActionSchema` widens the validation surface: a policy that references a
/// newly-declared action validates only *after* the schema declares it.
#[test]
fn set_action_schema_widens_the_validation_surface() {
    let (mut engine, dir) = open("widen");
    engine
        .install(PERMIT, SCHEMA_RE, None, None)
        .expect("installs under the base schema");

    // Under the base schema (no `Login`), a policy about `Login` is rejected.
    let err = engine.batch(vec![Verb::Add {
        policy: LOGIN_POLICY.to_string(),
    }]);
    assert!(
        err.is_err(),
        "a Login policy must be rejected before the schema declares Login"
    );

    // Declare `Login`, then the same policy validates.
    engine
        .batch(vec![Verb::SetActionSchema {
            action_schema: SCHEMA_REL.to_string(),
        }])
        .expect("the additive schema change is accepted");
    let result = engine
        .batch(vec![Verb::Add {
            policy: LOGIN_POLICY.to_string(),
        }])
        .expect("the Login policy now validates");
    assert_eq!(result.minted.len(), 1, "the Login policy was added");

    let _ = std::fs::remove_file(&dir);
}

/// **The core property: a `SetActionSchema` alone keeps every window.**
///
/// A history-gated forbid is armed (a doc is read, then denied export). An
/// additive schema change must not reset it: the same doc is still denied
/// afterwards, while an *unread* doc is allowed — so the window carried and the
/// rule is still discriminating (not vacuously denying).
#[test]
fn set_action_schema_alone_keeps_all_history() {
    let (mut engine, dir) = open("keep");
    engine
        .install(&base(), SCHEMA_RE, None, None)
        .expect("installs");

    // Arm the window: read "target", then exporting "target" is denied.
    assert!(decide(&mut engine, "Read", "target"));
    assert!(
        !decide(&mut engine, "Export", "target"),
        "baseline: a formerly-read doc is denied export"
    );

    // An additive schema change (adds Login, touches no existing leaf).
    let applied = engine
        .batch(vec![Verb::SetActionSchema {
            action_schema: SCHEMA_REL.to_string(),
        }])
        .expect("additive schema change accepted");
    // The re-lower transplanted every window (nothing was marked fresh), so the
    // batch reports a nonzero retained count — the property the `install_policies`
    // benchmark's `reapply` keep-window path relies on.
    assert!(
        applied.leaves_retained > 0,
        "a SetActionSchema re-lower must retain its leaves, got {}",
        applied.leaves_retained
    );

    // The window survived: "target" is still denied. A reset would allow it.
    assert!(
        !decide(&mut engine, "Export", "target"),
        "SetActionSchema must not reset history: the earlier Read must still count"
    );
    // ...and the rule still discriminates — an unread doc is allowed.
    assert!(
        decide(&mut engine, "Export", "never-read"),
        "a doc never read must still be allowed (the forbid is not vacuous)"
    );

    let _ = std::fs::remove_file(&dir);
}

// ─── Rejection & atomicity ───────────────────────────────────────────

/// A schema change under which the retained set no longer validates — a
/// referenced action removed — is rejected, and the running set keeps serving.
#[test]
fn removing_a_referenced_action_is_rejected_and_leaves_the_set_serving() {
    let (mut engine, dir) = open("remove_action");
    engine
        .install(&base(), SCHEMA_RE, None, None)
        .expect("installs");
    assert!(decide(&mut engine, "Read", "target"));
    assert!(!decide(&mut engine, "Export", "target"), "baseline denies");
    let offset_before = engine.log_offset();

    // Drop `Export`, which both policies reference: the retained set will not
    // revalidate, so the whole batch is rejected. Unlike a parse-stage rejection,
    // this one folds cleanly and fails only at rebuild/validation — and it must
    // still write zero durable records.
    let err = engine.batch(vec![Verb::SetActionSchema {
        action_schema: SCHEMA_R.to_string(),
    }]);
    assert!(
        err.is_err(),
        "a schema dropping a referenced action must reject"
    );
    assert_eq!(
        engine.log_offset(),
        offset_before,
        "a validation-stage rejection must also write no records"
    );

    // The old schema still governs and the window is intact.
    assert_eq!(engine.list().len(), 2, "the rejected batch changed nothing");
    assert!(
        !decide(&mut engine, "Export", "target"),
        "the running set (old schema + its history) must still serve"
    );

    let _ = std::fs::remove_file(&dir);
}

/// A schema that does not even parse is rejected, and changes nothing.
#[test]
fn a_malformed_action_schema_is_rejected() {
    let (mut engine, dir) = open("malformed");
    engine
        .install(PERMIT, SCHEMA_RE, None, None)
        .expect("installs");

    let err = engine.batch(vec![Verb::SetActionSchema {
        action_schema: "this is not a cedar schema {{{".to_string(),
    }]);
    assert!(err.is_err(), "a malformed action schema must reject");
    assert_eq!(engine.list().len(), 1, "nothing changed");
    // The store still decides under the original schema.
    assert!(decide(&mut engine, "Read", "anything"));

    let _ = std::fs::remove_file(&dir);
}

/// A rejected `SetActionSchema` rejects the **whole** batch: a valid sibling
/// `Add` in the same batch does not take effect.
#[test]
fn a_rejected_set_action_schema_batch_is_atomic() {
    let (mut engine, dir) = open("atomic");
    engine
        .install(PERMIT, SCHEMA_RE, None, None)
        .expect("installs"); // one policy

    let err = engine.batch(vec![
        Verb::Add {
            policy: FORBID_EXPORT_ON_READ.to_string(),
        },
        Verb::SetActionSchema {
            action_schema: "garbage {{{".to_string(),
        },
    ]);
    assert!(err.is_err(), "the batch must reject as a unit");
    assert_eq!(
        engine.list().len(),
        1,
        "the sibling Add must not have taken effect"
    );

    let _ = std::fs::remove_file(&dir);
}

// ─── The "grow the surface" workflow ────────────────────────────────

/// `[SetActionSchema(augmented); Add(policy about the new action)]` in one batch
/// adds the action and the policy while keeping every existing window — the
/// canonical lazy-growth flow.
#[test]
fn grow_the_surface_in_one_batch_keeps_history() {
    let (mut engine, dir) = open("grow");
    engine
        .install(&base(), SCHEMA_RE, None, None)
        .expect("installs");
    assert!(decide(&mut engine, "Read", "target"));
    assert!(!decide(&mut engine, "Export", "target"), "baseline denies");

    let result = engine
        .batch(vec![
            Verb::SetActionSchema {
                action_schema: SCHEMA_REL.to_string(),
            },
            Verb::Add {
                policy: LOGIN_POLICY.to_string(),
            },
        ])
        .expect("the augmenting batch is accepted");
    assert_eq!(result.minted.len(), 1, "the new-action policy was added");
    assert_eq!(engine.list().len(), 3, "permit + forbid + login");

    // Growth left the existing forbid's window intact.
    assert!(
        !decide(&mut engine, "Export", "target"),
        "growing the action surface must not reset existing history"
    );

    let _ = std::fs::remove_file(&dir);
}

/// The **last** `SetActionSchema` in a batch wins (the fold is sequential).
#[test]
fn last_set_action_schema_in_a_batch_wins() {
    // Last is the augmented schema: the Login policy validates → accepted.
    let (mut engine, dir) = open("lastwins_ok");
    engine
        .install(PERMIT, SCHEMA_RE, None, None)
        .expect("installs");
    engine
        .batch(vec![
            Verb::SetActionSchema {
                action_schema: SCHEMA_RE.to_string(),
            },
            Verb::SetActionSchema {
                action_schema: SCHEMA_REL.to_string(),
            },
            Verb::Add {
                policy: LOGIN_POLICY.to_string(),
            },
        ])
        .expect("last schema (with Login) governs, so the Login policy validates");
    let _ = std::fs::remove_file(&dir);

    // Reversed: last is the base schema (no Login) → the Login policy rejects,
    // and rejects the whole batch.
    let (mut engine, dir) = open("lastwins_reject");
    engine
        .install(PERMIT, SCHEMA_RE, None, None)
        .expect("installs");
    let err = engine.batch(vec![
        Verb::SetActionSchema {
            action_schema: SCHEMA_REL.to_string(),
        },
        Verb::SetActionSchema {
            action_schema: SCHEMA_RE.to_string(),
        },
        Verb::Add {
            policy: LOGIN_POLICY.to_string(),
        },
    ]);
    assert!(
        err.is_err(),
        "the last schema (no Login) governs, so the Login policy must reject"
    );
    let _ = std::fs::remove_file(&dir);
}

// ─── Durability ──────────────────────────────────────────────────────

/// A `SetActionSchema` and the history it preserved both survive a restart: the
/// record replays at its position (the new action is available afterwards) and
/// the pre-change window still counts (it was carried across the replayed
/// change, not reset).
#[test]
fn set_action_schema_and_history_survive_a_restart() {
    let dir = store("restart");
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(&base(), SCHEMA_RE, None, None)
            .expect("installs");
        assert!(decide(&mut engine, "Read", "target"));
        assert!(!decide(&mut engine, "Export", "target"), "baseline denies");
        engine
            .batch(vec![Verb::SetActionSchema {
                action_schema: SCHEMA_REL.to_string(),
            }])
            .expect("additive schema change");
    }

    // Reopen: recovery replays the SetActionSchema record and carries the window.
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");

    // (a) The window carried across the replayed change.
    assert!(
        !decide(&mut engine, "Export", "target"),
        "the pre-change Read must still count after recovery"
    );
    // (b) The replayed schema is in force — a Login policy now validates, which
    //     it would not under the base schema the store first had.
    engine
        .batch(vec![Verb::Add {
            policy: LOGIN_POLICY.to_string(),
        }])
        .expect("the replayed SetActionSchema left Login available");

    let _ = std::fs::remove_file(&dir);
}

// ─── Append: the atomic "add to the schema" verb ─────────────────────

/// A fragment declaring the additional `Login` action — what an operator would
/// append to widen the surface.
const LOGIN_FRAGMENT: &str = r#"action Login appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };"#;

/// `AppendActionSchema` is the atomic alternative to fetch-then-`SetActionSchema`:
/// it concatenates a fragment onto the schema in force *server-side*, so no
/// concurrent change can slip in between reading the schema and setting it. It
/// widens the validation surface and, being additive, carries every window — and
/// both effects survive a restart (the append record replays).
#[test]
fn append_action_schema_widens_the_surface_atomically_and_carries_history() {
    let (mut engine, dir) = open("append_widen");
    engine
        .install(&base(), SCHEMA_RE, None, None)
        .expect("installs");

    // Arm a history-gated forbid: read "target", then exporting it is denied.
    assert!(decide(&mut engine, "Read", "target"));
    assert!(!decide(&mut engine, "Export", "target"), "baseline denies");

    // Before the append, a policy about `Login` is rejected — Login is undeclared.
    assert!(
        engine
            .batch(vec![Verb::Add {
                policy: LOGIN_POLICY.to_string(),
            }])
            .is_err(),
        "a Login policy must be rejected before the schema declares Login"
    );

    // One atomic batch: append the Login declaration AND add the policy about it.
    // Neither half is visible to a concurrent reader until both commit.
    engine
        .batch(vec![
            Verb::AppendActionSchema {
                fragment: LOGIN_FRAGMENT.to_string(),
            },
            Verb::Add {
                policy: LOGIN_POLICY.to_string(),
            },
        ])
        .expect("append + add applied atomically");

    // The surface widened: the Login policy is now installed ...
    assert_eq!(engine.list().len(), 3, "permit + forbid + login");
    // ... and the append carried every window (additive, no reset): the earlier
    // Read still denies the Export.
    assert!(
        !decide(&mut engine, "Export", "target"),
        "append is additive, so the pre-existing window must carry"
    );

    // Restart: the append record replays, so Login is still declared and the
    // carried history is still in force.
    drop(engine);
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
    assert!(
        !decide(&mut engine, "Export", "target"),
        "the carried window must survive the replayed append"
    );
    engine
        .batch(vec![Verb::Add {
            policy: LOGIN_POLICY.to_string(),
        }])
        .expect("the replayed append left Login declared");

    let _ = std::fs::remove_file(&dir);
}

/// A fragment that will not lower rejects the **whole** batch: neither the schema
/// change nor a sibling `Add` takes effect, and no record is written.
#[test]
fn a_rejected_append_leaves_the_set_and_schema_intact() {
    let (mut engine, dir) = open("append_reject");
    engine
        .install(PERMIT, SCHEMA_RE, None, None)
        .expect("installs"); // one policy, id 0
    let offset_before = engine.log_offset();

    let err = engine.batch(vec![
        Verb::AppendActionSchema {
            fragment: "action {{{ not a cedar declaration".to_string(),
        },
        Verb::Add {
            policy: FORBID_EXPORT_ON_READ.to_string(),
        },
    ]);
    assert!(err.is_err(), "a malformed append must reject the batch");
    assert_eq!(
        engine.log_offset(),
        offset_before,
        "a rejected append writes no records"
    );
    assert_eq!(
        engine.list().len(),
        1,
        "the sibling Add must not have taken effect"
    );
    // The original schema still governs.
    assert!(decide(&mut engine, "Read", "anything"));

    let _ = std::fs::remove_file(&dir);
}

// ─── Composition with resetting verbs ────────────────────────────────

/// In a batch that both changes the schema and `Update`s one policy, only the
/// updated policy resets; a policy the batch does not name keeps its window.
/// This isolates that `SetActionSchema` itself carries state (the reset comes
/// from the `Update`), even inside a mixed batch.
#[test]
fn set_action_schema_carries_while_a_sibling_update_resets() {
    // Two independent history-gated forbids, on different decision actions but
    // both armed by a past Read of the same doc.
    const PERMIT_RED: &str = r#"permit (principal, action in [Action::"Read", Action::"Export", Action::"Delete"], resource);"#;
    const FORBID_DELETE_ON_READ: &str = r#"forbid (principal, action == Action::"Delete", resource) when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } };"#;
    // A schema with all three actions.
    const SCHEMA_RED: &str = r#"
entity User;
entity Doc;
action Read appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };
action Export appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };
action Delete appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };
"#;

    let (mut engine, dir) = open("mixed");
    // ids: 0 permit, 1 forbid-export, 2 forbid-delete.
    engine
        .install(
            &format!("{PERMIT_RED}\n\n{FORBID_EXPORT_ON_READ}\n\n{FORBID_DELETE_ON_READ}"),
            SCHEMA_RED,
            None,
            None,
        )
        .expect("installs");

    // Arm both windows with a Read of "target".
    assert!(decide(&mut engine, "Read", "target"));
    assert!(!decide(&mut engine, "Export", "target"), "export denied");
    assert!(!decide(&mut engine, "Delete", "target"), "delete denied");

    // One batch: change the (additive-compatible) schema AND update the export
    // forbid (same text — an "update means reset"). The delete forbid is
    // untouched.
    let export_forbid = tok(&engine, 1);
    engine
        .batch(vec![
            Verb::SetActionSchema {
                action_schema: SCHEMA_RED.to_string(),
            },
            Verb::Update {
                id: export_forbid,
                policy: FORBID_EXPORT_ON_READ.to_string(),
            },
        ])
        .expect("mixed batch accepted");

    // The updated policy reset — its Read history is gone, so export is allowed.
    assert!(
        decide(&mut engine, "Export", "target"),
        "the Updated forbid reset, so the earlier Read no longer counts for it"
    );
    // The untouched policy kept its window — delete is still denied. This is the
    // point: the SetActionSchema in the same batch did not reset it.
    assert!(
        !decide(&mut engine, "Delete", "target"),
        "a policy the batch did not name keeps its window across a SetActionSchema"
    );

    let _ = std::fs::remove_file(&dir);
}
