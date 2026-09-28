//! Recovery replays **per-verb policy-change records**, not just events.
//!
//! A durable verb record is re-applied at its own position in the order,
//! through the same composite `(id, clause ordinal)` transplant a live batch
//! uses. These tests hand-write the
//! records — that is the point of testing the path before anything depends on
//! it — and cover the three retention outcomes that matter:
//!
//! - **Update** — the same id, new content, "update means reset", so
//!   the old window does not carry even for an unchanged clause.
//! - **Reset** — the same id, unchanged content, cleared history: the case a
//!   content diff cannot express, unlocked by the composite-key retention.
//! - **Add** — a new policy is born fresh at a new id, while a policy not
//!   named by any verb keeps its accumulated window.
//!
//! Each verb targets a **single** policy by id. `install`'s multi-statement
//! source is split into one entry per top-level policy, so an `Update`
//! record's `statement` must be exactly *one* canonical policy.

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{
    DurableLog, DurableTemporalEngine, Outcome, PolicyId, PolicyToken, Record, Submitted,
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

/// A single-policy source: one permit that covers every action the tests use.
/// Installed at id 0.
const PERMIT: &str = r#"permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);"#;

/// A single-policy source: the temporal forbid gated on a past `Read`.
/// Installed at id 1.
const READ_FORBID: &str = r#"forbid (principal, action == Action::"Export", resource) when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } };"#;

/// A single-policy source: the temporal forbid gated on a past `Login` — the
/// same shape as [`READ_FORBID`] but a different clause.
const LOGIN_FORBID: &str = r#"forbid (principal, action == Action::"Export", resource) when temporal { formerly within 1h Action::"Login"::request{} };"#;

/// The initial two-policy `.dw` source: the permit + the `Read`-gated forbid.
fn initial_source() -> String {
    format!("{PERMIT}\n\n{READ_FORBID}")
}

fn ev(action: &str, doc: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), "request")
        .principal("User::\"alice\"")
        .resource("Doc::\"d\"")
        .field("input", "doc", Value::String(doc.to_string()))
        .request_context("input", "doc", Value::String(doc.to_string()))
}

/// Open a fresh store, install the initial (permit + Read-gated forbid) set,
/// record one `Read` under it, then close. Ids are minted 0 (permit) and 1
/// (the temporal forbid, so its monitor is the one carrying the `Read`).
fn store_with_recorded_read(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("dogwood_replay_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    let store = dir.join("store.redb");
    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("opens");
        state
            .install(&initial_source(), ACTION_SCHEMA, None, None)
            .expect("installs the initial set");
        state.submit(ev("Read", "target")).expect("submit");
    }
    store
}

fn next_record_timestamp(log: &DurableLog) -> i64 {
    let mut last = None;
    log.scan_from(log.base_offset(), |_offset, bytes| {
        last = Some(
            Record::decode(bytes)
                .expect("fixture record decodes")
                .timestamp(),
        );
    })
    .expect("scans fixture log");
    last.expect("fixture has installed records")
        .checked_add(1)
        .expect("fixture timestamp has room")
}

/// A replayed **Update** re-uses the same [`PolicyId`] but resets its history
/// ("update means reset"), even when the new statement's temporal clause
/// is textually identical to the old one.
///
/// Update targets id 1 (the temporal forbid) with the same forbid text.
/// Retention must still reset because Update means reset — the composite key's
/// content-guard tail matches, but `fresh` explicitly names id 1.
#[test]
fn replaying_an_update_resets_history_even_for_an_unchanged_clause() {
    let store = store_with_recorded_read("update");

    {
        let log = DurableLog::open(&store).expect("reopen log");
        let record = Record::Update {
            ts: next_record_timestamp(&log),
            id: PolicyId(1),
            statement: READ_FORBID.to_string(),
        };
        log.append(&record.encode()).expect("append the update");
    }

    let mut state = DurableTemporalEngine::open(&store, 0).expect("recovers");

    // The Read from before the Update was recorded, but Update reset id 1's
    // window; the Export must therefore be allowed.
    match state.submit(ev("Export", "target")).expect("submit") {
        Submitted {
            outcome: Outcome::Decision(r),
            ..
        } => assert!(
            r.allowed(),
            "Update means reset (§2.2): the pre-Update `Read` must not carry \
             even when the clause text is unchanged"
        ),
        other => panic!("expected a decision, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(store.parent().unwrap());
}

/// A replayed **Reset** clears one policy's history, content unchanged. This
/// is the case a content diff cannot express — under the composite `(id,
/// clause ordinal)` transplant, `fresh = {id}` is enough to drop it.
#[test]
fn replaying_a_reset_clears_the_history() {
    let store = store_with_recorded_read("reset");

    {
        let log = DurableLog::open(&store).expect("reopen log");
        let record = Record::Reset {
            ts: next_record_timestamp(&log),
            id: PolicyId(1),
        };
        log.append(&record.encode()).expect("append the reset");
    }

    let mut state = DurableTemporalEngine::open(&store, 0).expect("recovers");
    match state.submit(ev("Export", "target")).expect("submit") {
        Submitted {
            outcome: Outcome::Decision(r),
            ..
        } => assert!(
            r.allowed(),
            "Reset clears the window; the pre-Reset `Read` must not carry"
        ),
        other => panic!("expected a decision, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(store.parent().unwrap());
}

/// A replayed **Add** puts a new policy into the set at a *new* id, born fresh
/// (empty history), while the running policies' windows carry.
///
/// The set already holds ids 0 (permit) and 1 (Read-gated forbid), with one
/// `Read` in id 1's monitor. Adding a `Login`-gated forbid at id 2 must:
///
/// - install it fresh (no `Login` has ever been submitted, so its clause is
///   empty — but this is not what the test isolates);
/// - leave id 1's window intact: its Read-gated `Export` must still deny.
#[test]
fn replaying_an_add_installs_the_new_policy_fresh_and_keeps_the_others() {
    let store = store_with_recorded_read("add");

    {
        let log = DurableLog::open(&store).expect("reopen log");
        let record = Record::Add {
            ts: next_record_timestamp(&log),
            id: PolicyId(2),
            token: PolicyToken("SPreplayadd2".to_string()),
            statement: LOGIN_FORBID.to_string(),
        };
        log.append(&record.encode()).expect("append the add");
    }

    let mut state = DurableTemporalEngine::open(&store, 0).expect("recovers");
    let source = state
        .policy_source()
        .expect("a policy is installed")
        .to_string();
    assert!(
        source.contains(r#"formerly within 1h Action::"Login"::request"#),
        "the recorded Add must have installed the Login-watching policy; got:\n{source}"
    );

    // The old `Read`-gated Export still denies — id 1's window survived a
    // replayed change that did not name it.
    match state.submit(ev("Export", "target")).expect("submit") {
        Submitted {
            outcome: Outcome::Decision(r),
            ..
        } => assert!(
            !r.allowed(),
            "a policy not named by the replayed verb keeps its window (§2.2 default)"
        ),
        other => panic!("expected a decision, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(store.parent().unwrap());
}

/// A verb nullified by a later one in the log folds away on replay
/// ("a nullified verb is just ordinary history that folds away"). An `Add`
/// followed by a `DeleteAll` must leave the set empty after recovery — the Add
/// contributed nothing.
#[test]
fn a_nullified_verb_folds_away_on_replay() {
    let store = store_with_recorded_read("nullified");

    {
        let log = DurableLog::open(&store).expect("reopen log");
        let add_ts = next_record_timestamp(&log);
        // Add a policy, then wipe everything — the Add is erased before it ever
        // takes effect.
        log.append(
            &Record::Add {
                ts: add_ts,
                id: PolicyId(2),
                token: PolicyToken("SPreplaynull2".to_string()),
                statement: LOGIN_FORBID.to_string(),
            }
            .encode(),
        )
        .expect("append add");
        log.append(
            &Record::DeleteAll {
                ts: add_ts.checked_add(1).expect("fixture timestamp has room"),
            }
            .encode(),
        )
        .expect("append delete_all");
    }

    let engine = DurableTemporalEngine::open(&store, 0).expect("recovers");
    assert!(
        engine.list().is_empty(),
        "the Add was nullified by the following DeleteAll, so the recovered set \
         must be empty — got {:?}",
        engine.list().iter().map(|e| e.id).collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(store.parent().unwrap());
}

/// Add ordinals are minted from one monotone cursor and live tokens are unique.
/// A replay record violating either fact could only come from log corruption.
#[test]
fn invalid_add_identity_fails_recovery() {
    for tag in ["reused_id", "duplicate_token", "skipped_id"] {
        let store = store_with_recorded_read(tag);
        let state = DurableTemporalEngine::open(&store, 0).expect("recovers seed");
        let existing_token = state.list()[0].token.clone();
        drop(state);

        let (id, token) = match tag {
            "reused_id" => (
                PolicyId(1),
                PolicyToken("SPreplay-corrupt-reused".to_string()),
            ),
            "duplicate_token" => (PolicyId(2), existing_token),
            "skipped_id" => (
                PolicyId(3),
                PolicyToken("SPreplay-corrupt-skipped".to_string()),
            ),
            _ => unreachable!(),
        };
        let log = DurableLog::open(&store).expect("reopen log");
        let timestamp = next_record_timestamp(&log);
        log.append(
            &Record::Add {
                ts: timestamp,
                id,
                token,
                statement: LOGIN_FORBID.to_string(),
            }
            .encode(),
        )
        .expect("append invalid Add");
        drop(log);

        let err = match DurableTemporalEngine::open(&store, 0) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("recovery accepted invalid Add identity {tag}"),
        };
        assert!(
            err.contains("replay verb: add"),
            "unexpected error for {tag}: {err}"
        );
        let _ = std::fs::remove_dir_all(store.parent().unwrap());
    }
}

/// A record replay cannot interpret must fail loudly rather than be skipped:
/// silently ignoring one rebuilds state missing whatever it carried.
#[test]
fn an_undecodable_record_fails_recovery() {
    let dir = std::env::temp_dir().join(format!("dogwood_replay_bad_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    let store = dir.join("store.redb");
    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("opens");
        state
            .install(&initial_source(), ACTION_SCHEMA, None, None)
            .expect("installs");
    }
    {
        let log = DurableLog::open(&store).expect("reopen log");
        log.append(br#"{"ts":5,"mystery":{}}"#).expect("append");
    }
    let err = match DurableTemporalEngine::open(&store, 0) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("recovery must not silently skip a record it cannot read"),
    };
    assert!(err.contains("replay"), "unexpected error: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}
