//! [`Durability::Periodic`] across a clean close and reopen, on every platform.
//!
//! Each test drops the engine and opens the store again, so it needs no copy of
//! a store that is still open and runs where `periodic_durability.rs` cannot.
//! It checks the half of the mode a clean close can show: events appended
//! without an fsync are on disk once something flushes them. What a crash
//! loses is covered by `periodic_durability.rs`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{Durability, DurableTemporalEngine, Outcome};

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

/// `Export` is denied once a `Read` response is in history, so a `Read` that
/// did not reach disk shows up after the reopen as an allowed `Export`.
const POLICY: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

const PERIODIC: Durability = Durability::Periodic {
    max_events: 1000,
    max_interval: Duration::from_secs(3600),
};

fn ev(action: &str, kind: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), kind)
        .principal("User::\"alice\"")
        .resource("Doc::\"d1\"")
        .field("input", "doc", Value::String("d1".to_string()))
        .request_context("input", "doc", Value::String("d1".to_string()))
}

fn path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dogwood_periodic_reopen_{tag}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn opened(path: &Path) -> DurableTemporalEngine {
    let mut engine = DurableTemporalEngine::open(path, 0).expect("opens");
    engine
        .install(POLICY, ACTION_SCHEMA, None, None)
        .expect("installs");
    engine
}

fn export_allowed(engine: &mut DurableTemporalEngine) -> bool {
    match engine
        .submit(ev("Export", "request"))
        .expect("submits")
        .outcome
    {
        Outcome::Decision(r) => r.allowed(),
        Outcome::Recorded => panic!("Export request is a decision kind"),
    }
}

/// Submit `n` history events; the `read_at`-th (1-based), if any, is a `Read`
/// response and the rest are `Login` responses.
fn submit_history(engine: &mut DurableTemporalEngine, n: usize, read_at: Option<usize>) {
    for i in 1..=n {
        let action = if Some(i) == read_at { "Read" } else { "Login" };
        engine.submit(ev(action, "response")).expect("submits");
    }
}

#[test]
fn periodic_events_survive_a_clean_close_and_reopen() {
    let live = path("close");
    let mut engine = opened(&live);
    engine.set_durability(PERIODIC).expect("sets");
    // Neither bound is reached, so the close is what flushes these.
    submit_history(&mut engine, 30, Some(17));
    let end = engine.log_offset();
    drop(engine);

    let mut reopened = DurableTemporalEngine::open(&live, 0).expect("reopens");
    assert_eq!(reopened.log_offset(), end, "every event is in the log");
    assert!(
        !export_allowed(&mut reopened),
        "the Read still gates Export"
    );

    let _ = std::fs::remove_file(&live);
}

#[test]
fn flushed_periodic_events_reopen_to_the_verdicts_of_a_never_closed_store() {
    let live = path("flush");
    let reference_path = path("flush_reference");
    let mut engine = opened(&live);
    engine.set_durability(PERIODIC).expect("sets");
    let mut reference = opened(&reference_path);

    submit_history(&mut engine, 30, Some(17));
    submit_history(&mut reference, 30, Some(17));
    engine.flush().expect("flushes");
    let end = engine.log_offset();
    drop(engine);

    let mut reopened = DurableTemporalEngine::open(&live, 0).expect("reopens");
    assert_eq!(reopened.log_offset(), end);
    assert_eq!(
        export_allowed(&mut reopened),
        export_allowed(&mut reference)
    );

    drop(reference);
    for p in [&live, &reference_path] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn events_from_both_modes_survive_a_switch_and_a_reopen() {
    let live = path("switch");
    let mut engine = opened(&live);
    engine.set_durability(PERIODIC).expect("sets");
    submit_history(&mut engine, 5, Some(2));
    engine
        .set_durability(Durability::EveryEvent)
        .expect("switches and flushes");
    assert_eq!(engine.durability(), Durability::EveryEvent);
    submit_history(&mut engine, 3, None);
    let end = engine.log_offset();
    drop(engine);

    let mut reopened = DurableTemporalEngine::open(&live, 0).expect("reopens");
    assert_eq!(reopened.log_offset(), end);
    assert_eq!(
        reopened.durability(),
        Durability::EveryEvent,
        "the mode is not stored"
    );
    assert!(
        !export_allowed(&mut reopened),
        "the Read still gates Export"
    );

    let _ = std::fs::remove_file(&live);
}
