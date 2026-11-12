//! What [`Durability::Periodic`] keeps and what it gives up across a crash.
//!
//! A crash is modelled by copying the store file while the engine is still
//! open. redb's `Durability::None` commit writes nothing to storage, so the copy
//! holds exactly what a killed process (or a power cut) would leave behind: the
//! state of the last `Immediate` commit. Dropping the engine instead would run
//! the clean-close path, which flushes, and so model a restart, not a crash.
//!
//! Unix-only. Copying a store that is still open fails on Windows, where redb
//! holds its file with exclusive access (ERROR_LOCK_VIOLATION, OS error 33).
//! The mode itself is platform-independent; only this crash model is not, and
//! `periodic_durability_reopen.rs` covers what a clean close can show on every
//! platform. The whole file compiles to nothing on Windows so its helpers do
//! not warn as unused there.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{
    Clock, Durability, DurableConfig, DurableLog, DurableTemporalEngine, Outcome, Record,
};

/// A clock the test moves by hand, so the interval bound is exact rather than
/// a race against the scheduler.
#[derive(Clone)]
struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    fn new(start_nanos: i64) -> Self {
        ManualClock(Arc::new(AtomicI64::new(start_nanos)))
    }
    fn advance(&self, by: Duration) {
        let by = i64::try_from(by.as_nanos()).expect("fits");
        self.0.fetch_add(by, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_nanos(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

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

/// `Export` is denied once a `Read` response is in history: the shape of a "no
/// push until tested" rule, where forgetting the history event fails open.
const POLICY: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

/// A second set, distinguishable from `POLICY` by its source.
const OTHER_POLICY: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Login"::response{} };
"#;

const LONG: Duration = Duration::from_secs(3600);

fn ev(action: &str, kind: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), kind)
        .principal("User::\"alice\"")
        .resource("Doc::\"d1\"")
        .field("input", "doc", Value::String("d1".to_string()))
        .request_context("input", "doc", Value::String("d1".to_string()))
}

fn path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_periodic_{tag}_{}", std::process::id()));
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

/// The crash: a byte copy of the store while the engine is still open.
fn crash_image(live: &Path, tag: &str) -> PathBuf {
    let frozen = path(tag);
    std::fs::copy(live, &frozen).expect("freeze");
    frozen
}

/// The offsets of the `Event` records in the store at `path`, after checking
/// the log is consistent: every offset from the prune watermark to the end is
/// present exactly once, and each record decodes.
fn recovered_events(path: &Path) -> Vec<u64> {
    let log = DurableLog::open(path).expect("frozen image opens");
    let mut offsets = Vec::new();
    let mut events = Vec::new();
    log.scan_from(0, |offset, bytes| {
        offsets.push(offset);
        if let Record::Event(_) = Record::decode(bytes).expect("record decodes") {
            events.push(offset);
        }
    })
    .expect("scans");
    let expected: Vec<u64> = (log.base_offset()..log.next_offset()).collect();
    assert_eq!(
        offsets, expected,
        "offsets are contiguous and end at next_offset"
    );
    events
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
fn flushed_periodic_events_all_recover_and_decide_like_a_never_closed_store() {
    let live = path("a_live");
    let reference_path = path("a_reference");
    let mut engine = opened(&live);
    engine
        .set_durability(Durability::Periodic {
            max_events: 1000,
            max_interval: LONG,
        })
        .expect("sets");
    let mut reference = opened(&reference_path);

    submit_history(&mut engine, 30, Some(17));
    submit_history(&mut reference, 30, Some(17));
    engine.flush().expect("flushes");
    let frozen = crash_image(&live, "a_frozen");
    drop(engine);

    assert_eq!(recovered_events(&frozen).len(), 30);
    let mut recovered = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    assert_eq!(
        export_allowed(&mut recovered),
        export_allowed(&mut reference)
    );
    assert!(!export_allowed(&mut recovered), "the Read gates Export");

    for p in [&live, &reference_path, &frozen] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn a_clean_close_flushes_periodic_events() {
    let live = path("b_live");
    let mut engine = opened(&live);
    engine
        .set_durability(Durability::Periodic {
            max_events: 1000,
            max_interval: LONG,
        })
        .expect("sets");
    submit_history(&mut engine, 30, None);
    assert_eq!(
        recovered_events(&crash_image(&live, "b_before_close")).len(),
        0,
        "nothing was fsynced before the close"
    );
    drop(engine);

    assert_eq!(recovered_events(&live).len(), 30);
    let _ = std::fs::remove_file(&live);
    let _ = std::fs::remove_file(path("b_before_close"));
}

/// Documents the loss the periodic mode accepts: after a crash, the events
/// since the last count-driven fsync are gone, and a verdict that rested on one
/// of them flips from Deny to Allow.
#[test]
fn a_crash_loses_the_events_after_the_last_periodic_fsync_and_fails_open() {
    let live = path("c_live");
    let mut engine = opened(&live);
    let first_event = engine.log_offset();
    engine
        .set_durability(Durability::Periodic {
            max_events: 10,
            max_interval: LONG,
        })
        .expect("sets");
    // Event 23 is the `Read` that gates `Export`.
    submit_history(&mut engine, 25, Some(23));
    assert!(!export_allowed(&mut engine), "live: the Read denies Export");
    let frozen = crash_image(&live, "c_frozen");
    drop(engine);

    let recovered = recovered_events(&frozen);
    let expected: Vec<u64> = (first_event..first_event + 20).collect();
    assert_eq!(
        recovered, expected,
        "exactly the two fsynced batches of 10 survive; events 21..=25 are lost"
    );
    let mut reopened = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    assert_eq!(reopened.log_offset(), first_event + 20);
    assert!(
        export_allowed(&mut reopened),
        "after the crash the lost Read no longer gates Export: fail-open"
    );

    let _ = std::fs::remove_file(&live);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_crash_loses_only_the_events_after_the_last_interval_driven_fsync() {
    let live = path("d_live");
    let clock = ManualClock::new(1_000_000_000_000);
    let mut engine = DurableTemporalEngine::open_with_config(
        &live,
        DurableConfig::new(0).with_clock(Box::new(clock.clone())),
    )
    .expect("opens");
    engine
        .install(POLICY, ACTION_SCHEMA, None, None)
        .expect("installs");
    let first_event = engine.log_offset();
    let interval = Duration::from_millis(200);
    engine
        .set_durability(Durability::Periodic {
            max_events: u32::MAX,
            max_interval: interval,
        })
        .expect("sets");

    // Past the install's stamp, so the first event is stamped at the clock
    // rather than clamped a nanosecond above it.
    clock.advance(Duration::from_millis(1));
    // Three events while the clock stands still; the monotonic clamp spaces
    // the second and third a nanosecond apart.
    submit_history(&mut engine, 3, None);
    clock.advance(interval);
    // The interval is measured at submit on the store's clock: this fourth
    // event is exactly `interval` after the first and triggers the fsync of
    // all four.
    submit_history(&mut engine, 1, None);
    // These two are within the new interval and stay unsynced.
    submit_history(&mut engine, 2, None);
    let frozen = crash_image(&live, "d_frozen");
    drop(engine);

    let expected: Vec<u64> = (first_event..first_event + 4).collect();
    assert_eq!(recovered_events(&frozen), expected);

    let _ = std::fs::remove_file(&live);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_policy_install_survives_a_crash_in_periodic_mode() {
    let live = path("e_live");
    let mut engine = opened(&live);
    engine
        .set_durability(Durability::Periodic {
            max_events: 1000,
            max_interval: LONG,
        })
        .expect("sets");
    submit_history(&mut engine, 3, None);
    engine
        .install(OTHER_POLICY, ACTION_SCHEMA, None, None)
        .expect("reinstalls");
    let after_install = engine.log_offset();
    // Unsynced again: these two are lost, the install is not.
    submit_history(&mut engine, 2, None);
    let frozen = crash_image(&live, "e_frozen");
    drop(engine);

    // The install's `Immediate` commit also persisted the three events before it.
    assert_eq!(recovered_events(&frozen).len(), 3);
    let reopened = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    assert_eq!(reopened.log_offset(), after_install);
    let source = reopened.policy_source().expect("a policy is installed");
    assert!(
        source.contains("Action::\"Login\"::response"),
        "the second install is in force after recovery: {source}"
    );

    let _ = std::fs::remove_file(&live);
    let _ = std::fs::remove_file(&frozen);
}

/// The promise is "every batch", so the empty one must keep it too: it has no
/// commit of its own to carry the pending events and flushes instead.
#[test]
fn an_empty_batch_makes_deferred_events_durable() {
    let live = path("g_live");
    let mut engine = opened(&live);
    engine
        .set_durability(Durability::Periodic {
            max_events: 1000,
            max_interval: LONG,
        })
        .expect("sets");
    submit_history(&mut engine, 5, None);
    assert_eq!(recovered_events(&crash_image(&live, "g_before")).len(), 0);

    let result = engine.batch(Vec::new()).expect("empty batch succeeds");
    assert!(result.minted.is_empty());
    let frozen = crash_image(&live, "g_frozen");
    drop(engine);

    assert_eq!(recovered_events(&frozen).len(), 5);

    for p in [&live, &frozen, &path("g_before")] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn switching_back_to_every_event_flushes_and_fsyncs_what_follows() {
    let live = path("f_live");
    let mut engine = opened(&live);
    engine
        .set_durability(Durability::Periodic {
            max_events: 1000,
            max_interval: LONG,
        })
        .expect("sets");
    submit_history(&mut engine, 5, None);
    let before_switch = crash_image(&live, "f_before_switch");
    assert_eq!(recovered_events(&before_switch).len(), 0);

    engine
        .set_durability(Durability::EveryEvent)
        .expect("switches and flushes");
    let at_switch = crash_image(&live, "f_at_switch");
    assert_eq!(recovered_events(&at_switch).len(), 5, "the switch flushed");

    submit_history(&mut engine, 3, None);
    let after = crash_image(&live, "f_after");
    assert_eq!(
        recovered_events(&after).len(),
        8,
        "each later event is fsynced"
    );
    drop(engine);

    for p in [&live, &before_switch, &at_switch, &after] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn a_checkpoint_makes_deferred_events_durable() {
    let live = path("checkpoint_live");
    let mut engine = opened(&live);
    engine
        .set_durability(Durability::Periodic {
            max_events: 1000,
            max_interval: LONG,
        })
        .expect("sets");
    submit_history(&mut engine, 4, Some(2));
    let up_to = engine.checkpoint().expect("checkpoints");
    let frozen = crash_image(&live, "checkpoint_frozen");
    drop(engine);

    let mut reopened = DurableTemporalEngine::open(&frozen, 0).expect("recovers");
    assert_eq!(reopened.log_offset(), up_to);
    assert!(
        !export_allowed(&mut reopened),
        "the snapshotted Read still gates"
    );

    let _ = std::fs::remove_file(&live);
    let _ = std::fs::remove_file(&frozen);
}
