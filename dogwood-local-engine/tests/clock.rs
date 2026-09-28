//! The injected [`Clock`] and the monotonic clamp it feeds.
//!
//! `DurableTemporalEngine` assigns each record its timestamp from a [`Clock`].
//! In production that is the system clock; here a
//! [`ManualClock`] lets a test set the instant exactly — and, crucially, step it
//! *backwards*, which `submit_contract`'s
//! `the_clock_survives_a_checkpoint_that_empties_the_log` notes it cannot do:
//! "there is no seam to inject one". This is that seam.
//!
//! The property under test is that the clamp `max(now, last + 1)` keeps the
//! assigned sequence strictly increasing regardless of what the clock does —
//! monitor windows are measured against it and its `partition_point` front-prune
//! assumes ascending order, so a single backwards step would corrupt state.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use dogwood_language::{Event, EventBuilder, UNPINNED_EVENT_SCHEMA, Value};
use dogwood_local_engine::{
    Clock, DurableConfig, DurableError, DurableLog, DurableTemporalEngine, Record, Snapshot,
    SnapshotPayload, Verb, Write,
};

/// A clock a test drives by hand. Cloneable and internally shared, so the test
/// keeps one handle to move the clock while the engine holds another.
#[derive(Clone)]
struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    fn new(start_nanos: i64) -> Self {
        ManualClock(Arc::new(AtomicI64::new(start_nanos)))
    }
    /// Move the clock to `nanos` — forwards or backwards.
    fn set(&self, nanos: i64) {
        self.0.store(nanos, Ordering::SeqCst);
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
"#;

/// A permit-only policy: no temporal clause, so `response` events are plain
/// history and every submit is accepted and stamped.
const POLICY: &str = r#"permit (principal, action == Action::"Read", resource);"#;

const TEMPORAL_POLICY: &str = r#"
permit (principal, action == Action::"Read", resource);

forbid (principal, action == Action::"Read", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

fn ev() -> EventBuilder {
    Event::builder("Action::Read", "response")
}

fn global_ev() -> EventBuilder {
    Event::builder("Action::Read", "response")
        .principal("User::\"alice\"")
        .resource("Doc::\"d1\"")
        .field("input", "doc", Value::String("d1".to_string()))
        .request_context("input", "doc", Value::String("d1".to_string()))
}

fn store(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_clock_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Open an engine over a fresh store, driven by `clock`, with a policy installed.
fn opened(tag: &str, clock: ManualClock) -> (DurableTemporalEngine, std::path::PathBuf) {
    let dir = store(tag);
    let mut engine = DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(clock)),
    )
    .expect("opens");
    engine
        .install(POLICY, ACTION_SCHEMA, None, None)
        .expect("applies");
    (engine, dir)
}

/// When the clock is ahead of the last-assigned timestamp, the assigned value is
/// exactly what the clock reports — the engine stamps from the injected source.
#[test]
fn the_injected_clock_supplies_the_timestamp() {
    let start = 1_800_000_000_000_000_000; // an arbitrary epoch-nanos instant
    let clock = ManualClock::new(start);
    let (mut engine, dir) = opened("supplies", clock.clone());

    // The apply already consumed `start` (records share the clock), so advance
    // the clock past it and submit: the event takes the clock's value.
    let ahead = start + 5_000_000_000;
    clock.set(ahead);
    let ts = engine.submit(ev()).expect("submit").ts;
    assert_eq!(
        ts, ahead,
        "with the clock ahead of the last stamp, the assigned ts is the clock's value"
    );
    let _ = std::fs::remove_file(&dir);
}

/// The property `submit_contract` could not reach: stepping the clock **backwards**
/// still yields a strictly-increasing timestamp, because the clamp falls back to
/// `last + 1`.
#[test]
fn a_backwards_clock_step_still_increases_the_timestamp() {
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let (mut engine, dir) = opened("backwards", clock.clone());

    let ahead = start + 5_000_000_000;
    clock.set(ahead);
    let first = engine.submit(ev()).expect("submit").ts;
    assert_eq!(first, ahead);

    // Wind the clock back well before the last assigned stamp.
    clock.set(ahead - 3_000_000_000);
    let second = engine.submit(ev()).expect("submit").ts;

    assert!(
        second > first,
        "a backwards clock step must not produce a non-increasing timestamp: \
         {first} then {second}"
    );
    assert_eq!(
        second,
        first + 1,
        "with the clock behind, the clamp assigns exactly last + 1"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn excessive_live_clock_skew_rejects_without_appending_and_recovers_when_time_catches_up() {
    const SIX_MINUTES: i64 = 6 * 60 * 1_000_000_000;
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let (mut engine, dir) = opened("live_skew", clock.clone());
    let offset_before = engine.log_offset();

    clock.set(start - SIX_MINUTES);
    let error = engine
        .submit(ev())
        .expect_err("a live clock more than five minutes behind must reject");
    assert!(
        matches!(
            error,
            DurableError::Rejected(ref message)
                if message.contains("exceeding the maximum allowed future skew")
        ),
        "unexpected live clock-skew error: {error}"
    );
    assert_eq!(
        engine.log_offset(),
        offset_before,
        "clock-skew rejection must append no event"
    );

    clock.set(start);
    let submitted = engine
        .submit(ev())
        .expect("writes resume once the clock is within tolerance");
    assert_eq!(
        submitted.ts,
        start + 1,
        "the rejected write must not consume a timestamp"
    );
    let _ = std::fs::remove_file(&dir);
}

/// A frozen clock (never advancing) still orders events: each takes `last + 1`.
#[test]
fn a_frozen_clock_still_orders_events() {
    let frozen_at = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(frozen_at);
    let (mut engine, dir) = opened("frozen", clock.clone());

    // The apply took `frozen_at`; the clock never moves, so each event clamps to
    // one past the previous.
    let mut previous = None;
    for _ in 0..4 {
        let ts = engine.submit(ev()).expect("submit").ts;
        if let Some(p) = previous {
            assert_eq!(
                ts,
                p + 1,
                "a frozen clock advances the sequence by last + 1"
            );
        }
        previous = Some(ts);
    }
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn timestamp_exhaustion_rejects_without_appending() {
    let clock = ManualClock::new(i64::MAX);
    let (mut engine, dir) = opened("exhausted", clock);
    let offset_before = engine.log_offset();

    let error = engine
        .submit(ev())
        .expect_err("the timestamp after i64::MAX is unrepresentable");
    assert!(
        matches!(
            error,
            DurableError::Rejected(ref message)
                if message.contains("timestamp space is exhausted")
        ),
        "unexpected timestamp-exhaustion error: {error}"
    );
    assert_eq!(
        engine.log_offset(),
        offset_before,
        "timestamp exhaustion must reject before appending"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn full_log_recovery_rejects_a_descending_event_timestamp() {
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let (mut engine, dir) = opened("descending_full_log", clock);
    let latest = engine.submit(ev()).expect("records valid event").ts;
    drop(engine);

    let log = DurableLog::open(&dir).expect("opens log");
    log.append(&Record::Event(ev().timestamp(latest - 1).build()).encode())
        .expect("appends malformed descending event");
    drop(log);

    let error = match DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(latest))),
    ) {
        Ok(_) => panic!("recovery accepted a descending event timestamp"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            DurableError::Log(ref message)
                if message.contains("timestamps are not in durable order")
        ),
        "unexpected descending-replay error: {error}"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn snapshot_tail_recovery_rejects_a_nonincreasing_timestamp() {
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let (mut engine, dir) = opened("descending_snapshot_tail", clock);
    let latest = engine.submit(ev()).expect("records valid event").ts;
    engine.checkpoint().expect("checkpoints valid event");
    drop(engine);

    let log = DurableLog::open(&dir).expect("opens log");
    log.append(&Record::Event(ev().timestamp(latest).build()).encode())
        .expect("appends malformed tied event");
    drop(log);

    let error = match DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(latest))),
    ) {
        Ok(_) => panic!("recovery accepted a tail timestamp at the snapshot high-water mark"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            DurableError::Log(ref message)
                if message.contains("timestamps are not in durable order")
        ),
        "unexpected snapshot-tail replay error: {error}"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn snapshot_tail_accepts_equal_control_timestamps_after_the_floor_advances() {
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let (mut engine, dir) = opened("equal_control_tail", clock);
    let latest = engine.submit(ev()).expect("records valid event").ts;
    engine.checkpoint().expect("checkpoints valid event");
    drop(engine);

    let control_ts = latest.checked_add(1).expect("fixture timestamp has room");
    let log = DurableLog::open(&dir).expect("opens log");
    log.append(&Record::ResetAll { ts: control_ts }.encode())
        .expect("appends first tied control");
    log.append(&Record::ResetAll { ts: control_ts }.encode())
        .expect("appends second tied control");
    drop(log);

    let mut recovered = DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(control_ts))),
    )
    .expect("accepts a strictly newer first control followed by a tied control");
    assert!(
        recovered.submit(ev()).expect("submits after recovery").ts > control_ts,
        "accepted controls must advance the recovered high-water mark"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn full_log_recovery_rejects_every_tie_involving_an_event() {
    for (tag, event_first, event_second) in [
        ("event_event", true, true),
        ("event_control", true, false),
        ("control_event", false, true),
    ] {
        let start = 1_800_000_000_000_000_000;
        let clock = ManualClock::new(start);
        let (mut engine, dir) = opened(tag, clock);
        let latest = engine.submit(ev()).expect("records valid event").ts;
        drop(engine);

        let tied_ts = latest.checked_add(1).expect("fixture timestamp has room");
        let record = |is_event| {
            if is_event {
                Record::Event(ev().timestamp(tied_ts).build())
            } else {
                Record::ResetAll { ts: tied_ts }
            }
        };
        let log = DurableLog::open(&dir).expect("opens log");
        log.append(&record(event_first).encode())
            .expect("appends first tied record");
        log.append(&record(event_second).encode())
            .expect("appends second tied record");
        drop(log);

        let error = match DurableTemporalEngine::open_with_config(
            &dir,
            DurableConfig::new(0).with_clock(Box::new(ManualClock::new(tied_ts))),
        ) {
            Ok(_) => panic!("recovery accepted the {tag} timestamp tie"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                DurableError::Log(ref message)
                    if message.contains("timestamps are not in durable order")
            ),
            "unexpected {tag} replay error: {error}"
        );
        let _ = std::fs::remove_file(&dir);
    }
}

#[test]
fn pruned_global_snapshot_rejects_an_outer_clock_behind_monitor_state() {
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let dir = store("global_snapshot_clock_pruned");
    let latest = {
        let mut engine = DurableTemporalEngine::open_with_config(
            &dir,
            DurableConfig::new(0).with_clock(Box::new(clock.clone())),
        )
        .expect("opens");
        engine
            .install(
                TEMPORAL_POLICY,
                ACTION_SCHEMA,
                Some(UNPINNED_EVENT_SCHEMA),
                None,
            )
            .expect("installs global temporal policy");
        clock.set(start + 1);
        let latest = engine
            .submit(global_ev())
            .expect("records global monitor history")
            .ts;
        engine.checkpoint().expect("checkpoints global state");
        latest
    };

    {
        let log = DurableLog::open(&dir).expect("opens log");
        assert!(log.base_offset() > 0, "checkpoint must prune the log");
        let snapshot = log
            .get_snapshot()
            .expect("reads snapshot")
            .expect("snapshot exists");
        let mut payload = SnapshotPayload::decode(&snapshot.payload).expect("decodes snapshot");
        assert_eq!(payload.last_ts, latest);
        payload.last_ts = latest - 1;
        log.commit(&[Write::Snapshot(&Snapshot {
            up_to_offset: snapshot.up_to_offset,
            payload: payload.encode().expect("encodes inconsistent snapshot"),
        })])
        .expect("stores inconsistent snapshot");
    }

    let error = match DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(latest))),
    ) {
        Ok(_) => panic!("recovery accepted an outer clock below global monitor state"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            DurableError::Log(ref message)
                if message.contains("older than restored engine state")
        ),
        "unexpected inconsistent-snapshot error: {error}"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn inconsistent_global_snapshot_degrades_to_an_unpruned_full_log() {
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let source = store("global_snapshot_clock_source");
    let frozen = store("global_snapshot_clock_full_log");
    let latest = {
        let mut engine = DurableTemporalEngine::open_with_config(
            &source,
            DurableConfig::new(0).with_clock(Box::new(clock.clone())),
        )
        .expect("opens");
        engine
            .install(
                TEMPORAL_POLICY,
                ACTION_SCHEMA,
                Some(UNPINNED_EVENT_SCHEMA),
                None,
            )
            .expect("installs global temporal policy");
        clock.set(start + 1);
        engine
            .submit(global_ev())
            .expect("records global monitor history")
            .ts
    };
    std::fs::copy(&source, &frozen).expect("freezes the unpruned full log");

    let snapshot = {
        let mut engine = DurableTemporalEngine::open_with_config(
            &source,
            DurableConfig::new(0).with_clock(Box::new(ManualClock::new(latest))),
        )
        .expect("recovers snapshot source");
        engine.checkpoint().expect("creates a valid snapshot");
        drop(engine);
        DurableLog::open(&source)
            .expect("opens source log")
            .get_snapshot()
            .expect("reads snapshot")
            .expect("snapshot exists")
    };
    {
        let log = DurableLog::open(&frozen).expect("opens frozen log");
        assert_eq!(log.base_offset(), 0, "the fallback needs the full log");
        let mut payload = SnapshotPayload::decode(&snapshot.payload).expect("decodes snapshot");
        payload.last_ts = latest - 1;
        log.commit(&[Write::Snapshot(&Snapshot {
            up_to_offset: snapshot.up_to_offset,
            payload: payload.encode().expect("encodes inconsistent snapshot"),
        })])
        .expect("injects inconsistent snapshot without pruning");
    }

    let mut recovered = DurableTemporalEngine::open_with_config(
        &frozen,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(latest))),
    )
    .expect("an inconsistent snapshot with a full log must degrade to replay");
    assert!(
        recovered
            .submit(global_ev())
            .expect("submits after replay")
            .ts
            > latest,
        "full replay must restore the durable high-water mark"
    );
    drop(recovered);
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn global_snapshot_accepts_an_outer_clock_newer_than_monitor_state() {
    let start = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(start);
    let dir = store("global_snapshot_newer_outer_clock");
    let history_ts = {
        let mut engine = DurableTemporalEngine::open_with_config(
            &dir,
            DurableConfig::new(0).with_clock(Box::new(clock.clone())),
        )
        .expect("opens");
        engine
            .install(
                TEMPORAL_POLICY,
                ACTION_SCHEMA,
                Some(UNPINNED_EVENT_SCHEMA),
                None,
            )
            .expect("installs global temporal policy");
        clock.set(start + 1);
        let history_ts = engine
            .submit(global_ev())
            .expect("records global monitor history")
            .ts;
        clock.set(start + 2);
        engine
            .batch(vec![Verb::Add {
                policy: POLICY.to_string(),
            }])
            .expect("records a later policy change");
        engine.checkpoint().expect("checkpoints global state");
        history_ts
    };

    {
        let log = DurableLog::open(&dir).expect("opens log");
        let snapshot = log
            .get_snapshot()
            .expect("reads snapshot")
            .expect("snapshot exists");
        let payload = SnapshotPayload::decode(&snapshot.payload).expect("decodes snapshot");
        assert!(
            payload.last_ts > history_ts,
            "the policy record must advance the outer clock beyond monitor history"
        );
    }

    DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(start + 2))),
    )
    .unwrap_or_else(|error| {
        panic!("a newer outer clock with valid global monitor state must recover: {error}")
    });
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn a_comments_only_add_writes_nothing_and_consumes_no_timestamp() {
    let frozen_at = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(frozen_at);
    let (mut engine, dir) = opened("comments_only_add", clock);
    let offset_before = engine.log_offset();
    let policies_before = engine.list();

    let error = engine
        .batch(vec![
            Verb::Add {
                policy: POLICY.into(),
            },
            Verb::Add {
                policy: "// intentionally contains no policy\n".into(),
            },
        ])
        .expect_err("a comments-only Add must reject");

    match error {
        DurableError::Rejected(message) => {
            assert_eq!(message, "rejected: source contains no policy");
        }
        other => panic!("expected a policy rejection, got {other}"),
    }
    assert_eq!(
        engine.log_offset(),
        offset_before,
        "the rejected Add must append no durable record"
    );
    assert_eq!(
        engine.list(),
        policies_before,
        "the rejected Add must leave the running set unchanged"
    );

    let next = engine.submit(ev()).expect("submit after rejection");
    assert_eq!(
        next.ts,
        frozen_at + 1,
        "the rejected Add must not consume the next timestamp"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn a_rejected_comments_only_add_leaves_nothing_for_recovery() {
    let frozen_at = 1_800_000_000_000_000_000;
    let clock = ManualClock::new(frozen_at);
    let (mut engine, dir) = opened("comments_only_add_recovery", clock);
    let offset_before = engine.log_offset();
    let policies_before = engine.list();

    engine
        .batch(vec![
            Verb::Add {
                policy: POLICY.into(),
            },
            Verb::Add {
                policy: "// intentionally contains no policy\n".into(),
            },
        ])
        .expect_err("a comments-only Add must reject");
    drop(engine);

    let mut recovered = DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(frozen_at))),
    )
    .expect("reopens after rejection");
    assert_eq!(
        recovered.log_offset(),
        offset_before,
        "recovery must find no record from the rejected batch"
    );
    assert_eq!(
        recovered.list(),
        policies_before,
        "recovery must restore the pre-batch policy set"
    );

    let next = recovered.submit(ev()).expect("submit after recovery");
    assert_eq!(
        next.ts,
        frozen_at + 1,
        "recovery must not observe a timestamp from the rejected batch"
    );
    let _ = std::fs::remove_file(&dir);
}

/// The clamp holds across a restart: a store recovered under a clock that reads
/// *earlier* than the store's last assigned timestamp must not reissue or go
/// backwards — the durable `last_ts` (carried in the snapshot) still wins.
#[test]
fn the_clamp_holds_across_a_restart_under_an_earlier_clock() {
    let start = 1_800_000_000_000_000_000;
    let dir = store("restart");

    let last_before = {
        let clock = ManualClock::new(start + 5_000_000_000);
        let mut engine = DurableTemporalEngine::open_with_config(
            &dir,
            DurableConfig::new(0).with_clock(Box::new(clock)),
        )
        .expect("opens");
        engine
            .install(POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
        engine.submit(ev()).expect("submit").ts
    };

    // Reopen under a clock that reads well before the last stamp.
    let clock = ManualClock::new(start);
    let mut engine = DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(clock)),
    )
    .expect("recovers");
    let after = engine.submit(ev()).expect("submit").ts;
    assert!(
        after > last_before,
        "recovery under an earlier clock must not rewind the sequence: \
         {last_before} then {after}"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn recovery_accepts_the_default_five_minute_future_skew_boundary() {
    const FIVE_MINUTES: i64 = 5 * 60 * 1_000_000_000;
    let now = 1_800_000_000_000_000_000;
    let dir = store("future_boundary");

    {
        let mut engine = DurableTemporalEngine::open_with_config(
            &dir,
            DurableConfig::new(0).with_clock(Box::new(ManualClock::new(now + FIVE_MINUTES))),
        )
        .expect("opens");
        engine
            .install(POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
    }

    DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(now))),
    )
    .unwrap_or_else(|error| panic!("the exact five-minute boundary must recover: {error}"));
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn log_recovery_rejects_more_than_five_minutes_of_future_skew() {
    const TOO_FAR_AHEAD: i64 = 5 * 60 * 1_000_000_000 + 1;
    let now = 1_800_000_000_000_000_000;
    let dir = store("future_log_rejected");

    {
        let mut engine = DurableTemporalEngine::open_with_config(
            &dir,
            DurableConfig::new(0).with_clock(Box::new(ManualClock::new(now + TOO_FAR_AHEAD))),
        )
        .expect("opens");
        engine
            .install(POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
    }

    let error = match DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(now))),
    ) {
        Ok(_) => panic!("recovery accepted a timestamp beyond the default future-skew limit"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            DurableError::Rejected(ref message)
                if message.contains("exceeding the maximum allowed future skew")
        ),
        "unexpected recovery error: {error}"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn snapshot_recovery_rejects_more_than_five_minutes_of_future_skew() {
    const SIX_MINUTES: i64 = 6 * 60 * 1_000_000_000;
    let now = 1_800_000_000_000_000_000;
    let dir = store("future_snapshot_rejected");

    {
        let mut engine = DurableTemporalEngine::open_with_config(
            &dir,
            DurableConfig::new(0).with_clock(Box::new(ManualClock::new(now + SIX_MINUTES))),
        )
        .expect("opens");
        engine
            .install(POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
        let cut = engine.checkpoint().expect("checkpoint");
        assert!(cut > 0, "checkpoint must cover the policy records");
    }

    let error = match DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0).with_clock(Box::new(ManualClock::new(now))),
    ) {
        Ok(_) => panic!("snapshot recovery accepted a timestamp beyond the skew limit"),
        Err(error) => error,
    };
    assert!(
        matches!(error, DurableError::Rejected(_)),
        "unexpected recovery error: {error}"
    );

    DurableTemporalEngine::open_with_config(
        &dir,
        DurableConfig::new(0)
            .with_clock(Box::new(ManualClock::new(now)))
            .with_max_future_skew(Duration::from_secs(10 * 60)),
    )
    .unwrap_or_else(|error| panic!("configured future-skew override must recover: {error}"));
    let _ = std::fs::remove_file(&dir);
}
