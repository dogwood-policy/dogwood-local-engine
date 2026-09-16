//! What [`DurableTemporalEngine::submit`] promises its caller.
//!
//! Every accepted submit is appended before it is evaluated, so acceptance and
//! position are the same event: a decision-bearing event has an offset exactly
//! as a history event does. [`Submitted`] carries the offset outside the
//! [`Outcome`], which makes that hold by construction — there is no way to
//! express an accepted event with no position.
//!
//! This drives the durable engine directly, with no server or socket: the
//! sequencer's contract is a property of the engine, so it is tested where it is
//! made. The engine takes an un-timestamped [`EventBuilder`] and assigns the
//! timestamp itself (`DESIGN.md` §3.3), so these tests build events with the
//! frontend builder and never name a timestamp.

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{DurableLog, DurableTemporalEngine, Outcome, Record};

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

/// One rule gated on a past `Read`, so `request` events are decision points and
/// `response` events are history.
const POLICY: &str = r#"
permit (principal, action == Action::"Read", resource);

forbid (principal, action == Action::"Read", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

/// An event of the given kind, as an un-timestamped builder — the durable engine
/// stamps it. Mirrors the wire event the server would map here: a single logged
/// `input.doc` field, no request scope.
fn ev(kind: &str) -> EventBuilder {
    Event::builder("Action::Read", kind).field("input", "doc", Value::String("d1".to_string()))
}

fn store(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dogwood_submit_contract_{tag}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn opened(tag: &str) -> (DurableTemporalEngine, std::path::PathBuf) {
    let dir = store(tag);
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    engine
        .install(POLICY, ACTION_SCHEMA, None, None)
        .expect("applies");
    (engine, dir)
}

#[test]
fn every_accepted_submit_reports_a_strictly_increasing_offset() {
    let (mut engine, dir) = opened("increasing");

    let mut offsets = Vec::new();
    for _ in 0..4 {
        offsets.push(engine.submit(ev("response")).expect("submit").offset);
    }

    assert!(
        offsets.windows(2).all(|w| w[1] > w[0]),
        "offsets must strictly increase: {offsets:?}"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn a_decision_event_reports_an_offset_too() {
    // The asymmetry this pins: the offset used to be attached only to the
    // history-event branch, as though it were a substitute for a verdict rather
    // than a receipt in its own right. A decision event is appended to the same
    // log, at a position that is precisely where its verdict was evaluated.
    let (mut engine, dir) = opened("decision");

    let history = engine.submit(ev("response")).expect("history");
    let decision = engine.submit(ev("request")).expect("decision");

    assert!(
        matches!(history.outcome, Outcome::Recorded),
        "a `response` event is history"
    );
    assert!(
        matches!(decision.outcome, Outcome::Decision(_)),
        "a `request` event is a decision point"
    );
    assert!(
        decision.offset > history.offset,
        "the decision was evaluated at {} which must follow the history at {}",
        decision.offset,
        history.offset
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn a_denied_decision_is_still_recorded_at_an_offset() {
    // Append precedes evaluation, so the verdict never decides whether the event
    // exists. A deny that vanished from history would silently change every
    // later window that should have counted it.
    let (mut engine, dir) = opened("denied");

    // The `response` makes the `forbid`'s clause hold, so the next request denies.
    let history = engine.submit(ev("response")).expect("history");
    let denied = engine.submit(ev("request")).expect("decision");

    match &denied.outcome {
        Outcome::Decision(r) => assert!(!r.allowed(), "the forbid must fire"),
        other => panic!("expected a decision, got {other:?}"),
    }
    assert_eq!(
        denied.offset,
        history.offset + 1,
        "a denied event occupies the next offset like any other"
    );
    assert_eq!(
        engine.log_offset(),
        denied.offset + 1,
        "the log advanced past it"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn offsets_continue_across_a_reopen() {
    // The offset a caller was given must keep meaning the same thing after
    // recovery, or an acknowledgement cannot be checked against a recovered
    // store.
    let dir = store("reopen");
    let last = {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
        engine.submit(ev("response")).expect("submit").offset
    };

    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
    let next = engine.submit(ev("response")).expect("submit").offset;
    assert!(
        next > last,
        "offsets must not restart or repeat across a reopen: {last} then {next}"
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn the_reported_timestamp_is_the_one_actually_stored() {
    // The whole value of returning it is that a caller can reason about when its
    // history ages out. That only holds if the number it is given is the number
    // the windows are measured against — so compare it to the record on disk
    // rather than to itself.
    let dir = store("ts_matches_record");
    let mut reported = Vec::new();
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
        for _ in 0..3 {
            let s = engine.submit(ev("response")).expect("submit");
            reported.push((s.offset, s.ts));
        }
    }

    let log = DurableLog::open(&dir).expect("reopen log");
    for (offset, ts) in &reported {
        let mut found = None;
        log.scan_from(*offset, |o, bytes| {
            if o == *offset && found.is_none() {
                found = Some(Record::decode(bytes).expect("decodes").timestamp());
            }
        })
        .expect("scan");
        assert_eq!(
            found,
            Some(*ts),
            "offset {offset} was reported at {ts} but stored a different timestamp"
        );
    }
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn reported_timestamps_are_epoch_nanoseconds_and_strictly_increase() {
    let (mut engine, dir) = opened("ts_unit");

    let now_nanos = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_nanos(),
    )
    .expect("fits i64");

    let mut previous = None;
    for _ in 0..4 {
        let ts = engine.submit(ev("response")).expect("submit").ts;
        // Within a minute of wall clock in *nanoseconds*. A seconds-era value
        // (~1.7e9) misses this by nine orders of magnitude, so the check is a unit
        // assertion as much as a freshness one — the audit trail and the event
        // clock disagreed on exactly this until recently.
        assert!(
            (now_nanos - ts).abs() < 60_000_000_000,
            "{ts} is not epoch nanoseconds near {now_nanos}"
        );
        if let Some(p) = previous {
            assert!(ts > p, "timestamps must strictly increase: {p} then {ts}");
        }
        previous = Some(ts);
    }
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn a_decision_reports_a_timestamp_too() {
    // Same asymmetry the offset had: a verdict is only meaningful relative to the
    // moment it was evaluated at, so withholding that moment returns an answer
    // without what makes it true.
    let (mut engine, dir) = opened("ts_decision");

    let history = engine.submit(ev("response")).expect("history");
    let decision = engine.submit(ev("request")).expect("decision");

    assert!(matches!(decision.outcome, Outcome::Decision(_)));
    assert!(
        decision.ts > history.ts,
        "the decision at {} must follow the history at {}",
        decision.ts,
        history.ts
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn an_apply_reports_where_and_when_it_landed() {
    let dir = store("apply_position");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");

    let first = engine
        .install(POLICY, ACTION_SCHEMA, None, None)
        .expect("applies");
    let event = engine.submit(ev("response")).expect("submit");
    let second = engine
        .install(POLICY, ACTION_SCHEMA, None, None)
        .expect("re-applies");

    // Events and policy changes share `next_timestamp`, so one strictly
    // increasing sequence covers both and sorting by it is the linearization.
    assert!(
        first.ts < event.ts && event.ts < second.ts,
        "apply/submit/apply must interleave in one order: {} {} {}",
        first.ts,
        event.ts,
        second.ts
    );
    // Same for offsets: the change records occupy positions in the same log.
    assert!(
        first.offset < event.offset && event.offset < second.offset,
        "offsets must interleave too: {} {} {}",
        first.offset,
        event.offset,
        second.offset
    );
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn the_clock_survives_a_checkpoint_that_empties_the_log() {
    // `checkpoint` snapshots at `next_offset` and prunes below it, so the working
    // log is left EMPTY while `next_offset` stays where it was. The assigned clock
    // used to be read back from the log's tail record on every submit, and in this
    // state there is no tail: the read returned `None`, `max(now, last + 1)`
    // degraded to `now`, and the monotonicity guarantee vanished exactly when a
    // backwards clock step would matter. A timestamp below the history already
    // folded into the snapshot corrupts monitor state, since `Monitor`'s timeline
    // assumes ascending order and front-prunes with `partition_point`.
    //
    // The clock now travels in the snapshot, so it survives having no records at
    // all. This test cannot force the clock backwards — there is no seam to inject
    // one — so it pins the reachable half: the store still knows where the clock
    // had reached, across the emptying checkpoint and across a restart.
    let dir = store("clock_across_empty_log");
    let before = {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
        let ts = engine.submit(ev("response")).expect("submit").ts;
        engine.checkpoint().expect("checkpoint");
        ts
    };

    // The premise: nothing at all survives in the log.
    {
        let log = DurableLog::open(&dir).expect("reopen log");
        assert_eq!(
            log.base_offset(),
            log.next_offset(),
            "the checkpoint must have emptied the log, or this proves nothing"
        );
        let mut any = false;
        log.scan_from(0, |_, _| any = true).expect("scan");
        assert!(!any, "no record may survive for a tail read to find");
    }

    // A restart, then one more event: its timestamp must still exceed the one
    // whose record no longer exists anywhere but the snapshot.
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("recovers");
    let after = engine.submit(ev("response")).expect("submit").ts;
    assert!(
        after > before,
        "the clock went backwards across an emptying checkpoint: {before} then {after}"
    );
    let _ = std::fs::remove_file(&dir);
}
