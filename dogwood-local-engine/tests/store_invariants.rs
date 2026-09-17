//! That the invariants in `common::invariants` *detect* their violations, and
//! that a real crash-and-recover cycle satisfies all of them.
//!
//! The first half is the point. A check that only ever passes is
//! indistinguishable from no check at all, and most of these states cannot be
//! produced from a real store on demand — `base > next` took the specific
//! prune-then-append sequence that was once a bug. Constructing [`LogFacts`] by
//! hand is what makes each one demonstrable.

mod common;

use std::time::{Duration, SystemTime};

use common::invariants::{
    self as inv, LogFacts, Violation, acked_survive, records_dense, timestamps_increase,
    timestamps_track_wall_clock, watermarks_ordered,
};
use common::workload::{Op, Promises, Recorder};
use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{DurableLog, DurableTemporalEngine};

// ---------------------------------------------------------------------------
// Synthetic states: does each check fire?
// ---------------------------------------------------------------------------

/// A store holding offsets 0..3 with ascending timestamps, nothing pruned.
fn healthy() -> LogFacts {
    LogFacts {
        base_offset: 0,
        next_offset: 3,
        snapshot_up_to: None,
        records: vec![(0, 100, true), (1, 200, true), (2, 300, true)],
    }
}

/// Promises whose wall-clock window contains `healthy`'s timestamps, reporting
/// `acked` as acknowledged event offsets.
fn promised(acked: &[u64]) -> Promises {
    Promises {
        ops: acked
            .iter()
            .map(|&offset| Op::Submitted {
                ts: 100 + offset as i64,
                offset,
                event: ev(),
                live: None,
            })
            .collect(),
        started: SystemTime::UNIX_EPOCH,
        finished: SystemTime::UNIX_EPOCH + Duration::from_micros(1),
    }
}

#[test]
fn a_healthy_state_passes_everything() {
    let f = healthy();
    let p = promised(&[0, 1, 2]);
    assert_eq!(inv::check_all(&f, &p), Ok(()));
}

#[test]
fn base_above_next_is_caught() {
    // Bug 1: a prune emptied the log and a derived next_offset restarted at 0,
    // leaving appends below the watermark recovery starts from.
    let f = LogFacts {
        base_offset: 2,
        next_offset: 0,
        ..LogFacts::default()
    };
    assert_eq!(
        watermarks_ordered(&f),
        Err(Violation::BaseAboveNext { base: 2, next: 0 })
    );
}

#[test]
fn a_snapshot_past_the_end_is_caught() {
    let f = LogFacts {
        next_offset: 3,
        snapshot_up_to: Some(9),
        ..healthy()
    };
    assert_eq!(
        watermarks_ordered(&f),
        Err(Violation::SnapshotBeyondNext { up_to: 9, next: 3 })
    );
}

#[test]
fn pruning_past_the_snapshot_is_caught() {
    // Bug 3's shape: records below base are gone, and the snapshot does not
    // reach them, so their history is unrecoverable.
    let f = LogFacts {
        base_offset: 4,
        next_offset: 6,
        snapshot_up_to: Some(2),
        records: vec![(4, 100, true), (5, 200, true)],
    };
    assert_eq!(
        watermarks_ordered(&f),
        Err(Violation::PrunedPastSnapshot { base: 4, up_to: 2 })
    );
    assert!(!f.is_recoverable());
}

#[test]
fn a_hole_is_caught() {
    let f = LogFacts {
        base_offset: 0,
        next_offset: 3,
        snapshot_up_to: None,
        records: vec![(0, 100, true), (2, 300, true)], // 1 is missing
    };
    assert_eq!(records_dense(&f), Err(Violation::Hole { offset: 1 }));
}

#[test]
fn a_record_beyond_next_offset_is_caught() {
    let f = LogFacts {
        base_offset: 0,
        next_offset: 2,
        snapshot_up_to: None,
        records: vec![(0, 100, true), (1, 200, true), (2, 300, true)],
    };
    assert_eq!(
        records_dense(&f),
        Err(Violation::RecordBeyondNext { offset: 2, next: 2 })
    );
}

#[test]
fn a_repeated_or_falling_timestamp_across_events_is_caught() {
    // Two events sharing a timestamp: windows are measured against the event
    // sequence, so it must strictly increase (the `true` marks these as events).
    let f = LogFacts {
        records: vec![(0, 100, true), (1, 100, true)],
        next_offset: 2,
        ..LogFacts::default()
    };
    assert_eq!(
        timestamps_increase(&f),
        Err(Violation::TimestampNotIncreasing {
            offset: 1,
            timestamp: 100,
            previous: 100,
        })
    );

    // A falling timestamp is a violation regardless of record kind.
    let f = LogFacts {
        records: vec![(0, 200, false), (1, 100, false)],
        next_offset: 2,
        ..LogFacts::default()
    };
    assert_eq!(
        timestamps_increase(&f),
        Err(Violation::TimestampNotIncreasing {
            offset: 1,
            timestamp: 100,
            previous: 200,
        })
    );
}

#[test]
fn policy_records_in_one_batch_may_share_a_timestamp() {
    // A batch is one atomic instant (§2.5): its verb records (`false` = not an
    // event) share a timestamp, ordered by offset. That tie is allowed — only an
    // event tie is a violation. A following event must still strictly advance.
    let f = LogFacts {
        records: vec![(0, 100, false), (1, 100, false), (2, 101, true)],
        next_offset: 3,
        ..LogFacts::default()
    };
    assert_eq!(timestamps_increase(&f), Ok(()));

    // But an event may not share the batch's instant.
    let f = LogFacts {
        records: vec![(0, 100, false), (1, 100, false), (2, 100, true)],
        next_offset: 3,
        ..LogFacts::default()
    };
    assert_eq!(
        timestamps_increase(&f),
        Err(Violation::TimestampNotIncreasing {
            offset: 2,
            timestamp: 100,
            previous: 100,
        })
    );
}

#[test]
fn a_sequence_that_ascends_but_leaves_the_wall_clock_is_caught() {
    // Bug 4 exactly. `max(now, last + 1)` at whole-second resolution fires on
    // every event of any burst faster than 1/s, so the sequence keeps ascending
    // while running a second ahead per event. `timestamps_increase` is satisfied
    // throughout — only tracking real time exposes it.
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let promises = Promises {
        started: start,
        finished: start + Duration::from_millis(108), // 12 events in 0.108s
        ..Promises::default()
    };
    let base = 1_000_000i64 * 1_000_000_000;
    let f = LogFacts {
        base_offset: 0,
        next_offset: 12,
        snapshot_up_to: None,
        // One second apart, as the buggy clamp produced.
        records: (0..12)
            .map(|i| (i as u64, base + i * 1_000_000_000, true))
            .collect(),
    };

    assert_eq!(
        timestamps_increase(&f),
        Ok(()),
        "the buggy sequence does ascend — which is why that check missed it"
    );
    let err = timestamps_track_wall_clock(&f, &promises, Duration::from_secs(1))
        .expect_err("a sequence eleven seconds long inside 0.108s must be caught");
    assert!(
        matches!(err, Violation::TimestampOffWallClock { .. }),
        "{err}"
    );
}

#[test]
fn an_acked_offset_that_is_gone_is_caught() {
    let f = LogFacts {
        base_offset: 4,
        next_offset: 6,
        snapshot_up_to: Some(4),
        records: vec![(4, 100, true), (5, 200, true)],
    };
    // 4 and 5 are present; 3 was folded in by the snapshot; 9 never existed.
    assert_eq!(acked_survive(&f, &promised(&[3, 4, 5])), Ok(()));
    assert_eq!(
        acked_survive(&f, &promised(&[9])),
        Err(Violation::AckedLost {
            offset: 9,
            base: 4,
            snapshot_up_to: Some(4),
        })
    );
}

#[test]
fn an_acked_offset_reclaimed_without_a_snapshot_is_caught() {
    // The distinction the obligation turns on: a record may be reclaimed only if
    // a durable snapshot folded its effect in. Without one, it is simply lost.
    let f = LogFacts {
        base_offset: 2,
        next_offset: 3,
        snapshot_up_to: None,
        records: vec![(2, 300, true)],
    };
    assert_eq!(
        acked_survive(&f, &promised(&[1])),
        Err(Violation::AckedLost {
            offset: 1,
            base: 2,
            snapshot_up_to: None,
        })
    );
}

#[test]
fn refusing_with_acknowledged_work_is_caught() {
    let f = healthy();
    let refused: Result<&DurableTemporalEngine, String> = Err("truncated history".to_string());
    assert_eq!(
        inv::refuses_exactly_when_it_must(&f, refused, &promised(&[])),
        Ok(()),
        "refusing a store nobody was promised anything from is correct"
    );
    let refused: Result<&DurableTemporalEngine, String> = Err("truncated history".to_string());
    assert!(matches!(
        inv::refuses_exactly_when_it_must(&f, refused, &promised(&[0, 1])),
        Err(Violation::RefusedWithAckedWork { .. })
    ));
}

// ---------------------------------------------------------------------------
// A real cycle
// ---------------------------------------------------------------------------

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

const POLICY: &str = r#"
permit (principal, action == Action::"Read", resource);

forbid (principal, action == Action::"Read", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

fn ev() -> EventBuilder {
    Event::builder("Action::Read", "response").field(
        "input",
        "doc",
        Value::String("d1".to_string()),
    )
}

fn path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_store_inv_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Run a workload, freeze the store by copying it, recover from the copy, and
/// hold the whole cycle to every invariant.
fn cycle(tag: &str, checkpoint: bool) {
    let live = path(&format!("{tag}_live"));
    let frozen = path(&format!("{tag}_frozen"));

    let promises = {
        let mut rec = Recorder::new(DurableTemporalEngine::open(&live, 0).expect("opens"));
        rec.install(POLICY, ACTION_SCHEMA).expect("installs");
        for _ in 0..4 {
            rec.submit(ev()).expect("submit");
        }
        if checkpoint {
            // Snapshots and prunes, so acked records legitimately disappear and
            // `acked_survive` must accept them as folded in rather than lost.
            rec.checkpoint().expect("checkpoint");
        }
        rec.finish()
    };
    // Freeze after the state is dropped: a file cannot be copied out from under
    // redb mid-transaction, and this cycle is testing recovery, not tearing.
    std::fs::copy(&live, &frozen).expect("freeze");

    let facts = {
        let log = DurableLog::open(&frozen).expect("read frozen");
        LogFacts::read(&log).expect("facts")
    };
    let recovered = DurableTemporalEngine::open(&frozen, 0);
    inv::assert_cycle(&facts, recovered.as_ref(), &promises);

    // Guard against the cycle quietly becoming vacuous.
    assert!(
        !promises.acked_event_offsets().is_empty(),
        "the workload must promise something, or every check is trivially satisfied"
    );
    if checkpoint {
        assert!(
            facts.snapshot_up_to.is_some() && facts.base_offset > 0,
            "a checkpointed cycle must have snapshotted and pruned, or the \
             folded-in branch of `acked_survive` is never taken: {facts:?}"
        );
        assert!(
            promises
                .acked_event_offsets()
                .iter()
                .any(|&o| o < facts.base_offset),
            "at least one acknowledged offset must have been reclaimed, so the \
             obligation is met by the snapshot rather than by presence: acked \
             {:?} against base {}",
            promises.acked_event_offsets(),
            facts.base_offset
        );
    } else {
        assert_eq!(
            facts.base_offset, 0,
            "nothing should have been pruned without a checkpoint"
        );
    }
    let _ = std::fs::remove_file(&live);
    let _ = std::fs::remove_file(&frozen);
}

#[test]
fn a_real_cycle_satisfies_every_invariant() {
    cycle("plain", false);
}

#[test]
fn a_real_cycle_with_a_checkpoint_satisfies_every_invariant() {
    // The interesting case: pruning removes records that were acknowledged, and
    // the obligation is met by the snapshot rather than by their presence.
    cycle("checkpointed", true);
}
