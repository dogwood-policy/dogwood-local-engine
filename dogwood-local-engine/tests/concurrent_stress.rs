//! Many concurrent callers submitting decisions at once: nothing lost or
//! duplicated, and the recovered store agrees with the reference oracle.
//!
//! The server serializes every submit behind one lock, so
//! concurrent callers line up single-file. This test checks that under real
//! contention nothing falls through the cracks — no event is double-counted, none
//! is lost, and the recovered verdict matches the reference interpreter.
//!
//! The key trick: during the storm the correct answer depends on the order the
//! racing submits land in, and that order is only decided at the append point. So
//! we don't predict it — we read it back. The engine stamps every record with a
//! strictly increasing timestamp, so sorting by timestamp *is* the linearization.

mod common;

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use common::invariants::LogFacts;
use common::oracle::{self, Sensitivity};
use common::workload::{Op, Promises, Retention};
use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{DurableLog, DurableTemporalEngine, Installed, Outcome};

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

const WATCHING_READ: &str = r#"
permit (principal, action in [Action::"Read", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

/// A reference-only carrier of the installed source for the oracle's `Op`
/// (re-lowered to build the reference interpreter); never returned to the
/// engine, which got the real split set via `install`.
fn reference_policy() -> Installed {
    Installed {
        policies: dogwood_local_engine::PolicySet::from_statements([WATCHING_READ.to_string()], 0),
        action_schema: ACTION_SCHEMA.to_string(),
    }
}

fn ev(action: &str, kind: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), kind)
        .principal("User::\"alice\"")
        .resource("Doc::\"d1\"")
        .field("input", "doc", Value::String("d1".to_string()))
        .request_context("input", "doc", Value::String("d1".to_string()))
}

fn path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_concurrent_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn run_scenario(tag: &str, callers: usize, each: usize) {
    let live = path(tag);
    let started = SystemTime::now();

    let engine = DurableTemporalEngine::open(&live, 0).expect("opens");
    let engine = Arc::new(Mutex::new(engine));

    let apply_op = {
        let mut guard = engine.lock().expect("unpoisoned");
        let applied = guard
            .install(WATCHING_READ, ACTION_SCHEMA, None, None)
            .expect("installs");
        Op::Applied {
            ts: applied.ts,
            offset: applied.offset,
            first_offset: applied.first_offset,
            policy: reference_policy(),
            retention: Retention::AllReset,
        }
    };

    let mut handles = Vec::new();
    for _ in 0..callers {
        let engine = Arc::clone(&engine);
        handles.push(std::thread::spawn(move || {
            let mut ops = Vec::new();
            for _ in 0..each {
                for (action, kind) in [("Read", "response"), ("Export", "request")] {
                    let event = ev(action, kind);
                    std::thread::yield_now();
                    let submitted = {
                        let mut guard = engine.lock().expect("unpoisoned");
                        guard.submit(event.clone()).expect("submit")
                    };
                    let live_verdict = match &submitted.outcome {
                        Outcome::Decision(r) => Some(r.allowed()),
                        Outcome::Recorded => None,
                    };
                    ops.push(Op::Submitted {
                        ts: submitted.ts,
                        offset: submitted.offset,
                        event,
                        live: live_verdict,
                    });
                }
            }
            ops
        }));
    }

    let mut ops = vec![apply_op];
    for handle in handles {
        ops.extend(handle.join().expect("caller thread succeeds"));
    }
    let finished = SystemTime::now();

    ops.sort_by_key(|op| op.ts());
    let promises = Promises {
        ops,
        started,
        finished,
    };

    // Enumerate every offset each op wrote: an event is one, an apply is the
    // whole contiguous range of its per-verb records (schemas, DeleteAll,
    // one Add per policy).
    let mut offsets: Vec<u64> = promises
        .ops
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
    let total = offsets.len() as u64;
    offsets.sort_unstable();
    let unique = {
        let mut u = offsets.clone();
        u.dedup();
        u.len() as u64
    };
    assert_eq!(
        unique, total,
        "an offset was assigned to two records — a concurrent submit raced the offset counter"
    );
    assert_eq!(
        offsets,
        (0..total).collect::<Vec<_>>(),
        "assigned offsets are not the contiguous range 0..{total}"
    );

    drop(
        Arc::try_unwrap(engine)
            .ok()
            .expect("sole owner")
            .into_inner()
            .expect("unpoisoned"),
    );

    let facts = {
        let log = DurableLog::open(&live).expect("reopen log");
        LogFacts::read(&log).expect("read facts")
    };
    let mut recovered = DurableTemporalEngine::open(&live, 0).expect("recovers");
    oracle::assert_agrees(
        &mut recovered,
        &facts,
        &promises,
        &ev("Export", "request"),
        Sensitivity::HistoryDependent,
    );

    drop(recovered);
    let _ = std::fs::remove_file(&live);
}

#[test]
fn concurrent_submissions_stay_well_formed_and_decide_correctly() {
    for run in 0..20 {
        run_scenario(&format!("run{run}"), 8, 5);
    }
}
