//! Native pin partitioning at the SERVER level:
//! auto-enabled whenever the schema declares universal symmetric pins
//! (the default event schema pins `callerPrincipal`).
//!
//! Verdicts CANNOT distinguish the modes — the relativization theorem
//! makes relativized-global and native-partitioned verdict-equivalent by
//! design, and the whole existing suite referees that equivalence just by
//! passing. What these tests pin is that partitioning is actually LIVE
//! (per-principal shards exist), that it survives crash recovery (both
//! the v2-snapshot path and log replay through `step_monitors`, where the
//! routing bug this file's second test caught lived), and that policy
//! applies carry history through the keyed-state transplant.

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{
    DurableError, DurableLog, DurableTemporalEngine, Snapshot, SnapshotPayload, Verb, Write,
};

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User,
    resource: Doc,
    context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User,
    resource: Doc,
    context: { input: { doc: String } }
};
"#;

const WATCHING_READ: &str = r#"
permit (principal, action in [Action::"Read", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

/// An unrelated single policy to `Add` in a batch — it touches no existing
/// leaf, so adding it must leave every existing per-principal window intact.
const UNRELATED: &str =
    r#"forbid (principal, action == Action::"Read", resource) when { principal has dept };"#;

fn ev(action: &str, kind: &str, who: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), kind)
        .principal(&format!("User::\"{who}\""))
        .resource("Doc::\"d1\"")
        .field("input", "doc", Value::String("d1".to_string()))
        .request_context("input", "doc", Value::String("d1".to_string()))
}

fn path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_partmode_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Pin-derived auto-enablement: the default schema pins, so submitting
/// under two principals must materialize two shards.
#[test]
fn partitioning_is_live_under_the_default_schema() {
    let p = path("live");
    let mut st = DurableTemporalEngine::open(&p, 0).expect("opens");
    st.install(WATCHING_READ, ACTION_SCHEMA, None, None)
        .expect("applies");
    assert_eq!(st.temporal_shard_count(), 0, "no events yet");
    st.submit(ev("Read", "response", "alice")).expect("alice");
    st.submit(ev("Read", "response", "bob")).expect("bob");
    assert!(
        st.temporal_shard_count() >= 2,
        "two principals must occupy two shards (got {})",
        st.temporal_shard_count()
    );
    drop(st);
    let _ = std::fs::remove_file(&p);
}

/// Recovery re-partitions: reopen the store (no checkpoint was taken, so
/// this exercises full log REPLAY through step_monitors — the path where
/// replayed history silently vanished before the routing fix) and the
/// shards must be rebuilt.
#[test]
fn recovery_rebuilds_shards_from_replay() {
    let p = path("replay");
    {
        let mut st = DurableTemporalEngine::open(&p, 0).expect("opens");
        st.install(WATCHING_READ, ACTION_SCHEMA, None, None)
            .expect("applies");
        st.submit(ev("Read", "response", "alice")).expect("alice");
        st.submit(ev("Read", "response", "bob")).expect("bob");
    } // crash
    let st = DurableTemporalEngine::open(&p, 0).expect("recovers");
    assert!(
        st.temporal_shard_count() >= 2,
        "replay must rebuild per-principal shards (got {})",
        st.temporal_shard_count()
    );
    drop(st);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn recovery_rejects_outer_clock_below_partition_snapshot_clock() {
    let p = path("outer_clock");
    let latest_ts = {
        let mut st = DurableTemporalEngine::open(&p, 0).expect("opens");
        st.install(WATCHING_READ, ACTION_SCHEMA, None, None)
            .expect("applies");
        let latest = st
            .submit(ev("Read", "response", "alice"))
            .expect("records history")
            .ts;
        st.checkpoint().expect("checkpoints partition state");
        latest
    };

    {
        let log = DurableLog::open(&p).expect("opens log");
        let snapshot = log
            .get_snapshot()
            .expect("reads snapshot")
            .expect("snapshot exists");
        let mut payload = SnapshotPayload::decode(&snapshot.payload).expect("decodes snapshot");
        assert_eq!(
            payload.last_ts, latest_ts,
            "the valid checkpoint must start with matching clocks"
        );
        payload.last_ts = latest_ts - 1;
        log.commit(&[Write::Snapshot(&Snapshot {
            up_to_offset: snapshot.up_to_offset,
            payload: payload.encode().expect("encodes inconsistent snapshot"),
        })])
        .expect("stores inconsistent snapshot");
    }

    let error = match DurableTemporalEngine::open(&p, 0) {
        Ok(_) => panic!("recovery accepted an outer clock below restored partition state"),
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
    let _ = std::fs::remove_file(&p);
}

#[test]
fn inconsistent_outer_clock_degrades_to_an_unpruned_full_log() {
    let p = path("outer_clock_source");
    let frozen = path("outer_clock_full_log");
    let latest_ts = {
        let mut st = DurableTemporalEngine::open(&p, 0).expect("opens");
        st.install(WATCHING_READ, ACTION_SCHEMA, None, None)
            .expect("applies");
        st.submit(ev("Read", "response", "alice"))
            .expect("records history")
            .ts
    };
    std::fs::copy(&p, &frozen).expect("freezes the unpruned full log");

    let snapshot = {
        let mut st = DurableTemporalEngine::open(&p, 0).expect("recovers source");
        st.checkpoint().expect("creates a valid snapshot");
        drop(st);
        DurableLog::open(&p)
            .expect("opens source log")
            .get_snapshot()
            .expect("reads snapshot")
            .expect("snapshot exists")
    };
    {
        let log = DurableLog::open(&frozen).expect("opens frozen log");
        assert_eq!(log.base_offset(), 0, "the fallback needs the full log");
        let mut payload = SnapshotPayload::decode(&snapshot.payload).expect("decodes snapshot");
        payload.last_ts = latest_ts - 1;
        log.commit(&[Write::Snapshot(&Snapshot {
            up_to_offset: snapshot.up_to_offset,
            payload: payload.encode().expect("encodes inconsistent snapshot"),
        })])
        .expect("injects inconsistent snapshot without pruning");
    }

    let recovered = DurableTemporalEngine::open(&frozen, 0)
        .expect("an inconsistent snapshot with a full log must degrade to replay");
    assert!(
        recovered.temporal_shard_count() >= 1,
        "full replay must reconstruct the partition history"
    );
    drop(recovered);
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(&frozen);
}

/// A **batch that keeps every window** must carry the shards through the
/// keyed-state transplant (the partitioned mode-matrix path). Under the
/// verb-batch model "keep the existing policies" means a batch that does not
/// name them — here `[Add(unrelated)]`, which reborns only the new policy and
/// leaves every existing per-principal window intact (§2.2).
#[test]
fn a_batch_add_carries_shards_through_the_keyed_transplant() {
    let p = path("apply");
    let mut st = DurableTemporalEngine::open(&p, 0).expect("opens");
    st.install(WATCHING_READ, ACTION_SCHEMA, None, None)
        .expect("installs");
    st.submit(ev("Read", "response", "alice")).expect("alice");
    st.submit(ev("Read", "response", "bob")).expect("bob");
    let before = st.temporal_shard_count();
    assert!(before >= 2);
    st.batch(vec![Verb::Add {
        policy: UNRELATED.to_string(),
    }])
    .expect("adds an unrelated policy");
    assert_eq!(
        st.temporal_shard_count(),
        before,
        "the keyed transplant must carry every shard across the change"
    );
    // Scalar equality can hide a lost+gained pair (review F6): assert
    // the HISTORY carried by VERDICT — alice's and bob's pre-apply Reads
    // must still gate their Exports, and carol (no Read) must pass.
    let denied = |st: &mut DurableTemporalEngine, who: &str| -> bool {
        let sub = st.submit(ev("Export", "request", who)).expect("submits");
        format!("{sub:?}").contains("Deny")
    };
    assert!(denied(&mut st, "alice"), "alice's window must have carried");
    assert!(denied(&mut st, "bob"), "bob's window must have carried");
    assert!(
        !denied(&mut st, "carol"),
        "carol has no Read history; the forbid must not fire"
    );
    drop(st);
    let _ = std::fs::remove_file(&p);
}
