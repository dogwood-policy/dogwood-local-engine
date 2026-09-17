//! Crash-safety of recovery when a store's bundle register and its snapshot
//! could disagree about which policy was in force.
//!
//! `LocalTemporalEngine::load_snapshot` is positional: it checks the leaf count
//! and each monitor's incremental tag, and that the byte stream is exactly
//! consumed — never which FORMULAS the state belongs to. So if recovery rebuilt
//! the *wrong* policy's leaves and loaded a snapshot into them, the load would
//! succeed and bind one formula's history to another.
//!
//! That disagreement is no longer reachable from a live `apply`: a policy change
//! is a single durable `Record::Apply` append (no separate bundle register, no
//! audit entry, no checkpoint), and recovery starts from the bundle the
//! **snapshot itself names** (`SnapshotPayload`), never a register a crash could
//! leave pointing elsewhere. These tests reconstruct the historical hazard by
//! hand — a stale `dogwood_server_bundle` meta slot written alongside a snapshot
//! taken under a *different* policy — and pin that recovery serves the policy the
//! snapshot names (ignoring the stale register), and that it refuses to open when
//! the log is pruned and the snapshot is unusable.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use dogwood_local_engine::{DurableLog, DurableTemporalEngine};
use dogwood_server::codec::to_event_builder;
use dogwood_server::protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, WireEvent,
};
use dogwood_server::{ControlAllowlist, ControlClient, DataClient, Installed, Paths, Server};

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

/// Bundle A: one leaf, gated on a past `Read` of the same doc.
const POLICY_A: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } };
"#;

/// Bundle B: also ONE leaf with ONE predicate — the same arity as A, so a
/// positional snapshot load cannot tell them apart — but gated on `Login`.
const POLICY_B: &str = r#"
permit (principal, action in [Action::"Read", Action::"Login", Action::"Export"], resource);

forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Login"::request{} };
"#;

fn bundle(policy: &str) -> Installed {
    Installed {
        policies: dogwood_local_engine::PolicySet::from_statements([policy.to_string()], 0),
        action_schema: ACTION_SCHEMA.to_string(),
    }
}

fn ev(action: &str, doc: &str) -> WireEvent {
    let mut e = WireEvent::new(&format!("Action::{action}"), "request");
    e.principal = Some("User::\"alice\"".to_string());
    e.resource = Some("Doc::\"d\"".to_string());
    e.logged
        .insert("input".to_string(), serde_json::json!({ "doc": doc }));
    e.context
        .insert("input".to_string(), serde_json::json!({ "doc": doc }));
    e
}

/// **The snapshot names the policy its state belongs to.**
///
/// Manufacture the disagreement a crash used to leave — the bundle register says
/// B, the snapshot holds state taken under A — and recovery must come up serving
/// A, whose leaves that state describes. Resolving it the other way is what used
/// to bind A's `Read` history to B's `Login` formula.
#[test]
fn the_snapshot_names_the_policy_its_state_belongs_to() {
    let dir = std::env::temp_dir().join(format!("dogwood_applycrash_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Set the mode explicitly rather than inheriting the process umask. `bind`
    // clamps the umask across a socket bind, and for the data socket's 0666 that
    // clamp is 0o111 — so a directory created concurrently by another test is
    // born without its execute bit and cannot be traversed. Cargo runs tests as
    // threads in one process, so that window is shared.
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let store = Paths::new(&dir).store();

    // Install A and record a Read, so A's leaf has history.
    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("opens");
        state
            .install(POLICY_A, ACTION_SCHEMA, None, None)
            .expect("applies A");
        let _ = state
            .submit(to_event_builder(&ev("Read", "target")))
            .expect("submit");
        state.checkpoint().expect("checkpoint");
    }

    // The crash window: the register moved to B, the snapshot did not.
    {
        let log = DurableLog::open(&store).expect("reopen log");
        let bytes = serde_json::to_vec(&bundle(POLICY_B)).expect("serialize");
        log.commit(&[dogwood_local_engine::Write::Meta {
            key: "dogwood_server_bundle",
            value: &bytes,
        }])
        .expect("put");
    }

    let paths = Paths::new(&dir);
    let server = Server::open(paths.clone(), ControlAllowlist::own_uid(), 0)
        .expect("server opens after the simulated crash");
    let shutdown = server.shutdown_handle();
    let handle = std::thread::spawn(move || server.serve().expect("serves"));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut c) = DataClient::connect(paths.data_socket())
            && matches!(c.call(&DataRequest::Ping), Ok(DataResponse::Pong { .. }))
        {
            break;
        }
        assert!(Instant::now() < deadline, "server never became ready");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Which policy is running?
    let source = match ControlClient::connect(paths.control_socket())
        .expect("control")
        .call(&ControlRequest::GetPolicy)
        .expect("get policy")
    {
        ControlResponse::Policy { source } => source,
        other => panic!("expected the policy, got {other:?}"),
    };

    // And does its history still hold? A's rule denies exporting a doc formerly
    // read, and the Read above is that history.
    let allowed = match DataClient::connect(paths.data_socket())
        .expect("connects")
        .call(&DataRequest::Submit {
            event: ev("Export", "target"),
        })
        .expect("submit")
    {
        DataResponse::Decision { allowed, .. } => allowed,
        other => panic!("expected a decision, got {other:?}"),
    };

    shutdown.store(true, Ordering::SeqCst);
    let _ = std::os::unix::net::UnixStream::connect(paths.data_socket());
    let _ = std::os::unix::net::UnixStream::connect(paths.control_socket());
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&dir);

    // The two differ only in what their temporal clause watches; both name every
    // action in their permit *scope*, so the `::request` event kind (which only
    // appears in the temporal clause) is what identifies them. Matched on that
    // token rather than the raw clause text, since `GetPolicy` returns the
    // canonical `expanded_source` form (which parenthesizes the event).
    assert!(
        source.contains(r#"Action::"Read"::request"#),
        "recovery must install the policy the snapshot names (A); got:\n{source}"
    );
    assert!(
        !source.contains(r#"Action::"Login"::request"#),
        "recovery must NOT install the register's policy (B); got:\n{source}"
    );
    assert!(
        !allowed,
        "A's own history must survive: the Read recorded before the crash still \
         denies the Export"
    );
}

/// When the snapshot is unreadable **and** the log has been pruned past the point
/// a replay would need, there is no way to reconstruct the state. Recovery must
/// say so rather than start with a hole in the history: a history-gated `forbid`
/// with missing history simply passes.
#[test]
fn recovery_refuses_when_the_log_is_pruned_and_the_snapshot_is_unusable() {
    let dir = std::env::temp_dir().join(format!("dogwood_applycrash2_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Set the mode explicitly rather than inheriting the process umask. `bind`
    // clamps the umask across a socket bind, and for the data socket's 0666 that
    // clamp is 0o111 — so a directory created concurrently by another test is
    // born without its execute bit and cannot be traversed. Cargo runs tests as
    // threads in one process, so that window is shared.
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let store = Paths::new(&dir).store();

    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("opens");
        state
            .install(POLICY_A, ACTION_SCHEMA, None, None)
            .expect("applies A");
        let _ = state
            .submit(to_event_builder(&ev("Read", "target")))
            .expect("submit");
        // Checkpoint AFTER the event, so the log is reclaimed up to it.
        state.checkpoint().expect("checkpoint");
    }
    {
        let log = DurableLog::open(&store).expect("reopen log");
        assert!(
            log.base_offset() > 0,
            "fixture: the log must be pruned for this case to bite"
        );
        // Corrupt the snapshot payload. Recovery treats an unreadable snapshot as
        // absent, which is safe — but the records that would have rebuilt the
        // state have been reclaimed, so there is nothing left to replay from.
        let up_to = log
            .get_snapshot()
            .expect("read")
            .expect("exists")
            .up_to_offset;
        log.commit(&[dogwood_local_engine::Write::Snapshot(
            &dogwood_local_engine::Snapshot {
                up_to_offset: up_to,
                payload: vec![0xff; 32],
            },
        )])
        .expect("corrupt the snapshot");
    }

    let err = match DurableTemporalEngine::open(&store, 0) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("must refuse to open rather than serve with truncated history"),
    };
    assert!(
        err.contains("no usable snapshot") && err.contains("pruned"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
