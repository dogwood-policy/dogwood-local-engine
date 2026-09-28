//! Pin-sharded routing: does the server derive a partition
//! key when — and *only* when — partitioning is actually sound?
//!
//! The equivalence itself (per-key evaluation ≡ global evaluation) is the
//! frontend's — the relativization rewrite — and is tested in
//! `dogwood-language/tests/pin_partition_differential.rs`. These tests cover the
//! half that lives here, which is where a partitioned deployment would actually go
//! wrong:
//!
//! 1. **Shardability is derived from the schema, not assumed.** A schema with a
//!    universal symmetric pin is shardable on that pin; the default schema, which
//!    pins nothing, is not — and is reported as such rather than silently
//!    partitioned on something plausible-looking.
//! 2. **Routing agrees with correlation.** Events that a policy correlates must
//!    land in the same partition, and events it must never correlate must not.
//! 3. **The end-to-end verdicts match**, per key, when a partitioned stream is
//!    replayed against a single instance — the property routing exists to preserve.

use dogwood_language::UNPINNED_EVENT_SCHEMA;
use dogwood_local_engine::DurableTemporalEngine;
use dogwood_server::protocol::{ControlRequest, ControlResponse, DataRequest, DataResponse};
use dogwood_server::{ControlAllowlist, DataClient, Paths, Server, ShardPlan};
use std::os::unix::fs::PermissionsExt;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// ─── Fixtures ────────────────────────────────────────────────────────

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc,
    context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc,
    context: { input: { doc: String } }
};
"#;

/// A **pinned** event schema: `callerPrincipal` pinned to the request principal
/// on *every* kind. This is a universal symmetric pin, so the frontend rewrites
/// the universally quantified temporal positions for key-local evaluation and the
/// stream becomes partitionable by principal.
const PINNED_EVENT_SCHEMA: &str = r#"
decision event <A>::request {
    ...inputs(A),
    pin callerPrincipal: principalType(A) = principal,
    callerResource:  resourceType(A),
    requestId:       String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    pin callerPrincipal: principalType(A) = principal,
    callerResource:  resourceType(A),
    requestId:       String,
}
"#;

/// The same pin on only ONE kind — **not** universal. A resolution event could
/// then land in any partition, and the frontend does not rewrite for it, so this
/// must be reported unshardable even though a pin is present.
const HALF_PINNED_EVENT_SCHEMA: &str = r#"
decision event <A>::request {
    ...inputs(A),
    pin callerPrincipal: principalType(A) = principal,
    callerResource:  resourceType(A),
    requestId:       String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    callerPrincipal: principalType(A),
    callerResource:  resourceType(A),
    requestId:       String,
}
"#;

/// A per-principal rule: exporting a doc this principal formerly read is denied.
/// Under the pinned schema the correlation is per-principal, so alice's read must
/// not affect bob's export — exactly what partitioning by principal preserves.
const POLICY: &str = r#"
permit (
    principal,
    action in [Action::"Read", Action::"Export"],
    resource
);

forbid (
    principal,
    action == Action::"Export",
    resource
)
when temporal {
    formerly within 1h Action::"Read"::request{ input.doc: context.input.doc }
};
"#;

/// A policy that parses and canonicalizes fine but references `Action::"Delete"`,
/// which `ACTION_SCHEMA` does not declare — so it clears the parse/canonicalize
/// stage (which consults only the event schema + macros) and fails at the
/// validation stage inside `rebuild`. That is the failure the store-config
/// atomicity tests need: one that reaches the record-commit path and must abort
/// it, not one rejected before `apply` is ever entered.
const BAD_POLICY: &str = r#"permit (principal, action == Action::"Delete", resource);"#;

fn temp_dir(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("dogwood_shard_test_{tag}_{}", std::process::id()));
    dir
}

/// Open a `DurableTemporalEngine` directly (no sockets) and install a bundle. Enough for
/// the plan-derivation tests, which need no I/O.
fn state_with(tag: &str, event_schema: Option<&str>) -> DurableTemporalEngine {
    let dir = temp_dir(tag);
    let _ = std::fs::remove_dir_all(&dir);
    // Set the mode explicitly rather than inheriting the process umask. `bind`
    // clamps the umask across a socket bind, and for the data socket's 0666 that
    // clamp is 0o111 — so a directory created concurrently by another test is
    // born without its execute bit and cannot be traversed. Cargo runs tests as
    // threads in one process, so that window is shared.
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let mut state = DurableTemporalEngine::open(dir.join("store.redb"), 0).expect("opens");
    state
        .install(POLICY, ACTION_SCHEMA, event_schema, None)
        .expect("applies");
    state
}

// ─── Plan derivation ─────────────────────────────────────────────────

/// A universal symmetric pin makes the stream shardable, on that pin.
#[test]
fn a_universal_symmetric_pin_yields_a_partition_key() {
    let state = state_with("pinned", Some(PINNED_EVENT_SCHEMA));
    match state.shard_plan() {
        ShardPlan::Sharded { key_paths } => {
            assert_eq!(
                key_paths,
                vec![vec!["callerPrincipal".to_string()]],
                "the partition key must be the pinned field"
            );
        }
        ShardPlan::Unshardable => {
            panic!("a universal symmetric pin must yield a partition key")
        }
    }
    assert_eq!(
        state.status().partition_key,
        vec!["callerPrincipal".to_string()],
        "status must report the key so an operator can see it"
    );
}

/// **The default schema is not shardable, and says so.**
///
/// The default schema declares no pins, so the frontend does not rewrite
/// `previous` / `since` for key-local evaluation — partitioning it would change
/// verdicts. The interesting part is that principal-based routing would *look*
/// perfectly reasonable here, which is exactly the mistake this reports instead of
/// making.
#[test]
fn the_default_schema_is_reported_unshardable() {
    let state = state_with("unpinned", Some(UNPINNED_EVENT_SCHEMA));
    assert_eq!(
        state.shard_plan(),
        ShardPlan::Unshardable,
        "the unpinned schema pins nothing, so no partitioning is sound"
    );
    assert!(
        state.status().partition_key.is_empty(),
        "status must report no partition key"
    );
}

/// **A pin on only some event kinds is not a partition key.**
///
/// This is the subtle case. A pin is present, and routing requests by it would
/// work; but resolutions carry no pin, so they cannot be routed consistently, and
/// the frontend's rewrite does not trigger. Treating this as shardable would
/// partition a stream whose history events scatter — silently losing the
/// correlation a `formerly` depends on.
#[test]
fn a_pin_on_only_one_event_kind_is_not_a_partition_key() {
    let state = state_with("half", Some(HALF_PINNED_EVENT_SCHEMA));
    assert_eq!(
        state.shard_plan(),
        ShardPlan::Unshardable,
        "a non-universal pin must not be treated as a partition key"
    );
}

/// Shardability tracks the **store's** event schema: a pinned schema yields a
/// sharded plan, an unpinned one does not.
///
/// The event schema is store configuration now, fixed at the first install and
/// immutable thereafter — changing a pin
/// re-buckets all state, so it is a deliberate store rebuild, not an apply. So
/// each schema is exercised on its **own** store (the rebuild), and an attempt
/// to switch the event schema on a live store is asserted to be **rejected**.
#[test]
fn shardability_follows_the_stores_event_schema() {
    // A fresh store per schema — the rebuild that a pin change requires.
    let unpinned = state_with("switch_unpinned", Some(UNPINNED_EVENT_SCHEMA));
    assert_eq!(
        unpinned.shard_plan(),
        ShardPlan::Unshardable,
        "an unpinned schema is not shardable"
    );

    let pinned = state_with("switch_pinned", Some(PINNED_EVENT_SCHEMA));
    assert!(
        matches!(pinned.shard_plan(), ShardPlan::Sharded { .. }),
        "a pinned schema must be shardable"
    );

    // Switching the event schema on a live store is refused — it would reborn
    // every policy and re-bucket all state, so it is a store rebuild, not an
    // install.
    let dir = temp_dir("switch_reject");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let mut state = DurableTemporalEngine::open(dir.join("store.redb"), 0).expect("opens");
    state
        .install(POLICY, ACTION_SCHEMA, Some(UNPINNED_EVENT_SCHEMA), None)
        .expect("first install configures the event schema");
    let err = state.install(POLICY, ACTION_SCHEMA, Some(PINNED_EVENT_SCHEMA), None);
    assert!(
        err.is_err(),
        "changing the event schema on a live store must be rejected, got {err:?}"
    );
}

/// The store's event schema is durable: a **custom** (non-default) event schema
/// configured at install is still in force after a restart, not reverted to the
/// built-in default (it lives in a metadata
/// slot, read back at open).
///
/// The default schema *pins* `callerPrincipal` (shardable); `UNPINNED_EVENT_SCHEMA`
/// does not. So configuring the unpinned schema and finding the store still
/// unshardable after a reopen proves the custom schema persisted — a store that
/// forgot it would revert to the pinned default and read as shardable.
#[test]
fn a_custom_event_schema_survives_a_restart() {
    let dir = temp_dir("event_schema_restart");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let store = dir.join("store.redb");

    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("opens");
        state
            .install(POLICY, ACTION_SCHEMA, Some(UNPINNED_EVENT_SCHEMA), None)
            .expect("installs under the unpinned schema");
        assert_eq!(
            state.shard_plan(),
            ShardPlan::Unshardable,
            "the unpinned schema is not shardable"
        );
    }

    // Reopen: the configured (unpinned) event schema must still govern.
    let state = DurableTemporalEngine::open(&store, 0).expect("reopens");
    assert_eq!(
        state.shard_plan(),
        ShardPlan::Unshardable,
        "the custom event schema must survive the restart — reverting to the \
         pinned default would read as shardable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Re-installing with the **same** event schema is accepted: only a
/// *change* to the store-config schema is rejected, so a declarative re-apply of
/// an unchanged configuration is a no-op on the config, not an error.
#[test]
fn re_installing_with_the_same_event_schema_is_idempotent() {
    let dir = temp_dir("event_schema_idempotent");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let mut state = DurableTemporalEngine::open(dir.join("store.redb"), 0).expect("opens");

    state
        .install(POLICY, ACTION_SCHEMA, Some(UNPINNED_EVENT_SCHEMA), None)
        .expect("first install configures the event schema");
    // Same config again — accepted (idempotent), not rejected as a change.
    state
        .install(POLICY, ACTION_SCHEMA, Some(UNPINNED_EVENT_SCHEMA), None)
        .expect("re-install with the same event schema must be accepted");

    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Store-config is set once, and only by a *successful* install ────

/// **Positive control** for the set-once rule: once an install has
/// *succeeded* and locked in an event schema, a later install that would change
/// it is rejected — the event schema is fixed at store configuration. This is the
/// mechanism the atomicity tests below prove does *not* fire on a rejected install;
/// it must genuinely fire here, or those tests would pass vacuously.
#[test]
fn changing_the_event_schema_after_a_successful_install_is_rejected() {
    let dir = temp_dir("event_schema_change_rejected");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let mut state = DurableTemporalEngine::open(dir.join("store.redb"), 0).expect("opens");

    state
        .install(POLICY, ACTION_SCHEMA, Some(UNPINNED_EVENT_SCHEMA), None)
        .expect("first install locks in the unpinned schema");
    assert_eq!(
        state.event_schema().as_deref(),
        Some(UNPINNED_EVENT_SCHEMA),
        "the successful install must have adopted its event schema"
    );

    // A later install carrying a *different* event schema is rejected.
    let err = state.install(POLICY, ACTION_SCHEMA, Some(PINNED_EVENT_SCHEMA), None);
    assert!(
        err.is_err(),
        "changing the event schema after configuration must be rejected"
    );
    assert_eq!(
        state.event_schema().as_deref(),
        Some(UNPINNED_EVENT_SCHEMA),
        "the rejected change must not have altered the configured schema"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// **A rejected first install must not lock in its event schema.** The store
/// config (event schema / macros) is written in the *same* transaction as
/// the policy records it configures, so an install that fails validation persists
/// nothing — leaving the store free to be configured with a *different* event
/// schema by a later install. Before the fix, `install` committed the event
/// schema in its own transaction *before* validating the policy, so a failed
/// first install stranded the schema (set-once) and no different schema could ever
/// be installed short of a fresh store.
#[test]
fn a_rejected_first_install_does_not_lock_in_the_event_schema() {
    let dir = temp_dir("event_schema_rejected_no_lock");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let mut state = DurableTemporalEngine::open(dir.join("store.redb"), 0).expect("opens");

    // First install: a valid event schema paired with a policy that fails
    // validation (references an undeclared action). The whole install must fail.
    let err = state.install(BAD_POLICY, ACTION_SCHEMA, Some(PINNED_EVENT_SCHEMA), None);
    assert!(
        err.is_err(),
        "an install whose policy fails validation must be rejected"
    );

    // Nothing was configured or installed: the event schema is still unset and no
    // policy is running.
    assert_eq!(
        state.event_schema(),
        None,
        "a rejected install must not have locked in its event schema"
    );
    assert!(
        state.list().is_empty(),
        "a rejected install must not have installed a policy"
    );

    // A later install with a *different* event schema succeeds — the proof the
    // first did not lock the store. (Were the schema stranded, set-once would
    // reject this as an illegal change.)
    state
        .install(POLICY, ACTION_SCHEMA, Some(UNPINNED_EVENT_SCHEMA), None)
        .expect("a fresh install with a different event schema must succeed");
    assert_eq!(
        state.event_schema().as_deref(),
        Some(UNPINNED_EVENT_SCHEMA),
        "the successful install's event schema is the one now in force"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The crash-injection variant of the above: a rejected first install leaves *no
/// durable trace*, so even across a restart the store is still reconfigurable.
/// Reopening after the failed install and installing a different event schema must
/// succeed and persist — a stranded config slot would survive the reopen and block
/// it exactly as it would in-process.
#[test]
fn a_rejected_first_install_leaves_the_store_reconfigurable_across_a_restart() {
    let dir = temp_dir("event_schema_rejected_restart");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let store = dir.join("store.redb");

    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("opens");
        let err = state.install(BAD_POLICY, ACTION_SCHEMA, Some(PINNED_EVENT_SCHEMA), None);
        assert!(err.is_err(), "the first install must be rejected");
        // Drop the engine (simulating a process exit) with the failed install
        // behind us.
    }

    // Reopen: recovery sees an empty store (the rejected install wrote nothing),
    // so a first install with a *different* event schema is accepted.
    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("reopens");
        assert_eq!(
            state.event_schema(),
            None,
            "the rejected install must have left no configured schema to recover"
        );
        state
            .install(POLICY, ACTION_SCHEMA, Some(UNPINNED_EVENT_SCHEMA), None)
            .expect("installing a different event schema after the reopen must succeed");
    }

    // And it persisted: a final reopen still governs under the unpinned schema.
    let state = DurableTemporalEngine::open(&store, 0).expect("reopens again");
    assert_eq!(
        state.event_schema().as_deref(),
        Some(UNPINNED_EVENT_SCHEMA),
        "the schema installed after the failed first attempt must persist"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Routing agrees with correlation ─────────────────────────────────

/// Events the policy correlates route together; events it must not correlate route
/// apart. This is the routing invariant a partitioned deployment needs: if two
/// events that must be compared land in different partitions, the comparison never
/// happens and a `forbid` silently fails to fire.
#[test]
fn routing_groups_exactly_the_events_that_must_correlate() {
    let state = state_with("routing", Some(PINNED_EVENT_SCHEMA));
    let plan = state.shard_plan();

    let event = |principal: &str, doc: &str, kind: &str| {
        let mut ev = dogwood_server::protocol::WireEvent::new("Action::Read", kind);
        ev.principal = Some(format!("User::\"{principal}\""));
        ev.logged
            .insert("input".to_string(), serde_json::json!({ "doc": doc }));
        ev
    };

    use dogwood_server::key_of;
    let alice_read = key_of(&plan, &event("alice", "d1", "request")).expect("key");
    let alice_other = key_of(&plan, &event("alice", "d2", "request")).expect("key");
    let alice_hist = key_of(&plan, &event("alice", "d1", "resolution")).expect("key");
    let bob_read = key_of(&plan, &event("bob", "d1", "request")).expect("key");

    // Same principal ⇒ same partition, regardless of doc or event KIND. The kind
    // matters: a history event must reach the same monitor as the decision that
    // will look back on it.
    assert_eq!(alice_read, alice_other, "same principal, different doc");
    assert_eq!(
        alice_read, alice_hist,
        "a history event must route to the same partition as its decision events"
    );
    // Different principal ⇒ different partition.
    assert_ne!(
        alice_read, bob_read,
        "different principals must not share a partition"
    );
}

// ─── End-to-end: partitioned verdicts match ──────────────────────────

/// A server on its own thread, for the end-to-end check.
struct TestServer {
    paths: Paths,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(tag: &str) -> Self {
        let dir = temp_dir(tag);
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths::new(&dir);
        let server = Server::open(paths.clone(), ControlAllowlist::own_uid(), 0)
            .expect("server opens")
            .with_idle_timeout(Duration::from_secs(5));
        let shutdown = server.shutdown_handle();
        let handle = std::thread::spawn(move || server.serve().expect("serves"));
        let this = TestServer {
            paths,
            shutdown,
            handle: Some(handle),
        };
        this.wait_ready();
        this
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(mut c) = DataClient::connect(self.paths.data_socket())
                && matches!(c.call(&DataRequest::Ping), Ok(DataResponse::Pong { .. }))
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("server not ready");
    }

    fn apply_pinned(&self) {
        let response = dogwood_server::ControlClient::connect(self.paths.control_socket())
            .expect("control connects")
            .call(&ControlRequest::Install {
                policy: POLICY.to_string(),
                action_schema: ACTION_SCHEMA.to_string(),
                event_schema: Some(PINNED_EVENT_SCHEMA.to_string()),
            })
            .expect("apply call");
        assert!(
            !matches!(response, ControlResponse::Error { .. }),
            "apply rejected: {response:?}"
        );
    }

    /// Submit a decision event for `principal` and return whether it was allowed.
    fn decide(&self, principal: &str, action: &str, doc: &str) -> bool {
        let mut ev =
            dogwood_server::protocol::WireEvent::new(&format!("Action::{action}"), "request");
        ev.principal = Some(format!("User::\"{principal}\""));
        ev.resource = Some("Doc::\"d\"".to_string());
        ev.logged
            .insert("input".to_string(), serde_json::json!({ "doc": doc }));
        ev.context
            .insert("input".to_string(), serde_json::json!({ "doc": doc }));
        match DataClient::connect(self.paths.data_socket())
            .expect("connects")
            .call(&DataRequest::Submit { event: ev })
            .expect("submit")
        {
            DataResponse::Decision { allowed, .. } => allowed,
            other => panic!("expected a decision, got {other:?}"),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = std::os::unix::net::UnixStream::connect(self.paths.data_socket());
            let _ = std::os::unix::net::UnixStream::connect(self.paths.control_socket());
            let _ = h.join();
        }
    }
}

/// **The property partitioning must preserve, observed through the server.**
///
/// With the pinned schema, one principal's history must not influence another's
/// verdict. That is what makes routing by principal safe: each partition would see
/// only its own events, and this test confirms a single instance already behaves
/// that way — so splitting the stream cannot change any verdict.
#[test]
fn per_principal_history_does_not_leak_across_keys() {
    let server = TestServer::start("e2e");
    server.apply_pinned();

    // alice reads d1, so alice's export of d1 is denied.
    assert!(server.decide("alice", "Read", "d1"));
    assert!(
        !server.decide("alice", "Export", "d1"),
        "alice's own read must deny alice's export"
    );

    // bob never read d1 — alice's read must not bleed into bob's partition.
    assert!(
        server.decide("bob", "Export", "d1"),
        "alice's history must not deny bob's export (the partitioning invariant)"
    );

    // And bob's own read denies only bob.
    assert!(server.decide("bob", "Read", "d2"));
    assert!(
        !server.decide("bob", "Export", "d2"),
        "bob's own read must deny bob's export"
    );
    assert!(
        server.decide("alice", "Export", "d2"),
        "bob's history must not deny alice's export"
    );
}
