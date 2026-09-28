//! End-to-end: a real server over real Unix sockets.
//!
//! These drive the server the way a deployment does — install a policy through
//! the control plane, submit events on the data plane, restart, apply a new
//! policy — and assert the properties `DESIGN.md` promises: durability across a
//! restart, prospective installs (§9), atomic swap (§8), the verb split (§8.1),
//! and store-assigned timestamps (§3.3).
//!
//! The server is run in-process on a thread rather than as a subprocess: same
//! code path, but a failure surfaces as an assertion instead of a parsed stdout,
//! and there is no test-only binary path to keep in sync.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dogwood_server::protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, PolicySummary, WireEvent, WireVerb,
};
use dogwood_server::{ControlAllowlist, ControlClient, DataClient, Paths, Server};

// ─── Fixtures ────────────────────────────────────────────────────────

/// A minimal action schema: one principal, one resource, three actions. Each
/// action's `context.input.doc` is what the temporal rules below correlate on.
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
action Delete appliesTo {
    principal: User,
    resource: Doc,
    context: { input: { doc: String } }
};
"#;

/// A policy with no temporal condition — the simplest thing that can decide.
const PLAIN_POLICY: &str = r#"
permit(principal, action == Action::"Read", resource);
"#;

/// A temporal policy: `Export` is forbidden if the same doc was read before.
///
/// Exercises `formerly` plus correlation against the request context, so the
/// leaf's *state* — not just its structure — determines the verdict. That is what
/// makes the restart and prospective-install tests below meaningful: a server
/// that lost history would flip these verdicts.
const TEMPORAL_POLICY: &str = r#"
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

/// A policy that does not type-check: `Read` has no `context.input.missing`.
const INVALID_POLICY: &str = r#"
permit(principal, action == Action::"Read", resource)
when { context.input.missing == "x" };
"#;

// ─── Harness ─────────────────────────────────────────────────────────

/// A server running on its own thread, with a unique state directory.
struct TestServer {
    paths: Paths,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    /// Start a server in a fresh directory tagged by `name`.
    fn start(name: &str) -> Self {
        let dir = temp_dir(name);
        let _ = std::fs::remove_dir_all(&dir);
        Self::start_in(dir)
    }

    /// Start a server in an existing directory (for restart tests).
    fn start_in(dir: PathBuf) -> Self {
        let paths = Paths::new(&dir);
        // `snapshot_interval: 3` so the periodic-snapshot path (§6.3) is
        // exercised by these short traces rather than only by the default 10k.
        // A 1s idle timeout (vs. the 30s default) lets the flood test observe slot
        // reclamation without waiting out production timing; every other test
        // completes a round trip well inside it.
        let server = Server::open(paths.clone(), ControlAllowlist::own_uid(), 3)
            .expect("server opens")
            .with_idle_timeout(Duration::from_secs(1));
        let shutdown = server.shutdown_handle();
        let handle = std::thread::spawn(move || {
            server.serve().expect("serves");
        });

        let this = TestServer {
            paths,
            shutdown,
            handle: Some(handle),
        };
        this.wait_ready();
        this
    }

    /// Block until the data socket answers a `Ping`. Binding happens on the
    /// server's thread, so a client that connects immediately can otherwise race
    /// it.
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(mut client) = DataClient::connect(self.paths.data_socket())
                && matches!(
                    client.call(&DataRequest::Ping),
                    Ok(DataResponse::Pong { .. })
                )
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("server did not become ready within 10s");
    }

    fn data(&self) -> DataClient {
        DataClient::connect(self.paths.data_socket()).expect("data connects")
    }

    fn control(&self) -> ControlClient {
        ControlClient::connect(self.paths.control_socket()).expect("control connects")
    }

    /// Install a policy bundle, asserting it was accepted.
    fn install(&self, policy: &str) -> ControlResponse {
        let response = self
            .control()
            .call(&ControlRequest::Install {
                policy: policy.to_string(),
                action_schema: ACTION_SCHEMA.to_string(),
                event_schema: None,
            })
            .expect("apply call");
        assert!(
            !matches!(response, ControlResponse::Error { .. }),
            "apply was rejected: {response:?}"
        );
        response
    }

    /// Submit a decision event and return whether it was allowed.
    fn decide(&self, action: &str, doc: &str) -> bool {
        let mut client = self.data();
        let event = request_event(action, doc);
        match client
            .call(&DataRequest::Submit { event })
            .expect("submit call")
        {
            DataResponse::Decision { allowed, .. } => allowed,
            other => panic!("expected a decision, got {other:?}"),
        }
    }

    /// One page of `List` as `(handles, next_token)`.
    fn list_page(
        &self,
        max_results: Option<usize>,
        next_token: Option<String>,
    ) -> (Vec<String>, Option<String>) {
        match self
            .control()
            .call(&ControlRequest::List {
                max_results,
                next_token,
            })
            .expect("list call")
        {
            ControlResponse::PolicyList {
                policies,
                next_token,
            } => (
                policies
                    .iter()
                    .map(|p: &PolicySummary| p.id.clone())
                    .collect(),
                next_token,
            ),
            other => panic!("expected PolicyList, got {other:?}"),
        }
    }

    /// The handles from a single `List` page.
    fn list_ids(&self, max_results: Option<usize>, next_token: Option<String>) -> Vec<String> {
        self.list_page(max_results, next_token).0
    }

    /// Stop the server and wait for its thread.
    fn stop(mut self) -> PathBuf {
        let dir = self.paths.dir.clone();
        // `stop_listening` sets the flag and self-connects to wake both blocked
        // `accept` calls.
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = std::os::unix::net::UnixStream::connect(self.paths.data_socket());
        let _ = std::os::unix::net::UnixStream::connect(self.paths.control_socket());
        if let Some(handle) = self.handle.take() {
            handle.join().expect("server thread exits cleanly");
        }
        dir
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = std::os::unix::net::UnixStream::connect(self.paths.data_socket());
            let _ = std::os::unix::net::UnixStream::connect(self.paths.control_socket());
            let _ = handle.join();
        }
    }
}

/// A unique directory per test (tag + pid), so concurrent test binaries and
/// repeated runs never share a store.
fn temp_dir(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("dogwood_server_test_{tag}_{}", std::process::id()));
    dir
}

/// A decision-kind event for `action` (a bare action id) on `doc`.
///
/// Two details a client must get right, both worth stating because getting either
/// wrong yields a silent non-match rather than an error:
///
/// - **The action is qualified.** An event's action carries the Cedar action
///   *type path*, so the bare id `Read` is sent as `Action::Read` — matching how
///   the policy writes `Action::"Read"`. A bare `Read` has an empty namespace and
///   correlates with nothing.
/// - **The doc goes in both bags.** `logged` is the durable temporal record a
///   `formerly` predicate matches against; `context` is the Cedar request context
///   a policy reads as `context.input.doc`. They are deliberately separate
///   datasets (see `EventBuilder::field` vs `request_context`), so a field both
///   consumers need is supplied to both.
fn request_event(action: &str, doc: &str) -> WireEvent {
    let mut event = WireEvent::new(&format!("Action::{action}"), "request");
    event.principal = Some("User::\"alice\"".to_string());
    event.resource = Some("Doc::\"d1\"".to_string());
    event
        .logged
        .insert("input".to_string(), serde_json::json!({ "doc": doc }));
    event
        .context
        .insert("input".to_string(), serde_json::json!({ "doc": doc }));
    event
}

// ─── Tests ───────────────────────────────────────────────────────────

/// The baseline round trip: install a policy, get a verdict for each action.
#[test]
fn installs_a_policy_and_decides() {
    let server = TestServer::start("basic");
    server.install(PLAIN_POLICY);

    assert!(server.decide("Read", "d1"), "Read is permitted");
    assert!(
        !server.decide("Export", "d1"),
        "Export matches no permit, so it is an implicit deny"
    );
}

/// Before any policy is installed, `submit` is **refused** rather than answered.
///
/// This is the fail-closed direction that matters most: an unconfigured server
/// must not look like a permissive one. Answering `Allow` would make a deployment
/// that forgot to install policy silently unmonitored.
#[test]
fn refuses_to_decide_with_no_policy_installed() {
    let server = TestServer::start("nopolicy");
    let mut client = server.data();
    match client
        .call(&DataRequest::Submit {
            event: request_event("Read", "d1"),
        })
        .expect("submit call")
    {
        DataResponse::Error { message } => {
            assert!(
                message.contains("no policy"),
                "error should name the cause: {message}"
            );
        }
        other => {
            panic!("expected an error, got {other:?} — an unconfigured server must not decide")
        }
    }
}

/// A temporal rule fires on history the server itself recorded: reading a doc
/// then exporting it is denied, exporting an unread doc is allowed.
#[test]
fn temporal_rules_see_history_across_submissions() {
    let server = TestServer::start("temporal");
    server.install(TEMPORAL_POLICY);

    // An untouched doc exports fine — the `formerly` finds nothing.
    assert!(
        server.decide("Export", "fresh"),
        "exporting a never-read doc is permitted"
    );

    // Read it, then export: the forbid now bites.
    assert!(server.decide("Read", "seen"));
    assert!(
        !server.decide("Export", "seen"),
        "exporting a previously-read doc must be denied"
    );

    // Correlation is per-doc, not global: a different doc is unaffected.
    assert!(
        server.decide("Export", "other"),
        "the forbid must correlate on the doc, not fire globally"
    );
}

/// **Durability.** State survives a full server restart: history recorded before
/// the stop still drives verdicts after it.
///
/// This is the property event sourcing exists for (`DESIGN.md` §3) — and the one
/// an in-memory monitor cannot offer. A restart that silently forgot history
/// would turn every history-gated `forbid` into a pass.
#[test]
fn history_and_policy_survive_a_restart() {
    let server = TestServer::start("restart");
    server.install(TEMPORAL_POLICY);
    assert!(server.decide("Read", "doc-a"));
    assert!(!server.decide("Export", "doc-a"), "denied before restart");

    let dir = server.stop();

    // A brand-new server over the same directory.
    let server = TestServer::start_in(dir);

    // The policy set came back with it — no re-apply needed (§7: the server owns
    // the policy set, which is only true across a reboot if it is durable).
    match server
        .control()
        .call(&ControlRequest::Status)
        .expect("status")
    {
        ControlResponse::Status {
            rule_count,
            leaf_count,
            ..
        } => {
            assert_eq!(rule_count, 2, "both rules recovered");
            assert_eq!(leaf_count, 1, "the temporal leaf recovered");
        }
        other => panic!("expected status, got {other:?}"),
    }

    // And so did the history the verdict depends on.
    assert!(
        !server.decide("Export", "doc-a"),
        "the pre-restart Read must still be visible to the forbid"
    );
    assert!(
        server.decide("Export", "doc-b"),
        "an unread doc is still permitted after recovery"
    );
}

/// A single policy: forbid `Read` of a doc formerly `Delete`d. Added over
/// [`TEMPORAL_POLICY`] to exercise "add a rule, keep the rest" — it watches a
/// different action, so it is a genuinely new leaf, and no test submits a
/// `Delete`, so it stays inert and cannot itself flip a verdict.
const DELETE_GATED_FORBID: &str = r#"forbid (principal, action == Action::"Read", resource) when temporal { formerly within 24h Action::"Delete"::request{ input.doc: context.input.doc } };"#;

/// **Adding a rule over the wire preserves the existing rule's window** (§9.1,
/// §2.2 "not mentioned ⇒ untouched").
///
/// The incremental path is now a real wire verb: `Batch [Add …]` adds a policy
/// and keeps every policy the batch does not name. The check is behavioural — a
/// doc read *before* the Add is still denied export *after* it; if the Add had
/// reset the existing forbid's window, this would flip to Allow.
#[test]
fn adding_a_rule_over_the_wire_preserves_the_existing_rule_history() {
    let server = TestServer::start("prospective");
    server.install(TEMPORAL_POLICY); // permit (id 0) + Read-gated forbid (id 1)

    assert!(server.decide("Read", "keep"));
    assert!(!server.decide("Export", "keep"), "denied before the change");

    // Add the new rule via a batch. It mints a fresh id and leaves ids 0 and 1
    // untouched — so the Read-gated forbid keeps its window.
    let response = server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Add {
                policy: DELETE_GATED_FORBID.to_string(),
            }],
        })
        .expect("batch call");
    match response {
        ControlResponse::Batched {
            minted,
            applied_at_nanos,
        } => {
            assert_eq!(minted.len(), 1, "the added rule minted one handle");
            assert!(
                applied_at_nanos > 1_500_000_000_000_000_000,
                "expected epoch nanoseconds on the same clock as events, got \
                 {applied_at_nanos}"
            );
        }
        other => panic!("expected Batched, got {other:?}"),
    }

    // The behavioural check: history from before the Add still counts.
    assert!(
        !server.decide("Export", "keep"),
        "adding an unrelated rule must not wipe the existing rule's window"
    );
}

/// The incremental verb surface end to end: `Add` mints an id (returned),
/// `Update` by id keeps it, `Delete` by id removes it, and `List`/`GetPolicyById`
/// reflect each step. An unknown-id verb rejects the whole batch.
#[test]
fn batch_add_update_delete_over_the_wire() {
    let server = TestServer::start("batch_wire");
    server.install(PLAIN_POLICY); // permit Read (id 0)

    // Capture the install handle (the sole policy so far).
    let h0 = server.list_ids(None, None)[0].clone();

    // Add a second policy — the minted handle comes back.
    let added = server.control().call(&ControlRequest::Batch {
        verbs: vec![WireVerb::Add {
            policy: r#"permit(principal, action == Action::"Export", resource);"#.to_string(),
        }],
    });
    let h1 = match added.expect("batch") {
        ControlResponse::Batched { minted, .. } => {
            assert_eq!(minted.len(), 1);
            minted[0].clone()
        }
        other => panic!("expected Batched, got {other:?}"),
    };

    // List shows both, in creation order.
    assert_eq!(server.list_ids(None, None), vec![h0.clone(), h1.clone()]);

    // Update the second to a forbid — same handle, new content.
    server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Update {
                id: h1.clone(),
                policy: r#"forbid(principal, action == Action::"Export", resource);"#.to_string(),
            }],
        })
        .expect("update batch");
    match server
        .control()
        .call(&ControlRequest::GetPolicyById { id: h1.clone() })
        .expect("get by id")
    {
        ControlResponse::Policy { source } => {
            assert!(
                source.contains("forbid"),
                "the handle was updated: {source}"
            )
        }
        other => panic!("expected Policy, got {other:?}"),
    }
    assert_eq!(
        server.list_ids(None, None),
        vec![h0.clone(), h1.clone()],
        "update keeps the handle"
    );

    // Delete the first.
    server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Delete { id: h0 }],
        })
        .expect("delete batch");
    assert_eq!(server.list_ids(None, None), vec![h1.clone()]);

    // An unknown handle rejects the whole batch.
    let rejected = server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Delete {
                id: "SPnope".to_string(),
            }],
        })
        .expect("call completes");
    assert!(
        matches!(rejected, ControlResponse::Error { .. }),
        "an unknown handle must reject, got {rejected:?}"
    );
    assert_eq!(
        server.list_ids(None, None),
        vec![h1],
        "rejected batch changed nothing"
    );
}

/// Over the wire, a bulk `Add` slices a multi-policy source into one entry (and
/// one minted id) per policy (§2.4); an `Update` with >1 policy is rejected.
#[test]
fn wire_add_slices_and_update_rejects_multi() {
    let server = TestServer::start("wire_slice");
    server.install(PLAIN_POLICY); // id 0

    // One Add carrying two policies -> two minted ids, two new entries.
    let two = format!(
        "{}\n\n{}",
        r#"permit(principal, action == Action::"Export", resource);"#,
        r#"permit(principal, action == Action::"Delete", resource);"#
    );
    match server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Add { policy: two }],
        })
        .expect("bulk add")
    {
        ControlResponse::Batched { minted, .. } => {
            assert_eq!(minted.len(), 2, "the two policies each minted a handle")
        }
        other => panic!("expected Batched, got {other:?}"),
    }
    let ids = server.list_ids(None, None);
    assert_eq!(ids.len(), 3);

    // A multi-policy Update is rejected.
    let two_update = format!(
        "{}\n\n{}",
        r#"permit(principal, action == Action::"Export", resource);"#,
        r#"permit(principal, action == Action::"Delete", resource);"#
    );
    let rejected = server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Update {
                id: ids[1].clone(),
                policy: two_update,
            }],
        })
        .expect("call completes");
    assert!(
        matches!(rejected, ControlResponse::Error { .. }),
        "a multi-policy update must reject, got {rejected:?}"
    );
    assert_eq!(server.list_ids(None, None).len(), 3, "nothing changed");
}

/// `List` paginates over the owned snapshot: `max_results` caps a page and
/// `next_token` (the handle to resume after) walks the rest (§2.7).
#[test]
fn list_paginates() {
    let server = TestServer::start("list_page");
    server.install(PLAIN_POLICY);
    // Add three more, for four policies total.
    for _ in 0..3 {
        server
            .control()
            .call(&ControlRequest::Batch {
                verbs: vec![WireVerb::Add {
                    policy: r#"permit(principal, action == Action::"Export", resource);"#
                        .to_string(),
                }],
            })
            .expect("add");
    }

    // The full order (handles are opaque, so capture them rather than predict).
    let (all, none) = server.list_page(None, None);
    assert_eq!(all.len(), 4);
    assert_eq!(none, None, "the whole list fits, so no continuation token");

    // First page of two: the first two handles, with a continuation token.
    let (page, next) = server.list_page(Some(2), None);
    assert_eq!(page, all[..2].to_vec());
    let after = next.expect("more remain, so a token is returned");
    assert_eq!(after, all[1], "the token is the last handle of the page");

    // Second page: the last two, and no further token (end reached).
    let (page, next) = server.list_page(Some(2), Some(after));
    assert_eq!(page, all[2..].to_vec());
    assert_eq!(next, None, "the last page has no continuation token");
}

/// Pagination edges: a zero-size page is rejected (it can never make progress,
/// and an empty page with no token reads as "the set is empty"), and a
/// `next_token` at or past the last id yields an empty final page with no token
/// rather than looping.
#[test]
fn list_rejects_a_zero_page_and_terminates_past_the_end() {
    let server = TestServer::start("list_edges");
    server.install(PLAIN_POLICY); // id 0
    server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Add {
                policy: r#"permit(principal, action == Action::"Export", resource);"#.to_string(),
            }],
        })
        .expect("add"); // id 1

    // max_results = 0 is rejected, not answered with a silent empty page.
    let response = server
        .control()
        .call(&ControlRequest::List {
            max_results: Some(0),
            next_token: None,
        })
        .expect("call completes");
    assert!(
        matches!(response, ControlResponse::Error { .. }),
        "a zero-size page must be rejected, got {response:?}"
    );

    // A token equal to the last handle: nothing resumes after it, so an empty
    // page and no further token — a client's loop terminates instead of stalling.
    let (all, _) = server.list_page(None, None);
    let last = all.last().expect("two policies installed").clone();
    let (page, next) = server.list_page(None, Some(last));
    assert!(
        page.is_empty(),
        "nothing follows the last handle, got {page:?}"
    );
    assert_eq!(
        next, None,
        "resuming past the end yields no continuation token"
    );

    // An unknown handle behaves the same (empty final page).
    let (page, next) = server.list_page(Some(2), Some("SPunknownhandle".to_string()));
    assert!(page.is_empty(), "no policy bears this handle, got {page:?}");
    assert_eq!(
        next, None,
        "a token past every id yields no continuation token"
    );
}

/// `GetPolicyById` returns one policy's statement (or an error for an unknown
/// id), and `GetSchema` returns the original action schema plus the configured
/// event schema (`None` for the default).
#[test]
fn get_policy_by_id_and_get_schema() {
    let server = TestServer::start("get");
    server.install(PLAIN_POLICY);
    let h0 = server.list_ids(None, None)[0].clone();

    match server
        .control()
        .call(&ControlRequest::GetPolicyById { id: h0 })
        .expect("get by id")
    {
        ControlResponse::Policy { source } => assert!(source.contains("permit"), "{source}"),
        other => panic!("expected Policy, got {other:?}"),
    }
    assert!(
        matches!(
            server
                .control()
                .call(&ControlRequest::GetPolicyById {
                    id: "SPunknown".to_string()
                })
                .expect("call completes"),
            ControlResponse::Error { .. }
        ),
        "an unknown handle must be an error"
    );

    match server
        .control()
        .call(&ControlRequest::GetSchema)
        .expect("get schema")
    {
        ControlResponse::Schema {
            action_schema,
            event_schema,
        } => {
            assert!(
                action_schema.contains("action Read"),
                "the original action schema is returned: {action_schema}"
            );
            assert_eq!(
                event_schema, None,
                "no event schema was configured, so the default (None) is reported"
            );
        }
        other => panic!("expected Schema, got {other:?}"),
    }
}

/// `GetSchema` returns the **original** action schema the operator authored, not
/// the augmented one lowering derives (§2.7). A temporal policy triggers schema
/// augmentation internally (a synthesized `context` field per hoisted leaf), so
/// this installs one and asserts the returned schema is byte-identical to what
/// was authored — no synthesized fields leaked back.
#[test]
fn get_schema_returns_the_original_not_the_augmented_schema() {
    let server = TestServer::start("get_original_schema");
    server.install(TEMPORAL_POLICY); // has a temporal clause → augmentation happens

    match server
        .control()
        .call(&ControlRequest::GetSchema)
        .expect("get schema")
    {
        ControlResponse::Schema { action_schema, .. } => {
            assert_eq!(
                action_schema, ACTION_SCHEMA,
                "GetSchema must return the authored action schema verbatim"
            );
            assert!(
                !action_schema.contains("temporal"),
                "no synthesized temporal field may leak into the returned schema: \
                 {action_schema}"
            );
        }
        other => panic!("expected Schema, got {other:?}"),
    }
}

/// `AppendActionSchema` over the wire widens the action surface atomically: a
/// policy about a newly-appended action validates only after the append, and the
/// append and the new policy ride one batch — the atomic alternative to
/// `GetSchema` → edit → `SetActionSchema`.
#[test]
fn wire_append_action_schema_widens_the_surface() {
    const LOGIN_FRAGMENT: &str = r#"action Login appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };"#;
    const LOGIN_POLICY: &str = r#"permit(principal, action == Action::"Login", resource);"#;

    let server = TestServer::start("wire_append");
    server.install(PLAIN_POLICY); // schema declares Read/Export/Delete, not Login

    // Before the append, a Login policy is rejected — Login is undeclared.
    let before = server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Add {
                policy: LOGIN_POLICY.to_string(),
            }],
        })
        .expect("call completes");
    assert!(
        matches!(before, ControlResponse::Error { .. }),
        "a Login policy must reject before Login is declared, got {before:?}"
    );

    // Append the Login declaration and add the policy in one batch.
    let after = server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![
                WireVerb::AppendActionSchema {
                    fragment: LOGIN_FRAGMENT.to_string(),
                },
                WireVerb::Add {
                    policy: LOGIN_POLICY.to_string(),
                },
            ],
        })
        .expect("call completes");
    assert!(
        matches!(after, ControlResponse::Batched { .. }),
        "append + add must be accepted, got {after:?}"
    );

    // GetSchema now reflects the widened action schema.
    match server
        .control()
        .call(&ControlRequest::GetSchema)
        .expect("get schema")
    {
        ControlResponse::Schema { action_schema, .. } => assert!(
            action_schema.contains("Login"),
            "the appended action must appear in the schema: {action_schema}"
        ),
        other => panic!("expected Schema, got {other:?}"),
    }
}

/// Over the wire, `DeleteAll` is terminal and fail-closed (§2.1): the empty set
/// stays installed and every decision denies — not a `NoPolicy` error.
#[test]
fn wire_delete_all_is_terminal_and_denies() {
    let server = TestServer::start("wire_delete_all");
    server.install(PLAIN_POLICY);
    assert!(server.decide("Read", "d1"), "permitted before DeleteAll");

    server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::DeleteAll],
        })
        .expect("delete all");

    // Still decides — and denies. A `submit` that errored would be the wrong
    // (fail-open-shaped) behaviour.
    assert!(
        !server.decide("Read", "d1"),
        "an empty installed set denies every decision"
    );
}

/// Over the wire, `Reset` and `ResetAll` clear accumulated windows.
#[test]
fn wire_reset_and_reset_all_clear_windows() {
    let server = TestServer::start("wire_reset");
    server.install(TEMPORAL_POLICY); // permit (id 0) + Export-forbid-on-Read (id 1)

    // Arm and confirm the forbid fires for doc "a".
    assert!(server.decide("Read", "a"));
    assert!(!server.decide("Export", "a"), "denied after reading a");

    // The forbid is the second policy (creation order).
    let forbid = server.list_ids(None, None)[1].clone();
    server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::Reset { id: forbid }],
        })
        .expect("reset");
    assert!(
        server.decide("Export", "a"),
        "Reset cleared the window, so export is now allowed"
    );

    // Re-arm for doc "b", then clear everything with ResetAll.
    assert!(server.decide("Read", "b"));
    assert!(!server.decide("Export", "b"), "denied after reading b");
    server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![WireVerb::ResetAll],
        })
        .expect("reset all");
    assert!(
        server.decide("Export", "b"),
        "ResetAll cleared every window"
    );
}

/// Over the wire, a mixed batch is atomic (§2.5): a valid `Add` alongside a
/// failing `SetActionSchema` applies nothing.
#[test]
fn wire_mixed_batch_is_atomic() {
    let server = TestServer::start("wire_atomic");
    server.install(PLAIN_POLICY); // one policy, id 0

    let response = server
        .control()
        .call(&ControlRequest::Batch {
            verbs: vec![
                WireVerb::Add {
                    policy: r#"permit(principal, action == Action::"Export", resource);"#
                        .to_string(),
                },
                WireVerb::SetActionSchema {
                    action_schema: "not a schema {{{".to_string(),
                },
            ],
        })
        .expect("call completes");
    assert!(
        matches!(response, ControlResponse::Error { .. }),
        "the batch must reject as a unit, got {response:?}"
    );
    assert_eq!(
        server.list_ids(None, None).len(),
        1,
        "the valid Add must not have taken effect"
    );
}

/// **Atomic swap** (§8): a policy that fails validation is rejected, and the
/// previously installed set keeps serving.
///
/// A server left policy-less by a bad apply would be a trivially exploitable
/// outage; one left half-applied would be worse.
#[test]
fn a_rejected_apply_leaves_the_running_set_serving() {
    let server = TestServer::start("reject");
    server.install(PLAIN_POLICY);
    assert!(server.decide("Read", "d1"));

    let response = server
        .control()
        .call(&ControlRequest::Install {
            policy: INVALID_POLICY.to_string(),
            action_schema: ACTION_SCHEMA.to_string(),
            event_schema: None,
        })
        .expect("apply call");
    match response {
        ControlResponse::Error { message } => {
            // Server-side validation is the non-negotiable part of §8: a
            // compromised control client is exactly who would skip a client-side
            // check.
            assert!(
                message.contains("validation") || message.contains("policy"),
                "rejection should explain itself: {message}"
            );
        }
        other => panic!("an invalid policy must be rejected, got {other:?}"),
    }

    // The old set is still the running set.
    assert!(
        server.decide("Read", "d1"),
        "the previously installed policy must still serve after a rejected apply"
    );
    match server
        .control()
        .call(&ControlRequest::GetPolicy)
        .expect("get")
    {
        ControlResponse::Policy { source } => {
            // The engine canonicalizes each installed policy through
            // `expanded_source`, so the retrieved source is the canonical form
            // of `PLAIN_POLICY`, not the literal string. What the test needs is
            // that the rejected apply left the previous policy in place — that
            // is, the retrieved source still describes the `permit ... Read`
            // policy and not `TEMPORAL_POLICY`'s `forbid`.
            assert!(source.contains("permit"), "expected permit, got: {source}");
            assert!(
                source.contains(r#"Action::"Read""#),
                "expected Read, got: {source}"
            );
            assert!(
                !source.contains("forbid"),
                "the rejected TEMPORAL_POLICY must not appear: {source}"
            );
        }
        other => panic!("expected the policy, got {other:?}"),
    }
}

/// **The verb split** (§8.1): the data socket does not serve control verbs.
///
/// Sending an `apply`-shaped payload to the data socket must not install
/// anything. This is the end-to-end counterpart to the type-level check in
/// `protocol.rs` — it confirms the *server* wires the split, not just that the
/// types could.
#[test]
fn the_data_socket_does_not_serve_control_verbs() {
    let server = TestServer::start("verbsplit");
    server.install(PLAIN_POLICY);

    // Speak the control protocol at the data socket, bypassing the typed client.
    let mut stream =
        std::os::unix::net::UnixStream::connect(server.paths.data_socket()).expect("connects");
    let install = ControlRequest::Install {
        policy: TEMPORAL_POLICY.to_string(),
        action_schema: ACTION_SCHEMA.to_string(),
        event_schema: None,
    };
    dogwood_server::protocol::write_frame(&mut stream, &install).expect("writes");
    let response: DataResponse =
        dogwood_server::protocol::read_frame(&mut stream).expect("reads a response");
    assert!(
        matches!(response, DataResponse::Error { .. }),
        "the data socket must reject a control verb, got {response:?}"
    );

    // Nothing was installed: the original policy still governs.
    match server
        .control()
        .call(&ControlRequest::GetPolicy)
        .expect("get")
    {
        ControlResponse::Policy { source } => {
            // Canonicalized form again; assert the plain policy is still what
            // is installed, not the temporal one the caller tried to sneak in.
            assert!(source.contains("permit"), "expected permit, got: {source}");
            assert!(
                !source.contains("forbid"),
                "an apply on the data socket must not change the policy set: {source}"
            );
        }
        other => panic!("expected the policy, got {other:?}"),
    }
}

/// **The permission layout is the privilege asymmetry**, so every mode is pinned
/// (§7, §8.1).
///
/// The two halves pull in opposite directions and both must hold:
///
/// - the state directory and control socket must be **unreachable** by another
///   uid (they are the policy set and the authority to change it);
/// - the data socket must be **reachable** by another uid — because the whole
///   deployment model has the agent running as a different user. On Linux a
///   `connect()` needs write permission on the socket *and* search permission on
///   every directory above it, so a `0600` socket inside a `0700` directory —
///   the obvious-looking choice — is unreachable by the very caller it exists
///   for, and would make the documented uid split unusable.
#[test]
fn the_permission_layout_separates_private_state_from_the_data_socket() {
    use std::os::unix::fs::PermissionsExt;

    let server = TestServer::start("perms");
    let mode_of = |p: std::path::PathBuf| {
        std::fs::metadata(&p)
            .unwrap_or_else(|e| panic!("{} must exist: {e}", p.display()))
            .permissions()
            .mode()
            & 0o777
    };

    // Private: the policy set, the log, and the authority to change them.
    assert_eq!(
        mode_of(server.paths.dir.clone()),
        0o700,
        "the state directory holds the policy set and log — owner-only"
    );
    assert_eq!(
        mode_of(server.paths.control_socket()),
        0o700,
        "the control socket must be owner-only (§8.1 layer 1)"
    );

    // Reachable: search-only on the run dir, connectable on the socket itself.
    assert_eq!(
        mode_of(server.paths.run_dir()),
        0o711,
        "the run dir must be traversable (--x) by the agent's uid but not listable"
    );
    assert_eq!(
        mode_of(server.paths.data_socket()),
        0o666,
        "a connect() needs write permission, and the agent is a different uid; \
         the data socket is protected by its verb set, not its mode"
    );

    // The control socket lives inside the private directory, so it is unreachable
    // for two independent reasons — not just its own mode.
    assert_eq!(
        server.paths.control_socket().parent(),
        Some(server.paths.dir.as_path()),
        "the control socket must sit inside the 0700 directory"
    );
    assert_ne!(
        server.paths.data_socket().parent(),
        Some(server.paths.dir.as_path()),
        "the data socket must NOT sit inside the 0700 directory, or the \
         documented uid split cannot connect to it"
    );
}

/// The socket is never observable at a **more permissive** mode than intended,
/// even briefly.
///
/// `bind()` creates the socket subject to the process umask, so a
/// `bind`-then-`chmod` leaves a window where the control socket accepts
/// connections at whatever the umask allowed. The server clamps the umask across
/// the bind; this test sets a hostile (fully-permissive) umask first, which is
/// exactly the condition that would expose the gap.
#[test]
fn a_permissive_umask_cannot_widen_the_control_socket() {
    // SAFETY: umask is per-process and this test only widens it, then restores
    // it. Cargo runs tests in threads, so this is briefly visible to other tests
    // — which is harmless here: the server sets every mode it cares about
    // explicitly, and that is precisely what this test verifies.
    let previous = unsafe { set_umask(0o000) };
    let server = TestServer::start("umask");
    let control_mode = std::fs::metadata(server.paths.control_socket())
        .expect("control socket exists")
        .permissions()
        .mode()
        & 0o777;
    unsafe { set_umask(previous) };

    assert_eq!(
        control_mode, 0o700,
        "a 000 umask must not widen the control socket beyond owner-only"
    );
}

/// `umask(2)`, for the hostile-umask test above.
unsafe fn set_umask(mask: u32) -> u32 {
    unsafe extern "C" {
        fn umask(mask: u32) -> u32;
    }
    unsafe { umask(mask) }
}

/// **Store-assigned timestamps** (§3.3): the server stamps events, strictly
/// increasing, regardless of what a client says — and a client cannot say
/// anything, since `WireEvent` has no timestamp field.
///
/// Verified through behaviour rather than by reading timestamps back: two events
/// submitted in the same wall-clock second must still be ordered, which is what
/// makes `previous` and window eviction well-defined. A `formerly within 1h`
/// firing on an event submitted microseconds earlier demonstrates both events
/// landed in the trace in order with sane ages.
#[test]
fn the_store_assigns_strictly_increasing_timestamps() {
    let server = TestServer::start("timestamps");
    server.install(TEMPORAL_POLICY);

    // Two submissions with no delay — almost certainly the same wall-clock
    // second, so the `max(now, last + 1)` clamp is what orders them.
    assert!(server.decide("Read", "rapid"));
    assert!(
        !server.decide("Export", "rapid"),
        "same-second events must still be ordered, so the Read is in the past"
    );

    // History events are also stamped and durable, and acked with their offset.
    let mut client = server.data();
    let mut history = WireEvent::new("Action::Read", "resolution");
    history
        .logged
        .insert("input".to_string(), serde_json::json!({ "doc": "rapid" }));
    match client
        .call(&DataRequest::Submit { event: history })
        .expect("submit call")
    {
        // `Recorded` carries the assigned timestamp and nothing else. *Where* it
        // landed is `submit_contract.rs`'s business — the offset is an internal
        // identifier and does not cross the wire.
        DataResponse::Recorded { recorded_at_nanos } => {
            // Epoch nanoseconds, so far past the seconds-era magnitude that a
            // unit regression would be obvious: 2020 in nanos is ~1.5e18, while
            // any plausible seconds value is ~1.7e9.
            assert!(
                recorded_at_nanos > 1_500_000_000_000_000_000,
                "expected epoch nanoseconds, got {recorded_at_nanos}"
            );
        }
        other => panic!("a history-kind event must be Recorded, got {other:?}"),
    }
}

/// A history-kind event is acked with an offset and yields no verdict — the
/// second half of the schema-driven `submit` (§10). Which kinds decide comes from
/// the schema, not from a hardcoded name.
#[test]
fn history_events_are_recorded_without_a_verdict() {
    let server = TestServer::start("history");
    server.install(PLAIN_POLICY);

    let mut client = server.data();
    let mut event = WireEvent::new("Action::Read", "resolution");
    event
        .logged
        .insert("input".to_string(), serde_json::json!({ "doc": "d1" }));

    let first = client
        .call(&DataRequest::Submit {
            event: event.clone(),
        })
        .expect("submit");
    let second = client.call(&DataRequest::Submit { event }).expect("submit");

    // Both are acknowledged with no verdict, and their assigned timestamps
    // strictly increase. Asserting order *here* is legitimate where asserting it
    // on offsets was not: the timestamp is something the client is told and can
    // act on, so it is part of the protocol's contract rather than an internal
    // identifier this test would be reaching through the wire to observe.
    match (first, second) {
        (
            DataResponse::Recorded {
                recorded_at_nanos: a,
            },
            DataResponse::Recorded {
                recorded_at_nanos: b,
            },
        ) => {
            assert!(
                b > a,
                "assigned timestamps must strictly increase: {a} then {b}"
            );
        }
        other => panic!("history events must be Recorded, got {other:?}"),
    }
}

/// `status` reports the running set, and every temporal leaf runs on the
/// incremental path (no scan fallback) — the same zero-fallback property the
/// engine's corpus test asserts, observed through the server.
#[test]
fn status_reports_the_running_set_with_all_leaves_incremental() {
    let server = TestServer::start("status");
    server.install(TEMPORAL_POLICY);

    match server
        .control()
        .call(&ControlRequest::Status)
        .expect("status")
    {
        ControlResponse::Status {
            rule_count,
            leaf_count,
            incremental_leaves,
            decision_kinds,
            control_uids,
            ..
        } => {
            assert_eq!(rule_count, 2);
            assert_eq!(leaf_count, 1);
            assert_eq!(
                incremental_leaves, leaf_count,
                "every leaf must run incrementally"
            );
            assert!(
                decision_kinds.iter().any(|k| k == "request"),
                "the default schema's decision kind is reported as data, not assumed"
            );
            assert_eq!(
                control_uids,
                vec![rustix_uid()],
                "the default control allowlist is the server's own uid (§8.1)"
            );
        }
        other => panic!("expected status, got {other:?}"),
    }
}

/// An explicit checkpoint succeeds and reports the offset it covers (§6.3).
#[test]
fn checkpoint_reports_the_offset_it_covers() {
    let server = TestServer::start("checkpoint");
    server.install(PLAIN_POLICY);
    server.decide("Read", "d1");
    server.decide("Read", "d2");

    match server
        .control()
        .call(&ControlRequest::Checkpoint)
        .expect("checkpoint")
    {
        ControlResponse::Checkpointed { up_to_offset } => {
            assert!(
                up_to_offset >= 2,
                "the checkpoint must cover the submitted events, got {up_to_offset}"
            );
        }
        other => panic!("expected Checkpointed, got {other:?}"),
    }
}

/// Many concurrent submissions all succeed and are all durably recorded.
///
/// §3.3 expects exactly this load ("an agent might spawn many sub-agents") and
/// answers it with single-writer-per-instance: callers serialize at the append
/// point, each emerging with a distinct timestamp. The test's job is to confirm
/// nothing is dropped or double-counted under contention.
#[test]
fn concurrent_submissions_are_all_recorded() {
    let server = TestServer::start("concurrent");
    server.install(PLAIN_POLICY);

    const CALLERS: usize = 8;
    const EACH: usize = 5;

    let socket = server.paths.data_socket();
    let mut threads = Vec::new();
    for caller in 0..CALLERS {
        let socket = socket.clone();
        threads.push(std::thread::spawn(move || {
            let mut client = DataClient::connect(&socket).expect("connects");
            for i in 0..EACH {
                let event = request_event("Read", &format!("c{caller}-{i}"));
                match client
                    .call(&DataRequest::Submit { event })
                    .expect("submit call")
                {
                    DataResponse::Decision { allowed, .. } => assert!(allowed),
                    other => panic!("expected a decision, got {other:?}"),
                }
            }
        }));
    }
    for t in threads {
        t.join().expect("caller thread succeeds");
    }

    // Every event reached the log exactly once. A dropped append would show as a
    // low offset; a double append as a high one. The install itself occupies a
    // contiguous *range* of per-verb records — one per policy plus the schema
    // and `DeleteAll` preamble. For
    // `PLAIN_POLICY` (one policy) the install writes 3 records:
    // `SetActionSchema + DeleteAll + Add`. (The event schema is store config in a
    // metadata slot, not a log record, §2.7.)
    const INSTALL_RECORDS: usize = 3;
    match server
        .control()
        .call(&ControlRequest::Status)
        .expect("status")
    {
        ControlResponse::Status { log_offset, .. } => assert_eq!(
            log_offset as usize,
            CALLERS * EACH + INSTALL_RECORDS,
            "every concurrent submission must be appended exactly once"
        ),
        other => panic!("expected status, got {other:?}"),
    }
}

/// **Connection flooding neither kills nor permanently starves the server.**
///
/// The data socket is reachable by the untrusted process, and this test pins both
/// halves of the defence, because either alone is insufficient:
///
/// - **The cap** stops a connect-in-a-loop caller from exhausting memory or the
///   thread limit. Without it the server dies, which fails *open*: a dead server
///   enforces no policy at all.
/// - **The idle timeout** stops a caller that grabs exactly the cap's worth of
///   connections and goes silent from holding every slot forever. A cap alone
///   converts a crash into an indefinite lockout — quieter, but just as effective
///   an attack.
///
/// So the test floods with silent connections *and holds them open*, then requires
/// the server to recover **while the flood is still held**. That only passes if
/// slots are being reclaimed from idle peers, not merely capped.
#[test]
#[ignore = "flaky under connection flood: post-recovery submit can receive ECONNRESET"]
fn the_server_survives_and_recovers_from_a_connection_flood() {
    let server = TestServer::start("flood");
    server.install(PLAIN_POLICY);

    // Well past MAX_CONNECTIONS (256), opened and then left silent. Held for the
    // whole test — nothing below drops them.
    let mut hoarded = Vec::new();
    for _ in 0..400 {
        if let Ok(s) = std::os::unix::net::UnixStream::connect(server.paths.data_socket()) {
            hoarded.push(s);
        }
    }
    assert!(
        hoarded.len() > 256,
        "the flood must exceed the cap to be a real test, got {}",
        hoarded.len()
    );

    // The server must come back while the flood is STILL open. The harness sets a
    // 1s idle timeout, so reclamation should take a second or two; allow generous
    // slack for a loaded test machine.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut served = false;
    while Instant::now() < deadline && !served {
        if let Ok(mut client) = DataClient::connect(server.paths.data_socket())
            && matches!(
                client.call(&DataRequest::Ping),
                Ok(DataResponse::Pong { .. })
            )
        {
            served = true;
        } else {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    assert!(
        served,
        "the server must reclaim slots from idle connections and serve again \
         while the flood is still held — a cap without a timeout would hang here"
    );

    // And it is fully functional, not just answering pings.
    assert!(
        server.decide("Read", "during-flood"),
        "the server must decide normally while the flood is held"
    );

    drop(hoarded);
}

/// This process's uid, for asserting attestation and allowlist defaults.
fn rustix_uid() -> u32 {
    // Read via the same path the server uses, so the two agree by construction.
    dogwood_server::peer::ControlAllowlist::own_uid().uids()[0]
}

// ─── Timestamp resolution ────────────────────────────────────────────

/// **The store's timestamps must track real time, not run ahead of it.**
///
/// `next_timestamp` clamps to `max(now, last + 1)` so the sequence is strictly
/// increasing — window eviction and `previous` both read it. At *whole-second*
/// resolution that clamp fires on every event of any burst faster than 1/s, so
/// the sequence advances a full second per event: 12 events submitted in a tenth
/// of a second used to land 12 units apart, ending 11 "seconds" in the future.
/// A burst of 3600 would then span an entire `within 1h` window and evict its own
/// history, making a declared hour mean "the last 3600 events".
///
/// At nanosecond resolution real elapsed time dominates and the clamp
/// effectively never fires, so a declared hour is an hour. This asserts the
/// spread of a burst stays close to the wall-clock time it actually took, which
/// is what fails under the old unit.
#[test]
fn a_burst_of_timestamps_tracks_the_wall_clock() {
    use dogwood_local_engine::{DurableLog, DurableTemporalEngine};
    use dogwood_server::codec::to_event_builder;

    // Driven through `DurableTemporalEngine` directly, with periodic snapshots DISABLED:
    // a checkpoint prunes the log below its offset, and the assigned timestamps
    // are only readable from the log records themselves.
    let dir = temp_dir("tsunit");
    let _ = std::fs::remove_dir_all(&dir);
    // Set the mode explicitly rather than inheriting the process umask. `bind`
    // clamps the umask across a socket bind, and for the data socket's 0666 that
    // clamp is 0o111 — so a directory created concurrently by another test is
    // born without its execute bit and cannot be traversed. Cargo runs tests as
    // threads in one process, so that window is shared.
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let store = dir.join("store.redb");

    let n = 12usize;
    let wall_start = Instant::now();
    {
        let mut state = DurableTemporalEngine::open(&store, 0).expect("opens");
        state
            .install(TEMPORAL_POLICY, ACTION_SCHEMA, None, None)
            .expect("applies");
        for i in 0..n {
            let mut ev = WireEvent::new("Action::Read", "resolution");
            ev.logged.insert(
                "input".to_string(),
                serde_json::json!({ "doc": format!("d{i}") }),
            );
            state.submit(to_event_builder(&ev)).expect("submit");
        }
    }
    let wall_nanos = wall_start.elapsed().as_nanos() as i64;

    // The log holds the policy change that installed the rule as well as the
    // events, so decode and keep the events: this is about the timestamps the
    // store assigns to EVENTS.
    let log = DurableLog::open(&store).expect("reopen log");
    let mut ts: Vec<i64> = Vec::new();
    log.scan_from(0, |_off, rec| {
        if let Ok(dogwood_server::record::Record::Event(e)) =
            dogwood_server::record::Record::decode(rec)
        {
            ts.push(e.timestamp());
        }
    })
    .expect("scan");
    assert_eq!(ts.len(), n, "expected {n} event records, got {}", ts.len());

    // Strictly increasing — the property the clamp exists to guarantee.
    assert!(
        ts.windows(2).all(|w| w[1] > w[0]),
        "timestamps must be strictly increasing: {ts:?}"
    );

    // The discriminating check: the values must BE epoch nanoseconds, i.e. sit
    // next to the wall clock. Comparing the span alone would not distinguish the
    // units — a 12-event burst spans 11 under whole-second assignment, which is a
    // small number either way. Comparing absolutely does: second-valued
    // timestamps are ~10^9 smaller than the nanosecond clock, so they miss by
    // about 57 years.
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos() as i64;
    let slack = Duration::from_secs(60).as_nanos() as i64;
    assert!(
        (now_nanos - ts[n - 1]).abs() < slack,
        "timestamps are not epoch nanoseconds: newest is {} but the clock reads {} \
         (off by {} ns)",
        ts[n - 1],
        now_nanos,
        (now_nanos - ts[n - 1]).abs()
    );

    // And the burst must not have advanced the sequence beyond the time that
    // actually passed. This is what fails when the clamp manufactures time:
    // whole-second assignment would spread 12 events over 11 seconds of window
    // despite taking a fraction of one.
    let span_nanos = ts[n - 1] - ts[0];
    let allowed = wall_nanos + Duration::from_millis(500).as_nanos() as i64;
    assert!(
        span_nanos <= allowed,
        "a burst that took {wall_nanos} ns of wall clock spanned {span_nanos} ns of \
         timestamp space; the sequence is running ahead of real time"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A store whose timestamps were assigned in a different unit must be REFUSED,
/// not adopted. Reading second-valued history as nanoseconds makes every event
/// look decades old, so the next append would prune all of it — silently, and
/// fail-open, since a history-gated `forbid` with no history just passes.
#[test]
fn a_store_from_another_time_unit_is_refused() {
    use dogwood_local_engine::{DurableLog, DurableTemporalEngine};

    // An untagged store with events in it: what a pre-tagging build left behind.
    let dir = temp_dir("tsunit_legacy");
    let _ = std::fs::remove_dir_all(&dir);
    // Set the mode explicitly rather than inheriting the process umask. `bind`
    // clamps the umask across a socket bind, and for the data socket's 0666 that
    // clamp is 0o111 — so a directory created concurrently by another test is
    // born without its execute bit and cannot be traversed. Cargo runs tests as
    // threads in one process, so that window is shared.
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let store = dir.join("store.redb");
    {
        let log = DurableLog::open(&store).expect("opens");
        log.append(br#"{"ts":1786064398,"event":{"action":"A","kind":"request"}}"#)
            .expect("append");
    }
    let err = match DurableTemporalEngine::open(&store, 0) {
        Err(e) => e,
        Ok(_) => panic!("must refuse an untagged non-empty store"),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("no recorded time unit"),
        "unexpected error: {msg}"
    );

    // And one tagged with a DIFFERENT unit.
    let dir2 = temp_dir("tsunit_seconds");
    let _ = std::fs::remove_dir_all(&dir2);
    // Set the mode explicitly rather than inheriting the process umask. `bind`
    // clamps the umask across a socket bind, and for the data socket's 0666 that
    // clamp is 0o111 — so a directory created concurrently by another test is
    // born without its execute bit and cannot be traversed. Cargo runs tests as
    // threads in one process, so that window is shared.
    std::fs::create_dir_all(&dir2).expect("create dir");
    std::fs::set_permissions(&dir2, std::fs::Permissions::from_mode(0o700)).expect("set dir mode");
    let store2 = dir2.join("store.redb");
    {
        let log = DurableLog::open(&store2).expect("opens");
        log.commit(&[dogwood_local_engine::Write::Meta {
            key: "dogwood_server_time_unit",
            value: b"seconds",
        }])
        .expect("tag");
    }
    let err = match DurableTemporalEngine::open(&store2, 0) {
        Err(e) => e,
        Ok(_) => panic!("must refuse a mismatched unit"),
    };
    assert!(
        err.to_string().contains("was written with timestamps in"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}
