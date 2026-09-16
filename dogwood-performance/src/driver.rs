//! Uniform drivers for the implementations under comparison.
//!
//! # What is being compared, and the caveat that governs everything here
//!
//! The two implementations do **different amounts of work by design**, and any
//! honest report has to lead with that rather than bury it:
//!
//! | | reference (`InMemoryTemporalEngine`) | server (`DurableTemporalEngine`) |
//! |---|---|---|
//! | durability | none — state is RAM, lost on exit | every event `fsync`ed before the call returns |
//! | temporal evaluation | rescans history at each decision | incremental, window-bounded |
//! | boundary | in-process function call | in-process, or framed IPC over a Unix socket |
//!
//! So "the server is slower per event" is not a finding — it is the price of
//! durability, and the [`fsync_floor`] probe measures that price directly so a
//! reader can subtract it. Conversely "the reference is slower at 1000 policies"
//! *is* a finding, because it reflects an algorithmic difference (rescan vs.
//! incremental) rather than a durability choice.
//!
//! The drivers exist so neither engine can be accidentally advantaged: they are
//! fed from one [`GenEvent`] stream, they observe the same events in the same
//! order, and each returns the same `Option<bool>` verdict so a benchmark can
//! assert the two agree before trusting any timing.

use dogwood_language::{Authorizer, Event, Value};
use dogwood_local_engine::{DurableTemporalEngine, Outcome, Verb};
use dogwood_server::codec::to_event_builder;
use dogwood_server::protocol::WireEvent;

use crate::workload::{ACTION_SCHEMA, GenEvent, Pinning, policy_set};

/// A verdict stream, for cross-checking that two engines agree.
pub type Verdicts = Vec<Option<bool>>;

// ─── The reference implementation ────────────────────────────────────

/// Drive the in-memory reference engine over `events`, returning per-event
/// verdicts (`None` for a history event).
///
/// This is the **oracle**: the frontend's default `InMemoryTemporalEngine`, whose
/// verdicts the whole regression corpus is validated against. It keeps history in
/// RAM and re-runs the interpreter over the trace at each decision point, so its
/// per-decision cost grows with both history length and policy count.
pub fn run_reference(
    policies: dogwood_language::LoweredPolicySet,
    events: &[GenEvent],
) -> Verdicts {
    let mut authorizer = Authorizer::new(policies);
    events
        .iter()
        .map(|e| {
            let event = to_event(e);
            authorizer.is_authorized(&event).map(|r| r.allowed())
        })
        .collect()
}

/// Render a generated event as a frontend [`Event`].
///
/// `input` goes in **both** bags by design: the logged bag is the durable temporal
/// record a `formerly` predicate matches against, and the request context is what
/// a `context.<path>` clause (and a pin's request side) reads. Supplying only one
/// leaves the other consumer's read unresolved — which would silently make every
/// correlation fail and turn the benchmark into a measurement of the non-matching
/// path.
pub fn to_event(e: &GenEvent) -> Event {
    Event::builder(&format!("Example::Action::{}", e.action), "request")
        .timestamp(e.ts)
        .principal(&format!("Example::OAuthUser::\"{}\"", e.user))
        .resource("Example::Gateway::\"gw1\"")
        .field("input", "user", Value::String(e.user.clone()))
        .field("input", "server", Value::String(e.server.clone()))
        .field("input", "document", Value::String("d".to_string()))
        .field("meta", "session_id", Value::String(e.session.clone()))
        .request_context("input", "user", Value::String(e.user.clone()))
        .request_context("input", "server", Value::String(e.server.clone()))
        .request_context("input", "document", Value::String("d".to_string()))
        .request_context("meta", "session_id", Value::String(e.session.clone()))
        .build()
}

// ─── The server ──────────────────────────────────────────────────────

/// An in-process server, with its durable store in a temp directory.
///
/// Benchmarking `DurableTemporalEngine` directly (rather than over the socket) isolates the
/// *engine plus durability* cost from the IPC cost. The socket adds framing and a
/// syscall round trip; measuring both separately is what lets a reader see which
/// one matters — and for a path that `fsync`s, the answer is neither.
pub struct ServerHarness {
    pub state: DurableTemporalEngine,
    dir: std::path::PathBuf,
}

impl ServerHarness {
    /// Open a server and install a policy set of `count` rules under `pinning`.
    ///
    /// `snapshot_interval: 0` disables periodic checkpoints so they do not land
    /// mid-measurement as an occasional multi-millisecond outlier. Checkpoint cost
    /// is real, but it is a *separate* thing to measure, not noise to sprinkle
    /// through a latency distribution.
    pub fn new(tag: &str, count: usize, pinning: Pinning) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "dogwood_perf_{tag}_{}_{}",
            std::process::id(),
            count
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create bench dir");

        let mut state =
            DurableTemporalEngine::open(dir.join("store.redb"), 0).expect("server state opens");
        state
            .install(
                &policy_set(count),
                ACTION_SCHEMA,
                Some(pinning.event_schema()),
                None,
            )
            .expect("policy set installs");
        ServerHarness { state, dir }
    }

    /// Submit one event, returning its verdict (`None` for a history event).
    pub fn submit(&mut self, e: &GenEvent) -> Option<bool> {
        match self
            .state
            .submit(to_event_builder(&to_wire(e)))
            .map(|s| s.outcome)
        {
            Ok(Outcome::Decision(r)) => Some(r.allowed()),
            Ok(Outcome::Recorded) => None,
            Err(err) => panic!("server rejected a benchmark event: {err}"),
        }
    }

    /// Submit the whole stream.
    pub fn run(&mut self, events: &[GenEvent]) -> Verdicts {
        events.iter().map(|e| self.submit(e)).collect()
    }

    /// Re-lower the **running** set in place, returning how many leaves kept their
    /// accumulated window across the rebuild.
    ///
    /// Distinct from [`new`](Self::new) in the way that matters for measurement:
    /// `new` applies into an empty store, so it never exercises the transplant, the
    /// swap, or the release of the previous set's state. This *re*-apply does all
    /// three, and those are the parts whose cost tracks retained history rather
    /// than policy count.
    ///
    /// It goes through the verb-batch **keep-window** path, not `install`: a
    /// `SetActionSchema` with the unchanged schema re-lowers and re-validates the
    /// whole set while carrying every leaf's window (nothing is marked fresh), so
    /// `leaves_retained` is the full leaf count and the transplant is what gets
    /// timed. An `install` would be reborn-all (`POLICY_INSTALL_SEMANTICS.md`
    /// §2.1) — it transplants nothing and would return 0.
    pub fn reapply(&mut self) -> usize {
        self.state
            .batch(vec![Verb::SetActionSchema {
                action_schema: ACTION_SCHEMA.to_string(),
            }])
            .expect("re-lowering the identical set keeps its windows")
            .leaves_retained
    }
}

impl Drop for ServerHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Render a generated event as a [`WireEvent`].
///
/// Note the absent timestamp: the wire form carries none, because the store
/// assigns it at the append point (`DESIGN.md` §3.3). The reference driver uses
/// `GenEvent::ts` and the server mints its own, so the two see *different*
/// absolute times — which is fine for the temporal windows used here (1h, while
/// the whole benchmark runs in well under that), but is exactly why verdict
/// cross-checks in the benchmarks compare **shape**, not timing-sensitive edges.
pub fn to_wire(e: &GenEvent) -> WireEvent {
    let mut w = WireEvent::new(&format!("Example::Action::{}", e.action), "request");
    w.principal = Some(format!("Example::OAuthUser::\"{}\"", e.user));
    w.resource = Some("Example::Gateway::\"gw1\"".to_string());
    let input = serde_json::json!({
        "user": e.user, "server": e.server, "document": "d"
    });
    let meta = serde_json::json!({ "session_id": e.session });
    w.logged.insert("input".to_string(), input.clone());
    w.logged.insert("meta".to_string(), meta.clone());
    w.context.insert("input".to_string(), input);
    w.context.insert("meta".to_string(), meta);
    w
}

// ─── The durability floor ────────────────────────────────────────────

/// Measure the cost of one durable append on this machine: `iters` fsync'd redb
/// commits, returning the mean per-commit duration.
///
/// This is the single most important number for interpreting the server's
/// results. The server `fsync`s before answering, so **no amount of engine
/// optimization can push its per-event latency below this floor** — and its
/// throughput ceiling is the reciprocal. Reporting server latency without it
/// invites the reader to attribute storage cost to the policy engine.
///
/// Deliberately measured through redb (the server's actual store) rather than a
/// raw `File::sync_all`, so it includes the same transaction machinery.
pub fn fsync_floor(iters: u64) -> std::time::Duration {
    use dogwood_local_engine::DurableLog;
    let path = std::env::temp_dir().join(format!("dogwood_perf_fsync_{}.redb", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let log = DurableLog::open(&path).expect("open log");
    let payload = b"benchmark durability probe payload";

    let start = std::time::Instant::now();
    for _ in 0..iters {
        log.append(payload).expect("append");
    }
    let elapsed = start.elapsed();

    drop(log);
    let _ = std::fs::remove_file(&path);
    elapsed / iters.max(1) as u32
}
