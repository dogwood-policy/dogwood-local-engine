//! Workload generation: the policy sets, schemas, and event streams both engines
//! are measured against.
//!
//! Everything here is **deterministic** — no clocks, no RNG. A benchmark that
//! generates a different workload per run cannot tell a regression from a
//! different input, and the two engines must see byte-identical inputs or the
//! comparison measures the generator instead of the engines.

use dogwood_language::{LoweredPolicySet, PolicySchema, ServiceSchema, UNPINNED_EVENT_SCHEMA};

/// Whether the event schema declares a **universal symmetric pin** on the session
/// id.
///
/// This is not merely a schema detail — it changes the work an engine does, in two
/// opposing directions, which is why it is a benchmark axis:
///
/// - **More work per predicate.** Every temporal predicate gains an injected
///   `session_id` correlation, so each candidate row carries an extra comparison.
/// - **Less work overall, potentially much less.** The correlation is also a
///   *filter*: a `formerly` scanning history rejects every event from another
///   session immediately. With many concurrent sessions the pinned variant can
///   examine a small fraction of the rows the unpinned one does.
///
/// Which effect wins depends on how many sessions the trace interleaves, so the
/// workload takes the session count as a parameter and the answer is measured
/// rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pinning {
    /// The default event schema: no pins. A `formerly` sees every session's
    /// events.
    Unpinned,
    /// `session_id` pinned symmetrically on every event kind — a universal
    /// symmetric pin, so it is both a per-predicate correlation and (per
    /// `DESIGN.md` §3.3) a valid partition key.
    PinnedSession,
}

impl Pinning {
    /// A short label for benchmark IDs.
    pub fn label(self) -> &'static str {
        match self {
            Pinning::Unpinned => "unpinned",
            Pinning::PinnedSession => "pinned",
        }
    }

    /// The event-schema source this arm installs.
    ///
    /// `Unpinned` names [`UNPINNED_EVENT_SCHEMA`] **explicitly** rather than
    /// omitting the schema to take the default. As of dogwood-language v1.0 the
    /// default event schema carries a universal symmetric pin on
    /// `callerPrincipal`, so falling back to it would make BOTH arms pinned —
    /// silently collapsing the very axis this harness measures, while still
    /// reporting numbers. Every call site must go through here.
    pub fn event_schema(self) -> &'static str {
        match self {
            Pinning::Unpinned => UNPINNED_EVENT_SCHEMA,
            Pinning::PinnedSession => PINNED_EVENT_SCHEMA,
        }
    }
}

/// The Cedar action schema. Two actions (`Login` writes history, `Read` decides),
/// each carrying the session id at `context.meta.session_id`.
///
/// Two constraints shaped this, both discovered by trying the obvious thing first:
///
/// 1. **The session field must be declared on the action.** The server
///    **validates** every policy set it installs, and a pin whose request-side
///    path is not declared lowers fine but fails strict validation — so the
///    corpus's `context.__example.session_id` shape replays happily in the test
///    harness yet is *rejected* by `dogwood-server apply`. Declaring it keeps both
///    paths on the same schema.
/// 2. **It must live inside a group, not at the top level.** `EventBuilder` has
///    only `field(group, name, ..)` / `request_context(group, name, ..)` — there is
///    no public setter for a top-level field. A pin on a bare `session_id` is
///    therefore unconstructible through the public API, so the benchmark could not
///    build the events to exercise it. Nesting it under `meta` makes it writable by
///    both drivers.
pub const ACTION_SCHEMA: &str = r#"
namespace Example {
  type LoginInput = { user: String, server: String };
  type ReadInput  = { user: String, server: String, document: String };
  type Meta       = { session_id: String };
  entity Gateway;
  entity OAuthUser;
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: LoginInput, meta: Meta }
  };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: ReadInput, meta: Meta }
  };
}
"#;

/// The pinned event schema: `meta.session_id` pinned to its own request path on
/// **every** kind, which is what makes the pin universal and symmetric.
///
/// Verified to register as a genuine partition key (not merely a per-predicate
/// correlation): lowering this yields `ShardPlan::Sharded { key_paths:
/// [["meta", "session_id"]] }`, which is the same condition the frontend's
/// relativization rewrite triggers on. `benches/decide_latency.rs` asserts that,
/// so the "pinned" axis cannot silently degrade into "unpinned with extra steps".
pub const PINNED_EVENT_SCHEMA: &str = r#"
decision event <A>::request {
    ...inputs(A),
    meta: { pin session_id: String = context.meta.session_id },
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    meta: { pin session_id: String = context.meta.session_id },
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
}
"#;

/// The lookback window every generated rule uses, in the store's timestamp
/// units. Ties the constant to the `formerly within 1h` in [`policy_set`] /
/// [`policy_set_shaped`] so a caller can reason about how much history is
/// reachable without re-deriving it from the policy text.
///
/// The store assigns timestamps in epoch NANOSECONDS
/// (`DurableTemporalEngine::next_timestamp`), so this is a real hour of wall-clock time: a
/// pre-load of any size lands inside it, and retained depth is bounded by the
/// number of events submitted rather than by the window.
///
/// It did not always read that way. Under whole-second assignment the clamp to
/// `max(now, last + 1)` advanced the sequence one unit per event, so a burst of
/// more than `WINDOW_SECONDS` events evicted its own oldest entries as it ran and
/// retained depth saturated here regardless of how many were sent.
pub const WINDOW_SECONDS: usize = 3600;

/// Generate a policy set of `count` temporal rules.
///
/// Each rule is a `forbid` gated on a `formerly within 1h` for a past `Login`
/// **correlated to the current request's server** (`input.server:
/// context.input.server`) and additionally filtered by a per-rule document value.
/// Structurally identical, semantically independent rules — which is what makes
/// `count` a clean axis. Sharing one condition across rules would let an
/// implementation that deduplicates leaves show artificially flat scaling.
///
/// # Why the correlation is load-bearing, not decoration
///
/// The obvious formulation — `formerly … Login{ input.server: "s{i}" }`, with a
/// hardcoded literal — is **uncorrelated with the request**, and it silently
/// destroys the benchmark: once any `Login` on `s0` has occurred, rule `r0` fires
/// for *every* subsequent `Read` regardless of what that read is doing, so every
/// decision denies forever and the workload measures one code path. The verdict
/// mix assertion in `benches/decide_latency.rs` caught exactly this.
///
/// Correlating on `context.input.server` makes a rule fire only when the request's
/// own server has a matching login, so the verdict depends on the request — which
/// is both realistic and what keeps allows and denies mixed.
///
/// A single leading `permit` makes `Read` allowable at all.
pub fn policy_set(count: usize) -> String {
    let mut out = String::new();
    out.push_str("permit ( principal, action == Example::Action::\"Read\", resource );\n");
    for i in 0..count {
        out.push_str(&format!(
            r#"
@id("r{i}")
forbid ( principal, action == Example::Action::"Read", resource )
when temporal {{
    formerly within 1h Example::Action::"Login"::request{{
        input.server: context.input.server,
        input.user: "blocked{i}"
    }}
}};
"#
        ));
    }
    out
}

/// Lower a policy set under the given pinning. Panics on failure — a benchmark
/// fixture that does not build is a bug in the harness, not a result.
pub fn lower(count: usize, pinning: Pinning) -> LoweredPolicySet {
    let service = ServiceSchema::builder()
        .event_schema_str(pinning.event_schema())
        .build()
        .expect("service schema builds");
    let policy_schema =
        PolicySchema::from_cedarschema_str(ACTION_SCHEMA).expect("action schema parses");
    LoweredPolicySet::from_str(&policy_set(count), &service, &policy_schema)
        .expect("policy set lowers")
}

/// One generated event, in a form both drivers can render.
///
/// Deliberately engine-agnostic: the reference driver turns it into a
/// `dogwood_language::Event` and the server driver into a `WireEvent`, from the
/// *same* description, so neither engine can be handed a different workload.
#[derive(Debug, Clone)]
pub struct GenEvent {
    /// `"Login"` (history-bearing) or `"Read"` (a decision).
    pub action: &'static str,
    /// Wall-clock timestamp for the reference driver. The server assigns its own
    /// (`DESIGN.md` §3.3), so this is ignored there — see `driver::server`.
    pub ts: i64,
    pub user: String,
    pub server: String,
    pub session: String,
    /// Whether this event is a decision point (a `Read`).
    pub decides: bool,
}

/// Generate a deterministic event stream.
///
/// - `events` total events; roughly one in `login_every` is a `Login` (history),
///   the rest are `Read` decisions.
/// - `sessions` distinct session ids, round-robined. This is the parameter that
///   makes pinning matter: with `sessions == 1` a pin filters nothing, and with
///   many sessions it filters most of history.
/// - `servers` distinct server values, round-robined, so a rule's
///   request-correlated `formerly` sometimes matches and sometimes does not.
///
/// # Producing a genuine allow/deny mix
///
/// Two details, each fixing a way this silently collapses to one code path:
///
/// 1. **Every third `Login` uses the user name `blocked0`**, which is what rule
///    `r0`'s `input.user: "blocked{i}"` filter looks for. Without it the filter
///    never matches and every decision allows.
/// 2. **`servers` must be coprime to `login_every`.** Servers are assigned
///    `s{i % servers}`, and logins occupy only indices divisible by `login_every`.
///    If `login_every` divides `servers` (e.g. 5 and 50), login servers are exactly
///    the multiples of 5 and read servers are exactly the non-multiples — two
///    disjoint sets, so **no read can ever find a matching login** and every
///    decision allows. That produced 0 denies out of 160 before being caught: the
///    mirror of the all-deny bug, and equally useless. With `servers` coprime to
///    `login_every` (49 and 5) the login indices walk the whole pool and the sets
///    overlap. `benches/decide_latency.rs` asserts the resulting mix, so a future
///    edit to either constant cannot quietly reintroduce this.
///
/// Only rule `r0` is ever satisfied, which is deliberate: the other rules still
/// cost full evaluation, so policy count is measured honestly, while the verdict
/// stays request-dependent.
///
/// Timestamps advance by 1s per event, so a `within 1h` window covers the most
/// recent 3600 events — for the sizes used here the window never expires, so the
/// engines are measured against a *growing* history, which is the harder case.
pub fn event_stream(
    events: usize,
    sessions: usize,
    servers: usize,
    login_every: usize,
) -> Vec<GenEvent> {
    assert!(sessions > 0 && servers > 0 && login_every > 0);
    (0..events)
        .map(|i| {
            let is_login = i % login_every == 0;
            // Some logins are by the user rule r0 forbids; the rest are ordinary.
            let user = if is_login && (i / login_every).is_multiple_of(3) {
                "blocked0".to_string()
            } else {
                format!("u{}", i % sessions)
            };
            let server = format!("s{}", i % servers);
            GenEvent {
                action: if is_login { "Login" } else { "Read" },
                ts: i as i64,
                user,
                server,
                session: format!("sess{}", i % sessions),
                decides: !is_login,
            }
        })
        .collect()
}

/// The canonical benchmark policy counts, as requested: 10, 100, 1000.
pub const POLICY_COUNTS: [usize; 4] = [10, 100, 1000, 10_000];

/// Whether a rule's `formerly` predicate is **selective** or **broad**.
///
/// This axis exists because it decides whether pinning can possibly help, and
/// omitting it produced a misleading "pinning makes no difference" result.
///
/// A pin's benefit is that it filters other sessions' history out of a scan. But a
/// predicate that *already* filters those rows for another reason leaves the pin
/// nothing to remove:
///
/// - [`Selective`](PredicateShape::Selective) pins the past `Login` to a literal
///   user (`input.user: "blocked{i}"`). That literal rejects nearly every history
///   row on its own, so adding a session correlation changes almost nothing —
///   measured at 0.96–1.00× (i.e. no effect, or a hair slower from the extra
///   comparison).
/// - [`Broad`](PredicateShape::Broad) counts *any* `Login` (wildcard user and
///   server). Unpinned, that scans every session's logins; pinned, only the
///   current session's. Measured at **2.8× faster** with 32 balanced sessions.
///
/// So both shapes are benchmarked, and the pinning column is only interpretable
/// per-shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateShape {
    /// A literal-filtered predicate: highly selective, so a pin adds little.
    Selective,
    /// A wildcard aggregation over all logins: a pin is the only thing confining
    /// the scan, so its effect is visible.
    Broad,
}

impl PredicateShape {
    pub fn label(self) -> &'static str {
        match self {
            PredicateShape::Selective => "selective",
            PredicateShape::Broad => "broad",
        }
    }
}

/// Generate a policy set of `count` rules with the given predicate shape.
///
/// [`policy_set`] is the [`PredicateShape::Selective`] case; this is the general
/// form. The broad rules use a `count … where formerly …` aggregation over
/// wildcard logins with a threshold no workload reaches, so they never fire — the
/// point is the *scan cost*, and a rule that fired would change the verdict mix
/// between shapes and make the two incomparable.
pub fn policy_set_shaped(count: usize, shape: PredicateShape) -> String {
    match shape {
        PredicateShape::Selective => policy_set(count),
        PredicateShape::Broad => {
            let mut out = String::new();
            out.push_str(
                "permit ( principal, action == Example::Action::\"Read\", resource );\n",
            );
            for i in 0..count {
                out.push_str(&format!(
                    r#"
@id("r{i}")
forbid ( principal, action == Example::Action::"Read", resource )
when temporal {{
    exists (c{i}: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (
                Example::Action::"Login"::request{{ input.user: _, input.server: _ }} && tp(t)
            )
        )) == c{i} && c{i} > 100000
    )
}};
"#
                ));
            }
            out
        }
    }
}

/// Lower a shaped policy set.
pub fn lower_shaped(count: usize, pinning: Pinning, shape: PredicateShape) -> LoweredPolicySet {
    let service = ServiceSchema::builder()
        .event_schema_str(pinning.event_schema())
        .build()
        .expect("service schema builds");
    let policy_schema =
        PolicySchema::from_cedarschema_str(ACTION_SCHEMA).expect("action schema parses");
    LoweredPolicySet::from_str(&policy_set_shaped(count, shape), &service, &policy_schema)
        .expect("policy set lowers")
}
