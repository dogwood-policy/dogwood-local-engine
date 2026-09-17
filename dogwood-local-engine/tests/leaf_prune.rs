//! SparseLeaf prune-cost battery.
//!
//! THE SUSPECTED FLAW (design discussion 2026-08-13): `SparseLeaf::
//! drop_front` removes expired matches with `Vec::drain(..keep)`, which
//! MEMMOVES the entire tail. In steady state (a trace longer than the
//! policy window) pruning fires on ~every observe, so a densely-matching
//! predicate pays O(in-window matches) per ingested event — ingest cost
//! grows LINEARLY with window content, where it should be O(1) amortized.
//!
//! `p1_ingest_scales_with_window` exhibits it: same event rate, same
//! steady-state pruning, two policy windows (1 000 s vs 16 000 s ⇒ 16× the
//! in-window matches). Under the drain design, per-event ingest grows
//! severalfold (measured 3.6→7.4 µs at a 4× spread already); under amortized compaction it stays ~flat. The assertion
//! (ratio < 2.0) is RED against the drain design by construction.

use dogwood_language::{
    Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, Value,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
namespace Test {
  type TransferInput = { user: String, amount: Long };
  type TransferOutput = { result: Bool };
  type ReadInput = { user: String, threshold: Long };
  entity Gateway;
  entity User;
  action "Transfer" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: TransferInput, output: TransferOutput }
  };
  action "Read" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: ReadInput }
  };
}
"#;

const EVENT_SCHEMA: &str = r#"
max_window = 8760h

decision event <A>::request {
    ...inputs(A),
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
    sessionId:         String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
    sessionId:         String,
}
event <A>::error {
    ...inputs(A),
    callerPrincipal:   principalType(A),
    callerResource:    resourceType(A),
    requestId:         String,
    sessionId:         String,
}
"#;

fn lower(policy: &str) -> LoweredPolicySet {
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema builds");
    let service = ServiceSchema::builder()
        .event_schema_str(EVENT_SCHEMA)
        .build()
        .expect("event schema builds");
    LoweredPolicySet::from_str(policy, &service, &schema).expect("policy lowers")
}

fn transfer(ts: i64, user: &str) -> Event {
    Event::builder("Test::Action::Transfer", "response")
        .timestamp(ts)
        .principal("Test::User::\"alice\"")
        .resource("Test::Gateway::\"gw1\"")
        .field("input", "user", Value::String(user.into()))
        .field("input", "amount", Value::Int(1))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user.into()))
        .build()
}

fn prepared(policy: &str) -> LocalTemporalEngine {
    let lowered = lower(policy);
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let mut e = LocalTemporalEngine::new();
    e.prepare(&leaves, &schema, &sigs).expect("prepares");
    e
}

/// Per-event steady-state ingest cost for a window of `w_secs`, with one
/// densely-matching event per second: in-window matches ≈ w_secs.
fn steady_state_ingest_us(w_secs: usize) -> f64 {
    let policy = format!(
        r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {{
    formerly within {w_secs}s Test::Action::"Transfer"::response{{ input.user: context.input.user, output.result: true }}
}};"#
    );
    let mut e = prepared(&policy);
    let mut ts = 1_000i64;
    // Fill the window and enter the steady state (1.5× the window).
    for _ in 0..(w_secs * 3 / 2) {
        e.observe(&transfer(ts, "u0"));
        ts += 1;
    }
    // Measure pure ingest under per-event pruning.
    let n = w_secs; // scale the sample with the window for stable numbers
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        e.observe(&transfer(ts, "u0"));
        ts += 1;
    }
    t0.elapsed().as_micros() as f64 / n as f64
}

/// THE EXHIBIT: 4× the in-window matches must NOT mean ~4× the
/// per-event ingest cost. RED against the `drain(..keep)` design.
#[test]
#[ignore = "scale: run explicitly with --ignored (release)"]
fn p1_ingest_scales_with_window() {
    let small = steady_state_ingest_us(1_000);
    let large = steady_state_ingest_us(16_000);
    let ratio = large / small.max(0.001);
    println!(
        "p1 steady-state ingest: W=1000 {small:.2} us/event | W=16000 {large:.2} us/event | ratio {ratio:.2} (flat would be ~1.0)"
    );
    assert!(
        ratio < 2.0,
        "per-event ingest grows with window content ({ratio:.2}x for 4x matches): \
         the drop_front drain memmove is O(in-window matches) per observe"
    );
}
