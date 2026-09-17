//! Coverage for `compare_rows`'s left-var equality-binding arm (`(Some, None)`).
//!
//! An `Eq` comparison binds whichever operand is the unbound variable. The
//! corpus's only equality-binding shape is the aggregate threshold
//! `count(...) == n` — aggregate on the left, binder `n` on the right — so only
//! the `(None, Some(name))` arm is exercised. `build_compare` preserves authored
//! operand order (no canonicalization), so writing the equality **var-first**
//! (`n == count(...)`) drives the mirror `(Some(name), None)` arm instead. This
//! also pins a real property: equality-binding must be order-independent.
//!
//! Lowered with the unpinned service schema; verdict known by construction.

use dogwood_language::{
    Authorizer, Decision, LoweredPolicySet, PolicySchema, ServiceSchema, Validator,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
  entity User;
  entity Gateway;

  type GuardInput = {
    g: Long,
  };

  action "Guard" appliesTo {
    principal: [User],
    resource: [Gateway],
    context: { input: GuardInput }
  };

  type CounterInput = {
    amt: Long,
  };

  action "Counter" appliesTo {
    principal: [User],
    resource: [Gateway],
    context: { input: CounterInput }
  };
"#;

// Var-FIRST equality: `n == (count ...)`. `n` is the unbound `exists` binder on
// the left; the count resolves on the right, so `compare_rows` takes the
// `(Some("n"), None)` arm and binds `n` to the count. (The standard form
// `(count ...) == n` — binder on the right — is what the corpus already covers.)
const POLICY: &str = r#"permit (
    principal,
    action == Action::"Guard",
    resource
)
when temporal {
    exists (n: Long). (
        n == (count for (t: Timepoint). where formerly within 1000s (Action::"Counter"::request{ input.amt: 7 } && tp(t)))
        && n >= 1
    )
};"#;

// One matching Counter request in-window, then the Guard request decision:
// count == 1, so `n` binds to 1 and `n >= 1` holds → allow.
const TRACE: &str = r#"@21 scope(principal: User::"u", resource: Gateway::"g") request_context(input: { amt: 7 }) Action::"Counter"::request(input: { amt: 7 }, callerPrincipal: User::"u", callerResource: Gateway::"g", requestId: "c1")
@1020 scope(principal: User::"u", resource: Gateway::"g") request_context(input: { g: 0 }) Action::"Guard"::request(input: { g: 0 }, callerPrincipal: User::"u", callerResource: Gateway::"g", requestId: "gy")"#;

fn unpinned_service() -> ServiceSchema {
    ServiceSchema::builder()
        .event_schema_str(dogwood_language::UNPINNED_EVENT_SCHEMA)
        .build()
        .expect("unpinned event schema builds")
}

#[test]
fn var_first_equality_binds_via_left_arm() {
    let service = unpinned_service();
    let policy_schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema parses");
    let lowered =
        LoweredPolicySet::from_str(POLICY, &service, &policy_schema).expect("policy lowers");
    let result = Validator::new().validate(&lowered);
    if !result.validation_passed() {
        let errs: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        panic!("policy must type-check; errors:\n{}", errs.join("\n"));
    }

    let events = dogwood_language::parse_trace(TRACE).expect("trace parses");
    let mut auth = Authorizer::builder(lowered)
        .temporal_engine(LocalTemporalEngine::new())
        .build()
        .expect("authorizer builds");

    let mut decision = None;
    for e in &events {
        if let Some(r) = auth.is_authorized(e) {
            decision = Some(r.decision());
        }
    }
    // count == 1, n bound to 1 via the left-var arm, n >= 1 → allow.
    assert_eq!(
        decision,
        Some(Decision::Allow),
        "var-first `n == count(...)` should bind n and allow"
    );
}
