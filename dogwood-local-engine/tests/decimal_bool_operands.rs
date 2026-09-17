//! Coverage for `resolve_term`'s `Decimal` / `Bool` arms: literal comparison
//! *operands* in a temporal clause.
//!
//! The engine's `build_operand` wraps every non-aggregate term — including
//! literals — as `Operand::Term(..)` without baking, so a `decimal("…")` or
//! `true` on the right of a comparison is resolved at eval time by
//! `resolve_term`. The corpus only ever carries decimal/bool literals as
//! predicate *args* (resolved at compile time by `literal_value`), never as
//! comparison operands, so those two `resolve_term` arms were uncovered. This
//! test supplies exactly that shape.
//!
//! Lowered with the **unpinned** service schema so the authored comparison
//! stays in its authored form. The verdict is known by construction (all three
//! conjuncts hold), so no second engine is needed.

use dogwood_language::{
    Authorizer, Decision, LoweredPolicySet, PolicySchema, ServiceSchema, Validator,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
  entity User;
  entity Gateway;

  type ActInput = {
    user: String,
  };

  type ActOutput = {
    score: decimal,
    flag: Bool,
  };

  action "Act" appliesTo {
    principal: [User],
    resource: [Gateway],
    context: { input: ActInput, output?: ActOutput }
  };
"#;

// A temporal clause that binds a past response's output fields and compares them
// to a decimal literal and a bool literal. Binding to per-timepoint values makes
// the conjuncts genuinely vary (a bare decision-time comparison is rejected as
// "monitors nothing"); the literal operands (`decimal("1.50")`, `true`) are what
// route through `resolve_term`. Decimals support `==`/`!=` only — no ordering.
const POLICY: &str = r#"permit (
    principal,
    action == Action::"Act",
    resource
)
when temporal {
    exists (s: decimal). (exists (f: Bool). (
        formerly within 1h (
            Action::"Act"::response{ output.score: s, output.flag: f }
            && s == decimal("1.50")
            && f == true
        )
    ))
};"#;

// A prior Act response carrying output.score == 1.50 and output.flag == true
// (bound to s/f, so the comparisons hold), then the Act request decision — so
// `formerly` holds and both literal operands are resolved during the window scan.
const TRACE: &str = r#"@10 scope(principal: User::"u", resource: Gateway::"g") Action::"Act"::response(input: { user: "u" }, output: { score: 1.50, flag: true }, callerPrincipal: User::"u", callerResource: Gateway::"g", requestId: "a1")
@20 scope(principal: User::"u", resource: Gateway::"g") request_context(input: { user: "u" }) Action::"Act"::request(input: { user: "u" }, callerPrincipal: User::"u", callerResource: Gateway::"g", requestId: "a2")"#;

fn unpinned_service() -> ServiceSchema {
    ServiceSchema::builder()
        .event_schema_str(dogwood_language::UNPINNED_EVENT_SCHEMA)
        .build()
        .expect("unpinned event schema builds")
}

#[test]
fn decimal_and_bool_literal_comparison_operands_resolve() {
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

    // The decision is the Act request at time point 1; all three conjuncts hold
    // (prior response, amt == 1.50, flag == true), so it must allow — which means
    // both the decimal and bool comparison operands were resolved via resolve_term.
    let mut decision = None;
    for e in &events {
        if let Some(r) = auth.is_authorized(e) {
            decision = Some(r.decision());
        }
    }
    assert_eq!(
        decision,
        Some(Decision::Allow),
        "the Act request should allow (decimal + bool operands resolved and matched)"
    );
}
