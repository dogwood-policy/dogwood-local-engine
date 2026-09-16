//! Targeted test that the incremental non-correlated-`formerly` path is
//! actually built and produces correct verdicts — independent of whether the
//! corpus happens to exercise it after relativization.
//!
//! It (1) drives the `TemporalEngine` trait directly so it can assert the leaf
//! runs on the INCREMENTAL path (`incremental_leaf_count() >= 1`, not the scan
//! fallback), and (2) cross-checks the full decision stream against the
//! in-memory interpreter oracle (`Authorizer::new`).

use dogwood_language::cedar::Schema;
use dogwood_language::{
    Authorizer, Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, Value,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
namespace Example {
  type ActInput = { note: String };
  entity Gateway;
  entity OAuthUser;
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ActInput }
  };
  action "Act" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ActInput }
  };
}
"#;

/// Permit `Act` iff a `Login` occurred in the last hour — a NON-correlated
/// `formerly` (empty body args), the shape the incremental path admits.
const POLICY: &str = r#"
permit (
    principal,
    action == Example::Action::"Act",
    resource
)
when temporal {
    formerly within 1h Example::Action::"Login"::request{}
};
"#;

fn policies() -> LoweredPolicySet {
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema builds");
    LoweredPolicySet::from_str(POLICY, &ServiceSchema::defaults(), &schema).expect("policy lowers")
}

fn ev(action: &str, ts: i64) -> Event {
    Event::builder(&format!("Example::Action::{action}"), "request")
        .timestamp(ts)
        .principal("Example::OAuthUser::\"alice\"")
        .resource("Example::Gateway::\"gw1\"")
        .field("input", "note", Value::String("n".into()))
        .build()
}

fn stream() -> Vec<Event> {
    vec![
        ev("Login", 0),
        ev("Act", 10),
        ev("Act", 4000),
        ev("Login", 4100),
        ev("Act", 4200),
    ]
}

/// A default (all-permissive) Cedar schema handle — the engine's `prepare` only
/// forwards it to the (no-op here) backend; the temporal leaves carry their own
/// structure. We reuse the frontend's lowered Cedar schema.
fn cedar_schema() -> Schema {
    // The lowered policy set exposes the compiled Cedar schema.
    policies().cedar_schema().clone()
}

/// Per-`formerly` leaf boolean at the decision point, driving the engine's
/// `TemporalEngine` methods directly so we can inspect the incremental count.
#[test]
fn incremental_formerly_is_built_and_correct() {
    let lowered = policies();
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    assert_eq!(leaves.len(), 1, "one temporal leaf");
    let leaf_id = leaves[0].id.clone();

    let sigs: Vec<_> = lowered.event_signatures().collect();
    let mut engine = LocalTemporalEngine::new();
    // Slicing off: this test reads the leaf's verdict after EVERY event in the
    // stream, `Login` events included, and the rule that owns the leaf is scoped
    // to `Act`. A decision for `Login` cannot reach that rule, so sliced
    // `evaluate` reports the leaf `false` there and is right to
    // (`dogwood_language::DecisionLeafMap`);
    // the subject here is the sliding-window operator, which needs the raw verdict
    // at every step. The decision-path lanes below stay sliced.
    engine.disable_slicing();
    engine
        .prepare(&leaves, &cedar_schema(), &sigs)
        .expect("engine prepares");

    // Prove the leaf runs on the incremental path, not the scan fallback.
    assert_eq!(
        engine.incremental_leaf_count(),
        1,
        "the non-correlated `formerly` leaf must be incrementalized, not fall back"
    );

    // Drive the stream; record the leaf's boolean after each event.
    let mut leaf_bools = Vec::new();
    for e in stream() {
        engine.observe(&e);
        let bindings = engine.evaluate().expect("evaluate");
        leaf_bools.push(*bindings.get(&leaf_id).expect("leaf present"));
    }

    // The `formerly within 1h Login{}` leaf holds iff a Login occurred in the
    // last hour — INCLUDING the current event if it is itself a Login (age 0).
    // Login@0: the Login is a match at age 0 → true. Act@10: login 10s ago →
    // true. Act@4000: last login 4000s ago (>3600) → false. Login@4100: itself
    // a login, age 0 → true. Act@4200: login 100s ago → true.
    assert_eq!(
        leaf_bools,
        vec![true, true, false, true, true],
        "incremental sliding-window verdicts"
    );
}

/// A CORRELATED write-after-read policy: permit `Act` iff a prior `Login` by
/// the SAME user (`input.user: context.input.user`) is within the hour. This is
/// the verdict-time-correlation-join path (the factoring), the common Dogwood
/// shape. Uses `Act`'s own `input.user` as the correlation key.
const CORRELATED_SCHEMA: &str = r#"
namespace Example {
  type LoginInput = { user: String };
  type ActInput = { user: String };
  entity Gateway;
  entity OAuthUser;
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: LoginInput }
  };
  action "Act" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ActInput }
  };
}
"#;

const CORRELATED_POLICY: &str = r#"
permit (
    principal,
    action == Example::Action::"Act",
    resource
)
when temporal {
    formerly within 1h Example::Action::"Login"::request{ input.user: context.input.user }
};
"#;

fn correlated_policies() -> LoweredPolicySet {
    let schema = PolicySchema::from_cedarschema_str(CORRELATED_SCHEMA).expect("schema builds");
    LoweredPolicySet::from_str(CORRELATED_POLICY, &ServiceSchema::defaults(), &schema)
        .expect("policy lowers")
}

fn ev_user(action: &str, ts: i64, user: &str) -> Event {
    // A well-formed event populates BOTH bags: `field` (logged temporal record,
    // matched by predicate field-args) AND `request_context` (the Cedar request
    // context, read by `context.input.user`). The corpus `.log` format does the
    // same; the two datasets are deliberately separate.
    Event::builder(&format!("Example::Action::{action}"), "request")
        .timestamp(ts)
        .principal("Example::OAuthUser::\"alice\"")
        .resource("Example::Gateway::\"gw1\"")
        .field("input", "user", Value::String(user.into()))
        .request_context("input", "user", Value::String(user.into()))
        .build()
}

#[test]
fn correlated_formerly_is_incremental_and_matches_oracle() {
    let lowered = correlated_policies();
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let leaf_id = leaves[0].id.clone();

    let sigs: Vec<_> = lowered.event_signatures().collect();
    let mut engine = LocalTemporalEngine::new();
    // Slicing off, for the reason the test above gives: the stream's `Login`
    // positions are probed, and the rule is scoped to `Act`.
    engine.disable_slicing();
    engine
        .prepare(
            &leaves,
            &correlated_policies().cedar_schema().clone(),
            &sigs,
        )
        .expect("prepares");
    assert_eq!(
        engine.incremental_leaf_count(),
        1,
        "correlated `formerly` must be incrementalized via the verdict-time join"
    );

    // alice logs in @0; bob logs in @5. Act by alice @10 → true (alice login
    // 10s ago). Act by bob @20 → true (bob login 15s ago). Act by carol @30 →
    // false (no carol login). Act by alice @4000 → false (alice login 4000s
    // ago, out of window).
    let stream = [
        ev_user("Login", 0, "alice"),
        ev_user("Login", 5, "bob"),
        ev_user("Act", 10, "alice"),
        ev_user("Act", 20, "bob"),
        ev_user("Act", 30, "carol"),
        ev_user("Act", 4000, "alice"),
    ];
    let mut bools = Vec::new();
    for e in &stream {
        engine.observe(e);
        bools.push(*engine.evaluate().expect("eval").get(&leaf_id).unwrap());
    }
    // Login@0, Login@5: the leaf gates Act, not Login. With slicing off (above)
    // the leaf is still *computed* at those positions — it evaluates against the
    // Login's own user, and alice/bob each just logged in, so it holds for them —
    // but a real decision for `Login` never reads it. We assert the Act positions.
    assert!(bools[2], "alice Act@10: alice login 10s ago");
    assert!(bools[3], "bob Act@20: bob login 15s ago");
    assert!(!bools[4], "carol Act@30: no carol login");
    assert!(!bools[5], "alice Act@4000: alice login out of window");

    // Cross-check the same stream against the in-memory oracle.
    let mut oracle = Authorizer::new(correlated_policies());
    let want: Vec<Option<bool>> = stream
        .iter()
        .map(|e| oracle.is_authorized(e).map(|r| r.allowed()))
        .collect();
    let mut sut = Authorizer::builder(correlated_policies())
        .temporal_engine(LocalTemporalEngine::new())
        .build()
        .expect("build");
    let got: Vec<Option<bool>> = stream
        .iter()
        .map(|e| sut.is_authorized(e).map(|r| r.allowed()))
        .collect();
    assert_eq!(
        got, want,
        "correlated incremental decisions match the oracle"
    );
}

#[test]
fn incremental_engine_matches_in_memory_oracle() {
    // SUT: the local engine (incremental path for this leaf).
    let sut_decisions: Vec<Option<bool>> = {
        let mut a = Authorizer::builder(policies())
            .temporal_engine(LocalTemporalEngine::new())
            .build()
            .expect("build sut");
        stream()
            .iter()
            .map(|e| a.is_authorized(e).map(|r| r.allowed()))
            .collect()
    };

    // Oracle: the frontend's default in-memory interpreter (the rescan).
    let oracle_decisions: Vec<Option<bool>> = {
        let mut a = Authorizer::new(policies());
        stream()
            .iter()
            .map(|e| a.is_authorized(e).map(|r| r.allowed()))
            .collect()
    };

    assert_eq!(
        sut_decisions, oracle_decisions,
        "incremental engine must agree with the in-memory oracle"
    );
}
