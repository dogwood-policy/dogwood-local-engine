//! Arithmetic comparison operands (`+ - *`) in the incremental monitor.
//!
//! Three-lane differential with pinned verdicts: every case drives the
//! memo-ON engine, the memo-OFF engine, and the interpreter oracle over the
//! same events, asserting the three verdict streams identical at every probe
//! AND equal to the expected verdict written next to the probe. The cases
//! mirror the arithmetic groups in `dogwood-language`'s
//! `tests/experimental/corpus/` (6001-6016), which are deliberately not
//! embedded in the shared corpus until every backend evaluates arithmetic —
//! moving them into `tests/passing/temporal_only/corpus/` is the
//! cross-engine conformance step, after which `corpus_diff.rs` covers this
//! ground automatically.
//!
//! The saturation pins are the semantic contract: per-operation saturating
//! i64 in tree order, exactly the reference `resolve_term_at`, which differs
//! observably from evaluating at wider precision and clamping once
//! (guide 08 §5.4; `dogwood-language/tests/arithmetic_eval.rs`).
//!
//! EXPERIMENTAL-ARITHMETIC: the frontend accepts these policies only with
//! its `experimental-arithmetic` feature on, so this file runs only when
//! this crate's feature of the same name (which forwards to the frontend's)
//! is on.
#![cfg(feature = "experimental-arithmetic")]

use dogwood_language::{
    Event, InMemoryTemporalEngine, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine,
    Value,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
namespace Test {
  type LoginInput = { user: String, session: String };
  type LoginOutput = { result: Bool };
  type TransferInput = { user: String, amount: Long };
  type TransferOutput = { result: Bool };
  type ReadInput = { user: String, threshold: Long };
  type ReadOutput = { result: Bool };
  entity Gateway = { coverage: Long };
  entity User;
  action "Login" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: LoginInput, output: LoginOutput }
  };
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

fn base(action: &str, kind: &str, ts: i64) -> dogwood_language::EventBuilder {
    Event::builder(&format!("Test::Action::{action}"), kind)
        .timestamp(ts)
        .principal("Test::User::\"alice\"")
        .resource("Test::Gateway::\"gw1\"")
}

fn login(ts: i64, user: &str) -> Event {
    base("Login", "response", ts)
        .field("input", "user", Value::String(user.into()))
        .field("input", "session", Value::String(format!("s{user}")))
        .field("output", "result", Value::Bool(true))
        .build()
}

fn transfer(ts: i64, user: &str, amount: i64) -> Event {
    base("Transfer", "response", ts)
        .field("input", "user", Value::String(user.into()))
        .field("input", "amount", Value::Int(amount))
        .field("output", "result", Value::Bool(true))
        .build()
}

fn read(ts: i64, user: &str, threshold: i64) -> Event {
    base("Read", "request", ts)
        .field("input", "user", Value::String(user.into()))
        .field("input", "threshold", Value::Int(threshold))
        .request_context("input", "user", Value::String(user.into()))
        .request_context("input", "threshold", Value::Int(threshold))
        .build()
}

/// A probe whose decision context is missing `threshold`: any compound
/// reading `context.input.threshold` must fail closed (comparison false).
fn read_without_threshold(ts: i64, user: &str) -> Event {
    base("Read", "request", ts)
        .field("input", "user", Value::String(user.into()))
        .request_context("input", "user", Value::String(user.into()))
        .build()
}

/// A probe that also supplies the resource entity's `coverage` attribute,
/// so `resource.coverage` resolves at the decision.
fn read_with_coverage(ts: i64, user: &str, threshold: i64, coverage: i64) -> Event {
    base("Read", "request", ts)
        .field("input", "user", Value::String(user.into()))
        .request_context("input", "user", Value::String(user.into()))
        .request_context("input", "threshold", Value::Int(threshold))
        .entity(
            "Test::Gateway::\"gw1\"",
            [("coverage", Value::Int(coverage))],
        )
        .build()
}

/// A Transfer whose `amount` is a Decimal (schema-invalid at the event
/// level, which engine-side observation does not police): an arithmetic
/// atom bound to it must make the comparison false, never panic.
fn transfer_decimal(ts: i64, user: &str, amount: &str) -> Event {
    base("Transfer", "response", ts)
        .field("input", "user", Value::String(user.into()))
        .field("input", "amount", Value::Decimal(amount.into()))
        .field("output", "result", Value::Bool(true))
        .build()
}

fn prepared(lowered: &LoweredPolicySet, memo: bool) -> LocalTemporalEngine {
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let mut e = LocalTemporalEngine::new();
    if !memo {
        e.disable_agg_memo();
    }
    e.prepare(&leaves, &schema, &sigs).expect("prepares");
    e
}

fn oracle(lowered: &LoweredPolicySet) -> InMemoryTemporalEngine {
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let mut e = InMemoryTemporalEngine::new();
    e.prepare(&leaves, &schema, &sigs).expect("oracle prepares");
    e
}

/// Drive the events through memo-ON, memo-OFF, and the oracle. At every
/// probe (`Some(expected)`), all three verdicts must agree with each other
/// AND with the pinned expectation. Also asserts the arithmetic leaf runs on
/// the incremental path (prepare accepted it — no scan fallback).
fn run_pinned(policy: &str, events: &[(Event, Option<bool>)]) {
    let lowered = lower(policy);
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    assert_eq!(leaves.len(), 1, "one temporal leaf per case");
    let mut on = prepared(&lowered, true);
    let mut off = prepared(&lowered, false);
    let mut orc = oracle(&lowered);
    assert_eq!(
        on.incremental_leaf_count(),
        1,
        "arithmetic leaf must compile to the incremental path"
    );
    for (ev, expect) in events {
        on.observe(ev);
        off.observe(ev);
        orc.observe(ev);
        if let Some(want) = expect {
            let von = on.evaluate().expect("on evals")[&leaves[0].id];
            let voff = off.evaluate().expect("off evals")[&leaves[0].id];
            let vor = orc.evaluate().expect("oracle evals")[&leaves[0].id];
            assert_eq!(
                von,
                voff,
                "memo-ON vs memo-OFF diverge at ts={}",
                ev.timestamp()
            );
            assert_eq!(
                voff,
                vor,
                "engine vs oracle diverge at ts={}",
                ev.timestamp()
            );
            assert_eq!(von, *want, "pinned verdict at ts={}", ev.timestamp());
        }
    }
}

// ── group A: tolerances and offsets (6001) ──────────────────────────────

/// `invoice <= po + K`: a `+` over a bound event variable and a literal,
/// compared against a decision-context field.
#[test]
fn tolerance_offset_over_bound_var() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (po: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: po }
        && context.input.threshold <= po + 50
    )
};"#;
    run_pinned(
        policy,
        &[
            (transfer(1000, "alice", 1000), None),
            (read(1010, "alice", 1040), Some(true)),
            (read(1020, "alice", 1100), Some(false)),
            (read(1030, "bob", 900), Some(false)),
            (transfer(1040, "bob", 900), None),
            (read(1050, "bob", 940), Some(true)),
        ],
    );
}

// ── group B: differences with slack (6002, 6014) ────────────────────────

/// `(count A) - (count B) <= N`: two aggregates under one `-`.
#[test]
fn count_difference_with_slack() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    ))
    - (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Login"::response{} && tp(t))
    )) <= 2
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(true)),
            (transfer(1010, "alice", 1), None),
            (transfer(1020, "alice", 1), None),
            (transfer(1030, "alice", 1), None),
            (read(1040, "alice", 0), Some(false)),
            (login(1050, "alice"), None),
            (read(1060, "alice", 0), Some(true)),
        ],
    );
}

/// `(count ...) + -2 <= 0`: a negative literal in continuation position.
#[test]
fn negative_literal_operand() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    )) + -2 <= 0
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(true)),
            (transfer(1010, "alice", 1), None),
            (transfer(1020, "alice", 1), None),
            (read(1030, "alice", 0), Some(true)),
            (transfer(1040, "alice", 1), None),
            (read(1050, "alice", 0), Some(false)),
        ],
    );
}

// ── group C: budgets combining unlike sources (6003, 6007) ──────────────

/// `(sum ...) + context.field <= B`, plus the fail-closed pin: a probe whose
/// decision context lacks the field makes the comparison false, never a
/// panic or a match-anything.
#[test]
fn sum_plus_context_budget_and_fail_closed() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (sum a for (a: Long), (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{ input.amount: a } && tp(t))
    )) + context.input.threshold <= 100
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 50), Some(true)),
            (transfer(1010, "alice", 30), None),
            (read(1020, "alice", 50), Some(true)),
            (transfer(1030, "alice", 40), None),
            (read(1040, "alice", 50), Some(false)),
            (read_without_threshold(1050, "alice"), Some(false)),
        ],
    );
}

// ── group D: ratios via `*` (6004) ──────────────────────────────────────

/// `100 * (count A) <= 85 * count B`: multiplication on both sides, the
/// final aggregate bare (aggregate fencing allows only the last one bare).
#[test]
fn ratio_cross_multiplication() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    100 * (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    ))
    <= 85 * count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Login"::response{} && tp(t))
    )
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(true)),
            (transfer(1010, "alice", 1), None),
            (read(1020, "alice", 0), Some(false)),
            (login(1030, "alice"), None),
            (login(1040, "alice"), None),
            (read(1050, "alice", 0), Some(true)),
        ],
    );
}

// ── structure: precedence, associativity, binding (6008, 6010) ──────────

/// `c + c * 2 == 9 && c - 1 + 3 == 5`: `*` binds tighter than `+`, and
/// `+`/`-` associate left. Both conjuncts hold exactly at `c == 3`.
#[test]
fn precedence_and_left_associativity() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (c: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
        )) == c
        && c + c * 2 == 9
        && c - 1 + 3 == 5
    )
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(false)),
            (transfer(1010, "alice", 1), None),
            (transfer(1020, "alice", 1), None),
            (transfer(1030, "alice", 1), None),
            (read(1040, "alice", 0), Some(true)),
            (transfer(1050, "alice", 1), None),
            (read(1060, "alice", 0), Some(false)),
        ],
    );
}

/// A fully-resolved compound on one side of `==` binds the bare variable on
/// the other side (the compound itself never binds).
#[test]
fn compound_side_binds_bare_variable() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (m: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
        ))
        + (count for (t: Timepoint). where (
            formerly within 1h (Test::Action::"Login"::response{} && tp(t))
        )) == m
        && m <= 2
    )
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(true)),
            (transfer(1010, "alice", 1), None),
            (login(1020, "alice"), None),
            (read(1030, "alice", 0), Some(true)),
            (transfer(1040, "alice", 1), None),
            (read(1050, "alice", 0), Some(false)),
        ],
    );
}

// ── saturation: the §5.4 per-operation contract ─────────────────────────

/// `a + i64::MAX - i64::MAX` with `a == 5`: per-operation saturation gives
/// `(5 sat+ MAX) sat- MAX == 0`. Wider-precision-then-clamp would give `5` —
/// the `threshold == 5` probe pins that this engine does NOT do that.
#[test]
fn overflow_clamps_per_operation_not_once_at_the_end() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (a: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a }
        && a + 9223372036854775807 - 9223372036854775807 == context.input.threshold
    )
};"#;
    run_pinned(
        policy,
        &[
            (transfer(1000, "alice", 5), None),
            (read(1010, "alice", 0), Some(true)),
            (read(1020, "alice", 5), Some(false)),
        ],
    );
}

/// Saturation toward the other rail: `a - MAX - MAX` with `a == -5`
/// saturates to `i64::MIN` on the first `-` and stays there, and
/// `a * MAX` with `a == -5` saturates to `i64::MIN` directly.
#[test]
fn overflow_clamps_to_min_on_the_negative_rail() {
    let sub_policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (a: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a }
        && a - 9223372036854775807 - 9223372036854775807 == context.input.threshold
    )
};"#;
    run_pinned(
        sub_policy,
        &[
            (transfer(1000, "alice", -5), None),
            (read(1010, "alice", i64::MIN), Some(true)),
            (read(1020, "alice", -10), Some(false)),
        ],
    );
    let mul_policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (a: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a }
        && a * 9223372036854775807 == context.input.threshold
    )
};"#;
    run_pinned(
        mul_policy,
        &[
            (transfer(1000, "alice", -5), None),
            (read(1010, "alice", i64::MIN), Some(true)),
            (read(1020, "alice", -5), Some(false)),
        ],
    );
}

/// `a * i64::MAX` with `a == 5` saturates to `i64::MAX`.
#[test]
fn multiplication_overflow_clamps_to_max() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (a: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a }
        && a * 9223372036854775807 == 9223372036854775807
    )
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(false)),
            (transfer(1010, "alice", 5), None),
            (read(1020, "alice", 0), Some(true)),
        ],
    );
}

// ── structure: repeated aggregates, grouping, chains (6006, 6013) ───────

/// `x + x == 2 * x` where `x` is the same count three times: a tautology
/// at every probe (saturation agrees on both sides: `x sat+ x` and
/// `2 sat* x` rail identically). Its `!=` twin is always false. Each of the
/// three occurrences builds its own aggregate with its own memo id.
#[test]
fn same_count_on_both_sides_tautology() {
    let eq_policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    ))
    + (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    )) == 2 * count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    )
};"#;
    run_pinned(
        eq_policy,
        &[
            (read(1000, "alice", 0), Some(true)),
            (transfer(1010, "alice", 1), None),
            (transfer(1020, "alice", 1), None),
            (read(1030, "alice", 0), Some(true)),
        ],
    );
    let neq_policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    ))
    + (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    )) != 2 * count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    )
};"#;
    run_pinned(
        neq_policy,
        &[
            (read(1000, "alice", 0), Some(false)),
            (transfer(1010, "alice", 1), None),
            (read(1020, "alice", 0), Some(false)),
        ],
    );
}

/// `((count ...) + 2) * 3 <= 12`: parenthesized grouping overrides the
/// `*`-binds-tighter default (6013). True while the count is at most 2.
#[test]
fn parenthesized_grouping() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    ((count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    )) + 2) * 3 <= 12
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(true)),
            (transfer(1010, "alice", 1), None),
            (transfer(1020, "alice", 1), None),
            (read(1030, "alice", 0), Some(true)),
            (transfer(1040, "alice", 1), None),
            (read(1050, "alice", 0), Some(false)),
        ],
    );
}

/// `v - b >= K` over two event-bound variables (6005, the equity shape).
/// `exists` semantics: any in-window pair may witness.
#[test]
fn difference_of_two_bound_vars() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (v: Long). exists (b: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: "a1", input.amount: v }
        && formerly within 24h Test::Action::"Transfer"::response{ input.user: "a2", input.amount: b }
        && v - b >= 100
    )
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(false)),
            (transfer(1010, "a1", 500), None),
            (read(1020, "alice", 0), Some(false)),
            (transfer(1030, "a2", 450), None),
            (read(1040, "alice", 0), Some(false)),
            (transfer(1050, "a2", 350), None),
            (read(1060, "alice", 0), Some(true)),
        ],
    );
}

/// Aggregates named by eq-binding, then arithmetic over the bound names
/// (6009): the `bind` idiom composes with arithmetic.
#[test]
fn named_aggregates_difference() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (n1: Long). exists (n2: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
        )) == n1
        && (count for (t: Timepoint). where (
            formerly within 1h (Test::Action::"Login"::response{} && tp(t))
        )) == n2
        && n1 - n2 <= 1
    )
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 0), Some(true)),
            (transfer(1010, "alice", 1), None),
            (transfer(1020, "alice", 1), None),
            (read(1030, "alice", 0), Some(false)),
            (login(1040, "alice"), None),
            (read(1050, "alice", 0), Some(true)),
        ],
    );
}

/// A three-atom chain (6006): sum plus sum plus a context field, left
/// associated, against one budget.
#[test]
fn sum_plus_sum_chain() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (sum a for (a: Long), (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{ input.user: "a1", input.amount: a } && tp(t))
    ))
    + (sum b for (b: Long), (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{ input.user: "a2", input.amount: b } && tp(t))
    ))
    + context.input.threshold <= 100
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 50), Some(true)),
            (transfer(1010, "a1", 30), None),
            (read(1020, "alice", 50), Some(true)),
            (transfer(1030, "a2", 30), None),
            (read(1040, "alice", 50), Some(false)),
            (read(1050, "alice", 20), Some(true)),
        ],
    );
}

// ── binding and fail-closed edges ────────────────────────────────────────

/// An `==` whose compound side does not resolve binds nothing: the probe
/// without `threshold` yields no binding row, so the guard is false rather
/// than a match-anything.
#[test]
fn unresolved_compound_side_binds_nothing() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (m: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
        )) + context.input.threshold == m
        && m <= 100
    )
};"#;
    run_pinned(
        policy,
        &[
            (read(1000, "alice", 5), Some(true)),
            (read_without_threshold(1010, "alice"), Some(false)),
            (read(1020, "alice", 200), Some(false)),
        ],
    );
}

/// A runtime Decimal reaching an arithmetic atom (schema-invalid event)
/// fails the comparison closed; a later well-typed event restores matching.
#[test]
fn decimal_atom_fails_closed() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (po: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: po }
        && context.input.threshold <= po + 50
    )
};"#;
    run_pinned(
        policy,
        &[
            (transfer_decimal(1000, "alice", "100.5"), None),
            (read(1010, "alice", 100), Some(false)),
            (transfer(1020, "alice", 100), None),
            (read(1030, "alice", 100), Some(true)),
        ],
    );
}

/// `resource.coverage` as a compound atom (6007): resolves when the probe
/// supplies the entity attribute, fails the guard closed when it does not.
#[test]
fn scope_attribute_operand_and_fail_closed() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (sum a for (a: Long), (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{ input.amount: a } && tp(t))
    )) + context.input.threshold <= resource.coverage
};"#;
    run_pinned(
        policy,
        &[
            (read_with_coverage(1000, "alice", 50, 100), Some(true)),
            (transfer(1010, "alice", 60), None),
            (read_with_coverage(1020, "alice", 50, 100), Some(false)),
            (read_with_coverage(1030, "alice", 50, 200), Some(true)),
            (read(1040, "alice", 50), Some(false)),
        ],
    );
}

// ── pruning: `max_window` through arithmetic ─────────────────────────────

/// Two counts with DIFFERENT windows under one `-`: the operand's prune
/// horizon must be the max of both sides. The 2h-later probe is the pin —
/// events outside the 1h window but inside the 4h window must still be
/// retained and counted, so an under-approximated `max_window` (which
/// would let pruning evict them) flips the verdict.
#[test]
fn differing_windows_under_one_compound() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 4h (Test::Action::"Transfer"::response{} && tp(t))
    ))
    - (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{} && tp(t))
    )) >= 1
};"#;
    run_pinned(
        policy,
        &[
            (transfer(1000, "alice", 1), None),
            (transfer(1010, "alice", 1), None),
            (read(1020, "alice", 0), Some(false)),
            (read(1000 + 7200, "alice", 0), Some(true)),
            (read(1000 + 16000, "alice", 0), Some(false)),
        ],
    );
}

// ── snapshots: the Arith-extended fixed walk ────────────────────────────

/// Save mid-trace with aggregate state under an arithmetic operand, reload
/// into a freshly built engine, and continue: the resumed engine's verdicts
/// must match the uninterrupted engine's at every remaining probe. This
/// exercises `save_state`/`load_state` recursing through `Operand::Arith`
/// in the same fixed pre-order on both sides.
#[test]
fn snapshot_roundtrip_with_arithmetic_state() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    (sum a for (a: Long), (t: Timepoint). where (
        formerly within 1h (Test::Action::"Transfer"::response{ input.amount: a } && tp(t))
    ))
    - (count for (t: Timepoint). where (
        formerly within 1h (Test::Action::"Login"::response{} && tp(t))
    )) + context.input.threshold <= 100
};"#;
    let lowered = lower(policy);
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut live = prepared(&lowered, true);

    let prefix = [
        transfer(1000, "alice", 30),
        read(1010, "alice", 50),
        transfer(1020, "alice", 40),
    ];
    for ev in &prefix {
        live.observe(ev);
    }
    live.evaluate().expect("warm evaluate before save");

    let snap = live.save_snapshot();
    let mut resumed = prepared(&lowered, true);
    assert!(resumed.load_snapshot(&snap), "snapshot loads");

    let suffix = [
        (read(1030, "alice", 50), true),
        (transfer(1040, "alice", 20), false),
        (read(1050, "alice", 5), true),
        (login(1055, "alice"), false),
        (read(1060, "alice", 11), true),
        (read(1070, "alice", 50), true),
    ];
    for (ev, probe) in &suffix {
        live.observe(ev);
        resumed.observe(ev);
        if *probe {
            let want = live.evaluate().expect("live evals")[&leaves[0].id];
            let got = resumed.evaluate().expect("resumed evals")[&leaves[0].id];
            assert_eq!(
                want,
                got,
                "resumed engine diverges from uninterrupted at ts={}",
                ev.timestamp()
            );
        }
    }
}
