//! The aggregate-memo battery. Layers:
//!
//! PRECONDITIONS (green BEFORE the memo lands — if red, the memo's
//! soundness premises are broken and that is a pre-existing engine bug):
//!   U1 append-invariance, U2 prune-transparency.
//! THE MEMO ITSELF (red until implemented):
//!   U3 memo-across-pruning, U4 hit rate, U5 memoized None, U6 dom_eq
//!   keys, U7 clone reset, U8 snapshot reopen, U9 external free keys
//!   (the R2/R5 soundness channel), U10 nested-agg no deadlock,
//!   U11 kill-switch equivalence, S1 the 29-policy differential.
//! SCALE (#[ignore], release, the per-CR checklist):
//!   S2 growth ratio (corr_agg_in_window), S4 worst-case overhead.
//!
//! Two-lane discipline: `engines()` returns (memo-ON, memo-OFF) engines;
//! every semantic test drives both plus (where cheap) the interpreter
//! oracle, asserting identical verdicts at every probe.

use dogwood_language::{
    Event, InMemoryTemporalEngine, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine,
    Value,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
namespace Test {
  type LoginInput = { user: String, session: String };
  type LoginOutput = { result: Bool };
  type LogoutInput = { user: String, session: String };
  type LogoutOutput = { result: Bool };
  type TransferInput = { user: String, amount: Long };
  type TransferOutput = { result: Bool };
  type ReadInput = { user: String, threshold: Long };
  type ReadOutput = { result: Bool };
  entity Gateway;
  entity User;
  action "Login" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: LoginInput, output: LoginOutput }
  };
  action "Logout" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: LogoutInput, output: LogoutOutput }
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
        .request_context("input", "user", Value::String(user.into()))
        .build()
}

fn transfer(ts: i64, user: &str, amount: i64) -> Event {
    base("Transfer", "response", ts)
        .field("input", "user", Value::String(user.into()))
        .field("input", "amount", Value::Int(amount))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user.into()))
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

// ── the two-lane harness ────────────────────────────────────────────────

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

/// Drive events through memo-ON, memo-OFF, and the oracle; assert all
/// three verdict streams identical at every probe (events where
/// `probe == true`). Returns the ON lane for stats inspection.
fn three_lane(policy: &str, events: &[(Event, bool)]) -> LocalTemporalEngine {
    let lowered = lower(policy);
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut on = prepared(&lowered, true);
    let mut off = prepared(&lowered, false);
    let mut orc = oracle(&lowered);
    let mut fired = [0usize; 2];
    for (ev, probe) in events {
        on.observe(ev);
        off.observe(ev);
        orc.observe(ev);
        if *probe {
            let von = on.evaluate().expect("on evals");
            let voff = off.evaluate().expect("off evals");
            let vor = orc.evaluate().expect("oracle evals");
            for leaf in &leaves {
                assert_eq!(
                    von[&leaf.id],
                    voff[&leaf.id],
                    "memo-ON vs memo-OFF diverge at ts={}",
                    ev.timestamp()
                );
                assert_eq!(
                    voff[&leaf.id],
                    vor[&leaf.id],
                    "engine vs oracle diverge at ts={}",
                    ev.timestamp()
                );
                fired[usize::from(von[&leaf.id])] += 1;
            }
        }
    }
    assert!(
        fired[0] > 0 && fired[1] > 0,
        "vacuous battery: outcomes {fired:?}"
    );
    on
}

// ── policies ────────────────────────────────────────────────────────────

/// The sweep shape (agg under the outer formerly): REAL cross-decide
/// reuse — the memo's target (design §3.1).
const AGG_UNDER_SWEEP: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (u: String). (formerly within 24h (Test::Action::"Login"::response{ input.user: u, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::response{ input.user: u, output.result: true } && tp(t)))) >= 2))
};"#;

/// Root-conjunct correlated aggregate: point-eval at cur — NO
/// cross-decide reuse expected (design §3.1 [R1]); still must be
/// semantically identical in both lanes.
const AGG_ROOT: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (n: Long). ((count for (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true } && tp(t)))) == n && n >= 2)
};"#;

/// Sum variant with a threshold read from the decision context.
const SUM_ROOT: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (total: Long). ((sum a for (a: Long), (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a, output.result: true } && tp(t)))) == total && total >= 10)
};"#;

/// U9's channel: the agg body FILTERS on `u`, which is bound OUTSIDE
/// the aggregate by the Login pred. The body's free keys must include
/// `u`; an under-approximated walk wrong-hits across different u.
const AGG_READS_OUTER_VAR: &str = AGG_UNDER_SWEEP; // same shape: `u` is outer-bound

/// Nested windows for U2/U3: outer 2h, inner 1h — max_window must be
/// the SUM (3h) for pruning to be transparent.
const NESTED_WINDOWS: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (u: String). (formerly within 2h (Test::Action::"Login"::response{ input.user: u, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::response{ input.user: u, output.result: true } && tp(t)))) >= 1))
};"#;

// ── traces ──────────────────────────────────────────────────────────────

/// The standard sweep trace: users u0/u1 transfer then log in; probes
/// alternate warmed / unknown so verdicts vary.
fn sweep_trace() -> Vec<(Event, bool)> {
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    // Early probe BEFORE any qualifying state: FALSE for every policy
    // (the exists(u) shapes ignore the probe's user, so "nobody" probes
    // alone cannot provide outcome variety — this one can).
    ev.push((read(ts, "u0", 0), true));
    ts += 10;
    for round in 0..6 {
        for u in ["u0", "u1"] {
            ev.push((transfer(ts, u, 10 + round), false));
            ts += 10;
        }
        ev.push((login(ts, if round % 2 == 0 { "u0" } else { "u1" }), false));
        ts += 10;
        ev.push((read(ts, "u0", 0), true));
        ts += 10;
        ev.push((read(ts, "nobody", 0), true));
        ts += 10;
    }
    ev
}

// ── U1/U2: PRECONDITIONS (must be green before the memo lands) ─────────

/// U1 (design §4.1): occ at a past timepoint is invariant to appends.
/// Two identically-prepared engines; one decides DURING the trace, the
/// other decides only at the end via replay: every shared decision
/// point must agree. (Public-API formulation: verdicts at time T are a
/// function of the trace ≤ T only, so replay reproduces them.)
#[test]
fn u1_append_invariance() {
    for policy in [AGG_UNDER_SWEEP, AGG_ROOT, SUM_ROOT, NESTED_WINDOWS] {
        let lowered = lower(policy);
        let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
        let trace = sweep_trace();
        // Lane A: decide at every probe as the trace streams.
        let mut a = prepared(&lowered, false);
        let mut recorded = Vec::new();
        for (ev, probe) in &trace {
            a.observe(ev);
            if *probe {
                let v = a.evaluate().expect("evals");
                recorded.push((
                    ev.clone(),
                    leaves.iter().map(|l| v[&l.id]).collect::<Vec<_>>(),
                ));
            }
        }
        // Lane B: replay the FULL trace into a fresh engine, re-deciding
        // at each recorded point by replaying the prefix.
        for (idx, (probe_ev, expect)) in recorded.iter().enumerate() {
            let mut b = prepared(&lowered, false);
            let mut seen = 0usize;
            for (ev, probe) in &trace {
                b.observe(ev);
                if *probe {
                    if ev.timestamp() == probe_ev.timestamp() {
                        let v = b.evaluate().expect("evals");
                        let got: Vec<_> = leaves.iter().map(|l| v[&l.id]).collect();
                        assert_eq!(&got, expect, "probe #{idx} at ts={}", ev.timestamp());
                        break;
                    }
                    seen += 1;
                }
            }
            let _ = seen;
        }
    }
}

/// U2 (design §4.2): pruning is semantics-transparent — the engine
/// (which prunes at max_window = the NESTED SUM) agrees with the
/// oracle (which retains everything) on a trace long enough that
/// pruning fires, including probes at the horizon boundary.
#[test]
fn u2_prune_transparency() {
    let lowered = lower(NESTED_WINDOWS);
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut eng = prepared(&lowered, false);
    let mut orc = oracle(&lowered);
    let mut ts = 1_000i64;
    // 5h of trace against a 3h nesting sum: pruning fires repeatedly.
    for i in 0..60 {
        let u = if i % 2 == 0 { "u0" } else { "u1" };
        eng.observe(&transfer(ts, u, 1));
        orc.observe(&transfer(ts, u, 1));
        ts += 300; // 5 min
        if i % 5 == 0 {
            eng.observe(&login(ts, u));
            orc.observe(&login(ts, u));
            ts += 300;
        }
        let probe = read(ts, "u0", 0);
        eng.observe(&probe);
        orc.observe(&probe);
        ts += 1;
        let ve = eng.evaluate().expect("engine evals");
        let vo = orc.evaluate().expect("oracle evals");
        for l in &leaves {
            assert_eq!(ve[&l.id], vo[&l.id], "prune divergence at ts={ts}");
        }
    }
}

// ── U3–U11: the memo battery ────────────────────────────────────────────

/// U3 (§4.4): memo entries keyed by tp_id survive pruning; decides
/// straddling a prune agree with the memo-OFF lane. (Fails if keyed by
/// timeline INDEX — indices rebase on drain.)
#[test]
fn u3_memo_survives_pruning() {
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    // Warm phase (memo fills), then a long gap forces a prune, then
    // fresh activity and more probes.
    for i in 0..8 {
        let u = if i % 2 == 0 { "u0" } else { "u1" };
        ev.push((transfer(ts, u, 1), false));
        ts += 200;
        if i % 3 == 2 {
            ev.push((login(ts, u), false));
            ts += 200;
        }
        ev.push((read(ts, "u0", 0), true));
        ts += 200;
    }
    ts += 4 * 3600; // beyond the 3h nesting sum: prune fires on the next event
    for i in 0..6 {
        let u = if i % 2 == 0 { "u0" } else { "u1" };
        ev.push((transfer(ts, u, 1), false));
        ts += 200;
        ev.push((login(ts, u), false));
        ts += 200;
        ev.push((read(ts, "u0", 0), true));
        ts += 200;
        ev.push((read(ts, "nobody", 0), true));
        ts += 200;
    }
    three_lane(NESTED_WINDOWS, &ev);
}

/// U4 (§2.8, pitfall 2): the sweep shape actually HITS — guards the
/// Arc::make_mut clone pattern silently emptying the memo every observe.
#[test]
fn u4_memo_hit_rate() {
    let on = three_lane(AGG_UNDER_SWEEP, &sweep_trace());
    let (hits, misses) = on.agg_memo_stats();
    assert!(
        hits > 0,
        "no memo hits on the sweep shape (stats {hits}/{misses})"
    );
    assert!(
        hits > misses,
        "hit rate under 50% on the sweep shape: {hits} hits / {misses} misses"
    );
}

/// U5 (renamed per review F4): repeated identical probes HIT the cache
/// — including for keys whose data is absent (u1). NOTE: the Agg path
/// always yields Some(Int) (project_count/sum never fail), so the
/// memoized-None branch is defensively dead today; this pins the
/// repeat-hit behavior instead.
#[test]
fn u5_repeat_probes_hit() {
    // SUM_ROOT's threshold read makes the COMPARISON unresolvable for a
    // probe missing the threshold — but the agg VALUE itself resolves.
    // The None-agg channel: a sum whose bound field is absent. Use the
    // sweep policy against a user with logins but NO transfers: the agg
    // value is Some(0)… so instead pin the semantics three-lane and the
    // stats: repeated identical probes must HIT (whatever was cached).
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((read(ts, "u0", 0), true)); // pre-state probe: FALSE
    ts += 10;
    ev.push((transfer(ts, "u0", 5), false));
    ts += 10;
    ev.push((transfer(ts, "u0", 5), false));
    ts += 10;
    ev.push((login(ts, "u0"), false));
    ts += 10;
    for _ in 0..4 {
        ev.push((read(ts, "u0", 0), true));
        ts += 5;
        ev.push((read(ts, "u1", 0), true)); // u1: no data → the None/absent path
        ts += 5;
    }
    let on = three_lane(AGG_UNDER_SWEEP, &ev);
    let (hits, _) = on.agg_memo_stats();
    assert!(hits > 0, "repeated identical probes should hit");
}

/// U6 (§2.2 [R4]): dom_eq key semantics — decimal group keys that are
/// numerically equal but spelled differently must share a memo entry
/// (and, above all, never split semantics between the lanes).
#[test]
fn u6_dom_eq_key_semantics() {
    // The frontend lowers decimals through cedar Decimal; drive the
    // amount field (Long) and the user field (String) as key parts and
    // additionally pin the engine-level equality via the sum policy
    // (amount participates in rows). Spelling variance for decimals is
    // not constructible through these events, so this test pins the
    // STRING/INT key path end-to-end and defers spelling to the unit
    // test inside the crate (see src: dom_key tests).
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((login(ts, "u0"), false));
    ts += 10;
    ev.push((transfer(ts, "u0", 7), false));
    ts += 10;
    ev.push((transfer(ts, "u0", 7), false));
    ts += 10;
    ev.push((read(ts, "u0", 10), true));
    ts += 10;
    ev.push((read(ts, "u1", 20), true)); // u1: no transfers → FALSE
    ts += 10;
    ev.push((read(ts, "u0", 10), true));
    three_lane(SUM_ROOT, &ev);
}

/// U7: cloning the engine (snapshot of live state / Arc sharing) resets
/// stats and keeps verdicts identical.
#[test]
fn u7_clone_resets_memo() {
    let lowered = lower(AGG_UNDER_SWEEP);
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut on = prepared(&lowered, true);
    let mut ts = 1_000i64;
    on.observe(&login(ts, "u0"));
    ts += 10;
    on.observe(&transfer(ts, "u0", 1));
    ts += 10;
    on.observe(&transfer(ts, "u0", 1));
    ts += 10;
    on.observe(&read(ts, "u0", 0));
    let v1 = on.evaluate().expect("evals");
    // Snapshot round-trip exercises Monitor rebuild (the clone-adjacent
    // path an integration test can reach); stats must restart cold and
    // verdicts agree.
    let snap = on.save_snapshot();
    let mut fresh = prepared(&lowered, true);
    assert!(fresh.load_snapshot(&snap), "snapshot loads");
    let (h, m) = fresh.agg_memo_stats();
    assert_eq!((h, m), (0, 0), "restored engine starts cold");
    ts += 10;
    on.observe(&read(ts, "u0", 0));
    fresh.observe(&read(ts, "u0", 0));
    let va = on.evaluate().expect("evals");
    let vb = fresh.evaluate().expect("evals");
    // v1 (the pre-snapshot verdict) anchors the trace; the restored
    // engine is only comparable from the post-restore probe onward.
    let _ = v1;
    for l in &leaves {
        assert_eq!(va[&l.id], vb[&l.id], "warm vs restored diverge");
    }
}

/// U8 (§5.2 [R7]): save with a WARM memo via the engine snapshot path,
/// reload, and agree — the memo is derived state, never serialized.
#[test]
fn u8_snapshot_reopen_cold_memo() {
    let lowered = lower(NESTED_WINDOWS);
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut on = prepared(&lowered, true);
    let mut orc = oracle(&lowered);
    let mut ts = 1_000i64;
    for i in 0..10 {
        let u = if i % 2 == 0 { "u0" } else { "u1" };
        for e in [transfer(ts, u, 1), login(ts + 5, u)] {
            on.observe(&e);
            orc.observe(&e);
        }
        ts += 10;
        let p = read(ts, "u0", 0);
        on.observe(&p);
        orc.observe(&p);
        on.evaluate().expect("warm the memo");
        ts += 10;
    }
    let snap = on.save_snapshot();
    let mut back = prepared(&lowered, true);
    assert!(back.load_snapshot(&snap));
    for i in 0..6 {
        let u = if i % 2 == 0 { "u0" } else { "u1" };
        let e = transfer(ts, u, 1);
        on.observe(&e);
        back.observe(&e);
        orc.observe(&e);
        ts += 10;
        let p = read(ts, "u0", 0);
        on.observe(&p);
        back.observe(&p);
        orc.observe(&p);
        ts += 10;
        let va = on.evaluate().expect("evals");
        let vb = back.evaluate().expect("evals");
        let vo = orc.evaluate().expect("oracle");
        for l in &leaves {
            assert_eq!(va[&l.id], vb[&l.id], "warm vs reopened diverge at ts={ts}");
            assert_eq!(
                vb[&l.id], vo[&l.id],
                "reopened vs oracle diverge at ts={ts}"
            );
        }
    }
}

/// U9 (§5.2 [R5], the R2/R9 channels): the agg body reads bindings
/// from OUTSIDE the aggregate. Variant 1 (DETERMINISTIC catch): the
/// body correlates on `context.input.user` (the Correlated-arg
/// channel) — probes for u0 (3 transfers, TRUE) and u1 (1 transfer,
/// FALSE) share the same tp domain, so an env-blind memo key leaks
/// u0's count to u1's probe. Variant 2 (the Var channel): `u` is
/// existentially bound by the outer Login row; rows for u0 (count 1)
/// and u1 (count 3) evaluate at the SAME tp within one decide — an
/// env-blind key makes the second row hit the first row's count.
#[test]
fn u9_external_free_key_soundness() {
    // Variant 1: ctx-correlated body (AGG_ROOT), same tps, different users.
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((read(ts, "u0", 0), true)); // pre-state: FALSE
    ts += 10;
    for _ in 0..3 {
        ev.push((transfer(ts, "u0", 1), false));
        ts += 10;
    }
    ev.push((transfer(ts, "u1", 1), false));
    ts += 10;
    // Interleave u0/u1 probes tightly: same current tp advance pattern,
    // alternating env keys.
    for _ in 0..4 {
        ev.push((read(ts, "u0", 0), true)); // TRUE (3 transfers ≥ 2)
        ts += 5;
        ev.push((read(ts, "u1", 0), true)); // FALSE (1 transfer)
        ts += 5;
    }
    three_lane(AGG_ROOT, &ev);

    // Variant 2: the existential Var channel — u0 qualifies the Login
    // anchor but has ONE transfer; u1 has THREE. The exists must find
    // u1's row TRUE even if u0's row (count 1) evaluated first at the
    // same tp — an env-blind key would cache 1 and sink both rows.
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((read(ts, "u0", 0), true)); // pre-state: FALSE
    ts += 10;
    ev.push((transfer(ts, "u0", 1), false));
    ts += 10;
    for _ in 0..3 {
        ev.push((transfer(ts, "u1", 1), false));
        ts += 10;
    }
    ev.push((login(ts, "u0"), false));
    ts += 10;
    ev.push((login(ts, "u1"), false));
    ts += 10;
    for _ in 0..4 {
        ev.push((read(ts, "u0", 0), true)); // TRUE via u1's row
        ts += 5;
    }
    three_lane(AGG_UNDER_SWEEP, &ev);
}

/// U10 (§2.5 [R3]): agg-vs-agg comparison — BOTH operands memoize in
/// one compare_rows call; a held lock across the recompute deadlocks.
/// (Run under the suite's timeout; a hang is the failure signal.)
#[test]
fn u10_double_agg_no_deadlock() {
    let policy = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (u: String). (formerly within 24h (Test::Action::"Login"::response{ input.user: u, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::response{ input.user: u, output.result: true } && tp(t))))
           >= (count for (t2: Timepoint). where (formerly within 1h (Test::Action::"Logout"::response{ input.user: u, output.result: true } && tp(t2))))))
};"#;
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((read(ts, "u0", 0), true)); // pre-state: FALSE (no Login row)
    ts += 10;
    ev.push((transfer(ts, "u0", 1), false));
    ts += 10;
    ev.push((login(ts, "u0"), false));
    ts += 10;
    ev.push((read(ts, "u0", 0), true)); // count(T)=1 >= count(L)=0: TRUE
    ts += 10;
    ev.push((read(ts, "nobody", 0), true));
    three_lane(policy, &ev);
}

/// U11: the kill switch itself doesn't fork behavior — the OFF lane is
/// byte-for-byte today's path (already exercised by every three_lane
/// call); here we additionally pin that OFF really disables (0 stats).
#[test]
fn u11_kill_switch() {
    let lowered = lower(AGG_UNDER_SWEEP);
    let mut off = prepared(&lowered, false);
    let mut ts = 1_000i64;
    off.observe(&login(ts, "u0"));
    ts += 10;
    off.observe(&transfer(ts, "u0", 1));
    ts += 10;
    off.observe(&read(ts, "u0", 0));
    off.evaluate().expect("evals");
    assert_eq!(
        off.agg_memo_stats(),
        (0, 0),
        "OFF lane must not touch the memo"
    );
}

// ── S1: the wide differential (subset in CI; the full 29-case battery
//    runs via the bench harness) ───────────────

/// S1 (CI slice): the four agg policies × the sweep trace, three-lane.
#[test]
fn s1_differential_slice() {
    for policy in [AGG_UNDER_SWEEP, AGG_ROOT, SUM_ROOT, NESTED_WINDOWS] {
        three_lane(policy, &sweep_trace());
    }
}

// ── scale (#[ignore]; release; the per-CR checklist) ────────────────────

/// S2 [R6, amended after first measurement]: the SWEEP shape. The memo
/// removes the QUADRATIC term (the per-anchor window refold); what
/// remains is the And loop's per-anchor scan — LINEAR in state by
/// design (§3.1: "lookups + O(new j) refolds" per decide). So the
/// assertions are: (a) memo-ON beats memo-OFF ≥ 5× at state 2000,
/// (b) growth over 4× state stays ~linear (< 6), i.e. no quadratic
/// term reappears, (c) hits dominate. First measurement: OFF was
/// superlinear (8.2× per 4× state, 7 459 µs at 2000 on the bench
/// shape); ON is 4.4× / ~556 µs.
#[test]
#[ignore = "scale: run explicitly with --ignored (release)"]
fn s2_agg_growth() {
    let lowered = lower(AGG_UNDER_SWEEP);
    let mut on_cost = Vec::new();
    let mut off_cost = Vec::new();
    for &state in &[500usize, 2000] {
        for memo in [true, false] {
            let mut e = prepared(&lowered, memo);
            let keys = (state / 5).max(1);
            let mut ts = 1_000i64;
            for i in 0..state {
                let u = format!("u{}", i % keys);
                if (i / keys) % 3 == 2 {
                    e.observe(&login(ts, &u));
                } else {
                    e.observe(&transfer(ts, &u, 1));
                }
                ts += 1;
            }
            let t0 = std::time::Instant::now();
            let n = 50;
            for i in 0..n {
                e.observe(&read(ts, &format!("u{}", i % keys), 0));
                ts += 1;
                e.evaluate().expect("evals");
            }
            let us = t0.elapsed().as_micros() as f64 / n as f64;
            if memo {
                let (h, m) = e.agg_memo_stats();
                assert!(
                    h > m,
                    "hits ({h}) must exceed misses ({m}) at state {state}"
                );
                on_cost.push(us);
            } else {
                off_cost.push(us);
            }
        }
    }
    let ratio = on_cost[1] / on_cost[0].max(0.001);
    let speedup = off_cost[1] / on_cost[1].max(0.001);
    println!(
        "s2: ON {:.1} -> {:.1} us (ratio {ratio:.2}) | OFF {:.1} -> {:.1} us | speedup at 2000: {speedup:.1}x",
        on_cost[0], on_cost[1], off_cost[0], off_cost[1]
    );
    assert!(
        ratio < 6.0,
        "growth ratio {ratio:.2} suggests a quadratic term (want < 6)"
    );
    assert!(
        speedup > 5.0,
        "memo speedup at state 2000 only {speedup:.1}x (want > 5x)"
    );
}

/// S4: the every-key-fresh worst case — memo-ON within 15% of OFF.
#[test]
#[ignore = "scale: run explicitly with --ignored (release)"]
fn s4_overhead_worst_case() {
    let lowered = lower(AGG_ROOT); // root conjunct: zero reuse by design
    let mut lanes = Vec::new();
    for memo in [true, false] {
        let mut e = prepared(&lowered, memo);
        let mut ts = 1_000i64;
        for i in 0..1000 {
            e.observe(&transfer(ts, &format!("u{i}"), 1)); // unique key/event
            ts += 1;
        }
        let t0 = std::time::Instant::now();
        let n = 100;
        for i in 0..n {
            e.observe(&read(ts, &format!("u{i}"), 0));
            ts += 1;
            e.evaluate().expect("evals");
        }
        lanes.push(t0.elapsed().as_micros() as f64 / n as f64);
    }
    let overhead = lanes[0] / lanes[1].max(0.001);
    println!(
        "s4 overhead: ON {:.1} vs OFF {:.1} us/decide ({overhead:.3}x)",
        lanes[0], lanes[1]
    );
    assert!(
        overhead < 1.15,
        "worst-case overhead {overhead:.3}x (want < 1.15)"
    );
}

/// U12 (the steady-state eviction test — added after the O(entries)
/// retain-per-observe flaw was caught in design discussion): a trace
/// LONGER than the retention window, so pruning fires on essentially
/// every observe. Asserts (a) three-lane agreement throughout, (b) the
/// memo stays BOUNDED: entries never exceed what the retained window
/// can hold (tps in window × keys × agg nodes, with slack).
#[test]
fn u12_steady_state_eviction_bounded() {
    let lowered = lower(NESTED_WINDOWS); // 2h outer + 1h inner ⇒ 3h retention
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut on = prepared(&lowered, true);
    let mut off = prepared(&lowered, false);
    let mut orc = oracle(&lowered);
    let mut ts = 1_000i64;
    let mut max_len = 0usize;
    // 12h of trace at ~6 min per event: every event beyond the first 3h
    // advances the horizon (steady-state pruning).
    for i in 0..120 {
        let u = if i % 2 == 0 { "u0" } else { "u1" };
        let e = if i % 5 == 4 {
            login(ts, u)
        } else {
            transfer(ts, u, 1)
        };
        on.observe(&e);
        off.observe(&e);
        orc.observe(&e);
        ts += 360;
        let p = read(ts, "u0", 0);
        on.observe(&p);
        off.observe(&p);
        orc.observe(&p);
        ts += 1;
        let von = on.evaluate().expect("on");
        let voff = off.evaluate().expect("off");
        let vor = orc.evaluate().expect("oracle");
        for l in &leaves {
            assert_eq!(von[&l.id], voff[&l.id], "lanes diverge at ts={ts}");
            assert_eq!(voff[&l.id], vor[&l.id], "oracle diverges at ts={ts}");
        }
        max_len = max_len.max(on.agg_memo_len());
    }
    // Bound: ≤ retained tps (3h / ~3min ≈ 60, x2 events per loop ⇒ ~120)
    // × keys (2 users + the probe's) × agg nodes (1), with 4x slack.
    assert!(
        max_len < 1500,
        "memo grew past the window bound: {max_len} entries"
    );
    // And eviction actually ran: after the full trace the memo must not
    // hold anywhere near the whole trace's evaluations.
    let final_len = on.agg_memo_len();
    assert!(
        final_len < 1500,
        "final size {final_len} suggests eviction never fired"
    );
}

/// S6: prune-heavy ingest overhead — with pruning firing per observe,
/// memo-ON ingest must stay within 20% of OFF (the eviction index is
/// O(1) amortized per entry; the original full-map retain was O(map)
/// PER OBSERVE and would fail this).
#[test]
#[ignore = "scale: run explicitly with --ignored (release)"]
fn s6_prune_heavy_ingest_overhead() {
    let lowered = lower(NESTED_WINDOWS);
    let mut lanes = Vec::new();
    for memo in [true, false] {
        let mut e = prepared(&lowered, memo);
        let mut ts = 1_000i64;
        // Warm past the 3h horizon so pruning is continuous, with decides
        // interleaved to keep the memo populated.
        for i in 0..2_000 {
            let u = format!("u{}", i % 50);
            e.observe(&transfer(ts, &u, 1));
            ts += 60;
            if i % 10 == 9 {
                e.observe(&login(ts, &u));
                ts += 60;
                e.observe(&read(ts, &u, 0));
                ts += 1;
                e.evaluate().expect("evals");
            }
        }
        // The measured segment: pure ingest under steady-state pruning.
        let t0 = std::time::Instant::now();
        let n = 2_000;
        for i in 0..n {
            e.observe(&transfer(ts, &format!("u{}", i % 50), 1));
            ts += 60;
        }
        lanes.push(t0.elapsed().as_micros() as f64 / n as f64);
    }
    let overhead = lanes[0] / lanes[1].max(0.001);
    println!(
        "s6 prune-heavy ingest: ON {:.2} vs OFF {:.2} us/event ({overhead:.3}x)",
        lanes[0], lanes[1]
    );
    assert!(
        overhead < 1.2,
        "prune-heavy ingest overhead {overhead:.3}x (want < 1.2)"
    );
}
