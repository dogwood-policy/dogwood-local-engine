//! `workload_bench` — temporal-engine benchmark workloads.
//!
//! The generators cover 29 policy shapes across grids of state sizes and policy
//! counts. Separate ingest and decision timings show how each case scales
//! (linear work ~2× per state doubling, quadratic ~4×). The `true#` column is the vacuity guard: a case whose
//! probes never fire is measuring an all-miss path (the
//! multi_since_cross lesson) — treat `true# = 0` as a broken workload.
//!
//! Cases (one `#[test]` each; run one with `--test workload_bench <name>`):
//!
//! | test | original case | shape |
//! |---|---|---|
//! | `once` | once | `formerly within 24h Login` (ctx-correlated) |
//! | `prev` | prev | `previous within 24h Login::request` (per-step setup) |
//! | `since_simple` | since | `!Logout since within 24h Login` (ctx) |
//! | `count_since` | count_since | count over the since body `&& tp(t)`, `n > 0` |
//! | `sum_since` | sum_since | sum of `amount` over `!Refund since Transfer` |
//! | `count_window` | count_window | count over 1h `formerly`; `WINDOW_FRAC` sets the in-window share of state |
//! | `formerly_grid` | formerly_grid_n | P×B×C of plain `formerly` (non-aggregate control) |
//! | `since_grid` | since_grid_n | P×B×C of count-over-(C-way `&&` of ctx since) |
//! | `event_grid` | event_grid_n | same, exists-bound session correlation |
//! | `since_count_grid` | since_count_grid_n | `tp(t)` inside the first anchor: the count is genuinely multi-row |
//! | `event_count_grid` | event_count_grid_n | `count for (s: String)`: distinct active sessions |
//! | `since_churn_grid` | since_churn_grid_n | since_grid's policy, but the guard FIRES (`GUARD_CHURN` logouts per login) |
//! | `mixed_grid` | mixed_grid_n | seeded-PRNG heterogeneous grid (structural analogue; see the case docs) |
//!
//! Optional environment settings for the baseline sweep. Debug builds use
//! smaller workloads:
//!
//! ```text
//! STATE_SIZE=N       warmup anchors when STATE is not the swept axis
//! KEY_RATIO=0.2      distinct keys = ratio * state (min 1)
//! BENCH_MEASURE=50   measured decisions per configuration
//! GRID_POINTS="1 2 4"  points for the case's default axis (grids: C;
//!                      simple cases: STATE; churn: GUARD_CHURN;
//!                      count_window: percent in window, e.g. "100 50 10")
//! BENCH_SEED=1       mixed_grid PRNG seed
//! ```
//!
//! Run everything:
//! ```text
//! cargo test --release \
//!   -p dogwood-local-engine --test workload_bench -- --nocapture --test-threads=1 --ignored
//! ```

use std::time::{Duration, Instant};

use dogwood_language::{
    Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, Value,
};
use dogwood_local_engine::LocalTemporalEngine;

// ------------------------------------------------------------------ schema

/// One namespace carrying every action any case needs.
const SCHEMA: &str = r#"
namespace Test {
  type LoginInput = { user: String, session: String };
  type LoginOutput = { result: Bool };
  type LogoutInput = { user: String, session: String };
  type LogoutOutput = { result: Bool };
  type TransferInput = { user: String, amount: Long };
  type TransferOutput = { result: Bool };
  type RefundInput = { user: String };
  type RefundOutput = { result: Bool };
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
  action "Refund" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: RefundInput, output: RefundOutput }
  };
  action "Read" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: ReadInput }
  };
}
"#;

/// The bench event schema: unpinned, with `max_window` raised to a year so
/// the grids' unique-window allocation (n * 4h) never hits the 24h default
/// cap.
const BENCH_EVENT_SCHEMA: &str = r#"
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
    // UNPINNED (raised max_window) + validated, matching the original bench
    // harness exactly: the pinned default RELATIVIZES leaves (e.g. positive-left
    // since -> count aggregation; `previous` -> a shape 3 orders of magnitude
    // slower in BOTH engines), so pinned lowering benchmarks rewritten shapes
    // the original workload never ships.
    let service = ServiceSchema::builder()
        .event_schema_str(BENCH_EVENT_SCHEMA)
        .build()
        .expect("unpinned event schema builds");
    let lowered = LoweredPolicySet::from_str(policy, &service, &schema).expect("policy lowers");
    let validation = dogwood_language::Validator::new().validate(&lowered);
    assert!(
        validation.validation_passed(),
        "bench policy must validate cleanly: {:?}",
        validation.validation_errors().collect::<Vec<_>>()
    );
    lowered
}

// ------------------------------------------------------------------ events

fn user(k: usize) -> String {
    format!("user_{k}")
}

fn base(action: &str, sig: &str, ts: i64) -> dogwood_language::EventBuilder {
    Event::builder(&format!("Test::Action::{action}"), sig)
        .timestamp(ts)
        .principal("Test::User::\"alice\"")
        .resource("Test::Gateway::\"gw\"")
}

fn login_req(ts: i64, k: usize) -> Event {
    base("Login", "request", ts)
        .field("input", "user", Value::String(user(k)))
        .field("input", "session", Value::String(format!("sess_{k}")))
        .request_context("input", "user", Value::String(user(k)))
        .build()
}

fn login_resp(ts: i64, k: usize) -> Event {
    base("Login", "response", ts)
        .field("input", "user", Value::String(user(k)))
        .field("input", "session", Value::String(format!("sess_{k}")))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user(k)))
        .build()
}

fn logout_resp(ts: i64, k: usize) -> Event {
    base("Logout", "response", ts)
        .field("input", "user", Value::String(user(k)))
        .field("input", "session", Value::String(format!("sess_{k}")))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user(k)))
        .build()
}

fn transfer_resp(ts: i64, k: usize, amount: i64) -> Event {
    base("Transfer", "response", ts)
        .field("input", "user", Value::String(user(k)))
        .field("input", "amount", Value::Int(amount))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user(k)))
        .build()
}

fn refund_resp(ts: i64, k: usize) -> Event {
    base("Refund", "response", ts)
        .field("input", "user", Value::String(user(k)))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user(k)))
        .build()
}

fn read_req(ts: i64, who: &str) -> Event {
    base("Read", "request", ts)
        .field("input", "user", Value::String(who.into()))
        .request_context("input", "user", Value::String(who.into()))
        .build()
}

// ----------------------------------------------------------------- harness

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn keys_for(state: usize) -> usize {
    let ratio: f64 = std::env::var("KEY_RATIO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.2);
    ((state as f64 * ratio) as usize).max(1)
}

fn measure_count() -> usize {
    env_usize("BENCH_MEASURE", 50)
}

/// A measured decision: untimed setup events, then the timed probe
/// (matching the original harness's `MeasuredStep`).
struct Step {
    setup: Vec<Event>,
    probe: Event,
}

/// Plain probes alternating a warmed key and an unknown user (mixed
/// outcomes for context-correlated cases).
fn alternating_probes(ts: &mut i64, keys: usize, n: usize) -> Vec<Step> {
    (0..n)
        .map(|i| {
            let who = if i % 2 == 0 {
                user(i % keys)
            } else {
                "nobody".into()
            };
            let probe = read_req(*ts, &who);
            *ts += 1;
            Step {
                setup: Vec::new(),
                probe,
            }
        })
        .collect()
}

struct Metrics {
    prepare_ms: f64,
    ingest_us: f64,
    decide_us: f64,
}

fn lane<E: TemporalEngine>(
    mut engine: E,
    lowered: &LoweredPolicySet,
    warmup: &[Event],
    steps: &[Step],
) -> (Metrics, Vec<usize>) {
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();

    let t0 = Instant::now();
    engine.prepare(&leaves, &schema, &sigs).expect("prepare");
    let prepare_ms = t0.elapsed().as_secs_f64() * 1e3;

    let t0 = Instant::now();
    for ev in warmup {
        engine.observe(ev);
    }
    let ingest_us = if warmup.is_empty() {
        0.0
    } else {
        t0.elapsed().as_micros() as f64 / warmup.len() as f64
    };

    let mut verdicts = Vec::with_capacity(steps.len());
    let mut timed = Duration::ZERO;
    for step in steps {
        for ev in &step.setup {
            engine.observe(ev); // untimed, as in DTC
        }
        let t0 = Instant::now();
        engine.observe(&step.probe);
        let v = engine.evaluate().expect("evaluate");
        timed += t0.elapsed();
        verdicts.push(v.values().filter(|b| **b).count());
    }
    let decide_us = timed.as_micros() as f64 / steps.len() as f64;

    (
        Metrics {
            prepare_ms,
            ingest_us,
            decide_us,
        },
        verdicts,
    )
}

fn header(case: &str, axis: &str) {
    println!();
    println!("== {case} (axis: {axis}) ==");
    println!(
        "{:>10} | {:>6} | {:>8} | {:>8} | {:>9} | {:>6}",
        axis, "state", "prep-ms", "ing-us", "dec-us", "true#"
    );
}

/// Run both lanes on one configuration, cross-check, print one row.
fn run(
    axis_val: &str,
    state: usize,
    lowered: &LoweredPolicySet,
    warmup: Vec<Event>,
    steps: Vec<Step>,
) {
    let (inc, vi) = lane(LocalTemporalEngine::new(), lowered, &warmup, &steps);
    // Vacuity visibility (the multi_since_cross lesson): a bench whose
    // probes never fire measures an all-miss path without saying so. Print
    // the count of TRUE verdicts.
    let trues: usize = vi.iter().sum();
    println!(
        "{axis_val:>10} | {state:>6} | {:>8.1} | {:>8.1} | {:>9.1} | {trues:>6}",
        inc.prepare_ms, inc.ingest_us, inc.decide_us,
    );
}

fn axis_points(default: &[usize]) -> Vec<usize> {
    match std::env::var("GRID_POINTS") {
        Ok(s) => s
            .split_whitespace()
            .map(|v| v.parse().expect("GRID_POINTS parses"))
            .collect(),
        Err(_) => default.to_vec(),
    }
}

#[cfg(debug_assertions)]
const SIMPLE_STATES: &[usize] = &[0, 200];
#[cfg(not(debug_assertions))]
const SIMPLE_STATES: &[usize] = &[0, 500, 2_000];
#[cfg(debug_assertions)]
const GRID_C: &[usize] = &[1, 2];
#[cfg(not(debug_assertions))]
const GRID_C: &[usize] = &[1, 2, 4];

fn grid_state() -> usize {
    let s = env_usize("STATE_SIZE", 500);
    #[cfg(debug_assertions)]
    let s = s.min(100);
    s
}

// ---------------------------------------------------- simple case policies

const ONCE_POLICY: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    formerly within 24h
        Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }
};"#;

const PREV_POLICY: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    previous within 24h
        Test::Action::"Login"::request{ input.user: context.input.user }
};"#;

const SINCE_POLICY: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    !Test::Action::"Logout"::response{ input.user: context.input.user, output.result: true }
    since within 24h
    Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }
};"#;

const COUNT_SINCE_POLICY: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (n: Long). ((count for (t: Timepoint). where (
        (!Test::Action::"Logout"::response{ input.user: context.input.user, output.result: true }
         since within 24h
         Test::Action::"Login"::response{ input.user: context.input.user, output.result: true })
        && tp(t))) == n && n > 0)
};"#;

const SUM_SINCE_POLICY: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (total: Long). ((sum a for (a: Long), (t: Timepoint). where (
        (!Test::Action::"Refund"::response{ input.user: context.input.user, output.result: true }
         since within 24h
         Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a, output.result: true })
        && tp(t))) == total && total >= 0)
};"#;

const COUNT_WINDOW_POLICY: &str = r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (n: Long). ((count for (t: Timepoint). where (
        (formerly within 1h
            Test::Action::"Login"::response{ input.user: context.input.user, output.result: true })
        && tp(t))) == n && n > 0)
};"#;

/// Login-anchored simple case: warmup logins over the key set, alternating
/// probes.
fn login_case(policy: &str, name: &str) {
    header(name, "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(policy);
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                let e = login_resp(ts, i % keys);
                ts += 1;
                e
            })
            .collect();
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn once() {
    login_case(ONCE_POLICY, "once");
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn since_simple() {
    login_case(SINCE_POLICY, "since_simple");
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn count_since() {
    login_case(COUNT_SINCE_POLICY, "count_since");
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn sum_since() {
    header("sum_since", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(SUM_SINCE_POLICY);
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                let e = transfer_resp(ts, i % keys, 50);
                ts += 1;
                e
            })
            .collect();
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// `previous` holds one row per timepoint: each measured step's setup is a
/// Login REQUEST at the immediately preceding timepoint (untimed), then the
/// timed Read (as in the original `prev`; state axis is meaningless here).
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn prev() {
    header("prev", "n/a");
    let lowered = lower(PREV_POLICY);
    let state = 100usize;
    let keys = keys_for(state);
    let mut ts = 1i64;
    let warmup: Vec<Event> = (0..state)
        .map(|i| {
            let e = login_req(ts, i % keys);
            ts += 1;
            e
        })
        .collect();
    let steps: Vec<Step> = (0..measure_count())
        .map(|i| {
            let setup = vec![login_req(ts, i % keys)];
            ts += 1;
            let probe = read_req(ts, &user(i % keys));
            ts += 1;
            Step { setup, probe }
        })
        .collect();
    run("-", 1, &lowered, warmup, steps);
}

/// `count_window`: warmup spread over `window/frac` seconds so the newest
/// `frac` share of state is in the 1h window at the first probe. The axis
/// is the percentage in window.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn count_window() {
    const WINDOW_SECS: i64 = 3_600;
    #[cfg(debug_assertions)]
    const FRACS: &[usize] = &[100];
    #[cfg(not(debug_assertions))]
    const FRACS: &[usize] = &[100, 50, 10];

    header("count_window", "pct-in-win");
    let state = {
        let s = env_usize("STATE_SIZE", 1_000);
        #[cfg(debug_assertions)]
        let s = s.min(100);
        s
    };
    for &pct in &axis_points(FRACS) {
        let frac = pct as f64 / 100.0;
        let lowered = lower(COUNT_WINDOW_POLICY);
        let keys = keys_for(state);
        let warmup_span = ((WINDOW_SECS as f64) / frac).ceil() as i64;
        let slot_step = if state > 0 {
            (warmup_span / state as i64).max(1)
        } else {
            1
        };
        let anchor = slot_step * state as i64 + 1;
        let warmup: Vec<Event> = (0..state)
            .map(|slot| login_resp(anchor - slot_step * (state - slot) as i64, slot % keys))
            .collect();
        let mut ts = anchor;
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&format!("{pct}%"), state, &lowered, warmup, steps);
    }
}

// ------------------------------------------------------------- grid cases

/// The since/formerly condition vocabulary shared by all grids.
/// `corr`: how the condition correlates. Windows are handed out by the
/// caller so they stay globally unique (4h, 8h, …).
enum Corr<'a> {
    Ctx,
    Var(&'a str),
}

fn since_cond(hours: usize, corr: &Corr<'_>, tp_var: Option<&str>) -> String {
    let key = match corr {
        Corr::Ctx => "input.user: context.input.user".to_string(),
        Corr::Var(v) => format!("input.session: {v}"),
    };
    let anchor = match tp_var {
        Some(t) => format!(
            "(Test::Action::\"Login\"::response{{ {key}, output.result: true }} && tp({t}))"
        ),
        None => format!("Test::Action::\"Login\"::response{{ {key}, output.result: true }}"),
    };
    format!(
        "(!Test::Action::\"Logout\"::response{{ {key}, output.result: true }} \
         since within {hours}h {anchor})"
    )
}

fn formerly_cond(hours: usize) -> String {
    format!(
        "(formerly within {hours}h \
         Test::Action::\"Login\"::response{{ input.user: context.input.user, output.result: true }})"
    )
}

/// Block styles across the grid family (P policies × B blocks, `&&`-joined).
enum Block {
    /// count over C-way && of ctx-correlated since, `&& tp(t)` at top level
    /// (since_grid: the count is 0-or-1).
    SinceCount,
    /// same but exists-bound session (event_grid).
    EventCount,
    /// `tp(t)` inside the FIRST condition's anchor (since_count_grid: the
    /// count is the number of in-window anchors).
    SinceCountTp,
    /// `count for (s: String)` binding the session (event_count_grid:
    /// distinct active sessions).
    EventCountDistinct,
    /// plain C-way && of formerly, no aggregate (formerly_grid).
    Formerly,
}

fn block_source(style: &Block, b: usize, c: usize, window: &mut dyn FnMut() -> usize) -> String {
    match style {
        Block::SinceCount => {
            let conds: Vec<_> = (0..c)
                .map(|_| since_cond(window(), &Corr::Ctx, None))
                .collect();
            format!(
                "(exists (n{b}: Long). ((count for (t{b}: Timepoint). where \
                 (({conds}) && tp(t{b}))) == n{b} && n{b} > 0))",
                conds = conds.join(" && ")
            )
        }
        Block::EventCount => {
            let sv = format!("s{b}");
            let conds: Vec<_> = (0..c)
                .map(|_| since_cond(window(), &Corr::Var(&sv), None))
                .collect();
            format!(
                "(exists (n{b}: Long). ((count for (t{b}: Timepoint). where \
                 ((exists ({sv}: String). ({conds})) && tp(t{b}))) == n{b} && n{b} > 0))",
                conds = conds.join(" && ")
            )
        }
        Block::SinceCountTp => {
            let tv = format!("t{b}");
            let conds: Vec<_> = (0..c)
                .map(|i| since_cond(window(), &Corr::Ctx, (i == 0).then_some(tv.as_str())))
                .collect();
            format!(
                "(exists (n{b}: Long). ((count for ({tv}: Timepoint). where \
                 ({conds})) == n{b} && n{b} > 0))",
                conds = conds.join(" && ")
            )
        }
        Block::EventCountDistinct => {
            let sv = format!("s{b}");
            let conds: Vec<_> = (0..c)
                .map(|_| since_cond(window(), &Corr::Var(&sv), None))
                .collect();
            format!(
                "(exists (n{b}: Long). ((count for ({sv}: String). where \
                 ({conds})) == n{b} && n{b} > 0))",
                conds = conds.join(" && ")
            )
        }
        Block::Formerly => {
            let conds: Vec<_> = (0..c).map(|_| formerly_cond(window())).collect();
            format!("({})", conds.join(" && "))
        }
    }
}

fn grid_source(mk_block: impl Fn(usize) -> Block, p: usize, b: usize, c: usize) -> String {
    let mut next = 0usize;
    let mut window = move || {
        next += 1;
        next * 4
    };
    let mut src = String::new();
    for _ in 0..p {
        let body = (0..b)
            .map(|blk| block_source(&mk_block(blk), blk, c, &mut window))
            .collect::<Vec<_>>()
            .join("\n    &&\n    ");
        src.push_str(&format!(
            "permit (principal, action == Test::Action::\"Read\", resource)\n\
             when temporal {{\n    {body}\n}};\n\n"
        ));
    }
    src
}

/// A grid case swept along C (others at 1), login warmup, alternating probes.
fn grid_case(name: &str, style: fn(usize) -> Block) {
    header(name, "C");
    let state = grid_state();
    for &c in &axis_points(GRID_C) {
        let lowered = lower(&grid_source(style, 1, 1, c));
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                let e = login_resp(ts, i % keys);
                ts += 1;
                e
            })
            .collect();
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&c.to_string(), state, &lowered, warmup, steps);
    }
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn formerly_grid() {
    grid_case("formerly_grid", |_| Block::Formerly);
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn since_grid() {
    grid_case("since_grid", |_| Block::SinceCount);
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn event_grid() {
    grid_case("event_grid", |_| Block::EventCount);
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn since_count_grid() {
    grid_case("since_count_grid", |_| Block::SinceCountTp);
}

#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn event_count_grid() {
    grid_case("event_count_grid", |_| Block::EventCountDistinct);
}

/// since_grid's policy, but the guard FIRES: per anchor, `churn` logouts
/// follow the login; a trailing login per key keeps the verdict permitting.
/// Sweep churn with anchors HELD FIXED (the reading: flat cost = guard
/// state bounded; climbing = it is not).
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn since_churn_grid() {
    #[cfg(debug_assertions)]
    const CHURNS: &[usize] = &[0, 1];
    #[cfg(not(debug_assertions))]
    const CHURNS: &[usize] = &[0, 1, 4];

    header("since_churn_grid", "churn");
    let state = grid_state();
    for &churn in &axis_points(CHURNS) {
        let lowered = lower(&grid_source(|_| Block::SinceCount, 1, 1, 1));
        let keys = keys_for(state);
        let mut ts = 1i64;
        let mut warmup = Vec::new();
        for i in 0..state {
            let k = i % keys;
            warmup.push(login_resp(ts, k));
            ts += 1;
            for _ in 0..churn {
                warmup.push(logout_resp(ts, k));
                ts += 1;
            }
        }
        for k in 0..keys {
            warmup.push(login_resp(ts, k));
            ts += 1;
        }
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&churn.to_string(), state, &lowered, warmup, steps);
    }
}

/// Heterogeneous control (the original `mixed_grid_n`, structural analogue): block
/// styles drawn from a seeded xorshift PRNG over the proven templates, so no
/// two subgraphs are string-identical while staying structurally related.
/// The reading: an optimization that only fires on copy-paste shows
/// a gap against since_grid; one recognizing structural sameness closes it.
/// (The original's finer BENCH_MIX granularity — varying the action pair per
/// condition — is not reproduced.)
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn mixed_grid() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }
    let seed = env_usize("BENCH_SEED", 1) as u64;

    header("mixed_grid", "C");
    let state = grid_state();
    for &c in &axis_points(GRID_C) {
        let mut rng = Rng(seed.max(1));
        // B=4 blocks so the mix is visible even at C=1; styles drawn per block.
        let styles: Vec<Block> = (0..4)
            .map(|_| match rng.next() % 3 {
                0 => Block::SinceCount,
                1 => Block::EventCount,
                _ => Block::Formerly,
            })
            .collect();
        let src = {
            let mut next = 0usize;
            let mut window = move || {
                next += 1;
                next * 4
            };
            let body = styles
                .iter()
                .enumerate()
                .map(|(blk, st)| block_source(st, blk, c, &mut window))
                .collect::<Vec<_>>()
                .join("\n    &&\n    ");
            format!(
                "permit (principal, action == Test::Action::\"Read\", resource)\n\
                 when temporal {{\n    {body}\n}};\n"
            )
        };
        let lowered = lower(&src);
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                let e = login_resp(ts, i % keys);
                ts += 1;
                e
            })
            .collect();
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&c.to_string(), state, &lowered, warmup, steps);
    }
}

// ── nested temporal workloads ──────────────────────────────────────────

/// Nested-formerly policy of the given DEPTH: the outermost atom is a
/// Transfer response, each inner level wraps another `formerly` around the
/// next atom in [Refund, Logout, Login], windows shrinking inward. Depth 1
/// is the 1132 shape; every level past the atom is a FREEZE JOIN.
fn nested_policy(depth: usize) -> String {
    // Innermost level: a plain formerly over Login (1h). Each wrap adds a
    // freeze join: Refund (6h), then Logout (12h); the outermost conjunct
    // is always Transfer under a 24h window.
    let mut inner = String::from(
        "formerly within 1h Test::Action::\"Login\"::response{ input.user: context.input.user, output.result: true }",
    );
    let mids: [(&str, &str); 2] = [("Refund", "6h"), ("Logout", "12h")];
    for (action, window) in mids.iter().take(depth.saturating_sub(1)) {
        inner = format!(
            "formerly within {window} (Test::Action::\"{action}\"::response{{ input.user: context.input.user, output.result: true }} && {inner})"
        );
    }
    format!(
        "permit (principal, action == Test::Action::\"Read\", resource)\nwhen temporal {{\n    formerly within 24h (Test::Action::\"Transfer\"::response{{ input.user: context.input.user, output.result: true }} && {inner})\n}};"
    )
}

/// Warmup for depth-d nesting: per key, the event cycle
/// [Login, (Refund), (Logout), Transfer] at 1s spacing, so every Transfer
/// step qualifies through every level.
fn nested_warmup(state: usize, keys: usize, depth: usize, ts: &mut i64) -> Vec<Event> {
    let mut out = Vec::with_capacity(state);
    let mut k = 0usize;
    while out.len() < state {
        out.push(login_resp(*ts, k % keys));
        *ts += 1;
        if depth >= 2 && out.len() < state {
            out.push(refund_resp(*ts, k % keys));
            *ts += 1;
        }
        if depth >= 3 && out.len() < state {
            out.push(logout_resp(*ts, k % keys));
            *ts += 1;
        }
        if out.len() < state {
            out.push(transfer_resp(*ts, k % keys, 1));
            *ts += 1;
        }
        k += 1;
    }
    out
}

/// The 1132 shape (one freeze join) swept along STATE.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn nested_formerly() {
    header("nested_formerly", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(&nested_policy(1));
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup = nested_warmup(state, keys, 1, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// Point-native inner (`previous`): must cost like a plain formerly.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn nested_previous() {
    header("nested_previous", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    formerly within 24h (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
        && previous within 1h Test::Action::"Login"::response{ input.user: context.input.user, output.result: true })
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        // Login immediately before each Transfer: previous holds per step.
        let warmup = nested_warmup(state, keys, 1, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// Nesting DEPTH axis (1/2/3 freeze joins stacked), fixed state.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn nested_depth() {
    #[cfg(debug_assertions)]
    const DEPTHS: &[usize] = &[1, 2];
    #[cfg(not(debug_assertions))]
    const DEPTHS: &[usize] = &[1, 2, 3];
    header("nested_depth", "depth");
    let state = grid_state();
    for &depth in &axis_points(DEPTHS) {
        let lowered = lower(&nested_policy(depth));
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup = nested_warmup(state, keys, depth, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&depth.to_string(), state, &lowered, warmup, steps);
    }
}

/// Direction 1 of aggregate×nesting: a COUNT wrapping the nested-formerly
/// shape (the freeze join runs under the aggregate; top-level tp is
/// virtual, so the count is the 0/1 existence aggregate).
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn nested_agg() {
    header("nested_agg", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (n: Long). ((count for (t: Timepoint). where (
        (formerly within 24h (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
            && formerly within 1h Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }))
        && tp(t))) == n && n > 0)
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup = nested_warmup(state, keys, 1, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// An aggregate threshold inside a `formerly` body (the freeze
/// outer join capturing count-at-j; the threshold read as a residual).
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn agg_in_window() {
    header("agg_in_window", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    formerly within 24h (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Login"::response{ input.user: context.input.user, output.result: true } && tp(t)))) >= 1)
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup = nested_warmup(state, keys, 1, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// The since-ANCHOR composition: the anchor qualifies at birth via a
/// frozen aggregate; the negated guard rides the Stage-1 kill machinery.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn agg_in_since_anchor() {
    header("agg_in_since_anchor", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    !Test::Action::"Logout"::response{ input.user: context.input.user, output.result: true }
    since within 24h
    (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Login"::response{ input.user: context.input.user, output.result: true } && tp(t)))) >= 1)
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup = nested_warmup(state, keys, 1, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// Correlated aggregate ("some user who logged in AND — that same user —
/// made ≥ threshold transfers"): the per-binder totals join the enclosing
/// relation in delta-land; the threshold reads the joined total per
/// decision. The leaf has ONE param (the threshold), so the view is keyed
/// by it only at read; the binder column stays relational.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn correlated_agg() {
    header("correlated_agg", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (u: String). (
        formerly within 24h Test::Action::"Login"::response{ input.user: u, output.result: true }
        && (count for (t: Timepoint). where (formerly within 24h (Test::Action::"Transfer"::response{ input.user: u, output.result: true } && tp(t)))) >= 3)
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        // Cycle [Login, Transfer] per key: every key accumulates
        // state/(2*keys) transfers — some cross the threshold, most reads
        // scan the joined relation.
        let warmup = nested_warmup(state, keys, 1, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// Per-row aggregate threshold: "some transfer whose amount is below the
/// user's own transfer count" — the total joins the enclosing relation;
/// the comparison is column-vs-column per row at read.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn per_row_agg() {
    header("per_row_agg", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (u: String). (exists (a: Long). (
        formerly within 24h Test::Action::"Transfer"::response{ input.user: u, input.amount: a, output.result: true }
        && (count for (t: Timepoint). where (formerly within 24h (Test::Action::"Login"::response{ input.user: u, output.result: true } && tp(t)))) > a))
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        // [Login, Transfer(PER_ROW_AMOUNT)] cycle. With the default key
        // ratio each user gets ~2.5 logins REGARDLESS of state, so:
        // amount 1 → most users qualify, reads early-exit on the first
        // surviving row; amount ≥ 5 → nobody qualifies and every read
        // scans the ENTIRE joined relation (the full-scan regime).
        // PER_ROW_AMOUNT=0 → DISTINCT per-row amounts (all failing): the
        // project-dedup cannot collapse the joined relation, so reads scan
        // one row per in-window transfer — the true full-scan regime.
        let amount = env_usize("PER_ROW_AMOUNT", 1) as i64;
        let warmup: Vec<Event> = {
            let mut out = Vec::with_capacity(state);
            let mut k = 0usize;
            while out.len() < state {
                out.push(login_resp(ts, k % keys));
                ts += 1;
                if out.len() < state {
                    let a = if amount == 0 { 5 + k as i64 } else { amount };
                    out.push(transfer_resp(ts, k % keys, a));
                    ts += 1;
                }
                k += 1;
            }
            out
        };
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// The freeze antijoin: "a transfer with NO login in the second before
/// it". The [Login, Transfer, Transfer] cycle makes the first transfer
/// fail (login 1s before) and the second qualify — a 50/50 mix, so both
/// antijoin paths and the frozen log carry real rows.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn negated_nested_window() {
    header("negated_nested_window", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    formerly within 24h (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
        && !(formerly within 1s Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }))
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = {
            let mut out = Vec::with_capacity(state);
            let mut k = 0usize;
            while out.len() < state {
                out.push(login_resp(ts, k % keys));
                ts += 1;
                for _ in 0..2 {
                    if out.len() < state {
                        out.push(transfer_resp(ts, k % keys, 1));
                        ts += 1;
                    }
                }
                k += 1;
            }
            out
        };
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// Correlated aggregate INSIDE a window body: "a login at a step where
/// that user had ≥ 2 recent transfers" — per-binder capture through the
/// freeze outer join. The [Transfer, Transfer, Login] cycle qualifies
/// every login.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn corr_agg_in_window() {
    header("corr_agg_in_window", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (u: String). (formerly within 24h (Test::Action::"Login"::response{ input.user: u, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::response{ input.user: u, output.result: true } && tp(t)))) >= 2))
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = {
            let mut out = Vec::with_capacity(state);
            let mut k = 0usize;
            while out.len() < state {
                for _ in 0..2 {
                    if out.len() < state {
                        out.push(transfer_resp(ts, k % keys, 1));
                        ts += 1;
                    }
                }
                if out.len() < state {
                    out.push(login_resp(ts, k % keys));
                    ts += 1;
                }
                k += 1;
            }
            out
        };
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// Exclusion `!=` in a since-left, nested so Read probes work (a positive
/// left must match at the evaluation step). The anchor binds the compared
/// amount (frontend range restriction requires it); probes carry the
/// threshold and read the frozen anchor-bound values per request.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn exclusion_since_left() {
    header("exclusion_since_left", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (a: Long). (formerly within 24h ((Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a, output.result: true }
        && a != context.input.threshold)
    since within 1h
    Test::Action::"Transfer"::response{ input.user: context.input.user, input.amount: a, output.result: true }))
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        // All transfers (each anchors AND extends streaks), amount 1.
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                let e = transfer_resp(ts, i % keys, 1);
                ts += 1;
                e
            })
            .collect();
        // Probes alternate warmed/unknown users and thresholds 0/1 (1 =
        // the anchor-bound amount: excluded → false; 0: alive → true).
        let steps: Vec<Step> = (0..measure_count())
            .map(|i| {
                let who = if i % 2 == 0 {
                    user(i % keys)
                } else {
                    "nobody".into()
                };
                let probe = base("Read", "request", ts)
                    .field("input", "user", Value::String(who.clone()))
                    .request_context("input", "user", Value::String(who))
                    .request_context("input", "threshold", Value::Int((i % 2) as i64))
                    .build();
                ts += 1;
                Step {
                    setup: Vec::new(),
                    probe,
                }
            })
            .collect();
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// The LET-ENCODED aggregate binding in a window, DOUBLE-bounded
/// (`== n && n >= 1 && n <= 3`): agg_in_window's circuit plus one extra
/// residual per read — the substitution design's cost profile.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn let_agg_binding() {
    header("let_agg_binding", "STATE");
    for &state in &axis_points(SIMPLE_STATES) {
        let lowered = lower(
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (n: Long). (formerly within 24h (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Login"::response{ input.user: context.input.user, output.result: true } && tp(t)))) == n
        && n >= 1 && n <= 3))
};"#,
        );
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup = nested_warmup(state, keys, 1, &mut ts);
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// THE PRODUCTION CONFIGURATION: the DEFAULT (pinned) schema,
/// head-to-head — the incumbent evaluates the RELATIVIZED leaves globally
/// (production today: positive-left since → the count-equality encoding);
/// the IVM engine evaluates the NON-relativized leaves natively
/// partitioned by callerPrincipal. Verdict streams cross-checked.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn pinned_since_native() {
    header("pinned_since_native", "STATE");
    let policy = r#"permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    Test::Action::"Transfer"::request{ input.user: context.input.user }
    since within 24h
    Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }
};"#;
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema builds");
    let service = ServiceSchema::builder().build().expect("default builds");
    let lowered = LoweredPolicySet::from_str(policy, &service, &schema).expect("policy lowers");
    let rel: Vec<_> = lowered.temporal_fields().cloned().collect();
    // TWO LANES since native partitioning landed: the old production
    // configuration (relativized leaves, one global trace) vs native
    // sharding (non-relativized leaves, a monitor shard per pin).
    let nonrel: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let pin_keys = lowered.partition_keys().to_vec();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let cedar = lowered.cedar_schema().clone();

    let who = |k: usize| format!("Test::User::\"u{k}\"");
    let login = |ts: i64, k: usize| {
        let user = format!("user_{k}");
        Event::builder("Test::Action::Login", "response")
            .timestamp(ts)
            .principal(&who(k))
            .resource("Test::Gateway::\"gw\"")
            .field("input", "user", Value::String(user.clone()))
            .field("output", "result", Value::Bool(true))
            .request_context("input", "user", Value::String(user))
            .build()
    };
    let probe = |ts: i64, k: usize, known: bool| {
        let user = if known {
            format!("user_{k}")
        } else {
            "nobody".to_string()
        };
        Event::builder("Test::Action::Transfer", "request")
            .timestamp(ts)
            .principal(&who(k))
            .resource("Test::Gateway::\"gw\"")
            .field("input", "user", Value::String(user.clone()))
            .request_context("input", "user", Value::String(user))
            .build()
    };

    for &state in &axis_points(SIMPLE_STATES) {
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                let e = login(ts, i % keys);
                ts += 1;
                e
            })
            .collect();
        let probes: Vec<Event> = (0..measure_count())
            .map(|i| {
                let e = probe(ts, i % keys, i % 2 == 0);
                ts += 1;
                e
            })
            .collect();

        // Incumbent lane: relativized, global (production today).
        let mut inc = LocalTemporalEngine::new();
        inc.prepare(&rel, &cedar, &sigs)
            .expect("incumbent prepares");
        let t0 = std::time::Instant::now();
        for e in &warmup {
            inc.observe(e);
        }
        let inc_ingest = t0.elapsed().as_micros() as f64 / warmup.len().max(1) as f64;
        let mut vi = Vec::new();
        let t0 = std::time::Instant::now();
        for e in &probes {
            inc.observe(e);
            let v = inc.evaluate().expect("inc evals");
            vi.push(rel.iter().filter(|l| v[&l.id]).count());
        }
        let inc_us = t0.elapsed().as_micros() as f64 / probes.len() as f64;

        // NATIVE lane: sharded, non-relativized.
        let mut nat = LocalTemporalEngine::new();
        nat.set_partition_keys(&pin_keys);
        nat.prepare(&nonrel, &cedar, &sigs)
            .expect("native prepares");
        let t0 = std::time::Instant::now();
        for e in &warmup {
            nat.observe(e);
        }
        let nat_ingest = t0.elapsed().as_micros() as f64 / warmup.len().max(1) as f64;
        let mut vn = Vec::new();
        let t0 = std::time::Instant::now();
        for e in &probes {
            nat.observe(e);
            let v = nat.evaluate().expect("native evals");
            vn.push(nonrel.iter().filter(|l| v[&l.id]).count());
        }
        let nat_us = t0.elapsed().as_micros() as f64 / probes.len() as f64;
        assert_eq!(
            vi, vn,
            "relativized vs native verdicts diverge at state={state}"
        );

        let trues: usize = vi.iter().sum();
        assert!(
            state == 0 || trues > 0,
            "vacuous pinned workload at state={state}: true# must be nonzero"
        );
        println!(
            "{state:>10} | {state:>6} | rel {:>7.1} {:>9.1} | nat {:>7.1} {:>9.1} | {:>6.1}x | {trues:>6}",
            inc_ingest,
            inc_us,
            nat_ingest,
            nat_us,
            inc_us / nat_us.max(0.001),
        );
    }
}

/// MIXED-BODY nested since: `formerly ((X since B) && foo)` does NOT take
/// the bare divergence read — it freezes foo(j) ⋈ live-anchors per step.
/// Two variants: foo KEY-SHARED with the since (the common shape; expected
/// flat) and foo UNSHARED (the cross-join worst case; expected O(anchors)
/// per step — this case documents the boundary).
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn nested_mixed_since() {
    for (label, policy) in [
        (
            "key-shared",
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    formerly within 24h (Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }
        && (!Test::Action::"Logout"::response{ input.user: context.input.user, output.result: true }
            since within 1h
            Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }))
};"#,
        ),
        (
            "unshared",
            r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    formerly within 24h (Test::Action::"Login"::response{ output.result: true }
        && (!Test::Action::"Logout"::response{ input.user: context.input.user, output.result: true }
            since within 1h
            Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }))
};"#,
        ),
    ] {
        header(&format!("nested_mixed_since/{label}"), "STATE");
        let lowered = lower(policy);
        for &state in &axis_points(SIMPLE_STATES) {
            let keys = keys_for(state);
            let mut ts = 1i64;
            // Interleave Transfers (anchors+steps) with occasional Logins
            // (the outer-body match that triggers a freeze).
            let warmup: Vec<Event> = (0..state)
                .map(|i| {
                    // ONE dedicated login round (block 3 of 5, always inside
                    // warmup at KEY_RATIO 0.2): every user logs in once, with
                    // transfers before and after — modular interleaves keep
                    // missing probed users (the true# column's lesson).
                    let e = if i / keys == 3 {
                        login_resp(ts, i % keys)
                    } else {
                        transfer_resp(ts, i % keys, 1)
                    };
                    ts += 1;
                    e
                })
                .collect();
            let steps = alternating_probes(&mut ts, keys, measure_count());
            run(&state.to_string(), state, &lowered, warmup, steps);
        }
    }
}

/// MULTI-SINCE interval route: two sibling sinces in one window body —
/// the joined-anchor read (per-key anchor pairs, intersected intervals).
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn multi_since_interval() {
    header("multi_since_interval", "STATE");
    let lowered = lower(
        r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    formerly within 24h (Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
        && (!Test::Action::"Logout"::response{ input.user: context.input.user, output.result: true }
            since within 24h
            Test::Action::"Login"::response{ input.user: context.input.user, output.result: true })
        && (!Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }
            since within 24h
            Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }))
};"#,
    );
    for &state in &axis_points(SIMPLE_STATES) {
        let keys = keys_for(state);
        let mut ts = 1i64;
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                // Block-wise rounds (the multi_since_cross vacuity lesson):
                // i%4 with keys divisible by 4 never logs probed users in.
                let e = if (i / keys) % 4 == 3 {
                    login_resp(ts, i % keys)
                } else {
                    transfer_resp(ts, i % keys, 1)
                };
                ts += 1;
                e
            })
            .collect();
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}

/// MULTI-SINCE with DISJOINT anchors (the documented O(∏ kᵢ) bound):
/// since-1 keys on the user param, since-2 on an
/// existential session shared with NOTHING, so the joined anchor root is
/// a CROSS PRODUCT (user-anchors × all live session-anchors) and reads
/// enumerate it. This case DOCUMENTS the boundary — expected to grow
/// with state, unlike every keyed shape.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn multi_since_cross() {
    header("multi_since_cross", "STATE");
    let lowered = lower(
        r#"permit (principal, action == Test::Action::"Read", resource)
when temporal {
    exists (s: String). (formerly within 24h (
        Test::Action::"Transfer"::response{ input.user: context.input.user, output.result: true }
        && (!Test::Action::"Logout"::response{ input.user: context.input.user, output.result: true }
            since within 24h
            Test::Action::"Login"::response{ input.user: context.input.user, output.result: true })
        && (!Test::Action::"Logout"::response{ input.session: s, output.result: true }
            since within 24h
            Test::Action::"Login"::response{ input.session: s, output.result: true })))
};"#,
    );
    for &state in &axis_points(SIMPLE_STATES) {
        let keys = keys_for(state);
        let mut ts = 1i64;
        // Block-wise kinds: every 4th ROUND is transfers, so every probed
        // user has both logins (anchors) and transfers (candidates) — the
        // original i%4 interleave never gave even-indexed users a
        // transfer, making every probe an all-miss scan.
        let warmup: Vec<Event> = (0..state)
            .map(|i| {
                let e = if (i / keys) % 4 == 3 {
                    transfer_resp(ts, i % keys, 1)
                } else {
                    login_resp(ts, i % keys)
                };
                ts += 1;
                e
            })
            .collect();
        let steps = alternating_probes(&mut ts, keys, measure_count());
        run(&state.to_string(), state, &lowered, warmup, steps);
    }
}
