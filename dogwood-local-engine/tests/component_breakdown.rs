//! Per-decision cost breakdown for verdict slicing.
//!
//! The ignored benchmarks compare sliced and unsliced evaluation over identical
//! monitor state and assert their leaf-count and decision premises before timing.
//! `DEPTH_HOURS`, `BENCH_ITERS`, `SWEEP_HOURS`, and `DURABLE_DEPTH_HOURS`
//! configure the workload.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dogwood_language::cedar::Schema;
use dogwood_language::{
    Authorizer, Decision, Error, Event, EventBuilder, EventSignature, LoweredPolicySet,
    PartitionKey, PolicySchema, ServiceSchema, TemporalBindings, TemporalEngine, TemporalField,
    Value,
};
use dogwood_local_engine::{DurableLog, DurableTemporalEngine, LocalTemporalEngine, Outcome};

// ─── The workload (verbatim from the prototype's bench) ──────────────

/// The one declared action no temporal rule is scoped to — the map's best case,
/// and the only addition to the prototype's workload.
const UNTOUCHED: &str = "Untouched";

fn action_decl(name: &str) -> String {
    format!(
        "  action \"{name}\" appliesTo {{\n    \
         principal: [User], resource: [Resource],\n    \
         context: {{ input: {{ tag: String }} }}\n  }};\n"
    )
}

/// `n_actions` actions of identical shape in one namespace, plus [`UNTOUCHED`].
fn schema(n_actions: usize) -> String {
    let mut s = String::from("namespace Bench {\n  entity User;\n  entity Resource;\n");
    for i in 0..n_actions {
        s.push_str(&action_decl(&format!("A{i}")));
    }
    // Declared and appliable, but outside every temporal rule's scope, so the map
    // holds an entry for it naming no leaf at all.
    s.push_str(&action_decl(UNTOUCHED));
    s.push_str("}\n");
    s
}

/// One blanket `permit` plus one temporal `forbid` per `A{i}` action — so exactly
/// one rule's leaf is live for any one `A{i}` request, and the other 99 fold away.
/// The last ten are `count` aggregates rather than plain `formerly`: a
/// scan-and-count verdict, which is where the unsliced path's milliseconds come
/// from. Nothing is scoped to [`UNTOUCHED`].
fn policies(n_actions: usize) -> String {
    let mut p = String::new();
    p.push_str("permit (principal, action, resource);\n\n");
    for i in 0..n_actions.saturating_sub(10) {
        p.push_str(&format!(
            "forbid (principal, action == Bench::Action::\"A{i}\", resource)\n\
             when temporal {{ formerly within 1h Bench::Action::\"A{i}\"::request{{ input.tag: \"x\" }} }};\n\n"
        ));
    }
    for i in n_actions.saturating_sub(10)..n_actions {
        p.push_str(&format!(
            "forbid (principal, action == Bench::Action::\"A{i}\", resource)\n\
             when temporal {{ (count for (t: Timepoint). where (formerly within 1h (Bench::Action::\"A{i}\"::request{{ input.tag: \"x\" }} && tp(t)))) >= 5 }};\n\n"
        ));
    }
    p
}

fn builder_for(action: &str) -> EventBuilder {
    Event::builder(&format!("Bench::Action::{action}"), "request")
        .principal("Bench::User::\"u1\"")
        .resource("Bench::Resource::\"r1\"")
        .field("input", "tag", Value::String("x".to_string()))
        .request_context("input", "tag", Value::String("x".to_string()))
}

fn event_builder(action_idx: usize) -> EventBuilder {
    builder_for(&format!("A{action_idx}"))
}

fn event(action_idx: usize) -> Event {
    event_builder(action_idx).build()
}

fn store_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dogwood_breakdown_{tag}_{}_{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// In-window events per action for a nominal depth in hours, at the prototype's
/// 0.1 events/s arrival rate.
fn events_for_hours(hours: usize) -> usize {
    hours * 360
}

// ─── The engine handle ───────────────────────────────────────────────

/// A [`LocalTemporalEngine`] the bench can still reach after handing it to an
/// [`Authorizer`].
///
/// `AuthorizerBuilder::temporal_engine` takes the engine by value as a private
/// `Box<dyn TemporalEngine>`, so without a handle the only way to give an
/// authorizer 432,000 events of history is to *authorize* all 432,000 — each one
/// a full decision, which at this depth costs hours on the unsliced lane. With a
/// handle the preload is `observe` alone (what authorize would do to the monitor,
/// minus the verdicts and the Cedar call), so both e2e lanes start from the same
/// state for the price of stepping it.
///
/// Every method forwards verbatim. Unlike the mechanism this replaced, nothing
/// about the forwarding is load-bearing for slicing: the map lives behind
/// `evaluate()`, which every wrapper in the crate already forwards — including
/// the shipping `SharedEngine` (see component 5). `Arc<Mutex<_>>` rather than
/// `Rc<RefCell<_>>` because `TemporalEngine: Send`.
#[derive(Clone)]
struct Handle(Arc<Mutex<LocalTemporalEngine>>);

impl Handle {
    fn new() -> Self {
        Handle(Arc::new(Mutex::new(LocalTemporalEngine::new())))
    }

    fn with_mut<R>(&self, f: impl FnOnce(&mut LocalTemporalEngine) -> R) -> R {
        f(&mut self
            .0
            .lock()
            .expect("bench is single-threaded; no panic to poison"))
    }

    /// Cumulative leaf verdicts computed — the spy that distinguishes "computed
    /// nothing" from "answered `false` correctly".
    fn verdicts_computed(&self) -> u64 {
        self.with_mut(|e| e.verdicts_computed())
    }
}

impl TemporalEngine for Handle {
    fn prepare(
        &mut self,
        leaves: &[TemporalField],
        schema: &Schema,
        events: &[EventSignature],
    ) -> Result<(), Error> {
        self.with_mut(|e| e.prepare(leaves, schema, events))
    }

    fn observe(&mut self, event: &Event) {
        self.with_mut(|e| e.observe(event));
    }

    fn evaluate(&mut self) -> Result<TemporalBindings, String> {
        self.with_mut(|e| e.evaluate())
    }

    fn supports_partitioning(&self) -> bool {
        self.with_mut(|e| e.supports_partitioning())
    }

    fn set_partition_keys(&mut self, keys: &[PartitionKey]) {
        self.with_mut(|e| e.set_partition_keys(keys));
    }
}

/// The leaf the rule scoped to `A{action_idx}` hoists.
fn leaf_id_for(lowered: &LoweredPolicySet, action_idx: usize) -> String {
    let want = format!("A{action_idx}");
    let mut matches = lowered
        .temporal_fields()
        .filter(|f| f.target_actions.iter().any(|a| a.id == want))
        .map(|f| f.id.clone());
    let found = matches.next().expect("one leaf is scoped to this action");
    assert!(
        matches.next().is_none(),
        "the workload scopes exactly one rule to each action"
    );
    found
}

// ─── One depth's measurements ────────────────────────────────────────

struct Breakdown {
    n_actions: usize,
    history_per_action: usize,
    n_iters: usize,
    leaves: usize,
    /// Leaf verdicts the mapped path computed per decision, for an `A0` request.
    mapped_leaves: u64,
    /// How many actions the map answers for.
    map_keys: usize,
    fsync_us: f64,
    step_us: f64,
    eval_all_us: f64,
    eval_mapped_us: f64,
    /// The floor: a decision on an action no temporal rule is scoped to.
    eval_floor_us: f64,
    /// `prepare` with the map built, and without it. The difference is the map,
    /// paid once per policy set.
    prepare_us: f64,
    prepare_no_map_us: f64,
    e2e_unsliced_us: f64,
    e2e_sliced_us: f64,
    /// Component 5, when its lane was run — see [`durable_submit_us`].
    submit_us: Option<f64>,
    submit_depth: usize,
}

fn mean_us(total: std::time::Duration, n: usize) -> f64 {
    total.as_secs_f64() * 1e6 / n as f64
}

/// Component 1: one durable append, fsync included, with nothing else in it.
fn fsync_us(n_iters: usize) -> f64 {
    let path = store_path("fsync");
    let log = DurableLog::open(&path).expect("open");
    let payload = b"benchmark payload 64 bytes padded to be realistic size!!!!!!!!";
    for _ in 0..10 {
        log.append(payload).expect("append");
    }
    let t0 = Instant::now();
    for _ in 0..n_iters {
        log.append(payload).expect("append");
    }
    let us = mean_us(t0.elapsed(), n_iters);
    drop(log);
    let _ = std::fs::remove_file(&path);
    us
}

/// Component 3c: `prepare`, with the leaf map built and with it suppressed.
///
/// The map is not built per decision, so it cannot be timed as one of the
/// per-decision components; the honest measurement is the *whole* preparation
/// step both ways, since that is what a policy apply actually pays. No history is
/// needed — `prepare` rebuilds the monitors from the leaves and never looks at the
/// log. Returns (with map µs, without map µs, map keys).
fn prepare_us(
    leaves: &[TemporalField],
    schema: &Schema,
    sigs: &[EventSignature],
    n_iters: usize,
) -> (f64, f64, usize) {
    let mut with_map = LocalTemporalEngine::new();
    let t0 = Instant::now();
    for _ in 0..n_iters {
        with_map.prepare(leaves, schema, sigs).expect("prepares");
    }
    let with_us = mean_us(t0.elapsed(), n_iters);
    let map_keys = with_map.leaf_map_entries();
    assert!(
        map_keys > 0,
        "the map must answer for at least one action, or 3c measured nothing"
    );
    assert!(
        with_map.unresolved_action_scopes().is_empty(),
        "every rule in this workload names its action exactly; an unresolved \
         scope would mean the whole workload fell back to computing everything"
    );

    let mut without_map = LocalTemporalEngine::new();
    without_map.disable_slicing();
    let t0 = Instant::now();
    for _ in 0..n_iters {
        without_map.prepare(leaves, schema, sigs).expect("prepares");
    }
    let without_us = mean_us(t0.elapsed(), n_iters);
    assert_eq!(
        without_map.leaf_map_entries(),
        0,
        "a slicing-disabled engine must build no map at all, or this is not the \
         baseline it claims to be"
    );
    (with_us, without_us, map_keys)
}

/// Components 4a/4b: the whole frontend authorize path, slicing off then on.
///
/// Same engine type and same history on both lanes, so slicing is the only
/// variable — the [`Handle`] is what makes "same history" affordable. Returns
/// (unsliced µs, sliced µs, leaves the sliced lane computed per decision).
fn e2e_us(
    lowered_off: LoweredPolicySet,
    lowered_on: LoweredPolicySet,
    n_actions: usize,
    history_per_action: usize,
    n_iters: usize,
) -> (f64, f64, u64) {
    let history: Vec<Event> = (0..n_actions).map(event).collect();
    let decision = event(0);

    let lane = |lowered: LoweredPolicySet, slice: bool| {
        let mut handle = Handle::new();
        if !slice {
            // Before `build`, so `prepare` never builds a map to begin with.
            handle.with_mut(|e| e.disable_slicing());
        }
        let mut authorizer = Authorizer::builder(lowered)
            .temporal_engine(handle.clone())
            .build()
            .expect("the local engine prepares");

        // Preload through the handle, not through `is_authorized`.
        for _ in 0..history_per_action {
            for e in &history {
                handle.observe(e);
            }
        }

        // Warm up, and pin the premise: with the decision's own leaf true, the
        // forbid fires, so both lanes must reach `Deny`.
        let response = authorizer
            .is_authorized(&decision)
            .expect("`request` is a decision kind");
        assert_eq!(
            response.decision(),
            Decision::Deny,
            "slicing={slice}: the A0 leaf is true on this history, so its forbid must fire"
        );

        let before = handle.verdicts_computed();
        let t0 = Instant::now();
        for _ in 0..n_iters {
            let _ = authorizer.is_authorized(&decision);
        }
        let us = mean_us(t0.elapsed(), n_iters);
        let per_decision = (handle.verdicts_computed() - before) / n_iters as u64;
        (us, per_decision)
    };

    let (off, off_leaves) = lane(lowered_off, false);
    let (on, on_leaves) = lane(lowered_on, true);
    // One leaf per action in this workload, so the unsliced lane computes
    // `n_actions` of them per decision and the sliced lane exactly one.
    assert_eq!(
        off_leaves, n_actions as u64,
        "the unsliced lane must compute every leaf per decision"
    );
    assert_eq!(
        on_leaves, 1,
        "the sliced lane must compute exactly the one leaf this action can read"
    );
    (off, on, on_leaves)
}

/// Component 5: the shipping durable submit path.
fn durable_submit_us(
    n_actions: usize,
    history_per_action: usize,
    n_iters: usize,
    policy_src: &str,
    action_schema_src: &str,
) -> f64 {
    let store = store_path("e2e");
    let mut durable = DurableTemporalEngine::open(&store, 0).expect("opens");
    durable
        .install(policy_src, action_schema_src, None, None)
        .expect("installs");
    for _ in 0..history_per_action {
        for a in 0..n_actions {
            durable.submit(event_builder(a)).expect("preload");
        }
    }
    let warmup = durable.submit(event_builder(0)).expect("warmup submit");
    let Outcome::Decision(response) = warmup.outcome else {
        panic!("request must produce a decision");
    };
    assert_eq!(
        response.decision(),
        Decision::Deny,
        "the A0 leaf must be true before timing durable submits"
    );

    let t0 = Instant::now();
    for _ in 0..n_iters {
        durable.submit(event_builder(0)).expect("submit");
    }
    let us = mean_us(t0.elapsed(), n_iters);
    drop(durable);
    let _ = std::fs::remove_file(&store);
    us
}

/// Every component at one depth. `durable_depth` of `None` skips component 5.
fn measure(
    n_actions: usize,
    history_per_action: usize,
    n_iters: usize,
    durable_depth: Option<usize>,
) -> Breakdown {
    let action_schema_src = schema(n_actions);
    let policy_src = policies(n_actions);

    let lower = || {
        let service = ServiceSchema::builder()
            .build()
            .expect("default service schema");
        let ps = PolicySchema::from_cedarschema_str(&action_schema_src).expect("schema builds");
        LoweredPolicySet::from_str(&policy_src, &service, &ps).expect("policy lowers")
    };

    let fsync_us = fsync_us(n_iters);

    // ─── The engine under components 2, 3a, 3b, 3c′ ──────────────────
    let lowered = lower();
    let live_leaf = leaf_id_for(&lowered, 0);
    let schema_for_prepare = lowered.cedar_schema().clone();
    let leaves: Vec<TemporalField> = lowered.temporal_fields().cloned().collect();
    let sigs: Vec<EventSignature> = lowered.event_signatures().collect();
    assert_eq!(leaves.len(), n_actions, "one leaf per action");

    // ─── Component 3c: the map build, amortized over a policy set ────
    let (prepare_us, prepare_no_map_us, map_keys) =
        prepare_us(&leaves, &schema_for_prepare, &sigs, n_iters);
    assert_eq!(
        map_keys,
        n_actions + 1,
        "the map answers for every declared appliable action — the {n_actions} \
         ruled ones and `{UNTOUCHED}`"
    );

    let mut engine = LocalTemporalEngine::new();
    engine
        .prepare(&leaves, &schema_for_prepare, &sigs)
        .expect("the workload's leaves compile");

    let history: Vec<Event> = (0..n_actions).map(event).collect();
    for _ in 0..history_per_action {
        for e in &history {
            engine.observe(e);
        }
    }
    let decision = event(0);
    engine.observe(&decision);

    // ─── Component 2: step all monitors ──────────────────────────────
    let t0 = Instant::now();
    for _ in 0..n_iters {
        engine.observe(&decision);
    }
    let step_us = mean_us(t0.elapsed(), n_iters);

    // ─── Component 3b: verdict, mapped ───────────────────────────────
    // First, because the unsliced lane below is reached by *disabling* slicing on
    // this same engine — one preload, and byte-identical monitor state on both.
    let before_mapped = engine.verdicts_computed();
    let t0 = Instant::now();
    let mut mapped_bindings = None;
    for _ in 0..n_iters {
        mapped_bindings = Some(engine.evaluate().expect("evaluates"));
    }
    let eval_mapped_us = mean_us(t0.elapsed(), n_iters);
    let mapped_bindings = mapped_bindings.expect("at least one iteration");
    let mapped_leaves = (engine.verdicts_computed() - before_mapped) / n_iters as u64;
    assert_eq!(
        mapped_leaves, 1,
        "exactly one leaf is scoped to A0; anything else and this is not \
         measuring a slice"
    );
    assert_eq!(mapped_bindings.get(&live_leaf), Some(&true));
    assert_eq!(
        mapped_bindings.values().filter(|v| **v).count(),
        1,
        "the other 99 leaves are bound false without being computed"
    );

    // ─── Component 3c′: the floor — an action with no leaf at all ────
    let untouched = builder_for(UNTOUCHED).build();
    engine.observe(&untouched);
    // Checked outside the timed loop, so the assertion is not part of the number.
    assert!(
        engine.evaluate().expect("evaluates").values().all(|v| !*v),
        "no rule is scoped to `{UNTOUCHED}`, so every leaf is bound false"
    );
    let before_floor = engine.verdicts_computed();
    let t0 = Instant::now();
    for _ in 0..n_iters {
        let _ = engine.evaluate().expect("evaluates");
    }
    let eval_floor_us = mean_us(t0.elapsed(), n_iters);
    assert_eq!(
        engine.verdicts_computed() - before_floor,
        0,
        "an action outside every rule's scope must compute NO leaf verdict"
    );

    // ─── Component 3a: verdict, every leaf ───────────────────────────
    // The same engine, the same request, slicing off: the unsliced baseline.
    engine.observe(&decision);
    engine.disable_slicing();
    let before_all = engine.verdicts_computed();
    let t0 = Instant::now();
    let mut all_bindings = None;
    for _ in 0..n_iters {
        all_bindings = Some(engine.evaluate().expect("evaluates"));
    }
    let eval_all_us = mean_us(t0.elapsed(), n_iters);
    let all_bindings = all_bindings.expect("at least one iteration");
    assert_eq!(
        (engine.verdicts_computed() - before_all) / n_iters as u64,
        n_actions as u64,
        "the unsliced verdict must compute every leaf"
    );
    assert_eq!(
        all_bindings.get(&live_leaf),
        Some(&true),
        "non-vacuity: A0's leaf is genuinely true on this history, so a sliced \
         `false` would be a demonstrated skip"
    );

    // ─── Components 4a/4b: the full authorize path ───────────────────
    let (e2e_unsliced_us, e2e_sliced_us, _) =
        e2e_us(lower(), lower(), n_actions, history_per_action, n_iters);

    // ─── Component 5: durable submit ─────────────────────────────────
    let submit_depth = durable_depth.unwrap_or(0);
    let submit_us = durable_depth
        .map(|depth| durable_submit_us(n_actions, depth, n_iters, &policy_src, &action_schema_src));

    Breakdown {
        n_actions,
        history_per_action,
        n_iters,
        leaves: leaves.len(),
        mapped_leaves,
        map_keys,
        fsync_us,
        step_us,
        eval_all_us,
        eval_mapped_us,
        eval_floor_us,
        prepare_us,
        prepare_no_map_us,
        e2e_unsliced_us,
        e2e_sliced_us,
        submit_us,
        submit_depth,
    }
}

fn report(b: &Breakdown) {
    println!("\n=== Per-decision component breakdown ===");
    println!(
        "  {} monitors, {} in-window events/action, {} retained",
        b.n_actions,
        b.history_per_action,
        b.history_per_action * b.n_actions
    );
    println!(
        "  {} temporal leaves; the map answers for {} actions and names {} leaf(s) \
         for this request",
        b.leaves, b.map_keys, b.mapped_leaves
    );
    println!("  {} iterations each\n", b.n_iters);
    println!("  1.  fsync (one append):          {:>10.1} µs", b.fsync_us);
    println!(
        "  2.  step (all {} monitors):     {:>10.1} µs",
        b.n_actions, b.step_us
    );
    println!(
        "  3a. verdict ALL (unsliced):      {:>10.1} µs   ({} leaf verdicts)",
        b.eval_all_us, b.leaves
    );
    println!(
        "  3b. verdict MAPPED:              {:>10.1} µs   ({} leaf verdict(s))",
        b.eval_mapped_us, b.mapped_leaves
    );
    println!(
        "  3c′ verdict MAPPED, floor:       {:>10.1} µs   (0 leaf verdicts: an \
         action no rule is scoped to)",
        b.eval_floor_us
    );
    println!(
        "  4a. e2e authorize, slicing OFF:  {:>10.1} µs",
        b.e2e_unsliced_us
    );
    println!(
        "  4b. e2e authorize, slicing ON:   {:>10.1} µs",
        b.e2e_sliced_us
    );
    match b.submit_us {
        Some(us) => println!(
            "  5.  e2e durable submit:          {:>10.1} µs   (sliced, as shipped; \
             depth {} events/action)",
            us, b.submit_depth
        ),
        None => println!("  5.  e2e durable submit:                  skipped"),
    }
    println!();
    println!(
        "  verdict: slicing saves           {:>10.1} µs ({:.1}%)",
        b.eval_all_us - b.eval_mapped_us,
        100.0 * (b.eval_all_us - b.eval_mapped_us) / b.eval_all_us
    );
    println!(
        "  e2e:     slicing saves           {:>10.1} µs ({:.1}%)",
        b.e2e_unsliced_us - b.e2e_sliced_us,
        100.0 * (b.e2e_unsliced_us - b.e2e_sliced_us) / b.e2e_unsliced_us
    );
    println!(
        "  sum (fsync+step+mapped):         {:>10.1} µs",
        b.fsync_us + b.step_us + b.eval_mapped_us
    );
    println!(
        "  sum (fsync+step+all):            {:>10.1} µs",
        b.fsync_us + b.step_us + b.eval_all_us
    );
    // Reported apart from the per-decision components, because it is not one:
    // the map is built once per policy set, and one decision's saving already
    // repays it many times over at this depth.
    println!("\n  3c. ONE-TIME, per policy set (not per decision):");
    println!(
        "      prepare, map built:          {:>10.1} µs",
        b.prepare_us
    );
    println!(
        "      prepare, slicing disabled:   {:>10.1} µs",
        b.prepare_no_map_us
    );
    println!(
        "      of which the map build:      {:>10.1} µs   (repaid after {:.2} sliced \
         decision(s))",
        b.prepare_us - b.prepare_no_map_us,
        (b.prepare_us - b.prepare_no_map_us).max(0.0)
            / (b.eval_all_us - b.eval_mapped_us).max(1e-9)
    );
}

// ─── The tests ───────────────────────────────────────────────────────

/// The full breakdown at the prototype's workload: 100 actions, 12h of history
/// at 0.1/s (4,320 in-window events per action), 50 iterations.
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn component_breakdown() {
    let n_actions = env_usize("N_ACTIONS", 100);
    let depth_hours = env_usize("DEPTH_HOURS", 12);
    let n_iters = env_usize("BENCH_ITERS", 50);
    // `0` skips component 5 outright. Its preload is `depth * n_actions` full
    // decisions over a filling window — quadratic in depth even now that they are
    // sliced — so at 12h it is not a measurement, it is an overnight job. Run it
    // at a depth it can reach and report that depth.
    let durable_hours = env_usize("DURABLE_DEPTH_HOURS", depth_hours);

    let b = measure(
        n_actions,
        events_for_hours(depth_hours),
        n_iters,
        (durable_hours > 0).then(|| events_for_hours(durable_hours)),
    );
    report(&b);
}

/// How the win scales with history depth: the same components at several depths,
/// component 5 excluded (its preload is quadratic in depth, so it gets the
/// dedicated knob on [`component_breakdown`] instead).
#[test]
#[ignore = "benchmark: run explicitly with -- --ignored"]
fn depth_sweep() {
    let n_actions = env_usize("N_ACTIONS", 100);
    let n_iters = env_usize("BENCH_ITERS", 50);
    let hours: Vec<usize> = std::env::var("SWEEP_HOURS")
        .unwrap_or_else(|_| "1 6 12".to_string())
        .split_whitespace()
        .filter_map(|h| h.parse().ok())
        .collect();

    let mut rows = Vec::new();
    for h in &hours {
        let b = measure(n_actions, events_for_hours(*h), n_iters, None);
        report(&b);
        rows.push((*h, b));
    }

    println!("\n=== Depth sweep ({n_actions} monitors, {n_iters} iterations) ===\n");
    println!(
        "  {:>5}  {:>9}  {:>12}  {:>12}  {:>10}  {:>12}  {:>12}",
        "depth", "events/a", "verdict ALL", "verdict MAP", "floor", "e2e OFF", "e2e ON"
    );
    for (h, b) in &rows {
        println!(
            "  {:>4}h  {:>9}  {:>10.1} µs  {:>10.1} µs  {:>8.1} µs  {:>10.1} µs  {:>10.1} µs",
            h,
            b.history_per_action,
            b.eval_all_us,
            b.eval_mapped_us,
            b.eval_floor_us,
            b.e2e_unsliced_us,
            b.e2e_sliced_us
        );
    }
    println!();
}
