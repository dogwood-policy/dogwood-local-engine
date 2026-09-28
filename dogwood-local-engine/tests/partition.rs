//! Native pin partitioning — the battery.
//!
//! THREE-LANE DISCIPLINE: every semantic test drives
//!   (1) the native-sharded local engine (non-relativized leaves +
//!       set_partition_keys — THE NEW CODE),
//!   (2) the relativized-global local engine (production today), and
//!   (3) the partitioned interpreter oracle,
//! asserting identical verdict streams at every decision. Lane 1≠3 means
//! the sharding is wrong; 1≠2 with 1=3 blames the relativization rewrite.
//!
//! RED-FIRST: against the pre-partitioning engine, `set_partition_keys`
//! is the trait's default no-op and the native lane silently runs
//! global semantics over non-relativized leaves — the routing tests
//! diverge from the oracle. The leak/sweep tests are red on the absent
//! hooks (`shard_count`, `maintain_all`).

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
}
"#;

/// The DEFAULT service schema: universal symmetric pins (callerPrincipal
/// et al.), exactly the production configuration.
fn lower(policy: &str) -> LoweredPolicySet {
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema builds");
    let service = ServiceSchema::builder().build().expect("default builds");
    LoweredPolicySet::from_str(policy, &service, &schema).expect("policy lowers")
}

/// `Transfer request since-within Login response`, correlated on the
/// user — under partitioning, each principal's shard sees only its own
/// history.
const SINCE_POLICY: &str = r#"permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    Test::Action::"Transfer"::request{ input.user: context.input.user }
    since within 24h
    Test::Action::"Login"::response{ input.user: context.input.user, output.result: true }
};"#;

/// A shard-bleed detector: TRUE iff ANY Login ever happened (no user
/// correlation) — under global semantics one login makes every later
/// probe true; under partitioning only the SAME PIN's probes.
const ANY_LOGIN_POLICY: &str = r#"permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 24h Test::Action::"Login"::response{ output.result: true }
};"#;

const TWO_LEAF_POLICY: &str = r#"
permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 1h Test::Action::"Login"::response{ output.result: true }
};

permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 24h Test::Action::"Login"::response{ output.result: true }
};
"#;

fn principal(k: &str) -> String {
    format!("Test::User::\"{k}\"")
}

fn login(ts: i64, pin: &str, user: &str) -> Event {
    Event::builder("Test::Action::Login", "response")
        .timestamp(ts)
        .principal(&principal(pin))
        .resource("Test::Gateway::\"gw\"")
        .field("input", "user", Value::String(user.into()))
        .field("input", "session", Value::String(format!("s-{user}")))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user.into()))
        .build()
}

fn logout(ts: i64, pin: &str, user: &str) -> Event {
    Event::builder("Test::Action::Logout", "response")
        .timestamp(ts)
        .principal(&principal(pin))
        .resource("Test::Gateway::\"gw\"")
        .field("input", "user", Value::String(user.into()))
        .field("input", "session", Value::String(format!("s-{user}")))
        .field("output", "result", Value::Bool(true))
        .request_context("input", "user", Value::String(user.into()))
        .build()
}

fn probe(ts: i64, pin: &str, user: &str) -> Event {
    Event::builder("Test::Action::Transfer", "request")
        .timestamp(ts)
        .principal(&principal(pin))
        .resource("Test::Gateway::\"gw\"")
        .field("input", "user", Value::String(user.into()))
        .field("input", "amount", Value::Int(1))
        .request_context("input", "user", Value::String(user.into()))
        .build()
}

// ── the three-lane harness ──────────────────────────────────────────────

fn native(lowered: &LoweredPolicySet) -> LocalTemporalEngine {
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let keys = lowered.partition_keys().to_vec();
    assert!(!keys.is_empty(), "the default schema pins");
    let mut e = LocalTemporalEngine::new();
    e.set_partition_keys(&keys);
    e.prepare(&leaves, &schema, &sigs).expect("native prepares");
    e
}

fn relativized(lowered: &LoweredPolicySet) -> LocalTemporalEngine {
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let mut e = LocalTemporalEngine::new();
    e.prepare(&leaves, &schema, &sigs)
        .expect("relativized prepares");
    e
}

fn oracle(lowered: &LoweredPolicySet) -> InMemoryTemporalEngine {
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let keys = lowered.partition_keys().to_vec();
    let mut e = InMemoryTemporalEngine::new();
    e.set_partition_keys(&keys);
    e.prepare(&leaves, &schema, &sigs).expect("oracle prepares");
    e
}

/// Drive the trace through all three lanes; assert identical verdict
/// streams at every probe. Returns the native lane for hook inspection.
fn three_lane(policy: &str, events: &[(Event, bool)]) -> LocalTemporalEngine {
    let lowered = lower(policy);
    // The NON-relativized leaves and the relativized ones have the same
    // ids (the rewrite preserves identity), so verdict maps align.
    let nat_leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let rel_leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut nat = native(&lowered);
    let mut rel = relativized(&lowered);
    let mut orc = oracle(&lowered);
    let mut fired = [0usize; 2];
    for (ev, is_probe) in events {
        nat.observe(ev);
        rel.observe(ev);
        orc.observe(ev);
        if *is_probe {
            let vn = nat.evaluate().expect("native evals");
            let vr = rel.evaluate().expect("relativized evals");
            let vo = orc.evaluate().expect("oracle evals");
            for (nl, rl) in nat_leaves.iter().zip(&rel_leaves) {
                assert_eq!(
                    vn[&nl.id],
                    vo[&nl.id],
                    "NATIVE vs ORACLE diverge at ts={} (the sharding is wrong)",
                    ev.timestamp()
                );
                assert_eq!(
                    vo[&nl.id],
                    vr[&rl.id],
                    "ORACLE vs RELATIVIZED diverge at ts={} (rewrite bug?)",
                    ev.timestamp()
                );
                fired[usize::from(vn[&nl.id])] += 1;
            }
        }
    }
    assert!(
        fired[0] > 0 && fired[1] > 0,
        "vacuous battery: outcomes {fired:?}"
    );
    nat
}

// ── routing-contract traces ─────────────────────────────────────────────

/// P1: interleaved pins must not bleed. alice logs in; bob probes the
/// ANY-LOGIN policy — global semantics say TRUE (someone logged in),
/// partitioned semantics say FALSE (not in bob's shard). This is THE
/// discriminator between the modes, and the reason relativization
/// exists; all three lanes agree only when the native lane actually
/// shards. (RED: a no-op set_partition_keys leaves the native lane
/// global ⇒ native diverges from the oracle at ts=30.)
#[test]
fn p1_no_shard_bleed() {
    let ev = vec![
        (probe(10, "alice", "alice"), true), // FALSE everywhere (no logins yet)
        (login(20, "alice", "alice"), false),
        (probe(30, "bob", "bob"), true), // FALSE partitioned; a global engine says TRUE
        (probe(40, "alice", "alice"), true), // TRUE everywhere
        (logout(50, "alice", "alice"), false),
        (probe(60, "bob", "bob"), true), // still FALSE
    ];
    three_lane(ANY_LOGIN_POLICY, &ev);
}

/// P2: the correlated since under interleaved pins — each pin's
/// anchors/guards live in its own shard; heavy interleaving stresses
/// the routing on every event kind.
#[test]
fn p2_interleaved_since() {
    let mut ev = Vec::new();
    let mut ts = 10i64;
    for round in 0..4 {
        for pin in ["alice", "bob", "carol"] {
            ev.push((login(ts, pin, pin), false));
            ts += 5;
        }
        // Logout ONE pin per round: its since dies, others stay alive.
        let victim = ["alice", "bob", "carol"][round % 3];
        ev.push((logout(ts, victim, victim), false));
        ts += 5;
        for pin in ["alice", "bob", "carol"] {
            ev.push((probe(ts, pin, pin), true));
            ts += 5;
        }
    }
    three_lane(SINCE_POLICY, &ev);
}

/// P3: decisions for never-seen pins — lazy shard creation must not
/// crash, and the verdict is the empty-shard one.
#[test]
fn p3_unseen_pin_decisions() {
    let ev = vec![
        (login(10, "alice", "alice"), false),
        (probe(20, "stranger1", "stranger1"), true), // FALSE: fresh shard
        (probe(30, "stranger2", "stranger2"), true), // FALSE: another fresh shard
        (probe(40, "alice", "alice"), true),         // TRUE: alice's shard intact
    ];
    three_lane(ANY_LOGIN_POLICY, &ev);
}

/// P4: same pin, different correlated users inside the shard — the
/// in-shard evaluation semantics are untouched by sharding (a shard IS
/// a monitor; user correlation still works within it).
#[test]
fn p4_in_shard_correlation() {
    let ev = vec![
        (login(10, "alice", "u1"), false),
        (probe(20, "alice", "u1"), true), // TRUE: u1's login in alice's shard
        (probe(30, "alice", "u2"), true), // FALSE: u2 never logged in
        (login(40, "alice", "u2"), false),
        (probe(50, "alice", "u2"), true), // TRUE now
    ];
    three_lane(SINCE_POLICY, &ev);
}

// ── the sweep ───────────────────────────────────────────────────────────

/// P5 (sweep-transparency — the full-expiry theorem as a test): pins go
/// quiet past the retention window, then are probed again. Verdicts
/// must match the oracle (which never deletes anything) exactly,
/// including AT the horizon boundary.
#[test]
fn p5_sweep_transparency() {
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    for pin in ["alice", "bob", "carol", "dave"] {
        ev.push((login(ts, pin, pin), false));
        ts += 60;
    }
    for pin in ["alice", "bob", "carol", "dave"] {
        ev.push((probe(ts, pin, pin), true)); // TRUE for each
        ts += 60;
    }
    // alice keeps traffic; the others go quiet for > 24h (the window).
    for i in 0..30 {
        ev.push((login(ts, "alice", "alice"), false));
        ts += 3600; // 30h of alice-only traffic
        if i % 5 == 0 {
            ev.push((probe(ts, "alice", "alice"), true));
            ts += 1;
        }
    }
    // The quiet pins return: their logins aged out ⇒ FALSE, exactly as
    // the never-deleting oracle computes.
    for pin in ["bob", "carol", "dave"] {
        ev.push((probe(ts, pin, pin), true));
        ts += 60;
    }
    // Re-login and probe: fresh shards work.
    for pin in ["bob", "carol"] {
        ev.push((login(ts, pin, pin), false));
        ts += 10;
        ev.push((probe(ts, pin, pin), true)); // TRUE
        ts += 10;
    }
    three_lane(ANY_LOGIN_POLICY, &ev);
}

/// P6 (THE LEAK TEST — the design's red-first exhibit): abandon most
/// pins past the window; the live shard count must descend to the warm
/// set, not track pins-ever-seen. Uses the observability hooks.
#[test]
fn p6_stale_shards_swept() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut nat = native(&lowered);
    let mut ts = 1_000i64;
    let n_pins = 500usize;
    for i in 0..n_pins {
        nat.observe(&login(ts, &format!("pin{i}"), "u"));
        ts += 1;
    }
    assert!(nat.shard_count() >= n_pins, "all pins sharded");
    // Only pin0 stays warm, for > 24h.
    for _ in 0..40 {
        nat.observe(&login(ts, "pin0", "u"));
        ts += 3600;
    }
    // Steady traffic sweeps incrementally (bounded pops per observe):
    // after enough observes, only the warm shard (and the freshly
    // touched ones) survive.
    for i in 0..200 {
        nat.observe(&probe(ts, "pin0", "u"));
        ts += 1;
        let _ = i;
    }
    let after_traffic = nat.shard_count();
    assert!(
        after_traffic < 50,
        "stale shards not swept under traffic: {after_traffic} live (want ~1)"
    );
    // maintain_all drains the backlog deterministically.
    nat.maintain_all();
    let final_count = nat.shard_count();
    assert!(
        final_count <= 2,
        "maintain_all left {final_count} shards (want the warm pin only)"
    );
}

/// P7: steady-state churn — new pins arrive as old pins die; the live
/// shard count stays window-bounded, never tracking total-ever-seen.
#[test]
fn p7_churn_bounded() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut nat = native(&lowered);
    let mut ts = 1_000i64;
    let mut max_live = 0usize;
    for i in 0..2_000usize {
        // One new pin per hour: after 24h any pin is stale.
        nat.observe(&login(ts, &format!("churn{i}"), "u"));
        ts += 3_600;
        max_live = max_live.max(nat.shard_count());
    }
    // Window 24h at one pin/hour ⇒ ~25 live + sweep lag (bounded pops).
    assert!(
        max_live < 100,
        "shard count tracked total pins, not the window: max {max_live}"
    );
}

/// P9: the aggregate MEMO composes with sharding — each shard carries
/// its own memo (cloned empty from the template), keyed by its OWN
/// timeline's tp_ids. Three-lane over an aggregate policy, plus a
/// hit-rate sanity via the (now shard-aware) stats hook.
#[test]
fn p9_memo_in_shards() {
    let policy = r#"permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    exists (u: String). (formerly within 24h (Test::Action::"Login"::response{ input.user: u, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::request{ input.user: u } && tp(t)))) >= 1))
};"#;
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((probe(ts, "alice", "alice"), true)); // FALSE: pre-state
    ts += 10;
    for _ in 0..3 {
        for pin in ["alice", "bob"] {
            ev.push((probe(ts, pin, pin), false)); // Transfers = agg candidates
            ts += 5;
        }
    }
    ev.push((login(ts, "alice", "alice"), false));
    ts += 5;
    for _ in 0..4 {
        ev.push((probe(ts, "alice", "alice"), true)); // TRUE (alice's shard)
        ts += 5;
        ev.push((probe(ts, "carol", "carol"), true)); // FALSE (fresh shard)
        ts += 5;
    }
    let nat = three_lane(policy, &ev);
    let (hits, misses) = nat.agg_memo_stats();
    assert!(
        hits > 0,
        "per-shard memos never hit under a sweep-shaped aggregate ({hits}/{misses})"
    );
}

/// P10: MULTIPLE leaves with different windows in one engine — each
/// leaf's ShardedMonitor sweeps at its own horizon; a pin can be swept
/// from the short-window leaf while alive in the long one; the shared
/// last_pin stays consistent (three-lane referees the verdicts).
#[test]
fn p10_multi_leaf_windows() {
    let policy = r#"permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 1h Test::Action::"Login"::response{ output.result: true }
};

permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 24h Test::Action::"Login"::response{ output.result: true }
};"#;
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((probe(ts, "alice", "alice"), true)); // FALSE both
    ts += 10;
    ev.push((login(ts, "alice", "alice"), false));
    ts += 10;
    ev.push((probe(ts, "alice", "alice"), true)); // TRUE both
    // 2h later: the 1h leaf is FALSE, the 24h leaf still TRUE.
    ts += 2 * 3600;
    ev.push((probe(ts, "alice", "alice"), true));
    // 30h later: both FALSE; alice's shard is sweepable in BOTH leaves
    // only after the long window passes — keep bob traffic flowing so
    // sweeps actually run at both horizons.
    for _ in 0..10 {
        ev.push((login(ts, "bob", "bob"), false));
        ts += 3 * 3600;
    }
    ev.push((probe(ts, "alice", "alice"), true)); // FALSE both (aged out)
    ev.push((probe(ts + 5, "bob", "bob"), true)); // TRUE both (fresh logins)
    three_lane(policy, &ev);
}

/// P11: EQUAL timestamps across pins (the stream is nondecreasing, not
/// strictly increasing) — routing and the sweep clock must handle ties.
#[test]
fn p11_equal_timestamps() {
    let ev = vec![
        (login(100, "alice", "alice"), false),
        (login(100, "bob", "bob"), false), // same ts, different pin
        (probe(100, "alice", "alice"), true), // same ts again: TRUE
        (probe(101, "bob", "bob"), true),  // TRUE
        (probe(101, "carol", "carol"), true), // FALSE
    ];
    three_lane(ANY_LOGIN_POLICY, &ev);
}

/// P12: the leaf-state transplant surfaces refuse partitioned engines —
/// iterating the (empty) monitor list would silently lose every shard on a
/// policy apply.
#[test]
fn p12_transplant_refusal() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut nat = native(&lowered);
    nat.observe(&login(10, "alice", "alice"));
    assert!(matches!(
        nat.share_leaf_state(),
        Err(dogwood_local_engine::LeafStateTransferError::PartitionedEngine)
    ));
    assert!(matches!(
        nat.adopt_leaf_state(&[]),
        Err(dogwood_local_engine::LeafStateTransferError::PartitionedEngine)
    ));
}

/// P13: evaluate() is idempotent in partitioned mode (re-reads the
/// last-routed shard without re-stepping).
#[test]
fn p13_double_evaluate() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let mut nat = native(&lowered);
    nat.observe(&login(10, "alice", "alice"));
    nat.observe(&probe(20, "alice", "alice"));
    let v1 = nat.evaluate().expect("first");
    let v2 = nat.evaluate().expect("second");
    for l in &leaves {
        assert_eq!(v1[&l.id], v2[&l.id], "evaluate must be idempotent");
    }
}

/// P14 (review-3 D1): keys after prepare would leave observe iterating
/// an empty shard list and evaluate returning EMPTY bindings — verdicts
/// silently vanish (fail-open). Must refuse.
#[test]
#[should_panic(expected = "before prepare")]
fn p14_late_partition_keys_refused() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut e = relativized(&lowered); // prepared, global
    let keys = lowered.partition_keys().to_vec();
    e.set_partition_keys(&keys); // too late
}

/// P15 (review-3 D2): re-prepare fully resets the previous mode — no
/// stale shards double-counted, no stale sweep clock. Partitioned →
/// re-prepare partitioned: counts start from zero; verdicts fresh.
#[test]
fn p15_reprepare_resets() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let mut e = native(&lowered);
    e.observe(&login(10, "alice", "alice"));
    e.observe(&login(20, "bob", "bob"));
    assert!(e.shard_count() >= 2);
    // Re-prepare (a policy apply rebuild): stale shards must vanish.
    e.prepare(&leaves, &schema, &sigs).expect("re-prepares");
    assert_eq!(e.shard_count(), 0, "stale shards survived re-prepare");
    assert_eq!(e.agg_memo_len(), 0);
    // And the engine works from scratch (incl. the reset sweep clock:
    // EARLIER timestamps than the pre-reset stream must be accepted).
    e.observe(&login(5, "carol", "carol"));
    e.observe(&probe(6, "carol", "carol"));
    let v = e.evaluate().expect("evals");
    for l in &leaves {
        assert!(v[&l.id], "fresh state after re-prepare");
    }
}

/// P16 (review-3 gap d): the memo composes with IN-SHARD PRUNING — an
/// aggregate policy driven past its retention inside shards, with the
/// memo's per-shard eviction riding each shard's prune. Three-lane.
#[test]
fn p16_memo_eviction_in_shards() {
    let policy = r#"permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    exists (u: String). (formerly within 2h (Test::Action::"Login"::response{ input.user: u, output.result: true }
        && (count for (t: Timepoint). where (formerly within 1h (Test::Action::"Transfer"::request{ input.user: u } && tp(t)))) >= 1))
};"#;
    let mut ev = Vec::new();
    let mut ts = 1_000i64;
    ev.push((probe(ts, "alice", "alice"), true)); // FALSE
    ts += 10;
    // 8h per pin at 20-min spacing: both shards prune continuously
    // (3h nesting sum), aggregates evaluated throughout.
    for i in 0..24 {
        let pin = if i % 2 == 0 { "alice" } else { "bob" };
        ev.push((probe(ts, pin, pin), false)); // agg candidates
        ts += 600;
        if i % 4 == 3 {
            ev.push((login(ts, pin, pin), false));
            ts += 600;
        }
        ev.push((probe(ts, pin, pin), true));
        ts += 600;
    }
    let nat = three_lane(policy, &ev);
    // The per-shard memos must be BOUNDED by the shard windows.
    assert!(
        nat.agg_memo_len() < 500,
        "per-shard memo eviction not riding shard pruning: {}",
        nat.agg_memo_len()
    );
}

/// P17 (review-3 gap f, adapted): leaves sweep at their OWN horizons.
/// (The design's i64::MAX never-sweep branch is frontend-UNREACHABLE —
/// every temporal operator requires a `within` clause — so it stays a
/// defensive branch; this test pins the differential-horizon behavior
/// that IS reachable: the same pin swept from the short-window leaf
/// while retained by the long one, with shard_count summing both.)
#[test]
fn p17_per_leaf_sweep_horizons() {
    let policy = r#"permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 8h Test::Action::"Login"::response{ output.result: true }
};

permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 1h Test::Action::"Login"::response{ output.result: true }
};"#;
    let lowered = lower(policy);
    let mut nat = native(&lowered);
    let mut ts = 1_000i64;
    for i in 0..20 {
        nat.observe(&login(ts, &format!("pin{i}"), "u"));
        ts += 1;
    }
    assert_eq!(nat.shard_count(), 40, "20 pins x 2 leaves");
    // Advance 3h with keeper traffic: past the 1h horizon, inside 8h.
    for _ in 0..18 {
        nat.observe(&login(ts, "keeper", "u"));
        ts += 600;
    }
    nat.maintain_all();
    // 1h leaf: keeper only (1). 8h leaf: all 21 still retained.
    assert_eq!(
        nat.shard_count(),
        21 + 1,
        "differential horizons: the 8h leaf retains, the 1h leaf sweeps"
    );
    // The aged pin diverges across leaves: TRUE for 8h, FALSE for 1h.
    nat.observe(&probe(ts, "pin0", "u"));
    let v = nat.evaluate().expect("evals");
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let verdicts: Vec<bool> = leaves.iter().map(|l| v[&l.id]).collect();
    assert!(
        verdicts.contains(&true) && verdicts.contains(&false),
        "8h/1h leaves must diverge on the aged pin: {verdicts:?}"
    );
}

/// P18 (review-3 gap c): duplicate delivery of the SAME event instance
/// (same ts, same pin, same fields — an at-least-once transport).
/// Three-lane referees whatever the semantics are; the lanes must agree.
#[test]
fn p18_duplicate_delivery() {
    let l = login(100, "alice", "alice");
    let p = probe(200, "alice", "alice");
    let ev = vec![
        (probe(50, "alice", "alice"), true), // FALSE
        (l.clone(), false),
        (l, false), // duplicate
        (p.clone(), true),
        (p, true), // duplicate decision
    ];
    three_lane(ANY_LOGIN_POLICY, &ev);
}

// ── custom-schema cases (the oracle's fixtures made these expressible:
//    `pin <field> = context.<path>` + parse_trace for events the
//    builder cannot construct) ────────────────────────────────────────

const DRUPE_SCHEMA: &str = r#"
namespace Drupe {
  type LoginInput = { user: String };
  type ReadInput  = { user: String };
  type Empty = { };
  entity Gateway;
  entity OAuthUser = { id: String };
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: LoginInput, output?: Empty }
  };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: ReadInput, output?: Empty }
  };
}
"#;

const SESSION_PIN_SCHEMA: &str = r#"
decision event <A>::request {
    ...inputs(A),
    pin sessionId: String = context.sessionId,
    requestId: String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    pin sessionId: String = context.sessionId,
    requestId: String,
}
"#;

const P_SESSION_LOGIN: &str = r#"
permit ( principal, action == Drupe::Action::"Read", resource )
when temporal {
    formerly within 1h Drupe::Action::"Login"::response{}
};
"#;

fn lower_custom(event_schema: &str, policy: &str) -> LoweredPolicySet {
    let service = ServiceSchema::builder()
        .event_schema_str(event_schema)
        .build()
        .expect("event schema builds");
    let schema = PolicySchema::from_cedarschema_str(DRUPE_SCHEMA).expect("schema builds");
    LoweredPolicySet::from_str(policy, &service, &schema).expect("policy lowers")
}

/// Three lanes over a parse_trace log: probe at every decision
/// (`request`-kind) event.
fn three_lane_trace(lowered: &LoweredPolicySet, log: &str) {
    let events = dogwood_language::parse_trace(log).expect("trace parses");
    let nat_leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let rel_leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let mut nat = native(lowered);
    let mut rel = relativized(lowered);
    let mut orc = oracle(lowered);
    let mut fired = [0usize; 2];
    for ev in &events {
        nat.observe(ev);
        rel.observe(ev);
        orc.observe(ev);
        if ev.kind() == "request" {
            let vn = nat.evaluate().expect("native evals");
            let vr = rel.evaluate().expect("relativized evals");
            let vo = orc.evaluate().expect("oracle evals");
            for (nl, rl) in nat_leaves.iter().zip(&rel_leaves) {
                assert_eq!(
                    vn[&nl.id],
                    vo[&nl.id],
                    "NATIVE vs ORACLE at ts={}",
                    ev.timestamp()
                );
                assert_eq!(
                    vo[&nl.id],
                    vr[&rl.id],
                    "ORACLE vs RELATIVIZED at ts={}",
                    ev.timestamp()
                );
                fired[usize::from(vn[&nl.id])] += 1;
            }
        }
    }
    assert!(fired[0] > 0 && fired[1] > 0, "vacuous trace: {fired:?}");
}

/// P19 (review-3 gap e): the `<none>` shard. Events whose LOGGED pin
/// field is ABSENT all route to the shared `<none>` partition — they
/// see each other's history (by the oracle's definition) and nothing
/// from real sessions; real sessions never see `<none>` events.
#[test]
fn p19_none_shard_semantics() {
    let lowered = lower_custom(SESSION_PIN_SCHEMA, P_SESSION_LOGIN);
    let log = [
        // A malformed Login response: NO sessionId in the logged record →
        // routes to `<none>`.
        r#"@1 Drupe::Action::"Login"::response(input: { user: "alice" }, requestId: "u1")"#,
        // A Read decision ALSO lacking sessionId → the `<none>` shard: it
        // must SEE the malformed login (same shard) — all lanes agree on
        // whatever that verdict is.
        r#"@2 scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") request_context(input: { user: "alice" }) Drupe::Action::"Read"::request(input: { user: "alice" }, requestId: "u2")"#,
        // A Read in a REAL session s1: must NOT see the `<none>` login.
        r#"@3 scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") request_context(input: { user: "alice" }, sessionId: "s1") Drupe::Action::"Read"::request(input: { user: "alice" }, sessionId: "s1", requestId: "u3")"#,
        // A proper s1 login, then an s1 Read: TRUE in s1.
        r#"@4 Drupe::Action::"Login"::response(input: { user: "alice" }, sessionId: "s1", requestId: "u4")"#,
        r#"@5 scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") request_context(input: { user: "alice" }, sessionId: "s1") Drupe::Action::"Read"::request(input: { user: "alice" }, sessionId: "s1", requestId: "u5")"#,
    ]
    .join("\n");
    three_lane_trace(&lowered, &log);
}

/// P20: MULTI-KEY pins (session AND caller): the composite routing —
/// same session + different principal = different shards, and vice
/// versa. (The unit tests cover the encoding; this is the end-to-end.)
#[test]
fn p20_multi_key_pins() {
    const TWO_PIN_SCHEMA: &str = r#"
decision event <A>::request {
    ...inputs(A),
    pin callerPrincipal: principalType(A) = principal,
    pin sessionId: String = context.sessionId,
    requestId: String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    pin callerPrincipal: principalType(A) = principal,
    pin sessionId: String = context.sessionId,
    requestId: String,
}
"#;
    let lowered = lower_custom(TWO_PIN_SCHEMA, P_SESSION_LOGIN);
    assert!(
        lowered.partition_keys().len() >= 2,
        "fixture must declare two pins"
    );
    let log = [
        // alice logs in, in session s1.
        r#"@1 Drupe::Action::"Login"::response(input: { user: "alice" }, callerPrincipal: Drupe::OAuthUser::"alice", sessionId: "s1", requestId: "u1")"#,
        // alice reads in s1: TRUE (same composite shard).
        r#"@2 scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") request_context(input: { user: "alice" }, sessionId: "s1") Drupe::Action::"Read"::request(input: { user: "alice" }, callerPrincipal: Drupe::OAuthUser::"alice", sessionId: "s1", requestId: "u2")"#,
        // alice reads in s2: FALSE (session differs → different shard).
        r#"@3 scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") request_context(input: { user: "alice" }, sessionId: "s2") Drupe::Action::"Read"::request(input: { user: "alice" }, callerPrincipal: Drupe::OAuthUser::"alice", sessionId: "s2", requestId: "u3")"#,
        // bob reads in s1: FALSE (principal differs → different shard).
        r#"@4 scope(principal: Drupe::OAuthUser::"bob", resource: Drupe::Gateway::"gw1") request_context(input: { user: "bob" }, sessionId: "s1") Drupe::Action::"Read"::request(input: { user: "bob" }, callerPrincipal: Drupe::OAuthUser::"bob", sessionId: "s1", requestId: "u4")"#,
    ]
    .join("\n");
    three_lane_trace(&lowered, &log);
}

/// P21 (review-3 rank 4): scaled post-sweep verdict re-probe — 100 pins
/// warmed, most swept past the window, then EVERY pin re-probed with
/// the oracle refereeing (sweep-boundary errors that manifest only on
/// specific pins — e.g. index-ordering bugs — surface here).
#[test]
fn p21_scaled_post_sweep_reprobes() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let nat_leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let mut nat = native(&lowered);
    let mut orc = oracle(&lowered);
    let mut ts = 1_000i64;
    let pins: Vec<String> = (0..100).map(|i| format!("p{i}")).collect();
    for p in &pins {
        let e = login(ts, p, "u");
        nat.observe(&e);
        orc.observe(&e);
        ts += 1;
    }
    // 30h of keeper traffic: everyone else ages past the 24h window and
    // gets swept incrementally.
    for _ in 0..36 {
        let e = login(ts, "keeper", "u");
        nat.observe(&e);
        orc.observe(&e);
        ts += 3_000;
    }
    // Re-probe EVERY pin: all FALSE except keeper — and identical to the
    // never-deleting oracle, pin by pin.
    for p in pins.iter().chain(std::iter::once(&"keeper".to_string())) {
        let e = probe(ts, p, "u");
        nat.observe(&e);
        orc.observe(&e);
        ts += 1;
        let vn = nat.evaluate().expect("native");
        let vo = orc.evaluate().expect("oracle");
        for l in &nat_leaves {
            assert_eq!(vn[&l.id], vo[&l.id], "post-sweep divergence at pin {p}");
        }
    }
}

/// P22: lifecycle no-ops — maintain_all before any observe; the
/// partitioning hooks in GLOBAL mode; engine drop with a sweep backlog
/// in the dropper channel.
#[test]
fn p22_lifecycle_noops() {
    // maintain_all before any observe: no panic, no effect.
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut fresh = native(&lowered);
    fresh.maintain_all();
    assert_eq!(fresh.shard_count(), 0);
    // Global mode: hooks are inert.
    let mut glob = relativized(&lowered);
    glob.observe(&login(10, "alice", "alice"));
    assert_eq!(glob.shard_count(), 0);
    glob.maintain_all();
    // Drop with corpses in flight: build a backlog via observe-path
    // sweeps, then drop the engine immediately (the dropper thread must
    // exit via the closed channel; a hang fails the suite's timeout).
    let mut nat = native(&lowered);
    let mut ts = 1_000i64;
    for i in 0..50 {
        nat.observe(&login(ts, &format!("d{i}"), "u"));
        ts += 1;
    }
    ts += 48 * 3600;
    for i in 0..5 {
        nat.observe(&login(ts, &format!("late{i}"), "u"));
        ts += 1;
    }
    drop(nat);
}

// ── snapshot format v2 ───────────────────────

/// P23: the partitioned snapshot round-trip — warm shards (incl. warm
/// memos), save, load into a freshly prepared engine, and continue the
/// trace with the oracle refereeing both engines.
#[test]
fn p23_partitioned_snapshot_roundtrip() {
    let lowered = lower(SINCE_POLICY);
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let mut a = native(&lowered);
    let mut orc = oracle(&lowered);
    let mut ts = 1_000i64;
    for pin in ["alice", "bob", "carol"] {
        let e = login(ts, pin, pin);
        a.observe(&e);
        orc.observe(&e);
        ts += 10;
        let p = probe(ts, pin, pin);
        a.observe(&p);
        orc.observe(&p);
        a.evaluate().expect("warm");
        ts += 10;
    }
    let snap = a.save_snapshot();
    let mut b = native(&lowered);
    assert!(b.load_snapshot(&snap), "v2 snapshot must load");
    assert_eq!(b.shard_count(), a.shard_count(), "shards restored");
    assert_eq!(
        b.save_snapshot(),
        snap,
        "restored shards must retain canonical snapshot order"
    );
    // Continue: logout bob (kills his since), probe everyone, both
    // engines + oracle agree.
    let e = logout(ts, "bob", "bob");
    a.observe(&e);
    b.observe(&e);
    orc.observe(&e);
    ts += 10;
    for pin in ["alice", "bob", "carol", "newpin"] {
        let p = probe(ts, pin, pin);
        a.observe(&p);
        b.observe(&p);
        orc.observe(&p);
        ts += 10;
        let va = a.evaluate().expect("a");
        let vb = b.evaluate().expect("b");
        let vo = orc.evaluate().expect("oracle");
        for l in &leaves {
            assert_eq!(va[&l.id], vb[&l.id], "warm vs restored at {pin}");
            assert_eq!(vb[&l.id], vo[&l.id], "restored vs oracle at {pin}");
        }
    }
}

/// P24: cross-mode loads refuse in BOTH directions (the fingerprint
/// carries the mode + keys).
#[test]
fn p24_cross_mode_refusal() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut glob = relativized(&lowered);
    glob.observe(&login(10, "alice", "alice"));
    let v1 = glob.save_snapshot();
    let mut nat = native(&lowered);
    nat.observe(&login(10, "alice", "alice"));
    let v2 = nat.save_snapshot();
    assert!(
        !nat.load_snapshot(&v1),
        "global snapshot into partitioned engine"
    );
    // A fresh global engine (prepared with the RELATIVIZED leaves) must
    // refuse the partitioned bytes too.
    let mut glob2 = relativized(&lowered);
    assert!(
        !glob2.load_snapshot(&v2),
        "partitioned snapshot into global engine"
    );
    // And the well-matched loads succeed.
    let mut glob3 = relativized(&lowered);
    assert!(glob3.load_snapshot(&v1));
    let mut nat2 = native(&lowered);
    assert!(nat2.load_snapshot(&v2));
}

/// P25: a snapshot from a DIFFERENT pin set refuses (session-pinned vs
/// two-pinned schemas over the same policy text).
#[test]
fn p25_key_set_mismatch_refusal() {
    let one = lower_custom(SESSION_PIN_SCHEMA, P_SESSION_LOGIN);
    let mut a = native(&one);
    let ev = dogwood_language::parse_trace(
        r#"@1 Drupe::Action::"Login"::response(input: { user: "alice" }, sessionId: "s1", requestId: "u1")"#,
    )
    .expect("parses");
    a.observe(&ev[0]);
    let snap = a.save_snapshot();
    const TWO_PIN_SCHEMA: &str = r#"
decision event <A>::request {
    ...inputs(A),
    pin callerPrincipal: principalType(A) = principal,
    pin sessionId: String = context.sessionId,
    requestId: String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    pin callerPrincipal: principalType(A) = principal,
    pin sessionId: String = context.sessionId,
    requestId: String,
}
"#;
    let two = lower_custom(TWO_PIN_SCHEMA, P_SESSION_LOGIN);
    let mut b = native(&two);
    assert!(
        !b.load_snapshot(&snap),
        "a snapshot from a different pin set must refuse"
    );
}

/// P26: sweep-before-save — fully-expired shards are NOT written; the
/// restored engine starts without them, and the restored staleness
/// index still sweeps what LATER expires (the index is rebuilt from
/// restored timeline tails, not serialized).
#[test]
fn p26_stale_shards_not_saved_and_index_rebuilt() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut a = native(&lowered);
    let mut ts = 1_000i64;
    for i in 0..30 {
        a.observe(&login(ts, &format!("old{i}"), "u"));
        ts += 1;
    }
    ts += 48 * 3600; // everything above is now fully expired
    a.observe(&login(ts, "fresh", "u"));
    // NOTE: only bounded pops have run; many stale shards may still be
    // resident — the SAVE must filter them regardless.
    let snap = a.save_snapshot();
    let mut b = native(&lowered);
    assert!(b.load_snapshot(&snap));
    assert!(
        b.shard_count() <= 2,
        "stale shards were serialized: {} restored",
        b.shard_count()
    );
    // The rebuilt index sweeps what expires AFTER the restore.
    let mut ts2 = ts + 48 * 3600;
    b.observe(&login(ts2, "newer", "u"));
    ts2 += 1;
    let _ = ts2;
    b.maintain_all();
    assert_eq!(b.shard_count(), 1, "post-restore sweep must work");
}

/// P27: the keyed-state transplant round-trip in partitioned mode
/// (policy applies): save_keyed_state → a fresh engine adopts → agree.
#[test]
fn p27_keyed_state_roundtrip() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let mut a = native(&lowered);
    a.observe(&login(10, "alice", "alice"));
    a.observe(&login(20, "bob", "bob"));
    let keyed = a.save_keyed_state();
    let mut b = native(&lowered);
    let restored = b.load_keyed_state(&keyed).expect("keyed state loads");
    assert!(restored > 0, "keyed state must restore leaves");
    assert_eq!(b.shard_count(), a.shard_count());
    for pin in ["alice", "bob", "carol"] {
        let p = probe(30, pin, pin);
        a.observe(&p);
        b.observe(&p);
        let va = a.evaluate().expect("a");
        let vb = b.evaluate().expect("b");
        for l in &leaves {
            assert_eq!(va[&l.id], vb[&l.id], "keyed round-trip at {pin}");
        }
    }
}

/// A rejected keyed leaf body must not install its valid prefix. In particular,
/// the restored count and the destination state must agree about rejection.
#[test]
fn p28_keyed_state_trailing_bytes_leave_destination_unchanged() {
    let lowered = lower(TWO_LEAF_POLICY);
    let mut source = native(&lowered);
    source.observe(&login(10, "alice", "alice"));
    source.observe(&login(20, "bob", "bob"));
    let mut keyed = source.save_keyed_state();
    for (_, bytes) in &mut keyed {
        bytes.push(0xff);
    }

    let mut destination = native(&lowered);
    destination.observe(&login(5, "carol", "carol"));
    let before = destination.save_keyed_state();
    let before_snapshot = destination.save_snapshot();
    let before_shards = destination.shard_count();

    assert_eq!(
        destination
            .load_keyed_state(&keyed)
            .expect("well-shaped destination"),
        0,
    );
    assert_eq!(destination.shard_count(), before_shards);
    assert_eq!(destination.save_keyed_state(), before);
    assert_eq!(destination.save_snapshot(), before_snapshot);
}

/// Rejection at the final whole-snapshot framing check is transactional: valid
/// leaf bodies parsed before the trailing byte must remain unobservable.
#[test]
fn p29_snapshot_trailing_bytes_leave_destination_unchanged() {
    let lowered = lower(TWO_LEAF_POLICY);
    let mut source = native(&lowered);
    source.observe(&login(10, "alice", "alice"));
    source.observe(&login(20, "bob", "bob"));
    let mut snapshot = source.save_snapshot();
    snapshot.push(0xff);

    let mut destination = native(&lowered);
    destination.observe(&login(5, "carol", "carol"));
    let before = destination.save_snapshot();
    let before_shards = destination.shard_count();

    assert!(!destination.load_snapshot(&snapshot));
    assert_eq!(destination.shard_count(), before_shards);
    assert_eq!(destination.save_snapshot(), before);
}

/// A malformed later leaf must not leave an earlier successfully decoded leaf
/// installed. This exercises snapshot-wide atomicity across multiple leaves.
#[test]
fn p30_later_snapshot_leaf_failure_leaves_all_leaves_unchanged() {
    let lowered = lower(TWO_LEAF_POLICY);
    let mut source = native(&lowered);
    source.observe(&login(10, "alice", "alice"));
    source.observe(&login(20, "bob", "bob"));
    let mut snapshot = source.save_snapshot();
    append_to_sharded_snapshot_body(&mut snapshot, 1, 0xff);

    let mut destination = native(&lowered);
    destination.observe(&login(5, "carol", "carol"));
    let before = destination.save_snapshot();
    let before_shards = destination.shard_count();

    assert!(!destination.load_snapshot(&snapshot));
    assert_eq!(destination.shard_count(), before_shards);
    assert_eq!(destination.save_snapshot(), before);
}

#[test]
fn p31_global_snapshot_trailing_bytes_leave_destination_unchanged() {
    let lowered = lower(TWO_LEAF_POLICY);
    let mut source = relativized(&lowered);
    source.observe(&login(10, "alice", "alice"));
    source.observe(&login(20, "bob", "bob"));
    let mut snapshot = source.save_snapshot();
    snapshot.push(0xff);

    let mut destination = relativized(&lowered);
    destination.observe(&login(5, "carol", "carol"));
    let before = destination.save_snapshot();

    assert!(!destination.load_snapshot(&snapshot));
    assert_eq!(destination.save_snapshot(), before);
}

#[test]
fn p32_later_global_snapshot_leaf_failure_leaves_all_leaves_unchanged() {
    let lowered = lower(TWO_LEAF_POLICY);
    let mut source = relativized(&lowered);
    source.observe(&login(10, "alice", "alice"));
    source.observe(&login(20, "bob", "bob"));
    let mut snapshot = source.save_snapshot();
    append_to_global_snapshot_body(&mut snapshot, 1, 0xff);

    let mut destination = relativized(&lowered);
    destination.observe(&login(5, "carol", "carol"));
    let before = destination.save_snapshot();

    assert!(!destination.load_snapshot(&snapshot));
    assert_eq!(destination.save_snapshot(), before);
}

#[test]
fn p33_partitioned_snapshot_replaces_a_warm_destination() {
    let lowered = lower(TWO_LEAF_POLICY);
    let leaves: Vec<_> = lowered.nonrelativized_temporal_fields().cloned().collect();
    let mut source = native(&lowered);
    source.observe(&login(10, "alice", "alice"));
    let snapshot = source.save_snapshot();

    let mut destination = native(&lowered);
    destination.observe(&login(5, "carol", "carol"));
    assert!(destination.load_snapshot(&snapshot));
    assert_eq!(destination.shard_count(), source.shard_count());

    for (ts, pin, expected) in [(20, "alice", true), (30, "carol", false)] {
        let event = probe(ts, pin, pin);
        source.observe(&event);
        destination.observe(&event);
        let source_values = source.evaluate().expect("source evaluates");
        let destination_values = destination.evaluate().expect("destination evaluates");
        for leaf in &leaves {
            assert_eq!(destination_values[&leaf.id], source_values[&leaf.id]);
            assert_eq!(destination_values[&leaf.id], expected);
        }
    }
}

#[test]
fn p34_empty_partitioned_snapshot_clears_a_warm_destination() {
    let lowered = lower(TWO_LEAF_POLICY);
    let source = native(&lowered);
    let snapshot = source.save_snapshot();

    let mut destination = native(&lowered);
    destination.observe(&login(5, "carol", "carol"));
    assert!(destination.shard_count() > 0);

    assert!(destination.load_snapshot(&snapshot));
    assert_eq!(destination.shard_count(), 0);

    destination.observe(&probe(10, "carol", "carol"));
    let values = destination.evaluate().expect("destination evaluates");
    assert!(values.values().all(|value| !value));
}

#[test]
fn p35_snapshot_clock_must_dominate_every_restored_shard() {
    let lowered = lower(ANY_LOGIN_POLICY);
    let mut source = native(&lowered);
    source.observe(&login(40, "alice", "alice"));
    let mut snapshot = source.save_snapshot();

    let fingerprint_len = read_u64_at(&snapshot, 0) as usize;
    let clock_offset = 8 + fingerprint_len;
    snapshot[clock_offset..clock_offset + 8].copy_from_slice(&39i64.to_le_bytes());

    let mut destination = native(&lowered);
    destination.observe(&login(90, "existing", "existing"));
    let before = destination.save_snapshot();
    let before_shards = destination.shard_count();

    assert!(!destination.load_snapshot(&snapshot));
    assert_eq!(destination.shard_count(), before_shards);
    assert_eq!(destination.save_snapshot(), before);
}

#[test]
fn p36_snapshot_accepts_equal_and_extreme_clock_boundaries() {
    let lowered = lower(ANY_LOGIN_POLICY);
    for timestamp in [i64::MIN, i64::MAX] {
        let mut source = native(&lowered);
        source.observe(&login(timestamp, "alice", "alice"));
        let snapshot = source.save_snapshot();
        let mut destination = native(&lowered);

        assert!(destination.load_snapshot(&snapshot));
        assert_eq!(destination.save_snapshot(), snapshot);
    }
}

fn read_u64_at(bytes: &[u8], pos: usize) -> u64 {
    u64::from_le_bytes(bytes[pos..pos + 8].try_into().expect("u64 framing"))
}

fn append_to_sharded_snapshot_body(snapshot: &mut Vec<u8>, body_index: usize, byte: u8) {
    append_to_snapshot_body(snapshot, body_index, byte, 8);
}

fn append_to_global_snapshot_body(snapshot: &mut Vec<u8>, body_index: usize, byte: u8) {
    append_to_snapshot_body(snapshot, body_index, byte, 0);
}

fn append_to_snapshot_body(
    snapshot: &mut Vec<u8>,
    body_index: usize,
    byte: u8,
    mode_header_len: usize,
) {
    let fingerprint_len = read_u64_at(snapshot, 0) as usize;
    let mut pos = 8 + fingerprint_len + mode_header_len;
    let body_count = read_u64_at(snapshot, pos) as usize;
    assert!(body_index < body_count);
    pos += 8;

    for index in 0..body_count {
        let length_offset = pos;
        let body_len = read_u64_at(snapshot, length_offset) as usize;
        let body_start = length_offset + 8;
        let body_end = body_start + body_len;
        if index == body_index {
            snapshot.insert(body_end, byte);
            snapshot[length_offset..length_offset + 8]
                .copy_from_slice(&((body_len + 1) as u64).to_le_bytes());
            return;
        }
        pos = body_end;
    }

    unreachable!("validated body index was not visited");
}
