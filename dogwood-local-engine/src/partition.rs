//! Native pin partitioning: one monitor shard per pin value.
//!
//! The routing contract delegates value encoding to the reference interpreter's
//! [`dogwood_language::partition_value_key`] — two events share a shard iff the
//! oracle would route them to one trace. The three-lane battery in
//! `tests/partition.rs` referees the integration end-to-end.
//!
//! The stale-shard sweep: a
//! shard whose last event predates `global_now − max_window` is
//! indistinguishable from a deleted one (its next `step` would prune
//! everything it retains), so it is dropped wholesale — with BOUNDED
//! incremental pops per observe and deallocation shipped off-thread by
//! ownership transfer (background FREEING, never background sweeping:
//! no second thread ever touches these structures).

use std::collections::{BTreeMap, HashMap};

use dogwood_language::{Event, PartitionKey, partition_value_key};

use crate::incremental::Monitor;
use crate::sync::mpsc::Sender;

/// Dead shards popped per observe: bounds the sweep's worst-case
/// addition to a single observe (each pop is a map remove + a channel
/// send). A backlog drains at this rate; timeliness is correctness-free.
const SWEEP_POPS_PER_OBSERVE: usize = 8;

/// Encode one event's partition-key tuple to a stable string — the
/// oracle's routing function. Reads each key's LOGGED
/// field (what μ-matching reads); absent → a distinct `<none>` marker;
/// multi-key joined with the unit separator.
pub(crate) fn partition_value_of(event: &Event, keys: &[PartitionKey]) -> String {
    keys.iter()
        .map(|k| match event.field_path(&k.field_path) {
            Some(v) => partition_value_key(v),
            None => "<none>".to_string(),
        })
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

/// One leaf's partitioned state: a monitor shard per live pin value.
pub(crate) struct ShardedMonitor {
    /// Built once from the NON-relativized leaf; empty histories, memo
    /// tables computed. Every shard is a clone of this.
    template: Monitor,
    shards: HashMap<String, Monitor>,
    /// Shards ordered by their last event's timestamp — the sweep pops
    /// dead ones from the front. Re-keyed on every routed event.
    by_staleness: BTreeMap<(i64, String), ()>,
    /// The reverse handle for re-keying (pin → its current index ts).
    last_ts: HashMap<String, i64>,
    /// The leaf's retention horizon (`Monitor::max_window`): shards
    /// whose last event predates `now − retention` are fully expired.
    retention: i64,
}

impl ShardedMonitor {
    pub(crate) fn new(template: Monitor) -> Self {
        let retention = template.retention_window();
        ShardedMonitor {
            template,
            shards: HashMap::new(),
            by_staleness: BTreeMap::new(),
            last_ts: HashMap::new(),
            retention,
        }
    }

    /// Build an empty transactional restore target with the same leaf shape and
    /// runtime configuration, without cloning any live shard history.
    pub(crate) fn empty_for_restore(&self) -> Self {
        Self::new(self.template.clone())
    }

    /// Route one event into its pin's shard (lazily created from the
    /// template), then run the bounded sweep. `dropper` receives dead
    /// shards for off-thread deallocation (falls back to dropping
    /// inline if the channel is gone).
    /// `now` is the engine's max-folded clock (NOT necessarily this
    /// event's ts): the sweep must never run on a stale timestamp.
    pub(crate) fn step(
        &mut self,
        event: &Event,
        pin: &str,
        now: i64,
        dropper: Option<&Sender<Monitor>>,
    ) {
        // Re-key the staleness index. The index ts is MAX-FOLDED per
        // shard: under a (contract-violating) non-monotone stream a
        // decreasing ts must never make the just-routed shard look
        // stale — with debug assertions off, that would let the sweep
        // delete the shard the CURRENT decision routed to, and its
        // verdict would silently fall through to the empty template
        // (release-safe defense in depth; the contract is asserted in
        // debug builds at the engine level).
        let ts = event.timestamp();
        let index_ts = match self.last_ts.get(pin) {
            Some(&prev) => {
                self.by_staleness.remove(&(prev, pin.to_string()));
                prev.max(ts)
            }
            None => ts,
        };
        self.last_ts.insert(pin.to_string(), index_ts);
        self.by_staleness.insert((index_ts, pin.to_string()), ());
        self.shards
            .entry(pin.to_string())
            .or_insert_with(|| self.template.clone())
            .step(event);
        self.sweep(now, SWEEP_POPS_PER_OBSERVE, dropper);
    }

    /// Pop up to `budget` fully-expired shards (last event older than
    /// `now − retention` ⇒ deletion is
    /// indistinguishable from keeping). `i64::MAX` retention never
    /// expires anything — correct: that history stays reachable.
    pub(crate) fn sweep(&mut self, now: i64, budget: usize, dropper: Option<&Sender<Monitor>>) {
        if self.retention == i64::MAX {
            return;
        }
        let horizon = now.saturating_sub(self.retention);
        for _ in 0..budget {
            let Some((&(ts, ref pin), ())) = self.by_staleness.first_key_value() else {
                return;
            };
            if ts >= horizon {
                return; // the front is live: everything behind it is too
            }
            let pin = pin.clone();
            self.by_staleness.remove(&(ts, pin.clone()));
            self.last_ts.remove(&pin);
            if let Some(corpse) = self.shards.remove(&pin) {
                // Background FREEING by ownership transfer: the corpse is
                // detached; a channel failure just drops it inline.
                retire(corpse, dropper);
            }
        }
    }

    /// Drain the sweep completely (the host's `maintain` hook / tests).
    /// Drops synchronously — deterministic for tests.
    pub(crate) fn sweep_all(&mut self, now: i64) {
        loop {
            let before = self.shards.len();
            self.sweep(now, usize::MAX, None);
            if self.shards.len() == before {
                return;
            }
        }
    }

    /// The pin's shard's verdict. A pin with no shard (never observed,
    /// or swept) is an EMPTY monitor — but
    /// `evaluate` always follows an `observe` that routed the decision
    /// into its shard, so this is only reachable for foreign pins.
    pub(crate) fn verdict(&self, decision: &Event, pin: &str) -> bool {
        match self.shards.get(pin) {
            Some(m) => m.verdict(decision),
            None => self.template.verdict(decision),
        }
    }

    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// The newest restored shard timestamp (rebuilds the engine's sweep
    /// clock after a keyed-state adoption).
    pub(crate) fn newest_shard_ts(&self) -> Option<i64> {
        self.by_staleness.last_key_value().map(|((ts, _), ())| *ts)
    }

    /// Serialize the LIVE shards (sweep-before-save as a WRITE FILTER:
    /// fully-expired shards are deletable,
    /// so they are simply not written — the save stays `&self`).
    /// Format: shard count, then per shard (pin len, pin bytes,
    /// monitor len, monitor bytes) — the monitor encoding is
    /// `Monitor::save`'s existing stable format.
    pub(crate) fn save(&self, global_now: i64) -> Vec<u8> {
        let horizon = if self.retention == i64::MAX {
            i64::MIN
        } else {
            global_now.saturating_sub(self.retention)
        };
        let mut live: Vec<(&String, &Monitor)> = self
            .shards
            .iter()
            .filter(|(pin, _)| self.last_ts.get(*pin).copied().unwrap_or(i64::MIN) >= horizon)
            .collect();
        // HashMap order is randomized per process. A snapshot of unchanged
        // state must remain byte-identical after recovery, so canonicalize the
        // explicitly keyed shard collection before writing it.
        live.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        let mut out = Vec::new();
        out.extend_from_slice(&(live.len() as u64).to_le_bytes());
        for (pin, m) in live {
            out.extend_from_slice(&(pin.len() as u64).to_le_bytes());
            out.extend_from_slice(pin.as_bytes());
            let bytes = m.save();
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }

    /// Restore shards from `save` bytes (the template must already be
    /// prepared). Rebuilds the staleness index from each restored
    /// shard's timeline tail. Returns None on any corruption.
    pub(crate) fn load(&mut self, bytes: &[u8], pos: &mut usize) -> Option<()> {
        let read_u64 = |b: &[u8], p: &mut usize| -> Option<u64> {
            let end = p.checked_add(8)?;
            let v = u64::from_le_bytes(b.get(*p..end)?.try_into().ok()?);
            *p = end;
            Some(v)
        };
        // SCRATCH-THEN-SWAP: parse into fresh maps and install only
        // after the complete input slice is consumed, so corruption or trailing
        // bytes leave the live state untouched. Bounds via checked_add:
        // corrupt input degrades, never panics.
        let mut shards = HashMap::new();
        let mut by_staleness = BTreeMap::new();
        let mut last_ts = HashMap::new();
        let n = usize::try_from(read_u64(bytes, pos)?).ok()?;
        // Every shard has at least two u64 lengths, even with empty payloads.
        if n > bytes.len().checked_sub(*pos)? / 16 {
            return None;
        }
        for _ in 0..n {
            let pin_len = usize::try_from(read_u64(bytes, pos)?).ok()?;
            let pin_end = pos.checked_add(pin_len)?;
            let pin_text = std::str::from_utf8(bytes.get(*pos..pin_end)?).ok()?;
            let mut pin = String::new();
            pin.try_reserve_exact(pin_len).ok()?;
            pin.push_str(pin_text);
            *pos = pin_end;
            if shards.contains_key(&pin) {
                return None;
            }
            let m_len = usize::try_from(read_u64(bytes, pos)?).ok()?;
            let m_end = pos.checked_add(m_len)?;
            let m_bytes = bytes.get(*pos..m_end)?;
            *pos = m_end;
            let mut m = self.template.clone();
            if !m.load(m_bytes) {
                return None;
            }
            let ts = m.last_event_ts()?;
            by_staleness.insert((ts, pin.clone()), ());
            last_ts.insert(pin.clone(), ts);
            shards.insert(pin, m);
        }
        if *pos != bytes.len() {
            return None;
        }
        self.shards = shards;
        self.by_staleness = by_staleness;
        self.last_ts = last_ts;
        Some(())
    }

    /// Kill the aggregate memo on the template AND every live shard
    /// (the engine's kill switch must work in either call order).
    pub(crate) fn disable_agg_memo(&mut self) {
        self.template.disable_agg_memo();
        for m in self.shards.values_mut() {
            m.disable_agg_memo();
        }
    }

    /// (hits, misses) summed across live shards.
    pub(crate) fn agg_memo_stats(&self) -> (u64, u64) {
        self.shards.values().fold((0, 0), |(h, m), mon| {
            let (a, b) = mon.agg_memo_stats();
            (h + a, m + b)
        })
    }

    /// Total memo entries across live shards.
    pub(crate) fn agg_memo_len(&self) -> usize {
        self.shards.values().map(|m| m.agg_memo_len()).sum()
    }
}

/// Transfer an unreachable value to the background dropper, or drop it inline.
///
/// `SendError<T>` retains ownership of `T`, so discarding the failed result is
/// the fallback drop. Keeping this generic makes the ownership contract directly
/// testable without adding hooks to `Monitor`.
fn retire<T>(value: T, dropper: Option<&Sender<T>>) {
    if let Some(tx) = dropper {
        let _ = tx.send(value);
    }
}

#[cfg(test)]
mod routing_tests {
    //! The routing encodings the integration battery's entity-only
    //! pins cannot reach. Each case mirrors the oracle's semantics.

    use dogwood_language::{Value, partition_value_key};

    #[test]
    fn decimal_spellings_share_a_partition() {
        assert_eq!(
            partition_value_key(&Value::Decimal("1.5".into())),
            partition_value_key(&Value::Decimal("1.50".into())),
        );
        assert_ne!(
            partition_value_key(&Value::Decimal("1.5".into())),
            partition_value_key(&Value::Decimal("1.51".into())),
        );
    }

    #[test]
    fn partition_key_agrees_with_dom_eq_for_reported_decimal_spellings() {
        let leading_plain = Value::Decimal("2.5".into());
        let leading_zero = Value::Decimal("02.5".into());
        assert!(
            leading_plain.dom_eq(&leading_zero),
            "Cedar decimal equality ignores leading zeroes"
        );
        assert_eq!(
            partition_value_key(&leading_plain),
            partition_value_key(&leading_zero),
            "dom-equal leading-zero spellings must share a partition"
        );

        let negative_zero = Value::Decimal("-0.0".into());
        let positive_zero = Value::Decimal("0.0".into());
        assert!(
            negative_zero.dom_eq(&positive_zero),
            "Cedar decimal equality treats signed zeroes as equal"
        );
        assert_eq!(
            partition_value_key(&negative_zero),
            partition_value_key(&positive_zero),
            "dom-equal signed-zero spellings must share a partition"
        );
    }

    #[test]
    fn entity_and_lookalike_string_do_not_collide() {
        let ent = Value::Entity {
            ty: "Test::User".into(),
            id: "alice".into(),
        };
        let s = Value::String("Test::User::\"alice\"".into());
        assert_ne!(partition_value_key(&ent), partition_value_key(&s));
    }

    #[test]
    fn framing_is_unambiguous_under_nesting() {
        // Arrays/objects length-frame their bodies: concatenations that
        // would collide flat must not collide framed.
        let a = Value::Array(vec![Value::String("ab".into()), Value::String("c".into())]);
        let b = Value::Array(vec![Value::String("a".into()), Value::String("bc".into())]);
        assert_ne!(partition_value_key(&a), partition_value_key(&b));
        // Nested decimals canonicalize inside arrays.
        let c = Value::Array(vec![Value::Decimal("2.50".into())]);
        let d = Value::Array(vec![Value::Decimal("2.5".into())]);
        assert_eq!(partition_value_key(&c), partition_value_key(&d));
    }

    #[test]
    fn absent_field_routes_to_none_marker() {
        use dogwood_language::{EventPinRoot, PartitionKey};
        let ev = dogwood_language::Event::builder("Test::Action::X", "request")
            .timestamp(1)
            .principal("T::U::\"a\"")
            .resource("T::G::\"g\"")
            .build();
        let bogus = PartitionKey {
            field_path: vec!["definitely_absent".into()],
            root: EventPinRoot::Context,
            context_path: Vec::new(),
        };
        let caller = PartitionKey {
            field_path: vec!["callerPrincipal".into()],
            root: EventPinRoot::Scope,
            context_path: Vec::new(),
        };
        // Absent → the distinct marker; two absent events share it.
        assert_eq!(super::partition_value_of(&ev, &[bogus.clone()]), "<none>");
        // A STRING pin value spelled "<none>" must NOT alias the marker
        // (the framed encoding distinguishes them).
        assert_ne!(
            partition_value_key(&Value::String("<none>".into())),
            "<none>"
        );
        // Multi-key ASYMMETRIC absence: (present, absent) ≠ (absent, present).
        let ab = super::partition_value_of(&ev, &[caller.clone(), bogus.clone()]);
        let ba = super::partition_value_of(&ev, &[bogus, caller]);
        assert_ne!(ab, ba, "key order must matter under partial absence");
    }

    #[test]
    fn null_bool_int_tags_distinct() {
        let variants = [
            partition_value_key(&Value::Null),
            partition_value_key(&Value::Bool(false)),
            partition_value_key(&Value::Int(0)),
            partition_value_key(&Value::String("".into())),
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j], "{i} vs {j}");
            }
        }
    }
}

#[cfg(test)]
mod sweep_tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use dogwood_language::{
        Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, Value,
    };

    use super::{ShardedMonitor, retire};
    use crate::LocalTemporalEngine;
    use crate::sync::mpsc;

    const SCHEMA: &str = r#"
namespace Test {
  type LoginInput = { user: String };
  type LoginOutput = { result: Bool };
  entity Gateway;
  entity User;
  action "Login" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: LoginInput, output: LoginOutput }
  };
}
"#;

    const POLICY: &str = r#"
permit (principal, action == Test::Action::"Login", resource)
when temporal {
    formerly within 1h Test::Action::"Login"::response{ output.result: true }
};
"#;

    fn login(ts: i64, pin: &str) -> Event {
        Event::builder("Test::Action::Login", "response")
            .timestamp(ts)
            .principal(&format!("Test::User::\"{pin}\""))
            .resource("Test::Gateway::\"gw\"")
            .field("input", "user", Value::String(pin.to_string()))
            .field("output", "result", Value::Bool(true))
            .request_context("input", "user", Value::String(pin.to_string()))
            .build()
    }

    fn engine_with_dropper(
        dropper: Option<mpsc::Sender<crate::incremental::Monitor>>,
    ) -> LocalTemporalEngine {
        let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema builds");
        let service = ServiceSchema::builder()
            .build()
            .expect("default service builds");
        let lowered = LoweredPolicySet::from_str(POLICY, &service, &schema).expect("policy lowers");
        let leaves = lowered
            .nonrelativized_temporal_fields()
            .cloned()
            .collect::<Vec<_>>();
        let signatures = lowered.event_signatures().collect::<Vec<_>>();
        let mut engine = LocalTemporalEngine::new();
        engine.set_partition_keys(lowered.partition_keys());
        engine
            .prepare(&leaves, lowered.cedar_schema(), &signatures)
            .expect("engine prepares");
        engine.dropper = dropper;
        engine
    }

    fn empty_sharded_monitor() -> ShardedMonitor {
        engine_with_dropper(None)
            .sharded
            .pop()
            .expect("one sharded monitor")
    }

    fn assert_index_consistent(monitor: &ShardedMonitor) {
        assert_eq!(monitor.shards.len(), monitor.last_ts.len());
        assert!(
            monitor
                .shards
                .keys()
                .all(|pin| monitor.last_ts.contains_key(pin))
        );
        let expected = monitor
            .last_ts
            .iter()
            .map(|(pin, ts)| ((*ts, pin.clone()), ()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(monitor.by_staleness, expected);
        assert_eq!(
            monitor.newest_shard_ts(),
            monitor.last_ts.values().copied().max()
        );
    }

    #[test]
    fn empty_and_stepped_shards_keep_an_exact_staleness_index() {
        let mut monitor = empty_sharded_monitor();
        assert_eq!(monitor.newest_shard_ts(), None);
        assert_index_consistent(&monitor);

        monitor.step(&login(10, "alice"), "alice", 10, None);
        assert_eq!(monitor.newest_shard_ts(), Some(10));
        assert_index_consistent(&monitor);

        monitor.step(&login(20, "bob"), "bob", 20, None);
        monitor.step(&login(20, "carol"), "carol", 20, None);
        assert_eq!(monitor.newest_shard_ts(), Some(20));
        assert_eq!(
            monitor
                .by_staleness
                .keys()
                .filter(|(timestamp, _)| *timestamp == 20)
                .count(),
            2,
        );
        assert_index_consistent(&monitor);

        monitor.step(&login(5, "alice"), "alice", 20, None);
        assert_eq!(monitor.last_ts.get("alice"), Some(&10));
        assert_eq!(monitor.newest_shard_ts(), Some(20));
        assert_index_consistent(&monitor);
    }

    #[test]
    fn saturating_horizons_and_unbounded_retention_do_not_overflow() {
        let mut monitor = empty_sharded_monitor();
        monitor.step(&login(i64::MIN, "oldest"), "oldest", i64::MIN, None);
        monitor.sweep(i64::MIN, usize::MAX, None);
        assert_eq!(monitor.shard_count(), 1);
        assert_index_consistent(&monitor);

        monitor.sweep(i64::MIN.saturating_add(3_601), usize::MAX, None);
        assert_eq!(monitor.shard_count(), 0);
        assert_index_consistent(&monitor);

        monitor.retention = i64::MAX;
        monitor.step(&login(i64::MIN, "unbounded"), "unbounded", i64::MAX, None);
        monitor.sweep(i64::MAX, usize::MAX, None);
        assert_eq!(monitor.shard_count(), 1);
        assert_index_consistent(&monitor);
    }

    #[test]
    fn sweep_removes_only_the_eligible_ordered_prefix_within_budget() {
        let mut monitor = empty_sharded_monitor();
        for (ts, pin) in [(10, "ten"), (20, "twenty"), (30, "thirty"), (40, "forty")] {
            monitor.step(&login(ts, pin), pin, ts, None);
        }

        monitor.sweep(3_625, 2, None);
        assert_eq!(
            monitor
                .last_ts
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["thirty", "forty"]),
        );
        assert_index_consistent(&monitor);

        monitor.sweep(3_635, usize::MAX, None);
        assert_eq!(
            monitor
                .last_ts
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["forty"]),
        );
        assert_index_consistent(&monitor);
    }

    #[test]
    fn duplicate_serialized_pin_is_rejected_without_mutating_indexes() {
        let mut source = empty_sharded_monitor();
        source.step(&login(10, "alice"), "alice", 10, None);
        let mut malformed = source.save(10);
        let duplicate = malformed[8..].to_vec();
        malformed[..8].copy_from_slice(&2u64.to_le_bytes());
        let second_entry = malformed.len();
        malformed.extend_from_slice(&duplicate);

        let pin_len = u64::from_le_bytes(
            malformed[second_entry..second_entry + 8]
                .try_into()
                .expect("pin length"),
        ) as usize;
        let monitor_start = second_entry + 8 + pin_len + 8;
        let second_timestamp = monitor_start + 8;
        malformed[second_timestamp..second_timestamp + 8].copy_from_slice(&20i64.to_le_bytes());

        let mut destination = empty_sharded_monitor();
        destination.step(&login(5, "existing"), "existing", 5, None);
        let before = destination.save(5);
        let mut pos = 0;

        assert!(destination.load(&malformed, &mut pos).is_none());
        assert_eq!(destination.save(5), before);
        assert_index_consistent(&destination);
    }

    #[test]
    fn serialized_shard_with_an_empty_monitor_is_rejected_atomically() {
        let source = empty_sharded_monitor();
        let monitor_bytes = source.template.save();
        let pin = b"alice";
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&1u64.to_le_bytes());
        malformed.extend_from_slice(&(pin.len() as u64).to_le_bytes());
        malformed.extend_from_slice(pin);
        malformed.extend_from_slice(&(monitor_bytes.len() as u64).to_le_bytes());
        malformed.extend_from_slice(&monitor_bytes);

        let mut destination = empty_sharded_monitor();
        destination.step(&login(5, "existing"), "existing", 5, None);
        let before = destination.save(5);
        let mut pos = 0;

        assert!(destination.load(&malformed, &mut pos).is_none());
        assert_eq!(destination.save(5), before);
        assert_index_consistent(&destination);
    }

    fn assert_budgeted_drain(stale: usize, expected: &[(usize, usize)]) {
        let (tx, rx) = mpsc::channel();
        let mut engine = engine_with_dropper(Some(tx));
        let mut ts = 1_000;
        for index in 0..stale {
            engine.observe(&login(ts, &format!("stale-{index}")));
            ts += 1;
        }
        assert_eq!(engine.shard_count(), stale);

        ts += 7_200;
        let mut retired = 0;
        for &(expected_live, expected_retired) in expected {
            engine.observe(&login(ts, "keeper"));
            ts += 1;
            retired += rx.try_iter().count();
            assert_eq!(engine.shard_count(), expected_live, "stale={stale}");
            assert_eq!(retired, expected_retired, "stale={stale}");
        }
    }

    #[test]
    fn sweep_removes_exactly_eight_expired_shards_per_observe() {
        for (stale, expected) in [
            (0, vec![(1, 0)]),
            (7, vec![(1, 7)]),
            (8, vec![(1, 8)]),
            (9, vec![(2, 8), (1, 9)]),
            (16, vec![(9, 8), (1, 16)]),
            (17, vec![(10, 8), (2, 16), (1, 17)]),
        ] {
            assert_budgeted_drain(stale, &expected);
        }
    }

    #[test]
    fn shard_at_the_horizon_survives_until_the_next_tick() {
        let (tx, rx) = mpsc::channel();
        let mut engine = engine_with_dropper(Some(tx));
        engine.observe(&login(1_000, "boundary"));
        engine.observe(&login(4_600, "keeper"));
        assert_eq!(engine.shard_count(), 2);
        assert_eq!(rx.try_iter().count(), 0);

        engine.observe(&login(4_601, "keeper"));
        assert_eq!(engine.shard_count(), 1);
        assert_eq!(rx.try_iter().count(), 1);
    }

    #[derive(Clone)]
    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn retirement_transfers_or_drops_ownership_exactly_once() {
        let connected_drops = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        retire(DropProbe(connected_drops.clone()), Some(&tx));
        assert_eq!(connected_drops.load(Ordering::SeqCst), 0);
        drop(rx.recv().expect("connected receiver gets ownership"));
        assert_eq!(connected_drops.load(Ordering::SeqCst), 1);

        let disconnected_drops = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        drop(rx);
        retire(DropProbe(disconnected_drops.clone()), Some(&tx));
        assert_eq!(disconnected_drops.load(Ordering::SeqCst), 1);

        let inline_drops = Arc::new(AtomicUsize::new(0));
        retire(DropProbe(inline_drops.clone()), None);
        assert_eq!(inline_drops.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "shuttle")]
    #[test]
    fn background_dropper_drains_and_disconnects_under_shuttle() {
        use shuttle::scheduler::RandomScheduler;
        use shuttle::{Config, Runner};

        let mut config = Config::default();
        config.stack_size = 8 * 1024 * 1024;
        Runner::new(RandomScheduler::new_from_seed(0x8b_d0_0d, 16), config).run(|| {
            let mut engine = engine_with_dropper(None);
            let mut ts = 1_000;
            for index in 0..17 {
                engine.observe(&login(ts, &format!("stale-{index}")));
                ts += 1;
            }
            ts += 7_200;
            for _ in 0..3 {
                engine.observe(&login(ts, "keeper"));
                ts += 1;
            }
            assert_eq!(engine.shard_count(), 1);

            // Dropping the last sender wakes the worker after it drains every
            // queued monitor. Runner completion proves the task terminated.
            drop(engine);
        });
    }
}
