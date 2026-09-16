//! A single-machine, event-sourced temporal engine for Dogwood.
//!
//! This crate is the no-AWS counterpart to `the cloud backend`'s DSQL/Aurora
//! backend: an incremental temporal monitor over a durable *local* event log,
//! implementing [`dogwood_language::TemporalEngine`]. It is embeddable as a
//! library; the security-bearing server (`dogwood-server`) builds on it, adding
//! the process boundary that keeps the policy set outside a monitored agent's
//! reach — which a library the agent links cannot do.
//!
//! See `DESIGN.md` for the architecture: the durable ordered log as the source
//! of truth, Monpoly-style incremental evaluation of the past-only temporal
//! operators, window/snapshot-bounded state and log pruning, and prospective
//! (install-offset-scoped) policy semantics.
//!
//! # What is here
//!
//! - [`LocalTemporalEngine`] evaluates each temporal leaf at the current decision
//!   timepoint with a per-leaf **incremental monitor** — the general table-based
//!   `meval` ported from the verified MonPoly/VeriMon reference (`DESIGN.md` §4),
//!   not a whole-history rescan. It agrees with the interpreter oracle
//!   case-for-case over the whole passing corpus (`tests/corpus_diff.rs`), which
//!   also asserts that **every** real leaf is on the incremental path. Each
//!   monitor front-prunes its own windowed state to its own lookback (§6.2), so
//!   state stays bounded for bounded-window policies without any shared history.
//! - [`LocalTemporalEngine`] uses [`dogwood_language::DecisionLeafMap`] to
//!   compute only the temporal leaves reachable by the decision's action.
//! - [`DurableLog`] is a redb-backed, ordered, append-only event log with atomic
//!   fsync'd append, prefix pruning, and a snapshot slot (§3, §6).
//! - [`leaf_key`] gives each leaf a **content-derived identity** so a policy
//!   change can preserve unchanged rules' accumulated windows while genuinely new
//!   rules start empty — the mechanism prospective installs rest on (§9.1). Used
//!   with [`LocalTemporalEngine::save_keyed_state`] /
//!   [`load_keyed_state`](LocalTemporalEngine::load_keyed_state).
//!
//! # What this crate deliberately does not do
//!
//! It knows nothing about callers, IPC, or who may change a policy. Embedding it
//! gives correctness and durability but **not** tamper-resistance — your process
//! can still rewrite the policy set it is judged by. `dogwood-server` is where
//! that changes.

mod clock;
mod codec;
mod durable;
#[cfg(feature = "fault-injection")]
#[doc(hidden)]
pub mod fault_injection;
mod identity;
mod incremental;
pub mod log;
mod partition;
mod policy_store;
mod record;
mod rel;
mod rows;
mod shard;
mod shared;
mod snapshot;
mod sync;
mod tick;

pub use codec::{event_from_json, event_to_json};
pub use identity::leaf_key;
pub use log::{DurableLog, LogError, Pruned, Snapshot, Write};
pub use tick::TickRate;

// The durable-engine assembly: the crash-consistent, event-sourced decision
// service layered over `DurableLog` + `LocalTemporalEngine`. See `durable.rs`
// and `docs/design/DURABLE_ENGINE_REFACTOR.md`.
pub use clock::{Clock, WallClock};
pub use durable::{
    Applied, BatchResult, DecisionDiagnostics, DecisionResponse, DurableConfig, DurableError,
    DurableTemporalEngine, Installed, Outcome, PolicyAttribution, Status, Submitted,
};
pub use policy_store::{BatchError, PolicyEntry, PolicyId, PolicySet, PolicyToken, Verb};
#[doc(hidden)]
pub use policy_store::{FoldOutcome, FoldedRecord};
pub use record::{Record, SnapshotPayload};
pub use shard::ShardPlan;

// The durable engine + its event codec seam are defined below; named here for
// discoverability alongside the log types they build on.

use std::sync::Arc;

use dogwood_language::cedar::Schema;
use dogwood_language::{
    DecisionLeafMap, Error, Event, EventSignature, TemporalBindings, TemporalEngine, TemporalField,
};

/// A single-machine [`TemporalEngine`]: retains the observed event log and
/// evaluates each temporal leaf at the current decision timepoint.
///
/// The retained trace is **window-pruned** (`DESIGN.md` §6.2): after each
/// observed event, events older than the installed leaves' maximum lookback
/// reach are dropped — they can never again fall inside any operator's window,
/// so verdicts are unchanged while steady-state memory (and, with bounded
/// windows, per-event scan cost) stays bounded. Pruning drops nothing when any
/// leaf's reach is effectively unbounded (a windowless operator); those cases
/// are what snapshots (§6.3) will bound instead.
#[derive(Default)]
pub struct LocalTemporalEngine {
    /// The temporal leaves to evaluate, installed at `prepare`.
    leaves: Vec<TemporalField>,
    /// The stable [`PolicyId`] of each installed policy, indexed by the policy's
    /// **source position** (`policy_N` in a leaf's `id`, `POLICY_INSTALL_SEMANTICS.md`
    /// §2.3). Set by [`set_policy_ids`](Self::set_policy_ids) after `prepare`, so
    /// the keyed-state transplant can key each leaf by `(stable policy id,
    /// within-policy clause ordinal)` rather than by content — which is what makes
    /// retention scope to the *policy* (no cross-policy window sharing) and survive
    /// a policy's source position shifting when another is added or deleted. Empty
    /// until set; a leaf whose origin cannot be resolved keys fail-safe (matches
    /// nothing, so it starts empty).
    policy_ids: Vec<PolicyId>,
    /// The most recently observed event: the decision point every `evaluate`
    /// anchors on, and the only event any reader ever wanted.
    ///
    /// `None` before the first `observe`, and after a snapshot-based recovery
    /// until a live event arrives — `step_monitors` deliberately advances
    /// monitors without it, since a snapshot carries monitor state and no trace.
    latest: Option<Event>,
    /// The unit the timestamps this engine is fed are in, used to convert each
    /// declared window into the same domain (see [`TickRate`]). Seconds by
    /// default, matching `dogwood_language`'s interpreter and the corpus.
    tick_rate: TickRate,
    /// Per-leaf incremental monitor, same length and order as `leaves`, stepped
    /// on every `observe`.
    ///
    /// Not optional: `prepare` refuses a policy set containing a leaf it cannot
    /// compile, so every leaf has one by construction.
    ///
    /// Behind an [`Arc`] so a policy change can hand a leaf's accumulated window
    /// to the engine replacing it **without copying or serializing it**. Every
    /// mutation goes through `Arc::make_mut`, which clones only while a handle is
    /// genuinely shared — and sharing is momentary: the old engine is dropped as
    /// soon as the new set is installed, so the refcount is 1 and stepping is
    /// free from then on.
    ///
    /// Sharing rather than moving is what keeps a failed apply harmless. A move
    /// would gut the running engine before the new set is known to be valid and
    /// durable; sharing leaves the old monitors intact and unmutated, so a
    /// rejected apply changes nothing.
    monitors: Vec<Arc<incremental::Monitor>>,
    /// Aggregate-memo kill switch (inverted so `derive(Default)` means
    /// ENABLED): set via `disable_agg_memo()` or, fleet-wide, the
    /// DOGWOOD_DISABLE_AGG_MEMO env var (checked at prepare).
    agg_memo_disabled: bool,
    /// Partition keys (docs/design/PARTITION_DESIGN.md): non-empty ⇒
    /// partitioned mode — `prepare` builds ShardedMonitors from the
    /// NON-relativized leaves the caller passes, and every event routes
    /// to its pin's shard.
    partition_keys: Vec<dogwood_language::PartitionKey>,
    /// Per-leaf sharded state (parallel to `leaves`; partitioned mode).
    sharded: Vec<partition::ShardedMonitor>,
    /// Where the most recent event routed (the oracle's `last`).
    last_pin: Option<String>,
    /// The pin-set fingerprint, cached at set_partition_keys (used by
    /// the keyed-state transplant verification).
    partition_keys_fingerprint_cached: Vec<u8>,
    /// Max observed event timestamp — the sweep's clock. The engine's
    /// existing contract is a nondecreasing event stream; in partitioned
    /// mode a violation would make the sweep DELETE a live shard (worse
    /// than global mode's mis-windowing), so the clock is max-folded and
    /// debug-asserted rather than trusted per-event.
    global_now: i64,
    /// The background dropper: dead shards are MOVED here for
    /// off-thread deallocation (spawned lazily; None until first use).
    dropper: Option<sync::mpsc::Sender<incremental::Monitor>>,
    /// Cumulative leaf verdicts actually computed.
    verdicts_computed: u64,
    /// Leaf ids reachable by each decision, rebuilt at every `prepare`.
    leaf_map: DecisionLeafMap,
    /// Operational and test kill switch for verdict slicing.
    slicing_disabled: bool,
}

impl LocalTemporalEngine {
    /// A fresh engine with no observed history, interpreting timestamps in
    /// whole seconds. Use [`with_tick_rate`](Self::with_tick_rate) for a store
    /// that assigns them at another resolution.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the unit of the timestamps this engine will be fed, which is the unit
    /// its windows are compared in. See [`TickRate`].
    ///
    /// Must be set BEFORE `prepare`: the conversion is applied when the monitors
    /// and the retention horizon are built, so a later change would leave
    /// already-built windows in the old unit.
    pub fn with_tick_rate(mut self, rate: TickRate) -> Self {
        self.tick_rate = rate;
        self
    }
}

impl TemporalEngine for LocalTemporalEngine {
    /// `events` (the declared event signatures) is unused: this engine
    /// *interprets* each leaf's condition over a retained trace rather than
    /// compiling it to a query, so it never needs the declared field types to
    /// emit type-correct comparisons — it compares `Value`s directly with the
    /// frontend's own equality.
    /// `schema` supplies the actions used to rebuild the leaf map.
    fn prepare(
        &mut self,
        leaves: &[TemporalField],
        schema: &Schema,
        _events: &[EventSignature],
    ) -> Result<(), Error> {
        self.leaves = leaves.to_vec();
        // Build an incremental monitor per leaf, and refuse the whole policy set
        // if any leaf cannot be compiled.
        //
        // Failing here rather than deferring to the scan fallback is deliberate.
        // Every condition `Monitor::build` declines is an unexpanded macro
        // artefact — `ConditionKind::Call`, `SigilRef`, `Refine`, or an
        // `AggExprKind::Call` inside an operand — and [`eval`] *panics* on all
        // four, phrased as "expansion did not run". So the fallback is not a
        // slower path for those leaves; it is a panic waiting for the first
        // decision, inside `is_authorized`, whose whole contract is to fail
        // closed. Rejecting at preparation turns that into an apply the control
        // plane declines, with the offending leaf named.
        let mut monitors = Vec::with_capacity(self.leaves.len());
        for leaf in &self.leaves {
            match incremental::Monitor::build(&leaf.condition.condition, self.tick_rate) {
                Some(mut monitor) => {
                    if self.agg_memo_disabled || std::env::var("DOGWOOD_DISABLE_AGG_MEMO").is_ok() {
                        monitor.disable_agg_memo();
                    }
                    monitors.push(Arc::new(monitor));
                }
                None => {
                    return Err(Error::Leaf {
                        id: leaf.id.clone(),
                        message: "cannot be compiled: the condition still contains a macro \
                                  call, a condition sigil, or a field-injection refinement, so \
                                  macro expansion did not run over it. Refusing the policy set \
                                  rather than accepting a leaf that cannot be evaluated."
                            .to_string(),
                    });
                }
            }
        }
        // Re-prepare drops the previous mode's state entirely: stale
        // shards/monitors would otherwise be double-counted by the
        // diagnostics, and a stale sweep clock could mis-sweep.
        self.sharded.clear();
        self.monitors.clear();
        self.global_now = i64::MIN;
        self.last_pin = None;
        self.latest = None;
        // The id↔position mapping belongs to the *previous* leaf set; the caller
        // re-establishes it via `set_policy_ids` after this prepare. Until then a
        // composite key falls back to the fail-safe (matches nothing) path.
        self.policy_ids.clear();
        // The map and leaves must always describe the same prepared policy set.
        self.slicing_disabled |= std::env::var("DOGWOOD_DISABLE_SLICING").is_ok();
        self.leaf_map = if self.slicing_disabled {
            DecisionLeafMap::default()
        } else {
            DecisionLeafMap::build(&self.leaves, schema)
        };
        if self.partition_keys.is_empty() {
            self.monitors = monitors;
        } else {
            // Partitioned mode: the monitors just built (from the
            // NON-relativized leaves the caller passes per the trait
            // contract) become shard TEMPLATES.
            self.sharded = monitors
                .into_iter()
                .map(|m| {
                    partition::ShardedMonitor::new(
                        Arc::try_unwrap(m).unwrap_or_else(|a| (*a).clone()),
                    )
                })
                .collect();
        }
        Ok(())
    }

    fn observe(&mut self, event: &Event) {
        if !self.partition_keys.is_empty() {
            let ts = event.timestamp();
            debug_assert!(
                self.global_now == i64::MIN || ts >= self.global_now,
                "partitioned mode requires a nondecreasing event stream \
                 (got {ts} after {}): the stale-shard sweep's clock depends on it",
                self.global_now
            );
            self.global_now = self.global_now.max(ts);
            let now = self.global_now;
            let pin = partition::partition_value_of(event, &self.partition_keys);
            let dropper = self.dropper_handle();
            for sm in self.sharded.iter_mut() {
                sm.step(event, &pin, now, dropper.as_ref());
            }
            self.last_pin = Some(pin);
            self.latest = Some(event.clone());
            return;
        }
        // Advance every incremental monitor by this event (before pruning the
        // trace — a monitor's state summarizes all events it has seen).
        for m in self.monitors.iter_mut() {
            Arc::make_mut(m).step(event);
        }
        self.latest = Some(event.clone());
    }

    /// Compute leaves reachable by this decision's action. A map miss
    /// conservatively computes every leaf.
    fn evaluate(&mut self) -> Result<TemporalBindings, String> {
        let needed = self
            .latest
            .as_ref()
            .and_then(|event| self.leaf_map.needed_for(event));
        // Held as an owned `Arc` handle, not a borrow: `evaluate_leaves` takes
        // `&mut self`, which a reference into `self.leaf_map` could not survive.
        match &needed {
            Some(set) => self.evaluate_leaves(Plan::Only(set)),
            None => self.evaluate_leaves(Plan::All),
        }
    }

    fn supports_partitioning(&self) -> bool {
        true
    }

    /// Install the pins (called before `prepare` per the trait contract;
    /// the leaves subsequently handed to `prepare` are non-relativized).
    fn set_partition_keys(&mut self, keys: &[dogwood_language::PartitionKey]) {
        // The trait contract: called BEFORE prepare. Accepting keys after
        // prepare would leave observe iterating an empty shard list and
        // evaluate returning EMPTY bindings — verdicts silently vanish
        // (a fail-open at the authorization boundary). Refuse loudly.
        assert!(
            self.monitors.is_empty() && self.sharded.is_empty(),
            "set_partition_keys must be called before prepare"
        );
        self.partition_keys = keys.to_vec();
        self.partition_keys_fingerprint_cached = self.keys_fingerprint();
    }
}

fn unresolved_composite_key(leaf_content_key: &str) -> String {
    format!("?:{leaf_content_key}")
}

/// A leaf's transplant key: `"{policy id}:{clause ordinal}:{leaf_content_key}"`.
///
/// The `(stable policy id, within-policy clause ordinal)` prefix is the
/// retention identity (§2.3); the trailing `leaf_content_key` is content, kept
/// as a **defensive guard** folded into the key so a match requires the formula
/// itself to still agree — a stronger, fail-safe form of §2.3's "defensive
/// assertion" (a disagreement resets rather than carrying, never panicking in
/// release). Because the policy id and ordinal are colon-free digit runs, the
/// two leading colons are unambiguous separators, so the key is injective in
/// `(id, ordinal, content)` regardless of what the content contains.
///
/// If the leaf's origin cannot be resolved (an unexpected `leaf_id` shape, or
/// `policy_ids` unset — the case for a bare [`LocalTemporalEngine`] used
/// outside the durable layer), the key degrades to a `?:{content}` form. That
/// is still sound (a key can only match another key with the same content),
/// but loses the cross-policy-sharing guard the composite provides. The
/// durable layer's [`DurableTemporalEngine::rebuild`] always calls
/// [`LocalTemporalEngine::set_policy_ids`], so it never lands here.
fn composite_key(policy_ids: &[PolicyId], leaf_id: &str, leaf_content_key: &str) -> String {
    match parse_leaf_origin(leaf_id) {
        Some((source_position, clause_ordinal)) if source_position < policy_ids.len() => {
            composite_transplant_key(
                policy_ids[source_position],
                clause_ordinal,
                leaf_content_key,
            )
        }
        _ => unresolved_composite_key(leaf_content_key),
    }
}

const KEYED_STATE_MAGIC: [u8; 5] = *b"DLEK1";
const KEYED_STATE_GLOBAL: u8 = 0;
const KEYED_STATE_PARTITIONED: u8 = 1;

fn encode_keyed_state(body: Vec<u8>, fingerprint: Option<&[u8]>) -> Vec<u8> {
    let fingerprint_len = fingerprint.map_or(0, |value| value.len());
    let mut encoded = Vec::with_capacity(
        KEYED_STATE_MAGIC.len()
            + 1
            + if fingerprint.is_some() {
                8 + fingerprint_len
            } else {
                0
            }
            + body.len(),
    );
    encoded.extend_from_slice(&KEYED_STATE_MAGIC);
    match fingerprint {
        None => encoded.push(KEYED_STATE_GLOBAL),
        Some(value) => {
            encoded.push(KEYED_STATE_PARTITIONED);
            encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
            encoded.extend_from_slice(value);
        }
    }
    encoded.extend_from_slice(&body);
    encoded
}

fn decode_keyed_state<'a>(
    encoded: &'a [u8],
    expected_fingerprint: Option<&[u8]>,
) -> Option<&'a [u8]> {
    let body_start = KEYED_STATE_MAGIC.len() + 1;
    if encoded.get(..KEYED_STATE_MAGIC.len())? != KEYED_STATE_MAGIC.as_slice() {
        return None;
    }
    let mode = *encoded.get(KEYED_STATE_MAGIC.len())?;
    match (mode, expected_fingerprint) {
        (KEYED_STATE_GLOBAL, None) => encoded.get(body_start..),
        (KEYED_STATE_PARTITIONED, Some(expected)) => {
            let length_end = body_start.checked_add(8)?;
            let length_bytes = encoded.get(body_start..length_end)?;
            let fingerprint_len =
                usize::try_from(u64::from_le_bytes(length_bytes.try_into().ok()?)).ok()?;
            let fingerprint_end = length_end.checked_add(fingerprint_len)?;
            if encoded.get(length_end..fingerprint_end)? != expected {
                return None;
            }
            encoded.get(fingerprint_end..)
        }
        _ => None,
    }
}

fn clone_shared_leaf_state(monitor: &Arc<incremental::Monitor>) -> LeafState {
    LeafState(Arc::clone(monitor))
}

fn install_shared_leaf_state(monitor: &mut Arc<incremental::Monitor>, state: &LeafState) {
    *monitor = Arc::clone(&state.0);
}

fn string_contents_equal(left: &String, right: &String) -> bool {
    left.eq(right)
}

fn first_matching_leaf_state(entries: &[(String, LeafState)], key: &String) -> Option<usize> {
    let mut index = 0usize;
    while index < entries.len() {
        if string_contents_equal(&entries[index].0, key) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn first_matching_serialized_entry(entries: &[(String, Vec<u8>)], key: &String) -> Option<usize> {
    let mut index = 0usize;
    while index < entries.len() {
        if string_contents_equal(&entries[index].0, key) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn load_global_keyed_bytes(monitor: &mut Arc<incremental::Monitor>, encoded: &[u8]) -> bool {
    let Some(body) = decode_keyed_state(encoded, None) else {
        return false;
    };
    Arc::make_mut(monitor).load(body)
}

fn load_sharded_keyed_bytes(
    monitor: &mut partition::ShardedMonitor,
    encoded: &[u8],
    fingerprint: &[u8],
) -> bool {
    let Some(body) = decode_keyed_state(encoded, Some(fingerprint)) else {
        return false;
    };
    let mut pos = 0usize;
    monitor.load(body, &mut pos).is_some() && pos == body.len()
}

fn load_global_serialized_by_key(
    keys: &[String],
    monitors: &mut Vec<Arc<incremental::Monitor>>,
    entries: &[(String, Vec<u8>)],
) -> Option<usize> {
    if keys.len() != monitors.len() {
        return None;
    }
    let mut restored = 0usize;
    let mut index = 0usize;
    while index < keys.len() {
        if let Some(source_index) = first_matching_serialized_entry(entries, &keys[index]) {
            if load_global_keyed_bytes(&mut monitors[index], &entries[source_index].1) {
                restored += 1;
            }
        }
        index += 1;
    }
    Some(restored)
}

fn load_sharded_serialized_by_key(
    keys: &[String],
    monitors: &mut Vec<partition::ShardedMonitor>,
    entries: &[(String, Vec<u8>)],
    fingerprint: &[u8],
    initial_max_ts: i64,
) -> Option<(usize, i64)> {
    if keys.len() != monitors.len() {
        return None;
    }
    let mut restored = 0usize;
    let mut max_ts = initial_max_ts;
    let mut index = 0usize;
    while index < keys.len() {
        if let Some(source_index) = first_matching_serialized_entry(entries, &keys[index]) {
            if load_sharded_keyed_bytes(&mut monitors[index], &entries[source_index].1, fingerprint)
            {
                restored += 1;
                max_ts = max_ts.max(monitors[index].newest_shard_ts().unwrap_or(i64::MIN));
            }
        }
        index += 1;
    }
    Some((restored, max_ts))
}

fn share_leaf_states_by_key(
    keys: Vec<String>,
    monitors: &Vec<Arc<incremental::Monitor>>,
) -> Vec<(String, LeafState)> {
    let mut shared = Vec::with_capacity(keys.len());
    for key in keys {
        let index = shared.len();
        let state = clone_shared_leaf_state(&monitors[index]);
        shared.push((key, state));
    }
    shared
}

fn adopt_leaf_states_by_key(
    keys: &Vec<String>,
    monitors: &mut Vec<Arc<incremental::Monitor>>,
    entries: &[(String, LeafState)],
) -> usize {
    let mut restored = 0usize;
    let mut index = 0usize;
    while index < keys.len() {
        let match_index = first_matching_leaf_state(entries, &keys[index]);
        if let Some(source_index) = match_index {
            install_shared_leaf_state(&mut monitors[index], &entries[source_index].1);
            restored += 1;
        }
        index += 1;
    }
    restored
}

/// Leaves to compute. Both plans bind every installed leaf.
#[derive(Clone, Copy, Debug)]
enum Plan<'a> {
    All,
    Only(&'a std::collections::BTreeSet<String>),
}

impl LocalTemporalEngine {
    /// Skipped leaves are bound `false`; only computed leaves are counted.
    fn evaluate_leaves(&mut self, plan: Plan<'_>) -> Result<TemporalBindings, String> {
        // The current decision point is the most recently observed event.
        let decision = self.latest.as_ref().ok_or("no event observed")?;
        let wanted = |id: &str| match plan {
            Plan::All => true,
            Plan::Only(needed) => needed.contains(id),
        };
        let mut computed = 0u64;
        let bindings = if !self.partition_keys.is_empty() {
            let pin = self.last_pin.as_ref().ok_or("no event observed")?;
            self.leaves
                .iter()
                .zip(&self.sharded)
                .map(|(leaf, sm)| {
                    let verdict = if wanted(&leaf.id) {
                        computed += 1;
                        sm.verdict(decision, pin)
                    } else {
                        false
                    };
                    (leaf.id.clone(), verdict)
                })
                .collect::<TemporalBindings>()
        } else {
            self.leaves
                .iter()
                .zip(&self.monitors)
                // The request is seeded into the monitor's env from the decision
                // event at verdict time.
                .map(|(leaf, monitor)| {
                    let verdict = if wanted(&leaf.id) {
                        computed += 1;
                        monitor.verdict(decision)
                    } else {
                        false
                    };
                    (leaf.id.clone(), verdict)
                })
                .collect::<TemporalBindings>()
        };
        self.verdicts_computed += computed;
        Ok(bindings)
    }

    /// Cumulative count of leaf verdicts actually computed.
    #[doc(hidden)]
    pub fn verdicts_computed(&self) -> u64 {
        self.verdicts_computed
    }

    /// Turn verdict slicing off so every `evaluate` computes every leaf.
    ///
    /// Effective before or after `prepare`. Also settable with
    /// `DOGWOOD_DISABLE_SLICING`.
    #[doc(hidden)]
    pub fn disable_slicing(&mut self) {
        self.slicing_disabled = true;
        self.leaf_map = DecisionLeafMap::default();
    }

    /// Number of decisions the leaf map can answer without falling back.
    #[doc(hidden)]
    pub fn leaf_map_entries(&self) -> usize {
        self.leaf_map.entry_count()
    }

    /// Leaves whose action scopes could not be resolved to concrete actions.
    #[doc(hidden)]
    pub fn unresolved_action_scopes(&self) -> Vec<(String, &'static str)> {
        self.leaf_map.unresolved().to_vec()
    }

    /// How many installed leaves run on the incremental path (vs. the scan
    /// fallback). A diagnostic — and the hook tests use to prove the
    /// incremental operators are actually exercised. Valid after `prepare`.
    pub fn incremental_leaf_count(&self) -> usize {
        if self.partition_keys.is_empty() {
            self.monitors.len()
        } else {
            self.sharded.len()
        }
    }

    /// The identity of the leaf set this engine's snapshot state describes: each
    /// installed leaf's [`leaf_key`], length-prefixed and concatenated in
    /// `leaves` order.
    ///
    /// [`save_snapshot`](Self::save_snapshot) embeds this and
    /// [`load_snapshot`](Self::load_snapshot) refuses a snapshot whose embedded
    /// value disagrees. That check is what makes snapshot recovery safe, because
    /// the snapshot payload is **positional**: it restores the k-th monitor's
    /// state into the k-th leaf, and validates only arity and byte framing. Two
    /// different leaf sets of the same arity — a plausible pair, since editing one
    /// rule's condition leaves the count unchanged — would otherwise load into
    /// each other, binding one formula's history to another. That is not a
    /// corrupt-data problem but a wrong-verdict one: a `formerly` would hold at
    /// timepoints where its own predicate never matched.
    ///
    /// The keys are length-prefixed for the same reason [`leaf_key`] prefixes its
    /// own payloads: so no combination of key contents can imitate a different
    /// sequence.
    /// The pin set's identity (field paths, ordered).
    fn keys_fingerprint(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for k in &self.partition_keys {
            let path = k.field_path.join(".");
            out.extend_from_slice(&(path.len() as u64).to_le_bytes());
            out.extend_from_slice(path.as_bytes());
        }
        out
    }

    fn state_fingerprint(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // The MODE + pin set are part of the identity: a global snapshot
        // must not load into a partitioned engine (or vice versa), and a
        // partitioned one must not load under a different key set — the
        // shard payloads would be misread positionally.
        // Preamble ONLY in partitioned mode (review F1): global
        // fingerprints stay byte-identical to the pre-partitioning
        // format so existing production snapshots keep loading across
        // the upgrade — breaking them, combined with pruned logs, was a
        // silent history hole.
        //
        // WHY cross-mode fingerprints can never collide (the precise
        // invariant — re-verify before ANY change to this encoding, it
        // guards a security-critical refusal): it is NOT merely
        // "count vs length" on the leading u64 (with ≥10 keys those can
        // coincide). After the count, the partitioned preamble emits u64
        // PATH-LENGTH prefixes whose high bytes are 0x00 at fixed
        // offsets, whereas a global fingerprint holds NUL-free ASCII
        // leaf-key content at those offsets (leaf keys are rendered
        // conditions, min ~10 bytes, no NULs) — the byte streams diverge
        // within the first ~9 bytes regardless of key counts. Do not
        // switch to varint lengths or reorder fields without a new
        // collision argument.
        if !self.partition_keys.is_empty() {
            out.extend_from_slice(&(self.partition_keys.len() as u64).to_le_bytes());
            for k in &self.partition_keys {
                let path = k.field_path.join(".");
                out.extend_from_slice(&(path.len() as u64).to_le_bytes());
                out.extend_from_slice(path.as_bytes());
            }
        }
        for leaf in &self.leaves {
            let key = leaf_key(leaf);
            out.extend_from_slice(&(key.len() as u64).to_le_bytes());
            out.extend_from_slice(key.as_bytes());
        }
        out
    }

    /// Serialize every incremental monitor's derived state (`DESIGN.md` §6.3),
    /// length-prefixed per leaf in `leaves` order, so a restart can restore the
    /// monitors without replaying the whole log — the only way to bound
    /// recovery (and log pruning) for **unbounded** operators, whose window
    /// never expires. Valid after `prepare`.
    ///
    /// Prefixed with [`state_fingerprint`](Self::state_fingerprint), so a
    /// snapshot cannot be loaded into a different leaf set.
    ///
    /// Only the incremental state is captured; the retained event trace (used
    /// by the defensive scan path) is not — a snapshot-based recovery replays
    /// only post-snapshot events, which is exactly what makes it cheap.
    /// Kill switch for the aggregate memo (MEMO_DESIGN.md).
    /// Effective in either order: before `prepare` (sets the default
    /// for built monitors) or after (disables the live ones). Also
    /// settable fleet-wide via `DOGWOOD_DISABLE_AGG_MEMO`.
    #[doc(hidden)]
    pub fn disable_agg_memo(&mut self) {
        self.agg_memo_disabled = true;
        for m in self.monitors.iter_mut() {
            std::sync::Arc::make_mut(m).disable_agg_memo();
        }
        for sm in self.sharded.iter_mut() {
            sm.disable_agg_memo();
        }
    }

    /// Total memo entries across monitors (steady-state boundedness).
    #[doc(hidden)]
    pub fn agg_memo_len(&self) -> usize {
        self.monitors
            .iter()
            .map(|m| m.agg_memo_len())
            .sum::<usize>()
            + self
                .sharded
                .iter()
                .map(|sm| sm.agg_memo_len())
                .sum::<usize>()
    }

    /// (hits, misses) summed across monitors.
    #[doc(hidden)]
    pub fn agg_memo_stats(&self) -> (u64, u64) {
        let base = self.monitors.iter().fold((0, 0), |(h, m), mon| {
            let (a, b) = mon.agg_memo_stats();
            (h + a, m + b)
        });
        self.sharded.iter().fold(base, |(h, m), sm| {
            let (a, b) = sm.agg_memo_stats();
            (h + a, m + b)
        })
    }

    /// PARTITIONING HOOKS (docs/design/PARTITION_DESIGN.md).
    /// Whether this engine runs in partitioned mode (pins installed).
    #[doc(hidden)]
    pub fn is_partitioned(&self) -> bool {
        !self.partition_keys.is_empty()
    }

    /// Live shard count across leaves (0 in global mode).
    #[doc(hidden)]
    pub fn shard_count(&self) -> usize {
        self.sharded.iter().map(|sm| sm.shard_count()).sum()
    }

    /// The newest timestamp represented by serialized monitor state.
    ///
    /// The durable snapshot envelope uses this to validate that its `last_ts`
    /// high-water mark cannot fall behind the engine state it encloses.
    pub(crate) fn latest_state_timestamp(&self) -> i64 {
        if !self.partition_keys.is_empty() {
            return self.global_now;
        }
        self.monitors
            .iter()
            .filter_map(|monitor| monitor.last_event_ts())
            .max()
            .unwrap_or(i64::MIN)
    }

    /// Drain the stale-shard sweep completely, dropping synchronously —
    /// the host's idle-maintenance hook (the engine has no clock of its
    /// own; observe-driven sweeps are bounded, this one is exhaustive).
    #[doc(hidden)]
    pub fn maintain_all(&mut self) {
        // Gate on the sweep CLOCK, not `latest` (review F5): recovery
        // replays through step_monitors, which advances global_now but
        // never sets latest — the latest-gate made post-recovery idle
        // sweeps silent no-ops until the first live observe.
        if self.global_now == i64::MIN {
            return;
        }
        let now = self.global_now;
        for sm in self.sharded.iter_mut() {
            sm.sweep_all(now);
        }
    }

    /// The background dropper's sender, spawning the thread on first
    /// use. Dead shards are MOVED here; the thread only receives and
    /// drops (background freeing — no engine state is shared).
    fn dropper_handle(&mut self) -> Option<sync::mpsc::Sender<incremental::Monitor>> {
        if self.dropper.is_none() {
            let (tx, rx) = sync::mpsc::channel::<incremental::Monitor>();
            sync::thread::Builder::new()
                .name("dogwood-shard-dropper".into())
                .spawn(move || while rx.recv().is_ok() {})
                .ok()?;
            self.dropper = Some(tx);
        }
        self.dropper.clone()
    }

    pub fn save_snapshot(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let fingerprint = self.state_fingerprint();
        out.extend_from_slice(&(fingerprint.len() as u64).to_le_bytes());
        out.extend_from_slice(&fingerprint);
        if !self.partition_keys.is_empty() {
            // Format v2 (PARTITION_DESIGN.md §4.3): global_now, then one
            // sharded body per leaf. The fingerprint above already binds
            // mode + keys, so a v1 reader refuses before touching this.
            out.extend_from_slice(&self.global_now.to_le_bytes());
            out.extend_from_slice(&(self.sharded.len() as u64).to_le_bytes());
            for sm in &self.sharded {
                let bytes = sm.save(self.global_now);
                out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                out.extend_from_slice(&bytes);
            }
            return out;
        }
        out.extend_from_slice(&(self.monitors.len() as u64).to_le_bytes());
        for m in &self.monitors {
            let bytes = m.save();
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }

    /// Restore monitor state produced by [`save_snapshot`](Self::save_snapshot)
    /// into the (already-`prepare`d, same-leaves) engine. Returns `false` on
    /// any mismatch/corruption without changing existing monitor state, so the
    /// caller can safely fall back to full replay.
    pub fn load_snapshot(&mut self, bytes: &[u8]) -> bool {
        let mut pos = 0usize;
        let read_u64 = |b: &[u8], p: &mut usize| -> Option<u64> {
            let end = p.checked_add(8)?;
            let v = u64::from_le_bytes(b.get(*p..end)?.try_into().ok()?);
            *p = end;
            Some(v)
        };
        let read_usize =
            |b: &[u8], p: &mut usize| -> Option<usize> { usize::try_from(read_u64(b, p)?).ok() };
        // Refuse a snapshot describing a DIFFERENT leaf set before restoring any
        // state. The payload below is positional, so without this a stale
        // snapshot of equal arity would load successfully and hand one formula
        // another's history — see `state_fingerprint`. A snapshot written before
        // fingerprinting existed fails here too (its leading bytes are a monitor
        // count, not a length-prefixed key sequence), which degrades to replay.
        let Some(fp_len) = read_usize(bytes, &mut pos) else {
            return false;
        };
        let fp_end = match pos.checked_add(fp_len) {
            Some(e) if e <= bytes.len() => e,
            _ => return false,
        };
        if bytes[pos..fp_end] != self.state_fingerprint()[..] {
            return false;
        }
        pos = fp_end;

        if !self.partition_keys.is_empty() {
            // Format v2: the fingerprint (mode + keys + leaves) matched,
            // so the body is per-leaf sharded state.
            let Some(now_end) = pos.checked_add(8) else {
                return false;
            };
            let Some(now_bytes) = bytes.get(pos..now_end) else {
                return false;
            };
            let global_now = i64::from_le_bytes(now_bytes.try_into().expect("8 bytes"));
            pos = now_end;
            let Some(count) = read_usize(bytes, &mut pos) else {
                return false;
            };
            if count != self.sharded.len() {
                return false;
            }
            let mut sharded: Vec<_> = self
                .sharded
                .iter()
                .map(partition::ShardedMonitor::empty_for_restore)
                .collect();
            for sm in sharded.iter_mut() {
                let Some(len) = read_usize(bytes, &mut pos) else {
                    return false;
                };
                let end = match pos.checked_add(len) {
                    Some(e) if e <= bytes.len() => e,
                    _ => return false,
                };
                let mut inner = 0usize;
                if sm.load(&bytes[pos..end], &mut inner).is_none() || inner != end - pos {
                    return false;
                }
                pos = end;
            }
            if pos != bytes.len() {
                return false;
            }
            if sharded.iter().any(|monitor| {
                monitor
                    .newest_shard_ts()
                    .is_some_and(|timestamp| timestamp > global_now)
            }) {
                return false;
            }
            self.sharded = sharded;
            self.global_now = global_now;
            return true;
        }

        let Some(count) = read_usize(bytes, &mut pos) else {
            return false;
        };
        if count != self.monitors.len() {
            return false;
        }
        let mut monitors = self.monitors.clone();
        for m in monitors.iter_mut() {
            let Some(len) = read_usize(bytes, &mut pos) else {
                return false;
            };
            let end = match pos.checked_add(len) {
                Some(e) if e <= bytes.len() => e,
                _ => return false,
            };
            if !Arc::make_mut(m).load(&bytes[pos..end]) {
                return false;
            }
            pos = end;
        }
        if pos != bytes.len() {
            return false;
        }
        self.monitors = monitors;
        true
    }

    /// Advance only the incremental monitors by `event` — **not** the retained
    /// trace — for replaying post-snapshot events during recovery (the trace is
    /// not part of a snapshot, and monitors carry their own windowed timeline).
    pub fn step_monitors(&mut self, event: &Event) {
        // Partitioned mode (review-3 called this unreachable; it is NOT:
        // snapshot recovery REPLAYS the post-snapshot log through here,
        // and without routing the replayed history silently vanished —
        // found by recovery_oracle::history_carries_across…): route the
        // event exactly as observe does, advancing the sweep clock, but
        // deliberately NOT touching `latest`/`last_pin` — this method's
        // contract is "advance state without a decision context".
        if !self.partition_keys.is_empty() {
            let ts = event.timestamp();
            self.global_now = self.global_now.max(ts);
            let now = self.global_now;
            let pin = partition::partition_value_of(event, &self.partition_keys);
            let dropper = self.dropper_handle();
            for sm in self.sharded.iter_mut() {
                sm.step(event, &pin, now, dropper.as_ref());
            }
            return;
        }
        for m in self.monitors.iter_mut() {
            Arc::make_mut(m).step(event);
        }
    }

    // ─── Keyed state: the prospective-install mechanism (§9.1) ──────────

    /// Record the stable [`PolicyId`] of each installed policy, indexed by source
    /// position — the map the composite keyed-state key needs
    /// (`POLICY_INSTALL_SEMANTICS.md` §2.3). Call after `prepare`, before any
    /// transplant. `ids[N]` is the policy whose leaves carry `policy_N` in their
    /// `id`, i.e. the N-th policy in the combined source (ascending id order).
    pub fn set_policy_ids(&mut self, ids: &[PolicyId]) {
        self.policy_ids = ids.to_vec();
    }

    /// Serialize each incremental monitor's state **keyed by its leaf's
    /// content-derived identity** ([`leaf_key`]) rather than by position.
    ///
    /// This is what makes prospective policy installs correct (`DESIGN.md`
    /// §9.1). [`save_snapshot`](Self::save_snapshot) is positional, so it is
    /// only valid when reloaded into an engine prepared with the *identical*
    /// leaf list — fine for crash recovery, wrong across a policy change, where
    /// inserting a rule shifts every later leaf's index and would hand one
    /// formula's accumulated window to a different formula. Keying by formula
    /// content instead means:
    ///
    /// - an **unchanged** leaf finds its key and resumes with its window intact;
    /// - a **new** leaf finds no key and starts empty — exactly the prospective
    ///   semantics of §9, with no epoch bookkeeping needed in the state itself;
    /// - a **removed** leaf's entry is simply never claimed.
    ///
    /// Non-incremental leaves (scan fallback, no derived state) are omitted.
    /// Hand every leaf's accumulated state to another engine **without copying
    /// it**, keyed by content-derived identity ([`leaf_key`]) exactly as
    /// [`save_keyed_state`](Self::save_keyed_state) is.
    ///
    /// This is the in-memory counterpart of the serialized form, and the one a
    /// policy change should use. Serializing was pure overhead there: the bytes
    /// were produced and immediately parsed back to move state between two
    /// engines in the same process, and the cost grew with retained history — an
    /// apply against 20 000 events cost ~397 ms, nearly all of it this round
    /// trip. Sharing an [`Arc`] is O(1) per leaf and converts no formats.
    ///
    /// Use [`save_keyed_state`](Self::save_keyed_state) when the destination is a
    /// disk; use this when it is another engine.
    pub fn share_leaf_state(&self) -> Result<Vec<(String, LeafState)>, LeafStateTransferError> {
        // Partitioned engines have no per-leaf monitor to transplant —
        // iterating self.monitors here would SILENTLY LOSE every shard
        // on a policy apply (masked by prospective-install semantics).
        // Refuse until the sharded transplant lands
        // (PARTITION_DESIGN.md §4 discipline).
        self.validate_leaf_state_transfer()?;
        let keys: Vec<String> = self
            .leaves
            .iter()
            .map(|leaf| {
                let content = leaf_key(leaf);
                composite_key(&self.policy_ids, &leaf.id, &content)
            })
            .collect();
        Ok(share_leaf_states_by_key(keys, &self.monitors))
    }

    /// Adopt shared leaf state, matched by [`leaf_key`]. Returns how many leaves
    /// were given a window; the rest retain their prior state. Policy rebuild
    /// callers use a freshly prepared destination, so those unmatched leaves
    /// remain empty, which is prospective-install semantics (`DESIGN.md` §9.1).
    ///
    /// The adopting engine shares each monitor with whoever handed it over until
    /// the first mutation, and `Arc::make_mut` only copies while both are alive.
    /// In the case this exists for — a policy change, where the previous set is
    /// dropped as it is replaced — nothing is ever copied.
    pub fn adopt_leaf_state(
        &mut self,
        entries: &[(String, LeafState)],
    ) -> Result<usize, LeafStateTransferError> {
        // Partitioned engines have no per-leaf monitor to transplant —
        // iterating self.monitors here would SILENTLY LOSE every shard
        // on a policy apply (masked by prospective-install semantics).
        // Refuse until the sharded transplant lands
        // (PARTITION_DESIGN.md §4 discipline).
        self.validate_leaf_state_transfer()?;
        // Precompute the composite keys before mutably borrowing the monitors.
        let keys: Vec<String> = self
            .leaves
            .iter()
            .map(|leaf| {
                let content = leaf_key(leaf);
                composite_key(&self.policy_ids, &leaf.id, &content)
            })
            .collect();
        Ok(adopt_leaf_states_by_key(&keys, &mut self.monitors, entries))
    }

    fn validate_leaf_state_transfer(&self) -> Result<(), LeafStateTransferError> {
        if !self.partition_keys.is_empty() {
            return Err(LeafStateTransferError::PartitionedEngine);
        }
        validate_leaf_monitor_count(self.leaves.len(), self.monitors.len())
    }

    pub fn save_keyed_state(&self) -> Vec<(String, Vec<u8>)> {
        if !self.partition_keys.is_empty() {
            // Partitioned: each leaf's entry is its SHARDED body (the v2
            // per-leaf encoding — sweep-filtered), wrapped in an explicit
            // partitioned envelope with the pin-set fingerprint. The mode tag
            // makes cross-mode refusal structural rather than relying on the
            // monitor decoders to reject another format accidentally.
            let kfp = self.keys_fingerprint();
            return self
                .leaves
                .iter()
                .zip(&self.sharded)
                .map(|(leaf, sm)| {
                    let bytes = encode_keyed_state(sm.save(self.global_now), Some(kfp.as_slice()));
                    let content = leaf_key(leaf);
                    (composite_key(&self.policy_ids, &leaf.id, &content), bytes)
                })
                .collect();
        }
        self.leaves
            .iter()
            .zip(&self.monitors)
            .map(|(leaf, monitor)| {
                let content = leaf_key(leaf);
                (
                    composite_key(&self.policy_ids, &leaf.id, &content),
                    encode_keyed_state(monitor.save(), None),
                )
            })
            .collect()
    }

    /// Restore keyed state from [`save_keyed_state`](Self::save_keyed_state)
    /// into this (already-`prepare`d) engine, matching leaves by content
    /// identity. Returns the number of leaves whose state was restored; leaves
    /// with no matching entry keep their fresh (empty) state, which is the
    /// prospective-install path. A destination whose leaf and monitor counts
    /// disagree is rejected before any monitor is changed.
    ///
    /// An entry whose bytes fail to load is skipped, leaving that leaf empty
    /// rather than half-loaded — a leaf that under-reports history is the
    /// fail-safe direction (it can only fail to fire a `formerly`, matching a
    /// freshly-installed rule's warm-up window, §9.2).
    pub fn load_keyed_state(
        &mut self,
        entries: &[(String, Vec<u8>)],
    ) -> Result<usize, LeafStateTransferError> {
        // Precompute composite keys before mutably borrowing monitor state.
        let keys: Vec<String> = self
            .leaves
            .iter()
            .map(|leaf| {
                let content = leaf_key(leaf);
                composite_key(&self.policy_ids, &leaf.id, &content)
            })
            .collect();
        if !self.partition_keys.is_empty() {
            let Some((restored, max_ts)) = load_sharded_serialized_by_key(
                &keys,
                &mut self.sharded,
                entries,
                self.partition_keys_fingerprint_cached.as_slice(),
                self.global_now,
            ) else {
                return Err(LeafStateTransferError::LeafMonitorCountMismatch {
                    leaves: self.leaves.len(),
                    monitors: self.sharded.len(),
                });
            };
            self.global_now = max_ts;
            return Ok(restored);
        }
        load_global_serialized_by_key(&keys, &mut self.monitors, entries).ok_or(
            LeafStateTransferError::LeafMonitorCountMismatch {
                leaves: self.leaves.len(),
                monitors: self.monitors.len(),
            },
        )
    }

    /// The content-derived identity of every installed leaf, in `leaves` order —
    /// a **diagnostic**. The transplant used to key on this alone, but since
    /// `POLICY_INSTALL_SEMANTICS.md` §2.3 retention is scoped to the policy
    /// (composite `(policy id, clause ordinal)`, not shared across policies), the
    /// bare content key is retained only for observability and the defensive-guard
    /// tail of the composite key builder.
    pub fn leaf_keys(&self) -> Vec<String> {
        self.leaves.iter().map(leaf_key).collect()
    }

    /// The leaves' **composite** transplant keys — the composite key builder
    /// for each, i.e. the resolved `"{policy id}:{ordinal}:{content}"` form, or
    /// the `"?:{content}"` fallback when a leaf's origin cannot be resolved
    /// (an unexpected id shape, or [`policy_ids`](Self::set_policy_ids) too short
    /// for its `policy_N`). Unlike [`leaf_keys`](Self::leaf_keys) — which returns
    /// the bare *content* key and so never carries the `?:` sentinel — this
    /// reflects the actual retention key, so the durable layer can scan it to
    /// refuse a transplant whose state it could not scope to a policy.
    pub fn composite_leaf_keys(&self) -> Vec<String> {
        self.leaves
            .iter()
            .map(|leaf| {
                let content = leaf_key(leaf);
                composite_key(&self.policy_ids, &leaf.id, &content)
            })
            .collect()
    }
}

/// Parse a leaf's generated `id` (`policy_N__temporal_M` or an equivalent
/// distincter-prefixed spelling) into `(N, M)`.
///
/// The frontend emits leaf ids as `{rule_key}__temporal_{ordinal}`, where
/// `rule_key` is `policy_{N}` under the default lowering (or
/// `{distincter}_{N}` when a distincter is set) and `ordinal` is the leaf's
/// position among *all* hoisted leaves in that policy — a temporal+provider
/// shared counter, so it is not a dense temporal-only index. That is exactly
/// what we want here: the composite key must survive a policy edit that adds or
/// removes an unrelated provider leaf, so long as the *remaining* temporal
/// clauses keep their traversal positions, which they do when the policy is
/// unchanged.
///
/// This is the same id [`identity.rs`](crate::leaf_key) documents as
/// **positional**: that module's `__temporal_M` is the `ordinal` read here (it
/// shifts when a rule is inserted ahead of the leaf), and the `policy_N` prefix
/// — which that doc elides — names the owning policy. `composite_key` keys on the
/// pair, so a shifted `ordinal` alone does not change the retention identity.
///
/// Returns `None` on any deviation from the expected shape — which the durable
/// transplant guard turns into a fail-closed rejection, so a lowering change to
/// the id format surfaces loudly rather than silently mis-scoping history.
#[doc(hidden)]
pub fn parse_leaf_origin(id: &str) -> Option<(usize, usize)> {
    // Find the `__temporal_` seam, then require the exact
    // `{cedar_identifier}_{policy_index}` rule-key shape emitted by lowering.
    let (prefix, suffix) = id.rsplit_once("__temporal_")?;
    let ordinal: usize = suffix.parse().ok()?;
    let (distincter, policy_index) = prefix.rsplit_once('_')?;
    let mut chars = distincter.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    let policy_index: usize = policy_index.parse().ok()?;
    Some((policy_index, ordinal))
}

/// Construct the resolved transplant key from its independently meaningful
/// parts. Kept public-but-hidden so the external property suite can exhaust
/// delimiter and injectivity adversaries without constructing monitor state.
#[doc(hidden)]
pub fn composite_transplant_key(
    policy_id: PolicyId,
    clause_ordinal: usize,
    leaf_content_key: &str,
) -> String {
    format!("{}:{clause_ordinal}:{leaf_content_key}", policy_id.0)
}

/// One leaf's accumulated monitor state, shared rather than copied.
///
/// Opaque on purpose: the monitor's internals are an implementation detail, and a
/// consumer only needs to be able to carry this from one engine to another. Cheap
/// to clone — it is a refcount.
#[derive(Clone)]
pub struct LeafState(Arc<incremental::Monitor>);

impl std::fmt::Debug for LeafState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeafState(..)")
    }
}

/// A leaf-state transfer cannot be performed without risking lost or
/// incorrectly associated monitor history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafStateTransferError {
    /// Partitioned engines store state in shards rather than `monitors`.
    PartitionedEngine,
    /// An engine violated its parallel leaf/monitor vector invariant.
    LeafMonitorCountMismatch { leaves: usize, monitors: usize },
}

impl std::fmt::Display for LeafStateTransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeafStateTransferError::PartitionedEngine => {
                write!(
                    f,
                    "leaf-state transfer is not supported on a partitioned engine"
                )
            }
            LeafStateTransferError::LeafMonitorCountMismatch { leaves, monitors } => {
                write!(
                    f,
                    "leaf and monitor counts diverged \
                     (leaves: {leaves}, monitors: {monitors})"
                )
            }
        }
    }
}

impl std::error::Error for LeafStateTransferError {}

fn validate_leaf_monitor_count(
    leaves: usize,
    monitors: usize,
) -> Result<(), LeafStateTransferError> {
    if leaves != monitors {
        return Err(LeafStateTransferError::LeafMonitorCountMismatch { leaves, monitors });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use dogwood_language::{
        Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, Value,
    };

    use super::{
        KEYED_STATE_MAGIC, KEYED_STATE_PARTITIONED, LeafStateTransferError, LocalTemporalEngine,
        PolicyId, composite_key, decode_keyed_state, encode_keyed_state,
        load_global_serialized_by_key, load_sharded_serialized_by_key, parse_leaf_origin,
        validate_leaf_monitor_count,
    };

    const KEYED_LOAD_SCHEMA: &str = r#"
namespace Test {
  type LoginInput = { user: String };
  type LoginOutput = { result: Bool };
  type TransferInput = { user: String };
  entity Gateway;
  entity User;
  action "Login" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: LoginInput, output: LoginOutput }
  };
  action "Transfer" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: TransferInput }
  };
}
"#;

    const KEYED_LOAD_POLICY: &str = r#"
permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 24h Test::Action::"Login"::response{ output.result: true }
};
"#;

    const TWO_LEAF_KEYED_LOAD_POLICY: &str = r#"
permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 1h Test::Action::"Login"::response{ output.result: true }
};

permit (principal, action == Test::Action::"Transfer", resource)
when temporal {
    formerly within 24h Test::Action::"Login"::response{ output.result: true }
};
"#;

    fn keyed_load_engine(policy: &str, partitioned: bool) -> LocalTemporalEngine {
        let schema = PolicySchema::from_cedarschema_str(KEYED_LOAD_SCHEMA).expect("schema builds");
        let service = ServiceSchema::builder()
            .build()
            .expect("default service builds");
        let lowered = LoweredPolicySet::from_str(policy, &service, &schema).expect("policy lowers");
        let leaves: Vec<_> = if partitioned {
            lowered.nonrelativized_temporal_fields().cloned().collect()
        } else {
            lowered.temporal_fields().cloned().collect()
        };
        let signatures = lowered.event_signatures().collect::<Vec<_>>();
        let mut engine = LocalTemporalEngine::new();
        if partitioned {
            engine.set_partition_keys(lowered.partition_keys());
        }
        engine
            .prepare(&leaves, lowered.cedar_schema(), &signatures)
            .expect("engine prepares");
        engine
    }

    fn keyed_load_login(timestamp: i64, pin: &str) -> Event {
        Event::builder("Test::Action::Login", "response")
            .timestamp(timestamp)
            .principal(&format!("Test::User::\"{pin}\""))
            .resource("Test::Gateway::\"gw\"")
            .field("input", "user", Value::String(pin.to_string()))
            .field("output", "result", Value::Bool(true))
            .request_context("input", "user", Value::String(pin.to_string()))
            .build()
    }

    fn keyed_load_probe(timestamp: i64, pin: &str) -> Event {
        Event::builder("Test::Action::Transfer", "request")
            .timestamp(timestamp)
            .principal(&format!("Test::User::\"{pin}\""))
            .resource("Test::Gateway::\"gw\"")
            .field("input", "user", Value::String(pin.to_string()))
            .request_context("input", "user", Value::String(pin.to_string()))
            .build()
    }

    /// The id shapes the frontend actually emits parse to `(policy index, ordinal)`.
    #[test]
    fn leaf_origin_parses_the_frontend_id_shapes() {
        // Default lowering: `policy_{N}__temporal_{M}`.
        assert_eq!(parse_leaf_origin("policy_0__temporal_0"), Some((0, 0)));
        assert_eq!(parse_leaf_origin("policy_12__temporal_3"), Some((12, 3)));
        // Distincter-prefixed rule key (`{distincter}_{N}`): the policy index is the
        // trailing decimal run, whatever word precedes it.
        assert_eq!(parse_leaf_origin("batch_5__temporal_2"), Some((5, 2)));
    }

    /// Shapes it cannot scope return `None`. The durable transplant guard turns
    /// that into a fail-closed rejection rather than mis-scoped history — so this
    /// pins the contract, and a future lowering change that broke it would fail
    /// here (targeted) instead of as a mysterious rebuild/recovery rejection.
    #[test]
    fn leaf_origin_rejects_shapes_it_cannot_scope() {
        assert_eq!(parse_leaf_origin("policy_0"), None); // no `__temporal_` seam
        assert_eq!(parse_leaf_origin("__temporal_0"), None); // empty rule key
        assert_eq!(parse_leaf_origin("policyX__temporal_0"), None); // no trailing decimal
        assert_eq!(parse_leaf_origin("policy_0__temporal_x"), None); // non-numeric ordinal
        assert_eq!(parse_leaf_origin("0__temporal_0"), None); // no distincter
        assert_eq!(parse_leaf_origin("bad-_0__temporal_0"), None); // invalid Cedar identifier
        assert_eq!(parse_leaf_origin("é_0__temporal_0"), None); // non-ASCII distincter
    }

    #[test]
    fn composite_key_resolves_only_an_in_range_frontend_origin() {
        let ids = vec![PolicyId(7), PolicyId(u64::MAX)];

        assert_eq!(
            composite_key(&ids, "policy_1__temporal_3", "content:with:colons"),
            format!("{}:3:content:with:colons", u64::MAX),
        );
        assert_eq!(
            composite_key(&ids, "policy_2__temporal_0", "leaf"),
            "?:leaf",
        );
        assert_eq!(composite_key(&ids, "malformed", "leaf"), "?:leaf");
    }

    #[test]
    fn keyed_state_envelope_requires_the_destination_mode_and_fingerprint() {
        let global_body = b"global state".to_vec();
        let partitioned_body = b"partitioned state".to_vec();
        let fingerprint = b"callerPrincipal";
        let global = encode_keyed_state(global_body.clone(), None);
        let partitioned = encode_keyed_state(partitioned_body.clone(), Some(fingerprint));

        assert_eq!(
            decode_keyed_state(&global, None),
            Some(global_body.as_slice())
        );
        assert_eq!(
            decode_keyed_state(&partitioned, Some(fingerprint)),
            Some(partitioned_body.as_slice())
        );
        assert_eq!(decode_keyed_state(&global, Some(fingerprint)), None);
        assert_eq!(decode_keyed_state(&partitioned, None), None);
        assert_eq!(decode_keyed_state(&partitioned, Some(b"sessionId")), None);
    }

    #[test]
    fn keyed_state_envelope_rejects_malformed_headers() {
        let global = encode_keyed_state(Vec::new(), None);
        for end in 0..KEYED_STATE_MAGIC.len() + 1 {
            assert_eq!(decode_keyed_state(&global[..end], None), None);
        }

        let mut bad_magic = global.clone();
        bad_magic[0] ^= 0xff;
        assert_eq!(decode_keyed_state(&bad_magic, None), None);

        let mut unknown_mode = global;
        unknown_mode[KEYED_STATE_MAGIC.len()] = 0xff;
        assert_eq!(decode_keyed_state(&unknown_mode, None), None);

        let mut impossible_length = Vec::from(KEYED_STATE_MAGIC.as_slice());
        impossible_length.push(KEYED_STATE_PARTITIONED);
        impossible_length.extend_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_keyed_state(&impossible_length, Some(b"fingerprint")),
            None
        );

        let partitioned = encode_keyed_state(Vec::new(), Some(b"fingerprint"));
        let missing_fingerprint_byte = partitioned.len() - 1;
        assert_eq!(
            decode_keyed_state(
                &partitioned[..missing_fingerprint_byte],
                Some(b"fingerprint"),
            ),
            None
        );
    }

    #[test]
    fn leaf_monitor_count_mismatch_is_a_transfer_error() {
        assert_eq!(
            validate_leaf_monitor_count(1, 0),
            Err(LeafStateTransferError::LeafMonitorCountMismatch {
                leaves: 1,
                monitors: 0,
            })
        );
        assert_eq!(validate_leaf_monitor_count(2, 2), Ok(()));
    }

    #[test]
    fn global_keyed_load_rejects_count_mismatch_before_mutation() {
        let keys = vec!["1:0:leaf".to_string()];
        let entries = vec![("1:0:leaf".to_string(), vec![0xff])];
        let mut monitors = Vec::new();

        assert_eq!(
            load_global_serialized_by_key(&keys, &mut monitors, &entries),
            None,
        );
        assert!(monitors.is_empty());
    }

    #[test]
    fn partitioned_keyed_load_rejects_count_mismatch_before_mutation() {
        let keys = vec!["1:0:leaf".to_string()];
        let entries = vec![("1:0:leaf".to_string(), vec![0xff])];
        let mut monitors = Vec::new();

        assert_eq!(
            load_sharded_serialized_by_key(&keys, &mut monitors, &entries, b"fingerprint", 17,),
            None,
        );
        assert!(monitors.is_empty());
    }

    #[test]
    fn public_global_keyed_load_rejects_count_mismatch_before_mutation() {
        let mut source = keyed_load_engine(TWO_LEAF_KEYED_LOAD_POLICY, false);
        source.observe(&keyed_load_login(20, "source"));
        let entries = source.save_keyed_state();

        let mut destination = keyed_load_engine(TWO_LEAF_KEYED_LOAD_POLICY, false);
        destination.observe(&keyed_load_login(10, "destination"));
        destination.monitors.pop();
        let before = destination.save_keyed_state();

        assert_eq!(
            destination.load_keyed_state(&entries),
            Err(LeafStateTransferError::LeafMonitorCountMismatch {
                leaves: 2,
                monitors: 1,
            })
        );
        assert_eq!(destination.save_keyed_state(), before);
    }

    #[test]
    fn public_partitioned_keyed_load_rejects_count_mismatch_before_mutation() {
        let mut source = keyed_load_engine(TWO_LEAF_KEYED_LOAD_POLICY, true);
        source.observe(&keyed_load_login(20, "source"));
        let entries = source.save_keyed_state();

        let mut destination = keyed_load_engine(TWO_LEAF_KEYED_LOAD_POLICY, true);
        destination.observe(&keyed_load_login(10, "destination"));
        destination.sharded.pop();
        let before = destination.save_keyed_state();
        let before_now = destination.global_now;

        assert_eq!(
            destination.load_keyed_state(&entries),
            Err(LeafStateTransferError::LeafMonitorCountMismatch {
                leaves: 2,
                monitors: 1,
            })
        );
        assert_eq!(destination.save_keyed_state(), before);
        assert_eq!(destination.global_now, before_now);
    }

    #[test]
    fn partitioned_keyed_load_uses_the_first_duplicate_entry() {
        let mut first = keyed_load_engine(KEYED_LOAD_POLICY, true);
        first.observe(&keyed_load_login(10, "alice"));
        let first_entry = first.save_keyed_state().pop().expect("one leaf");

        let mut second = keyed_load_engine(KEYED_LOAD_POLICY, true);
        second.observe(&keyed_load_login(20, "bob"));
        let second_entry = second.save_keyed_state().pop().expect("one leaf");
        assert_eq!(first_entry.0, second_entry.0);

        let mut destination = keyed_load_engine(KEYED_LOAD_POLICY, true);
        assert_eq!(
            destination.load_keyed_state(&[first_entry, second_entry]),
            Ok(1)
        );
        assert_eq!(destination.global_now, 10);

        destination.observe(&keyed_load_probe(30, "alice"));
        assert!(
            destination
                .evaluate()
                .expect("alice evaluates")
                .values()
                .all(|value| *value)
        );
        destination.observe(&keyed_load_probe(40, "bob"));
        assert!(
            destination
                .evaluate()
                .expect("bob evaluates")
                .values()
                .all(|value| !value)
        );
    }

    #[test]
    fn partitioned_keyed_load_max_folds_the_restored_and_destination_clocks() {
        let mut source = keyed_load_engine(KEYED_LOAD_POLICY, true);
        source.observe(&keyed_load_login(40, "source"));
        let entries = source.save_keyed_state();

        let mut fresh_destination = keyed_load_engine(KEYED_LOAD_POLICY, true);
        assert_eq!(fresh_destination.load_keyed_state(&entries), Ok(1));
        assert_eq!(fresh_destination.global_now, 40);

        let mut later_destination = keyed_load_engine(KEYED_LOAD_POLICY, true);
        later_destination.observe(&keyed_load_login(90, "destination"));
        assert_eq!(later_destination.load_keyed_state(&entries), Ok(1));
        assert_eq!(later_destination.global_now, 90);
    }
}
