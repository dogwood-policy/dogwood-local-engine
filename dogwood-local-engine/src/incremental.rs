//! Incremental temporal monitoring — the general **table-based**
//! tree-walk.
//!
//! # The design (why it is uniform, with no special cases)
//!
//! This mirrors the interpreter's relational recursion
//! (the frontend interpreter's `match_occurrences`) **exactly**, over a maintained,
//! window-bounded set of timepoints instead of the full trace. The property
//! that must never be compromised: a node is evaluated **at a timepoint** under
//! an environment, and the decision request is threaded as ordinary env
//! bindings — so a `context.*` / `principal` / `resource` read (which always
//! refers to the **decision** request, even inside a past operator) resolves
//! uniformly at every timepoint, never collapsed away or deferred.
//!
//! ## Structure
//!
//! - Predicates keep a **per-timepoint history** of their matched rows over the
//!   retained window (one `Option<Row>` per retained timepoint). No collapsing.
//! - [`occ`](Node::occ) evaluates any node **at a retained timepoint index `k`**
//!   under `env` (join for `&&`, union
//!   for `||`, anti-filter for `!`, projection for `exists`, `tp` binding,
//!   comparison filter/binder, aggregation reduction).
//! - Temporal nodes union / streak / delay their child's `occ` over the
//!   in-window timepoints — the only place windowing lives.
//! - `step` appends each predicate's current match and front-prunes the shared
//!   timeline to the max window; `verdict` seeds `env` from the decision request
//!   and asks the root for its relation at the current timepoint.
//!
//! # Correlation, uniformly
//!
//! A predicate arg `field: context.input.user` binds the matched **event's**
//! value under the env key `context.input.user`; at verdict that same key is
//! seeded with the **decision's** value, so [`compatible`] joins them — the
//! correlation. A `context.*` used directly in a comparison reads the same
//! seeded key.
//!
//! [`Node::build`] returns `None` only for inputs outside the temporal fragment
//! (transient macro sigils / `Refine`, which never reach a prepared leaf).

use std::collections::BTreeMap;

use dogwood_language::temporal_ast::{
    AggExprKind, CmpOp, Condition, ConditionKind, Predicate, Term, TypedBinder, WithinSpec,
};
use dogwood_language::{Event, Value};

use crate::rel::{LeafHistory, LeafStore, Rel, RelRead, TimeRel};
use crate::rows::{DistinctRows, Row, dedup_rows, join_rows, project_count, project_sum};
use crate::tick::TickRate;

/// Bindings threaded through evaluation (variable / request-key → value).
/// Seeded at verdict with the decision request's `context.*` values (key
/// `context.<path>`) and scope values (key `@<path>`), then extended with
/// matched-variable bindings as the recursion descends.
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

type Env = BTreeMap<String, Value>;

/// The retained timeline shared by all predicates in a monitor: each retained
/// timepoint's timestamp and its monotonic id (for `tp` binding — the id
/// survives pruning; only distinctness/order matters, no timepoint literals
/// exist in the language). Index `k` is the `k`-th retained timepoint.
/// `Clone` for `Arc::make_mut`: see `LocalTemporalEngine::monitors`.
#[derive(Clone)]
struct Timeline {
    ts: std::collections::VecDeque<i64>,
    tp_id: std::collections::VecDeque<i64>,
}

/// The memo key's env part: the body's free-key values in fixed order,
/// with dom_eq equality/hashing (decimal spellings collapse — reuses
/// `rows::dom_hash_value`, the same discipline as `project_count`).
#[derive(Debug, Clone)]
struct DomEqKey(Vec<Option<Value>>);

impl std::hash::Hash for DomEqKey {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        use std::hash::Hash;
        self.0.len().hash(h);
        for v in &self.0 {
            match v {
                None => 8u8.hash(h), // distinct from every dom_hash tag
                Some(v) => crate::rows::dom_hash_value(v, h),
            }
        }
    }
}
impl PartialEq for DomEqKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self.0.iter().zip(&other.0).all(|(a, b)| match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => a.dom_eq(b),
                _ => false,
            })
    }
}
impl Eq for DomEqKey {}

/// The memo's storage: the value map plus a TIMEPOINT-BUCKETED eviction
/// index. In steady state (a trace longer than the window) the prune
/// branch fires on ~every observe, so eviction must NOT rescan the map
/// (O(entries) per event): the
/// index makes it O(log W) to find the dead prefix and O(1) amortized
/// per entry over its lifetime (each entry is enqueued once at insert,
/// dequeued once at eviction). Inserts are NOT tp-ordered across
/// decides (each decide's sweep revisits old timepoints), which is why
/// this is a BTreeMap of buckets and not a queue.
#[derive(Default)]
struct MemoMap {
    entries: HashMap<(u32, i64, DomEqKey), Option<Value>>,
    /// tp → the (node, env-key) pairs inserted at that tp.
    by_tp: BTreeMap<i64, Vec<(u32, DomEqKey)>>,
}

impl MemoMap {
    fn get(&self, key: &(u32, i64, DomEqKey)) -> Option<Option<Value>> {
        self.entries.get(key).cloned()
    }
    fn insert(&mut self, key: (u32, i64, DomEqKey), v: Option<Value>) {
        self.by_tp
            .entry(key.1)
            .or_default()
            .push((key.0, key.2.clone()));
        self.entries.insert(key, v);
    }
    /// Drop every entry whose timepoint is BEFORE `min_live`: O(log W)
    /// to split the dead prefix + O(1) per dropped entry.
    fn evict_before(&mut self, min_live: i64) {
        let live = self.by_tp.split_off(&min_live);
        let dead = std::mem::replace(&mut self.by_tp, live);
        for (tp, keys) in dead {
            for (node, env_key) in keys {
                self.entries.remove(&(node, tp, env_key));
            }
        }
    }
}

/// The aggregate memo: caches `Operand::Agg`
/// values keyed by (agg id, PERMANENT timepoint id, the env projected
/// onto the body's free keys). Sound because the language is past-only
/// (a value at tp is fixed once evaluated) and pruning is
/// semantics-transparent (`max_window` is the nesting sum), so entries
/// never go stale; eviction is memory-only. NEVER serialized.
struct AggMemo {
    /// Per agg id: the env keys the body can read (a build-time
    /// OVER-approximation — extra keys cost hit rate, never soundness).
    free_keys: Vec<Vec<String>>,
    /// Per agg id: false when the body contains opaque terms
    /// (ParamRef/BinderRef/nested Term::Agg) — those run unmemoized.
    eligible: Vec<bool>,
    /// Locks RECOVER from poisoning (`into_inner`): entries never go
    /// stale, so a panic mid-decide cannot leave a wrong value —
    /// at worst a missing insert. `.expect` would brick both decide
    /// AND ingest (step's eviction) forever after one panic.
    map: Mutex<MemoMap>,
    enabled: bool,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl AggMemo {
    fn new() -> Self {
        AggMemo {
            free_keys: Vec::new(),
            eligible: Vec::new(),
            map: Mutex::new(MemoMap::default()),
            enabled: true,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }
}

impl Clone for AggMemo {
    /// `Monitor` is Clone for `Arc::make_mut` copy-on-write. A cloned
    /// memo would stay VALID (values never go stale), but the clone is
    /// cheapest and simplest EMPTY — the owner rewarms in one decide.
    fn clone(&self) -> Self {
        AggMemo {
            free_keys: self.free_keys.clone(),
            eligible: self.eligible.clone(),
            map: Mutex::new(MemoMap::default()),
            enabled: self.enabled,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }
}

/// A per-leaf incremental monitor.
/// `Clone` for `Arc::make_mut`: see `LocalTemporalEngine::monitors`.
#[derive(Clone)]
pub struct Monitor {
    root: Node,
    timeline: Timeline,
    /// Max window (seconds) in the tree — the prune horizon. `i64::MAX` ⇒ never.
    max_window: i64,
    next_tp: i64,
    /// Decision terms read anywhere (predicate args / comparison operands),
    /// each with the env key it seeds at verdict.
    req_terms: Vec<(String, Term)>,
    /// The aggregate memo (derived state: not serialized, cloned empty).
    memo: AggMemo,
}

impl Monitor {
    /// Build an incremental monitor for `cond`; `None` only for transient nodes.
    pub fn build(cond: &Condition, rate: TickRate) -> Option<Monitor> {
        let mut req = BTreeMap::new();
        let root = Node::build(cond, &mut req, rate)?;
        let max_window = root.max_window();
        let mut root = root;
        let mut memo = AggMemo::new();
        index_agg_memos(&mut root, &mut memo);
        Some(Monitor {
            root,
            timeline: Timeline {
                ts: std::collections::VecDeque::new(),
                tp_id: std::collections::VecDeque::new(),
            },
            max_window,
            next_tp: 0,
            req_terms: req.into_iter().collect(),
            memo,
        })
    }

    /// Advance by one observed event: extend the timeline, record each
    /// predicate's match at the new timepoint, then front-prune the window.
    pub fn step(&mut self, event: &Event) {
        let ts = event.timestamp();
        self.timeline.ts.push_back(ts);
        self.timeline.tp_id.push_back(self.next_tp);
        self.next_tp += 1;
        self.root.record(event);

        if self.max_window != i64::MAX {
            let horizon = ts.saturating_sub(self.max_window);
            let drop = self.timeline.ts.partition_point(|t| *t < horizon);
            if drop > 0 {
                self.timeline.ts.drain(..drop);
                self.timeline.tp_id.drain(..drop);
                self.root.drop_front(drop);
                // Memo eviction: memory-only (entries never go stale);
                // anything whose timepoint left the
                // retained timeline can never be read again.
                let min_live = self.timeline.tp_id.front().copied().unwrap_or(i64::MAX);
                self.memo
                    .map
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .evict_before(min_live);
            }
        }
    }

    /// Serialize the monitor's **mutable derived state** — the shared timeline
    /// (`ts` / `tp_id` / `next_tp`) and every predicate's per-timepoint match
    /// history, in a fixed tree-walk order. The `Node` tree *shape* is not
    /// stored; it is rebuilt from the leaves at [`build`](Self::build) and the
    /// state loaded back into it.
    pub fn save(&self) -> Vec<u8> {
        use crate::snapshot::{encode_time_row, put_i64, put_u64};
        let mut out = Vec::new();
        put_u64(&mut out, self.timeline.ts.len() as u64);
        for &t in &self.timeline.ts {
            put_i64(&mut out, t);
        }
        for &t in &self.timeline.tp_id {
            put_i64(&mut out, t);
        }
        put_i64(&mut out, self.next_tp);
        // Per-predicate histories, in the tree's fixed pre-order. The on-disk
        // form is the *dense* per-timepoint sequence (`len`, then one optional
        // row per retained timepoint) regardless of the in-memory
        // representation, so the format is stable across a sparse/dense swap:
        // materialize each retained slot from the sparse leaf via `at`.
        self.root.save_state(&mut out, &mut |node_out, history| {
            let len = history.logical_len();
            put_u64(node_out, len as u64);
            for k in 0..len {
                let cell = history.at(k).first().cloned();
                encode_time_row(node_out, &cell);
            }
        });
        out
    }

    /// Restore state produced by [`save`](Self::save) into a freshly-built
    /// monitor (same leaves ⇒ same tree shape ⇒ same walk order). Returns
    /// `false` on malformed / mismatched input, leaving the monitor for the
    /// caller to rebuild by replay instead (fail-safe).
    pub fn load(&mut self, bytes: &[u8]) -> bool {
        use crate::snapshot::{Reader, decode_time_row};
        let mut r = Reader::new(bytes);
        let Some(n) = r.usize() else { return false };
        // Validate all fixed-width timeline framing before allocating either
        // vector. Each field owns its sizing check; there is no duplicated
        // formula coupling this reader to the on-disk layout.
        let Some(ts_block) = r.u64_block(n) else {
            return false;
        };
        let Some(tp_id_block) = r.u64_block(n) else {
            return false;
        };
        let Some(next_tp) = r.u64() else { return false };
        let Some(ts) = ts_block.decode_i64s() else {
            return false;
        };
        let Some(tp_id) = tp_id_block.decode_i64s() else {
            return false;
        };
        let Ok(next_tp) = i64::try_from(next_tp) else {
            return false;
        };
        if ts.windows(2).any(|pair| pair[0] > pair[1])
            || tp_id.first().is_some_and(|id| *id < 0)
            || tp_id
                .windows(2)
                .any(|pair| pair[0].checked_add(1) != Some(pair[1]))
            || match tp_id.last() {
                Some(last) => last.checked_add(1) != Some(next_tp),
                None => next_tp != 0,
            }
        {
            return false;
        }
        let mut ok = true;
        // Decode predicate histories into scratch state. `load_state` replaces
        // histories as it walks, so applying it directly to `self.root` would
        // leave an early prefix installed when a later history is malformed.
        let mut root = self.root.clone();
        root.load_state(&mut r, &mut |rd| {
            // Read the same dense per-timepoint sequence `save` wrote and replay
            // it into the sparse leaf via `push` (matches kept, absences skipped
            // but still counted), reconstructing the retained length exactly.
            let mut hist = LeafStore::new();
            if !ok {
                return hist;
            }
            let Some(len) = rd.count(1) else {
                ok = false;
                return hist;
            };
            if len != n {
                ok = false;
                return hist;
            }
            for _ in 0..len {
                match decode_time_row(rd) {
                    Some(tr) => hist.push(tr),
                    None => {
                        ok = false;
                        return LeafStore::new();
                    }
                }
            }
            hist
        });
        if !ok || !r.at_end() {
            return false;
        }
        self.root = root;
        self.timeline.ts = ts.into();
        self.timeline.tp_id = tp_id.into();
        self.next_tp = next_tp;
        true
    }

    /// The prune horizon (the nesting-sum max window) — the shard
    /// sweep's full-expiry threshold (src/partition.rs).
    pub fn retention_window(&self) -> i64 {
        self.max_window
    }

    /// The newest retained timepoint's timestamp (None when empty) —
    /// rebuilds the shard staleness index after a snapshot load.
    pub fn last_event_ts(&self) -> Option<i64> {
        self.timeline.ts.back().copied()
    }

    /// Disable the aggregate memo (the kill switch / test OFF lane).
    pub fn disable_agg_memo(&mut self) {
        self.memo.enabled = false;
    }

    /// Current entry count (test hook: steady-state boundedness).
    pub fn agg_memo_len(&self) -> usize {
        self.memo
            .map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .len()
    }

    /// (hits, misses) since construction.
    pub fn agg_memo_stats(&self) -> (u64, u64) {
        (
            self.memo.hits.load(Ordering::Relaxed),
            self.memo.misses.load(Ordering::Relaxed),
        )
    }

    /// Whether the leaf holds at the current decision point.
    pub fn verdict(&self, decision: &Event) -> bool {
        let Some(cur) = self.timeline.ts.len().checked_sub(1) else {
            return false;
        };
        // Seed env with the decision request's values. A term that does not
        // resolve is left ABSENT, which is what marks it unresolvable
        // downstream: `resolve_term` yields `None` (dropping the row) and the
        // `Pred` arm of `Node::rel` drops a leaf correlating on it — matching
        // `eval.rs`, where `match_args` propagates the same `None` through `?`.
        let mut env = Env::new();
        for (key, term) in &self.req_terms {
            if let Some(v) = resolve_decision_term(decision, term) {
                env.insert(key.clone(), v);
            }
        }
        !self
            .root
            .occ(cur, &env, &self.timeline, &self.memo)
            .is_empty()
    }
}

/// A stateful monitor node.
#[derive(Clone)]
enum Node {
    Pred {
        namespace: Vec<String>,
        action: String,
        kind: String,
        args: Vec<ArgSpec>,
        /// This predicate's window-pruned match history, read as a relation.
        /// See [`LeafHistory`]; the representation is the [`LeafStore`] alias.
        history: LeafStore,
    },
    Formerly {
        window: i64,
        child: Box<Node>,
    },
    Previous {
        window: i64,
        child: Box<Node>,
    },
    Since {
        window: i64,
        left: Box<Node>,
        right: Box<Node>,
    },
    And {
        left: Box<Node>,
        right: Box<Node>,
    },
    Or {
        left: Box<Node>,
        right: Box<Node>,
    },
    Not {
        child: Box<Node>,
    },
    Exists {
        var: String,
        child: Box<Node>,
    },
    Tp {
        var: String,
    },
    /// A comparison `left <op> right` where each operand is either a plain term
    /// or an aggregate over a body relation. Covers term-vs-term, agg-vs-term,
    /// and agg-vs-agg uniformly (mirrors `eval.rs`, where both operands go
    /// through `resolve_term_at`, which handles `Term::Agg`).
    Compare {
        op: CmpOp,
        left: Operand,
        right: Operand,
    },
}

/// A comparison operand: a plain term, or an aggregate reducing a body node's
/// relation at the current timepoint.
#[derive(Clone)]
enum Operand {
    Term(Term),
    Agg {
        kind: AggKind,
        for_vars: Vec<TypedBinder>,
        bound_var: Option<String>,
        body: Box<Node>,
        /// Index into the Monitor's `AggMemo` tables, assigned at build.
        memo_id: u32,
    },
}

#[derive(Clone)]
enum AggKind {
    Count,
    Sum,
}

impl Operand {
    fn max_window(&self) -> i64 {
        match self {
            Operand::Term(_) => 0,
            Operand::Agg { body, .. } => body.max_window(),
        }
    }
    fn record(&mut self, event: &Event) {
        if let Operand::Agg { body, .. } = self {
            body.record(event);
        }
    }
    fn drop_front(&mut self, n: usize) {
        if let Operand::Agg { body, .. } = self {
            body.drop_front(n);
        }
    }
    fn save_state(&self, out: &mut Vec<u8>, visit: &mut dyn FnMut(&mut Vec<u8>, &LeafStore)) {
        if let Operand::Agg { body, .. } = self {
            body.save_state(out, visit);
        }
    }
    fn load_state(
        &mut self,
        r: &mut crate::snapshot::Reader,
        next: &mut dyn FnMut(&mut crate::snapshot::Reader) -> LeafStore,
    ) {
        if let Operand::Agg { body, .. } = self {
            body.load_state(r, next);
        }
    }

    /// If this operand is a plain unbound variable (a range-binder candidate),
    /// its name; else `None`. An aggregate is never a binder.
    fn unbound_var<'a>(&'a self, env: &Env) -> Option<&'a str> {
        match self {
            Operand::Term(Term::Var(n)) if env.get(n).is_none() => Some(n),
            _ => None,
        }
    }

    /// Reduce this operand to a value at timepoint `k` under `env`. `None` if a
    /// term does not resolve (e.g. an unbound variable / absent field).
    fn value(&self, k: usize, env: &Env, tl: &Timeline, memo: &AggMemo) -> Option<Value> {
        match self {
            Operand::Term(t) => resolve_term(env, t),
            Operand::Agg {
                kind,
                for_vars,
                bound_var,
                body,
                memo_id,
            } => {
                let inner = shed_for_binders(env, for_vars);
                let idx = *memo_id as usize;
                // THE MEMO: the value
                // at a PERMANENT timepoint id under the body's free-key
                // projection is fixed forever (past-only language;
                // prune-transparent retention), so cache-through.
                if memo.enabled && memo.eligible[idx] {
                    let key_env: Vec<Option<Value>> = memo.free_keys[idx]
                        .iter()
                        .map(|kk| inner.get(kk).cloned())
                        .collect();
                    let key = (*memo_id, tl.tp_id[k], DomEqKey(key_env));
                    // Lock scope: get+clone, UNLOCK before the recompute —
                    // a nested Agg re-enters this memo (deadlock otherwise).
                    let cached = {
                        let g = memo.map.lock().unwrap_or_else(|e| e.into_inner());
                        g.get(&key)
                    };
                    if let Some(v) = cached {
                        memo.hits.fetch_add(1, Ordering::Relaxed);
                        return v;
                    }
                    memo.misses.fetch_add(1, Ordering::Relaxed);
                    let rows = body.occ(k, &inner, tl, memo);
                    let v = Some(Value::Int(match kind {
                        AggKind::Count => project_count(&rows, for_vars),
                        AggKind::Sum => {
                            project_sum(&rows, for_vars, bound_var.as_deref().unwrap_or(""))
                        }
                    }));
                    memo.map
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key, v.clone());
                    return v;
                }
                // Fold the body's relation at `k` into the distinct-projection
                // aggregate in one pass (a `dom_eq`-consistent hash), rather than
                // materializing a deduped `Vec<Row>` and reducing it — see
                // `project_count` / `project_sum`.
                let rows = body.occ(k, &inner, tl, memo);
                Some(Value::Int(match kind {
                    AggKind::Count => project_count(&rows, for_vars),
                    AggKind::Sum => {
                        project_sum(&rows, for_vars, bound_var.as_deref().unwrap_or(""))
                    }
                }))
            }
        }
    }
}

/// How one predicate arg constrains a matched event and what it binds.
#[derive(Clone)]
enum ArgSpec {
    Literal {
        field: Vec<String>,
        value: Value,
    },
    Wildcard {
        field: Vec<String>,
    },
    Var {
        field: Vec<String>,
        name: String,
    },
    /// `field: context.X / principal / resource` — bind the event field under
    /// the **request env key** for that decision term, so the correlation is a
    /// join against the decision's seeded value.
    Correlated {
        field: Vec<String>,
        key: String,
    },
}

impl Node {
    fn build(cond: &Condition, req: &mut BTreeMap<String, Term>, rate: TickRate) -> Option<Node> {
        match &cond.kind {
            ConditionKind::Predicate(p) => Some(build_pred(p, req)),
            ConditionKind::Formerly { within, body } => Some(Node::Formerly {
                window: interval_ticks(within, rate),
                child: Box::new(Node::build(body, req, rate)?),
            }),
            ConditionKind::Previous { within, body } => Some(Node::Previous {
                window: interval_ticks(within, rate),
                child: Box::new(Node::build(body, req, rate)?),
            }),
            ConditionKind::Since {
                left,
                within,
                right,
            } => Some(Node::Since {
                window: interval_ticks(within, rate),
                left: Box::new(Node::build(left, req, rate)?),
                right: Box::new(Node::build(right, req, rate)?),
            }),
            ConditionKind::And { left, right } => Some(Node::And {
                left: Box::new(Node::build(left, req, rate)?),
                right: Box::new(Node::build(right, req, rate)?),
            }),
            ConditionKind::Or { left, right } => Some(Node::Or {
                left: Box::new(Node::build(left, req, rate)?),
                right: Box::new(Node::build(right, req, rate)?),
            }),
            ConditionKind::Not { inner } => Some(Node::Not {
                child: Box::new(Node::build(inner, req, rate)?),
            }),
            ConditionKind::Exists { var, body } => Some(Node::Exists {
                var: var.name().to_string(),
                child: Box::new(Node::build(body, req, rate)?),
            }),
            ConditionKind::Tp { var } => Some(Node::Tp {
                var: var.name().to_string(),
            }),
            ConditionKind::Comparison { op, left, right } => {
                build_compare(*op, left, right, req, rate)
            }
            ConditionKind::Call(_)
            | ConditionKind::SigilRef { .. }
            | ConditionKind::Refine { .. } => None,
        }
    }

    /// Max window (seconds) in the subtree — windows compose additively down
    /// temporal operators; `i64::MAX` is unbounded.
    fn max_window(&self) -> i64 {
        match self {
            Node::Pred { .. } | Node::Tp { .. } => 0,
            Node::Compare { left, right, .. } => left.max_window().max(right.max_window()),
            Node::Formerly { window, child } | Node::Previous { window, child } => {
                window.saturating_add(child.max_window())
            }
            Node::Since {
                window,
                left,
                right,
            } => window.saturating_add(left.max_window().max(right.max_window())),
            Node::And { left, right } | Node::Or { left, right } => {
                left.max_window().max(right.max_window())
            }
            Node::Not { child } | Node::Exists { child, .. } => child.max_window(),
        }
    }

    /// Visit each predicate's history in a fixed pre-order (the same order as
    /// [`record`](Self::record) / [`drop_front`](Self::drop_front)), calling
    /// `visit` to serialize it. `save`/`load` share this walk so state loads
    /// back into the identically-shaped tree.
    fn save_state(&self, out: &mut Vec<u8>, visit: &mut dyn FnMut(&mut Vec<u8>, &LeafStore)) {
        match self {
            Node::Pred { history, .. } => visit(out, history),
            Node::Formerly { child, .. }
            | Node::Previous { child, .. }
            | Node::Not { child }
            | Node::Exists { child, .. } => child.save_state(out, visit),
            Node::Since { left, right, .. }
            | Node::And { left, right }
            | Node::Or { left, right } => {
                left.save_state(out, visit);
                right.save_state(out, visit);
            }
            Node::Compare { left, right, .. } => {
                left.save_state(out, visit);
                right.save_state(out, visit);
            }
            Node::Tp { .. } => {}
        }
    }

    /// Restore each predicate's history in the same pre-order. `next` yields the
    /// next history (or an empty one on malformed input, flagged by the caller).
    fn load_state(
        &mut self,
        r: &mut crate::snapshot::Reader,
        next: &mut dyn FnMut(&mut crate::snapshot::Reader) -> LeafStore,
    ) {
        match self {
            Node::Pred { history, .. } => *history = next(r),
            Node::Formerly { child, .. }
            | Node::Previous { child, .. }
            | Node::Not { child }
            | Node::Exists { child, .. } => child.load_state(r, next),
            Node::Since { left, right, .. }
            | Node::And { left, right }
            | Node::Or { left, right } => {
                left.load_state(r, next);
                right.load_state(r, next);
            }
            Node::Compare { left, right, .. } => {
                left.load_state(r, next);
                right.load_state(r, next);
            }
            Node::Tp { .. } => {}
        }
    }

    /// Record this event's match at the new (last) retained timepoint, into
    /// every predicate's history.
    fn record(&mut self, event: &Event) {
        match self {
            Node::Pred {
                namespace,
                action,
                kind,
                args,
                history,
            } => history.push(match_pred_event(event, namespace, action, kind, args)),
            Node::Formerly { child, .. }
            | Node::Previous { child, .. }
            | Node::Not { child }
            | Node::Exists { child, .. } => child.record(event),
            Node::Since { left, right, .. }
            | Node::And { left, right }
            | Node::Or { left, right } => {
                left.record(event);
                right.record(event);
            }
            Node::Compare { left, right, .. } => {
                left.record(event);
                right.record(event);
            }
            Node::Tp { .. } => {}
        }
    }

    /// Drop the first `n` retained timepoints from every predicate history.
    fn drop_front(&mut self, n: usize) {
        match self {
            Node::Pred { history, .. } => {
                history.drop_front(n);
            }
            Node::Formerly { child, .. }
            | Node::Previous { child, .. }
            | Node::Not { child }
            | Node::Exists { child, .. } => child.drop_front(n),
            Node::Since { left, right, .. }
            | Node::And { left, right }
            | Node::Or { left, right } => {
                left.drop_front(n);
                right.drop_front(n);
            }
            Node::Compare { left, right, .. } => {
                left.drop_front(n);
                right.drop_front(n);
            }
            Node::Tp { .. } => {}
        }
    }

    /// The relation at a single timepoint — the degenerate range `rel(k, k)`.
    /// The point view used by `Operand::value`, the `Since` streak check, and
    /// `Monitor::verdict`.
    fn occ(&self, k: usize, env: &Env, tl: &Timeline, memo: &AggMemo) -> Vec<Row> {
        self.rel(k, k, env, tl, memo).at(k).to_vec()
    }

    /// The relation of satisfying binding rows at each timepoint in `lo..=hi`
    /// under `env`, as a [`Rel`]. Mirrors the interpreter's `match_occurrences`
    /// arm for arm; the temporal arms evaluate their child **once** over a
    /// widened range and roll it up, rather than re-recursing per timepoint.
    fn rel(&self, lo: usize, hi: usize, env: &Env, tl: &Timeline, memo: &AggMemo) -> Rel {
        let mut out = Rel::empty();
        if tl.ts.is_empty() || lo > hi || hi >= tl.ts.len() {
            return out;
        }
        match self {
            Node::Pred { args, history, .. } => {
                // A correlated arg joins against a request key `verdict` seeds
                // from the decision. An UNSEEDED key means that term did not
                // resolve, so the correlation is unresolvable and the leaf
                // matches no occurrence — as in the reference, where
                // `match_args` propagates `resolve_term`'s `None` through `?`.
                let resolvable = args.iter().all(|a| match a {
                    ArgSpec::Correlated { key, .. } => env.contains_key(key),
                    _ => true,
                });
                if resolvable {
                    for (i, rows) in history.range(lo, hi) {
                        // A leaf cell is exactly one matched row.
                        if let [row] = rows
                            && compatible(row, env)
                        {
                            out.put(i, vec![row.clone()]);
                        }
                    }
                }
            }

            // Union the body's rows over every in-window past timepoint. Body
            // evaluated once over the widened range; each output rolls it up
            // over its own window. Dedup, mirroring the interpreter.
            Node::Formerly { window, child } => {
                let start = window_start(tl, lo, *window);
                let brel = child.rel(start, hi, env, tl, memo);
                for i in lo..=hi {
                    let in_win = brel
                        .range(start, i)
                        .filter(|(j, _)| in_window(tl, i, *j, *window))
                        .flat_map(|(_, jrows)| jrows.iter().cloned());
                    out.put(i, dedup_rows(in_win));
                }
            }

            // The immediately preceding timepoint, if in window.
            Node::Previous { window, child } => {
                let start = lo.saturating_sub(1);
                let brel = child.rel(start, hi, env, tl, memo);
                for i in lo..=hi {
                    if i >= 1 && in_window(tl, i, i - 1, *window) {
                        out.put(i, brel.at(i - 1).to_vec());
                    }
                }
            }

            // An in-window anchor from `right`, with `left` holding at every
            // step after it. Anchors evaluated once over the widened range; the
            // streak check reuses the point view per step. Anchors deduped.
            Node::Since {
                window,
                left,
                right,
            } => {
                let start = window_start(tl, lo, *window);
                let rrel = right.rel(start, hi, env, tl, memo);
                for i in lo..=hi {
                    let mut rows = DistinctRows::new();
                    for (j, anchors) in rrel.range(start, i) {
                        if !in_window(tl, i, j, *window) {
                            continue;
                        }
                        for anchor in anchors {
                            let mut env2 = env.clone();
                            for (kk, vv) in anchor {
                                env2.insert(kk.clone(), vv.clone());
                            }
                            let holds =
                                ((j + 1)..=i).all(|m| !left.occ(m, &env2, tl, memo).is_empty());
                            if holds {
                                rows.insert(anchor.clone());
                            }
                        }
                    }
                    out.put(i, rows.into_vec());
                }
            }

            // Per-timepoint correlated join: `right` runs at each `i` under env
            // extended by the left row. Deduped.
            Node::And { left, right } => {
                let lrel = left.rel(lo, hi, env, tl, memo);
                for (i, lrows) in lrel.iter() {
                    let mut rows = DistinctRows::new();
                    for lrow in lrows {
                        let mut env2 = env.clone();
                        for (kk, vv) in lrow {
                            env2.insert(kk.clone(), vv.clone());
                        }
                        for rrow in right.rel(i, i, &env2, tl, memo).at(i) {
                            if let Some(j) = join_rows(lrow, rrow) {
                                rows.insert(j);
                            }
                        }
                    }
                    out.put(i, rows.into_vec());
                }
            }

            // Per-timepoint union, deduping right into left. The left cell is
            // already distinct (a child `rel` cell), so inserting left-then-right
            // reproduces "left as-is, right deduped in" in the same order.
            Node::Or { left, right } => {
                let lrel = left.rel(lo, hi, env, tl, memo);
                let rrel = right.rel(lo, hi, env, tl, memo);
                for i in lo..=hi {
                    let union = lrel.at(i).iter().chain(rrel.at(i)).cloned();
                    out.put(i, dedup_rows(union));
                }
            }

            // One empty witness row exactly where the child relation is empty.
            Node::Not { child } => {
                let crel = child.rel(lo, hi, env, tl, memo);
                for i in lo..=hi {
                    if crel.at(i).is_empty() {
                        out.put(i, vec![Vec::new()]);
                    }
                }
            }

            // Project the bound variable out of the body's relation and dedup.
            Node::Exists { var, child } => {
                let mut inner = env.clone();
                inner.remove(var);
                let brel = child.rel(lo, hi, &inner, tl, memo);
                for (i, brows) in brel.iter() {
                    let projected = brows.iter().map(|row| {
                        let mut p = row.clone();
                        p.retain(|(kk, _)| kk != var);
                        p
                    });
                    out.put(i, dedup_rows(projected));
                }
            }

            // Bind `var` to the current timepoint id, unless env pins it away.
            Node::Tp { var } => {
                for i in lo..=hi {
                    let id = Value::Int(tl.tp_id[i]);
                    let skip = matches!(env.get(var), Some(b) if !b.dom_eq(&id));
                    if !skip {
                        out.put(i, vec![vec![(var.clone(), id)]]);
                    }
                }
            }

            // Equality that binds a variable, else a filter; operands may be
            // aggregates (agg-vs-agg included).
            Node::Compare { op, left, right } => {
                for i in lo..=hi {
                    out.put(i, compare_rows(*op, left, right, i, env, tl, memo));
                }
            }
        }
        out
    }
}

/// The rows a `Compare` node produces at timepoint `i`: an eq-binding row when
/// exactly one operand is an unbound var and the other resolves, otherwise a
/// filter (one empty witness row iff the comparison holds).
fn compare_rows(
    op: CmpOp,
    left: &Operand,
    right: &Operand,
    i: usize,
    env: &Env,
    tl: &Timeline,
    memo: &AggMemo,
) -> Vec<Row> {
    if op == CmpOp::Eq {
        match (left.unbound_var(env), right.unbound_var(env)) {
            (Some(name), None) => {
                return match right.value(i, env, tl, memo) {
                    Some(v) => vec![vec![(name.to_string(), v)]],
                    None => Vec::new(),
                };
            }
            (None, Some(name)) => {
                return match left.value(i, env, tl, memo) {
                    Some(v) => vec![vec![(name.to_string(), v)]],
                    None => Vec::new(),
                };
            }
            _ => {}
        }
    }
    let (Some(l), Some(r)) = (left.value(i, env, tl, memo), right.value(i, env, tl, memo)) else {
        return Vec::new();
    };
    if compare_values(op, &l, &r) {
        vec![Vec::new()]
    } else {
        Vec::new()
    }
}

/// Closed-window test `0 <= ts[i] - ts[j] <= w`. `w == i64::MAX` (unbounded)
/// always holds, since timestamps are nondecreasing so the difference is `>= 0`.
fn in_window(tl: &Timeline, i: usize, j: usize, w: i64) -> bool {
    let d = tl.ts[i].saturating_sub(tl.ts[j]);
    (0..=w).contains(&d)
}

/// The earliest timepoint index any output in `lo..=hi` could reach through a
/// window of `w` ticks: the smallest `s` with `ts[s] >= ts[lo] - w`. A temporal
/// operator evaluates its child from here **once**, covering the union of every
/// output timepoint's window, then rolls the child's relation up. `w ==
/// i64::MAX` reaches back to `0` (the whole retained timeline).
fn window_start(tl: &Timeline, lo: usize, w: i64) -> usize {
    let floor = tl.ts[lo].saturating_sub(w);
    tl.ts.partition_point(|&t| t < floor)
}

/// Assign memo ids to every `Operand::Agg` (pre-order) and record each
/// body's FREE ENV KEYS — a build-time over-approximation of the env
/// bindings the body can read. Env-reading
/// channels, enumerated BY EVALUATION SITE: `compatible` (Pred row keys:
/// Var names + Correlated request-keys), `Node::Tp`'s `env.get(var)`
/// (READS, not just binds), `resolve_term` (Var / ContextField /
/// ScopeField / Array), and `Operand::unbound_var` (a Compare Var).
fn index_agg_memos(node: &mut Node, memo: &mut AggMemo) {
    match node {
        Node::Compare { left, right, .. } => {
            index_agg_operand(left, memo);
            index_agg_operand(right, memo);
        }
        Node::Formerly { child, .. }
        | Node::Previous { child, .. }
        | Node::Not { child }
        | Node::Exists { child, .. } => index_agg_memos(child, memo),
        Node::Since { left, right, .. } | Node::And { left, right } | Node::Or { left, right } => {
            index_agg_memos(left, memo);
            index_agg_memos(right, memo);
        }
        Node::Pred { .. } | Node::Tp { .. } => {}
    }
}

fn index_agg_operand(op: &mut Operand, memo: &mut AggMemo) {
    if let Operand::Agg {
        for_vars,
        bound_var,
        body,
        memo_id,
        ..
    } = op
    {
        // Nested aggregates first: their ids exist before the outer's.
        index_agg_memos(body, memo);
        let mut keys = std::collections::BTreeSet::new();
        free_env_keys(body, &mut keys);
        // shed_for_binders sheds exactly the for_vars; bound_var
        // removal is safe only because bound_var ∈ for_vars.
        if let Some(b) = bound_var {
            debug_assert!(
                for_vars.iter().any(|v| v.name() == b),
                "sum bound_var must be a for binder"
            );
        }
        for v in for_vars.iter() {
            keys.remove(v.name());
        }
        *memo_id = memo.free_keys.len() as u32;
        memo.free_keys.push(keys.into_iter().collect());
        // Eligibility: opaque terms AND unbounded retention —
        // eviction rides pruning, so a body whose max_window is i64::MAX
        // would grow the memo forever. Such bodies run
        // unmemoized.
        memo.eligible
            .push(!body_has_opaque_terms(body) && body.max_window() != i64::MAX);
    }
}

/// Terms whose env behavior we refuse to reason about:
/// pre-substitution forms and nested Term-level aggregates. Bodies
/// containing them run UNMEMOIZED (today's path verbatim).
fn body_has_opaque_terms(node: &Node) -> bool {
    fn term_opaque(t: &Term) -> bool {
        match t {
            Term::ParamRef(_) | Term::BinderRef(_) | Term::Agg(_) => true,
            Term::Array(items) => items.iter().any(term_opaque),
            _ => false,
        }
    }
    fn operand_opaque(o: &Operand) -> bool {
        match o {
            Operand::Term(t) => term_opaque(t),
            Operand::Agg { body, .. } => body_has_opaque_terms(body),
        }
    }
    match node {
        Node::Compare { left, right, .. } => operand_opaque(left) || operand_opaque(right),
        Node::Formerly { child, .. }
        | Node::Previous { child, .. }
        | Node::Not { child }
        | Node::Exists { child, .. } => body_has_opaque_terms(child),
        Node::Since { left, right, .. } | Node::And { left, right } | Node::Or { left, right } => {
            body_has_opaque_terms(left) || body_has_opaque_terms(right)
        }
        Node::Pred { .. } | Node::Tp { .. } => false,
    }
}

fn free_env_keys(node: &Node, out: &mut std::collections::BTreeSet<String>) {
    match node {
        Node::Pred { args, .. } => {
            for a in args {
                match a {
                    ArgSpec::Var { name, .. } => {
                        out.insert(name.clone());
                    }
                    ArgSpec::Correlated { key, .. } => {
                        out.insert(key.clone());
                    }
                    ArgSpec::Literal { .. } | ArgSpec::Wildcard { .. } => {}
                }
            }
        }
        // Tp READS env.get(var) as a filter — include, never remove.
        Node::Tp { var } => {
            out.insert(var.clone());
        }
        Node::Exists { var, child } => {
            let mut inner = std::collections::BTreeSet::new();
            free_env_keys(child, &mut inner);
            inner.remove(var); // Exists shadows via env.remove
            out.extend(inner);
        }
        Node::Compare { left, right, .. } => {
            operand_env_keys(left, out);
            operand_env_keys(right, out);
        }
        Node::Formerly { child, .. } | Node::Previous { child, .. } | Node::Not { child } => {
            free_env_keys(child, out)
        }
        Node::Since { left, right, .. } | Node::And { left, right } | Node::Or { left, right } => {
            free_env_keys(left, out);
            free_env_keys(right, out);
        }
    }
}

fn operand_env_keys(op: &Operand, out: &mut std::collections::BTreeSet<String>) {
    match op {
        Operand::Term(t) => term_env_keys(t, out),
        Operand::Agg { for_vars, body, .. } => {
            let mut inner = std::collections::BTreeSet::new();
            free_env_keys(body, &mut inner);
            for v in for_vars.iter() {
                inner.remove(v.name());
            }
            out.extend(inner);
        }
    }
}

fn term_env_keys(t: &Term, out: &mut std::collections::BTreeSet<String>) {
    match t {
        Term::Var(n) => {
            out.insert(n.clone());
        }
        Term::ContextField(p) => {
            out.insert(context_key(p));
        }
        Term::ScopeField(p) => {
            out.insert(scope_key(p));
        }
        Term::Array(items) => {
            for it in items {
                term_env_keys(it, out);
            }
        }
        _ => {}
    }
}

/// Whether a matched predicate row is consistent with `env`: shared keys agree
/// (`dom_eq`). This is the join between a past event's bindings and the decision
/// request's seeded values — the correlation. The only absent columns that reach
/// the `None` arm are free variables, because the `Pred` arm of [`Node::rel`]
/// rejects a leaf whose correlated key is unseeded before it ever joins.
fn compatible(row: &Row, env: &Env) -> bool {
    row.iter().all(|(k, v)| match env.get(k) {
        Some(ev) => ev.dom_eq(v),
        None => true,
    })
}

/// Clone `env`, shedding each local `for` binder (alpha-equivalence).
fn shed_for_binders(env: &Env, for_vars: &[TypedBinder]) -> Env {
    let mut inner = env.clone();
    for v in for_vars {
        inner.remove(v.name());
    }
    inner
}

fn compare_values(op: CmpOp, l: &Value, r: &Value) -> bool {
    match op {
        CmpOp::Eq => l.dom_eq(r),
        CmpOp::NotEq => !l.dom_eq(r),
        CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => match (l.as_int(), r.as_int()) {
            (Some(a), Some(b)) => match op {
                CmpOp::Lt => a < b,
                CmpOp::Le => a <= b,
                CmpOp::Gt => a > b,
                CmpOp::Ge => a >= b,
                _ => unreachable!(),
            },
            _ => false,
        },
    }
}

/// Resolve a term under `env`. Context / scope terms read the seeded decision
/// keys (`context.<path>` / `@<path>`), exactly as `eval.rs::resolve_term`
/// reads `request_env`.
fn resolve_term(env: &Env, term: &Term) -> Option<Value> {
    match term {
        Term::Integer(n) => Some(Value::Int(*n)),
        Term::Decimal(s) => Some(Value::Decimal(s.clone())),
        Term::String(s) => Some(Value::String(s.clone())),
        Term::Bool(b) => Some(Value::Bool(*b)),
        Term::Entity { ty, id } => Some(Value::Entity {
            ty: ty.clone(),
            id: id.clone(),
        }),
        Term::Array(items) => {
            let vals: Option<Vec<Value>> = items.iter().map(|t| resolve_term(env, t)).collect();
            vals.map(Value::Array)
        }
        Term::Var(name) => env.get(name).cloned(),
        Term::ContextField(path) => env.get(&context_key(path)).cloned(),
        Term::ScopeField(path) => env.get(&scope_key(path)).cloned(),
        Term::Wildcard | Term::Agg(_) | Term::ParamRef(_) | Term::BinderRef(_) => None,
    }
}

/// The env key for a `context.*` term / correlated predicate arg.
fn context_key(path: &[String]) -> String {
    format!("context.{}", path.join("."))
}

/// The env key for a `principal`/`resource` scope term (`@`-headed, disjoint
/// from context keys — mirrors `eval.rs::scope_env_key`).
fn scope_key(path: &[String]) -> String {
    format!("@{}", path.join("."))
}

/// The env key for a decision term (a `context.*` / scope read).
fn req_key(term: &Term) -> Option<String> {
    match term {
        Term::ContextField(path) => Some(context_key(path)),
        Term::ScopeField(path) => Some(scope_key(path)),
        _ => None,
    }
}

/// Record a decision term (if a `context.*` / scope read) so `verdict` seeds it.
fn record_req_term(term: &Term, req: &mut BTreeMap<String, Term>) {
    if let Some(key) = req_key(term) {
        req.entry(key).or_insert_with(|| term.clone());
    }
}

/// Build a `Pred` node, classifying each arg and recording decision terms.
fn build_pred(p: &Predicate, req: &mut BTreeMap<String, Term>) -> Node {
    let mut args = Vec::with_capacity(p.args.len());
    for arg in &p.args {
        let field = arg.field_path();
        let spec = match &arg.value {
            Term::Wildcard => ArgSpec::Wildcard { field },
            Term::Var(name) => ArgSpec::Var {
                field,
                name: name.clone(),
            },
            Term::ContextField(_) | Term::ScopeField(_) => {
                record_req_term(&arg.value, req);
                ArgSpec::Correlated {
                    field,
                    key: req_key(&arg.value).expect("context/scope term"),
                }
            }
            other => match literal_value(other) {
                Some(value) => ArgSpec::Literal { field, value },
                None => ArgSpec::Wildcard { field },
            },
        };
        args.push(spec);
    }
    Node::Pred {
        namespace: p.namespace.clone(),
        action: p.action.clone(),
        kind: p.kind.clone(),
        args,
        history: LeafStore::new(),
    }
}

/// Match an event against a predicate's arg specs, returning the event-side
/// binding row (vars + correlated request-keys bound to event field values) or
/// `None`.
fn match_pred_event(
    event: &Event,
    namespace: &[String],
    action: &str,
    kind: &str,
    args: &[ArgSpec],
) -> Option<Row> {
    if event.action() != action || event.kind() != kind || event.namespace() != namespace {
        return None;
    }
    let mut row: Row = Vec::new();
    for spec in args {
        match spec {
            ArgSpec::Literal { field, value } => match event.field_path(field) {
                Some(v) if v.dom_eq(value) => {}
                _ => return None,
            },
            ArgSpec::Wildcard { field } => {
                event.field_path(field)?;
            }
            ArgSpec::Var { field, name } => {
                bind_or_check(&mut row, name, event.field_path(field)?.clone())?;
            }
            ArgSpec::Correlated { field, key } => {
                bind_or_check(&mut row, key, event.field_path(field)?.clone())?;
            }
        }
    }
    Some(row)
}

/// Bind `col` to `v`, or fail if already present with a different value.
fn bind_or_check(row: &mut Row, col: &str, v: Value) -> Option<()> {
    if let Some((_, prev)) = row.iter().find(|(k, _)| k == col) {
        if prev.dom_eq(&v) { Some(()) } else { None }
    } else {
        row.push((col.to_string(), v));
        Some(())
    }
}

/// Build a comparison node, turning each operand into an [`Operand`] (a plain
/// term or an aggregate over a body). Handles term-vs-term, agg-vs-term, and
/// agg-vs-agg uniformly.
fn build_compare(
    op: CmpOp,
    left: &Term,
    right: &Term,
    req: &mut BTreeMap<String, Term>,
    rate: TickRate,
) -> Option<Node> {
    record_req_term(left, req);
    record_req_term(right, req);
    Some(Node::Compare {
        op,
        left: build_operand(left, req, rate)?,
        right: build_operand(right, req, rate)?,
    })
}

/// Build a comparison operand from a term: an aggregate → [`Operand::Agg`]
/// (recursively building its body), else [`Operand::Term`].
fn build_operand(term: &Term, req: &mut BTreeMap<String, Term>, rate: TickRate) -> Option<Operand> {
    match term {
        Term::Agg(agg) => {
            let (kind, for_vars, bound_var, body_cond) = match &agg.kind {
                AggExprKind::Count { for_vars, body } => {
                    (AggKind::Count, for_vars.clone(), None, body.as_ref())
                }
                AggExprKind::Sum {
                    bound_var,
                    for_vars,
                    body,
                } => (
                    AggKind::Sum,
                    for_vars.clone(),
                    Some(bound_var.name().to_string()),
                    body.as_ref(),
                ),
                AggExprKind::Call(_) => return None,
            };
            Some(Operand::Agg {
                kind,
                for_vars,
                bound_var,
                body: Box::new(Node::build(body_cond, req, rate)?),
                memo_id: 0,
            })
        }
        _ => Some(Operand::Term(term.clone())),
    }
}

/// Resolve a decision-request term against the decision event.
fn resolve_decision_term(event: &Event, term: &Term) -> Option<Value> {
    match term {
        Term::ContextField(path) => event.request_context_path(path).cloned(),
        Term::ScopeField(path) => {
            let root = path.first()?;
            if root != "principal" && root != "resource" {
                return None;
            }
            event.scope_attr(root, &path[1..])
        }
        _ => None,
    }
}

/// A node's window in the engine's tick unit. This is the ONE place a declared
/// window (seconds) crosses into the timestamp domain, so it is the only place
/// the conversion belongs — every `Node` therefore stores its window already in
/// ticks, ready to compare against a `ts` difference.
fn interval_ticks(within: &WithinSpec, rate: TickRate) -> i64 {
    rate.ticks_from_seconds(within.interval().seconds())
}

fn literal_value(term: &Term) -> Option<Value> {
    Some(match term {
        Term::Integer(n) => Value::Int(*n),
        Term::Decimal(s) => Value::Decimal(s.clone()),
        Term::String(s) => Value::String(s.clone()),
        Term::Bool(b) => Value::Bool(*b),
        Term::Entity { ty, id } => Value::Entity {
            ty: ty.clone(),
            id: id.clone(),
        },
        Term::Array(items) => {
            let vals: Option<Vec<Value>> = items.iter().map(literal_value).collect();
            Value::Array(vals?)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod load_atomicity_tests {
    use std::collections::VecDeque;
    use std::mem::size_of;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use dogwood_language::Value;

    use super::{AggMemo, ArgSpec, Monitor, Node, Timeline};
    use crate::rel::{LeafHistory, LeafStore};
    use crate::snapshot::{put_i64, put_u64};

    fn predicate(action: &str, value: i64, len: usize) -> Node {
        let mut history = LeafStore::new();
        for _ in 0..len {
            history.push(Some(vec![("value".to_string(), Value::Int(value))]));
        }
        Node::Pred {
            namespace: vec!["Test".to_string()],
            action: action.to_string(),
            kind: "request".to_string(),
            args: Vec::<ArgSpec>::new(),
            history,
        }
    }

    fn monitor(first: i64, second: i64) -> Monitor {
        monitor_with_timeline(&[10], &[0], 1, first, second)
    }

    fn monitor_with_timeline(
        timestamps: &[i64],
        timepoint_ids: &[i64],
        next_tp: i64,
        first: i64,
        second: i64,
    ) -> Monitor {
        assert_eq!(timestamps.len(), timepoint_ids.len());
        Monitor {
            root: Node::And {
                left: Box::new(predicate("First", first, timestamps.len())),
                right: Box::new(predicate("Second", second, timestamps.len())),
            },
            timeline: Timeline {
                ts: VecDeque::from(timestamps.to_vec()),
                tp_id: VecDeque::from(timepoint_ids.to_vec()),
            },
            max_window: i64::MAX,
            next_tp,
            req_terms: Vec::new(),
            memo: AggMemo::new(),
        }
    }

    fn encoded_monitor(timeline_len: usize) -> Vec<u8> {
        let mut encoded = Vec::new();
        put_u64(&mut encoded, timeline_len as u64);
        for index in 0..timeline_len {
            put_i64(&mut encoded, i64::MIN.saturating_add(index as i64));
        }
        for index in 0..timeline_len {
            put_i64(&mut encoded, index as i64);
        }
        put_i64(&mut encoded, timeline_len as i64);
        for _ in 0..2 {
            put_u64(&mut encoded, timeline_len as u64);
            encoded.extend(std::iter::repeat(0).take(timeline_len));
        }
        encoded
    }

    fn assert_rejected_without_panic_or_mutation(encoded: &[u8], case: &str) {
        let mut destination = monitor(30, 40);
        let original_bytes = destination.save();

        let attempt = catch_unwind(AssertUnwindSafe(|| destination.load(encoded)));
        assert!(attempt.is_ok(), "{case} panicked");
        assert!(!attempt.unwrap(), "{case} decoded");
        assert_eq!(
            destination.save(),
            original_bytes,
            "{case} changed monitor state"
        );
    }

    #[test]
    fn timeline_sizes_round_trip_across_allocation_boundaries() {
        for size in [
            0usize, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511,
            512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097,
        ] {
            let encoded = encoded_monitor(size);
            let mut destination = monitor(30, 40);
            assert!(destination.load(&encoded), "timeline size {size} refused");
            assert_eq!(destination.timeline.ts.len(), size);
            assert_eq!(destination.timeline.tp_id.len(), size);
            assert_eq!(destination.next_tp, size as i64);
            assert_eq!(
                destination.save(),
                encoded,
                "timeline size {size} changed after restoration"
            );
        }
    }

    #[test]
    fn every_truncated_load_leaves_the_monitor_unchanged() {
        let encoded = monitor(10, 20).save();
        let original = monitor(30, 40);
        let original_bytes = original.save();

        for end in 0..encoded.len() {
            let mut destination = original.clone();
            assert!(
                !destination.load(&encoded[..end]),
                "strict prefix ending at {end} unexpectedly decoded"
            );
            assert_eq!(
                destination.save(),
                original_bytes,
                "failed prefix ending at {end} changed monitor state"
            );
        }
    }

    #[test]
    fn trailing_bytes_leave_the_monitor_unchanged() {
        let mut encoded = monitor(10, 20).save();
        encoded.push(0xff);
        let mut destination = monitor(30, 40);
        let original_bytes = destination.save();

        assert!(!destination.load(&encoded));
        assert_eq!(destination.save(), original_bytes);
    }

    #[test]
    fn mismatched_history_lengths_leave_the_monitor_unchanged() {
        let mut encoded = Vec::new();
        put_u64(&mut encoded, 1); // one retained timeline timepoint
        put_i64(&mut encoded, 10);
        put_i64(&mut encoded, 0);
        put_i64(&mut encoded, 1);
        put_u64(&mut encoded, 0); // first predicate has no retained slots
        put_u64(&mut encoded, 0); // second predicate has no retained slots

        let mut destination = monitor(30, 40);
        let original_bytes = destination.save();

        assert!(!destination.load(&encoded));
        assert_eq!(destination.save(), original_bytes);
    }

    #[test]
    fn unordered_timestamps_leave_the_monitor_unchanged() {
        let encoded = monitor_with_timeline(&[20, 10], &[0, 1], 2, 10, 20).save();
        let mut destination = monitor(30, 40);
        let original_bytes = destination.save();

        assert!(!destination.load(&encoded));
        assert_eq!(destination.save(), original_bytes);
    }

    #[test]
    fn duplicate_timepoint_ids_leave_the_monitor_unchanged() {
        let encoded = monitor_with_timeline(&[10, 20], &[0, 0], 1, 10, 20).save();
        let mut destination = monitor(30, 40);
        let original_bytes = destination.save();

        assert!(!destination.load(&encoded));
        assert_eq!(destination.save(), original_bytes);
    }

    #[test]
    fn negative_timepoint_ids_leave_the_monitor_unchanged() {
        let encoded = monitor_with_timeline(&[10, 20], &[-2, -1], 0, 10, 20).save();
        let mut destination = monitor(30, 40);
        let original_bytes = destination.save();

        assert!(!destination.load(&encoded));
        assert_eq!(destination.save(), original_bytes);
    }

    #[test]
    fn inconsistent_next_timepoint_leaves_the_monitor_unchanged() {
        let encoded = monitor_with_timeline(&[10, 20], &[0, 1], 1, 10, 20).save();
        let mut destination = monitor(30, 40);
        let original_bytes = destination.save();

        assert!(!destination.load(&encoded));
        assert_eq!(destination.save(), original_bytes);
    }

    #[test]
    fn empty_and_extreme_ordered_timelines_round_trip() {
        for source in [
            monitor_with_timeline(&[], &[], 0, 10, 20),
            monitor_with_timeline(&[i64::MIN, i64::MAX], &[0, 1], 2, 10, 20),
        ] {
            let encoded = source.save();
            let expected_last = source.last_event_ts();
            let mut destination = monitor(30, 40);

            assert!(destination.load(&encoded));
            assert_eq!(destination.last_event_ts(), expected_last);
            assert_eq!(destination.save(), encoded);
        }
    }

    #[test]
    fn impossible_timeline_length_rejects_without_panicking_or_mutating() {
        let mut encoded = Vec::new();
        put_u64(&mut encoded, u64::MAX);
        assert_rejected_without_panic_or_mutation(&encoded, "impossible timeline length");
    }

    #[test]
    fn timeline_count_size_overflow_rejects_without_panicking_or_mutating() {
        let count = usize::MAX / size_of::<u64>() + 1;
        let mut encoded = Vec::new();
        put_u64(&mut encoded, count as u64);
        assert_rejected_without_panic_or_mutation(&encoded, "overflowing timeline byte size");
    }

    #[test]
    fn large_but_nonoverflowing_timeline_count_rejects_before_allocation() {
        let mut encoded = Vec::new();
        put_u64(&mut encoded, 1_000_000);
        assert_rejected_without_panic_or_mutation(
            &encoded,
            "large timeline count without backing bytes",
        );
    }

    #[test]
    fn truncated_timeline_fields_reject_without_panicking_or_mutating() {
        const COUNT: usize = 3;
        let full = encoded_monitor(COUNT);
        let count_end = size_of::<u64>();
        let timestamps_end = count_end + COUNT * size_of::<u64>();
        let ids_end = timestamps_end + COUNT * size_of::<u64>();
        let next_tp_end = ids_end + size_of::<u64>();

        for (field, start, end) in [
            ("timestamps", count_end, timestamps_end),
            ("timepoint IDs", timestamps_end, ids_end),
            ("next timepoint", ids_end, next_tp_end),
        ] {
            for truncated_at in start..end {
                assert_rejected_without_panic_or_mutation(
                    &full[..truncated_at],
                    &format!("{field} truncated at byte {truncated_at}"),
                );
            }
        }
    }
}

#[cfg(test)]
mod agg_memo_key_tests {
    //! DomEqKey unit pins: decimal
    //! SPELLINGS must collide (dom_eq compares numerically), which the
    //! integration schema (Long fields) cannot reach.

    use super::DomEqKey;
    use dogwood_language::Value;

    fn h(k: &DomEqKey) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn decimal_spellings_collide() {
        let a = DomEqKey(vec![Some(Value::Decimal("2.5".into()))]);
        let b = DomEqKey(vec![Some(Value::Decimal("02.50".into()))]);
        assert_eq!(h(&a), h(&b), "decimal spellings must share a bucket");
        assert_eq!(a, b, "dom_eq treats 2.5 == 02.50");
        let c = DomEqKey(vec![Some(Value::Decimal("2.51".into()))]);
        assert_ne!(a, c, "different decimals stay distinct");
        assert_eq!(h(&a), h(&c), "all decimals share one hash bucket by design");
    }

    #[test]
    fn none_some_distinct() {
        let none = DomEqKey(vec![None]);
        let some = DomEqKey(vec![Some(Value::Int(0))]);
        assert_ne!(none, some);
        assert_ne!(h(&none), h(&some));
        assert_eq!(DomEqKey(vec![None]), DomEqKey(vec![None]));
    }

    #[test]
    fn arrays_hash_domwise() {
        let a = DomEqKey(vec![Some(Value::Array(vec![
            Value::Decimal("1.0".into()),
            Value::Int(2),
        ]))]);
        let b = DomEqKey(vec![Some(Value::Array(vec![
            Value::Decimal("01.00".into()),
            Value::Int(2),
        ]))]);
        assert_eq!(h(&a), h(&b));
        assert_eq!(a, b, "nested decimal spellings collide inside arrays");
    }

    #[test]
    fn length_mismatch_unequal() {
        let a = DomEqKey(vec![Some(Value::Int(1))]);
        let b = DomEqKey(vec![Some(Value::Int(1)), None]);
        assert_ne!(a, b);
    }
}
