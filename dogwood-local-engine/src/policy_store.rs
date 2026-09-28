//! Structured per-policy storage and the transactional verb-batch fold.
//!
//! This is the *pure data model* for the policy set: it owns an ordered list of
//! installed policies — each a stable, engine-minted [`PolicyId`] plus its
//! canonical statement — and folds a batch of [`Verb`]s into a new set,
//! reporting per-policy **retention** (which policies must start fresh vs. keep
//! their accumulated window) so the durable/engine layer can carry or reset
//! monitor state by `(id, clause index)` rather than by content.
//!
//! Durability, recovery, lowering, and the running authorizer live elsewhere.
//! Canonicalizing a policy's source (parse → macro-expand → render back to a
//! canonical statement via `expanded_source`) is *injected* as a closure, so
//! this module stays pure, engine-free, and unit-testable — the closure is
//! where the real pipeline (and its rejection of an invalid policy) plugs in.

use std::collections::{BTreeMap, BTreeSet};

const POLICY_ORDINAL_EXHAUSTED: &str = "policy ordinal space exhausted";

fn ensure_ordinal_capacity(next_id: u64, statement_count: usize) -> Result<(), &'static str> {
    let statement_count = u64::try_from(statement_count).map_err(|_| POLICY_ORDINAL_EXHAUSTED)?;
    next_id
        .checked_add(statement_count)
        .map(|_| ())
        .ok_or(POLICY_ORDINAL_EXHAUSTED)
}

/// The **internal ordinal**: a monotonic, never-reused sequence number the engine
/// assigns each policy in creation order. It is the *ordering* and *transplant*
/// key — the composite `(id, clause-index)` retention key rests on it, and
/// it is unique **by construction** (the cursor only advances, even across
/// delete/`DeleteAll`), so a new policy can never inherit a deleted one's monitor
/// window. It is **not** the caller-facing handle (that is [`PolicyToken`]); it
/// never leaves the engine except inside durable records.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct PolicyId(pub u64);

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy-{}", self.0)
    }
}

/// The **external handle**: an opaque, non-sequential token the engine mints on
/// `Add` (`SP` + base62 of 128 random bits)
/// and durably records so recovery re-uses it and never re-mints. This is what
/// callers see in `minted`/`list`/`get` and name in `Update`/`Delete`/`Reset`.
///
/// It is deliberately unpredictable so callers cannot couple to the internal
/// ordinal's sequence or order (order is conveyed by `created`). Correctness
/// never depends on it being collision-free: monitor state is keyed on the
/// [`PolicyId`] ordinal, so even a token collision cannot carry the wrong history.
/// Uniqueness among *live* policies is enforced at mint (regenerate on the
/// essentially-never clash); cross-lifetime uniqueness is entropy-bounded.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct PolicyToken(pub String);

impl std::fmt::Display for PolicyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One installed policy: its opaque external handle ([`token`](Self::token)), its
/// internal ordinal ([`id`](Self::id) — ordering + transplant key), its
/// **canonical** statement (the rendered source, so a semantics-preserving
/// reformat does not churn it), and the store-assigned create/update timestamps.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEntry {
    /// Internal ordinal — the ordering and transplant key. Not the caller handle.
    pub id: PolicyId,
    /// The opaque, caller-facing handle.
    pub token: PolicyToken,
    pub statement: String,
    pub created: i64,
    pub updated: i64,
}

/// A policy-changing verb. The `Add` here is the **control-plane** form
/// with no id — the engine mints one during the fold. Read operations (`list`,
/// `get_policy`, `action_schema`) are not here: they take no durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    /// Install policy from a source — one new entry (minted id, born with no
    /// history) **per policy** in the source. A single-policy source adds one; a
    /// multi-policy source *slices* into one entry each (a bulk add). An empty
    /// source is rejected. To add several policies as a coordinated unit, either
    /// pass them in one `Add` or use several `Add` verbs in one batch — both are
    /// atomic.
    Add { policy: String },
    /// Replace **one** policy's content by its handle — resets it (born again),
    /// same handle. The source must be exactly one policy: `Update` targets a
    /// single policy, so a multi-policy source is rejected.
    Update { id: PolicyToken, policy: String },
    /// Remove a policy by its handle.
    Delete { id: PolicyToken },
    /// Clear one policy's accumulated history by its handle; content unchanged.
    Reset { id: PolicyToken },
    /// Remove every policy; the schema is kept and the empty set stays
    /// installed (decisions then fail closed).
    DeleteAll,
    /// Clear every policy's history; all policies kept (re-born now).
    ResetAll,
    /// Revalidate + re-lower the whole set under a new action schema.
    SetActionSchema { action_schema: String },
    /// **Append** declarations to the current action schema, in one atomic batch.
    /// The fragment is concatenated onto the schema in force, so a caller
    /// can add a new entity/action without a read-modify-write round trip that a
    /// concurrent change could invalidate. Strictly additive — like an additive
    /// `SetActionSchema`, every window carries — and a fragment that redeclares an
    /// existing entity/action fails validation, rejecting the whole batch.
    AppendActionSchema { fragment: String },
}

/// Concatenate a fragment onto an action schema — the single rule both the live
/// fold and recovery replay use for [`Verb::AppendActionSchema`], so a batch and
/// its post-restart rebuild produce the identical merged schema. A newline joins
/// them (the human-readable Cedar schema is a sequence of declarations); an empty
/// base yields the fragment alone.
pub(crate) fn append_action_schema(base: &str, fragment: &str) -> String {
    let base = base.trim_end();
    if base.is_empty() {
        fragment.to_string()
    } else {
        format!("{base}\n{fragment}")
    }
}

/// Why a batch was rejected. A batch is all-or-nothing: on any error the
/// current set is left untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    /// `Update`/`Delete`/`Reset` named a handle not in the set.
    UnknownPolicy(PolicyToken),
    /// Canonicalizing (parse/lower) an `Add`/`Update` policy failed; the
    /// message is the pipeline's diagnostic. Also used for a `SetActionSchema`
    /// that fails to revalidate the retained set.
    Rejected(String),
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchError::UnknownPolicy(id) => write!(f, "no such policy: {id}"),
            BatchError::Rejected(m) => write!(f, "rejected: {m}"),
        }
    }
}

/// One folded verb's durable effect, minus the timestamp (the engine stamps every
/// record in a batch with the batch's single instant). The fold emits these
/// so the engine builds records without re-canonicalizing or re-minting — which
/// also matters because the minted [`PolicyToken`] is random and cannot be
/// reproduced by a second pass. Carries the resolved ordinal (`id`) so replay
/// keys on it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldedRecord {
    Add {
        id: PolicyId,
        token: PolicyToken,
        statement: String,
    },
    Update {
        id: PolicyId,
        statement: String,
    },
    Delete {
        id: PolicyId,
    },
    Reset {
        id: PolicyId,
    },
    DeleteAll,
    ResetAll,
    SetActionSchema {
        action_schema: String,
    },
    AppendActionSchema {
        fragment: String,
    },
}

/// The result of folding one batch: the new set, the ids minted (for the
/// caller's `BatchResult` and for the durable `Add` records), which policies
/// must start **fresh** (born now — their window does not carry), and the new
/// action schema if the batch set one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldOutcome {
    pub set: PolicySet,
    /// The **handles** minted, in order. Each `Add` verb contributes one token
    /// **per policy in its source** — an `Add` *slices* a multi-policy source into
    /// one entry per policy (a bulk add), so a single `Add` can mint several. They
    /// appear here in add-then-source order (this is the caller's `BatchResult`).
    pub minted: Vec<PolicyToken>,
    /// The ordered durable effects, so the engine can build records without a
    /// second canonicalization pass (and without re-minting the random tokens).
    pub records: Vec<FoldedRecord>,
    /// Ordinals whose state must start empty this batch (`Add`/`Update`/`Reset`,
    /// or all of them under `ResetAll`). A resulting policy **not** in this set
    /// keeps its window: the transplant layer carries it by `(id, clause index)`.
    pub fresh: BTreeSet<PolicyId>,
    pub action_schema: Option<String>,
}

/// The set of installed policies, keyed by stable id, plus the id-minting
/// cursor.
///
/// Iterated in **ascending-id order** — a deterministic order. Cedar's decision
/// is order-independent, but the engine lowers the set's combined source and
/// restores monitor state *positionally* (the k-th leaf into the k-th leaf), so
/// the lowered leaf order must be reproducible from the stored set; a
/// non-deterministic map iteration (e.g. `HashMap`) would make recovery load
/// windows into the wrong leaves. `next_id` is monotone and persisted so
/// recovery continues minting where it left off.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "PolicySetWire", try_from = "PolicySetWire")]
pub struct PolicySet {
    entries: BTreeMap<PolicyId, PolicyEntry>,
    next_id: u64,
}

/// Serialized form: a flat, id-ordered list (each entry already carries its id)
/// plus the mint cursor. Keeps the on-disk JSON a clean array of entries rather
/// than a map with numeric keys, and rebuilds the `BTreeMap` on load.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySetWire {
    entries: Vec<PolicyEntry>,
    next_id: u64,
}

fn encode_policy_set_wire(s: PolicySet) -> PolicySetWire {
    PolicySetWire {
        entries: s.entries.into_values().collect(),
        next_id: s.next_id,
    }
}

fn validate_policy_set_wire(wire: PolicySetWire) -> Result<PolicySet, String> {
    let next_id = wire.next_id;
    let mut entries = BTreeMap::new();
    let mut tokens = BTreeSet::new();
    for entry in wire.entries {
        if entry.id.0 >= next_id {
            return Err(format!(
                "policy id {} is not below next_id {}",
                entry.id.0, next_id
            ));
        }
        if entry.created > entry.updated {
            return Err(format!(
                "policy {} has created timestamp after updated timestamp",
                entry.id.0
            ));
        }
        let token = entry.token.clone();
        let inserted = tokens.insert(token);
        if !inserted {
            return Err("duplicate live policy token".to_string());
        }
        let id = entry.id;
        let previous = entries.insert(id, entry);
        if previous.is_some() {
            return Err(format!("duplicate policy id {}", id.0));
        }
    }
    Ok(PolicySet { entries, next_id })
}

#[inline]
fn decode_policy_set_wire(wire: PolicySetWire) -> Result<PolicySet, String> {
    validate_policy_set_wire(wire)
}

impl From<PolicySet> for PolicySetWire {
    fn from(s: PolicySet) -> Self {
        encode_policy_set_wire(s)
    }
}

impl TryFrom<PolicySetWire> for PolicySet {
    type Error = String;

    fn try_from(wire: PolicySetWire) -> Result<Self, Self::Error> {
        decode_policy_set_wire(wire)
    }
}

impl PolicySet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Policies in ascending-id order (deterministic — `entries` is a `BTreeMap`).
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &PolicyEntry> + '_ {
        self.entries.values()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// One policy's entry by its internal ordinal, or `None` if absent.
    pub fn get(&self, id: PolicyId) -> Option<&PolicyEntry> {
        self.entries.get(&id)
    }

    /// One policy's entry by its caller-facing handle, or
    /// `None`. A linear scan — the set is small, and the token is not the map key
    /// (the ordinal is, so iteration stays creation-ordered).
    pub fn get_by_token(&self, token: &PolicyToken) -> Option<&PolicyEntry> {
        self.entries.values().find(|e| &e.token == token)
    }

    /// Whether any live policy already holds this handle — the mint-time
    /// uniqueness check that keeps handles unambiguous among installed policies.
    pub fn contains_token(&self, token: &PolicyToken) -> bool {
        self.entries.values().any(|e| &e.token == token)
    }

    /// The next ordinal this set will mint. Persisted so recovery never re-mints
    /// an ordinal a durable `Add` already assigned.
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    /// Rebuild a set from durably-recorded entries and the recorded id cursor
    /// (recovery). Never re-mints; the cursor is taken as given.
    pub fn from_recorded(entries: Vec<PolicyEntry>, next_id: u64) -> Self {
        Self {
            entries: entries.into_iter().map(|e| (e.id, e)).collect(),
            next_id,
        }
    }

    /// Build a fresh set from canonical statements with **placeholder** handles,
    /// minting ordinals from 0. For building a *reference-only* carrier (tests,
    /// oracle) that never enters the engine — the handles are deterministic
    /// stand-ins, not the opaque tokens a real install mints. The engine's own
    /// install path uses [`from_statements_after`](Self::from_statements_after)
    /// with a real token generator.
    pub fn from_statements<I: IntoIterator<Item = String>>(statements: I, now: i64) -> Self {
        let mut n: u64 = 0;
        Self::from_statements_after(statements, now, 0, || {
            let t = PolicyToken(format!("SPref{n}"));
            n += 1;
            t
        })
        .expect("a fresh in-memory reference set cannot exhaust u64 ordinals")
    }

    /// Like [`from_statements`](Self::from_statements), but the ordinal cursor
    /// **continues from `next_id`** rather than restarting at 0, and each entry's
    /// opaque handle comes from `mint_token`. A declarative re-install
    /// (`[DeleteAll; Add each]`) wipes the set but keeps the monotone
    /// cursor, so an ordinal a caller's handle maps to is never silently reused.
    /// Handles are kept unique within the set (regenerating on a clash).
    /// Returns an error before calling `mint_token` if the complete replacement
    /// would exhaust the remaining ordinal space.
    pub fn from_statements_after<I: IntoIterator<Item = String>>(
        statements: I,
        now: i64,
        next_id: u64,
        mut mint_token: impl FnMut() -> PolicyToken,
    ) -> Result<Self, String> {
        let statements: Vec<String> = statements.into_iter().collect();
        ensure_ordinal_capacity(next_id, statements.len()).map_err(str::to_string)?;

        let mut set = Self {
            entries: BTreeMap::new(),
            next_id,
        };
        for statement in statements {
            let id = set.mint();
            let token = set.unique_token(&mut mint_token);
            set.entries.insert(
                id,
                PolicyEntry {
                    id,
                    token,
                    statement,
                    created: now,
                    updated: now,
                },
            );
        }
        Ok(set)
    }

    /// Draw handles from `mint_token` until one is unused by any live policy. The
    /// generator is random, so the loop is a formality — but it makes live-handle
    /// uniqueness a guarantee rather than a probability.
    fn unique_token(&self, mint_token: &mut impl FnMut() -> PolicyToken) -> PolicyToken {
        loop {
            let candidate = mint_token();
            if !self.contains_token(&candidate) {
                return candidate;
            }
        }
    }

    /// Every installed policy's id, ascending. For `ResetAll`, which marks the
    /// whole set fresh.
    pub fn ids(&self) -> impl ExactSizeIterator<Item = PolicyId> + '_ {
        self.entries.keys().copied()
    }

    /// Whether a policy with `id` is installed.
    pub fn contains(&self, id: PolicyId) -> bool {
        self.entries.contains_key(&id)
    }

    // ─── Replay-fold: applying durable verb records with explicit ids ────
    //
    // Recovery folds the log's per-verb records (`Record::Add`/`Update`/…)
    // forward one at a time. Unlike the live [`fold`], these carry ids the engine
    // already minted, so replay must re-use them and never re-mint. The
    // set mutations below take an explicit id and keep `next_id` monotone so a
    // later live `Add` cannot collide with a replayed one.

    /// Insert a policy under the ordinal and handle a durable `Add` record
    /// already minted, advancing the ordinal cursor past it. Born at `now`
    /// (created == updated). Both the ordinal and the opaque handle come from the
    /// record, so replay reproduces them exactly and never re-mints.
    pub fn insert_recorded(
        &mut self,
        id: PolicyId,
        token: PolicyToken,
        statement: String,
        now: i64,
    ) {
        let entry = PolicyEntry {
            id,
            token,
            statement,
            created: now,
            updated: now,
        };
        self.entries.insert(id, entry);
        self.next_id = self.next_id.max(id.0.saturating_add(1));
    }

    /// Replace a policy's content by id (a durable `Update`), keeping `created`
    /// and stamping `updated`. Returns whether the policy existed.
    pub fn update_statement(&mut self, id: PolicyId, statement: String, updated: i64) -> bool {
        match self.entries.get_mut(&id) {
            Some(entry) => {
                entry.statement = statement;
                entry.updated = updated;
                true
            }
            None => false,
        }
    }

    /// Remove a policy by id (a durable `Delete`). Returns whether it existed.
    pub fn remove(&mut self, id: PolicyId) -> bool {
        self.entries.remove(&id).is_some()
    }

    /// Remove every policy (a durable `DeleteAll`), keeping the mint cursor —
    /// so a subsequent `Add` never re-uses a wiped policy's id.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Fold a batch onto a **working copy** of this set, verb by verb in listed
    /// order (each verb sees the effect of the ones before it), and either
    /// return the committed [`FoldOutcome`] or reject the whole batch leaving
    /// `self` conceptually untouched. `self` is not mutated; the caller
    /// swaps in `outcome.set` only on success.
    ///
    /// `canon(source) -> Result<statements, msg>` canonicalizes a source into its
    /// constituent policies (the `expanded_source` pipeline, one string per
    /// policy) and rejects an invalid or empty one. `Add` installs all of them
    /// (slicing a multi-policy source); `Update` requires exactly one. `now`
    /// stamps created/updated. `mint_token` supplies each `Add`ed policy's opaque
    /// handle (kept unique among live policies). Per-policy verbs (`Update`,
    /// `Delete`, `Reset`) address a policy by its handle, which the fold resolves
    /// to its ordinal against the working set.
    ///
    /// Also returns the ordered [`FoldedRecord`]s so the caller commits them
    /// verbatim — no second canonicalization, and the random `Add` tokens (which
    /// a re-derivation could not reproduce) flow straight through.
    pub fn fold(
        &self,
        verbs: &[Verb],
        now: i64,
        current_action_schema: &str,
        canon: impl Fn(&str) -> Result<Vec<String>, String>,
        mut mint_token: impl FnMut() -> PolicyToken,
    ) -> Result<FoldOutcome, BatchError> {
        let mut set = self.clone();
        let mut minted = Vec::new();
        let mut records = Vec::new();
        let mut fresh = BTreeSet::new();
        let mut action_schema = None;

        for verb in verbs {
            match verb {
                Verb::Add { policy } => {
                    // Slice: one new entry per policy in the source.
                    let statements = canon(policy).map_err(BatchError::Rejected)?;
                    if statements.is_empty() {
                        return Err(BatchError::Rejected(
                            "source contains no policy".to_string(),
                        ));
                    }
                    ensure_ordinal_capacity(set.next_id, statements.len())
                        .map_err(|message| BatchError::Rejected(message.to_string()))?;
                    for statement in statements {
                        let id = set.mint();
                        let token = set.unique_token(&mut mint_token);
                        set.entries.insert(
                            id,
                            PolicyEntry {
                                id,
                                token: token.clone(),
                                statement: statement.clone(),
                                created: now,
                                updated: now,
                            },
                        );
                        minted.push(token.clone());
                        fresh.insert(id);
                        records.push(FoldedRecord::Add {
                            id,
                            token,
                            statement,
                        });
                    }
                }
                Verb::Update { id: token, policy } => {
                    let mut statements = canon(policy).map_err(BatchError::Rejected)?;
                    // Update addresses a single policy, so its source must be
                    // exactly one — slicing would have nowhere to put the extras.
                    if statements.len() != 1 {
                        return Err(BatchError::Rejected(format!(
                            "update expects exactly one policy, got {}",
                            statements.len()
                        )));
                    }
                    let statement = statements.pop().expect("checked len == 1");
                    let id = set
                        .resolve(token)
                        .ok_or_else(|| BatchError::UnknownPolicy(token.clone()))?;
                    let entry = set.entries.get_mut(&id).expect("resolved to a live id");
                    entry.statement = statement.clone();
                    entry.updated = now;
                    fresh.insert(id); // "update means reset"
                    records.push(FoldedRecord::Update { id, statement });
                }
                Verb::Delete { id: token } => {
                    let id = set
                        .resolve(token)
                        .ok_or_else(|| BatchError::UnknownPolicy(token.clone()))?;
                    set.entries.remove(&id);
                    // A deleted policy carries no state forward; if it was made
                    // fresh earlier in this same batch, drop that (it's gone).
                    fresh.remove(&id);
                    records.push(FoldedRecord::Delete { id });
                }
                Verb::Reset { id: token } => {
                    // Content unchanged; just resolve it and mark fresh.
                    let id = set
                        .resolve(token)
                        .ok_or_else(|| BatchError::UnknownPolicy(token.clone()))?;
                    fresh.insert(id);
                    records.push(FoldedRecord::Reset { id });
                }
                Verb::DeleteAll => {
                    set.entries.clear();
                    fresh.clear(); // nothing left to carry or reset
                    records.push(FoldedRecord::DeleteAll);
                }
                Verb::ResetAll => {
                    for id in set.entries.keys() {
                        fresh.insert(*id);
                    }
                    records.push(FoldedRecord::ResetAll);
                }
                Verb::SetActionSchema { action_schema: s } => {
                    // The schema is a bundle-level concern. Revalidation
                    // / re-lowering of the retained set under it is the engine
                    // layer's job; here we record the requested schema (last wins).
                    action_schema = Some(s.clone());
                    records.push(FoldedRecord::SetActionSchema {
                        action_schema: s.clone(),
                    });
                }
                Verb::AppendActionSchema { fragment } => {
                    // Concatenate onto the schema in force so far — an earlier
                    // Set/Append in this same batch, else the current one. Sequential
                    // so `[Append A; Set B; Append C]` yields `B + C`.
                    let base = action_schema.as_deref().unwrap_or(current_action_schema);
                    action_schema = Some(append_action_schema(base, fragment));
                    records.push(FoldedRecord::AppendActionSchema {
                        fragment: fragment.clone(),
                    });
                }
            }
        }

        Ok(FoldOutcome {
            set,
            minted,
            records,
            fresh,
            action_schema,
        })
    }

    /// Resolve a caller handle to its internal ordinal against the current set.
    fn resolve(&self, token: &PolicyToken) -> Option<PolicyId> {
        self.entries
            .values()
            .find(|e| &e.token == token)
            .map(|e| e.id)
    }

    fn mint(&mut self) -> PolicyId {
        let id = PolicyId(self.next_id);
        self.next_id = self.next_id.checked_add(1).expect(POLICY_ORDINAL_EXHAUSTED);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonicalizer that trims and splits on `;` — enough to test the fold's
    /// set logic (including `Add` slicing) without the language pipeline (which
    /// is exercised at the engine layer). Each non-empty `;`-separated piece is
    /// one "policy"; an all-empty source is rejected.
    fn trim_canon(s: &str) -> Result<Vec<String>, String> {
        let parts: Vec<String> = s
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        if parts.is_empty() {
            return Err("empty policy".into());
        }
        Ok(parts)
    }

    fn ids(set: &PolicySet) -> Vec<u64> {
        set.entries().map(|e| e.id.0).collect()
    }

    fn wire_entry(id: u64, token: &str, created: i64, updated: i64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "token": token,
            "statement": "opaque policy text",
            "created": created,
            "updated": updated,
        })
    }

    #[test]
    fn persisted_policy_set_serialization_keeps_the_exact_wire_shape() {
        let set = PolicySet::from_recorded(
            vec![
                PolicyEntry {
                    id: PolicyId(7),
                    token: PolicyToken("SPseven".into()),
                    statement: "seven".into(),
                    created: 17,
                    updated: 19,
                },
                PolicyEntry {
                    id: PolicyId(1),
                    token: PolicyToken("SPone".into()),
                    statement: "one".into(),
                    created: -2,
                    updated: -1,
                },
            ],
            20,
        );

        assert_eq!(
            serde_json::to_string(&set).expect("policy set serializes"),
            r#"{"entries":[{"id":1,"token":"SPone","statement":"one","created":-2,"updated":-1},{"id":7,"token":"SPseven","statement":"seven","created":17,"updated":19}],"next_id":20}"#
        );
    }

    #[test]
    fn persisted_policy_set_invariants_are_validated_before_map_collection() {
        for invalid in [
            serde_json::json!({
                "entries": [
                    wire_entry(1, "a", 0, 0),
                    wire_entry(1, "b", 0, 0),
                ],
                "next_id": 2,
            }),
            serde_json::json!({
                "entries": [
                    wire_entry(0, "duplicate", 0, 0),
                    wire_entry(1, "duplicate", 0, 0),
                ],
                "next_id": 2,
            }),
            serde_json::json!({
                "entries": [wire_entry(2, "a", 0, 0)],
                "next_id": 2,
            }),
            serde_json::json!({
                "entries": [wire_entry(0, "a", 2, 1)],
                "next_id": 1,
            }),
        ] {
            assert!(
                serde_json::from_value::<PolicySet>(invalid).is_err(),
                "incoherent persisted set must reject"
            );
        }
    }

    #[test]
    fn persisted_policy_set_reports_duplicate_token_before_duplicate_id() {
        let duplicate_token_and_id = serde_json::json!({
            "entries": [
                wire_entry(1, "duplicate", 0, 0),
                wire_entry(1, "duplicate", 0, 0),
            ],
            "next_id": 2,
        });

        let error = serde_json::from_value::<PolicySet>(duplicate_token_and_id)
            .expect_err("an entry duplicating both token and id must reject");
        assert_eq!(error.to_string(), "duplicate live policy token");
    }

    #[test]
    fn persisted_policy_entries_accept_sparse_unordered_ids_and_normalize_them() {
        let wire = serde_json::json!({
            "entries": [
                wire_entry(7, "seven", 1, 2),
                wire_entry(1, "one", -1, -1),
            ],
            "next_id": 20,
        });
        let set: PolicySet = serde_json::from_value(wire).expect("valid persisted set");

        assert_eq!(ids(&set), vec![1, 7]);
        assert_eq!(set.next_id(), 20);
    }

    /// A deterministic handle generator for the fold — distinct, non-colliding
    /// tokens a test can capture and re-reference. Real handles are random; these
    /// are predictable only so the assertions stay readable.
    fn toks() -> impl FnMut() -> PolicyToken {
        let mut n = 0u64;
        move || {
            let t = PolicyToken(format!("SPtok{n}"));
            n += 1;
            t
        }
    }

    /// Fold a single-`Add` base and return the set plus the minted handle.
    fn base_with(statement: &str) -> (PolicySet, PolicyToken) {
        let out = PolicySet::new()
            .fold(
                &[Verb::Add {
                    policy: statement.into(),
                }],
                1,
                "",
                trim_canon,
                toks(),
            )
            .unwrap();
        let token = out.minted[0].clone();
        (out.set, token)
    }

    #[test]
    fn add_mints_monotone_ids_and_is_born_fresh() {
        let out = PolicySet::new()
            .fold(
                &[
                    Verb::Add {
                        policy: "p1".into(),
                    },
                    Verb::Add {
                        policy: "p2".into(),
                    },
                ],
                10,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        assert_eq!(ids(&out.set), vec![0, 1]);
        // Two distinct handles minted, in add order — `minted[k]` addresses the
        // k-th entry (ordinals 0, 1 respectively).
        assert_eq!(out.minted.len(), 2);
        assert_ne!(out.minted[0], out.minted[1]);
        assert_eq!(
            out.set.get_by_token(&out.minted[0]).unwrap().id,
            PolicyId(0)
        );
        assert_eq!(
            out.set.get_by_token(&out.minted[1]).unwrap().id,
            PolicyId(1)
        );
        assert_eq!(out.fresh, BTreeSet::from([PolicyId(0), PolicyId(1)]));
        assert_eq!(out.set.get(PolicyId(0)).unwrap().statement, "p1");
        assert_eq!(out.set.next_id(), 2);
    }

    #[test]
    fn add_slices_a_multi_policy_source_into_one_entry_each() {
        let out = PolicySet::new()
            .fold(
                &[Verb::Add {
                    policy: "p1; p2; p3".into(),
                }],
                10,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        // One `Add` verb, three policies in its source -> three entries + handles.
        assert_eq!(ids(&out.set), vec![0, 1, 2]);
        assert_eq!(out.minted.len(), 3);
        assert_eq!(
            out.fresh,
            BTreeSet::from([PolicyId(0), PolicyId(1), PolicyId(2)])
        );
        assert_eq!(out.set.get(PolicyId(0)).unwrap().statement, "p1");
        assert_eq!(out.set.get(PolicyId(2)).unwrap().statement, "p3");
    }

    #[test]
    fn update_rejects_a_multi_policy_source() {
        let (base, tok) = base_with("a");
        let err = base
            .fold(
                &[Verb::Update {
                    id: tok,
                    policy: "x; y".into(),
                }],
                2,
                "",
                trim_canon,
                toks(),
            )
            .expect_err("a multi-policy update must reject");
        assert_eq!(
            err,
            BatchError::Rejected("update expects exactly one policy, got 2".into())
        );
        // Base untouched.
        assert_eq!(base.get(PolicyId(0)).unwrap().statement, "a");
    }

    #[test]
    fn update_keeps_id_changes_content_and_resets() {
        let (base, tok) = base_with("a");
        let out = base
            .fold(
                &[Verb::Update {
                    id: tok,
                    policy: "b".into(),
                }],
                2,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        assert_eq!(ids(&out.set), vec![0]); // same ordinal
        assert_eq!(out.set.get(PolicyId(0)).unwrap().statement, "b");
        assert_eq!(out.set.get(PolicyId(0)).unwrap().created, 1);
        assert_eq!(out.set.get(PolicyId(0)).unwrap().updated, 2);
        assert!(out.fresh.contains(&PolicyId(0))); // update means reset
        assert!(out.minted.is_empty());
    }

    #[test]
    fn delete_removes_and_unknown_id_rejects_whole_batch() {
        let base_out = PolicySet::new()
            .fold(
                &[
                    Verb::Add { policy: "a".into() },
                    Verb::Add { policy: "b".into() },
                ],
                1,
                "",
                trim_canon,
                toks(),
            )
            .unwrap();
        let tok_a = base_out.minted[0].clone();
        let base = base_out.set;
        let out = base
            .fold(&[Verb::Delete { id: tok_a }], 2, "", trim_canon, toks())
            .expect("folds");
        assert_eq!(ids(&out.set), vec![1]);
        // Unknown handle -> whole batch rejected, base untouched.
        let unknown = PolicyToken("SPnope".into());
        let err = base
            .fold(
                &[
                    Verb::Add { policy: "c".into() },
                    Verb::Delete {
                        id: unknown.clone(),
                    },
                ],
                3,
                "",
                trim_canon,
                toks(),
            )
            .expect_err("rejects");
        assert_eq!(err, BatchError::UnknownPolicy(unknown));
    }

    #[test]
    fn reset_marks_fresh_without_changing_content() {
        let (base, tok) = base_with("a");
        let out = base
            .fold(&[Verb::Reset { id: tok }], 2, "", trim_canon, toks())
            .expect("folds");
        assert_eq!(out.set.get(PolicyId(0)).unwrap().statement, "a"); // unchanged
        assert_eq!(out.set.get(PolicyId(0)).unwrap().updated, 1); // reset is not an edit
        assert!(out.fresh.contains(&PolicyId(0)));
    }

    #[test]
    fn delete_all_empties_and_keeps_minting_cursor() {
        let base = PolicySet::new()
            .fold(
                &[
                    Verb::Add { policy: "a".into() },
                    Verb::Add { policy: "b".into() },
                ],
                1,
                "",
                trim_canon,
                toks(),
            )
            .unwrap()
            .set;
        let out = base
            .fold(&[Verb::DeleteAll], 2, "", trim_canon, toks())
            .expect("folds");
        assert!(out.set.is_empty());
        assert!(out.fresh.is_empty());
        assert_eq!(out.set.next_id(), 2); // cursor is monotone even across DeleteAll
    }

    #[test]
    fn declarative_replace_is_delete_all_then_adds() {
        let base = PolicySet::new()
            .fold(
                &[Verb::Add {
                    policy: "old".into(),
                }],
                1,
                "",
                trim_canon,
                toks(),
            )
            .unwrap()
            .set;
        let out = base
            .fold(
                &[
                    Verb::DeleteAll,
                    Verb::Add {
                        policy: "new1".into(),
                    },
                    Verb::Add {
                        policy: "new2".into(),
                    },
                ],
                5,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        // Old gone, two fresh policies with new ordinals (cursor continued past `old`).
        assert_eq!(ids(&out.set), vec![1, 2]);
        assert_eq!(out.fresh, BTreeSet::from([PolicyId(1), PolicyId(2)]));
    }

    #[test]
    fn reset_all_marks_every_policy_fresh_and_reset_is_then_noop() {
        let base_out = PolicySet::new()
            .fold(
                &[
                    Verb::Add { policy: "a".into() },
                    Verb::Add { policy: "b".into() },
                ],
                1,
                "",
                trim_canon,
                toks(),
            )
            .unwrap();
        let tok_a = base_out.minted[0].clone();
        let base = base_out.set;
        let out = base
            .fold(
                &[Verb::ResetAll, Verb::Reset { id: tok_a }],
                2,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        assert_eq!(out.fresh, BTreeSet::from([PolicyId(0), PolicyId(1)]));
    }

    #[test]
    fn add_then_delete_all_in_one_batch_yields_empty() {
        let out = PolicySet::new()
            .fold(
                &[Verb::Add { policy: "p".into() }, Verb::DeleteAll],
                1,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        assert!(out.set.is_empty());
        assert!(out.fresh.is_empty()); // the just-added policy is gone, nothing to reset
        assert_eq!(out.minted.len(), 1); // it *was* minted before being wiped
    }

    #[test]
    fn invalid_policy_rejects_whole_batch_leaving_base_untouched() {
        let (base, _) = base_with("a");
        let err = base
            .fold(
                &[
                    Verb::Add { policy: "b".into() },
                    Verb::Add {
                        policy: "   ".into(),
                    },
                ],
                2,
                "",
                trim_canon,
                toks(),
            )
            .expect_err("rejects");
        assert_eq!(err, BatchError::Rejected("empty policy".into()));
        // base is a value; the failed fold produced nothing, so nothing changed.
        assert_eq!(ids(&base), vec![0]);
    }

    #[test]
    fn set_action_schema_is_captured_last_wins() {
        let out = PolicySet::new()
            .fold(
                &[
                    Verb::SetActionSchema {
                        action_schema: "s1".into(),
                    },
                    Verb::Add { policy: "p".into() },
                    Verb::SetActionSchema {
                        action_schema: "s2".into(),
                    },
                ],
                1,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        assert_eq!(out.action_schema.as_deref(), Some("s2"));
        assert_eq!(ids(&out.set), vec![0]);
    }

    #[test]
    fn append_action_schema_concatenates_onto_the_schema_in_force() {
        // Append starts from the *current* schema (the fold's `current_action_schema`
        // argument), so a caller need not fetch-and-set.
        let out = PolicySet::new()
            .fold(
                &[Verb::AppendActionSchema {
                    fragment: "frag".into(),
                }],
                1,
                "base",
                trim_canon,
                toks(),
            )
            .expect("folds");
        assert_eq!(out.action_schema.as_deref(), Some("base\nfrag"));
        // Append is not a reset: it marks nothing fresh.
        assert!(out.fresh.is_empty());
    }

    #[test]
    fn set_then_append_composes_sequentially() {
        // Sequential: a Set replaces the base, a following Append extends
        // that — not the original `current_action_schema`.
        let out = PolicySet::new()
            .fold(
                &[
                    Verb::SetActionSchema {
                        action_schema: "s1".into(),
                    },
                    Verb::AppendActionSchema {
                        fragment: "frag".into(),
                    },
                ],
                1,
                "original",
                trim_canon,
                toks(),
            )
            .expect("folds");
        assert_eq!(out.action_schema.as_deref(), Some("s1\nfrag"));
    }

    #[test]
    fn from_recorded_continues_minting_where_recovery_left_off() {
        let set = PolicySet::from_recorded(
            vec![PolicyEntry {
                id: PolicyId(7),
                token: PolicyToken("SPseven".into()),
                statement: "x".into(),
                created: 1,
                updated: 1,
            }],
            8,
        );
        let out = set
            .fold(
                &[Verb::Add { policy: "y".into() }],
                2,
                "",
                trim_canon,
                toks(),
            )
            .expect("folds");
        // The new policy continues the ordinal cursor — 8, not 0 or 7.
        assert_eq!(out.minted.len(), 1);
        assert_eq!(
            out.set.get_by_token(&out.minted[0]).unwrap().id,
            PolicyId(8)
        );
    }

    #[test]
    fn add_rejects_ordinal_exhaustion_before_minting_tokens() {
        use std::cell::Cell;

        for (next_id, statements) in [
            (u64::MAX, vec!["one".to_string()]),
            (u64::MAX - 1, vec!["one".to_string(), "two".to_string()]),
        ] {
            let base = PolicySet::from_recorded(Vec::new(), next_id);
            let original = base.clone();
            let canonicalizer_calls = Cell::new(0);
            let mint_calls = Cell::new(0);
            let error = base
                .fold(
                    &[Verb::Add {
                        policy: "source".into(),
                    }],
                    1,
                    "",
                    |_| {
                        canonicalizer_calls.set(canonicalizer_calls.get() + 1);
                        Ok(statements.clone())
                    },
                    || {
                        mint_calls.set(mint_calls.get() + 1);
                        PolicyToken("SPunexpected".into())
                    },
                )
                .expect_err("ordinal exhaustion must reject");

            assert_eq!(
                error,
                BatchError::Rejected("policy ordinal space exhausted".into())
            );
            assert_eq!(base, original);
            assert_eq!(canonicalizer_calls.get(), 1);
            assert_eq!(mint_calls.get(), 0);
        }
    }

    #[test]
    fn add_rejects_an_empty_successful_canonicalization_before_minting_tokens() {
        use std::cell::Cell;

        let base = PolicySet::new();
        let original = base.clone();
        let mint_calls = Cell::new(0);
        let error = base
            .fold(
                &[Verb::Add {
                    policy: "comments-only source".into(),
                }],
                1,
                "",
                |_| Ok(Vec::new()),
                || {
                    mint_calls.set(mint_calls.get() + 1);
                    PolicyToken("SPunexpected".into())
                },
            )
            .expect_err("an Add that canonicalizes to no policies must reject");

        assert_eq!(
            error,
            BatchError::Rejected("source contains no policy".into())
        );
        assert_eq!(base, original);
        assert_eq!(mint_calls.get(), 0);
    }

    #[test]
    fn later_empty_add_rejects_after_an_earlier_add_mints() {
        use std::cell::Cell;

        let (base, _) = base_with("existing");
        let canonicalizer_calls = Cell::new(0);
        let mint_calls = Cell::new(0);
        let error = base
            .fold(
                &[
                    Verb::Add {
                        policy: "valid source".into(),
                    },
                    Verb::Add {
                        policy: "comments-only source".into(),
                    },
                ],
                2,
                "",
                |source| {
                    canonicalizer_calls.set(canonicalizer_calls.get() + 1);
                    match source {
                        "valid source" => Ok(vec!["canonical policy".into()]),
                        "comments-only source" => Ok(Vec::new()),
                        other => panic!("unexpected source: {other}"),
                    }
                },
                || {
                    let call = mint_calls.get();
                    mint_calls.set(call + 1);
                    PolicyToken(format!("SPnew{call}"))
                },
            )
            .expect_err("the later empty Add must reject the whole batch");

        assert_eq!(
            error,
            BatchError::Rejected("source contains no policy".into())
        );
        assert_eq!(canonicalizer_calls.get(), 2);
        assert_eq!(
            mint_calls.get(),
            1,
            "callbacks before the rejecting verb may run"
        );
    }

    #[test]
    fn declarative_construction_rejects_ordinal_exhaustion_before_minting_tokens() {
        use std::cell::Cell;

        let mint_calls = Cell::new(0);
        let error = PolicySet::from_statements_after(
            ["one".to_string(), "two".to_string()],
            1,
            u64::MAX - 1,
            || {
                mint_calls.set(mint_calls.get() + 1);
                PolicyToken("SPunexpected".into())
            },
        )
        .expect_err("whole-set construction must preflight every ordinal");

        assert_eq!(error, POLICY_ORDINAL_EXHAUSTED);
        assert_eq!(mint_calls.get(), 0);
    }

    #[test]
    fn final_representable_cursor_value_is_reachable() {
        let base = PolicySet::from_recorded(Vec::new(), u64::MAX - 1);
        let outcome = base
            .fold(
                &[Verb::Add {
                    policy: "one".into(),
                }],
                1,
                "",
                trim_canon,
                toks(),
            )
            .expect("one remaining ordinal fits");

        assert_eq!(outcome.set.next_id(), u64::MAX);
        assert_eq!(
            outcome.set.ids().collect::<Vec<_>>(),
            vec![PolicyId(u64::MAX - 1)]
        );
    }
}
