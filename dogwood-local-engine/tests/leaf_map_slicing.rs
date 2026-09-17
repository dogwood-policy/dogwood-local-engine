//! End-to-end verdict-slicing tests, driven through the frontend's
//! [`Authorizer`].
//!
//! Every decision below comes from `dogwood_language::Authorizer` with a
//! [`LocalTemporalEngine`] installed — the production path, request
//! construction and entity store included. So this file needs no `cedar-policy`
//! dependency of its own: Cedar runs inside the frontend, and the few Cedar
//! types that appear (`EntityUid`, `Entities`) arrive through
//! `dogwood_language::cedar`, which is the frontend's own instance. Action
//! identities are read out of the parsed schema rather than reconstructed from
//! strings, so nothing here replicates the request-construction derivation the
//! frontend already owns.
//!
//! Fixtures make skipped leaves genuinely true, so an incorrect skip changes a
//! decision rather than merely lowering a counter. Coverage includes action
//! groups, lists, encoded ids, conservative fallbacks, and partitioned mode.
//!
//! ## Where "which leaves were computed" comes from
//!
//! The engine reports how many verdicts it computed
//! ([`LocalTemporalEngine::verdicts_computed`]), not which. [`Spy`] records that
//! counter's per-decision delta alongside the bindings the engine returned, and
//! [`computed_leaves`] recovers the exact SET from the pair by replaying the
//! same history with slicing off: every leaf is genuinely `true` in the unsliced
//! run, so in the sliced run `true` means computed and `false` means skipped.
//! The recovered set's size must equal the engine's own count, which makes that
//! reasoning an assertion rather than an assumption.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use dogwood_language::cedar::{Entities, EntityUid, PolicySet, Schema};
use dogwood_language::{
    ActionRef, AuthorizationDecision, AuthorizationRequest, Authorizer, CedarPolicyEngine,
    Decision, Error, Event, EventSignature, LoweredPolicySet, PartitionKey, PolicyEngine,
    PolicySchema, ServiceSchema, TemporalBindings, TemporalEngine, TemporalField, Value,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
namespace Test {
  entity User;
  entity Doc;
  action "Read" appliesTo {
    principal: [User], resource: [Doc],
    context: { input: { doc: String } }
  };
  action "Delete" appliesTo {
    principal: [User], resource: [Doc],
    context: { input: { doc: String } }
  };
  action "List" appliesTo {
    principal: [User], resource: [Doc],
    context: { input: { doc: String } }
  };
}
"#;

/// Two leaves scoped to different actions; `List` reaches neither.
const POLICY: &str = r#"
permit (principal, action, resource);

forbid (principal, action == Test::Action::"Read", resource)
when temporal { formerly within 1h Test::Action::"Read"::request{ input.doc: "d1" } };

forbid (principal, action == Test::Action::"Delete", resource)
when temporal { formerly within 1h Test::Action::"Delete"::request{ input.doc: "d1" } };
"#;

fn lower() -> LoweredPolicySet {
    lower_with(SCHEMA, POLICY)
}

fn lower_with(schema: &str, policy: &str) -> LoweredPolicySet {
    let schema = PolicySchema::from_cedarschema_str(schema).expect("schema builds");
    LoweredPolicySet::from_str(policy, &ServiceSchema::defaults(), &schema).expect("policy lowers")
}

/// The schema's own uid for the action whose raw id is `id`, found structurally
/// — by unescaped id under `Test::Action` — rather than by rendering a string
/// and reparsing it. For a fixture whose schema spells the id escaped, this is
/// also the round-trip check that the escaped literal really denotes `id`.
fn action_uid(schema: &Schema, id: &str) -> EntityUid {
    schema
        .actions()
        .find(|uid| {
            uid.id().unescaped() == id
                && uid.type_name().namespace() == "Test"
                && uid.type_name().basename() == "Action"
        })
        .cloned()
        .unwrap_or_else(|| panic!("the schema declares an action with raw id {id:?}"))
}

/// Whether an [`ActionRef`] the lowering reports names `uid` — the same
/// structural comparison [`action_uid`] makes, on the other side of the join.
fn action_ref_matches(action: &ActionRef, uid: &EntityUid) -> bool {
    action.id == uid.id().unescaped()
        && action.namespace.as_deref().unwrap_or_default() == uid.type_name().namespace()
}

/// Find the leaf whose expanded scope contains `action`.
fn leaf_id_for(lowered: &LoweredPolicySet, action: &EntityUid) -> String {
    let matches: Vec<String> = lowered
        .temporal_fields()
        .filter(|f| {
            f.target_actions
                .iter()
                .any(|a| action_ref_matches(a, action))
        })
        .map(|f| f.id.clone())
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one leaf scoped to {action}, got {matches:?}"
    );
    matches.into_iter().next().expect("checked above")
}

/// Use structured parts so action ids containing `::` remain intact.
fn request_at(ts: i64, action_id: &str, doc: &str) -> Event {
    Event::builder_for(&["Test", "Action"], action_id, "request")
        .timestamp(ts)
        .principal("Test::User::\"alice\"")
        .resource("Test::Doc::\"d1\"")
        .field("input", "doc", Value::String(doc.into()))
        .request_context("input", "doc", Value::String(doc.into()))
        .build()
}

/// History that makes both fixture leaves true before `decision`.
fn history_with_both_leaves_true(decision: Event) -> [Event; 3] {
    [
        request_at(1_000, "Read", "d1"),
        request_at(1_001, "Delete", "d1"),
        decision,
    ]
}

fn leaf_ids(lowered: &LoweredPolicySet) -> Vec<String> {
    lowered.temporal_fields().map(|f| f.id.clone()).collect()
}

/// `leaf_ids` as the `&[&str]` the computed-set assertions take.
fn all_of(leaf_ids: &[String]) -> Vec<&str> {
    leaf_ids.iter().map(String::as_str).collect()
}

// ─── The engine, and the observation seam over it ────────────────────

/// A [`LocalTemporalEngine`] the test still holds after the [`Authorizer`] takes
/// ownership of it.
///
/// `Authorizer` takes its temporal engine by value as a `Box<dyn
/// TemporalEngine>` and never hands it back, so the engine's own diagnostics
/// (`verdicts_computed`, `leaf_map_entries`, `unresolved_action_scopes`,
/// `is_partitioned`, `shard_count`) would be unreachable once installed — and
/// `disable_slicing` uncallable mid-run. Rather than widen the frontend's trait
/// for a test's benefit, the engine lives behind a shared handle: [`Spy`] locks
/// it for each call the frontend makes, and the test reads the very same
/// instance between decisions. Everything the frontend drives forwards
/// verbatim — the engine under test is the real one.
///
/// (`Arc<Mutex<_>>` rather than `Rc<RefCell<_>>` because `TemporalEngine: Send`.
/// Same motivation as the shared atomics in `leaf_map_corpus_diff.rs`, but a
/// handle on the engine itself: these lanes read several diagnostics, one of
/// them — the map's entry count — at a chosen point in the run, and one lane
/// re-prepares the same engine instance for a second policy set.)
#[derive(Clone)]
struct EngineHandle(Arc<Mutex<LocalTemporalEngine>>);

impl EngineHandle {
    fn new() -> Self {
        EngineHandle(Arc::new(Mutex::new(LocalTemporalEngine::new())))
    }

    /// Run `f` against the engine. Held per call and never across one, so the
    /// frontend's calls and the test's reads cannot interleave.
    fn with<T>(&self, f: impl FnOnce(&mut LocalTemporalEngine) -> T) -> T {
        f(&mut self.0.lock().expect("the engine lock is never poisoned"))
    }
}

/// One decision point as the engine saw it.
#[derive(Clone, Debug)]
struct Pass {
    /// The decision event's action id — the pass's own account of what it
    /// decided, rather than the test's assumption about ordering.
    action: String,
    /// Leaf verdicts the engine actually computed at this decision.
    computed: u64,
    /// What it bound every leaf to.
    bindings: TemporalBindings,
    /// Decisions the map could answer at this point (0 once slicing is off).
    leaf_map_entries: usize,
}

/// Records each decision's slicing observables while delegating every trait
/// method to the real [`LocalTemporalEngine`] behind [`EngineHandle`].
struct Spy {
    engine: EngineHandle,
    /// The action of the most recently observed event: `evaluate` is defined to
    /// be for that event (`TemporalEngine::evaluate`).
    last_action: Option<String>,
    passes: Arc<Mutex<Vec<Pass>>>,
}

impl TemporalEngine for Spy {
    fn prepare(
        &mut self,
        leaves: &[TemporalField],
        schema: &Schema,
        events: &[EventSignature],
    ) -> Result<(), Error> {
        self.engine.with(|e| e.prepare(leaves, schema, events))
    }

    fn observe(&mut self, event: &Event) {
        self.last_action = Some(event.action().to_string());
        self.engine.with(|e| e.observe(event));
    }

    fn evaluate(&mut self) -> Result<TemporalBindings, String> {
        let (bindings, computed, leaf_map_entries) = self.engine.with(|e| {
            let before = e.verdicts_computed();
            let bindings = e.evaluate();
            (
                bindings,
                e.verdicts_computed() - before,
                e.leaf_map_entries(),
            )
        });
        let bindings = bindings?;
        self.passes
            .lock()
            .expect("the pass lock is never poisoned")
            .push(Pass {
                action: self
                    .last_action
                    .clone()
                    .expect("evaluate follows observe (TemporalEngine's contract)"),
                computed,
                bindings: bindings.clone(),
                leaf_map_entries,
            });
        Ok(bindings)
    }

    // Delegated, not defaulted: the partitioned lane's mode is chosen by the
    // frontend through these two, and a `false` here would silently downgrade
    // it to global evaluation.
    fn supports_partitioning(&self) -> bool {
        self.engine.with(|e| e.supports_partitioning())
    }

    fn set_partition_keys(&mut self, keys: &[PartitionKey]) {
        self.engine.with(|e| e.set_partition_keys(keys));
    }
}

/// A [`PolicyEngine`] that decides against an EMPTY entity store.
///
/// The frontend builds the store for every decision — bare scope entities plus
/// the schema's action hierarchy — so a caller cannot vary it from outside. This
/// wrapper can: it forwards each request to the built-in [`CedarPolicyEngine`]
/// with the entities replaced by an empty store, which is what "Cedar cannot see
/// the action `memberOf` edges" looks like from inside the production path.
#[derive(Default)]
struct StoreBlindPolicyEngine {
    inner: CedarPolicyEngine,
}

impl PolicyEngine for StoreBlindPolicyEngine {
    fn prepare(&mut self, policies: &PolicySet, schema: &Schema) -> Result<(), Error> {
        self.inner.prepare(policies, schema)
    }

    fn is_authorized(&self, request: AuthorizationRequest<'_>) -> AuthorizationDecision {
        let blind = Entities::empty();
        self.inner.is_authorized(AuthorizationRequest {
            request: request.request,
            entities: &blind,
        })
    }
}

/// A run to configure, then [`feed`](Replay::feed) a history to. Defaults to the
/// shipping configuration: slicing on, global evaluation, the frontend's own
/// entity store, a fresh engine.
struct Replay {
    lowered: LoweredPolicySet,
    slicing: bool,
    partitioned: bool,
    store_blind: bool,
    engine: Option<EngineHandle>,
}

impl Replay {
    fn new(lowered: LoweredPolicySet) -> Self {
        Replay {
            lowered,
            slicing: true,
            partitioned: false,
            store_blind: false,
            engine: None,
        }
    }

    /// The oracle: `disable_slicing` before `prepare`, so no map is built and
    /// every decision computes every leaf.
    fn unsliced(mut self) -> Self {
        self.slicing = false;
        self
    }

    /// Native pin partitioning, chosen the way a caller chooses it.
    fn partitioned(mut self) -> Self {
        self.partitioned = true;
        self
    }

    fn store_blind(mut self) -> Self {
        self.store_blind = true;
        self
    }

    /// Build over an engine that has already served a policy set, so this
    /// authorizer's `prepare` re-prepares that instance.
    fn reusing(mut self, engine: EngineHandle) -> Self {
        self.engine = Some(engine);
        self
    }

    fn feed(self, history: &[Event]) -> Run {
        let engine = self.engine.unwrap_or_else(EngineHandle::new);
        if !self.slicing {
            engine.with(LocalTemporalEngine::disable_slicing);
        }
        let passes = Arc::new(Mutex::new(Vec::new()));
        let mut builder = Authorizer::builder(self.lowered).temporal_engine(Spy {
            engine: engine.clone(),
            last_action: None,
            passes: Arc::clone(&passes),
        });
        if self.partitioned {
            builder = builder.partition_temporal();
        }
        if self.store_blind {
            builder = builder.policy_engine(StoreBlindPolicyEngine::default());
        }
        let mut run = Run {
            authorizer: builder.build().expect("the frontend prepares the engine"),
            engine,
            passes,
            decisions: Vec::new(),
        };
        run.feed(history);
        run
    }
}

/// One replay: the authorizer, a handle on the engine it drives, and what came
/// out.
struct Run {
    authorizer: Authorizer,
    engine: EngineHandle,
    passes: Arc<Mutex<Vec<Pass>>>,
    decisions: Vec<Decision>,
}

impl Run {
    /// Ingest more events. Every fixture event is a `request`, which the default
    /// event schema marks `decision`, so each one must yield a response — and a
    /// clean one: a fail-closed `Deny` carrying an evaluation error would
    /// otherwise be indistinguishable from a policy's `forbid` firing.
    fn feed(&mut self, history: &[Event]) -> &mut Self {
        for event in history {
            let response = self
                .authorizer
                .is_authorized(event)
                .expect("a `request` event is a decision point");
            let errors: Vec<&str> = response.diagnostics().errors().collect();
            assert!(
                errors.is_empty(),
                "authorizing {:?} reported evaluation errors: {errors:?}",
                event.action()
            );
            self.decisions.push(response.decision());
        }
        self
    }

    /// The pass for the last decision — the request each lane is about.
    fn last(&self) -> Pass {
        self.passes
            .lock()
            .expect("the pass lock is never poisoned")
            .last()
            .cloned()
            .expect("the history contained a decision point")
    }

    /// The last decision's verdict.
    fn decision(&self) -> Decision {
        *self
            .decisions
            .last()
            .expect("the history contained a decision point")
    }
}

// ─── Reading the computed set out of the engine's own numbers ────────

/// The leaves `sliced` really computed at its last decision, and the proof that
/// the reading is exact.
///
/// `unsliced` must be the same history replayed with slicing off, at the same
/// decision: its bindings are the leaves' real values. Requiring them all
/// `true` is the fixtures' teeth — it makes every `false` in `sliced` a genuine
/// skip, so `true` ⇔ computed. The final equality turns that inference into an
/// assertion: were the engine to compute a leaf and skip a different one, the
/// count and the true-set would disagree.
fn computed_leaves(sliced: &Pass, unsliced: &Pass) -> BTreeSet<String> {
    assert_eq!(
        sliced.action, unsliced.action,
        "the two runs must be compared at the same decision"
    );
    assert!(
        !unsliced.bindings.is_empty() && unsliced.bindings.values().all(|v| *v),
        "fixture history must make EVERY leaf genuinely true, or a `false` in the \
         sliced run proves nothing: {:?}",
        unsliced.bindings
    );
    assert_eq!(
        sliced.bindings.keys().collect::<Vec<&String>>(),
        unsliced.bindings.keys().collect::<Vec<&String>>(),
        "every leaf must still be bound — an absent one is a Cedar evaluation error"
    );

    let computed: BTreeSet<String> = sliced
        .bindings
        .iter()
        .filter(|(_, verdict)| **verdict)
        .map(|(id, _)| id.clone())
        .collect();
    assert_eq!(
        sliced.computed as usize,
        computed.len(),
        "the engine counted {} computed verdict(s) but reported {} true binding(s); \
         every leaf here is really true, so the two must agree: {:?}",
        sliced.computed,
        computed.len(),
        sliced.bindings
    );
    computed
}

/// [`computed_leaves`], against the exact set expected. Equality, not
/// containment: a lane fails both for skipping a leaf it must compute and for
/// computing one it must skip.
fn assert_computed(sliced: &Pass, unsliced: &Pass, expected: &[&str]) {
    let expected: BTreeSet<String> = expected.iter().map(|id| (*id).to_string()).collect();
    assert_eq!(
        computed_leaves(sliced, unsliced),
        expected,
        "computed the wrong leaf set on the {:?} decision",
        sliced.action
    );
}

/// The bindings a sliced pass must report: every leaf, true iff it is in
/// `computed`.
fn only(leaf_ids: &[String], computed: &[&str]) -> TemporalBindings {
    leaf_ids
        .iter()
        .map(|id| (id.clone(), computed.contains(&id.as_str())))
        .collect()
}

// ─── The map, and the two ends of the slice ──────────────────────────

/// The map covers what it should: one entry per action the schema declares, and
/// no unresolvable scope in the fixture — the premise the counting lanes below
/// rest on, and the non-vacuity guard for
/// [`a_bare_action_scope_is_computed_for_every_action`].
#[test]
fn the_map_is_built_over_the_schemas_actions_with_nothing_unresolved() {
    let run = Replay::new(lower()).feed(&history_with_both_leaves_true(request_at(
        1_002, "Read", "d1",
    )));
    run.engine.with(|engine| {
        assert_eq!(
            engine.leaf_map_entries(),
            3,
            "Read, Delete and List — every action the schema declares"
        );
        assert_eq!(
            engine.unresolved_action_scopes(),
            Vec::new(),
            "both fixture rules have an exact action scope, so nothing falls back"
        );
    });
}

/// An action outside every rule computes no leaves but still binds them all.
#[test]
fn an_action_no_rule_is_scoped_to_computes_no_verdicts_and_binds_every_leaf_false() {
    let lowered = lower();
    let leaf_ids = leaf_ids(&lowered);
    let history = history_with_both_leaves_true(request_at(1_002, "List", "other"));

    // Non-vacuity: the unsliced oracle computes `true` for both leaves.
    let unsliced = Replay::new(lower()).unsliced().feed(&history);
    let sliced = Replay::new(lower()).feed(&history);

    assert_computed(
        &sliced.last(),
        &unsliced.last(),
        &[], // an action no rule is scoped to must not compute a single verdict
    );
    assert_eq!(
        sliced.last().bindings,
        only(&leaf_ids, &[]),
        "every leaf must still be bound — an absent one is a Cedar evaluation error"
    );
    // And the all-`false` bindings reach the same decision as the real verdicts.
    assert_eq!(sliced.decision(), unsliced.decision());
    assert_eq!(sliced.decision(), Decision::Allow);
}

/// An action computes only the leaf of its applicable rule.
#[test]
fn an_action_scoped_rule_computes_exactly_its_own_leaf() {
    let lowered = lower();
    let leaf_ids = leaf_ids(&lowered);
    let read_leaf = leaf_id_for(&lowered, &action_uid(lowered.cedar_schema(), "Read"));
    let history = history_with_both_leaves_true(request_at(1_002, "Read", "d1"));

    // Non-vacuity: both leaves are genuinely true (asserted inside
    // `assert_computed`, which is what licenses reading `false` as "skipped").
    let unsliced = Replay::new(lower()).unsliced().feed(&history);
    let sliced = Replay::new(lower()).feed(&history);

    assert_computed(&sliced.last(), &unsliced.last(), &[&read_leaf]);
    assert_eq!(
        sliced.last().bindings,
        only(&leaf_ids, &[&read_leaf]),
        "only the Read rule's leaf carries its real verdict; the Delete rule's \
         leaf is reported false despite being true"
    );

    // The skipped leaf did not change the outcome, which is what makes the skip
    // sound rather than merely cheap.
    assert_eq!(
        sliced.decision(),
        unsliced.decision(),
        "sliced and unsliced bindings must decide this request identically"
    );
    assert_eq!(
        sliced.decision(),
        Decision::Deny,
        "the computed Read leaf is true, so the forbid fires"
    );
}

#[test]
fn disabling_slicing_computes_every_leaf() {
    let leaf_ids = leaf_ids(&lower());
    // Even for `List`, the action that reads nothing.
    for action_id in ["Read", "List"] {
        let history = history_with_both_leaves_true(request_at(1_002, action_id, "d1"));
        let run = Replay::new(lower()).unsliced().feed(&history);
        let pass = run.last();
        assert_eq!(
            pass.leaf_map_entries, 0,
            "a disabled engine builds no map at all"
        );
        // Its own witness: an unsliced pass is the real-verdict reference, and
        // must compute every leaf on a {action_id} request.
        assert_computed(&pass, &pass, &all_of(&leaf_ids));
        // A `BTreeMap` keyed by leaf id, same as the sliced path returns.
        let _: &BTreeMap<String, bool> = &pass.bindings;
    }
}

#[test]
fn slicing_can_be_disabled_after_prepare() {
    let leaf_ids = leaf_ids(&lower());
    let history = history_with_both_leaves_true(request_at(1_002, "Read", "d1"));
    let mut run = Replay::new(lower()).feed(&history);

    assert_eq!(
        run.last().bindings.values().filter(|v| **v).count(),
        1,
        "sliced: the Read request reads one leaf"
    );
    assert_eq!(run.decision(), Decision::Deny);

    // Mid-run, on the live engine the authorizer is driving.
    run.engine.with(LocalTemporalEngine::disable_slicing);
    run.feed(&[request_at(1_003, "Read", "d1")]);

    let pass = run.last();
    assert_eq!(
        pass.leaf_map_entries, 0,
        "the built map is dropped, so every lookup misses"
    );
    assert_computed(&pass, &pass, &all_of(&leaf_ids));
    assert_eq!(
        run.decision(),
        Decision::Deny,
        "and the decision is unchanged — slicing was never load-bearing"
    );
}

// ─── The conservative fallbacks a policy can provoke ─────────────────

/// A bare action scope contributes its leaf to every action.
#[test]
fn a_bare_action_scope_is_computed_for_every_action() {
    // One bare-scoped rule and one Read-scoped rule, so the slice is still
    // partial: `List` computes the bare leaf and not the Read one.
    const BARE_SCOPE_POLICY: &str = r#"
permit (principal, action, resource);

forbid (principal, action, resource)
when temporal { formerly within 1h Test::Action::"Read"::request{ input.doc: "d1" } };

forbid (principal, action == Test::Action::"Read", resource)
when temporal { formerly within 1h Test::Action::"Read"::request{ input.doc: "d1" } };
"#;
    let lowered = lower_with(SCHEMA, BARE_SCOPE_POLICY);
    let leaf_ids = leaf_ids(&lowered);
    assert_eq!(leaf_ids.len(), 2, "one leaf per rule");
    // `List` is the discriminator: only the bare-scoped rule covers it. (Naming
    // the bare leaf by `Read` would be ambiguous — both rules expand to `Read`,
    // which is itself the point.)
    let bare_leaf = leaf_id_for(&lowered, &action_uid(lowered.cedar_schema(), "List"));
    let read_leaf = leaf_ids
        .iter()
        .find(|id| **id != bare_leaf)
        .expect("the other leaf is the Read-scoped one")
        .clone();
    assert_ne!(read_leaf, bare_leaf);

    let history = [
        request_at(1_000, "Read", "d1"),
        request_at(1_002, "List", "d1"),
    ];
    // Non-vacuity: both leaves watch `Read`, so this history makes both true.
    let unsliced = Replay::new(lower_with(SCHEMA, BARE_SCOPE_POLICY))
        .unsliced()
        .feed(&history);
    let sliced = Replay::new(lower_with(SCHEMA, BARE_SCOPE_POLICY)).feed(&history);

    // The map says so, and says why — the diagnostic that lets an operator see a
    // policy set defeating slicing.
    sliced.engine.with(|engine| {
        assert_eq!(
            engine.unresolved_action_scopes(),
            vec![(
                bare_leaf.clone(),
                "bare `action` scope: the rule applies to every action"
            )]
        );
    });

    assert_computed(&sliced.last(), &unsliced.last(), &[&bare_leaf]);
    assert_eq!(sliced.last().bindings, only(&leaf_ids, &[&bare_leaf]));
    // The fail-open this guards: had the bare-scoped leaf been skipped, its
    // `forbid` — which applies to every action — would not have fired.
    assert_eq!(
        sliced.decision(),
        Decision::Deny,
        "the bare-scoped forbid fires on a List request"
    );

    // And on an action the narrow rule also covers, both leaves are computed —
    // the bare scope widens the set rather than replacing it.
    let read_history = [
        request_at(1_000, "Read", "d1"),
        request_at(1_002, "Read", "d1"),
    ];
    let unsliced = Replay::new(lower_with(SCHEMA, BARE_SCOPE_POLICY))
        .unsliced()
        .feed(&read_history);
    let sliced = Replay::new(lower_with(SCHEMA, BARE_SCOPE_POLICY)).feed(&read_history);
    assert_computed(&sliced.last(), &unsliced.last(), &all_of(&leaf_ids));
    assert_eq!(
        sliced.last().bindings,
        only(&leaf_ids, &all_of(&leaf_ids)),
        "both leaves carry their real verdict"
    );
    assert_eq!(sliced.decision(), Decision::Deny);
}

/// An undeclared action misses the map and computes every leaf.
#[test]
fn an_undeclared_action_falls_back_to_computing_every_leaf() {
    let leaf_ids = leaf_ids(&lower());
    let history = history_with_both_leaves_true(request_at(1_002, "Ghost", "d1"));

    let unsliced = Replay::new(lower()).unsliced().feed(&history);
    let sliced = Replay::new(lower()).feed(&history);

    assert_computed(
        &sliced.last(),
        &unsliced.last(),
        &all_of(&leaf_ids), // the map cannot answer, so compute every leaf, not none
    );
    // Same answer as the oracle — bindings and decision — which is the point of
    // falling back.
    assert_eq!(sliced.last().bindings, unsliced.last().bindings);
    assert_eq!(sliced.decision(), unsliced.decision());
    assert_eq!(
        sliced.decision(),
        Decision::Allow,
        "no rule is scoped to an action the schema never declared"
    );
}

/// Re-preparing replaces the map for the previous leaf set.
#[test]
fn re_preparing_rebuilds_the_map_for_the_new_policy_set() {
    const READ_SCOPED: &str = r#"
permit (principal, action, resource);

forbid (principal, action == Test::Action::"Read", resource)
when temporal { formerly within 1h Test::Action::"Read"::request{ input.doc: "d1" } };
"#;
    const LIST_SCOPED: &str = r#"
permit (principal, action, resource);

forbid (principal, action == Test::Action::"List", resource)
when temporal { formerly within 1h Test::Action::"Read"::request{ input.doc: "d1" } };
"#;
    let history = [
        request_at(1_000, "Read", "d1"),
        request_at(1_002, "List", "d1"),
    ];

    // First set: `List` is scoped to by nothing, so it reads no leaf.
    let unsliced = Replay::new(lower_with(SCHEMA, READ_SCOPED))
        .unsliced()
        .feed(&history);
    let first = Replay::new(lower_with(SCHEMA, READ_SCOPED)).feed(&history);
    assert_computed(&first.last(), &unsliced.last(), &[]);
    assert_eq!(first.decision(), Decision::Allow);

    // Second set, on the SAME engine instance: building this authorizer
    // re-prepares it, which must rebuild the map. `prepare` clears the observed
    // history along with the monitors, so the events are re-fed — as a real
    // policy apply's keyed-state transplant does.
    let second = lower_with(SCHEMA, LIST_SCOPED);
    let list_leaf = leaf_id_for(&second, &action_uid(second.cedar_schema(), "List"));
    let unsliced = Replay::new(lower_with(SCHEMA, LIST_SCOPED))
        .unsliced()
        .feed(&history);
    let reprepared = Replay::new(lower_with(SCHEMA, LIST_SCOPED))
        .reusing(first.engine.clone())
        .feed(&history);

    assert_computed(&reprepared.last(), &unsliced.last(), &[&list_leaf]);
    assert_eq!(
        reprepared.decision(),
        Decision::Deny,
        "a map left over from the previous policy set would fail open here"
    );
}

// ─── Complex scope shapes ────────────────────────────────────────────

/// `Delete` belongs to `Admin`; `Read` does not.
const GROUP_SCHEMA: &str = r#"
namespace Test {
  entity User;
  entity Doc;
  action "Admin";
  action "Delete" in [Action::"Admin"] appliesTo {
    principal: [User], resource: [Doc],
    context: { input: { doc: String } }
  };
  action "Read" appliesTo {
    principal: [User], resource: [Doc],
    context: { input: { doc: String } }
  };
}
"#;

const GROUP_POLICY: &str = r#"
permit (principal, action, resource);

forbid (principal, action in [Test::Action::"Admin"], resource)
when temporal { formerly within 1h Test::Action::"Delete"::request{ input.doc: "d1" } };
"#;

fn group_fixture() -> LoweredPolicySet {
    lower_with(GROUP_SCHEMA, GROUP_POLICY)
}

/// Group membership expands the rule scope to member actions.
#[test]
fn a_leaf_reachable_only_through_action_group_membership_is_computed() {
    let lowered = group_fixture();
    let leaf_ids = leaf_ids(&lowered);
    assert_eq!(leaf_ids.len(), 1, "the fixture hoists exactly one leaf");

    // The lowering's own view: the scope expands through the group, so the leaf
    // is on record as guarding `Delete` even though the text says `Admin`.
    assert_eq!(
        leaf_id_for(&lowered, &action_uid(lowered.cedar_schema(), "Delete")),
        leaf_ids[0]
    );

    let history = [
        request_at(1_000, "Delete", "d1"),
        request_at(1_002, "Delete", "d1"),
    ];
    // Non-vacuity: the leaf's real verdict is `true`, so a skip would show up.
    let unsliced = group_fixture_run().unsliced().feed(&history);
    let sliced = group_fixture_run().feed(&history);

    // The group itself is not a map key: it has no `appliesTo`, so no request can
    // carry it, and an entry for it would name its members' leaves rather than
    // its own. `Delete` and `Read` are the two keys.
    sliced
        .engine
        .with(|engine| assert_eq!(engine.leaf_map_entries(), 2));

    assert_computed(&sliced.last(), &unsliced.last(), &[&leaf_ids[0]]);
    assert_eq!(
        sliced.last().bindings,
        only(&leaf_ids, &[&leaf_ids[0]]),
        "the leaf must carry its real verdict, not the skipped default"
    );
    // The fail-open this test exists to catch: had the leaf been skipped and
    // reported `false`, the forbid would not fire and this would be `Allow`. The
    // membership edge comes from the entity store the frontend builds for the
    // decision, out of the schema's action hierarchy.
    assert_eq!(
        sliced.decision(),
        Decision::Deny,
        "the group-scoped forbid fires on the computed leaf"
    );
}

fn group_fixture_run() -> Replay {
    Replay::new(group_fixture())
}

/// A non-member action does not read the group-scoped leaf.
#[test]
fn a_non_member_action_reads_no_leaf_of_the_group_scoped_rule() {
    let leaf_ids = leaf_ids(&group_fixture());

    let history = [
        request_at(1_000, "Delete", "d1"),
        request_at(1_002, "Read", "d1"),
    ];
    let unsliced = group_fixture_run().unsliced().feed(&history);
    let sliced = group_fixture_run().feed(&history);

    assert_computed(
        &sliced.last(),
        &unsliced.last(),
        &[], // Read is not in the Admin group, so the rule cannot apply
    );
    assert_eq!(
        sliced.last().bindings,
        only(&leaf_ids, &[]),
        "the skipped leaf is still bound, to `false`, despite really being `true`"
    );
    assert_eq!(
        sliced.decision(),
        unsliced.decision(),
        "and skipping it does not change the decision, which is what makes it sound"
    );
    assert_eq!(sliced.decision(), Decision::Allow);
}

/// Map expansion depends on the schema, not the authorization entity store.
#[test]
fn the_group_expansion_does_not_depend_on_the_entity_store() {
    let leaf_ids = leaf_ids(&group_fixture());
    let history = [
        request_at(1_000, "Delete", "d1"),
        request_at(1_002, "Delete", "d1"),
    ];

    let unsliced = group_fixture_run().unsliced().feed(&history);
    let sliced = group_fixture_run().feed(&history);
    // The same decision, re-run with Cedar blinded to the entity store.
    let blind = group_fixture_run().store_blind().feed(&history);

    // The engine's work — and the binding it reported — is the same in both,
    // which is the independence being pinned: the map expands the group from the
    // SCHEMA, at prepare time, with no entity store in sight.
    assert_computed(&sliced.last(), &unsliced.last(), &[&leaf_ids[0]]);
    assert_computed(&blind.last(), &unsliced.last(), &[&leaf_ids[0]]);
    assert_eq!(sliced.last().bindings, only(&leaf_ids, &[&leaf_ids[0]]));
    assert_eq!(sliced.last().bindings, blind.last().bindings);
    assert_eq!(sliced.last().computed, blind.last().computed);

    // With the edge in the store the forbid fires; without it Cedar cannot see
    // the membership and allows.
    assert_eq!(sliced.decision(), Decision::Deny);
    assert_eq!(
        blind.decision(),
        Decision::Allow,
        "action `memberOf` edges are read from the entity store at authorize time"
    );
}

/// One rule scoped to both `Read` and `Delete`.
const LIST_SCOPE_POLICY: &str = r#"
permit (principal, action, resource);

forbid (principal, action in [Test::Action::"Read", Test::Action::"Delete"], resource)
when temporal { formerly within 1h Test::Action::"Read"::request{ input.doc: "d1" } };
"#;

/// Every action in a list scope reads the rule's leaf.
#[test]
fn every_action_in_a_list_scope_reads_the_rules_leaf() {
    let lowered = lower_with(SCHEMA, LIST_SCOPE_POLICY);
    let leaf_ids = leaf_ids(&lowered);
    assert_eq!(leaf_ids.len(), 1, "the fixture hoists exactly one leaf");

    for action_id in ["Read", "Delete"] {
        assert_eq!(
            leaf_id_for(&lowered, &action_uid(lowered.cedar_schema(), action_id)),
            leaf_ids[0],
            "{action_id} is in the list scope, so the lowering records the leaf as \
             guarding it"
        );

        // The leaf watches `Read`, so this history makes it true whichever action
        // the pending request carries.
        let history = [
            request_at(1_000, "Read", "d1"),
            request_at(1_002, action_id, "d1"),
        ];
        let unsliced = Replay::new(lower_with(SCHEMA, LIST_SCOPE_POLICY))
            .unsliced()
            .feed(&history);
        let sliced = Replay::new(lower_with(SCHEMA, LIST_SCOPE_POLICY)).feed(&history);

        assert_computed(&sliced.last(), &unsliced.last(), &[&leaf_ids[0]]);
        assert_eq!(sliced.last().bindings, only(&leaf_ids, &[&leaf_ids[0]]));
        assert_eq!(
            sliced.decision(),
            Decision::Deny,
            "the list-scoped forbid fires on a {action_id} request too"
        );
    }
}

/// An action outside the list does not read the leaf.
#[test]
fn an_action_outside_the_list_scope_reads_no_leaf() {
    let leaf_ids = leaf_ids(&lower_with(SCHEMA, LIST_SCOPE_POLICY));

    let history = [
        request_at(1_000, "Read", "d1"),
        request_at(1_002, "List", "d1"),
    ];
    let unsliced = Replay::new(lower_with(SCHEMA, LIST_SCOPE_POLICY))
        .unsliced()
        .feed(&history);
    let sliced = Replay::new(lower_with(SCHEMA, LIST_SCOPE_POLICY)).feed(&history);

    assert_computed(
        &sliced.last(),
        &unsliced.last(),
        &[], // List is in neither list element
    );
    assert_eq!(sliced.last().bindings, only(&leaf_ids, &[]));
    assert_eq!(sliced.decision(), unsliced.decision());
    assert_eq!(sliced.decision(), Decision::Allow);
}

/// Legal action ids that break naive string rendering, each with the escaped
/// spelling a `.cedarschema` / policy literal needs. The escaped form is written
/// out rather than derived from Cedar's escaper, so the fixture pins the
/// canonical spelling instead of restating whatever the escaper produces;
/// [`action_uid`] closes the loop by finding the RAW id in the parsed schema.
const AWKWARD_ACTION_IDS: [(&str, &str); 2] = [
    ("Read::Archive", "Read::Archive"),
    (r#"say "hi""#, r#"say \"hi\""#),
];

/// Build a fixture whose action id needs escaping in source.
fn awkward_fixture(escaped: &str) -> (String, String) {
    let schema = format!(
        r#"
namespace Test {{
  entity User;
  entity Doc;
  action "{escaped}" appliesTo {{
    principal: [User], resource: [Doc],
    context: {{ input: {{ doc: String }} }}
  }};
  action "Other" appliesTo {{
    principal: [User], resource: [Doc],
    context: {{ input: {{ doc: String }} }}
  }};
}}
"#
    );
    let policy = format!(
        r#"
permit (principal, action, resource);

forbid (principal, action == Test::Action::"{escaped}", resource)
when temporal {{ formerly within 1h Test::Action::"{escaped}"::request{{ input.doc: "d1" }} }};
"#
    );
    (schema, policy)
}

/// Event-derived and request-derived action identities must agree.
#[test]
fn a_leaf_scoped_to_a_non_canonically_encoded_action_id_is_computed() {
    for (action_id, escaped) in AWKWARD_ACTION_IDS {
        let (schema_src, policy_src) = awkward_fixture(escaped);
        let lowered = lower_with(&schema_src, &policy_src);
        let leaf_ids = leaf_ids(&lowered);
        assert_eq!(
            leaf_ids.len(),
            1,
            "one leaf per fixture, for id {action_id:?}"
        );

        // Found by the *raw* id in the parsed schema — no formatting, no
        // re-parsing, and proof the escaped literal denotes this id.
        assert_eq!(
            leaf_id_for(&lowered, &action_uid(lowered.cedar_schema(), action_id)),
            leaf_ids[0],
            "the lowering's expansion of the scope must round-trip {action_id:?}"
        );

        let history = [
            request_at(1_000, action_id, "d1"),
            request_at(1_002, action_id, "d1"),
        ];
        let unsliced = Replay::new(lower_with(&schema_src, &policy_src))
            .unsliced()
            .feed(&history);
        let sliced = Replay::new(lower_with(&schema_src, &policy_src)).feed(&history);

        assert_computed(&sliced.last(), &unsliced.last(), &[&leaf_ids[0]]);
        assert_eq!(sliced.last().bindings, only(&leaf_ids, &[&leaf_ids[0]]));
        assert_eq!(
            sliced.decision(),
            Decision::Deny,
            "the forbid scoped to {action_id:?} fires — so the event the engine \
             keyed on and the request the frontend built for Cedar name the same \
             action"
        );

        // The negative, per id: a different action in the same fixture reads
        // nothing.
        let other_history = [
            request_at(1_000, action_id, "d1"),
            request_at(1_002, "Other", "d1"),
        ];
        let unsliced = Replay::new(lower_with(&schema_src, &policy_src))
            .unsliced()
            .feed(&other_history);
        let sliced = Replay::new(lower_with(&schema_src, &policy_src)).feed(&other_history);
        assert_computed(
            &sliced.last(),
            &unsliced.last(),
            &[], // a different action makes the rule inapplicable
        );
        assert_eq!(sliced.decision(), Decision::Allow);
    }
}

// ─── Partitioned mode ────────────────────────────────────────────────

/// Partitioned evaluation applies the same slicing plan.
#[test]
fn slicing_applies_in_partitioned_mode_too() {
    let lowered = lower();
    let leaf_ids = leaf_ids(&lowered);
    let read_leaf = leaf_id_for(&lowered, &action_uid(lowered.cedar_schema(), "Read"));
    assert!(
        !lowered.partition_keys().is_empty(),
        "the default event schema pins, so `partition_temporal` is not a no-op"
    );

    // Non-vacuity, in this mode: both leaves are genuinely `true` per shard.
    let history = [
        request_at(1_000, "Read", "d1"),
        request_at(1_001, "Delete", "d1"),
        request_at(1_002, "Read", "d1"),
    ];
    let unsliced = Replay::new(lower()).partitioned().unsliced().feed(&history);
    unsliced.engine.with(|engine| {
        assert!(
            engine.is_partitioned(),
            "the frontend installed the pins, so this lane really is partitioned"
        );
        assert_eq!(
            engine.shard_count(),
            leaf_ids.len(),
            "one live shard per leaf — every fixture event carries the same pin value"
        );
    });
    assert_computed(
        &unsliced.last(),
        &unsliced.last(),
        &all_of(&leaf_ids), // the unsliced partitioned path computes every leaf
    );

    // A `Read` request reads one leaf: exactly that one is computed, per shard.
    let sliced = Replay::new(lower()).partitioned().feed(&history);
    sliced
        .engine
        .with(|engine| assert!(engine.is_partitioned()));
    assert_computed(&sliced.last(), &unsliced.last(), &[&read_leaf]);
    assert_eq!(sliced.last().bindings, only(&leaf_ids, &[&read_leaf]));
    assert_eq!(sliced.decision(), unsliced.decision());
    assert_eq!(sliced.decision(), Decision::Deny);

    // And an action that reads nothing still computes nothing.
    let list_history = [
        request_at(1_000, "Read", "d1"),
        request_at(1_001, "Delete", "d1"),
        request_at(1_002, "List", "other"),
    ];
    let unsliced = Replay::new(lower())
        .partitioned()
        .unsliced()
        .feed(&list_history);
    let sliced = Replay::new(lower()).partitioned().feed(&list_history);
    assert_computed(
        &sliced.last(),
        &unsliced.last(),
        &[], // an action that reads no leaf computes nothing here either
    );
    assert_eq!(sliced.last().bindings, only(&leaf_ids, &[]));
    assert_eq!(sliced.decision(), unsliced.decision());
    assert_eq!(sliced.decision(), Decision::Allow);
}

// ─── Action identity, which the whole map keys on ────────────────────

/// Escaped action ids lower to their raw structural identity.
#[test]
fn an_action_id_needing_escaping_lowers() {
    let (schema_src, policy_src) = awkward_fixture(r#"say \"hi\""#);
    // The *schema* accepts it — the escaped literal parses to the raw id.
    let schema = PolicySchema::from_cedarschema_str(&schema_src).expect("schema builds");
    let lowered = LoweredPolicySet::from_str(&policy_src, &ServiceSchema::defaults(), &schema)
        .expect("the frontend lowers a scope naming an escaped action id");

    let leaf_ids = leaf_ids(&lowered);
    assert_eq!(leaf_ids.len(), 1, "one leaf per fixture");
    assert_eq!(
        leaf_id_for(&lowered, &action_uid(lowered.cedar_schema(), r#"say "hi""#)),
        leaf_ids[0],
        "the expanded scope is keyed by the unescaped id"
    );
}

/// Demonstrate why action identity must not be reconstructed from strings.
#[test]
fn the_string_shortcuts_a_scope_replica_took_really_do_diverge() {
    // (a) Recovering the id from a combined `Ns::Action::id` string splits on the
    //     last `::`, so an id containing `::` is mangled before the map sees it.
    //     `Event::builder_for` takes the parts, so it survives — which is why
    //     `request_at` uses it.
    let mangled = Event::builder("Test::Action::Read::Archive", "request").build();
    assert_eq!(mangled.action(), "Archive");
    assert_eq!(mangled.namespace(), ["Test", "Action", "Read"]);
    let intact = Event::builder_for(&["Test", "Action"], "Read::Archive", "request").build();
    assert_eq!(intact.action(), "Read::Archive");
    assert_eq!(intact.namespace(), ["Test", "Action"]);

    // (b) Concatenating a raw id into `Ns::Action::"<id>"` is not the canonical
    //     rendering once the id needs escaping — so a text compare against the
    //     policy source, which must be canonical to parse, misses. The uid here
    //     is the schema's own, so this is Cedar's rendering of the real action.
    let quoted = r#"say "hi""#;
    let (schema_src, policy_src) = awkward_fixture(r#"say \"hi\""#);
    let lowered = lower_with(&schema_src, &policy_src);
    let uid = action_uid(lowered.cedar_schema(), quoted);
    assert_ne!(format!("Test::Action::\"{quoted}\""), uid.to_string());
    assert_eq!(uid.to_string(), r#"Test::Action::"say \"hi\"""#);
    // The id itself is untouched by that escaping: the divergence is only in the
    // rendering, which is precisely why the comparison has to be structural.
    assert_eq!(uid.id().unescaped(), quoted);
}
