//! Corpus differential for action-scope expansion in `LocalTemporalEngine`.
//!
//! Each `action == <uid>` scope is rewritten without changing applicability:
//! a singleton list, a group containing the action, a nested group, or a mixed
//! action/group list. The committed corpus output therefore remains the oracle.
//!
//! Each mutation runs through the full `Authorizer` stack with slicing enabled
//! and disabled. The test checks the committed verdict stream, exact agreement
//! between the engine's computed count and `DecisionLeafMap`, complete bindings,
//! and evidence that meaningful leaves were actually skipped. A disjoint-group
//! negative control proves the harness detects meaning-changing rewrites.
//!
//! The sibling `dogwood-language` test covers scope expansion itself; this test
//! covers the consumer boundary: map construction during `prepare`, map lookup
//! during `evaluate`, and snapshot restoration into a freshly prepared engine.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use dogwood_language::cedar::Schema;
use dogwood_language::corpus::{CorpusTrace, TemporalCase, TemporalCategory, temporal_cases};
use dogwood_language::{
    ActionRef, ActionScope, Authorizer, Decision, Error, Event, EventSignature, LoweredPolicySet,
    PartitionKey, PolicySchema, ServiceSchema, TemporalBindings, TemporalEngine, TemporalField,
    parse_trace,
};
use dogwood_local_engine::LocalTemporalEngine;

/// Shared by the existing corpus differentials for global-trace semantics.
const UNPINNED_EVENT_SCHEMA: &str = r#"
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

/// Cases already containing this prefix are excluded from mutation.
const MUT: &str = "__dw_mut_";

// ─── The case under mutation ─────────────────────────────────────────

#[derive(Clone)]
struct Case {
    name: String,
    policy: String,
    schema: String,
    event_schema: Option<String>,
    traces: Vec<CorpusTrace>,
}

impl From<&TemporalCase> for Case {
    fn from(case: &TemporalCase) -> Self {
        Case {
            name: case.name.clone(),
            policy: case.policy_src.clone(),
            schema: case.schema_src.clone(),
            event_schema: case.event_schema_src.clone(),
            traces: case.traces.clone(),
        }
    }
}

impl Case {
    fn lower(&self) -> Result<LoweredPolicySet, String> {
        let policy_schema =
            PolicySchema::from_cedarschema_str(&self.schema).map_err(|e| format!("{e:?}"))?;
        let service = ServiceSchema::builder()
            .event_schema_str(
                self.event_schema
                    .as_deref()
                    .unwrap_or(UNPINNED_EVENT_SCHEMA),
            )
            .build()
            .map_err(|e| format!("{e:?}"))?;
        LoweredPolicySet::from_str(&self.policy, &service, &policy_schema)
            .map_err(|e| format!("{e:?}"))
    }
}

/// Map in parallel while preserving input order.
fn par_map<I: Sync, T: Send>(items: &[I], f: impl Fn(&I) -> T + Sync) -> Vec<T> {
    let nthreads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(items.len().max(1));
    let chunk_size = items.len().div_ceil(nthreads).max(1);
    let f = &f;
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(f).collect::<Vec<T>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker thread panicked"))
            .collect()
    })
}

/// Normalize the corpus verdict format.
fn norm(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

// ─── Finding the `action ==` scopes in a policy text ─────────────────
//
// Kept textual so the whole stack reparses each mutated source case.

#[derive(Clone, Debug)]
struct Site {
    span: Range<usize>,
    /// Preserved verbatim to avoid re-rendering escapes.
    uid: String,
}

fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn commented(text: &str, at: usize) -> bool {
    let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    text[line_start..at].contains("//")
}

fn string_end(text: &str, at: usize) -> Option<usize> {
    let b = text.as_bytes();
    let mut i = at + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Return the end of a Cedar action UID such as `A::Action::"id"`.
fn action_uid_end(text: &str, at: usize) -> Option<usize> {
    let b = text.as_bytes();
    let mut i = at;
    let last;
    loop {
        let seg = i;
        while i < b.len() && ident_byte(b[i]) {
            i += 1;
        }
        if i == seg {
            return None;
        }
        if !text[i..].starts_with("::") {
            return None;
        }
        i += 2;
        if b.get(i) == Some(&b'"') {
            last = &text[seg..i - 2];
            break;
        }
    }
    (last == "Action").then(|| string_end(text, i)).flatten()
}

fn sites(policy: &str) -> Vec<Site> {
    let b = policy.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = policy[from..].find("action") {
        let at = from + rel;
        from = at + "action".len();
        // Reject identifiers containing "action" and field access.
        if at > 0 && (ident_byte(b[at - 1]) || b[at - 1] == b'.') {
            continue;
        }
        if commented(policy, at) {
            continue;
        }
        let mut i = from;
        while b.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
            i += 1;
        }
        if !policy[i..].starts_with("==") {
            continue;
        }
        i += 2;
        while b.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
            i += 1;
        }
        if let Some(end) = action_uid_end(policy, i) {
            out.push(Site {
                span: at..end,
                uid: policy[i..end].to_string(),
            });
            from = end;
        }
    }
    out
}

impl Site {
    /// Return the action id using the policy's original spelling.
    fn spelling(&self) -> Option<&str> {
        let quote = self.uid.find('"')?;
        self.uid.get(quote + 1..self.uid.len() - 1)
    }
}

// ─── Locating the declarations a mutation rewrites ───────────────────

/// Return the body of the simple namespace layout accepted by the rewriter.
fn namespace_interior(schema: &str, ns: &str) -> Option<Range<usize>> {
    let mut off = 0;
    let mut start = None;
    for line in schema.split_inclusive('\n') {
        let end = off + line.len();
        match start {
            None => {
                if let Some(rest) = line.trim().strip_prefix("namespace ")
                    && rest.trim().trim_end_matches('{').trim() == ns
                    && line.contains('{')
                {
                    start = Some(end);
                }
            }
            Some(start) if line.starts_with('}') => return Some(start..off),
            Some(_) => {}
        }
        off = end;
    }
    None
}

/// Find a declaration terminator outside nested brackets and strings.
fn decl_end(text: &str, at: usize) -> Option<usize> {
    let b = text.as_bytes();
    let (mut i, mut depth) = (at, 0i32);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = string_end(text, i)?;
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b';' if depth == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn bracket_close(text: &str, open: usize) -> Option<usize> {
    let b = text.as_bytes();
    let (mut i, mut depth) = (open, 0i32);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = string_end(text, i)?;
                continue;
            }
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

struct Decl {
    after_id: usize,
    parents_close: Option<usize>,
    applies_to: Range<usize>,
}

fn action_decl(schema: &str, interior: &Range<usize>, spelling: &str) -> Option<Decl> {
    let needle = format!("action \"{spelling}\"");
    let rel = schema[interior.clone()].find(&needle)?;
    let after_id = interior.start + rel + needle.len();
    let end = decl_end(schema, after_id)?;
    if end > interior.end {
        return None;
    }
    let rest = &schema[after_id..end];

    // Do not guess how to rewrite an unbracketed parent.
    let parents_close = match rest.trim_start().strip_prefix("in") {
        Some(after_in) => {
            let open_rel = after_in.find('[')?;
            if !after_in[..open_rel].trim().is_empty() {
                return None;
            }
            let lead = rest.len() - rest.trim_start().len();
            Some(bracket_close(
                schema,
                after_id + lead + "in".len() + open_rel,
            )?)
        }
        None => None,
    };

    let applies_rel = rest.find("appliesTo")?;
    Some(Decl {
        after_id,
        parents_close,
        applies_to: (after_id + applies_rel)..end,
    })
}

fn splice(text: &str, edits: &[(usize, String)]) -> String {
    assert!(
        edits.windows(2).all(|w| w[0].0 <= w[1].0),
        "splice edits must be sorted by offset"
    );
    let mut out = String::with_capacity(text.len() + 512);
    let mut cursor = 0;
    for (at, insert) in edits {
        out.push_str(&text[cursor..*at]);
        out.push_str(insert);
        cursor = *at;
    }
    out.push_str(&text[cursor..]);
    out
}

fn declared_namespaces(schema: &str) -> Vec<String> {
    schema
        .lines()
        .filter_map(|l| l.trim().strip_prefix("namespace "))
        .map(|rest| rest.trim().trim_end_matches('{').trim().to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

/// Require the simple namespace layout assumed by the textual rewriter.
fn textually_rewritable(case: &Case) -> bool {
    if declared_namespaces(&case.schema).is_empty() {
        return false;
    }
    case.schema.lines().all(|l| {
        let body = l.trim_start();
        body.len() != l.len()
            || body.is_empty()
            || body.starts_with("namespace ")
            || body.starts_with('}')
            || body.starts_with("//")
    })
}

// ─── The shapes ──────────────────────────────────────────────────────

/// A scope shape to rewrite `action == <uid>` into.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Shape {
    /// `action in [<uid>]`.
    Singleton,
    /// `action in [<G>]`, `<uid>` a member of `<G>` beside an extraneous one.
    Group,
    /// `action in [<G1>]`, `<G1>` ∋ `<G2>` ∋ `<uid>`, noise at both levels.
    NestedGroup,
    /// `action in [<uid>, <G_x>]`, `<G_x>` reaching only extraneous actions.
    MixedList,
    /// The negative control: `action in [<G_z>]` where `<G_z>` does **not**
    /// contain `<uid>`. This one really does change applicability.
    Disjoint,
}

impl Shape {
    fn tag(self) -> &'static str {
        match self {
            Shape::Singleton => "M1 singleton list",
            Shape::Group => "M2 group",
            Shape::NestedGroup => "M3 nested group",
            Shape::MixedList => "M4 mixed list",
            Shape::Disjoint => "negative control (disjoint group)",
        }
    }
}

struct Mutation {
    case: Case,
    shape: Shape,
    target: ActionRef,
}

impl Mutation {
    fn label(&self) -> String {
        format!("{} [{}]", self.case.name, self.shape.tag())
    }
}

/// Build one mutation or return its ineligibility reason.
fn mutate(
    origin: &Case,
    site: &Site,
    target: &ActionRef,
    shape: Shape,
) -> Result<Mutation, &'static str> {
    let rewritten = |scope: &str, schema: String| {
        let mut policy = origin.policy.clone();
        policy.replace_range(site.span.clone(), scope);
        Mutation {
            case: Case {
                name: origin.name.clone(),
                policy,
                schema,
                event_schema: origin.event_schema.clone(),
                traces: origin.traces.clone(),
            },
            shape,
            target: target.clone(),
        }
    };
    // Singleton lists require no schema surgery.
    if shape == Shape::Singleton {
        return Ok(rewritten(
            &format!("action in [{}]", site.uid),
            origin.schema.clone(),
        ));
    }

    let ns = target
        .namespace
        .as_deref()
        .ok_or("the pinned action is unnamespaced, so a group has no namespace to live in")?;
    let interior = namespace_interior(&origin.schema, ns)
        .ok_or("the schema has no `namespace <ns> { … }` block to append declarations to")?;
    let spelling = site
        .spelling()
        .ok_or("the site's uid has no string-literal id")?;
    let decl = action_decl(&origin.schema, &interior, spelling)
        .ok_or("the pinned action's declaration is not in the rewritable shape")?;
    let applies_to = origin.schema[decl.applies_to.clone()].trim().to_string();

    let uid = |name: &str| format!("{ns}::Action::\"{MUT}{name}\"");
    // Clone `appliesTo` so generated request actions validate.
    let noise = |name: &str, parent: &str| {
        format!("\n  action \"{MUT}{name}\" in [Action::\"{MUT}{parent}\"] {applies_to};\n")
    };
    let group = |name: &str| format!("\n  action \"{MUT}{name}\";\n");

    let (scope, parent, appended): (String, Option<&str>, String) = match shape {
        Shape::Singleton => unreachable!("returned above, it needs no schema surgery"),
        Shape::Group => (
            format!("action in [{}]", uid("g")),
            Some("g"),
            format!("{}{}", group("g"), noise("x_a", "g")),
        ),
        Shape::NestedGroup => (
            format!("action in [{}]", uid("g1")),
            // Membership is declared on the member: `g1 -> g2 -> <uid>`.
            Some("g2"),
            format!(
                "{}\n  action \"{MUT}g2\" in [Action::\"{MUT}g1\"];\n{}{}",
                group("g1"),
                noise("x_a", "g1"),
                noise("x_b", "g2"),
            ),
        ),
        Shape::MixedList => (
            format!("action in [{}, {}]", site.uid, uid("gx")),
            None,
            format!("{}{}", group("gx"), noise("x_c", "gx")),
        ),
        Shape::Disjoint => (
            format!("action in [{}]", uid("gz")),
            None,
            format!("{}{}", group("gz"), noise("x_z", "gz")),
        ),
    };

    let mut edits: Vec<(usize, String)> = Vec::new();
    if let Some(parent) = parent {
        let insert = format!("Action::\"{MUT}{parent}\"");
        match decl.parents_close {
            Some(close) => edits.push((close, format!(", {insert}"))),
            None => edits.push((decl.after_id, format!(" in [{insert}]"))),
        }
    }
    edits.push((interior.end, appended));
    edits.sort_by_key(|(at, _)| *at);
    Ok(rewritten(&scope, splice(&origin.schema, &edits)))
}

// ─── The engine, and the observation seam over it ────────────────────

/// Shared handle exposing engine diagnostics after `Authorizer` takes ownership.
#[derive(Clone)]
struct EngineHandle(Arc<Mutex<LocalTemporalEngine>>);

impl EngineHandle {
    /// Disable slicing before `prepare` so the oracle builds no map.
    fn new(slicing: bool) -> Self {
        let mut engine = LocalTemporalEngine::new();
        if !slicing {
            engine.disable_slicing();
        }
        EngineHandle(Arc::new(Mutex::new(engine)))
    }

    /// The lock is held only for this call.
    fn with<T>(&self, f: impl FnOnce(&mut LocalTemporalEngine) -> T) -> T {
        f(&mut self.0.lock().expect("the engine lock is never poisoned"))
    }
}

#[derive(Clone, Debug)]
struct Pass {
    action: String,
    namespace: Vec<String>,
    computed: u64,
    bindings: TemporalBindings,
}

/// Delegates to the real engine while recording each decision.
struct Spy {
    engine: EngineHandle,
    last: Option<Event>,
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
        self.last = Some(event.clone());
        self.engine.with(|e| e.observe(event));
    }

    fn evaluate(&mut self) -> Result<TemporalBindings, String> {
        let (bindings, computed) = self.engine.with(|e| {
            let before = e.verdicts_computed();
            let bindings = e.evaluate();
            (bindings, e.verdicts_computed() - before)
        });
        let bindings = bindings?;
        let event = self
            .last
            .as_ref()
            .expect("evaluate follows observe (TemporalEngine's contract)");
        self.passes
            .lock()
            .expect("the pass lock is never poisoned")
            .push(Pass {
                action: event.action().to_string(),
                namespace: event.namespace().to_vec(),
                computed,
                bindings: bindings.clone(),
            });
        Ok(bindings)
    }

    // Delegated, not defaulted: a `false` here would silently downgrade the
    // engine's advertised capability.
    fn supports_partitioning(&self) -> bool {
        self.engine.with(|e| e.supports_partitioning())
    }

    fn set_partition_keys(&mut self, keys: &[PartitionKey]) {
        self.engine.with(|e| e.set_partition_keys(keys));
    }
}

struct Run {
    verdicts: Vec<String>,
    passes: Vec<Pass>,
    unresolved: Vec<String>,
}

/// Replay through `Authorizer` and capture slicing diagnostics.
fn replay(lowered: LoweredPolicySet, events: &[Event], slicing: bool) -> Result<Run, String> {
    let engine = EngineHandle::new(slicing);
    let passes = Arc::new(Mutex::new(Vec::new()));
    let spy = Spy {
        engine: engine.clone(),
        last: None,
        passes: Arc::clone(&passes),
    };
    let mut authorizer = Authorizer::builder(lowered)
        .temporal_engine(spy)
        .build()
        .map_err(|e| format!("the authorizer did not build: {e:?}"))?;
    let unresolved = engine.with(|e| {
        e.unresolved_action_scopes()
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    });
    let mut verdicts = Vec::new();
    for (i, event) in events.iter().enumerate() {
        if let Some(response) = authorizer.is_authorized(event) {
            let allowed = response.decision() == Decision::Allow;
            verdicts.push(format!(
                "@{} (time point {i}): {allowed}",
                event.timestamp()
            ));
        }
    }
    Ok(Run {
        verdicts,
        passes: passes
            .lock()
            .expect("the pass lock is never poisoned")
            .clone(),
        unresolved,
    })
}

// ─── Eligibility ─────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct Census {
    cases_loaded: usize,
    cases_eligible: usize,
    skips: BTreeMap<&'static str, usize>,
}

impl Census {
    fn report(&self, sites: usize) -> String {
        let mut out = format!(
            "{} passing corpus cases loaded, {} eligible, {sites} mutable `action ==` sites",
            self.cases_loaded, self.cases_eligible
        );
        for (why, n) in &self.skips {
            out.push_str(&format!("\n  skipped {n}: {why}"));
        }
        out
    }
}

struct Candidate {
    case: usize,
    site: Site,
    target: ActionRef,
}

/// Cached corpus cases and mutable sites.
struct Corpus {
    cases: Vec<Case>,
    candidates: Vec<Candidate>,
    census: Census,
}

fn loaded() -> &'static Corpus {
    static CORPUS: std::sync::OnceLock<Corpus> = std::sync::OnceLock::new();
    CORPUS.get_or_init(build)
}

fn build() -> Corpus {
    let cases: Vec<Case> = temporal_cases()
        .iter()
        .filter(|c| c.category == TemporalCategory::Passing)
        .map(Case::from)
        .collect();
    let scanned = par_map(&cases, scan);

    let mut candidates = Vec::new();
    let mut census = Census {
        cases_loaded: cases.len(),
        ..Census::default()
    };
    for (i, (found, skips)) in scanned.into_iter().enumerate() {
        if !found.is_empty() {
            census.cases_eligible += 1;
        }
        for (site, target) in found {
            candidates.push(Candidate {
                case: i,
                site,
                target,
            });
        }
        for why in skips {
            *census.skips.entry(why).or_default() += 1;
        }
    }
    Corpus {
        cases,
        candidates,
        census,
    }
}

type Scan = (Vec<(Site, ActionRef)>, Vec<&'static str>);

/// Keep only sites whose baseline matches the corpus and whose singleton-list
/// rewrite preserves the exact target action.
fn scan(case: &Case) -> Scan {
    let mut skips = Vec::new();
    if !textually_rewritable(case) {
        skips.push("the schema declares something outside a namespace, so it cannot be spliced");
        return (Vec::new(), skips);
    }
    if case.policy.contains(MUT)
        || case.schema.contains(MUT)
        || case.traces.iter().any(|t| t.trace_log.contains(MUT))
    {
        skips.push("the case already mentions the synthesized-name prefix");
        return (Vec::new(), skips);
    }
    let found = sites(&case.policy);
    if found.is_empty() {
        skips.push("no `action ==` scope to mutate");
        return (Vec::new(), skips);
    }
    let Ok(lowered) = case.lower() else {
        skips.push("the committed case does not lower (left to its own harness)");
        return (Vec::new(), skips);
    };
    if lowered.temporal_fields().next().is_none() {
        skips.push("the case hoists no temporal leaf, so slicing has nothing to decide");
        return (Vec::new(), skips);
    }
    if !baseline_matches_committed(case) {
        skips.push(
            "this engine does not reproduce the committed stream for the UNMUTATED case, so \
             the committed output is not usable as ground truth here",
        );
        return (Vec::new(), skips);
    }
    let groups: BTreeSet<String> = lowered
        .cedar_schema()
        .action_groups()
        .map(|uid| uid.to_string())
        .collect();

    let mut out = Vec::new();
    for site in found {
        // Probe the singleton rewrite instead of parsing rule boundaries.
        let Some(target) = moved_leaf_target(case, &lowered, &site) else {
            skips.push("the site's own rule hoists no temporal leaf");
            continue;
        };
        let rendered = match target.namespace.as_deref() {
            Some(ns) => format!("{ns}::Action::\"{}\"", target.id),
            None => format!("Action::\"{}\"", target.id),
        };
        if groups.contains(&rendered) {
            skips.push(
                "the pinned action is itself an action group, so a list scope would reach its \
                 members and widen applicability",
            );
            continue;
        }
        out.push((site, target));
    }
    (out, skips)
}

/// Require the unmutated engine to reproduce the committed oracle.
fn baseline_matches_committed(case: &Case) -> bool {
    for trace in &case.traces {
        let Ok(events) = parse_trace(&trace.trace_log) else {
            return false;
        };
        let Ok(lowered) = case.lower() else {
            return false;
        };
        let Ok(run) = replay(lowered, &events, true) else {
            return false;
        };
        if norm(&run.verdicts.join("\n")) != norm(&trace.expected) {
            return false;
        }
    }
    true
}

/// Return the sole leaf target moved by the singleton-list rewrite. Reject a
/// rewrite that changes the expanded target set.
fn moved_leaf_target(case: &Case, lowered: &LoweredPolicySet, site: &Site) -> Option<ActionRef> {
    let before: Vec<&TemporalField> = lowered.temporal_fields().collect();
    let target = before
        .iter()
        .filter_map(|f| f.action.concrete())
        .next()?
        .clone();
    let probe = mutate(case, site, &target, Shape::Singleton).ok()?;
    let after_set = probe.case.lower().ok()?;
    let after: Vec<&TemporalField> = after_set.temporal_fields().collect();
    if before.len() != after.len() {
        return None;
    }
    let moved: Vec<(&&TemporalField, &&TemporalField)> = before
        .iter()
        .zip(&after)
        .filter(|(a, b)| a.id == b.id && a.action != b.action)
        .collect();
    let [(was, now)] = moved.as_slice() else {
        return None;
    };
    let pinned = was.action.concrete()?.clone();
    match &now.action {
        ActionScope::List(list) if list.as_slice() == [pinned.clone()] => {}
        _ => return None,
    }
    (now.target_actions == [pinned.clone()]).then_some(pinned)
}

// ─── What one mutation must prove ────────────────────────────────────

/// Non-vacuity counters accumulated across a sweep.
#[derive(Default, Debug, Clone)]
struct Sweep {
    mutations: usize,
    replays: usize,
    decisions: usize,
    decisions_on_target: usize,
    unsliced_leaves: u64,
    sliced_leaves: u64,
    sliced_decisions: usize,
    zero_leaf_decisions: usize,
    /// Decisions that skipped a leaf whose unsliced value was `true`.
    suppressed_true_decisions: usize,
}

impl Sweep {
    fn merge(&mut self, other: &Sweep) {
        self.mutations += other.mutations;
        self.replays += other.replays;
        self.decisions += other.decisions;
        self.decisions_on_target += other.decisions_on_target;
        self.unsliced_leaves += other.unsliced_leaves;
        self.sliced_leaves += other.sliced_leaves;
        self.sliced_decisions += other.sliced_decisions;
        self.zero_leaf_decisions += other.zero_leaf_decisions;
        self.suppressed_true_decisions += other.suppressed_true_decisions;
    }
}

/// Compare structurally rather than re-rendering a UID.
fn pass_is_on(pass: &Pass, target: &ActionRef) -> bool {
    let ns = target.namespace.as_deref().unwrap_or_default();
    pass.action == target.id && pass.namespace.join("::") == format!("{ns}::Action")
}

/// Replay one mutation through sliced and unsliced lanes.
fn check_mutation(m: &Mutation) -> (Sweep, Vec<String>) {
    let mut sweep = Sweep {
        mutations: 1,
        ..Sweep::default()
    };
    let mut fail = Vec::new();

    let lowered = match m.case.lower() {
        Ok(l) => l,
        Err(e) => {
            // Validation failure is evidence of under-expansion, not ineligibility.
            fail.push(format!(
                "{}: the mutated case does not lower — the rewritten scope was not expanded \
                 to the pinned action: {e}",
                m.label()
            ));
            return (sweep, fail);
        }
    };
    let all_ids: BTreeSet<String> = lowered.temporal_fields().map(|f| f.id.clone()).collect();
    // Bare-action leaves are intentionally unresolved and are not part of this
    // mutation's expansion check.
    let moved: BTreeSet<String> = lowered
        .temporal_fields()
        .filter(|f| f.action != ActionScope::Unconstrained)
        .filter(|f| f.target_actions.iter().any(|a| *a == m.target))
        .map(|f| f.id.clone())
        .collect();
    if moved.is_empty() {
        fail.push(format!(
            "{}: no leaf's expanded scope reaches {} — the rewritten scope lost the action \
             it was built around",
            m.label(),
            m.target.id
        ));
        return (sweep, fail);
    }
    let map = lowered.leaf_map();

    for trace in &m.case.traces {
        let events = match parse_trace(&trace.trace_log) {
            Ok(e) => e,
            Err(e) => {
                fail.push(format!(
                    "{}: trace_{}: parse: {e:?}",
                    m.label(),
                    trace.index
                ));
                continue;
            }
        };
        let (sliced, unsliced) = match (m.case.lower(), m.case.lower()) {
            (Ok(a), Ok(b)) => (replay(a, &events, true), replay(b, &events, false)),
            _ => {
                fail.push(format!(
                    "{}: trace_{}: re-lowering failed",
                    m.label(),
                    trace.index
                ));
                continue;
            }
        };
        let (sliced, unsliced) = match (sliced, unsliced) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => {
                fail.push(format!("{}: trace_{}: {e}", m.label(), trace.index));
                continue;
            }
        };
        sweep.replays += 1;
        let at = format!("{}: trace_{}", m.label(), trace.index);

        // The shipping configuration must preserve the committed stream.
        if norm(&sliced.verdicts.join("\n")) != norm(&trace.expected) {
            fail.push(format!(
                "{at}: the sliced stream does not match the committed expected_{}.out\n  \
                 got: {:?}\n  exp: {:?}",
                trace.index,
                norm(&sliced.verdicts.join("\n")),
                norm(&trace.expected)
            ));
            continue;
        }
        // The kill switch must not change decisions.
        if sliced.verdicts != unsliced.verdicts {
            fail.push(format!(
                "{at}: SLICING CHANGED A VERDICT\n  sliced:   {:?}\n  unsliced: {:?}",
                sliced.verdicts, unsliced.verdicts
            ));
            continue;
        }
        if sliced.passes.len() != unsliced.passes.len() {
            fail.push(format!(
                "{at}: the two lanes reached a different number of decision points ({} vs {})",
                sliced.passes.len(),
                unsliced.passes.len()
            ));
            continue;
        }

        // Falling back would preserve decisions without testing expansion.
        for id in &sliced.unresolved {
            if moved.contains(id) {
                fail.push(format!(
                    "{at}: leaf {id} is in the engine's unresolved set, so it is computed at \
                     every decision instead of being keyed by expansion"
                ));
            }
        }

        for (k, pass) in sliced.passes.iter().enumerate() {
            let unsliced_pass = &unsliced.passes[k];
            sweep.decisions += 1;
            sweep.sliced_leaves += pass.computed;
            sweep.unsliced_leaves += unsliced_pass.computed;

            // Hold the engine to the map's exact answer, not an upper bound.
            let predicted: BTreeSet<String> = match map.needed_for(&events_decision(&events, pass))
            {
                Some(ids) => (*ids).clone(),
                None => all_ids.clone(),
            };
            if pass.computed != predicted.len() as u64 {
                fail.push(format!(
                    "{at}: decision {k} ({}): the engine computed {} leaf verdict(s), the map \
                     predicts {} ({predicted:?})",
                    pass.action,
                    pass.computed,
                    predicted.len()
                ));
                continue;
            }
            if unsliced_pass.computed != all_ids.len() as u64 {
                fail.push(format!(
                    "{at}: decision {k} ({}): the kill switch computed {} of {} leaves — it is \
                     not computing everything",
                    pass.action,
                    unsliced_pass.computed,
                    all_ids.len()
                ));
                continue;
            }
            if pass.bindings.keys().cloned().collect::<BTreeSet<_>>() != all_ids {
                fail.push(format!(
                    "{at}: decision {k}: not every installed leaf was bound"
                ));
                continue;
            }

            if pass_is_on(pass, &m.target) {
                sweep.decisions_on_target += 1;
                // The target action must retain every moved leaf.
                for id in moved.difference(&predicted) {
                    fail.push(format!(
                        "{at}: decision {k}: the map does not key leaf {id} under {} — the \
                         rewritten scope was not expanded to it",
                        m.target.id
                    ));
                }
            }

            let skipped: Vec<&String> = all_ids.difference(&predicted).collect();
            if skipped.is_empty() {
                continue;
            }
            sweep.sliced_decisions += 1;
            if pass.computed == 0 {
                sweep.zero_leaf_decisions += 1;
            }
            // A skipped `true` leaf proves the verdict comparison is meaningful.
            if skipped
                .iter()
                .any(|id| unsliced_pass.bindings.get(*id) == Some(&true))
            {
                sweep.suppressed_true_decisions += 1;
            }
            for id in skipped {
                if pass.bindings.get(id) != Some(&false) {
                    fail.push(format!(
                        "{at}: decision {k}: skipped leaf {id} was bound {:?}, not false",
                        pass.bindings.get(id)
                    ));
                }
            }
        }
    }
    (sweep, fail)
}

/// Find an event with the action recorded by this pass.
fn events_decision<'a>(events: &'a [Event], pass: &Pass) -> &'a Event {
    events
        .iter()
        .find(|e| e.action() == pass.action && e.namespace() == pass.namespace.as_slice())
        .expect("the pass's action came from an event in this trace")
}

// ─── The sweeps ──────────────────────────────────────────────────────

/// Select deterministically by index, then mutate and replay.
#[track_caller]
fn sweep(shape: Shape, every: usize) -> Sweep {
    let loaded = loaded();
    let mut skipped: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mutations: Vec<Mutation> = loaded
        .candidates
        .iter()
        .step_by(every)
        .filter_map(
            |c| match mutate(&loaded.cases[c.case], &c.site, &c.target, shape) {
                Ok(m) => Some(m),
                Err(why) => {
                    *skipped.entry(why).or_default() += 1;
                    None
                }
            },
        )
        .collect();

    let mut sweep = Sweep::default();
    let mut failures = Vec::new();
    for (s, f) in par_map(&mutations, check_mutation) {
        sweep.merge(&s);
        failures.extend(f);
    }
    let cases = mutations
        .iter()
        .map(|m| m.case.name.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    eprintln!(
        "{}: {} mutations over {cases} cases (every {every} of {} candidates)\n  {}\n  {:?}",
        shape.tag(),
        sweep.mutations,
        loaded.candidates.len(),
        loaded.census.report(loaded.candidates.len()),
        sweep,
    );
    for (why, n) in &skipped {
        eprintln!("  {n} unmutated: {why}");
    }
    assert!(
        failures.is_empty(),
        "{}: {} failure(s):\n\n{}",
        shape.tag(),
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n\n")
    );
    sweep
}

/// Floors prevent corpus drift from making a sweep vacuous.
#[track_caller]
fn assert_not_vacuous(s: &Sweep, shape: Shape, mutations: usize, replays: usize) {
    assert!(
        s.mutations >= mutations,
        "{}: only {} mutations (floor {mutations}): {s:?}",
        shape.tag(),
        s.mutations
    );
    assert!(
        s.replays >= replays,
        "{}: only {} sliced mutation-replays (floor {replays}): {s:?}",
        shape.tag(),
        s.replays
    );
    assert!(
        s.decisions_on_target > 0,
        "{}: no decision was taken on a mutated scope's own action, so A2's map check \
         examined nothing: {s:?}",
        shape.tag()
    );
    assert!(
        s.sliced_leaves < s.unsliced_leaves,
        "{}: the sliced lane computed no fewer leaves than the kill-switch lane, so slicing \
         skipped nothing anywhere and this sweep proved nothing: {s:?}",
        shape.tag()
    );
    assert!(
        s.zero_leaf_decisions > 0,
        "{}: no decision skipped EVERY leaf, so the map's best case went unexercised: {s:?}",
        shape.tag()
    );
    assert!(
        s.suppressed_true_decisions > 0,
        "{}: no decision suppressed a leaf whose honest value was `true`, so the verdict \
         comparison had nothing to expose: {s:?}",
        shape.tag()
    );
}

#[test]
fn the_mutation_census_is_not_vacuous() {
    let loaded = loaded();
    let (n, census) = (loaded.candidates.len(), &loaded.census);
    eprintln!("scope-mutation census: {}", census.report(n));

    assert!(
        census.cases_loaded > 500,
        "the corpus did not load — {} passing cases",
        census.cases_loaded
    );
    assert!(
        n > 600,
        "too few mutable `action ==` sites: {n}\n{}",
        census.report(n)
    );
    assert!(
        census.cases_eligible > 500,
        "too few eligible cases: {}\n{}",
        census.cases_eligible,
        census.report(n)
    );
}

/// M1: replace equality with a singleton list.
#[test]
fn a_singleton_list_scope_keeps_every_committed_verdict() {
    let s = sweep(Shape::Singleton, 1);
    assert_not_vacuous(&s, Shape::Singleton, 600, 1200);
}

/// M2: scope to a group containing the original action and noise.
#[test]
fn a_group_scope_keeps_every_committed_verdict() {
    let s = sweep(Shape::Group, 1);
    assert_not_vacuous(&s, Shape::Group, 600, 1200);
}

/// M3: reach the original action through nested groups.
#[test]
fn a_nested_group_scope_keeps_every_committed_verdict() {
    let s = sweep(Shape::NestedGroup, 1);
    assert_not_vacuous(&s, Shape::NestedGroup, 600, 1200);
}

/// M4: combine the original action with an unrelated group.
#[test]
fn a_mixed_list_scope_keeps_every_committed_verdict() {
    let s = sweep(Shape::MixedList, 1);
    assert_not_vacuous(&s, Shape::MixedList, 600, 1200);
}

// ─── The snapshot/restore lane ───────────────────────────────────────

/// Replay across a restore into a freshly prepared engine. This preserves the
/// durable path's required order: rebuild the map, then restore monitor state.
fn replay_across_restore(
    case: &Case,
    events: &[Event],
    split: usize,
) -> Result<Vec<String>, String> {
    let stack = |case: &Case| -> Result<(Authorizer, EngineHandle), String> {
        let engine = EngineHandle::new(true);
        let spy = Spy {
            engine: engine.clone(),
            last: None,
            passes: Arc::new(Mutex::new(Vec::new())),
        };
        let authorizer = Authorizer::builder(case.lower()?)
            .temporal_engine(spy)
            .build()
            .map_err(|e| format!("the authorizer did not build: {e:?}"))?;
        Ok((authorizer, engine))
    };
    let mut verdicts = Vec::new();
    let mut decide = |authorizer: &mut Authorizer, range: Range<usize>| {
        for i in range {
            if let Some(response) = authorizer.is_authorized(&events[i]) {
                let allowed = response.decision() == Decision::Allow;
                verdicts.push(format!(
                    "@{} (time point {i}): {allowed}",
                    events[i].timestamp()
                ));
            }
        }
    };

    let (mut before, engine) = stack(case)?;
    decide(&mut before, 0..split);
    let snapshot = engine.with(|e| e.save_snapshot());

    // Restoring before `Authorizer::build` would be silently undone by prepare.
    let (mut after, engine) = stack(case)?;
    if !engine.with(|e| e.load_snapshot(&snapshot)) {
        return Err(
            "load_snapshot refused a snapshot of the same leaf set — the mutated scope changed \
             the state fingerprint"
                .to_string(),
        );
    }
    decide(&mut after, split..events.len());
    Ok(verdicts)
}

/// Sample every eighth M2 mutation and restore at the trace midpoint.
#[test]
fn a_snapshot_restore_mid_replay_survives_the_mutated_shapes() {
    let loaded = loaded();
    let mutations: Vec<Mutation> = loaded
        .candidates
        .iter()
        .step_by(8)
        .filter_map(|c| mutate(&loaded.cases[c.case], &c.site, &c.target, Shape::Group).ok())
        .collect();

    let checked = par_map(&mutations, |m| {
        let mut failures = Vec::new();
        let mut cuts = 0usize;
        for trace in &m.case.traces {
            let Ok(events) = parse_trace(&trace.trace_log) else {
                continue;
            };
            if events.len() < 2 {
                continue;
            }
            match replay_across_restore(&m.case, &events, events.len() / 2) {
                Ok(verdicts) => {
                    cuts += 1;
                    if norm(&verdicts.join("\n")) != norm(&trace.expected) {
                        failures.push(format!(
                            "{}: trace_{}: a snapshot/restore cut moved the stream\n  got: \
                             {:?}\n  exp: {:?}",
                            m.label(),
                            trace.index,
                            norm(&verdicts.join("\n")),
                            norm(&trace.expected)
                        ));
                    }
                }
                Err(e) => failures.push(format!("{}: trace_{}: {e}", m.label(), trace.index)),
            }
        }
        (cuts, failures)
    });

    let mut cuts = 0usize;
    let mut failures = Vec::new();
    for (n, f) in checked {
        cuts += n;
        failures.extend(f);
    }
    eprintln!(
        "snapshot/restore lane: {cuts} mid-replay cuts over {} M2 mutations",
        mutations.len()
    );
    assert!(
        failures.is_empty(),
        "{} snapshot/restore failure(s):\n\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n\n")
    );
    assert!(cuts > 50, "too few snapshot/restore cuts exercised: {cuts}");
}

// ─── The negative control ────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum Seen {
    StreamDiffers,
    DidNotLower,
    Unchanged,
}

fn observe_disjoint(m: &Mutation) -> Seen {
    let mut seen = Seen::Unchanged;
    for trace in &m.case.traces {
        let Ok(lowered) = m.case.lower() else {
            return Seen::DidNotLower;
        };
        let Ok(events) = parse_trace(&trace.trace_log) else {
            continue;
        };
        let Ok(run) = replay(lowered, &events, true) else {
            return Seen::DidNotLower;
        };
        if norm(&run.verdicts.join("\n")) != norm(&trace.expected) {
            seen = Seen::StreamDiffers;
        }
    }
    seen
}

/// A disjoint group must move a known-sensitive verdict stream. The wider
/// corpus sample measures how often the harness detects the same mutation.
#[test]
fn the_negative_control_sees_a_meaning_changing_mutation() {
    const GUARANTEED: &str = "0004_write_after_read";

    let loaded = loaded();
    let case_of = |c: &Candidate| &loaded.cases[c.case];

    let guaranteed = loaded
        .candidates
        .iter()
        .find(|c| case_of(c).name == GUARANTEED)
        .unwrap_or_else(|| panic!("corpus case {GUARANTEED} is no longer a mutable candidate"));
    assert!(
        case_of(guaranteed)
            .traces
            .iter()
            .any(|t| t.expected.contains("true")),
        "precondition: {GUARANTEED} must decide `true` somewhere, or removing its action from \
         scope could not change the stream"
    );
    let control = mutate(
        case_of(guaranteed),
        &guaranteed.site,
        &guaranteed.target,
        Shape::Disjoint,
    )
    .expect("the guaranteed case expresses the disjoint-group shape");
    assert_eq!(
        observe_disjoint(&control),
        Seen::StreamDiffers,
        "a scope that no longer reaches {} MUST move the verdict stream through this engine — \
         if it did not, the preserving sweeps' verdict comparison would be proving nothing",
        guaranteed.target.id
    );

    // Sample one mutation per eligible case.
    let mut seen = BTreeSet::new();
    let broad: Vec<Mutation> = loaded
        .candidates
        .iter()
        .filter(|c| seen.insert(c.case))
        .filter_map(|c| mutate(case_of(c), &c.site, &c.target, Shape::Disjoint).ok())
        .collect();
    let observed = par_map(&broad, observe_disjoint);
    let noticed = observed.iter().filter(|s| **s != Seen::Unchanged).count();
    eprintln!(
        "negative control: {noticed} of {} disjoint-group mutations were noticed ({} did not \
         lower)",
        broad.len(),
        observed.iter().filter(|s| **s == Seen::DidNotLower).count(),
    );
    assert!(
        noticed * 2 > broad.len(),
        "only {noticed} of {} meaning-changing mutations were noticed; this harness is mostly \
         blind to a broken expansion",
        broad.len()
    );
}
