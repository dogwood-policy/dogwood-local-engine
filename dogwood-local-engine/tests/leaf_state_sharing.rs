//! Handing a leaf's accumulated window to another engine **shares** it rather
//! than moving it.
//!
//! A policy change builds the replacement engine before it knows the change is
//! valid and durable, so the running engine must survive the handover intact. A
//! move would gut it; sharing leaves it untouched, and the copy `Arc::make_mut`
//! would make never happens in the case this exists for, because the old engine
//! is dropped as the new set is installed.

use dogwood_language::cedar::Schema;
use dogwood_language::{
    Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, Value,
};
use dogwood_local_engine::{LocalTemporalEngine, PolicyId};

const SCHEMA: &str = r#"
namespace Drupe {
  type ActInput = { note: String };
  entity Gateway;
  entity OAuthUser;
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ActInput }
  };
  action "Act" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ActInput }
  };
}
"#;

const POLICY: &str = r#"
permit (
    principal,
    action == Drupe::Action::"Act",
    resource
)
when temporal {
    formerly within 1h Drupe::Action::"Login"::request{}
};
"#;

fn lowered() -> LoweredPolicySet {
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema builds");
    LoweredPolicySet::from_str(POLICY, &ServiceSchema::defaults(), &schema).expect("lowers")
}

fn ev(action: &str, ts: i64) -> Event {
    Event::builder(&format!("Drupe::Action::{action}"), "request")
        .timestamp(ts)
        .principal("Drupe::OAuthUser::\"alice\"")
        .resource("Drupe::Gateway::\"gw\"")
        .field("input", "note", Value::String("n".into()))
        .request_context("input", "note", Value::String("n".into()))
        .build()
}

fn prepared(l: &LoweredPolicySet) -> LocalTemporalEngine {
    let leaves: Vec<_> = l.temporal_fields().cloned().collect();
    let schema: Schema = l.cedar_schema().clone();
    let sigs: Vec<_> = l.event_signatures().collect();
    let mut e = LocalTemporalEngine::new();
    e.prepare(&leaves, &schema, &sigs).expect("prepares");
    e
}

/// Sharing must not disturb the source: after handing its state over, the
/// original engine still answers as it did, and keeps accumulating.
#[test]
fn sharing_leaves_the_source_engine_intact() {
    let l = lowered();
    let leaf = l.temporal_fields().next().expect("one leaf").id.clone();

    let mut source = prepared(&l);
    source.observe(&ev("Login", 0));
    source.observe(&ev("Act", 1));
    assert!(
        *source.evaluate().expect("evaluates").get(&leaf).unwrap(),
        "fixture: the Login is in the source's window"
    );

    // Hand it over.
    let shared = source.share_leaf_state().expect("state can be shared");
    let mut destination = prepared(&l);
    assert_eq!(
        destination
            .adopt_leaf_state(&shared)
            .expect("state can be adopted"),
        1,
        "the leaf's window must be adopted"
    );

    // The destination sees the history it adopted...
    destination.observe(&ev("Act", 2));
    assert!(
        *destination
            .evaluate()
            .expect("evaluates")
            .get(&leaf)
            .unwrap(),
        "the adopted window must include the source's Login"
    );

    // ...and the source is untouched, still holding its own history and still
    // able to advance. This is what a move would have broken.
    source.observe(&ev("Act", 3));
    assert!(
        *source.evaluate().expect("evaluates").get(&leaf).unwrap(),
        "the source must still hold the window it shared"
    );
}

/// The two diverge after the handover: they share until one is mutated, and then
/// each has its own. Otherwise a later event on one would silently appear in the
/// other's history.
#[test]
fn the_two_engines_diverge_after_sharing() {
    let l = lowered();
    let leaf = l.temporal_fields().next().expect("one leaf").id.clone();

    let mut source = prepared(&l);
    source.observe(&ev("Act", 0)); // no Login yet
    let shared = source.share_leaf_state().expect("state can be shared");
    let mut destination = prepared(&l);
    assert_eq!(
        destination
            .adopt_leaf_state(&shared)
            .expect("state can be adopted"),
        1
    );

    // A Login recorded on the SOURCE must not become visible to the destination.
    source.observe(&ev("Login", 1));
    destination.observe(&ev("Act", 2));
    assert!(
        !*destination
            .evaluate()
            .expect("evaluates")
            .get(&leaf)
            .unwrap(),
        "an event observed only by the source must not appear in the \
         destination's window"
    );

    // And vice versa.
    source.observe(&ev("Act", 3));
    assert!(
        *source.evaluate().expect("evaluates").get(&leaf).unwrap(),
        "the source sees its own Login"
    );
}

/// A leaf the destination does not have in common gets nothing — prospective
/// install semantics, and the same content-keyed rule the serialized form uses.
#[test]
fn a_different_formula_adopts_nothing() {
    const OTHER: &str = r#"
permit (
    principal,
    action == Drupe::Action::"Act",
    resource
)
when temporal {
    formerly within 24h Drupe::Action::"Login"::request{}
};
"#;
    let a = lowered();
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema builds");
    let b = LoweredPolicySet::from_str(OTHER, &ServiceSchema::defaults(), &schema).expect("lowers");

    let mut source = prepared(&a);
    source.observe(&ev("Login", 0));
    let shared = source.share_leaf_state().expect("state can be shared");

    let mut destination = prepared(&b);
    assert_eq!(
        destination
            .adopt_leaf_state(&shared)
            .expect("state can be adopted"),
        0,
        "a widened window is a different formula, so it starts empty"
    );
}

/// `composite_leaf_keys` reflects the actual `(policy id, ordinal)` retention key
/// — resolved when `set_policy_ids` covers the leaf's `policy_N`, and the `?:`
/// content-only fallback when it does not. The durable transplant guard scans
/// **this**, not `leaf_keys` (the bare content key, which never bears `?:`); the
/// two differing is exactly what made an earlier guard against `leaf_keys` dead.
#[test]
fn composite_leaf_keys_expose_an_unresolved_origin() {
    let l = lowered();
    let mut e = prepared(&l);

    // Bare content keys never carry the sentinel — checking these could never
    // fire the guard.
    assert!(
        e.leaf_keys().iter().all(|k| !k.starts_with("?:")),
        "leaf_keys is the content key, not the composite key: {:?}",
        e.leaf_keys()
    );

    // No `policy_ids` set: every leaf origin is unresolved, so the composite key
    // is the `?:` fallback — proving the fallback is producible and detectable.
    let unset = e.composite_leaf_keys();
    assert!(
        !unset.is_empty() && unset.iter().all(|k| k.starts_with("?:")),
        "with no policy_ids, composite keys fall back to `?:`: {unset:?}"
    );

    // `policy_ids` too short for the leaf's `policy_N` — the durable guard's exact
    // trigger condition — still yields `?:`.
    e.set_policy_ids(&[]);
    assert!(
        e.composite_leaf_keys().iter().any(|k| k.starts_with("?:")),
        "an empty policy_ids resolves no leaf origin"
    );

    // `policy_ids` that covers the leaf (this single policy is ordinal 0):
    // resolved, so no key is the fallback — the guard must NOT fire here.
    e.set_policy_ids(&[PolicyId(0)]);
    let resolved = e.composite_leaf_keys();
    assert!(
        resolved.iter().all(|k| !k.starts_with("?:")),
        "with policy_ids covering the leaf, no key is the `?:` fallback: {resolved:?}"
    );
}
