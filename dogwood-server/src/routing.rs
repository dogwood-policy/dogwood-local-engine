//! Routing a wire event to its partition key.
//!
//! The schema-derived *plan* — what the event stream may be partitioned on — is
//! [`ShardPlan`], which lives in `dogwood-local-engine` because it is derived
//! from the lowered policy set. This module supplies the other half: computing
//! the key of a concrete [`WireEvent`], and *only* that event's key, so a future
//! multi-instance server can route each event to the instance owning its key.
//!
//! It lives in the server rather than the engine because it operates on the
//! server's wire type. Today's single-instance server does not route — but the
//! key derivation is defined and tested here so the property a multi-instance
//! deployment depends on ("what partition does this event belong to?") is a fact
//! rather than something to reinvent when the second instance is added.
//!
//! # Why this is sound (and why it isn't just hashing)
//!
//! Partitioning is correct only when a pin is *universal* and *symmetric* — the
//! conditions [`ShardPlan::from_policies`] checks, matching the frontend's
//! relativization rewrite. This module does not re-derive shardability; it keys
//! off the plan the engine already computed, so it cannot claim a partition the
//! rewrite did not establish. Hashing something convenient like the principal
//! would look right and be wrong on a schema that pins nothing.

use dogwood_local_engine::ShardPlan;

use crate::protocol::WireEvent;

/// A partition key: the rendered values of an event's pinned fields.
///
/// Kept as an opaque string so a caller cannot accidentally compare keys computed
/// under different plans. Parts are joined with `US` (unit separator, `0x1f`),
/// which cannot appear in a JSON string value unescaped, so two distinct
/// multi-field keys cannot collide by concatenation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardKey(String);

impl ShardKey {
    /// The key as a string, for logging and for indexing a partition map.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ShardKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The partition key of `event` under `plan`, or `None` when unshardable.
///
/// Returns `None` **also** when a shardable plan's event is missing a key field.
/// That is deliberately not defaulted to a catch-all partition: an event with no
/// key cannot be correlated with anything, so placing it anywhere would be
/// arbitrary. The caller routes such an event to the unsharded path, where it is
/// visible to every leaf — the conservative choice, since a *missing* event can
/// only cause a history-gated rule to under-fire, never to fire wrongly.
///
/// A free function rather than a method on [`ShardPlan`]: the plan is an engine
/// type, and this reads the server's [`WireEvent`], so the two cannot be an
/// inherent `impl`.
pub fn key_of(plan: &ShardPlan, event: &WireEvent) -> Option<ShardKey> {
    let ShardPlan::Sharded { key_paths } = plan else {
        return None;
    };
    let mut parts = Vec::with_capacity(key_paths.len());
    for path in key_paths {
        let value = lookup(event, path)?;
        parts.push(value);
    }
    Some(ShardKey(parts.join("\u{1f}")))
}

/// Read a dotted path out of a wire event, rendering the value canonically.
///
/// Looks in the **logged** bag (the durable temporal record), because that is
/// what a pinned field lives in and what temporal correlation matches against.
/// Single-segment paths are the reserved scope aliases, which a client sends as
/// `principal` / `resource` rather than as logged fields, so those are read from
/// the scope.
fn lookup(event: &WireEvent, path: &[String]) -> Option<String> {
    match path {
        // Reserved scope aliases: the client supplies these as the request scope.
        [only] if only == "callerPrincipal" => event.principal.clone(),
        [only] if only == "callerResource" => event.resource.clone(),
        // A grouped field: descend the logged bag.
        [group, rest @ ..] => {
            let mut cursor = event.logged.get(group)?;
            for segment in rest {
                cursor = cursor.get(segment)?;
            }
            Some(render(cursor))
        }
        [] => None,
    }
}

/// Render a JSON value to a canonical key string.
///
/// Type-tagged so values of different types cannot collide: without the tag the
/// string `"1"` and the number `1` would produce the same key, silently merging
/// two partitions (harmless for correctness — a merged partition is still a
/// superset — but it would make key counts and routing unpredictable).
fn render(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => format!("s:{s}"),
        serde_json::Value::Number(n) => format!("n:{n}"),
        serde_json::Value::Bool(b) => format!("b:{b}"),
        serde_json::Value::Null => "z:".to_string(),
        // Composite values are not sensible partition keys, but rendering them
        // rather than failing keeps routing total; equal composites still route
        // together.
        other => format!("j:{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with(doc: &str) -> WireEvent {
        let mut ev = WireEvent::new("Action::Read", "request");
        ev.logged.insert(
            "input".to_string(),
            serde_json::json!({ "doc": doc, "n": 1 }),
        );
        ev
    }

    /// An unshardable plan yields no key, whatever the event.
    #[test]
    fn unshardable_plans_have_no_key() {
        assert_eq!(key_of(&ShardPlan::Unshardable, &event_with("a")), None);
    }

    /// Equal key values route together; different ones route apart.
    #[test]
    fn keys_are_equal_exactly_when_the_pinned_values_are() {
        let plan = ShardPlan::Sharded {
            key_paths: vec![vec!["input".to_string(), "doc".to_string()]],
        };
        let a1 = key_of(&plan, &event_with("a")).expect("has key");
        let a2 = key_of(&plan, &event_with("a")).expect("has key");
        let b = key_of(&plan, &event_with("b")).expect("has key");
        assert_eq!(a1, a2, "same pinned value ⇒ same partition");
        assert_ne!(a1, b, "different pinned values ⇒ different partitions");
    }

    /// A missing key field yields `None` rather than a default partition, so the
    /// caller can route it conservatively instead of guessing.
    #[test]
    fn a_missing_key_field_has_no_key() {
        let plan = ShardPlan::Sharded {
            key_paths: vec![vec!["input".to_string(), "absent".to_string()]],
        };
        assert_eq!(key_of(&plan, &event_with("a")), None);
    }

    /// The scope aliases are read from the request scope, not the logged bag.
    #[test]
    fn scope_alias_keys_read_the_request_scope() {
        let plan = ShardPlan::Sharded {
            key_paths: vec![vec!["callerPrincipal".to_string()]],
        };
        let mut ev = event_with("a");
        assert_eq!(key_of(&plan, &ev), None, "no principal ⇒ no key");
        ev.principal = Some("User::\"alice\"".to_string());
        assert_eq!(
            key_of(&plan, &ev).map(|k| k.as_str().to_string()),
            Some("User::\"alice\"".to_string())
        );
    }

    /// Values of different JSON types do not collide into one key.
    #[test]
    fn type_tagging_prevents_cross_type_key_collisions() {
        let plan = ShardPlan::Sharded {
            key_paths: vec![vec!["input".to_string(), "v".to_string()]],
        };
        let key = |v: serde_json::Value| {
            let mut ev = WireEvent::new("Action::Read", "request");
            ev.logged
                .insert("input".to_string(), serde_json::json!({ "v": v }));
            key_of(&plan, &ev).expect("has key")
        };
        assert_ne!(
            key(serde_json::json!("1")),
            key(serde_json::json!(1)),
            "the string \"1\" and the number 1 must not share a partition key"
        );
    }

    /// Multi-field keys cannot collide by concatenation: `("ab","c")` and
    /// `("a","bc")` must differ.
    #[test]
    fn multi_field_keys_do_not_collide_by_concatenation() {
        let plan = ShardPlan::Sharded {
            key_paths: vec![
                vec!["input".to_string(), "x".to_string()],
                vec!["input".to_string(), "y".to_string()],
            ],
        };
        let key = |x: &str, y: &str| {
            let mut ev = WireEvent::new("Action::Read", "request");
            ev.logged
                .insert("input".to_string(), serde_json::json!({ "x": x, "y": y }));
            key_of(&plan, &ev).expect("has key")
        };
        assert_ne!(key("ab", "c"), key("a", "bc"));
    }
}
