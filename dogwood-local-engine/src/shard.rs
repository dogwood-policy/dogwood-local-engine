//! Pin-sharded partitioning: routing events to independent monitor instances
//! (`DESIGN.md` §3.3).
//!
//! # What makes this sound (and why it isn't just hashing)
//!
//! Splitting a temporal monitor across instances is only correct if evaluating a
//! policy over one partition's events yields the same verdicts as evaluating it
//! over the whole interleaved trace. That is *not* true in general — a foreign
//! event can change a verdict by merely **occupying a trace position**, without
//! matching anything:
//!
//! - `previous within W φ` asks about the event at position `i-1`; a foreign
//!   event landing there displaces the one the policy meant.
//! - `L since[0,W] A` asks that `L` held at *every* step since the anchor; a
//!   foreign event at any step breaks it, since a correlated `L` cannot match it.
//!
//! Dogwood makes it true by construction. When the event schema declares a
//! **universal symmetric pin** — the same field pinned to its own request-side
//! value on *every* event kind — the frontend rewrites those two universally
//! quantified positions so the formula's verdict over the global trace equals its
//! verdict over the key-local sub-trace. That rewrite is what this module's
//! routing cashes in: within a partition every event is "mine", so the rewritten
//! guards are tautological and the monitor is evaluating exactly the local
//! semantics it was rewritten to match.
//!
//! The theorem is not assumed here — it is tested in the frontend
//! (`dogwood-language/tests/pin_partition_differential.rs`, which replays global
//! interleavings against per-key slices and requires equal verdicts). This module
//! supplies the other half: routing that actually delivers each key's events, and
//! *only* that key's events, to one instance.
//!
//! # The fail-safe direction
//!
//! Without a universal symmetric pin, no partitioning is safe, and this module
//! reports that rather than guessing: [`ShardPlan::from_policies`] returns
//! [`ShardPlan::Unshardable`] and the server runs a single instance. Sharding is
//! **opt-in by schema**, exactly as the rewrite is — a schema that does not
//! declare a partition key does not get silently partitioned.
//!
//! This is why routing keys off the schema's declared pins rather than hashing
//! something convenient like the principal: hashing the principal would look
//! right and be wrong on a schema that pins nothing, because the frontend would
//! not have rewritten `previous`/`since` for it.

use dogwood_language::{EventPinRoot, LoweredPolicySet};

/// How to partition the event stream, derived from the installed schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardPlan {
    /// The schema declares no universal symmetric pin, so no partitioning is
    /// sound: one instance sees every event.
    Unshardable,
    /// The schema declares a partition key. Each event's value at these field
    /// paths determines its partition; events with equal keys always route to the
    /// same instance.
    Sharded {
        /// The pinned field paths, in a deterministic (sorted) order so the key
        /// is stable across processes and restarts.
        key_paths: Vec<Vec<String>>,
    },
}

impl ShardPlan {
    /// Derive the plan from a lowered policy set's event schema.
    ///
    /// A pin qualifies as a partition key when it is:
    ///
    /// - **universal** — declared on *every* derived event, so no event kind can
    ///   slip into the stream uncorrelated. A pin on `request` but not
    ///   `resolution` would let resolutions land in arbitrary partitions, and the
    ///   frontend does not rewrite for it either.
    /// - **symmetric** — the pinned field's request-side target is the field's own
    ///   path, or the reserved `principal` / `resource` scope alias. Symmetry is
    ///   what makes "the key of an event" and "the key of the current request" the
    ///   same function, which is what lets a router compute a partition from an
    ///   event alone.
    ///
    /// These are the same two conditions the frontend's relativization pass keys
    /// on, deliberately: routing must not claim a partition the rewrite did not
    /// establish.
    pub fn from_policies(policies: &LoweredPolicySet) -> ShardPlan {
        let signatures: Vec<_> = policies.event_signatures().collect();
        let Some((first, rest)) = signatures.split_first() else {
            // No declared events at all: nothing to route.
            return ShardPlan::Unshardable;
        };

        let mut key_paths: Vec<Vec<String>> = first
            .pins()
            .filter(|pin| is_symmetric(pin.field_path(), pin.target_path(), pin.root()))
            .filter(|pin| {
                // Universal: every other event declares the same pin.
                rest.iter().all(|ev| {
                    ev.pins().any(|other| {
                        other.field_path() == pin.field_path()
                            && other.target_path() == pin.target_path()
                            && other.root() == pin.root()
                    })
                })
            })
            .map(|pin| pin.field_path().to_vec())
            .collect();

        if key_paths.is_empty() {
            return ShardPlan::Unshardable;
        }
        // Sorted so the key rendering is independent of schema declaration order.
        key_paths.sort();
        ShardPlan::Sharded { key_paths }
    }
}

// Routing an event to its partition key — [`ShardKey`], `key_of`, and their
// value-rendering helpers — lives in the server (`dogwood-server`'s `routing`
// module), because it operates on the server's wire `WireEvent`. This module
// keeps only the schema-derived *plan*: what the stream may be partitioned on.

/// Is a pin *symmetric* — does its request-side target resolve to the pinned
/// field's own value?
///
/// Mirrors the frontend's `is_symmetric` (`event_schema/relativize.rs`), which is
/// crate-private there. The duplication is deliberate and narrow: this must agree
/// with the frontend exactly, so it is written to the same two rules rather than
/// approximated, and the agreement is checked by
/// `tests/shard_routing.rs::shardability_matches_the_frontends_rewrite_trigger`.
fn is_symmetric(field_path: &[String], target_path: &[String], root: EventPinRoot) -> bool {
    match root {
        // `pin f: T = context.f` — the field's own path.
        EventPinRoot::Context => target_path == field_path,
        // The reserved scope aliases, whose fields the engine populates from the
        // request scope. Note `callerPrincipal = context.principal` does NOT
        // qualify: that reads a context field literally named `principal`
        // (Cedar-consistent), not the scope entity — and the frontend agrees.
        EventPinRoot::Scope => {
            let field = field_path.join(".");
            let target = target_path.join(".");
            (field == "callerPrincipal" && target == "principal")
                || (field == "callerResource" && target == "resource")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Symmetry follows the frontend's two rules exactly.
    #[test]
    fn symmetry_matches_the_frontend_rules() {
        let p = |s: &str| vec![s.to_string()];
        // `pin f = context.f` — symmetric.
        assert!(is_symmetric(
            &p("session"),
            &p("session"),
            EventPinRoot::Context
        ));
        // `pin f = context.g` — asymmetric.
        assert!(!is_symmetric(
            &p("session"),
            &p("other"),
            EventPinRoot::Context
        ));
        // The reserved scope aliases.
        assert!(is_symmetric(
            &p("callerPrincipal"),
            &p("principal"),
            EventPinRoot::Scope
        ));
        assert!(is_symmetric(
            &p("callerResource"),
            &p("resource"),
            EventPinRoot::Scope
        ));
        // A scope pin that is not one of the reserved pairs.
        assert!(!is_symmetric(
            &p("owner"),
            &p("principal"),
            EventPinRoot::Scope
        ));
        // `callerPrincipal` pinned to a CONTEXT field named `principal` is not
        // the reserved alias (it reads context, not the scope entity).
        assert!(!is_symmetric(
            &p("callerPrincipal"),
            &p("principal"),
            EventPinRoot::Context
        ));
    }
}
