//! Content-derived leaf identity ([`leaf_key`]) — the mechanism prospective
//! installs rest on (`DESIGN.md` §9.1).
//!
//! `Condition` cannot be hand-constructed outside `dogwood-language` (its `span`
//! field carries a crate-private type), so these tests build keys from **real,
//! parsed policies** and assert the three properties that actually matter:
//!
//! 1. **Distinct formulas ⇒ distinct keys.** A collision would hand one rule's
//!    accumulated window to a different rule — a silent authorization fault.
//! 2. **Cosmetic edits preserve keys.** Reformatting, reordering rules, or adding
//!    an unrelated rule must not change an existing leaf's key, or every policy
//!    change would reset every rule's history (the §9.1 bug).
//! 3. **Semantic edits change keys.** Widening a window must produce a new key,
//!    because prospectivity cannot conjure history that was never retained —
//!    §9.2's "editing a temporal rule resets its window".

use dogwood_language::{LoweredPolicySet, PolicySchema, ServiceSchema};
use dogwood_local_engine::leaf_key;

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User,
    resource: Doc,
    context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User,
    resource: Doc,
    context: { input: { doc: String } }
};
"#;

/// The content-derived key of every temporal leaf in `policy`, in leaf order.
fn keys(policy: &str) -> Vec<String> {
    let schema = PolicySchema::from_cedarschema_str(ACTION_SCHEMA).expect("schema builds");
    let lowered = LoweredPolicySet::from_str(policy, &ServiceSchema::defaults(), &schema)
        .expect("policy lowers");
    lowered.temporal_fields().map(leaf_key).collect()
}

/// A one-leaf policy with the given window and predicate action.
fn policy_with(window: &str, past_action: &str) -> String {
    format!(
        r#"
forbid (
    principal,
    action == Action::"Export",
    resource
)
when temporal {{
    formerly within {window} Action::"{past_action}"::request{{ input.doc: context.input.doc }}
}};
"#
    )
}

/// Different formulas get different keys — the injectivity that keeps one rule's
/// history out of another rule's monitor.
#[test]
fn distinct_formulas_have_distinct_keys() {
    let variants = [
        policy_with("1h", "Read"),
        // A different window.
        policy_with("24h", "Read"),
        // A different past action.
        policy_with("1h", "Export"),
    ];

    let mut seen: Vec<String> = Vec::new();
    for policy in &variants {
        let key = keys(policy).into_iter().next().expect("one leaf");
        assert!(
            !seen.contains(&key),
            "two distinct formulas produced the same key:\n{key}"
        );
        seen.push(key);
    }
}

/// **Reformatting preserves the key.** The key is derived from structure, never
/// from source spans, so whitespace and comments cannot reset a rule's window.
///
/// This is why `identity.rs` renders the AST rather than `Debug`-formatting it:
/// `Condition` carries a span, so `{:?}` would change on any edit above the rule.
#[test]
fn reformatting_a_policy_preserves_its_leaf_key() {
    let tidy = policy_with("1h", "Read");
    let messy = r#"
// A comment that did not exist before, pushing every span down.


forbid ( principal, action == Action::"Export", resource )
when temporal { formerly within 1h Action::"Read"::request{ input.doc: context.input.doc } };
"#;

    assert_eq!(
        keys(&tidy),
        keys(messy),
        "a cosmetic edit must not change a leaf's identity"
    );
}

/// **An equivalent window spelling preserves the key.** `within 60m` and
/// `within 1h` denote the same window, so a rule rewritten between them keeps its
/// accumulated history.
#[test]
fn equivalent_window_spellings_share_a_key() {
    assert_eq!(
        keys(&policy_with("1h", "Read")),
        keys(&policy_with("60m", "Read")),
        "1h and 60m are the same window, so they must share state"
    );
    assert_eq!(
        keys(&policy_with("1m", "Read")),
        keys(&policy_with("60s", "Read")),
        "1m and 60s are the same window"
    );
}

/// **Widening a window changes the key**, so the rule starts prospectively.
///
/// This is deliberate, not a limitation: a `1h` monitor has only ever retained an
/// hour of history, so a `24h` rule cannot be handed that state and claim to have
/// been watching for a day (§9.2 — editing a temporal rule resets its window).
#[test]
fn widening_a_window_changes_the_key() {
    assert_ne!(
        keys(&policy_with("1h", "Read")),
        keys(&policy_with("24h", "Read")),
        "a widened window must not silently inherit the narrower rule's state"
    );
}

/// **Adding and reordering rules preserves each surviving leaf's key.**
///
/// The load-bearing §9.1 property: leaf ids are positional (`__temporal_0`,
/// `__temporal_1`, …), so inserting a rule *ahead* of an existing one shifts every
/// later id. Keying by content means the shifted leaf still finds its own state
/// instead of inheriting its neighbour's.
#[test]
fn inserting_a_rule_preserves_the_existing_leaf_keys() {
    let original = policy_with("1h", "Read");
    let original_keys = keys(&original);
    assert_eq!(original_keys.len(), 1);

    // The same rule with a DIFFERENT leaf inserted before it, so the original
    // leaf's positional id moves from __temporal_0 to __temporal_1.
    let with_leading = format!(
        r#"
forbid (
    principal,
    action == Action::"Read",
    resource
)
when temporal {{
    formerly within 30m Action::"Export"::request{{ input.doc: context.input.doc }}
}};
{original}
"#
    );
    let new_keys = keys(&with_leading);
    assert_eq!(new_keys.len(), 2, "two leaves now");
    assert!(
        new_keys.contains(&original_keys[0]),
        "the original leaf's key must survive an insertion ahead of it — \
         otherwise its accumulated window is handed to the new rule"
    );
    // And the inserted leaf is genuinely new, so it starts prospectively.
    assert_eq!(
        new_keys.iter().filter(|k| *k == &original_keys[0]).count(),
        1,
        "exactly one leaf claims the original key"
    );
}

/// Keys are stable across repeated lowerings of identical source — a restart
/// must not re-prospective existing rules (§9.2's "restart ≠ install").
#[test]
fn keys_are_deterministic_across_lowerings() {
    let policy = policy_with("1h", "Read");
    assert_eq!(
        keys(&policy),
        keys(&policy),
        "lowering the same source twice must yield the same keys"
    );
}

/// String payloads are length-prefixed, so a value containing the renderer's own
/// delimiters cannot forge a different formula's key.
///
/// Without length prefixing, a crafted doc name containing `)`/`(`/`:` could make
/// one predicate's rendering coincide with another's — and a policy author can put
/// arbitrary text in a string literal.
#[test]
fn delimiter_laden_literals_do_not_forge_other_keys() {
    let adversarial = [
        r#"a) (pred s:4:Read"#,
        r#"s:3:foo"#,
        r#"(((:::)))"#,
        r#"input.doc: context.input.doc"#,
    ];

    let mut seen: Vec<String> = Vec::new();
    for literal in adversarial {
        let policy = format!(
            r#"
forbid (
    principal,
    action == Action::"Export",
    resource
)
when temporal {{
    formerly within 1h Action::"Read"::request{{ input.doc: "{literal}" }}
}};
"#
        );
        let key = keys(&policy).into_iter().next().expect("one leaf");
        assert!(
            !seen.contains(&key),
            "literal {literal:?} collided with an earlier key:\n{key}"
        );
        seen.push(key);
    }

    // None of them collides with the ordinary correlated form either.
    let plain = keys(&policy_with("1h", "Read")).into_iter().next().unwrap();
    assert!(
        !seen.contains(&plain),
        "an adversarial literal must not imitate the correlated predicate's key"
    );
}
