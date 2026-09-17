//! **Content-derived leaf identity** — the stable name a temporal leaf's
//! derived monitor state is filed under (`DESIGN.md` §9.1).
//!
//! # Why positional identity is not enough
//!
//! Prospective installs (`DESIGN.md` §9) require that installing rule B leaves
//! rule A's accumulated window *untouched*. A policy change recompiles the whole
//! set, and a leaf's public id ([`TemporalField::id`]) is **positional** —
//! `__temporal_0`, `__temporal_1`, … assigned in hoist order. Insert a rule
//! ahead of an existing one and every subsequent leaf's id shifts, so
//! state filed under `__temporal_1` would be handed to a *different* formula.
//! That is the invisible bug §9.1 calls out: adding an unrelated rule silently
//! resets (or worse, cross-contaminates) every existing rule's history.
//!
//! So state is keyed by **what the leaf says, not where it sits**: a canonical,
//! span-free rendering of its condition AST. Two leaves with the same key
//! denote the same formula and may share state; a leaf whose key is absent from
//! a snapshot is genuinely new and starts empty — which is exactly prospective
//! install semantics, obtained without any epoch bookkeeping in the state itself.
//!
//! # Properties the rendering must have
//!
//! - **Span-free.** [`Condition`] carries a source [`span`](Condition), so
//!   `{:?}` changes when a policy file is merely reformatted or when an
//!   unrelated rule above it grows a line. Debug-formatting would reset state on
//!   a whitespace edit. Nothing here reads a span.
//! - **Injective.** The key is compared for equality to decide whether to
//!   transplant state into a formula, so a collision would silently evaluate one
//!   rule against another's history. Every string payload is therefore
//!   **length-prefixed** (`s:3:foo`), so no combination of delimiters inside an
//!   identifier, entity id, or string literal can forge a different tree's
//!   rendering. The full canonical string *is* the key — deliberately not a
//!   hash, since a 64-bit hash collision here is a silent authorization fault,
//!   and leaves per policy set number in the tens (the size cost is irrelevant).
//! - **Semantics-canonical where cheap.** `within 1m` and `within 60s` denote
//!   the same window, so both render as `w:60` and keep their shared state
//!   across such an edit. (The converse — a *widened* window, `1h` → `24h` —
//!   deliberately yields a different key: §9.2's "editing a temporal rule resets
//!   its window", since prospectivity cannot conjure history that was never
//!   retained.)
//!
//! [`TemporalField::id`]: dogwood_language::TemporalField

use dogwood_language::TemporalField;
use dogwood_language::temporal_ast::{
    AggExpr, AggExprKind, BinderSlot, CmpOp, Condition, ConditionKind, Predicate, Term, Type,
    TypedBinder, WithinSpec,
};

/// The content-derived identity of a temporal leaf: a canonical, span-free
/// rendering of its condition. Equal keys ⇒ the same formula ⇒ state may be
/// carried across a recompile (`DESIGN.md` §9.1).
pub fn leaf_key(leaf: &TemporalField) -> String {
    let mut out = String::new();
    render_condition(&leaf.condition.condition, &mut out);
    out
}

/// Append a length-prefixed string payload: `s:<byte-len>:<bytes>`. The
/// length prefix is what makes the whole rendering injective — an identifier or
/// literal containing `(`, `)`, `:` or a space cannot imitate surrounding
/// structure.
fn put_str(s: &str, out: &mut String) {
    out.push_str("s:");
    out.push_str(&s.len().to_string());
    out.push(':');
    out.push_str(s);
}

/// Append a dotted path as a length-prefixed segment list.
fn put_path(path: &[String], out: &mut String) {
    out.push('[');
    for seg in path {
        put_str(seg, out);
        out.push(' ');
    }
    out.push(']');
}

/// Append a window as its length in **seconds**, canonicalizing equivalent
/// spellings (`1m` ≡ `60s`). A still-unexpanded `?w` parameter renders as
/// itself rather than panicking (`WithinSpec::interval` panics on a sigil);
/// such a node never reaches a prepared leaf, but a key function must not be
/// the thing that discovers that.
fn put_within(within: &WithinSpec, out: &mut String) {
    match within {
        WithinSpec::Concrete(i) => {
            out.push_str("w:");
            out.push_str(&i.seconds().to_string());
        }
        WithinSpec::ParamRef(p) => {
            out.push_str("w?");
            put_str(p, out);
        }
    }
}

/// Append a binder slot. The three variants are tagged distinctly so a
/// concrete identifier can never render as an unexpanded sigil of the same name.
fn put_slot(slot: &BinderSlot, out: &mut String) {
    let (tag, name) = match slot {
        BinderSlot::Name(n) => ('n', n),
        BinderSlot::ParamRef(p) => ('p', p),
        BinderSlot::BinderRef(b) => ('b', b),
    };
    out.push(tag);
    put_str(name, out);
}

fn put_binder(binder: &TypedBinder, out: &mut String) {
    out.push('(');
    put_slot(&binder.slot, out);
    out.push(' ');
    match &binder.ty {
        Type::Timepoint => out.push_str("tp"),
        Type::Named(path) => {
            out.push_str("ty");
            put_path(path, out);
        }
    }
    out.push(')');
}

fn cmp_tag(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Le => "le",
        CmpOp::Lt => "lt",
        CmpOp::Ge => "ge",
        CmpOp::Gt => "gt",
        CmpOp::Eq => "eq",
        CmpOp::NotEq => "ne",
    }
}

/// Render a condition. Every arm opens with a distinct tag, so no two node
/// kinds can produce the same text.
fn render_condition(cond: &Condition, out: &mut String) {
    out.push('(');
    match &cond.kind {
        ConditionKind::And { left, right } => {
            out.push_str("and ");
            render_condition(left, out);
            out.push(' ');
            render_condition(right, out);
        }
        ConditionKind::Or { left, right } => {
            out.push_str("or ");
            render_condition(left, out);
            out.push(' ');
            render_condition(right, out);
        }
        ConditionKind::Not { inner } => {
            out.push_str("not ");
            render_condition(inner, out);
        }
        ConditionKind::Formerly { within, body } => {
            out.push_str("formerly ");
            put_within(within, out);
            out.push(' ');
            render_condition(body, out);
        }
        ConditionKind::Previous { within, body } => {
            out.push_str("previous ");
            put_within(within, out);
            out.push(' ');
            render_condition(body, out);
        }
        ConditionKind::Since {
            left,
            within,
            right,
        } => {
            out.push_str("since ");
            render_condition(left, out);
            out.push(' ');
            put_within(within, out);
            out.push(' ');
            render_condition(right, out);
        }
        ConditionKind::Predicate(p) => render_predicate(p, out),
        ConditionKind::Comparison { op, left, right } => {
            out.push_str("cmp ");
            out.push_str(cmp_tag(*op));
            out.push(' ');
            render_term(left, out);
            out.push(' ');
            render_term(right, out);
        }
        ConditionKind::Exists { var, body } => {
            out.push_str("exists ");
            put_binder(var, out);
            out.push(' ');
            render_condition(body, out);
        }
        ConditionKind::Tp { var } => {
            out.push_str("tp ");
            put_slot(var, out);
        }
        // Transient nodes: macro-expansion / relativization removes these before
        // a leaf is prepared. Rendered (rather than unreachable!) so this
        // function is total — a key function must never panic on a caller's AST.
        ConditionKind::Call(_) => out.push_str("call?"),
        // `sigil` is not rendered: its type (`Sigil`) is not part of the
        // exported `temporal_ast` surface, so it cannot be named here. Harmless
        // — a `SigilRef` never survives macro expansion into a prepared leaf.
        ConditionKind::SigilRef { name, .. } => {
            out.push_str("sigil ");
            put_str(name, out);
        }
        ConditionKind::Refine { base, fields, .. } => {
            out.push_str("refine ");
            render_condition(base, out);
            for f in fields {
                out.push(' ');
                put_str(f.field_name(), out);
                out.push(' ');
                render_term(&f.value, out);
            }
        }
    }
    out.push(')');
}

fn render_predicate(p: &Predicate, out: &mut String) {
    out.push_str("pred ");
    put_path(&p.namespace, out);
    put_str(&p.action, out);
    put_str(&p.kind, out);
    // Args in source order. Order is part of the identity: reordering a
    // predicate's fields is a source edit, and treating the two spellings as
    // distinct only ever *resets* state (the conservative direction), never
    // transplants one formula's history into another.
    for arg in &p.args {
        out.push(' ');
        put_str(arg.field_name(), out);
        out.push(' ');
        render_term(&arg.value, out);
    }
}

fn render_term(term: &Term, out: &mut String) {
    out.push('(');
    match term {
        Term::Entity { ty, id } => {
            out.push_str("ent ");
            put_str(ty, out);
            put_str(id, out);
        }
        Term::Integer(n) => {
            out.push_str("int ");
            out.push_str(&n.to_string());
        }
        // Decimals keep their literal text, so `1.5` and `1.50` yield
        // distinct keys. This is the *conservative* choice, not a claim about
        // runtime matching: the monitor's `dom_eq` treats `1.5 == 1.50` as
        // equal (see `rows.rs`), but a stricter key can only ever *reset*
        // state — the safe direction — never transplant one formula's history
        // into another.
        Term::Decimal(s) => {
            out.push_str("dec ");
            put_str(s, out);
        }
        Term::String(s) => {
            out.push_str("str ");
            put_str(s, out);
        }
        Term::Bool(b) => {
            out.push_str("bool ");
            out.push_str(if *b { "1" } else { "0" });
        }
        Term::ContextField(path) => {
            out.push_str("ctx");
            put_path(path, out);
        }
        Term::ScopeField(path) => {
            out.push_str("scope");
            put_path(path, out);
        }
        Term::Var(v) => {
            out.push_str("var ");
            put_str(v, out);
        }
        Term::Wildcard => out.push_str("wild"),
        Term::Array(items) => {
            out.push_str("arr");
            for t in items {
                out.push(' ');
                render_term(t, out);
            }
        }
        Term::Agg(agg) => render_agg(agg, out),
        Term::ParamRef(p) => {
            out.push_str("param ");
            put_str(p, out);
        }
        Term::BinderRef(b) => {
            out.push_str("binder ");
            put_str(b, out);
        }
    }
    out.push(')');
}

fn render_agg(agg: &AggExpr, out: &mut String) {
    match &agg.kind {
        AggExprKind::Sum {
            bound_var,
            for_vars,
            body,
        } => {
            out.push_str("sum ");
            put_slot(bound_var, out);
            out.push(' ');
            for v in for_vars {
                put_binder(v, out);
            }
            out.push(' ');
            render_condition(body, out);
        }
        AggExprKind::Count { for_vars, body } => {
            out.push_str("count ");
            for v in for_vars {
                put_binder(v, out);
            }
            out.push(' ');
            render_condition(body, out);
        }
        AggExprKind::Call(_) => out.push_str("aggcall?"),
    }
}

// NOTE: like `reach.rs`, this module operates on a `temporal_ast::Condition`
// whose `span` field carries a crate-private type that cannot be constructed
// outside `dogwood-language` — so a `Condition` cannot be hand-built in an
// out-of-crate unit test. `leaf_key` is instead exercised end-to-end over real,
// parsed policies by `tests/leaf_identity.rs`, which asserts the properties that
// actually matter: distinct formulas get distinct keys, a reformatted /
// reordered policy set keeps each leaf's key (so state survives), and a widened
// window changes it (so state resets, per §9.2).
