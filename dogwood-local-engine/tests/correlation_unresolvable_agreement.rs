//! The incremental engine must agree with the reference interpreter when a
//! decision request does NOT carry a field the policy correlates on.
//!
//! A correlated predicate arg (`input.user: context.input.user`) is a join
//! between a past event's value and the decision request's value. If the request
//! does not carry that field the correlation is **unresolvable**, and the
//! reference's `match_args` matches no occurrence (its `resolve_term` returns
//! `None`, propagated by `?`). The incremental engine reaches the same question
//! in `compatible`, where the correlation column is simply missing from the
//! seeded env — and a missing column must NOT be read as "no constraint", or
//! `field: context.x` silently widens to `field: *`.
//!
//! The divergence is invisible in a bare `permit`-vs-`DENY` reading, so the
//! cases below deliberately span the shapes that consume the leaf differently —
//! `permit`, `forbid`, `!`, and aggregate thresholds in both directions — since
//! each one inverts which engine is the permissive one. The free-variable cases
//! at the end are the counterweight: an absent **variable** column is still
//! vacuously compatible (`Exists` projects it away later), so a fix that drops
//! every absent column would break them.
//!
//! A correlation may also read the request **scope** (`field: principal.dept`),
//! which lives in its own `@`-headed keyspace and is seeded from the principal's
//! supplied entity attributes rather than the context, so it is covered too.

use std::fmt::Write as _;

use dogwood_language::{
    Authorizer, Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, Value,
};
use dogwood_local_engine::LocalTemporalEngine;

const SCHEMA: &str = r#"
namespace Example {
  type UserInput = { user: String, dept: String };
  entity Gateway;
  // `dept` is OPTIONAL so a request may legally omit it — that is what makes a
  // `principal.dept` correlation unresolvable rather than a schema violation.
  entity OAuthUser { dept?: String };
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: UserInput }
  };
  action "Suspend" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: UserInput }
  };
  action "Act" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: UserInput }
  };
}
"#;

/// `permit` gated on a required prior login by the same user.
const P_PERMIT: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    formerly within 1h Example::Action::"Login"::request{ input.user: context.input.user }
};
"#;

/// `forbid` gated on a suspension — the leaf's `false` is what ALLOWS here.
const P_FORBID: &str = r#"
permit (principal, action == Example::Action::"Act", resource);
forbid (principal, action == Example::Action::"Act", resource)
when temporal {
    formerly within 1h Example::Action::"Suspend"::request{ input.user: context.input.user }
};
"#;

/// Negation inside the formula — inverts whatever the inner leaf produces.
const P_NOT: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    !(formerly within 1h Example::Action::"Suspend"::request{ input.user: context.input.user })
};
"#;

/// Aggregate threshold requiring PRESENCE.
const P_COUNT_GE: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (Example::Action::"Login"::request{ input.user: context.input.user } && tp(t))
    )) >= 1
};
"#;

/// Aggregate threshold requiring ABSENCE — an unresolvable correlation counts 0,
/// which reads as "clean".
const P_COUNT_EQ0: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (Example::Action::"Suspend"::request{ input.user: context.input.user } && tp(t))
    )) == 0
};
"#;

/// Two correlated columns: the request supplies `dept` but not `user`, so one
/// resolves and one cannot (partial resolution).
const P_TWO_KEY: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    formerly within 1h Example::Action::"Login"::request{
        input.user: context.input.user,
        input.dept: context.input.dept
    }
};
"#;

/// SCOPE KEY: the correlation reads the request principal's `dept` attribute
/// instead of a context field, so the seeded key is `@`-headed (`scope_key`)
/// rather than `context.`-headed. Unresolvable when the request supplies the
/// principal uid but not that attribute.
const P_SCOPE: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    formerly within 1h Example::Action::"Login"::request{ input.dept: principal.dept }
};
"#;

/// FREE VARIABLE, no request read at all: the row's column is a variable, absent
/// from the env because it is still free. Must keep matching.
const P_EXISTS: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    exists (u: String). (formerly within 1h Example::Action::"Login"::request{ input.user: u })
};
"#;

/// FREE VARIABLE joined to the request by an explicit comparison rather than a
/// correlated arg — the variable column must survive while the comparison is
/// what fails to resolve.
const P_EXISTS_CMP: &str = r#"
permit (principal, action == Example::Action::"Act", resource)
when temporal {
    exists (u: String). (
        formerly within 1h Example::Action::"Login"::request{ input.user: u }
        && u == context.input.user
    )
};
"#;

fn try_lower(src: &str) -> Result<LoweredPolicySet, String> {
    let schema =
        PolicySchema::from_cedarschema_str(SCHEMA).map_err(|e| format!("schema: {e:?}"))?;
    LoweredPolicySet::from_str(src, &ServiceSchema::defaults(), &schema)
        .map_err(|e| format!("lower: {e:?}"))
}

/// A complete event: logged fields and request context, both keys.
fn ev(action: &str, ts: i64, user: &str, dept: &str) -> Event {
    Event::builder(&format!("Example::Action::{action}"), "request")
        .timestamp(ts)
        .principal(&format!("Example::OAuthUser::\"{user}\""))
        .resource("Example::Gateway::\"gw1\"")
        .field("input", "user", Value::String(user.into()))
        .field("input", "dept", Value::String(dept.into()))
        .request_context("input", "user", Value::String(user.into()))
        .request_context("input", "dept", Value::String(dept.into()))
        .build()
}

/// The same event with `context.input.user` omitted — `dept` is still supplied,
/// so the two-key case has exactly one resolvable column.
fn ev_no_ctx_user(action: &str, ts: i64, user: &str, dept: &str) -> Event {
    Event::builder(&format!("Example::Action::{action}"), "request")
        .timestamp(ts)
        .principal(&format!("Example::OAuthUser::\"{user}\""))
        .resource("Example::Gateway::\"gw1\"")
        .field("input", "user", Value::String(user.into()))
        .field("input", "dept", Value::String(dept.into()))
        .request_context("input", "dept", Value::String(dept.into()))
        .build()
}

/// [`ev`] plus the principal entity's `dept` ATTRIBUTE. Cedar keeps entity
/// identity (the uid, in the request scope) separate from entity attributes, so
/// the scope principal is otherwise in the store attribute-less and
/// `principal.dept` does not resolve — which is exactly the unresolvable case,
/// supplied by plain [`ev`].
fn ev_principal_dept(action: &str, ts: i64, user: &str, dept: &str) -> Event {
    Event::builder(&format!("Example::Action::{action}"), "request")
        .timestamp(ts)
        .principal(&format!("Example::OAuthUser::\"{user}\""))
        .resource("Example::Gateway::\"gw1\"")
        .field("input", "user", Value::String(user.into()))
        .field("input", "dept", Value::String(dept.into()))
        .request_context("input", "user", Value::String(user.into()))
        .request_context("input", "dept", Value::String(dept.into()))
        .entity(
            &format!("Example::OAuthUser::\"{user}\""),
            [("dept", Value::String(dept.into()))],
        )
        .build()
}

fn decide(src: &str, stream: &[Event], sut: bool) -> Option<bool> {
    let lowered = try_lower(src).expect("policy lowers");
    let mut a = if sut {
        Authorizer::builder(lowered)
            .temporal_engine(LocalTemporalEngine::new())
            .build()
            .expect("local engine prepares")
    } else {
        Authorizer::new(lowered)
    };
    let mut last = None;
    for e in stream {
        last = a.is_authorized(e).map(|r| r.allowed());
    }
    last
}

/// How many of this policy's leaves run on the INCREMENTAL path. A case that
/// falls back to the rescan would agree trivially and prove nothing, so every
/// case below asserts this is non-zero.
fn incremental_leaves(src: &str) -> usize {
    let lowered = try_lower(src).expect("policy lowers");
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let sigs: Vec<_> = lowered.event_signatures().collect();
    let schema = lowered.cedar_schema().clone();
    let mut engine = LocalTemporalEngine::new();
    match engine.prepare(&leaves, &schema, &sigs) {
        Ok(()) => engine.incremental_leaf_count(),
        Err(_) => 0,
    }
}

struct Case<'a> {
    label: &'a str,
    policy: &'a str,
    stream: Vec<Event>,
    /// The verdict both engines must produce, when it is worth pinning
    /// (`None` = only agreement is asserted).
    expect: Option<bool>,
}

#[test]
fn incremental_agrees_with_reference_on_unresolvable_correlation() {
    let login = ev("Login", 0, "alice", "eng");
    let suspend = ev("Suspend", 0, "alice", "eng");
    let complete = ev("Act", 10, "alice", "eng");
    let partial = ev_no_ctx_user("Act", 10, "alice", "eng");
    let with_dept_attr = ev_principal_dept("Act", 10, "alice", "eng");

    let cases = vec![
        // ─── Controls: the request carries the correlation field ───
        Case {
            label: "control permit, prior login",
            policy: P_PERMIT,
            stream: vec![login.clone(), complete.clone()],
            expect: Some(true),
        },
        Case {
            label: "control permit, no login",
            policy: P_PERMIT,
            stream: vec![complete.clone()],
            expect: Some(false),
        },
        Case {
            label: "control forbid, suspended",
            policy: P_FORBID,
            stream: vec![suspend.clone(), complete.clone()],
            expect: Some(false),
        },
        Case {
            label: "control not, suspended",
            policy: P_NOT,
            stream: vec![suspend.clone(), complete.clone()],
            expect: Some(false),
        },
        Case {
            label: "control count>=1, prior login",
            policy: P_COUNT_GE,
            stream: vec![login.clone(), complete.clone()],
            expect: Some(true),
        },
        Case {
            label: "control count==0, suspended",
            policy: P_COUNT_EQ0,
            stream: vec![suspend.clone(), complete.clone()],
            expect: Some(false),
        },
        Case {
            label: "control two-key, prior login",
            policy: P_TWO_KEY,
            stream: vec![login.clone(), complete.clone()],
            expect: Some(true),
        },
        Case {
            label: "control scope key, prior login",
            policy: P_SCOPE,
            stream: vec![login.clone(), with_dept_attr.clone()],
            expect: Some(true),
        },
        // ─── Free variables: an absent VARIABLE column stays compatible ───
        Case {
            label: "free var, prior login (complete)",
            policy: P_EXISTS,
            stream: vec![login.clone(), complete.clone()],
            expect: Some(true),
        },
        Case {
            label: "free var, prior login (no ctx user)",
            policy: P_EXISTS,
            stream: vec![login.clone(), partial.clone()],
            expect: Some(true),
        },
        Case {
            label: "free var, no login at all",
            policy: P_EXISTS,
            stream: vec![complete.clone()],
            expect: Some(false),
        },
        Case {
            label: "free var + cmp, prior login (complete)",
            policy: P_EXISTS_CMP,
            stream: vec![login.clone(), complete.clone()],
            expect: Some(true),
        },
        // ─── The unresolvable-correlation cases ───
        Case {
            label: "permit, request omits ctx user",
            policy: P_PERMIT,
            stream: vec![login.clone(), partial.clone()],
            expect: Some(false),
        },
        Case {
            label: "forbid, request omits ctx user",
            policy: P_FORBID,
            stream: vec![suspend.clone(), partial.clone()],
            expect: None,
        },
        Case {
            label: "not, request omits ctx user",
            policy: P_NOT,
            stream: vec![suspend.clone(), partial.clone()],
            expect: None,
        },
        Case {
            label: "count>=1, request omits ctx user",
            policy: P_COUNT_GE,
            stream: vec![login.clone(), partial.clone()],
            expect: Some(false),
        },
        Case {
            label: "count==0, request omits ctx user",
            policy: P_COUNT_EQ0,
            stream: vec![suspend.clone(), partial.clone()],
            expect: None,
        },
        Case {
            label: "two-key, only dept resolves",
            policy: P_TWO_KEY,
            stream: vec![login.clone(), partial.clone()],
            expect: Some(false),
        },
        Case {
            label: "free var + cmp, request omits ctx user",
            policy: P_EXISTS_CMP,
            stream: vec![login.clone(), partial.clone()],
            expect: Some(false),
        },
        Case {
            label: "scope key, principal supplies no dept attr",
            policy: P_SCOPE,
            stream: vec![login.clone(), complete.clone()],
            expect: Some(false),
        },
    ];

    let mut table = String::new();
    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        if let Err(e) = try_lower(case.policy) {
            failures.push(format!("{}: policy failed to lower: {e}", case.label));
            continue;
        }
        let want = decide(case.policy, &case.stream, false);
        let got = decide(case.policy, &case.stream, true);
        let leaves = incremental_leaves(case.policy);
        let f = |v: Option<bool>| match v {
            Some(true) => "ALLOW",
            Some(false) => "DENY ",
            None => "none ",
        };
        let _ = writeln!(
            table,
            "{:44} reference={} local={} incr_leaves={leaves}",
            case.label,
            f(want),
            f(got)
        );
        if want != got {
            failures.push(format!(
                "{}: reference={:?} local={:?} (engines disagree)",
                case.label, want, got
            ));
        }
        if leaves == 0 {
            failures.push(format!(
                "{}: no leaf on the incremental path — the case proves nothing",
                case.label
            ));
        }
        if let Some(expect) = case.expect
            && want != Some(expect)
        {
            failures.push(format!(
                "{}: reference={:?}, expected {:?} — the case does not test what it claims",
                case.label, want, expect
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} problem(s):\n{}\n\nfull table:\n{table}",
        failures.len(),
        failures.join("\n")
    );
}
