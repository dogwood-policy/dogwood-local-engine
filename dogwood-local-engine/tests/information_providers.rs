//! Information providers declared at install time.
//!
//! - a provider policy installs with providers and decides by the provider;
//! - the same policy is rejected without providers;
//! - a reopened store rebuilds with the persisted providers;
//! - providers are set once: an identical re-install succeeds, a changed one is
//!   rejected and the running set keeps deciding;
//! - a set mixing a temporal rule and a provider rule agrees with the frontend's
//!   in-memory `Authorizer`;
//! - a provider resolver set on the open engine answers providers, across policy
//!   changes, replacement, and reopen, and is never called by recovery.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dogwood_language::{
    Authorizer, Event, EventBuilder, LoweredPolicySet, PolicySchema, ProviderDeclarations,
    ProviderRequest, ProviderResolver, ServiceSchema, Value,
};
use dogwood_local_engine::{
    DecisionResponse, DurableError, DurableTemporalEngine, Outcome, Submitted, Verb,
};

const SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { document: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { document: String } }
};
"#;

const PROVIDERS: &str = r##"{
  "availableProviders": {
    "Strings::Matches": {
      "argumentTypes": [{ "paramType": "string" }, { "paramType": "string" }],
      "outputType": {
        "paramType": "record",
        "fields": { "matched": { "paramType": "bool" } },
        "required": ["matched"]
      },
      "implementation": {
        "kind": "rhai",
        "script": "fn evaluate(text, pattern) { if type_of(text) == \"()\" || type_of(pattern) == \"()\" { return #{ matched: false }; } #{ matched: regex_is_match(pattern, text) } }"
      }
    }
  }
}"##;

/// Same declaration, but the script never matches.
const PROVIDERS_NEVER: &str = r##"{
  "availableProviders": {
    "Strings::Matches": {
      "argumentTypes": [{ "paramType": "string" }, { "paramType": "string" }],
      "outputType": {
        "paramType": "record",
        "fields": { "matched": { "paramType": "bool" } },
        "required": ["matched"]
      },
      "implementation": {
        "kind": "rhai",
        "script": "fn evaluate(text, pattern) { #{ matched: false } }"
      }
    }
  }
}"##;

const READ_UPPERCASE: &str = r#"permit (principal, action == Action::"Read", resource) when guardrails { Strings::Matches(context.input.document, "^[A-Z]+$").matched == true };"#;

const PERMIT_EXPORT: &str = r#"permit (principal, action == Action::"Export", resource);"#;

const FORBID_EXPORT_AFTER_READ: &str = r#"forbid (principal, action == Action::"Export", resource) when temporal { formerly within 1h Action::"Read"::request{ input.document: context.input.document } };"#;

fn ev(action: &str, document: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), "request")
        .principal("User::\"alice\"")
        .resource("Doc::\"d\"")
        .field("input", "document", Value::String(document.to_string()))
        .request_context("input", "document", Value::String(document.to_string()))
}

fn decide(engine: &mut DurableTemporalEngine, action: &str, document: &str) -> bool {
    match engine.submit(ev(action, document)).expect("submit") {
        Submitted {
            outcome: Outcome::Decision(r),
            ..
        } => r.allowed(),
        other => panic!("expected a decision, got {other:?}"),
    }
}

fn store(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dogwood_information_providers_{tag}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn install(
    engine: &mut DurableTemporalEngine,
    source: &str,
    providers: Option<&str>,
) -> Result<(), DurableError> {
    engine
        .install_with_providers(source, SCHEMA, None, None, providers)
        .map(|_| ())
}

#[test]
fn provider_policy_decides_by_the_provider() {
    let path = store("decides");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
    install(&mut engine, READ_UPPERCASE, Some(PROVIDERS)).expect("installs");

    assert!(decide(&mut engine, "Read", "ABC"));
    assert!(!decide(&mut engine, "Read", "abc"));
    assert!(!decide(&mut engine, "Read", "AB12"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn provider_policy_without_providers_is_rejected() {
    let path = store("undeclared");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
    let err = engine
        .install(READ_UPPERCASE, SCHEMA, None, None)
        .expect_err("an undeclared provider must not lower");
    assert!(matches!(err, DurableError::Rejected(_)), "{err:?}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn malformed_providers_are_rejected_and_persist_nothing() {
    let path = store("malformed");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
    match install(&mut engine, PERMIT_EXPORT, Some("{ not json")) {
        Err(DurableError::Rejected(m)) => assert!(m.contains("information providers"), "{m}"),
        other => panic!("expected a rejection, got {other:?}"),
    }
    // The rejected first install fixed nothing, so a different config still installs.
    install(&mut engine, READ_UPPERCASE, Some(PROVIDERS)).expect("installs");
    assert!(decide(&mut engine, "Read", "ABC"));
    let _ = std::fs::remove_file(&path);
}

/// Same declaration, but the script is named by file instead of included.
const PROVIDERS_BY_FILE: &str = r##"{
  "availableProviders": {
    "Strings::Matches": {
      "argumentTypes": [{ "paramType": "string" }, { "paramType": "string" }],
      "outputType": {
        "paramType": "record",
        "fields": { "matched": { "paramType": "bool" } },
        "required": ["matched"]
      },
      "implementation": { "kind": "rhai", "scriptFile": "matches.rhai" }
    }
  }
}"##;

#[test]
fn script_named_by_file_is_rejected_and_persists_nothing() {
    let path = store("script_file");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
    match install(&mut engine, READ_UPPERCASE, Some(PROVIDERS_BY_FILE)) {
        Err(DurableError::Rejected(m)) => {
            assert!(m.starts_with("information providers:"), "{m}");
            assert!(
                m.contains("Strings::Matches") && m.contains("inline"),
                "{m}"
            );
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
    install(&mut engine, READ_UPPERCASE, Some(PROVIDERS)).expect("installs");
    assert!(decide(&mut engine, "Read", "ABC"));
    assert!(!decide(&mut engine, "Read", "abc"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn reopened_store_rebuilds_with_persisted_providers() {
    let path = store("reopen");
    {
        let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
        install(&mut engine, READ_UPPERCASE, Some(PROVIDERS)).expect("installs");
        assert!(decide(&mut engine, "Read", "ABC"));
    }
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("reopens");
    assert!(decide(&mut engine, "Read", "XYZ"));
    assert!(!decide(&mut engine, "Read", "xyz"));
    // The reopened config is the persisted one, so re-affirming it is a no-op.
    install(&mut engine, READ_UPPERCASE, Some(PROVIDERS)).expect("identical re-install");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn providers_are_set_once() {
    let path = store("set_once");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
    install(&mut engine, READ_UPPERCASE, Some(PROVIDERS)).expect("installs");
    install(&mut engine, READ_UPPERCASE, Some(PROVIDERS)).expect("identical re-install");

    match install(&mut engine, READ_UPPERCASE, Some(PROVIDERS_NEVER)) {
        Err(DurableError::Rejected(m)) => assert!(m.contains("information providers"), "{m}"),
        other => panic!("expected a rejection, got {other:?}"),
    }
    assert!(
        engine.install(READ_UPPERCASE, SCHEMA, None, None).is_err(),
        "dropping the providers is a change too"
    );

    assert!(decide(&mut engine, "Read", "ABC"));
    assert!(!decide(&mut engine, "Read", "abc"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn mixed_temporal_and_provider_set_agrees_with_the_frontend() {
    let source = format!("{READ_UPPERCASE}\n\n{PERMIT_EXPORT}\n\n{FORBID_EXPORT_AFTER_READ}");
    let trace: &[(&str, &str)] = &[
        ("Export", "ABC"),
        ("Read", "abc"),
        ("Export", "abc"),
        ("Read", "ABC"),
        ("Export", "ABC"),
        ("Export", "XYZ"),
        ("Read", "AB12"),
        ("Export", "AB12"),
    ];

    let service = ServiceSchema::builder()
        .providers(ProviderDeclarations::from_json(PROVIDERS).expect("providers parse"))
        .build()
        .expect("service builds");
    let policy_schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("schema parses");
    let lowered =
        LoweredPolicySet::from_str(&source, &service, &policy_schema).expect("policy lowers");
    let mut reference = Authorizer::new(lowered);
    let expected: Vec<bool> = trace
        .iter()
        .enumerate()
        .map(|(i, (action, doc))| {
            reference
                .is_authorized(&ev(action, doc).timestamp(i as i64).build())
                .expect("a decision")
                .allowed()
        })
        .collect();

    let path = store("mixed");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
    install(&mut engine, &source, Some(PROVIDERS)).expect("installs");
    let actual: Vec<bool> = trace
        .iter()
        .map(|(action, doc)| decide(&mut engine, action, doc))
        .collect();

    assert_eq!(actual, expected);
    // The trace exercises both rules: a provider deny and a temporal deny.
    assert!(expected.contains(&true));
    assert!(
        !expected[1],
        "lowercase Read is denied by the provider rule"
    );
    assert!(
        !expected[4],
        "Export after Read is denied by the temporal rule"
    );
    let _ = std::fs::remove_file(&path);
}

/// `Remote::Upper` has no implementation; `Strings::Matches` keeps its inline script.
const RESOLVED_PROVIDERS: &str = r##"{
  "availableProviders": {
    "Remote::Upper": {
      "argumentTypes": [{ "paramType": "string" }],
      "outputType": {
        "paramType": "record",
        "fields": { "matched": { "paramType": "bool" } },
        "required": ["matched"]
      }
    },
    "Strings::Matches": {
      "argumentTypes": [{ "paramType": "string" }, { "paramType": "string" }],
      "outputType": {
        "paramType": "record",
        "fields": { "matched": { "paramType": "bool" } },
        "required": ["matched"]
      },
      "implementation": {
        "kind": "rhai",
        "script": "fn evaluate(text, pattern) { if type_of(text) == \"()\" || type_of(pattern) == \"()\" { return #{ matched: false }; } #{ matched: regex_is_match(pattern, text) } }"
      }
    }
  }
}"##;

const READ_REMOTE_UPPER: &str = r#"permit (principal, action == Action::"Read", resource) when guardrails { Remote::Upper(context.input.document).matched == true };"#;

const EXPORT_DIGITS: &str = r#"permit (principal, action == Action::"Export", resource) when guardrails { Strings::Matches(context.input.document, "^[0-9]+$").matched == true };"#;

/// Answers `Remote::Upper` with "all ASCII uppercase", declines everything else,
/// and counts every call.
#[derive(Default)]
struct UpperResolver {
    calls: AtomicUsize,
}

impl ProviderResolver for UpperResolver {
    fn resolve(&self, request: ProviderRequest<'_>) -> Option<Result<Value, String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.key() != "Remote::Upper" {
            return None;
        }
        let matched = match request.args.first() {
            Some(Value::String(s)) => !s.is_empty() && s.chars().all(|c| c.is_ascii_uppercase()),
            _ => false,
        };
        Some(Ok(Value::Object(BTreeMap::from([(
            "matched".to_string(),
            Value::Bool(matched),
        )]))))
    }
}

impl UpperResolver {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// Answers every call with a fixed `matched` and counts calls.
struct FixedResolver {
    matched: bool,
    calls: AtomicUsize,
}

impl ProviderResolver for FixedResolver {
    fn resolve(&self, _request: ProviderRequest<'_>) -> Option<Result<Value, String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Some(Ok(Value::Object(BTreeMap::from([(
            "matched".to_string(),
            Value::Bool(self.matched),
        )]))))
    }
}

fn open_with(
    path: &std::path::Path,
    resolver: Option<&Arc<UpperResolver>>,
) -> DurableTemporalEngine {
    let mut engine = DurableTemporalEngine::open(path, 0).expect("opens");
    if let Some(r) = resolver {
        engine.set_provider_resolver(Arc::clone(r) as Arc<dyn ProviderResolver + Send + Sync>);
    }
    engine
}

fn respond(engine: &mut DurableTemporalEngine, action: &str, document: &str) -> DecisionResponse {
    match engine.submit(ev(action, document)).expect("submit") {
        Submitted {
            outcome: Outcome::Decision(r),
            ..
        } => r,
        other => panic!("expected a decision, got {other:?}"),
    }
}

#[test]
fn resolver_answers_a_provider_without_an_implementation() {
    let path = store("resolver_answers");
    let resolver = Arc::new(UpperResolver::default());
    let mut engine = open_with(&path, Some(&resolver));
    install(&mut engine, READ_REMOTE_UPPER, Some(RESOLVED_PROVIDERS)).expect("installs");

    assert!(decide(&mut engine, "Read", "ABC"));
    assert!(!decide(&mut engine, "Read", "abc"));
    assert!(resolver.calls() >= 2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn declined_call_falls_back_to_the_inline_script() {
    let path = store("resolver_fallback");
    let resolver = Arc::new(UpperResolver::default());
    let mut engine = open_with(&path, Some(&resolver));
    install(&mut engine, EXPORT_DIGITS, Some(RESOLVED_PROVIDERS)).expect("installs");

    assert!(decide(&mut engine, "Export", "123"));
    assert!(!decide(&mut engine, "Export", "ABC"));
    assert!(
        resolver.calls() >= 2,
        "the resolver is asked before the script"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolver_survives_a_policy_change() {
    let path = store("resolver_batch");
    let resolver = Arc::new(UpperResolver::default());
    let mut engine = open_with(&path, Some(&resolver));
    install(&mut engine, READ_REMOTE_UPPER, Some(RESOLVED_PROVIDERS)).expect("installs");
    assert!(decide(&mut engine, "Read", "ABC"));

    engine
        .batch(vec![Verb::Add {
            policy: EXPORT_DIGITS.to_string(),
        }])
        .expect("batch applies");
    let before = resolver.calls();
    assert!(decide(&mut engine, "Read", "XYZ"));
    assert!(!decide(&mut engine, "Read", "xyz"));
    assert!(decide(&mut engine, "Export", "42"));
    assert!(resolver.calls() > before);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn reopen_with_resolver_decides_and_recovery_never_calls_it() {
    let path = store("resolver_reopen");
    {
        let resolver = Arc::new(UpperResolver::default());
        let mut engine = open_with(&path, Some(&resolver));
        install(&mut engine, READ_REMOTE_UPPER, Some(RESOLVED_PROVIDERS)).expect("installs");
        assert!(decide(&mut engine, "Read", "ABC"));
        assert!(!decide(&mut engine, "Read", "abc"));
        engine
            .batch(vec![Verb::Add {
                policy: EXPORT_DIGITS.to_string(),
            }])
            .expect("batch applies");
        assert!(decide(&mut engine, "Export", "7"));
    }

    let resolver = Arc::new(UpperResolver::default());
    let mut engine = open_with(&path, Some(&resolver));
    assert_eq!(resolver.calls(), 0, "replay must not consult the resolver");
    assert!(decide(&mut engine, "Read", "XYZ"));
    assert!(!decide(&mut engine, "Read", "xyz"));
    assert!(decide(&mut engine, "Export", "8"));
    assert!(resolver.calls() > 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn reopen_without_resolver_denies_with_an_error() {
    let path = store("resolver_dropped");
    {
        let resolver = Arc::new(UpperResolver::default());
        let mut engine = open_with(&path, Some(&resolver));
        install(&mut engine, READ_REMOTE_UPPER, Some(RESOLVED_PROVIDERS)).expect("installs");
        assert!(decide(&mut engine, "Read", "ABC"));
    }

    let mut engine = open_with(&path, None);
    let response = respond(&mut engine, "Read", "ABC");
    assert!(!response.allowed());
    assert!(
        response.diagnostics().errors().next().is_some(),
        "an unresolved provider is reported in the diagnostics"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn replacing_the_resolver_changes_later_decisions() {
    let path = store("resolver_replaced");
    let first = Arc::new(UpperResolver::default());
    let mut engine = open_with(&path, Some(&first));
    install(&mut engine, READ_REMOTE_UPPER, Some(RESOLVED_PROVIDERS)).expect("installs");
    assert!(!decide(&mut engine, "Read", "abc"));

    let second = Arc::new(FixedResolver {
        matched: true,
        calls: AtomicUsize::new(0),
    });
    engine.set_provider_resolver(Arc::clone(&second) as Arc<dyn ProviderResolver + Send + Sync>);
    let first_calls = first.calls();
    assert!(decide(&mut engine, "Read", "abc"));
    assert_eq!(
        first.calls(),
        first_calls,
        "the replaced resolver is not consulted"
    );
    assert!(second.calls.load(Ordering::SeqCst) > 0);
    let _ = std::fs::remove_file(&path);
}

/// Panics for "BOOM", otherwise answers like `UpperResolver`.
struct PanickingResolver;

impl ProviderResolver for PanickingResolver {
    fn resolve(&self, request: ProviderRequest<'_>) -> Option<Result<Value, String>> {
        if let Some(Value::String(s)) = request.args.first()
            && s == "BOOM"
        {
            panic!("resolver exploded on {s}");
        }
        UpperResolver::default().resolve(request)
    }
}

#[test]
fn panicking_resolver_denies_with_an_error_and_the_engine_keeps_deciding() {
    let path = store("resolver_panics");
    let mut engine = DurableTemporalEngine::open(&path, 0).expect("opens");
    engine.set_provider_resolver(Arc::new(PanickingResolver));
    install(&mut engine, READ_REMOTE_UPPER, Some(RESOLVED_PROVIDERS)).expect("installs");

    let response = respond(&mut engine, "Read", "BOOM");
    assert!(!response.allowed());
    let errors: Vec<&str> = response.diagnostics().errors().collect();
    assert!(
        errors.iter().any(|e| e.contains("panicked")
            && e.contains("Remote::Upper")
            && e.contains("resolver exploded on BOOM")),
        "the panic is reported in the diagnostics: {errors:?}"
    );

    assert!(decide(&mut engine, "Read", "ABC"));
    assert!(!decide(&mut engine, "Read", "abc"));
    let _ = std::fs::remove_file(&path);
}
