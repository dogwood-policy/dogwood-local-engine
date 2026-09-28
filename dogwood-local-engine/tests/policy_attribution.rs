//! Reasons are sets keyed by real management tokens; the unchanged language
//! authorizer and lowered Cedar annotations supply the semantic reference.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use dogwood_language::{
    Authorizer, Decision, DogwoodRuleRef, Event, EventBuilder, LoweredPolicySet, PolicySchema,
    Response, ServiceSchema, Validator, Value,
};
use dogwood_local_engine::{
    Clock, DecisionDiagnostics, DecisionResponse, DurableConfig, DurableError, DurableLog,
    DurableTemporalEngine, LocalTemporalEngine, Outcome, PolicyAttribution, PolicyToken, Verb,
};

const SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

const PERMIT: &str = r#"
@id("read")
@description("Reading is permitted.")
permit (principal, action == Action::"Read", resource);
"#;

// Neither kind exists in ServiceSchema::defaults(). Re-lowering metadata with
// the defaults would fail to resolve the temporal audit predicate.
const CUSTOM_EVENTS: &str = r#"
decision event <A>::authorize {
    ...inputs(A),
    callerPrincipal: principalType(A),
    callerResource: resourceType(A),
}
event <A>::audit {
    ...inputs(A),
    callerPrincipal: principalType(A),
    callerResource: resourceType(A),
}
"#;

type Annotations = BTreeMap<String, String>;
type Reasons = BTreeMap<PolicyToken, Annotations>;

struct FixedClock;

impl Clock for FixedClock {
    fn now_nanos(&self) -> i64 {
        1_800_000_000_000_000_000
    }
}

struct Store(PathBuf);

impl Store {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "dogwood_attribution_{tag}_{}_{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!path.exists(), "test store already exists: {path:?}");
        Self(path)
    }

    fn open(&self) -> DurableTemporalEngine {
        DurableTemporalEngine::open_with_config(
            &self.0,
            DurableConfig::new(0).with_clock(Box::new(FixedClock)),
        )
        .expect("open durable engine")
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn event(action: &str, kind: &str, doc: &str) -> EventBuilder {
    Event::builder(&format!("Action::{action}"), kind)
        .principal("User::\"alice\"")
        .resource("Doc::\"report\"")
        .field("input", "doc", Value::String(doc.into()))
        .request_context("input", "doc", Value::String(doc.into()))
}

fn read() -> EventBuilder {
    event("Read", "request", "report")
}

fn submit(engine: &mut DurableTemporalEngine, event: EventBuilder) -> DecisionResponse {
    let before = engine.log_offset();
    let submitted = engine.submit(event).expect("accept decision event");
    assert_eq!(submitted.offset, before);
    assert_eq!(engine.log_offset(), before + 1);
    match submitted.outcome {
        Outcome::Decision(response) => response,
        Outcome::Recorded => panic!("expected a decision"),
    }
}

fn reason_set(response: &DecisionResponse) -> Reasons {
    let diagnostics: &DecisionDiagnostics = response.diagnostics();
    let mut reasons = Reasons::new();
    for attribution in diagnostics.reason() {
        let PolicyAttribution { token, annotations } = attribution;
        assert!(
            reasons.insert(token.clone(), annotations.clone()).is_none(),
            "a determining token must appear exactly once: {token}"
        );
    }
    reasons
}

fn assert_decision(response: &DecisionResponse, decision: Decision, reasons: &Reasons) {
    assert_eq!(response.decision(), decision);
    assert_eq!(response.allowed(), decision == Decision::Allow);
    assert_eq!(&reason_set(response), reasons);
    assert_eq!(
        response.diagnostics().errors().collect::<Vec<_>>(),
        Vec::<&str>::new()
    );
}

fn lower(source: &str, schema: &str, events: Option<&str>) -> LoweredPolicySet {
    let service = match events {
        Some(events) => ServiceSchema::builder()
            .event_schema_str(events)
            .build()
            .expect("custom service schema"),
        None => ServiceSchema::defaults(),
    };
    let schema = PolicySchema::from_cedarschema_str(schema).expect("action schema");
    let lowered = LoweredPolicySet::from_str(source, &service, &schema).expect("lower policies");
    let validation = Validator::new().validate(&lowered);
    assert!(
        validation.validation_passed(),
        "fixture must pass validation: {:?}",
        validation
            .validation_errors()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
    );
    lowered
}

fn installed_lowered(engine: &DurableTemporalEngine) -> LoweredPolicySet {
    lower(
        &engine.policy_source().expect("installed source"),
        &engine.action_schema().expect("installed action schema"),
        engine.event_schema().as_deref(),
    )
}

/// Compare against the public Cedar iterator, including Cedar's precise string
/// values. Do not parse annotations separately or unescape their values again.
fn installed_metadata(engine: &DurableTemporalEngine) -> Reasons {
    let entries = engine.list();
    let lowered = installed_lowered(engine);
    assert_eq!(entries.len(), lowered.rules().count());
    lowered
        .rules()
        .map(|rule| {
            let policy = lowered
                .as_cedar()
                .policy(&rule.cedar_policy_id.parse().expect("Cedar policy ID"))
                .expect("lowered rule has a Cedar policy");
            let annotations = policy
                .annotations()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect();
            (entries[rule.rule_index].token.clone(), annotations)
        })
        .collect()
}

fn selected(metadata: &Reasons, tokens: &[PolicyToken]) -> Reasons {
    tokens
        .iter()
        .map(|token| (token.clone(), metadata[token].clone()))
        .collect()
}

fn tokens(engine: &DurableTemporalEngine) -> Vec<PolicyToken> {
    engine.list().into_iter().map(|entry| entry.token).collect()
}

fn assert_language_response(
    engine: &DurableTemporalEngine,
    response: &DecisionResponse,
    reference: &Response,
) {
    assert_eq!(response.decision(), reference.decision());
    assert_eq!(response.allowed(), reference.allowed());
    // Error order is unspecified, but every string and its multiplicity matter.
    let mut actual_errors: Vec<_> = response.diagnostics().errors().collect();
    let mut expected_errors: Vec<_> = reference.diagnostics().errors().collect();
    actual_errors.sort_unstable();
    expected_errors.sort_unstable();
    assert_eq!(actual_errors, expected_errors);

    let entries = engine.list();
    let determining: Vec<_> = reference
        .diagnostics()
        .reason()
        .map(|rule| entries[rule.rule_index].token.clone())
        .collect();
    assert_eq!(
        reason_set(response),
        selected(&installed_metadata(engine), &determining)
    );
}

fn temporal_forbid(version: &str, kind: &str) -> String {
    format!(
        r#"
@id("history")
@description("{version}")
@owner("安全")
forbid (principal, action == Action::"Read", resource)
when temporal {{
    formerly within 1h Action::"Read"::{kind}{{ input.doc: context.input.doc }}
}};
"#
    )
}

#[test]
fn allow_attributes_all_non_temporal_permits_and_exact_cedar_annotations() {
    let store = Store::new("allow");
    let mut engine = store.open();
    engine
        .install(
            r#"
permit (principal, action == Action::"Read", resource);
@id("shared")
@reviewed
@description("雪と🌲\nline\t\"quoted\"\\literal\\n\u{1b}")
@owner("安全-équipe")
permit (principal, action == Action::"Read", resource);
@id("shared")
@reviewed
@description("雪と🌲\nline\t\"quoted\"\\literal\\n\u{1b}")
@owner("安全-équipe")
permit (principal, action == Action::"Read", resource);
"#,
            SCHEMA,
            None,
            None,
        )
        .expect("install annotation variations");
    let handles = tokens(&engine);
    let expected = installed_metadata(&engine);
    assert_eq!(installed_lowered(&engine).temporal_fields().count(), 0);
    assert!(expected[&handles[0]].is_empty());
    assert_eq!(expected[&handles[1]]["reviewed"], "");
    assert_eq!(expected[&handles[1]]["id"], "shared");
    assert_eq!(expected[&handles[1]]["owner"], "安全-équipe");
    assert_eq!(expected[&handles[1]], expected[&handles[2]]);
    assert_ne!(handles[1], handles[2]);
    assert_eq!(expected[&handles[1]].len(), 4);

    let response = submit(&mut engine, read());
    assert_decision(&response, Decision::Allow, &expected);
    assert_eq!(reason_set(&response).len(), 3);

    let annotated = response
        .diagnostics()
        .reason()
        .find(|policy| policy.token == handles[1])
        .unwrap();
    assert_eq!(annotated.annotation_id(), Some("shared"));
    assert_eq!(
        annotated.description(),
        Some("雪と🌲\nline\t\"quoted\"\\literal\\n\u{1b}")
    );
    assert_eq!(annotated.annotation("owner"), Some("安全-équipe"));
    assert_eq!(annotated.annotation("reviewed"), Some(""));
    assert_eq!(annotated.annotation("missing"), None);

    let mut empty_values = annotated.clone();
    empty_values.annotations.insert("id".into(), String::new());
    empty_values
        .annotations
        .insert("description".into(), String::new());
    assert_eq!(empty_values.annotation_id(), Some(""));
    assert_eq!(empty_values.description(), Some(""));

    let unannotated = response
        .diagnostics()
        .reason()
        .find(|policy| policy.token == handles[0])
        .unwrap();
    assert_eq!(unannotated.annotation_id(), None);
    assert_eq!(unannotated.description(), None);
    assert_eq!(unannotated.annotation("reviewed"), None);

    // Exercise the promised owned response/diagnostics and attribution traits.
    assert_eq!(response.clone(), response);
    assert_eq!(response.diagnostics().clone(), *response.diagnostics());
    for attribution in response.diagnostics().reason() {
        let json = serde_json::to_value(attribution).expect("serialize attribution");
        assert!(json["annotations"].is_object());
        assert_eq!(
            serde_json::from_value::<PolicyAttribution>(json).expect("deserialize attribution"),
            *attribution
        );
    }
}

#[test]
fn explicit_deny_attributes_both_forbids_and_excludes_the_matching_permit() {
    let store = Store::new("forbids");
    let mut engine = store.open();
    let source = format!(
        r#"{PERMIT}
@id("first") @owner("security")
forbid (principal, action == Action::"Read", resource);
@id("second") @description("Restricted document.")
forbid (principal, action == Action::"Read", resource)
when {{ context.input.doc == "report" }};
@id("unrelated")
forbid (principal, action == Action::"Export", resource);
"#
    );
    engine
        .install(&source, SCHEMA, None, None)
        .expect("install");
    let handles = tokens(&engine);
    let expected = selected(&installed_metadata(&engine), &handles[1..3]);
    let reference: Response = Authorizer::new(installed_lowered(&engine))
        .is_authorized(&read().timestamp(1).build())
        .expect("language decision");
    let response = submit(&mut engine, read());
    assert_decision(&response, Decision::Deny, &expected);
    assert_language_response(&engine, &response, &reference);
}

#[test]
fn implicit_deny_has_no_attribution_or_invented_errors() {
    let store = Store::new("implicit");
    let mut engine = store.open();
    engine.install(PERMIT, SCHEMA, None, None).expect("install");
    let reference: Response = Authorizer::new(installed_lowered(&engine))
        .is_authorized(&event("Export", "request", "report").timestamp(1).build())
        .expect("language decision");
    let response = submit(&mut engine, event("Export", "request", "report"));
    assert_decision(&response, Decision::Deny, &Reasons::new());
    assert_language_response(&engine, &response, &reference);
}

#[test]
fn error_only_deny_preserves_the_language_diagnostic_without_attribution() {
    let store = Store::new("error_only");
    let mut engine = store.open();
    engine.install(PERMIT, SCHEMA, None, None).expect("install");
    // Missing request scope reaches the authorizer's error-only deny; this is
    // still an accepted event, not a failed policy installation or submission.
    let malformed = || {
        Event::builder("Action::Read", "request")
            .field("input", "doc", Value::String("report".into()))
            .request_context("input", "doc", Value::String("report".into()))
    };
    let reference: Response = Authorizer::new(installed_lowered(&engine))
        .is_authorized(&malformed().timestamp(1).build())
        .expect("language decision");
    assert_eq!(reference.decision(), Decision::Deny);
    assert_eq!(reference.diagnostics().reason().count(), 0);
    assert!(reference.diagnostics().errors().count() > 0);
    let response = submit(&mut engine, malformed());
    assert_language_response(&engine, &response, &reference);
    assert!(reason_set(&response).is_empty());
}

#[test]
fn determining_policies_and_every_evaluation_error_match_the_language_response() {
    const NUMERIC_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { count: Long } }
};
"#;
    let request = |count| {
        Event::builder("Action::Read", "request")
            .principal("User::\"alice\"")
            .resource("Doc::\"report\"")
            .field("input", "count", Value::Int(count))
            .request_context("input", "count", Value::Int(count))
    };
    for effect in ["permit", "forbid"] {
        let store = Store::new(effect);
        let mut engine = store.open();
        let source = format!(
            r#"
@id("determining-a")
{effect} (principal, action == Action::"Read", resource);
@id("determining-b")
{effect} (principal, action == Action::"Read", resource);
@id("overflow-add")
forbid (principal, action == Action::"Read", resource)
when {{ context.input.count + 1 < 0 }};
@id("overflow-multiply")
forbid (principal, action == Action::"Read", resource)
when {{ context.input.count * 2 < 0 }};
"#
        );
        engine
            .install(&source, NUMERIC_SCHEMA, None, None)
            .expect("overflow fixtures are valid policies over valid Long input");
        let mut reference = Authorizer::new(installed_lowered(&engine));
        let control: Response = reference
            .is_authorized(&request(1).timestamp(1).build())
            .expect("control decision");
        assert_eq!(control.diagnostics().errors().count(), 0);
        let overflow: Response = reference
            .is_authorized(&request(i64::MAX).timestamp(2).build())
            .expect("overflow decision");
        assert_eq!(overflow.diagnostics().errors().count(), 2);
        assert_eq!(overflow.diagnostics().reason().count(), 2);

        let response = submit(&mut engine, request(i64::MAX));
        assert_language_response(&engine, &response, &overflow);
        assert_eq!(
            reason_set(&response),
            selected(&installed_metadata(&engine), &tokens(&engine)[..2])
        );
    }
}

#[test]
fn deleting_earlier_positions_keeps_the_surviving_tokens_and_metadata() {
    let store = Store::new("positions");
    let mut engine = store.open();
    engine
        .install(
            &format!(
                r#"{PERMIT}
@id("middle") permit (principal, action == Action::"Read", resource);
@id("last") permit (principal, action == Action::"Read", resource);"#
            ),
            SCHEMA,
            None,
            None,
        )
        .expect("install");
    let handles = tokens(&engine);
    let metadata = installed_metadata(&engine);
    for removed in &handles[..2] {
        engine
            .batch(vec![Verb::Delete {
                id: removed.clone(),
            }])
            .expect("delete earlier entry");
        let expected = selected(&metadata, &tokens(&engine));
        assert_decision(&submit(&mut engine, read()), Decision::Allow, &expected);
    }
    assert_eq!(tokens(&engine), handles[2..]);
    assert_eq!(
        installed_lowered(&engine)
            .rules()
            .next()
            .unwrap()
            .rule_index,
        0
    );
    assert_ne!(
        engine.list()[0].id.0,
        0,
        "ordinal differs from current source position"
    );
}

#[test]
fn annotation_update_retains_token_and_previously_returned_metadata() {
    let store = Store::new("update");
    let mut engine = store.open();
    engine.install(PERMIT, SCHEMA, None, None).expect("install");
    let handle = tokens(&engine)[0].clone();
    let before_metadata = installed_metadata(&engine);
    let before = submit(&mut engine, read());
    engine
        .batch(vec![Verb::Update {
            id: handle.clone(),
            policy: r#"
@id("renamed") @description("Updated\nsecond line") @owner("new owner")
permit (principal, action == Action::"Read", resource);
"#
            .into(),
        }])
        .expect("update annotations");
    assert_eq!(tokens(&engine), vec![handle]);
    let after_metadata = installed_metadata(&engine);
    assert_ne!(after_metadata, before_metadata);
    assert_decision(
        &submit(&mut engine, read()),
        Decision::Allow,
        &after_metadata,
    );
    assert_decision(&before, Decision::Allow, &before_metadata);

    engine
        .batch(vec![Verb::DeleteAll])
        .expect("delete policies");
    assert_decision(
        &submit(&mut engine, read()),
        Decision::Deny,
        &Reasons::new(),
    );
    assert_decision(&before, Decision::Allow, &before_metadata);
}

#[test]
fn concurrent_updates_return_the_version_that_decided_each_event() {
    const CALLERS: usize = 4;
    const EACH: usize = 24;
    const UPDATES: usize = 21;

    fn version_policy(revision: usize) -> String {
        let effect = if revision % 2 == 0 {
            "permit"
        } else {
            "forbid"
        };
        format!(
            "@revision(\"{revision}\") @effect(\"{effect}\") \
             {effect}(principal, action == Action::\"Read\", resource);"
        )
    }

    let store = Store::new("concurrent");
    let mut engine = store.open();
    let installed = engine
        .install(&version_policy(0), SCHEMA, None, None)
        .expect("install initial permit");
    let handles = tokens(&engine);
    assert_eq!(handles.len(), 1);
    let token = handles[0].clone();
    let mut retained = vec![engine.submit(read()).expect("initial submission")];
    let before = engine.log_offset();
    let engine = Arc::new(Mutex::new(engine));
    let barrier = Arc::new(Barrier::new(CALLERS + 1));

    let callers: Vec<_> = (0..CALLERS)
        .map(|_| {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                (0..EACH)
                    .map(|_| {
                        let submitted = {
                            let mut guard = engine.lock().expect("unpoisoned engine");
                            guard.submit(read()).expect("concurrent submission")
                        };
                        std::thread::yield_now();
                        submitted
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let updater = {
        let engine = Arc::clone(&engine);
        let token = token.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let mut versions = vec![(installed.ts, 0)];
            for revision in 1..=UPDATES {
                let batch = {
                    let mut guard = engine.lock().expect("unpoisoned engine");
                    guard
                        .batch(vec![Verb::Update {
                            id: token.clone(),
                            policy: version_policy(revision),
                        }])
                        .expect("update existing policy")
                };
                assert!(batch.minted.is_empty());
                versions.push((batch.ts, revision));
                std::thread::yield_now();
            }
            versions
        })
    };
    for caller in callers {
        let responses = caller.join().expect("submitter succeeds");
        assert_eq!(responses.len(), EACH);
        retained.extend(responses);
    }
    let versions = updater.join().expect("updater succeeds");
    assert_eq!(versions.len(), UPDATES + 1);
    assert!(versions.windows(2).all(|pair| pair[0].0 < pair[1].0));
    {
        let mut guard = engine.lock().expect("unpoisoned engine");
        assert_eq!(tokens(&guard), vec![token.clone()]);
        assert_eq!(
            guard.log_offset(),
            before + (CALLERS * EACH + UPDATES) as u64,
            "every submission and update appends exactly one record"
        );
        retained.push(guard.submit(read()).expect("final submission"));
        assert_eq!(
            guard.log_offset(),
            before + (CALLERS * EACH + UPDATES + 1) as u64
        );
    }
    assert_eq!(retained.len(), CALLERS * EACH + 2);
    let timestamps: BTreeSet<_> = versions
        .iter()
        .map(|(ts, _)| *ts)
        .chain(retained.iter().map(|submitted| submitted.ts))
        .collect();
    assert_eq!(
        timestamps.len(),
        versions.len() + retained.len(),
        "updates and submissions share one strictly ordered clock"
    );

    // Derive each expected revision from the update timestamps, never from the
    // returned annotation. Inspect owned responses outside the lock and only
    // after every update has finished, including the initial permit response.
    for submitted in &retained {
        let revision = versions
            .iter()
            .rev()
            .find(|(ts, _)| *ts < submitted.ts)
            .expect("a policy version precedes every submitted event")
            .1;
        let allowed = revision % 2 == 0;
        let expected = BTreeMap::from([(
            token.clone(),
            BTreeMap::from([
                ("revision".into(), revision.to_string()),
                (
                    "effect".into(),
                    if allowed { "permit" } else { "forbid" }.into(),
                ),
            ]),
        )]);
        let Outcome::Decision(response) = &submitted.outcome else {
            panic!("expected a decision");
        };
        assert_decision(
            response,
            if allowed {
                Decision::Allow
            } else {
                Decision::Deny
            },
            &expected,
        );
    }
    assert!(matches!(
        &retained.first().expect("initial response").outcome,
        Outcome::Decision(response) if response.allowed()
    ));
    assert!(matches!(
        &retained.last().expect("final response").outcome,
        Outcome::Decision(response) if !response.allowed()
    ));
}

#[test]
fn reset_delete_add_and_whole_install_follow_management_token_lifecycles() {
    let store = Store::new("tokens");
    let mut engine = store.open();
    engine.install(PERMIT, SCHEMA, None, None).expect("install");
    let initial = tokens(&engine)[0].clone();
    let metadata = installed_metadata(&engine);
    for verb in [
        Verb::Reset {
            id: initial.clone(),
        },
        Verb::ResetAll,
    ] {
        engine.batch(vec![verb]).expect("reset");
        assert_eq!(tokens(&engine), vec![initial.clone()]);
        assert_decision(&submit(&mut engine, read()), Decision::Allow, &metadata);
    }
    let added = engine
        .batch(vec![
            Verb::Delete {
                id: initial.clone(),
            },
            Verb::Add {
                policy: PERMIT.into(),
            },
        ])
        .expect("delete and add identical source");
    assert_eq!(added.minted.len(), 1);
    assert_ne!(added.minted[0], initial);
    assert_eq!(tokens(&engine), added.minted);
    let annotations = metadata[&initial].clone();
    let expected = BTreeMap::from([(added.minted[0].clone(), annotations.clone())]);
    assert_decision(&submit(&mut engine, read()), Decision::Allow, &expected);

    engine
        .install(PERMIT, SCHEMA, None, None)
        .expect("replace whole set");
    let replacement = tokens(&engine);
    let old: BTreeSet<_> = [initial, added.minted[0].clone()].into_iter().collect();
    assert!(replacement.iter().all(|token| !old.contains(token)));
    let expected = BTreeMap::from([(replacement[0].clone(), annotations)]);
    assert_decision(&submit(&mut engine, read()), Decision::Allow, &expected);
}

#[test]
fn failed_rebuild_preserves_the_old_authorizer_metadata_and_log() {
    let store = Store::new("rebuild");
    let mut engine = store.open();
    engine.install(PERMIT, SCHEMA, None, None).expect("install");
    let old_entries = engine.list();
    let metadata = installed_metadata(&engine);
    let before = submit(&mut engine, read());
    // Syntactically valid, but compares a String to a Long: fails at rebuild
    // validation after folding a valid update that would otherwise deny.
    let invalid = r#"forbid (principal, action == Action::"Read", resource)
when { context.input.doc > 3 };"#;
    let offset = engine.log_offset();
    let error = engine
        .batch(vec![
            Verb::Update {
                id: old_entries[0].token.clone(),
                policy: r#"@id("must-not-leak")
forbid (principal, action == Action::"Read", resource);"#
                    .into(),
            },
            Verb::Add {
                policy: invalid.into(),
            },
        ])
        .expect_err("reject invalid candidate");
    assert!(
        matches!(&error, DurableError::Rejected(message) if message.contains("failed validation")),
        "fixture must reach rebuild validation: {error}"
    );
    assert_eq!(engine.log_offset(), offset);
    assert_eq!(engine.list(), old_entries);
    assert_decision(&submit(&mut engine, read()), Decision::Allow, &metadata);
    assert_decision(&before, Decision::Allow, &metadata);

    let offset = engine.log_offset();
    engine
        .install(invalid, SCHEMA, None, None)
        .expect_err("reject invalid replacement");
    assert_eq!(engine.log_offset(), offset);
    assert_eq!(engine.list(), old_entries);
    assert_decision(&submit(&mut engine, read()), Decision::Allow, &metadata);
}

#[test]
fn action_schema_success_and_failure_keep_authorization_and_attribution_together() {
    const LOGIN: &str = r#"
action Login appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;
    let store = Store::new("schema");
    let mut engine = store.open();
    engine.install(PERMIT, SCHEMA, None, None).expect("install");
    let original = installed_metadata(&engine);
    let login_policy = r#"@id("login") @owner("identity")
permit (principal, action == Action::"Login", resource);"#;
    engine
        .batch(vec![
            Verb::SetActionSchema {
                action_schema: format!("{SCHEMA}\n{LOGIN}"),
            },
            Verb::Add {
                policy: login_policy.into(),
            },
        ])
        .expect("widen schema and add newly valid policy");
    let handles = tokens(&engine);
    let expected = installed_metadata(&engine);
    assert_decision(&submit(&mut engine, read()), Decision::Allow, &original);
    assert_decision(
        &submit(&mut engine, event("Login", "request", "report")),
        Decision::Allow,
        &selected(&expected, &handles[1..]),
    );

    let entries = engine.list();
    let offset = engine.log_offset();
    engine
        .batch(vec![
            Verb::Update {
                id: handles[0].clone(),
                policy: r#"@id("rejected")
forbid (principal, action == Action::"Read", resource);"#
                    .into(),
            },
            Verb::SetActionSchema {
                action_schema: SCHEMA.into(),
            },
        ])
        .expect_err("removing referenced Login must reject the entire batch");
    assert_eq!(engine.log_offset(), offset);
    assert_eq!(engine.list(), entries);
    assert_eq!(installed_metadata(&engine), expected);
    assert_decision(&submit(&mut engine, read()), Decision::Allow, &original);
    assert_decision(
        &submit(&mut engine, event("Login", "request", "report")),
        Decision::Allow,
        &selected(&expected, &handles[1..]),
    );
}

#[test]
fn custom_service_history_is_recorded_and_annotation_updates_reset_temporal_state() {
    let store = Store::new("custom");
    let mut engine = store.open();
    engine
        .install(
            &format!("{PERMIT}\n{}", temporal_forbid("before", "audit")),
            SCHEMA,
            Some(CUSTOM_EVENTS),
            None,
        )
        .expect("install using non-default decision and history kinds");
    let handles = tokens(&engine);
    let old_metadata = installed_metadata(&engine);
    let allowed = selected(&old_metadata, &handles[..1]);
    let denied = selected(&old_metadata, &handles[1..]);
    assert_decision(
        &submit(&mut engine, event("Read", "authorize", "report")),
        Decision::Allow,
        &allowed,
    );
    let history = engine
        .submit(event("Read", "audit", "report"))
        .expect("accept history");
    assert!(matches!(history.outcome, Outcome::Recorded));
    let before = submit(&mut engine, event("Read", "authorize", "report"));
    assert_decision(&before, Decision::Deny, &denied);
    assert_decision(
        &submit(&mut engine, event("Read", "authorize", "other")),
        Decision::Allow,
        &allowed,
    );

    let applied = engine
        .batch(vec![Verb::AppendActionSchema {
            fragment: "entity Team;".into(),
        }])
        .expect("additive schema change under the actual custom service");
    assert!(
        applied.leaves_retained > 0,
        "schema changes retain temporal state"
    );
    assert_decision(
        &submit(&mut engine, event("Read", "authorize", "report")),
        Decision::Deny,
        &denied,
    );

    engine
        .batch(vec![Verb::Update {
            id: handles[1].clone(),
            policy: temporal_forbid("after", "audit"),
        }])
        .expect("annotation-only update follows existing temporal reset semantics");
    assert_eq!(tokens(&engine), handles);
    assert_decision(
        &submit(&mut engine, event("Read", "authorize", "report")),
        Decision::Allow,
        &allowed,
    );
    let history = engine
        .submit(event("Read", "audit", "report"))
        .expect("new history");
    assert!(matches!(history.outcome, Outcome::Recorded));
    let new_denied = selected(&installed_metadata(&engine), &handles[1..]);
    assert_ne!(new_denied, denied);
    assert_decision(
        &submit(&mut engine, event("Read", "authorize", "report")),
        Decision::Deny,
        &new_denied,
    );
    assert_decision(&before, Decision::Deny, &denied);
}

fn recovery(checkpoint: bool) {
    let store = Store::new(if checkpoint { "checkpoint" } else { "full_log" });
    let mut engine = store.open();
    engine
        .install(
            &format!(
                r#"@id("deleted")
permit (principal, action == Action::"Export", resource);
{PERMIT}
{}"#,
                temporal_forbid("original", "audit")
            ),
            SCHEMA,
            Some(CUSTOM_EVENTS),
            None,
        )
        .expect("install");
    let handles = tokens(&engine);
    engine
        .batch(vec![
            Verb::Delete {
                id: handles[0].clone(),
            },
            Verb::Update {
                id: handles[2].clone(),
                policy: temporal_forbid("persisted", "audit"),
            },
        ])
        .expect("change metadata and shift source positions before recovery");
    let history = engine
        .submit(event("Read", "audit", "report"))
        .expect("history");
    assert!(matches!(history.outcome, Outcome::Recorded));
    let before_metadata = installed_metadata(&engine);
    let denied = selected(&before_metadata, &handles[2..]);
    let before = submit(&mut engine, event("Read", "authorize", "report"));
    assert_decision(&before, Decision::Deny, &denied);
    let watermark = checkpoint.then(|| engine.checkpoint().expect("checkpoint and prune"));
    // A real tail after the checkpoint exercises replay on top of restored
    // metadata and ensures the recovering engine rebuilds for later changes.
    engine
        .batch(vec![Verb::Add {
            policy: r#"@id("tail") @reviewed
permit (principal, action == Action::"Export", resource);"#
                .into(),
        }])
        .expect("append a policy change");
    let entries = engine.list();
    let expected = installed_metadata(&engine);
    let tail = entries.last().unwrap().token.clone();
    drop(engine);

    {
        let log = DurableLog::open(&store.0).expect("inspect recovery path");
        if let Some(watermark) = watermark {
            assert!(watermark > history.offset);
            assert_eq!(log.base_offset(), watermark, "history really was pruned");
            assert_eq!(
                log.get_snapshot()
                    .expect("snapshot")
                    .expect("checkpoint exists")
                    .up_to_offset,
                watermark
            );
            assert!(
                log.next_offset() > watermark,
                "post-checkpoint changes remain"
            );
        } else {
            assert_eq!(log.base_offset(), 0, "full log is available");
            assert!(log.get_snapshot().expect("snapshot lookup").is_none());
        }
    }
    let mut recovered = store.open();
    assert_eq!(recovered.list(), entries, "recovery must not remint tokens");
    assert_eq!(installed_metadata(&recovered), expected);
    assert_decision(
        &submit(&mut recovered, event("Read", "authorize", "report")),
        Decision::Deny,
        &denied,
    );
    assert_decision(
        &submit(&mut recovered, event("Read", "authorize", "other")),
        Decision::Allow,
        &selected(&expected, &handles[1..2]),
    );
    assert_decision(
        &submit(&mut recovered, event("Export", "authorize", "report")),
        Decision::Allow,
        &selected(&expected, &[tail]),
    );
    recovered
        .batch(vec![Verb::Delete {
            id: handles[2].clone(),
        }])
        .expect("delete recovered determining policy");
    assert_decision(
        &submit(&mut recovered, event("Read", "authorize", "report")),
        Decision::Allow,
        &selected(&expected, &handles[1..2]),
    );
    assert_decision(&before, Decision::Deny, &denied);
}

#[test]
fn full_log_recovery_restores_tokens_annotations_and_temporal_history() {
    recovery(false);
}

#[test]
fn checkpoint_and_pruned_log_recovery_restore_attribution_and_temporal_history() {
    recovery(true);
}

#[test]
fn direct_authorizers_with_both_backends_retain_language_response_and_rule_refs() {
    let source = format!("{PERMIT}\n{}", temporal_forbid("language", "response"));
    let interpreter = Authorizer::new(lower(&source, SCHEMA, None));
    let local = Authorizer::builder(lower(&source, SCHEMA, None))
        .temporal_engine(LocalTemporalEngine::new())
        .build()
        .expect("build authorizer over lower-level local backend");
    for mut authorizer in [interpreter, local] {
        let allowed: Response = authorizer
            .is_authorized(&read().timestamp(1).build())
            .expect("decision before history");
        assert_eq!(allowed.decision(), Decision::Allow);
        assert_eq!(allowed.diagnostics().reason().count(), 1);
        let history: Option<Response> =
            authorizer.is_authorized(&event("Read", "response", "report").timestamp(2).build());
        assert!(history.is_none());
        let denied: Response = authorizer
            .is_authorized(&read().timestamp(3).build())
            .expect("decision after history");
        assert_eq!(denied.decision(), Decision::Deny);
        assert_eq!(denied.diagnostics().errors().count(), 0);
        assert_eq!(denied.diagnostics().reason().count(), 1);
        let reason: &DogwoodRuleRef = denied.diagnostics().reason().next().unwrap();
        // No `..`: adding required public fields breaks this construction and
        // exhaustive destructuring, even when decision semantics still agree.
        let DogwoodRuleRef {
            rule_index,
            cedar_policy_id,
        } = reason.clone();
        assert_eq!(rule_index, 1);
        assert_eq!(
            DogwoodRuleRef {
                rule_index,
                cedar_policy_id
            },
            *reason
        );
    }
}
