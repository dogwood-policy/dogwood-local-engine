use std::collections::BTreeMap;

use dogwood_language::cedar::Schema;
use dogwood_language::{
    Decision, DogwoodRuleRef, LoweredPolicySet, PolicySchema, Response, ServiceSchema,
};

use super::super::{
    DecisionResponse, DurableTemporalEngine, Outcome, Record, RuleAttribution, attribute_response,
    build_attributions,
};
use super::{ACTION_SCHEMA, PERMIT_ALL, POLICY, event, store};
use crate::PolicySet;

#[test]
fn attribution_rebuild_requires_one_exact_cedar_policy_per_entry() {
    let schema = PolicySchema::from_cedarschema_str(ACTION_SCHEMA).unwrap();
    let lowered = LoweredPolicySet::from_str(
        &format!("{PERMIT_ALL}\n{POLICY}"),
        &ServiceSchema::defaults(),
        &schema,
    )
    .unwrap();
    let policies = PolicySet::from_statements([PERMIT_ALL.into(), POLICY.into()], 0);
    let rules: Vec<_> = lowered.rules().collect();
    let build =
        |rules: Vec<DogwoodRuleRef>| build_attributions(rules, lowered.as_cedar(), &policies);
    assert_eq!(build(rules.clone()).unwrap().len(), 2);
    assert!(build(rules[..1].to_vec()).is_err(), "missing rule");
    let first_id = rules[0].cedar_policy_id.as_str();
    let second_id = rules[1].cedar_policy_id.as_str();
    for (case, rule_index, cedar_policy_id) in [
        ("duplicate source position", 0, second_id),
        ("unknown source position", 2, second_id),
        ("duplicate Cedar policy", 1, first_id),
        ("unknown Cedar policy", 1, "unknown"),
    ] {
        let mut invalid = rules.clone();
        invalid[1] = DogwoodRuleRef {
            rule_index,
            cedar_policy_id: cedar_policy_id.into(),
        };
        assert!(build(invalid).is_err(), "{case}");
    }
    let mut extra = rules;
    extra.push(DogwoodRuleRef {
        rule_index: 2,
        cedar_policy_id: "policy_2".into(),
    });
    assert!(build(extra).is_err(), "extra rule");
    assert!(
        build_attributions(
            lowered.rules(),
            &dogwood_language::cedar::PolicySet::new(),
            &policies,
        )
        .is_err(),
        "missing Cedar set"
    );
}

#[test]
fn accepted_attribution_failure_denies_without_partial_reasons_and_keeps_errors() {
    let path = store("attribution_mismatch");
    let source = format!(
        r#"{PERMIT_ALL}
            @id("second") {PERMIT_ALL}
            forbid(principal, action == Test::Action::"Read", resource)
            when {{ 9223372036854775807 + 1 > 0 }};"#
    );
    let mut engine = DurableTemporalEngine::open(&path, 0).unwrap();
    engine.install(&source, ACTION_SCHEMA, None, None).unwrap();
    // An ordinary Cedar evaluation error accompanies two determining permits.
    let good = read_decision(&mut engine);
    assert_eq!(good.diagnostics().reason().count(), 2);
    assert!(good.diagnostics().errors().next().is_some());
    let authorizer_errors: Vec<_> = good.diagnostics().errors().map(str::to_owned).collect();

    enum Corruption {
        WrongCedarId,
        MissingMapping,
    }
    for corruption in [Corruption::WrongCedarId, Corruption::MissingMapping] {
        let metadata = &mut engine.running.as_mut().unwrap().attributions;
        match corruption {
            Corruption::WrongCedarId => metadata[1].cedar_policy_id = "unexpected".into(),
            Corruption::MissingMapping => metadata.clear(),
        }
        let offset = engine.log_offset();
        let submitted = engine.submit(event("Read", "public")).unwrap();
        assert_eq!(submitted.offset, offset);
        assert_eq!(engine.log_offset(), offset + 1, "accepted exactly once");
        let Outcome::Decision(response) = submitted.outcome else {
            panic!("decision");
        };
        assert!(!response.allowed());
        assert_eq!(response.decision(), Decision::Deny);
        assert_eq!(response.diagnostics().reason().count(), 0);
        let errors: Vec<_> = response.diagnostics().errors().collect();
        assert_eq!(&errors[..authorizer_errors.len()], authorizer_errors);
        assert_eq!(errors.len(), authorizer_errors.len() + 1);
        assert!(errors.last().unwrap().contains("policy attribution"));
        engine
            .log
            .scan_from(offset, |found, bytes| {
                assert_eq!(found, offset);
                assert_eq!(Record::decode(bytes).unwrap().timestamp(), submitted.ts);
            })
            .unwrap();
    }
    drop(engine);
    // The derived corruption was never persisted; normal rebuild restores it.
    let mut engine = DurableTemporalEngine::open(&path, 0).unwrap();
    let restored = read_decision(&mut engine);
    assert_eq!(restored.decision(), good.decision());
    let reasons = |response: &DecisionResponse| {
        response
            .diagnostics()
            .reason()
            .map(|a| (a.token.clone(), a.annotations.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(reasons(&restored), reasons(&good));
    assert_eq!(
        restored.diagnostics().errors().collect::<Vec<_>>(),
        good.diagnostics().errors().collect::<Vec<_>>(),
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn repeated_determining_rule_is_returned_once() {
    let (raw, metadata) = ordered_response();
    let response = attribute_response(&raw, &metadata);
    assert!(response.allowed());
    assert_eq!(
        response
            .diagnostics()
            .reason()
            .map(|a| &a.token)
            .collect::<Vec<_>>(),
        [
            &metadata[0].attribution.token,
            &metadata[1].attribution.token
        ],
    );
    assert_eq!(
        response.diagnostics().errors().collect::<Vec<_>>(),
        ["preserved error"]
    );
}

#[test]
fn attribution_failure_discards_partial_reasons_and_keeps_errors() {
    let (raw, mut metadata) = ordered_response();
    // Force a valid attribution to be assembled before an invalid one.
    // Real Cedar reason order is unspecified; this backend pins the order.
    metadata[1].cedar_policy_id = "unexpected".into();
    let failed = attribute_response(&raw, &metadata);
    assert!(!failed.allowed());
    assert_eq!(
        failed.diagnostics().reason().count(),
        0,
        "discard partial result"
    );
    let errors: Vec<_> = failed.diagnostics().errors().collect();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0], "preserved error");
    assert!(errors[1].contains("policy attribution"));
}

#[cfg(feature = "fault-injection")]
#[test]
fn failed_commit_keeps_the_old_authorizer_and_attribution_together() {
    use crate::fault_injection::{FaultInjector, StorageFailurePoint};
    use crate::{DurableConfig, Verb};
    use std::sync::Arc;
    let path = store("attribution_commit_failure");
    let faults = Arc::new(FaultInjector::new());
    let mut engine = DurableTemporalEngine::open_with_config(
        &path,
        DurableConfig::new(0).with_fault_injector(faults.clone()),
    )
    .unwrap();
    engine
        .install(
            &format!(r#"@description("old") {PERMIT_ALL}"#),
            ACTION_SCHEMA,
            None,
            None,
        )
        .unwrap();
    let token = engine.list()[0].token.clone();
    let before = read_decision(&mut engine);
    faults.fail_on(StorageFailurePoint::CommitBeforeCommit, 1);
    let offset = engine.log_offset();
    let error = engine
        .batch(vec![Verb::Update {
            id: token,
            policy: r#"@description("new")
                forbid(principal, action == Test::Action::"Read", resource);"#
                .into(),
        }])
        .unwrap_err();
    assert!(
        error.to_string().contains("injected storage failure"),
        "{error}"
    );
    assert_eq!(engine.log_offset(), offset);
    let after = read_decision(&mut engine);
    assert!(after.allowed(), "old permit still authorizes");
    assert_eq!(after, before, "old metadata is still active");
    drop(engine);
    let mut engine = DurableTemporalEngine::open(&path, 0).unwrap();
    let recovered = read_decision(&mut engine);
    assert_eq!(
        recovered, before,
        "recovery sees the previous committed policy"
    );
    let _ = std::fs::remove_file(path);
}

fn read_decision(engine: &mut DurableTemporalEngine) -> DecisionResponse {
    let Outcome::Decision(response) = engine.submit(event("Read", "public")).unwrap().outcome
    else {
        panic!("Read must produce a decision");
    };
    response
}

// Two determining permits with reason order [0, 0, 1] and an authorizer error.
fn ordered_response() -> (Response, Vec<RuleAttribution>) {
    struct RepeatedPolicy;
    impl dogwood_language::PolicyEngine for RepeatedPolicy {
        fn prepare(
            &mut self,
            _: &dogwood_language::cedar::PolicySet,
            _: &Schema,
        ) -> Result<(), dogwood_language::Error> {
            Ok(())
        }
        fn is_authorized(
            &self,
            _: dogwood_language::AuthorizationRequest<'_>,
        ) -> dogwood_language::AuthorizationDecision {
            dogwood_language::AuthorizationDecision {
                decision: dogwood_language::Decision::Allow,
                determining_policy_ids: vec![
                    "policy_0".into(),
                    "policy_0".into(),
                    "policy_1".into(),
                ],
                errors: vec!["preserved error".into()],
            }
        }
    }
    let schema = PolicySchema::from_cedarschema_str(ACTION_SCHEMA).unwrap();
    let lowered = LoweredPolicySet::from_str(
        &format!("{PERMIT_ALL}\n{PERMIT_ALL}"),
        &ServiceSchema::defaults(),
        &schema,
    )
    .unwrap();
    let policies = PolicySet::from_statements([PERMIT_ALL.into(), PERMIT_ALL.into()], 0);
    let metadata = build_attributions(lowered.rules(), lowered.as_cedar(), &policies).unwrap();
    let mut authorizer = dogwood_language::Authorizer::builder(lowered)
        .policy_engine(RepeatedPolicy)
        .build()
        .unwrap();
    let raw = authorizer
        .is_authorized(&event("Read", "public").build())
        .unwrap();
    assert_eq!(
        raw.diagnostics()
            .reason()
            .map(|rule| rule.rule_index)
            .collect::<Vec<_>>(),
        [0, 0, 1],
    );
    (raw, metadata)
}
