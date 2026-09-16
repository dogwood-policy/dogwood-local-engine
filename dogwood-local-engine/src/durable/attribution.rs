//! Decision metadata built with the authorizer and copied into responses.

use super::DurableError;
use crate::policy_store::{PolicySet, PolicyToken};
use dogwood_language::{Decision, DogwoodRuleRef, Response};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// One determining policy's durable handle and annotations.
///
/// All annotations are visible to the requesting caller. Keys and values come
/// directly from the lowered Cedar policy; `id` is an annotation, not the token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyAttribution {
    pub token: PolicyToken,
    pub annotations: BTreeMap<String, String>,
}

impl PolicyAttribution {
    /// Borrow an annotation's value. Missing keys return `None`; a present
    /// annotation with an empty value returns `Some("")`.
    pub fn annotation(&self, name: &str) -> Option<&str> {
        self.annotations.get(name).map(String::as_str)
    }

    /// The `@id` annotation, which may be absent or shared by several policies.
    /// Use [`Self::token`] for the policy's durable identity.
    pub fn annotation_id(&self) -> Option<&str> {
        self.annotation("id")
    }

    /// The `@description` annotation, if present.
    pub fn description(&self) -> Option<&str> {
        self.annotation("description")
    }
}

/// The complete result of a durable-engine authorization decision.
///
/// Reasons own their metadata from the policy set that made this decision.
/// Later policy changes cannot change an already returned response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionResponse {
    decision: Decision,
    diagnostics: DecisionDiagnostics,
}

impl DecisionResponse {
    pub fn decision(&self) -> Decision {
        self.decision
    }

    pub fn allowed(&self) -> bool {
        self.decision == Decision::Allow
    }

    pub fn diagnostics(&self) -> &DecisionDiagnostics {
        &self.diagnostics
    }
}

/// Determining policies and the authorizer's evaluation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionDiagnostics {
    reason: Vec<PolicyAttribution>,
    errors: Vec<String>,
}

impl DecisionDiagnostics {
    /// Each determining token appears once. Ordering is unspecified.
    pub fn reason(&self) -> impl Iterator<Item = &PolicyAttribution> {
        self.reason.iter()
    }

    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.errors.iter().map(String::as_str)
    }
}

/// Indexed by the lowered rule's source position, never by a durable ordinal.
#[derive(Debug)]
pub(super) struct RuleAttribution {
    pub(super) cedar_policy_id: String,
    pub(super) attribution: PolicyAttribution,
}

pub(super) fn build_attributions(
    rules: impl IntoIterator<Item = DogwoodRuleRef>,
    cedar: &dogwood_language::cedar::PolicySet,
    policies: &PolicySet,
) -> Result<Vec<RuleAttribution>, DurableError> {
    let entries: Vec<_> = policies.entries().collect();
    let mut attributions = Vec::with_capacity(entries.len());
    let mut seen_cedar_ids = BTreeSet::new();

    for (position, rule) in rules.into_iter().enumerate() {
        let entry = entries.get(rule.rule_index).ok_or_else(|| {
            DurableError::Rejected("policy attribution: missing installed policy".into())
        })?;

        if rule.rule_index != position || !seen_cedar_ids.insert(rule.cedar_policy_id.clone()) {
            return Err(DurableError::Rejected(
                "policy attribution: inconsistent lowered rule mapping".into(),
            ));
        }

        // Convert the complete opaque ID to Cedar's lookup key; never extract
        // a source index or durable identity from its spelling.
        let cedar_id = rule.cedar_policy_id.parse().map_err(|error| {
            DurableError::Rejected(format!("policy attribution: invalid Cedar id: {error}"))
        })?;

        let policy = cedar.policy(&cedar_id).ok_or_else(|| {
            DurableError::Rejected("policy attribution: missing lowered Cedar policy".into())
        })?;

        attributions.push(RuleAttribution {
            cedar_policy_id: rule.cedar_policy_id,
            attribution: PolicyAttribution {
                token: entry.token.clone(),
                annotations: policy
                    .annotations()
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .collect(),
            },
        });
    }

    if attributions.len() != entries.len() || cedar.policies().count() != entries.len() {
        return Err(DurableError::Rejected(
            "policy attribution: installed and lowered policy counts differ".into(),
        ));
    }
    Ok(attributions)
}

/// Attribution on submit visits only determining rules and their metadata.
/// Neither source text nor storage participates in this translation.
pub(super) fn attribute_response(
    response: &Response,
    metadata: &[RuleAttribution],
) -> DecisionResponse {
    let mut result = DecisionResponse {
        decision: response.decision(),
        diagnostics: DecisionDiagnostics {
            reason: Vec::new(),
            errors: response.diagnostics().errors().map(str::to_owned).collect(),
        },
    };

    let mut seen = HashSet::new();
    for rule in response.diagnostics().reason() {
        let entry = metadata
            .get(rule.rule_index)
            .filter(|entry| entry.cedar_policy_id == rule.cedar_policy_id);

        let Some(entry) = entry else {
            // Acceptance has already happened. Return its receipt with a deny,
            // preserving authorizer errors and discarding any partial reasons.
            result.decision = Decision::Deny;
            result.diagnostics.reason.clear();
            result.diagnostics.errors.push(
                "policy attribution failed: determining policy mapping is missing or inconsistent"
                    .into(),
            );
            return result;
        };

        if seen.insert(&entry.attribution.token) {
            result.diagnostics.reason.push(entry.attribution.clone());
        }
    }
    result
}
