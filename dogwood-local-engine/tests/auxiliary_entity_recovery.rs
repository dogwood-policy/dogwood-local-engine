//! Crash-image regression for auxiliary entities in persisted events.
//!
//! `DurableTemporalEngine` currently steps temporal monitors during recovery; it
//! does not re-authorize historical decision events. This test therefore checks
//! the stronger record contract directly: a decision event read from the crash
//! image must still produce the verdict it produced before persistence. That
//! contract matters to any replay/audit consumer and prevents recovery from
//! silently changing the semantic meaning of an accepted event.

use dogwood_language::{
    Authorizer, Decision, Event, EventBuilder, LoweredPolicySet, PolicySchema, ServiceSchema, Value,
};
use dogwood_local_engine::{DurableLog, DurableTemporalEngine, Outcome, Record};

const SCHEMA: &str = r#"
namespace Svc {
  entity Gateway;
  entity Group in [Group];
  entity User in [Group];
  action "Read" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: { doc: String } }
  };
}
"#;

const POLICY: &str = r#"
permit (
    principal in Svc::Group::"admins",
    action == Svc::Action::"Read",
    resource
);
"#;

const REQUIRED_ENTITY_SCHEMA: &str = r#"
namespace Svc {
  entity Gateway;
  entity User = {
    id: String
  };
  action "Read" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: { doc: String } }
  };
}
"#;

const IDENTITY_POLICY: &str = r#"
permit (
    principal == Svc::User::"alice",
    action == Svc::Action::"Read",
    resource
);
"#;

fn decide_with(event: &Event, policy: &str, schema: &str) -> Decision {
    let schema = PolicySchema::from_cedarschema_str(schema).expect("schema");
    let lowered =
        LoweredPolicySet::from_str(policy, &ServiceSchema::defaults(), &schema).expect("policy");
    Authorizer::new(lowered)
        .is_authorized(event)
        .expect("request is a decision point")
        .decision()
}

fn decide(event: &Event) -> Decision {
    decide_with(event, POLICY, SCHEMA)
}

fn event() -> EventBuilder {
    Event::builder("Svc::Action::Read", "request")
        .principal("Svc::User::\"alice\"")
        .resource("Svc::Gateway::\"gw1\"")
        .field("input", "doc", Value::String("report".to_string()))
        .request_context("input", "doc", Value::String("report".to_string()))
        .parents_for("Svc::User", "alice", [("Svc::Group", "engineering")])
        .parents_for("Svc::Group", "engineering", [("Svc::Group", "admins")])
}

fn empty_scope_entity_event() -> EventBuilder {
    Event::builder("Svc::Action::Read", "request")
        .principal_for("Svc::User", "alice")
        .resource_for("Svc::Gateway", "gw1")
        .field("input", "doc", Value::String("report".to_string()))
        .request_context("input", "doc", Value::String("report".to_string()))
        .entity_for("Svc::User", "alice", [])
}

struct TempStore(std::path::PathBuf);

impl TempStore {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "dogwood_auxiliary_entity_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn event_read_from_a_crash_image_keeps_its_live_membership_verdict() {
    let live = TempStore::new("live");
    let frozen = TempStore::new("frozen");
    let live_verdict = decide(&event().timestamp(1).build());
    assert_eq!(
        live_verdict,
        Decision::Allow,
        "positive control: alice is transitively in admins before persistence"
    );

    let mut engine = DurableTemporalEngine::open(live.path(), 0).expect("open live engine");
    engine
        .install(POLICY, SCHEMA, None, None)
        .expect("install policy");
    let submitted = engine.submit(event()).expect("submit decision event");
    let Outcome::Decision(response) = submitted.outcome else {
        panic!("request event did not produce a decision");
    };
    assert_eq!(
        response.decision(),
        live_verdict,
        "the durable engine must authorize the complete in-memory event"
    );
    std::fs::copy(live.path(), frozen.path()).expect("freeze crash image");
    drop(engine);

    // Establish that this is a complete engine image, not merely a standalone
    // DurableLog containing one hand-written record.
    drop(DurableTemporalEngine::open(frozen.path(), 0).expect("recover frozen engine"));

    let recovered = DurableLog::open(frozen.path()).expect("inspect crash image");
    let mut replayed = None;
    recovered
        .scan_from(0, |_offset, bytes| {
            let record = Record::decode(bytes).expect("decode recovered record");
            if let Record::Event(event) = record {
                assert!(replayed.is_none(), "fixture contains multiple events");
                replayed = Some(event);
            }
        })
        .expect("scan recovered log");
    let replayed = replayed.expect("the event survived the crash");

    assert_eq!(
        decide(&replayed),
        live_verdict,
        "the crash-recovered event must retain the transitive membership edge \
         that made its live verdict Allow"
    );
}

#[test]
fn event_read_from_a_crash_image_keeps_empty_entity_conformance_failure() {
    let live = TempStore::new("empty_live");
    let frozen = TempStore::new("empty_frozen");
    let bare = Event::builder("Svc::Action::Read", "request")
        .principal_for("Svc::User", "alice")
        .resource_for("Svc::Gateway", "gw1")
        .field("input", "doc", Value::String("report".to_string()))
        .request_context("input", "doc", Value::String("report".to_string()))
        .timestamp(1)
        .build();
    assert_eq!(
        decide_with(&bare, IDENTITY_POLICY, REQUIRED_ENTITY_SCHEMA),
        Decision::Allow,
        "positive control: an absent entity record leaves the scope entity bare"
    );

    let empty = empty_scope_entity_event().timestamp(1).build();
    let live_verdict = decide_with(&empty, IDENTITY_POLICY, REQUIRED_ENTITY_SCHEMA);
    assert_eq!(
        live_verdict,
        Decision::Deny,
        "positive control: supplying an empty User record fails required-attribute conformance"
    );

    let mut engine = DurableTemporalEngine::open(live.path(), 0).expect("open live engine");
    engine
        .install(IDENTITY_POLICY, REQUIRED_ENTITY_SCHEMA, None, None)
        .expect("install policy");
    let submitted = engine
        .submit(empty_scope_entity_event())
        .expect("submit decision event");
    let Outcome::Decision(response) = submitted.outcome else {
        panic!("request event did not produce a decision");
    };
    assert_eq!(
        response.decision(),
        live_verdict,
        "the durable engine must authorize the explicitly supplied empty entity"
    );
    std::fs::copy(live.path(), frozen.path()).expect("freeze crash image");
    drop(engine);

    drop(DurableTemporalEngine::open(frozen.path(), 0).expect("recover frozen engine"));

    let recovered = DurableLog::open(frozen.path()).expect("inspect crash image");
    let mut replayed = None;
    recovered
        .scan_from(0, |_offset, bytes| {
            let record = Record::decode(bytes).expect("decode recovered record");
            if let Record::Event(event) = record {
                assert!(replayed.is_none(), "fixture contains multiple events");
                replayed = Some(event);
            }
        })
        .expect("scan recovered log");
    let replayed = replayed.expect("the event survived the crash");

    assert_eq!(
        decide_with(&replayed, IDENTITY_POLICY, REQUIRED_ENTITY_SCHEMA),
        live_verdict,
        "dropping an explicitly supplied empty entity changes a live conformance Deny \
         into a recovered bare-scope Allow"
    );
}
