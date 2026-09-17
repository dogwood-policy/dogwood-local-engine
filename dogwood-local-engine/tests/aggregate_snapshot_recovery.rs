use dogwood_language::{
    Event, LoweredPolicySet, PolicySchema, ServiceSchema, TemporalEngine, UNPINNED_EVENT_SCHEMA,
    parse_trace,
};
use dogwood_local_engine::{LocalTemporalEngine, Record, TickRate};

const SCHEMA: &str = r#"
namespace Test {
  entity User;
  entity Gateway;

  action "Transfer" appliesTo {
    principal: [User],
    resource: [Gateway],
    context: {}
  };

  action "Alert" appliesTo {
    principal: [User],
    resource: [Gateway],
    context: {}
  };
}
"#;

const POLICY: &str = r#"
permit (
    principal,
    action == Test::Action::"Alert",
    resource
)
when temporal {
    (count for (t: Timepoint). where (
        formerly within 1h (
            Test::Action::"Transfer"::response{ requestId: _ } && tp(t)
        )
    )) < count for (t: Timepoint). where (
        formerly within 1h (
            Test::Action::"Transfer"::request{ requestId: _ } && tp(t)
        )
    )
};
"#;

fn lowered() -> LoweredPolicySet {
    let service = ServiceSchema::builder()
        .event_schema_str(UNPINNED_EVENT_SCHEMA)
        .build()
        .expect("event schema");
    let schema = PolicySchema::from_cedarschema_str(SCHEMA).expect("action schema");
    LoweredPolicySet::from_str(POLICY, &service, &schema).expect("policy lowers")
}

/// Slicing off, deliberately: this test reads the leaf's verdict at timepoints
/// whose action is `Transfer`, and the rule that owns the leaf is scoped to
/// `Alert`. A real decision never asks that question — an authorize for
/// `Transfer` cannot reach the `Alert` rule — so with slicing on `evaluate()`
/// correctly reports the leaf `false` there (`dogwood_language::DecisionLeafMap`).
/// The subject here is
/// snapshot-plus-tail-replay fidelity, which needs the raw aggregate verdict at
/// every step, so `disable_slicing` restores `evaluate()`'s "compute every leaf"
/// reading for the probe.
fn prepared(lowered: &LoweredPolicySet) -> LocalTemporalEngine {
    let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
    let signatures: Vec<_> = lowered.event_signatures().collect();
    let mut engine = LocalTemporalEngine::new().with_tick_rate(TickRate::NANOS);
    engine.disable_slicing();
    engine
        .prepare(&leaves, lowered.cedar_schema(), &signatures)
        .expect("engine prepares");
    engine
}

fn events() -> Vec<Event> {
    parse_trace(
        r#"
@1700000000000000000 scope(principal: Test::User::"alice", resource: Test::Gateway::"gw1") Test::Action::"Transfer"::request(callerPrincipal: Test::User::"alice", callerResource: Test::Gateway::"gw1", requestId: "u1")
@1700000001000000000 scope(principal: Test::User::"bob", resource: Test::Gateway::"gw1") Test::Action::"Transfer"::request(callerPrincipal: Test::User::"bob", callerResource: Test::Gateway::"gw1", requestId: "u2")
@1700000002000000000 scope(principal: Test::User::"alice", resource: Test::Gateway::"gw1") Test::Action::"Transfer"::response(callerPrincipal: Test::User::"alice", callerResource: Test::Gateway::"gw1", requestId: "u1")
@1700000003000000000 scope(principal: Test::User::"alice", resource: Test::Gateway::"gw1") Test::Action::"Alert"::request(callerPrincipal: Test::User::"alice", callerResource: Test::Gateway::"gw1", requestId: "a1")
@1700000004000000000 scope(principal: Test::User::"bob", resource: Test::Gateway::"gw1") Test::Action::"Transfer"::response(callerPrincipal: Test::User::"bob", callerResource: Test::Gateway::"gw1", requestId: "u2")
@1700000005000000000 scope(principal: Test::User::"alice", resource: Test::Gateway::"gw1") Test::Action::"Alert"::request(callerPrincipal: Test::User::"alice", callerResource: Test::Gateway::"gw1", requestId: "a2")
"#,
    )
    .expect("trace parses")
}

fn roundtrip(event: &Event) -> Event {
    let decoded =
        match Record::decode(&Record::Event(event.clone()).encode()).expect("record decodes") {
            Record::Event(event) => event,
            _ => unreachable!("encoded an event"),
        };
    assert_eq!(&decoded, event, "event record must preserve every field");
    decoded
}

fn verdict(engine: &mut LocalTemporalEngine, leaf_id: &str) -> bool {
    engine.evaluate().expect("evaluates")[leaf_id]
}

#[test]
fn aggregate_comparison_survives_snapshot_and_tail_replay() {
    let lowered = lowered();
    let leaf_id = lowered
        .temporal_fields()
        .next()
        .expect("one temporal leaf")
        .id
        .clone();
    let events = events();

    let mut uninterrupted = prepared(&lowered);
    let mut snapshotted = prepared(&lowered);
    uninterrupted.observe(&events[0]);
    snapshotted.observe(&events[0]);
    assert!(verdict(&mut uninterrupted, &leaf_id));
    assert!(verdict(&mut snapshotted, &leaf_id));

    let snapshot = snapshotted.save_snapshot();
    let mut recovered = prepared(&lowered);
    assert!(recovered.load_snapshot(&snapshot));

    for event in &events[1..5] {
        uninterrupted.observe(event);
        recovered.step_monitors(&roundtrip(event));
    }

    uninterrupted.observe(&events[5]);
    recovered.observe(&events[5]);
    assert!(
        !verdict(&mut uninterrupted, &leaf_id),
        "two requests and two responses make 2 < 2 false"
    );
    assert_eq!(
        verdict(&mut recovered, &leaf_id),
        verdict(&mut uninterrupted, &leaf_id),
        "snapshot plus tail replay must match uninterrupted execution"
    );
}
