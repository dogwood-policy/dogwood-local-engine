//! Wire-protocol properties, checked without a socket.
//!
//! Framing and the verb split are the parts of the protocol that carry security
//! weight — a desynchronizing frame or a data-path request that deserializes into
//! a control verb would defeat the boundary the socket permissions and uid
//! allowlist establish. These tests pin that behaviour where it is cheap to
//! check, so `server_e2e.rs` can concentrate on end-to-end semantics.

use std::io::Cursor;

use dogwood_server::protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, FrameError, MAX_FRAME,
    PolicySummary, WireEvent, WireVerb, read_frame, write_frame,
};

/// Round-trip a value through the framing layer.
fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let mut buf = Vec::new();
    write_frame(&mut buf, value).expect("writes");
    read_frame(&mut Cursor::new(buf)).expect("reads")
}

/// Every request/response variant survives the wire unchanged.
#[test]
fn all_message_variants_round_trip() {
    let mut event = WireEvent::new("Drupe::Action::Login", "request");
    event.principal = Some("Drupe::OAuthUser::\"alice\"".to_string());
    event
        .logged
        .insert("input".to_string(), serde_json::json!({"user": "alice"}));

    let data_requests = vec![
        DataRequest::Submit {
            event: event.clone(),
        },
        DataRequest::Ping,
    ];
    for request in &data_requests {
        assert_eq!(&round_trip(request), request);
    }

    let data_responses = vec![
        DataResponse::Decision {
            allowed: true,
            reason: vec!["0:policy0".to_string()],
            errors: vec![],
            recorded_at_nanos: 1_786_000_000_000_000_001,
        },
        DataResponse::Decision {
            allowed: false,
            reason: vec![],
            errors: vec!["missing attribute".to_string()],
            recorded_at_nanos: i64::MAX,
        },
        DataResponse::Recorded {
            recorded_at_nanos: 1_786_000_000_000_000_002,
        },
        DataResponse::Pong {
            version: "0.1.0".to_string(),
        },
        DataResponse::Error {
            message: "nope".to_string(),
        },
    ];
    for response in &data_responses {
        assert_eq!(&round_trip(response), response);
    }

    let control_requests = vec![
        ControlRequest::Install {
            policy: "permit(principal, action, resource);".to_string(),
            action_schema: "entity User;".to_string(),
            event_schema: None,
        },
        // A batch exercising every wire verb.
        ControlRequest::Batch {
            verbs: vec![
                WireVerb::Add {
                    policy: "permit(principal, action, resource);".to_string(),
                },
                WireVerb::Update {
                    id: "SP3".to_string(),
                    policy: "forbid(principal, action, resource);".to_string(),
                },
                WireVerb::Delete {
                    id: "SP7".to_string(),
                },
                WireVerb::Reset {
                    id: "SP7".to_string(),
                },
                WireVerb::DeleteAll,
                WireVerb::ResetAll,
                WireVerb::SetActionSchema {
                    action_schema: "entity User;".to_string(),
                },
            ],
        },
        ControlRequest::List {
            max_results: Some(10),
            next_token: Some("SP4".to_string()),
        },
        ControlRequest::List {
            max_results: None,
            next_token: None,
        },
        ControlRequest::Status,
        ControlRequest::GetPolicy,
        ControlRequest::GetPolicyById {
            id: "SP2".to_string(),
        },
        ControlRequest::GetSchema,
        ControlRequest::Checkpoint,
    ];
    for request in &control_requests {
        assert_eq!(&round_trip(request), request);
    }

    let control_responses = vec![
        ControlResponse::Applied {
            applied_at_nanos: 1_786_000_000_000_000_003,
            rule_count: 2,
            leaf_count: 1,
            leaves_retained: 0,
            leaves_prospective: 1,
        },
        ControlResponse::Status {
            rule_count: 1,
            leaf_count: 1,
            incremental_leaves: 1,
            decision_kinds: vec!["request".to_string()],
            partition_key: vec!["__cedar_principal".to_string()],
            log_offset: 7,
            control_uids: vec![1000],
        },
        // The unshardable shape too: `partition_key` is skipped when empty, so
        // this exercises the round trip through the absent-field path.
        ControlResponse::Status {
            rule_count: 1,
            leaf_count: 0,
            incremental_leaves: 0,
            decision_kinds: vec!["request".to_string()],
            partition_key: Vec::new(),
            log_offset: 7,
            control_uids: vec![1000],
        },
        ControlResponse::Batched {
            minted: vec!["SP2".to_string(), "SP3".to_string()],
            applied_at_nanos: 1_786_000_000_000_000_009,
        },
        // Batched with no minted ids (a batch of only Delete/Reset/etc.).
        ControlResponse::Batched {
            minted: Vec::new(),
            applied_at_nanos: 1_786_000_000_000_000_010,
        },
        ControlResponse::PolicyList {
            policies: vec![
                PolicySummary {
                    id: "SP0".to_string(),
                    created: 1,
                    updated: 1,
                },
                PolicySummary {
                    id: "SP3".to_string(),
                    created: 2,
                    updated: 5,
                },
            ],
            next_token: Some("SP3".to_string()),
        },
        // Last page: no continuation token (skipped when absent).
        ControlResponse::PolicyList {
            policies: Vec::new(),
            next_token: None,
        },
        ControlResponse::Policy {
            source: "permit(principal, action, resource);".to_string(),
        },
        ControlResponse::Schema {
            action_schema: "entity User;".to_string(),
            event_schema: Some("decision event <A>::request { ...inputs(A) }".to_string()),
        },
        // The default-event-schema shape: `event_schema` skipped when absent.
        ControlResponse::Schema {
            action_schema: "entity User;".to_string(),
            event_schema: None,
        },
        ControlResponse::Checkpointed { up_to_offset: 9 },
        ControlResponse::Error {
            message: "rejected".to_string(),
        },
    ];
    for response in &control_responses {
        assert_eq!(&round_trip(response), response);
    }
}

/// A payload containing newlines and braces round-trips intact. This is why the
/// framing is length-prefixed rather than newline-delimited: event field values
/// are arbitrary client-supplied strings, so a newline in one must not be able to
/// split a frame — a client that could split frames could inject a second
/// request the server would attribute to it.
#[test]
fn payloads_with_newlines_and_braces_do_not_desynchronize() {
    let mut event = WireEvent::new("A", "request");
    event.logged.insert(
        "input".to_string(),
        serde_json::json!({
            "text": "line one\nline two\r\n{\"op\":\"apply\"}\n",
            "braces": "}{}{",
        }),
    );
    let request = DataRequest::Submit { event };

    // Two frames back to back: the second must be read correctly, which only
    // holds if the first was consumed exactly.
    let mut buf = Vec::new();
    write_frame(&mut buf, &request).expect("writes");
    write_frame(&mut buf, &DataRequest::Ping).expect("writes");

    let mut cursor = Cursor::new(buf);
    let first: DataRequest = read_frame(&mut cursor).expect("first frame");
    let second: DataRequest = read_frame(&mut cursor).expect("second frame");
    assert_eq!(first, request);
    assert_eq!(second, DataRequest::Ping);
}

/// A hostile length header is rejected without allocating it. The data socket is
/// reachable by the process we do not trust, so an unbounded length prefix would
/// be a trivial memory-exhaustion denial of service.
#[test]
fn oversized_length_headers_are_rejected() {
    // A header claiming ~4 GiB, with no body at all.
    let bytes = u32::MAX.to_be_bytes().to_vec();
    let result: Result<DataRequest, _> = read_frame(&mut Cursor::new(bytes));
    match result {
        Err(FrameError::TooLarge(n)) => assert_eq!(n, u32::MAX),
        other => panic!("expected TooLarge, got {other:?}"),
    }

    // One byte over the limit is also refused (the boundary itself).
    let bytes = (MAX_FRAME + 1).to_be_bytes().to_vec();
    let result: Result<DataRequest, _> = read_frame(&mut Cursor::new(bytes));
    assert!(matches!(result, Err(FrameError::TooLarge(_))));
}

/// A clean close at a frame boundary is distinguished from a truncated frame.
/// The former is how every connection ends and must not be logged as an error;
/// the latter is a protocol violation.
#[test]
fn clean_close_and_truncation_are_distinguishable() {
    // Nothing at all: clean.
    let result: Result<DataRequest, _> = read_frame(&mut Cursor::new(Vec::new()));
    assert!(
        matches!(result, Err(FrameError::Eof { at_boundary: true })),
        "empty stream is a clean close"
    );

    // A partial header: truncated.
    let result: Result<DataRequest, _> = read_frame(&mut Cursor::new(vec![0, 0]));
    assert!(
        matches!(result, Err(FrameError::Eof { at_boundary: false })),
        "partial header is a truncation"
    );

    // A full header but a short body: truncated.
    let mut bytes = 100u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(b"{}");
    let result: Result<DataRequest, _> = read_frame(&mut Cursor::new(bytes));
    assert!(
        matches!(result, Err(FrameError::Eof { at_boundary: false })),
        "short body is a truncation"
    );
}

/// Malformed JSON inside a well-formed frame is a decode error, not a panic.
#[test]
fn malformed_bodies_are_decode_errors() {
    for body in [&b"not json"[..], &b"{}"[..], &br#"{"op":"nonesuch"}"#[..]] {
        let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(body);
        let result: Result<DataRequest, _> = read_frame(&mut Cursor::new(bytes));
        assert!(
            matches!(result, Err(FrameError::Decode(_))),
            "{body:?} must be a decode error"
        );
    }
}

/// **The verb split.** A control request must not deserialize as a data request.
///
/// This is the type-level layer of the three that keep policy authoring off the
/// agent's socket (`DESIGN.md` §8.1): even if the socket mode and the uid
/// allowlist both failed, an `apply` sent to the data socket cannot be
/// interpreted as anything the data handler will act on, because `DataRequest`
/// has no such variant.
#[test]
fn control_verbs_do_not_deserialize_as_data_requests() {
    let install = ControlRequest::Install {
        policy: "permit(principal, action, resource);".to_string(),
        action_schema: "entity User;".to_string(),
        event_schema: None,
    };
    // A batch — the incremental mutating verb — must be just as unreachable from
    // the data socket as `install`.
    let batch = ControlRequest::Batch {
        verbs: vec![WireVerb::DeleteAll],
    };
    for control in [&install, &batch] {
        let json = serde_json::to_vec(control).expect("serializes");
        let as_data: Result<DataRequest, _> = serde_json::from_slice(&json);
        assert!(
            as_data.is_err(),
            "a control verb must not deserialize as any DataRequest variant: {control:?}"
        );
    }

    // And the converse: a data verb is not a control verb, so a confused client
    // cannot drive the control plane with data-shaped traffic either.
    let submit = DataRequest::Submit {
        event: WireEvent::new("A", "request"),
    };
    let json = serde_json::to_vec(&submit).expect("serializes");
    let as_control: Result<ControlRequest, _> = serde_json::from_slice(&json);
    assert!(as_control.is_err(), "a Submit must not be a ControlRequest");
}

/// A `WireEvent` carries **no timestamp field**, so a client cannot assign or
/// forge one — the store stamps every event at the append point (`DESIGN.md`
/// §3.3). A client-supplied timestamp would let a caller backdate an event out of
/// a window, or reorder itself relative to another caller.
#[test]
fn wire_events_cannot_carry_a_client_timestamp() {
    let json = serde_json::to_value(WireEvent::new("A", "request")).expect("serializes");
    let object = json.as_object().expect("object");
    for forbidden in ["ts", "timestamp", "time"] {
        assert!(
            !object.contains_key(forbidden),
            "WireEvent must not expose a `{forbidden}` field"
        );
    }

    // A client that sends one anyway is refused rather than silently ignored:
    // silently dropping it would let a caller believe it had set the time.
    let with_ts = serde_json::json!({
        "action": "A", "kind": "request", "ts": 999
    });
    let parsed: Result<WireEvent, _> = serde_json::from_value(with_ts);
    assert!(
        parsed.is_err(),
        "an event carrying a timestamp must be rejected, not silently accepted"
    );
}
