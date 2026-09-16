//! Wire-side event decoding: [`WireEvent`] → [`EventBuilder`] → [`Event`].
//!
//! The durable log's record format — the [`JsonEventCodec`][dogwood_local_engine::JsonEventCodec] the engine appends
//! and replays with — now lives in `dogwood-local-engine` and ships as that
//! crate's default codec, so a durable engine needs no codec wired in. This
//! module keeps only the server's *wire* concern: turning an admitted
//! [`WireEvent`] into the Dogwood event the engine observes.
//!
//! The mapping stops at an [`EventBuilder`] — an event with content but **no
//! finalized timestamp** — because the durable engine, not the wire, owns the
//! clock: it assigns the store timestamp at the append point (`DESIGN.md` §3.3)
//! and finalizes the builder itself. [`to_event_builder`] is that primitive;
//! [`to_event`] is a convenience for callers that already hold an explicit
//! timestamp (recovery, oracle tests).

use dogwood_language::{Event, EventBuilder, Value};

use serde_json::Value as Json;

use crate::protocol::WireEvent;

/// Map a wire event to an un-timestamped [`EventBuilder`]: content only, no
/// `.timestamp(..)` and no `.build()`. The durable engine finalizes it with the
/// timestamp it assigns, so the store's stamp stays authoritative and a client
/// has no seam at which to set one ([`WireEvent`] carries none, deliberately).
///
/// Unresolvable pieces are dropped rather than rejected, mirroring the
/// interpreter: a field the schema does not declare is simply never read, and a
/// missing field a policy *does* read resolves to `None` — which drops the
/// candidate row and so fails **closed**. Rejecting instead would let a client
/// turn a typo into a hard error it could distinguish from a deny.
pub fn to_event_builder(wire: &WireEvent) -> EventBuilder {
    let mut builder: EventBuilder = Event::builder(&wire.action, &wire.kind);

    if let Some(p) = &wire.principal {
        builder = builder.principal(p);
    }
    if let Some(r) = &wire.resource {
        builder = builder.resource(r);
    }

    // The logged temporal record and the request context are separate bags by
    // design (see `EventBuilder::field` vs `request_context`); a field both need
    // is sent by the client in both.
    for (group, value) in &wire.logged {
        if let Json::Object(members) = value {
            for (name, v) in members {
                builder = builder.field(group, name, json_to_value(v));
            }
        }
    }
    for (group, value) in &wire.context {
        if let Json::Object(members) = value {
            for (name, v) in members {
                builder = builder.request_context(group, name, json_to_value(v));
            }
        }
    }

    for (uid, value) in &wire.entities {
        if let Json::Object(attrs) = value {
            let pairs: Vec<(&str, Value)> = attrs
                .iter()
                .map(|(k, v)| (k.as_str(), json_to_value(v)))
                .collect();
            builder = builder.entity(uid, pairs);
        }
    }
    for (uid, value) in &wire.parents {
        if let Json::Array(items) = value {
            let uids: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
            builder = builder.entity_parents(uid, uids);
        }
    }

    builder
}

/// Build a finished [`Event`] from a wire event and an **explicit** timestamp.
///
/// A convenience over [`to_event_builder`] for callers that already hold the
/// store-assigned timestamp — recovery replay and the oracle tests — rather than
/// letting the engine mint one. The live `submit` path does not use this: it
/// hands the engine the builder and lets it assign the timestamp.
pub fn to_event(wire: &WireEvent, ts: i64) -> Event {
    to_event_builder(wire).timestamp(ts).build()
}

/// Convert wire JSON to a Dogwood [`Value`].
///
/// Two conversions are worth naming:
///
/// - **Entity refs.** JSON has no entity type, so a string of canonical
///   `Ns::Type::"id"` shape becomes a [`Value::Entity`]. This is what lets a
///   client send `"User::\"alice\""` and have a policy's
///   `principal == User::"alice"` match it. A string that is not of that shape
///   stays a string, so ordinary text is unaffected.
/// - **Non-integer numbers** become [`Value::Decimal`] carrying their text,
///   which is how Dogwood represents decimals throughout (Cedar has no float).
fn json_to_value(json: &Json) -> Value {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Decimal(n.to_string()),
        },
        Json::String(s) => match parse_entity_uid(s) {
            Some(v) => v,
            None => Value::String(s.clone()),
        },
        Json::Array(items) => Value::Array(items.iter().map(json_to_value).collect()),
        Json::Object(members) => Value::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), json_to_value(v)))
                .collect(),
        ),
    }
}

/// Recognize a canonical Cedar entity-uid literal `Ns::Type::"id"` and unescape
/// its id, mirroring the `.log` trace parser so a wire event and a replayed
/// trace event produce identical values.
///
/// Requires the closing quote to be final so a string that merely *contains* a
/// uid-like prefix is left alone.
fn parse_entity_uid(s: &str) -> Option<Value> {
    let q = s.find("::\"")?;
    if !s.ends_with('"') || s.len() < q + 4 {
        return None;
    }
    let ty = &s[..q];
    if ty.is_empty() {
        return None;
    }
    let raw = &s[q + 3..s.len() - 1];
    // Unescape `\"` and `\\`, so `Value::Entity.id` holds the true id (the
    // inverse of the escaping the frontend applies at the Cedar boundary).
    let mut id = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) => id.push(next),
                // A trailing lone backslash: not a canonical literal.
                None => return None,
            }
        } else if c == '"' {
            // An unescaped interior quote means this is not a single uid.
            return None;
        } else {
            id.push(c);
        }
    }
    Some(Value::Entity {
        ty: ty.to_string(),
        id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;

    /// A wire event with every bag populated survives the wire → `Event` →
    /// record → `Event` path unchanged. This is the property recovery depends
    /// on: a replayed event must be *identical* to the one that was accepted,
    /// or a post-restart verdict can differ from the live one.
    ///
    /// Round-tripped through [`Record`], which is what recovery actually reads.
    /// This used to go through the engine's `JsonEventCodec` — a codec the server
    /// stopped using when it took ownership of the record format, so the test was
    /// asserting the property of something no longer on the path.
    #[test]
    fn event_round_trips_through_the_log_record() {
        let mut wire = WireEvent::new("Example::Action::Login", "request");
        wire.principal = Some("Example::OAuthUser::\"alice\"".to_string());
        wire.resource = Some("Example::Gateway::\"gw1\"".to_string());
        wire.logged.insert(
            "input".to_string(),
            serde_json::json!({ "user": "alice", "count": 3, "ok": true }),
        );
        wire.context.insert(
            "input".to_string(),
            serde_json::json!({ "user": "alice", "count": 3 }),
        );
        wire.entities.insert(
            "Example::OAuthUser::\"alice\"".to_string(),
            serde_json::json!({ "dept": "eng" }),
        );
        wire.parents.insert(
            "Example::OAuthUser::\"alice\"".to_string(),
            serde_json::json!(["Example::Group::\"admins\""]),
        );

        let event = to_event(&wire, 1234);
        let bytes = Record::Event(event.clone()).encode();
        let back = match Record::decode(&bytes).expect("decodes") {
            Record::Event(e) => e,
            other => panic!("expected an event record, got {other:?}"),
        };

        assert_eq!(event, back, "log record must round-trip the event exactly");
        assert_eq!(back.timestamp(), 1234);
        assert_eq!(back.kind(), "request");
        assert_eq!(back.action(), "Login");
    }

    /// A canonical uid string becomes an entity value (so `principal ==
    /// User::"alice"` matches), while ordinary text stays a string.
    #[test]
    fn uid_shaped_strings_become_entities_and_others_do_not() {
        assert_eq!(
            json_to_value(&serde_json::json!("User::\"alice\"")),
            Value::Entity {
                ty: "User".to_string(),
                id: "alice".to_string()
            }
        );
        // An id containing an escaped quote round-trips to the true id.
        assert_eq!(
            json_to_value(&serde_json::json!(r#"User::"a\"b""#)),
            Value::Entity {
                ty: "User".to_string(),
                id: "a\"b".to_string()
            }
        );
        for plain in ["alice", "a::b", "not a uid", "", "::\"x\""] {
            assert!(
                matches!(json_to_value(&serde_json::json!(plain)), Value::String(_)),
                "{plain:?} must stay a string"
            );
        }
    }
}
