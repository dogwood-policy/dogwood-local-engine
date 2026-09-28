//! The **persisted formats**: the log record envelope, and
//! the snapshot payload.
//!
//! # The kinds
//!
//! ```text
//! {"ts": <i64>, "event": { … }}                     an ingested event
//! {"ts": <i64>, "add":  {"id", "token", "statement"}}   a policy installed (ordinal + handle minted)
//! {"ts": <i64>, "update": {"id", "statement"}}      a policy's content replaced
//! {"ts": <i64>, "delete": {"id"}}                   a policy removed
//! {"ts": <i64>, "reset":  {"id"}}                   a policy's history cleared
//! {"ts": <i64>, "delete_all": {}}                   every policy removed
//! {"ts": <i64>, "reset_all":  {}}                   every policy's history cleared
//! {"ts": <i64>, "set_action_schema": {"action_schema"}}   the action schema re-set
//! {"ts": <i64>, "append_action_schema": {"fragment"}}     appended to the action schema
//! ```
//!
//! The event schema and macro library are **not** here: they are store
//! configuration, set once and held in a
//! metadata slot, so they never enter the ordered record stream.
//!
//! One discriminant, checked by presence. Each is either an event or **one
//! policy-management verb**. There is deliberately **no `Batch` record**: a batch is
//! a *set* of these verb records committed in one transaction
//! (`log.commit(&[Write::Append …])`), and because no event can interleave under
//! the single-writer lock they occupy contiguous offsets. Replay is therefore
//! grouping-agnostic — it folds the records forward one at a time and never needs
//! to know which were one batch, because consecutive verbs fold
//! observationally-equivalently (no intermediate state was ever observed).
//!
//! **Minted ids are recorded, like timestamps.** Each `Add` carries the
//! engine-assigned [`PolicyId`], written into the record exactly as `submit`
//! writes the timestamp it assigned, so replay re-applies and re-mints nothing
//! Every record is a redo record: once a snapshot summarizes it (the
//! snapshot carries the *folded* bundle), it is reclaimable like any event.

use dogwood_language::Event;
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::Value as Json;
use std::fmt;

use crate::durable::Installed;
use crate::policy_store::{PolicyId, PolicyToken};
use crate::{event_from_json, event_to_json};

/// Magic prefix on a snapshot payload, so a payload written by a build that did
/// not name its policy is recognised as such rather than misparsed.
const SNAPSHOT_MAGIC: &[u8; 4] = b"DWSP";
const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_HEADER_LEN: usize = 18;

/// A JSON value deserialized without allowing any object key to occur twice.
///
/// `serde_json::Value` normally keeps the last value for a duplicate key. That
/// is unsuitable for a durable format: two readers choosing different values
/// would replay different facts. This visitor rejects duplicates recursively
/// before converting the wire value into typed record structures.
struct UniqueJson(Json);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Json::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Json::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Json::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Json::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(Json::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Json::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Json::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Json::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            values.push(value.0);
        }
        Ok(UniqueJson(Json::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format_args!(
                    "duplicate JSON object key `{key}`"
                )));
            }
            values.insert(key, map.next_value::<UniqueJson>()?.0);
        }
        Ok(UniqueJson(Json::Object(values)))
    }
}

/// One record in the durable log: an ingested event, or one policy-management
/// verb. Every variant carries the
/// store-assigned timestamp, its position in the one order events and policy
/// changes share.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// An ingested event, at the timestamp the store assigned it.
    Event(Event),
    /// A new policy installed, born fresh (empty history). Both the internal
    /// [`PolicyId`] ordinal and the opaque [`PolicyToken`] handle are recorded
    /// here so replay re-uses them and never re-mints — the ordinal keys
    /// the transplant, the token is the caller's handle; the statement is already
    /// canonical.
    Add {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
        /// The minted ordinal.
        id: PolicyId,
        /// The minted handle.
        token: PolicyToken,
        /// The canonical statement.
        statement: String,
    },
    /// A policy's content replaced by id — same id, reset history ("update
    /// means reset").
    Update {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
        /// The ordinal of the replaced policy.
        id: PolicyId,
        /// The new canonical statement.
        statement: String,
    },
    /// A policy removed by id.
    Delete {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
        /// The ordinal of the removed policy.
        id: PolicyId,
    },
    /// One policy's accumulated history cleared; content unchanged.
    Reset {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
        /// The ordinal of the reset policy.
        id: PolicyId,
    },
    /// Every policy removed. The schema is kept and the empty set stays
    /// installed, so decisions fail closed.
    DeleteAll {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
    },
    /// Every policy's history cleared; all policies kept.
    ResetAll {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
    },
    /// The action schema re-set: revalidate + re-lower the whole set.
    SetActionSchema {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
        /// The new action schema.
        action_schema: String,
    },
    /// A fragment appended to the action schema: revalidate + re-lower the whole
    /// set under the concatenation. The record carries the *fragment*, not
    /// the merged schema — replay concatenates it onto the schema in force with
    /// the same rule the live fold used, so both reach the identical result.
    AppendActionSchema {
        /// The store-assigned timestamp, in epoch nanoseconds.
        ts: i64,
        /// The appended declarations.
        fragment: String,
    },
}

impl Record {
    /// The timestamp this record carries — the store-assigned position in the
    /// one order events and policy changes share.
    pub fn timestamp(&self) -> i64 {
        match self {
            Record::Event(e) => e.timestamp(),
            Record::Add { ts, .. }
            | Record::Update { ts, .. }
            | Record::Delete { ts, .. }
            | Record::Reset { ts, .. }
            | Record::DeleteAll { ts }
            | Record::ResetAll { ts }
            | Record::SetActionSchema { ts, .. }
            | Record::AppendActionSchema { ts, .. } => *ts,
        }
    }
}

fn record_field(field: &str) -> String {
    field.to_string()
}

fn record_text(text: &str) -> Json {
    Json::String(text.to_string())
}

fn record_i64(integer: i64) -> Json {
    Json::Number(integer.into())
}

fn record_u64(integer: u64) -> Json {
    Json::Number(integer.into())
}

fn record_marker() -> Json {
    Json::Object(serde_json::Map::new())
}

fn record_to_json(record: &Record) -> Json {
    let timestamp = record_i64(record.timestamp());
    let mut envelope = serde_json::Map::with_capacity(2);
    envelope.insert(record_field("ts"), timestamp);
    match record {
        Record::Event(event) => {
            envelope.insert(record_field("event"), event_to_json(event));
        }
        Record::Add {
            id,
            token,
            statement,
            ..
        } => {
            let mut payload = serde_json::Map::with_capacity(3);
            payload.insert(record_field("id"), record_u64(id.0));
            payload.insert(record_field("token"), record_text(&token.0));
            payload.insert(record_field("statement"), record_text(statement));
            envelope.insert(record_field("add"), Json::Object(payload));
        }
        Record::Update { id, statement, .. } => {
            let mut payload = serde_json::Map::with_capacity(2);
            payload.insert(record_field("id"), record_u64(id.0));
            payload.insert(record_field("statement"), record_text(statement));
            envelope.insert(record_field("update"), Json::Object(payload));
        }
        Record::Delete { id, .. } => {
            let mut payload = serde_json::Map::with_capacity(1);
            payload.insert(record_field("id"), record_u64(id.0));
            envelope.insert(record_field("delete"), Json::Object(payload));
        }
        Record::Reset { id, .. } => {
            let mut payload = serde_json::Map::with_capacity(1);
            payload.insert(record_field("id"), record_u64(id.0));
            envelope.insert(record_field("reset"), Json::Object(payload));
        }
        Record::DeleteAll { .. } => {
            envelope.insert(record_field("delete_all"), record_marker());
        }
        Record::ResetAll { .. } => {
            envelope.insert(record_field("reset_all"), record_marker());
        }
        Record::SetActionSchema { action_schema, .. } => {
            let mut payload = serde_json::Map::with_capacity(1);
            payload.insert(record_field("action_schema"), record_text(action_schema));
            envelope.insert(record_field("set_action_schema"), Json::Object(payload));
        }
        Record::AppendActionSchema { fragment, .. } => {
            let mut payload = serde_json::Map::with_capacity(1);
            payload.insert(record_field("fragment"), record_text(fragment));
            envelope.insert(record_field("append_action_schema"), Json::Object(payload));
        }
    }
    Json::Object(envelope)
}

fn serialize_record_json(json: &Json) -> Vec<u8> {
    // Built from serde_json's own value type, so serialization cannot fail.
    serde_json::to_vec(json).unwrap_or_default()
}

fn parse_record_json(bytes: &[u8]) -> Result<Json, String> {
    serde_json::from_slice::<UniqueJson>(bytes)
        .map(|json| json.0)
        .map_err(|error| format!("record json: {error}"))
}

fn record_decode_error(message: &str) -> String {
    message.to_string()
}

fn record_json_i64(value: &Json) -> Option<i64> {
    match value {
        Json::Number(number) => number.as_i64(),
        _ => None,
    }
}

fn record_json_u64(value: &Json) -> Option<u64> {
    match value {
        Json::Number(number) => number.as_u64(),
        _ => None,
    }
}

fn into_record_json_object(value: Json) -> Option<serde_json::Map<String, Json>> {
    match value {
        Json::Object(object) => Some(object),
        _ => None,
    }
}

fn into_record_json_text(value: Json) -> Option<String> {
    match value {
        Json::String(text) => Some(text),
        _ => None,
    }
}

fn decode_add_payload(payload: Json, timestamp: i64) -> Result<Record, String> {
    let mut object = match into_record_json_object(payload) {
        Some(object) => object,
        None => return Err(record_decode_error("record add payload is not an object")),
    };
    crate::codec::require_exact_fields(&object, &["id", "token", "statement"], "record add")?;
    let id_json = match crate::codec::json_object_remove(&mut object, "id") {
        Some(value) => value,
        None => return Err(record_decode_error("record add id is missing")),
    };
    let token_json = match crate::codec::json_object_remove(&mut object, "token") {
        Some(value) => value,
        None => return Err(record_decode_error("record add token is missing")),
    };
    let statement_json = match crate::codec::json_object_remove(&mut object, "statement") {
        Some(value) => value,
        None => return Err(record_decode_error("record add statement is missing")),
    };
    let id = match record_json_u64(&id_json) {
        Some(id) => id,
        None => return Err(record_decode_error("record add id is not a u64")),
    };
    let token = match into_record_json_text(token_json) {
        Some(token) => token,
        None => return Err(record_decode_error("record add token is not a string")),
    };
    let statement = match into_record_json_text(statement_json) {
        Some(statement) => statement,
        None => {
            return Err(record_decode_error("record add statement is not a string"));
        }
    };
    Ok(Record::Add {
        ts: timestamp,
        id: PolicyId(id),
        token: PolicyToken(token),
        statement,
    })
}

fn decode_id_payload(payload: Json, context: &str) -> Result<u64, String> {
    let mut object = match into_record_json_object(payload) {
        Some(object) => object,
        None => return Err(record_decode_error(context)),
    };
    crate::codec::require_exact_fields(&object, &["id"], context)?;
    let id_json = match crate::codec::json_object_remove(&mut object, "id") {
        Some(value) => value,
        None => return Err(record_decode_error(context)),
    };
    match record_json_u64(&id_json) {
        Some(id) => Ok(id),
        None => Err(record_decode_error(context)),
    }
}

fn decode_update_payload(payload: Json, timestamp: i64) -> Result<Record, String> {
    let mut object = match into_record_json_object(payload) {
        Some(object) => object,
        None => {
            return Err(record_decode_error(
                "record update payload is not an object",
            ));
        }
    };
    crate::codec::require_exact_fields(&object, &["id", "statement"], "record update")?;
    let id_json = match crate::codec::json_object_remove(&mut object, "id") {
        Some(value) => value,
        None => return Err(record_decode_error("record update id is missing")),
    };
    let statement_json = match crate::codec::json_object_remove(&mut object, "statement") {
        Some(value) => value,
        None => return Err(record_decode_error("record update statement is missing")),
    };
    let id = match record_json_u64(&id_json) {
        Some(id) => id,
        None => return Err(record_decode_error("record update id is not a u64")),
    };
    let statement = match into_record_json_text(statement_json) {
        Some(statement) => statement,
        None => {
            return Err(record_decode_error(
                "record update statement is not a string",
            ));
        }
    };
    Ok(Record::Update {
        ts: timestamp,
        id: PolicyId(id),
        statement,
    })
}

fn decode_marker_payload(payload: Json, context: &str) -> Result<(), String> {
    let object = match into_record_json_object(payload) {
        Some(object) => object,
        None => return Err(record_decode_error(context)),
    };
    if crate::codec::json_object_len(&object) == 0 {
        Ok(())
    } else {
        Err(record_decode_error(context))
    }
}

fn decode_single_text_payload(payload: Json, field: &str, context: &str) -> Result<String, String> {
    let mut object = match into_record_json_object(payload) {
        Some(object) => object,
        None => return Err(record_decode_error(context)),
    };
    crate::codec::require_exact_fields(&object, &[field], context)?;
    let value = match crate::codec::json_object_remove(&mut object, field) {
        Some(value) => value,
        None => return Err(record_decode_error(context)),
    };
    match into_record_json_text(value) {
        Some(text) => Ok(text),
        None => Err(record_decode_error(context)),
    }
}

fn decode_record_envelope(
    object: &mut serde_json::Map<String, Json>,
    kind: &str,
    context: &str,
) -> Result<(i64, Json), String> {
    crate::codec::require_exact_fields(&*object, &["ts", kind], context)?;
    let timestamp_json = match crate::codec::json_object_remove(object, "ts") {
        Some(value) => value,
        None => return Err(record_decode_error("record timestamp is missing")),
    };
    let payload = match crate::codec::json_object_remove(object, kind) {
        Some(value) => value,
        None => return Err(record_decode_error("record payload is missing")),
    };
    let timestamp = match record_json_i64(&timestamp_json) {
        Some(timestamp) => timestamp,
        None => return Err(record_decode_error("record timestamp is not an i64")),
    };
    Ok((timestamp, payload))
}

fn decode_event_record(object: &mut serde_json::Map<String, Json>) -> Result<Record, String> {
    let (timestamp, payload) = decode_record_envelope(object, "event", "record event")?;
    event_from_json(&payload, timestamp).map(Record::Event)
}

fn record_from_json(json: Json) -> Result<Record, String> {
    let mut object = match into_record_json_object(json) {
        Some(object) => object,
        None => return Err(record_decode_error("record is not an object")),
    };

    if crate::codec::json_object_contains(&object, "event") {
        decode_event_record(&mut object)
    } else if crate::codec::json_object_contains(&object, "add") {
        let (timestamp, payload) = decode_record_envelope(&mut object, "add", "record add")?;
        decode_add_payload(payload, timestamp)
    } else if crate::codec::json_object_contains(&object, "update") {
        let (timestamp, payload) = decode_record_envelope(&mut object, "update", "record update")?;
        decode_update_payload(payload, timestamp)
    } else if crate::codec::json_object_contains(&object, "delete") {
        let (timestamp, payload) = decode_record_envelope(&mut object, "delete", "record delete")?;
        let id = decode_id_payload(payload, "record delete id is not a u64")?;
        Ok(Record::Delete {
            ts: timestamp,
            id: PolicyId(id),
        })
    } else if crate::codec::json_object_contains(&object, "reset") {
        let (timestamp, payload) = decode_record_envelope(&mut object, "reset", "record reset")?;
        let id = decode_id_payload(payload, "record reset id is not a u64")?;
        Ok(Record::Reset {
            ts: timestamp,
            id: PolicyId(id),
        })
    } else if crate::codec::json_object_contains(&object, "delete_all") {
        let (timestamp, payload) =
            decode_record_envelope(&mut object, "delete_all", "record delete_all")?;
        decode_marker_payload(payload, "record delete_all marker is not empty")?;
        Ok(Record::DeleteAll { ts: timestamp })
    } else if crate::codec::json_object_contains(&object, "reset_all") {
        let (timestamp, payload) =
            decode_record_envelope(&mut object, "reset_all", "record reset_all")?;
        decode_marker_payload(payload, "record reset_all marker is not empty")?;
        Ok(Record::ResetAll { ts: timestamp })
    } else if crate::codec::json_object_contains(&object, "set_action_schema") {
        let (timestamp, payload) =
            decode_record_envelope(&mut object, "set_action_schema", "record set_action_schema")?;
        let action_schema = decode_single_text_payload(
            payload,
            "action_schema",
            "record set_action_schema payload is malformed",
        )?;
        Ok(Record::SetActionSchema {
            ts: timestamp,
            action_schema,
        })
    } else if crate::codec::json_object_contains(&object, "append_action_schema") {
        let (timestamp, payload) = decode_record_envelope(
            &mut object,
            "append_action_schema",
            "record append_action_schema",
        )?;
        let fragment = decode_single_text_payload(
            payload,
            "fragment",
            "record append_action_schema payload is malformed",
        )?;
        Ok(Record::AppendActionSchema {
            ts: timestamp,
            fragment,
        })
    } else {
        Err(record_decode_error(
            "record must contain exactly one recognised kind",
        ))
    }
}

impl Record {
    /// Serialize to the bytes appended to the log.
    pub fn encode(&self) -> Vec<u8> {
        serialize_record_json(&record_to_json(self))
    }

    /// Reconstruct a record from log bytes.
    ///
    /// An unrecognised record is an error rather than something skipped: replay
    /// that silently ignored a record it did not understand would reconstruct
    /// state missing whatever that record carried, and for a history-gated rule
    /// missing history simply passes.
    pub fn decode(bytes: &[u8]) -> Result<Record, String> {
        let json = parse_record_json(bytes)?;
        record_from_json(json)
    }
}

/// What the engine stores in a snapshot: the derived monitor state, **and the
/// policy set it was derived under**.
///
/// # Why the bundle belongs in here
///
/// Monitor state is positional — the k-th leaf's state restores into the k-th
/// leaf — so "state as of offset N" is meaningless without knowing which policy
/// was installed at N.
///
/// Recovery starts from whatever policy the snapshot says it
/// describes, so the state always matches the leaves it is loaded into, and can
/// then evolve forward through any later changes the log records.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotPayload {
    /// The policy set in force at the snapshot's offset.
    pub bundle: Installed,
    /// The highest timestamp assigned at the snapshot's offset, in epoch
    /// nanoseconds.
    ///
    /// Here because a snapshot's job is to carry everything needed to resume
    /// *without* the records it summarizes — and the assigned clock is one of
    /// those things.
    pub last_ts: i64,
    /// The engine's serialized monitor state (`LocalTemporalEngine::save_snapshot`).
    pub engine: Vec<u8>,
}

impl SnapshotPayload {
    /// `DWSP | u16 version | i64 last_ts | u32 bundle_len | bundle JSON |
    /// engine bytes`.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let bundle = serde_json::to_vec(&self.bundle)
            .map_err(|error| format!("snapshot payload bundle: {error}"))?;
        let bundle_len = checked_bundle_len(bundle.len())?;
        let capacity = SNAPSHOT_HEADER_LEN
            .checked_add(bundle.len())
            .and_then(|len| len.checked_add(self.engine.len()))
            .ok_or("snapshot payload length is out of range")?;
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.last_ts.to_le_bytes());
        out.extend_from_slice(&bundle_len.to_le_bytes());
        out.extend_from_slice(&bundle);
        out.extend_from_slice(&self.engine);
        Ok(out)
    }

    /// Parse an [`encode`](Self::encode)d payload; errors on a bad magic, an unsupported version, or a truncated or malformed bundle.
    pub fn decode(bytes: &[u8]) -> Result<SnapshotPayload, String> {
        if bytes.len() < SNAPSHOT_HEADER_LEN || &bytes[..4] != SNAPSHOT_MAGIC {
            return Err("snapshot payload does not name its policy set".to_string());
        }
        let mut version = [0u8; 2];
        version.copy_from_slice(&bytes[4..6]);
        let version = u16::from_le_bytes(version);
        if version != SNAPSHOT_VERSION {
            return Err(format!("unsupported snapshot payload version {version}"));
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[6..14]);
        let last_ts = i64::from_le_bytes(ts);
        let mut len = [0u8; 4];
        len.copy_from_slice(&bytes[14..18]);
        let len = u32::from_le_bytes(len) as usize;
        let end = SNAPSHOT_HEADER_LEN
            .checked_add(len)
            .filter(|e| *e <= bytes.len())
            .ok_or("snapshot payload bundle length is out of range")?;
        let bundle: Installed = serde_json::from_slice(&bytes[SNAPSHOT_HEADER_LEN..end])
            .map_err(|e| format!("snapshot payload bundle: {e}"))?;
        Ok(SnapshotPayload {
            bundle,
            last_ts,
            engine: bytes[end..].to_vec(),
        })
    }
}

fn checked_bundle_len(len: usize) -> Result<u32, String> {
    u32::try_from(len).map_err(|_| "snapshot payload bundle is too large".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dogwood_language::Value;

    fn event_at(timestamp: i64) -> Event {
        Event::builder("Ns::Action::Read", "request")
            .timestamp(timestamp)
            .principal("Ns::User::\"alice\"")
            .resource("Ns::Doc::\"d1\"")
            .field("input", "doc", Value::String("secret".into()))
            .request_context("input", "doc", Value::String("secret".into()))
            .build()
    }

    fn event() -> Event {
        event_at(1_700_000_000_123_456_789)
    }

    /// Every verb variant, for the round-trip below.
    fn every_verb() -> Vec<Record> {
        vec![
            Record::Add {
                ts: 1,
                id: PolicyId(3),
                token: PolicyToken("SPtest0000000000000003".to_string()),
                statement: "permit (principal, action, resource);".to_string(),
            },
            Record::Update {
                ts: 2,
                id: PolicyId(3),
                statement: "forbid (principal, action, resource);".to_string(),
            },
            Record::Delete {
                ts: 3,
                id: PolicyId(7),
            },
            Record::Reset {
                ts: 4,
                id: PolicyId(7),
            },
            Record::DeleteAll { ts: 5 },
            Record::ResetAll { ts: 6 },
            Record::SetActionSchema {
                ts: 7,
                action_schema: "entity User;".to_string(),
            },
            Record::AppendActionSchema {
                ts: 8,
                fragment: "action Delete appliesTo { principal: User, resource: User };"
                    .to_string(),
            },
        ]
    }

    #[test]
    fn an_event_record_round_trips() {
        let r = Record::Event(event());
        let back = Record::decode(&r.encode()).expect("decodes");
        match (&r, &back) {
            (Record::Event(a), Record::Event(b)) => {
                assert_eq!(a.timestamp(), b.timestamp());
                assert_eq!(a.kind(), b.kind());
                assert_eq!(a.principal_uid(), b.principal_uid());
                assert_eq!(a.resource_uid(), b.resource_uid());
            }
            other => panic!("wrong kind: {other:?}"),
        }
    }

    /// Every verb record survives the byte round trip unchanged — the minted id,
    /// the canonical statement, and the nullable event schema all carried exactly.
    #[test]
    fn every_verb_record_round_trips() {
        for r in every_verb() {
            assert_eq!(
                Record::decode(&r.encode()).expect("decodes"),
                r,
                "verb did not round-trip: {r:?}"
            );
        }
    }

    #[test]
    fn integer_boundaries_round_trip_for_every_record_kind() {
        for timestamp in [i64::MIN, i64::MAX] {
            let records = [
                Record::Event(event_at(timestamp)),
                Record::Add {
                    ts: timestamp,
                    id: PolicyId(u64::MAX),
                    token: PolicyToken("SPmax".to_string()),
                    statement: "permit (principal, action, resource);".to_string(),
                },
                Record::Update {
                    ts: timestamp,
                    id: PolicyId(u64::MAX),
                    statement: "forbid (principal, action, resource);".to_string(),
                },
                Record::Delete {
                    ts: timestamp,
                    id: PolicyId(u64::MAX),
                },
                Record::Reset {
                    ts: timestamp,
                    id: PolicyId(u64::MAX),
                },
                Record::DeleteAll { ts: timestamp },
                Record::ResetAll { ts: timestamp },
                Record::SetActionSchema {
                    ts: timestamp,
                    action_schema: "entity User;".to_string(),
                },
                Record::AppendActionSchema {
                    ts: timestamp,
                    fragment: "entity Resource;".to_string(),
                },
            ];
            for record in records {
                assert_eq!(
                    Record::decode(&record.encode()).expect("boundary record decodes"),
                    record
                );
            }
        }
    }

    #[test]
    fn decoder_moves_owned_string_allocations_into_records() {
        let token = "SP-owned-token-allocation".to_string();
        let statement = "permit (principal, action, resource) when { true };".to_string();
        let token_pointer = token.as_ptr();
        let statement_pointer = statement.as_ptr();
        let mut add_payload = serde_json::Map::new();
        add_payload.insert("id".to_string(), Json::Number(7u64.into()));
        add_payload.insert("token".to_string(), Json::String(token));
        add_payload.insert("statement".to_string(), Json::String(statement));
        let mut add_envelope = serde_json::Map::new();
        add_envelope.insert("ts".to_string(), Json::Number(11i64.into()));
        add_envelope.insert("add".to_string(), Json::Object(add_payload));

        match record_from_json(Json::Object(add_envelope)).expect("add decodes") {
            Record::Add {
                token, statement, ..
            } => {
                assert_eq!(token.0.as_ptr(), token_pointer);
                assert_eq!(statement.as_ptr(), statement_pointer);
            }
            other => panic!("wrong record kind: {other:?}"),
        }

        let schema = "entity OwnedSchemaAllocation;".to_string();
        let schema_pointer = schema.as_ptr();
        let mut schema_payload = serde_json::Map::new();
        schema_payload.insert("action_schema".to_string(), Json::String(schema));
        let mut schema_envelope = serde_json::Map::new();
        schema_envelope.insert("ts".to_string(), Json::Number(12i64.into()));
        schema_envelope.insert(
            "set_action_schema".to_string(),
            Json::Object(schema_payload),
        );

        match record_from_json(Json::Object(schema_envelope)).expect("schema record decodes") {
            Record::SetActionSchema { action_schema, .. } => {
                assert_eq!(action_schema.as_ptr(), schema_pointer);
            }
            other => panic!("wrong record kind: {other:?}"),
        }
    }

    /// The kinds must not be confusable: a verb read as an event (or one verb as
    /// another) would fold the wrong change into the set. Presence of a single
    /// discriminant key decides, so no two encodings can be read as each other.
    #[test]
    fn the_kinds_are_distinguishable() {
        let mut all = vec![Record::Event(event())];
        all.extend(every_verb());
        for r in &all {
            let decoded = Record::decode(&r.encode()).expect("decodes");
            assert_eq!(&decoded, r, "a record decoded as a different kind: {r:?}");
        }
    }

    /// A record replay does not understand must fail loudly. Skipping it would
    /// silently drop whatever it carried, and for a history-gated rule missing
    /// history means the rule stops firing.
    #[test]
    fn an_unknown_record_kind_is_an_error() {
        let bogus = serde_json::to_vec(&serde_json::json!({ "ts": 1, "mystery": {} })).unwrap();
        Record::decode(&bogus).expect_err("must not be silently accepted");

        let no_ts = serde_json::to_vec(&serde_json::json!({ "event": {} })).unwrap();
        assert!(
            Record::decode(&no_ts).is_err(),
            "a record needs a timestamp"
        );

        // A verb missing its required payload field is malformed, not silently
        // defaulted.
        let no_id = serde_json::to_vec(&serde_json::json!({ "ts": 1, "delete": {} })).unwrap();
        assert!(Record::decode(&no_id).is_err(), "delete needs an `id`");
        let no_stmt =
            serde_json::to_vec(&serde_json::json!({ "ts": 1, "add": { "id": 0 } })).unwrap();
        assert!(Record::decode(&no_stmt).is_err(), "add needs a `statement`");
    }

    /// The timestamp is in the envelope for every kind, so one order covers
    /// events and policy changes alike.
    #[test]
    fn every_kind_carries_its_position_in_the_order() {
        assert_eq!(
            Record::Event(event()).timestamp(),
            1_700_000_000_123_456_789
        );
        for r in every_verb() {
            let ts = r.timestamp();
            assert_eq!(
                Record::decode(&r.encode()).expect("decodes").timestamp(),
                ts
            );
        }
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    fn bundle() -> Installed {
        Installed {
            policies: crate::policy_store::PolicySet::from_statements(
                ["permit (principal, action, resource);".to_string()],
                0,
            ),
            action_schema: "entity User;".to_string(),
        }
    }

    #[test]
    fn a_payload_round_trips_with_its_policy() {
        let p = SnapshotPayload {
            bundle: bundle(),
            last_ts: 1_786_000_000_000_000_007,
            engine: vec![0, 1, 2, 250, 255],
        };
        let encoded = p.encode().expect("encodes");
        assert_eq!(SnapshotPayload::decode(&encoded).expect("decodes"), p);
    }

    /// Empty state is a real case — a snapshot taken before any event.
    #[test]
    fn an_empty_state_round_trips() {
        let p = SnapshotPayload {
            bundle: bundle(),
            last_ts: 0,
            engine: Vec::new(),
        };
        let encoded = p.encode().expect("encodes");
        assert_eq!(SnapshotPayload::decode(&encoded).expect("decodes"), p);
    }

    /// A payload from a build that did not name its policy must be REFUSED, not
    /// read as though its leading bytes were a bundle. Recovery treats an
    /// unreadable snapshot as absent, which is safe; misreading one is not.
    #[test]
    fn a_payload_without_the_magic_is_refused() {
        let legacy = vec![7u8; 64];
        let err = SnapshotPayload::decode(&legacy).expect_err("must refuse");
        assert!(err.contains("does not name its policy set"), "{err}");
        assert!(SnapshotPayload::decode(&[]).is_err(), "empty is refused");
    }

    /// The clock travels with the policy and the state, and survives values a
    /// naive encoding would mangle.
    #[test]
    fn the_assigned_clock_round_trips_including_its_extremes() {
        for last_ts in [0, -1, 1, i64::MIN, i64::MAX, 1_786_000_000_000_000_001] {
            let p = SnapshotPayload {
                bundle: bundle(),
                last_ts,
                engine: vec![1, 2, 3],
            };
            let encoded = p.encode().expect("encodes");
            let back = SnapshotPayload::decode(&encoded).expect("decodes");
            assert_eq!(back.last_ts, last_ts, "{last_ts} did not survive");
            assert_eq!(back, p);
        }
    }

    #[test]
    fn a_truncated_payload_is_refused() {
        let p = SnapshotPayload {
            bundle: bundle(),
            last_ts: -1,
            engine: vec![9, 9],
        };
        let bytes = p.encode().expect("encodes");
        let err = SnapshotPayload::decode(&bytes[..16]).expect_err("must refuse");
        assert!(err.contains("does not name its policy set"), "{err}");
        // A plausible header claiming more bundle than exists.
        let mut bogus = SNAPSHOT_MAGIC.to_vec();
        bogus.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        bogus.extend_from_slice(&0i64.to_le_bytes());
        bogus.extend_from_slice(&9999u32.to_le_bytes());
        bogus.extend_from_slice(b"{}");
        assert!(SnapshotPayload::decode(&bogus).is_err());
    }

    #[test]
    fn bundle_lengths_larger_than_the_wire_field_are_rejected() {
        assert_eq!(checked_bundle_len(u32::MAX as usize), Ok(u32::MAX));
        #[cfg(target_pointer_width = "64")]
        assert!(checked_bundle_len(u32::MAX as usize + 1).is_err());
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;

    /// A malformed record is an error, not a panic — recovery reads bytes a crash
    /// may have truncated mid-write, and `replay_from` turns any decode failure
    /// into a refusal to open rather than a skipped record.
    #[test]
    fn malformed_records_are_rejected() {
        for bad in [
            &b""[..],
            &b"{"[..],
            &br#"{"ts": 1}"#[..],
            &br#"{"event": {"action": "A", "kind": "request"}}"#[..],
            &br#"{"ts": 1, "event": {"kind": "request"}}"#[..],
            &br#"{"ts": "not a number", "event": {"action": "A", "kind": "request"}}"#[..],
            &br#"{"ts": 1, "neither": {}}"#[..],
        ] {
            assert!(
                Record::decode(bad).is_err(),
                "{:?} must be rejected",
                std::str::from_utf8(bad).unwrap_or("<invalid utf8>")
            );
        }
    }

    #[test]
    fn ambiguous_and_noncanonical_envelopes_are_rejected() {
        for bad in [
            &br#"{"ts":1,"delete":{"id":1},"reset":{"id":1}}"#[..],
            &br#"{"ts":1,"delete":{"id":1},"unknown":{}}"#[..],
            &br#"{"ts":1,"delete":{"id":1,"unknown":0}}"#[..],
            &br#"{"ts":1,"delete_all":{"unexpected":true}}"#[..],
            &br#"{"ts":1,"delete":null}"#[..],
        ] {
            assert!(Record::decode(bad).is_err());
        }
    }

    #[test]
    fn duplicate_keys_are_rejected_at_every_record_layer() {
        for bad in [
            &br#"{"ts":1,"ts":2,"delete":{"id":1}}"#[..],
            &br#"{"ts":1,"delete":{"id":1,"id":2}}"#[..],
            &br#"{"ts":1,"event":{"action":{"id":"Read","namespace":[]},"kind":"request","principal":null,"resource":null,"logged":{"x":1,"x":2},"context":{},"entities":{},"parents":{}}}"#[..],
        ] {
            assert!(Record::decode(bad).is_err());
        }
    }
}
