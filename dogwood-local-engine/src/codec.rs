//! The engine's built-in durable-log record format: an [`Event`] ↔ bytes codec.
//!
//! The engine is payload-agnostic (`DESIGN.md` §2): it maps an [`Event`] to and
//! from JSON and nothing more. The *envelope* — which record kind this is, and
//! the store-assigned timestamp it carries — belongs to whoever owns the log,
//! which is `dogwood-server`'s `record` module.
//!
//! # One format for the wire and the log
//!
//! Reusing the wire shape rather than inventing a second on-disk encoding means
//! recovery decodes exactly what was accepted — there is no second conversion
//! that could drift from the first and make a replayed verdict differ from the
//! live one. It also keeps the log inspectable.
//!
//! # Where the timestamp comes from
//!
//! The wire event carries none; the store assigns it (`DESIGN.md` §3.3). The
//! *record* carries it, because the assigned value is part of the durable fact — a
//! replay must reconstruct the same trace order and window ages it saw live, so
//! re-stamping at recovery time (with wall-clock, long after the fact) would
//! silently change what `formerly within 1h` means for recovered history.

use dogwood_language::{Event, EventBuilder, Value};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as Json};

fn malformed_bag_entry(bag: &str, name: &str) -> String {
    format!("record {bag}.{name}: malformed")
}

fn malformed_entity_attribute(uid: &str, name: &str) -> String {
    format!("record entities.{uid}.{name}: malformed")
}

fn malformed_entity_record(uid: &str) -> String {
    format!("record entities.{uid}: not a record")
}

fn malformed_entity_parent(uid: &str) -> String {
    format!("record parents.{uid}: malformed parent")
}

fn parent_record_not_array(uid: &str) -> String {
    format!("record parents.{uid}: not an array")
}

fn empty_parent_record(uid: &str) -> String {
    format!("record parents.{uid}: empty array")
}

fn event_missing_or_unknown_fields(context: &str) -> String {
    format!("{context} has missing or unknown fields")
}

fn event_bag_not_object(bag: &str) -> String {
    format!("record event `{bag}` is not an object")
}

fn event_optional_string_error(context: &str) -> String {
    format!("{context} is neither a string nor null")
}

fn event_namespace_non_string_error() -> String {
    "record event action namespace contains a non-string".to_string()
}

fn event_decode_error(message: &str) -> String {
    message.to_string()
}

fn restore_event_header(
    namespace: &[&str],
    action_id: &str,
    kind: &str,
    timestamp: i64,
) -> EventBuilder {
    Event::builder_for(namespace, action_id, kind).timestamp(timestamp)
}

fn restore_event_scope(
    mut builder: EventBuilder,
    principal: Option<&str>,
    resource: Option<&str>,
) -> EventBuilder {
    if let Some(uid) = principal {
        builder = builder.principal(uid);
    }
    if let Some(uid) = resource {
        builder = builder.resource(uid);
    }
    builder
}

fn ensure_entity_record(builder: EventBuilder, uid: &str) -> EventBuilder {
    builder.entity(uid, std::iter::empty::<(&str, Value)>())
}

fn restore_entity_attribute(
    builder: EventBuilder,
    uid: &str,
    name: &str,
    value: Value,
) -> EventBuilder {
    builder.entity(uid, [(name, value)])
}

fn restore_entity_parent(builder: EventBuilder, uid: &str, ty: &str, id: &str) -> EventBuilder {
    let parent = format!("{ty}::\"{}\"", escape_id(id));
    builder.entity_parents(uid, [parent.as_str()])
}

fn restore_entity_attributes(
    mut builder: EventBuilder,
    uid: &str,
    attrs: &JsonMap<String, Json>,
) -> Result<EventBuilder, String> {
    builder = ensure_entity_record(builder, uid);
    let mut entries = attrs.iter();
    loop {
        let entry = match entries.next() {
            Some(entry) => entry,
            None => break,
        };
        let decoded_result = record_to_value(entry.1);
        let decoded = match decoded_result {
            Some(value) => value,
            None => return Err(malformed_entity_attribute(uid, entry.0)),
        };
        builder = restore_entity_attribute(builder, uid, entry.0, decoded);
    }
    Ok(builder)
}

fn restore_entities(
    mut builder: EventBuilder,
    entities: &JsonMap<String, Json>,
) -> Result<EventBuilder, String> {
    let mut entries = entities.iter();
    loop {
        let entry = match entries.next() {
            Some(entry) => entry,
            None => break,
        };
        let Json::Object(attrs) = entry.1 else {
            return Err(malformed_entity_record(entry.0));
        };
        let restored = restore_entity_attributes(builder, entry.0, attrs);
        builder = match restored {
            Ok(builder) => builder,
            Err(error) => return Err(error),
        };
    }
    Ok(builder)
}

fn restore_entity_parents(
    mut builder: EventBuilder,
    uid: &str,
    items: &Vec<Json>,
) -> Result<EventBuilder, String> {
    let decoded_result = array_records_to_values(items);
    let decoded = match decoded_result {
        Some(decoded) => decoded,
        None => return Err(malformed_entity_parent(uid)),
    };
    builder = ensure_entity_record(builder, uid);
    let mut index = 0usize;
    while index < decoded.len() {
        let value = &decoded[index];
        let Value::Entity { ty, id } = value else {
            return Err(malformed_entity_parent(uid));
        };
        builder = restore_entity_parent(builder, uid, ty, id);
        index += 1;
    }
    Ok(builder)
}

fn restore_parents(
    mut builder: EventBuilder,
    parents: &JsonMap<String, Json>,
) -> Result<EventBuilder, String> {
    let mut entries = parents.iter();
    loop {
        let entry = match entries.next() {
            Some(entry) => entry,
            None => break,
        };
        let Json::Array(items) = entry.1 else {
            return Err(parent_record_not_array(entry.0));
        };
        if items.is_empty() {
            return Err(empty_parent_record(entry.0));
        }
        let restored = restore_entity_parents(builder, entry.0, items);
        builder = match restored {
            Ok(builder) => builder,
            Err(error) => return Err(error),
        };
    }
    Ok(builder)
}

/// Restore one decoded logged entry as a complete top-level value.
fn restore_logged_field(builder: EventBuilder, name: &str, value: Value) -> EventBuilder {
    builder.logged_field(name, value)
}

/// Restore one decoded context entry as a complete top-level value.
fn restore_context_field(builder: EventBuilder, name: &str, value: Value) -> EventBuilder {
    builder.request_context_field(name, value)
}

fn tagged_record(tag: &str, payload: Json) -> Json {
    let tag_value = Json::String(tag.to_string());
    let pair = vec![tag_value, payload];
    let result = Json::Array(pair);
    result
}

fn entity_record_payload(ty: &String, id: &String) -> Json {
    let parts = vec![Json::String(ty.clone()), Json::String(id.clone())];
    let result = Json::Array(parts);
    result
}

fn object_values_to_record(
    members: &std::collections::BTreeMap<String, Value>,
) -> JsonMap<String, Json> {
    let mut result = JsonMap::with_capacity(members.len());
    for entry in members.iter() {
        let encoded = value_to_record(entry.1);
        let key = entry.0.clone();
        result.insert(key, encoded);
    }
    result
}

fn array_values_to_record(items: &Vec<Value>) -> Vec<Json> {
    let mut result = Vec::with_capacity(items.len());
    let mut index = 0usize;
    while index < items.len() {
        let encoded = value_to_record(&items[index]);
        result.push(encoded);
        index += 1;
    }
    result
}

/// Render a Dogwood [`Value`] to its **log-record** JSON: an explicitly tagged
/// `[tag, payload]` pair.
///
/// The record format is tagged where a wire format is inferred, and the
/// difference is deliberate. On the wire, inference is a convenience for
/// hand-written clients (`"User::\"alice\""` means an entity, `1.5` means a
/// decimal) and any ambiguity is resolved once, at admission. A record, by
/// contrast, must reproduce the admitted `Value` **exactly** — the recovered
/// trace has to yield the same verdicts as the live one. Any scheme that infers
/// a type from an untagged payload can be forged by a client that sends the
/// payload the inference looks for: a sentinel string prefix would let the
/// literal text `__dec:1.5` come back as a decimal, and re-inferring entity
/// shape would let the string `"User::\"alice\""` come back as an entity.
/// Tagging removes the possibility rather than trying to escape around it.
fn value_to_record(value: &Value) -> Json {
    let result = match value {
        Value::Null => tagged_record("z", Json::Null),
        Value::Bool(b) => tagged_record("b", Json::Bool(*b)),
        Value::Int(i) => tagged_record("i", Json::Number(JsonNumber::from(*i))),
        // The decimal's text travels verbatim as a *string*: Dogwood compares
        // decimals structurally (`"1.5"` != `"1.50"`), so passing it through a
        // JSON number — which canonicalizes — could flip an `==`.
        Value::Decimal(d) => tagged_record("d", Json::String(d.clone())),
        Value::String(s) => tagged_record("s", Json::String(s.clone())),
        Value::Entity { ty, id } => tagged_record("e", entity_record_payload(ty, id)),
        Value::Array(items) => tagged_record("a", Json::Array(array_values_to_record(items))),
        Value::Object(members) => {
            tagged_record("o", Json::Object(object_values_to_record(members)))
        }
    };
    result
}

fn array_records_to_values(items: &Vec<Json>) -> Option<Vec<Value>> {
    let mut result = Vec::with_capacity(items.len());
    let mut index = 0usize;
    while index < items.len() {
        let decoded_result = record_to_value(&items[index]);
        let decoded = match decoded_result {
            Some(value) => value,
            None => return None,
        };
        result.push(decoded);
        index += 1;
    }
    Some(result)
}

fn object_records_to_values(
    members: &JsonMap<String, Json>,
) -> Option<std::collections::BTreeMap<String, Value>> {
    let mut result = std::collections::BTreeMap::new();
    let mut entries = members.iter();
    loop {
        let entry = match entries.next() {
            Some(entry) => entry,
            None => break,
        };
        let decoded_result = record_to_value(entry.1);
        let decoded = match decoded_result {
            Some(value) => value,
            None => return None,
        };
        let key = entry.0.clone();
        result.insert(key, decoded);
    }
    Some(result)
}

fn entity_record_to_value(parts: &Vec<Json>) -> Option<Value> {
    if parts.len() != 2 {
        return None;
    }
    let ty_result = parts[0].as_str();
    let ty = match ty_result {
        Some(ty) => ty,
        None => return None,
    };
    let id_result = parts[1].as_str();
    let id = match id_result {
        Some(id) => id,
        None => return None,
    };
    Some(Value::Entity {
        ty: ty.to_string(),
        id: id.to_string(),
    })
}

enum RecordValueTag {
    Null,
    Bool,
    Int,
    Decimal,
    String,
    Entity,
    Array,
    Object,
    Unknown,
}

fn record_value_tag(tag: &str) -> RecordValueTag {
    match tag {
        "z" => RecordValueTag::Null,
        "b" => RecordValueTag::Bool,
        "i" => RecordValueTag::Int,
        "d" => RecordValueTag::Decimal,
        "s" => RecordValueTag::String,
        "e" => RecordValueTag::Entity,
        "a" => RecordValueTag::Array,
        "o" => RecordValueTag::Object,
        _ => RecordValueTag::Unknown,
    }
}

/// Recover a value written by [`value_to_record`]. Returns `None` on any
/// malformed input — a record may have been truncated by a crash mid-write, so
/// this must fail rather than guess.
fn record_to_value(json: &Json) -> Option<Value> {
    let Json::Array(pair) = json else {
        return None;
    };
    if pair.len() != 2 {
        return None;
    }
    let tag = &pair[0];
    let payload = &pair[1];
    let tag_text_result = tag.as_str();
    let tag_text = match tag_text_result {
        Some(tag_text) => tag_text,
        None => return None,
    };
    let record_tag = record_value_tag(tag_text);
    match (record_tag, payload) {
        (RecordValueTag::Null, Json::Null) => Some(Value::Null),
        (RecordValueTag::Bool, Json::Bool(b)) => Some(Value::Bool(*b)),
        (RecordValueTag::Int, Json::Number(n)) => match n.as_i64() {
            Some(integer) => Some(Value::Int(integer)),
            None => None,
        },
        (RecordValueTag::Decimal, Json::String(s)) => Some(Value::Decimal(s.clone())),
        (RecordValueTag::String, Json::String(s)) => Some(Value::String(s.clone())),
        (RecordValueTag::Entity, Json::Array(parts)) => entity_record_to_value(parts),
        (RecordValueTag::Array, Json::Array(items)) => match array_records_to_values(items) {
            Some(values) => Some(Value::Array(values)),
            None => None,
        },
        (RecordValueTag::Object, Json::Object(members)) => {
            match object_records_to_values(members) {
                Some(values) => Some(Value::Object(values)),
                None => None,
            }
        }
        _ => None,
    }
}

fn restore_logged_fields(
    mut builder: EventBuilder,
    logged: &JsonMap<String, Json>,
) -> Result<EventBuilder, String> {
    let mut entries = logged.iter();
    loop {
        let entry = match entries.next() {
            Some(entry) => entry,
            None => break,
        };
        let decoded_result = record_to_value(entry.1);
        let decoded = match decoded_result {
            Some(value) => value,
            None => return Err(malformed_bag_entry("logged", entry.0)),
        };
        builder = restore_logged_field(builder, entry.0, decoded);
    }
    Ok(builder)
}

fn restore_context_fields(
    mut builder: EventBuilder,
    context: &JsonMap<String, Json>,
) -> Result<EventBuilder, String> {
    let mut entries = context.iter();
    loop {
        let entry = match entries.next() {
            Some(entry) => entry,
            None => break,
        };
        let decoded_result = record_to_value(entry.1);
        let decoded = match decoded_result {
            Some(value) => value,
            None => return Err(malformed_bag_entry("context", entry.0)),
        };
        builder = restore_context_field(builder, entry.0, decoded);
    }
    Ok(builder)
}

/// Serialize an [`Event`] to its log record: the assigned timestamp plus the
/// event in wire shape.
///
/// The scope principal/resource are read from the event's own accessors, and the
/// logged record from [`Event::logged_leaves`] — a schema-free enumeration of
/// every field the event carries at its dotted path, with no privileged
/// treatment of any group name (`DESIGN.md` §3.4).
/// An [`Event`]'s **content** as JSON, without the log envelope around it.
///
/// Exposed because the envelope and the payload belong to different owners. The
/// mapping below — grouped logged fields, the scope aliases, tagged `Value`s — is
/// frontend knowledge and lives here. What a *record* looks like is the caller's
/// concern (`DESIGN.md` §2), and a caller logging more than events needs to build
/// its own envelope around this rather than re-deriving the mapping.
///
/// The event's timestamp is deliberately NOT included: it orders the record, so
/// it belongs to whoever assigns it. Pass it back to
/// [`event_from_json`] on the way in.
pub fn event_to_json(event: &Event) -> Json {
    event_payload(event)
}

/// Rebuild an [`Event`] from [`event_to_json`]'s output and the timestamp its
/// envelope carried.
pub fn event_from_json(payload: &Json, ts: i64) -> Result<Event, String> {
    decode_payload(payload, ts)
}

fn event_persisted_logged_owned(event: &Event) -> std::collections::BTreeMap<String, Value> {
    event
        .logged_leaves()
        .into_iter()
        .filter_map(|(path, value)| {
            if path.len() == 1 && !scope_reconstructs_logged(event, &path[0], value) {
                Some((path[0].clone(), value.clone()))
            } else {
                None
            }
        })
        .collect()
}

fn event_logged_payload(event: &Event) -> JsonMap<String, Json> {
    let logged = event_persisted_logged_owned(event);
    object_values_to_record(&logged)
}

fn event_context_owned(event: &Event) -> std::collections::BTreeMap<String, Value> {
    event
        .request_context_groups()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect()
}

fn event_context_payload(event: &Event) -> JsonMap<String, Json> {
    let context = event_context_owned(event);
    object_values_to_record(&context)
}

fn event_entity_uids_owned(event: &Event) -> Vec<String> {
    event.entity_uids().map(str::to_string).collect()
}

fn event_entity_attributes_owned(
    event: &Event,
    uid: &str,
) -> std::collections::BTreeMap<String, Value> {
    event
        .entity_attributes(uid)
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect()
}

fn event_entity_parents_owned(event: &Event, uid: &str) -> Vec<Value> {
    event.entity_parents(uid).to_vec()
}

fn entity_attributes_nonempty(attributes: &std::collections::BTreeMap<String, Value>) -> bool {
    !attributes.is_empty()
}

fn entity_parents_nonempty(parents: &Vec<Value>) -> bool {
    !parents.is_empty()
}

fn event_entity_payload(event: &Event) -> (JsonMap<String, Json>, JsonMap<String, Json>) {
    let uids = event_entity_uids_owned(event);
    let mut entities = JsonMap::new();
    let mut parents = JsonMap::new();
    let mut index = 0usize;
    while index < uids.len() {
        let uid = &uids[index];
        let attrs = event_entity_attributes_owned(event, uid);
        let ps = event_entity_parents_owned(event, uid);
        let encoded_attrs = object_values_to_record(&attrs);
        let encoded_parents = array_values_to_record(&ps);
        let has_attributes = entity_attributes_nonempty(&attrs);
        let has_parents = entity_parents_nonempty(&ps);
        if has_attributes || !has_parents {
            entities.insert(uid.clone(), Json::Object(encoded_attrs));
        }
        if has_parents {
            parents.insert(uid.clone(), Json::Array(encoded_parents));
        }
        index += 1;
    }
    (entities, parents)
}

fn event_payload_field(field: &str) -> String {
    field.to_string()
}

fn event_payload_text(text: &str) -> Json {
    Json::String(text.to_string())
}

fn event_namespace_payload(namespace: &[String]) -> Json {
    let mut items = Vec::with_capacity(namespace.len());
    let mut index = 0usize;
    while index < namespace.len() {
        items.push(Json::String(namespace[index].clone()));
        index += 1;
    }
    Json::Array(items)
}

fn event_optional_text_payload(value: &Option<String>) -> Json {
    match value {
        Some(text) => Json::String(text.clone()),
        None => Json::Null,
    }
}

fn event_action_payload(event: &Event) -> Json {
    let namespace = event_namespace_payload(event.namespace());
    let action = event_payload_text(event.action());
    let mut members = JsonMap::with_capacity(2);
    members.insert(event_payload_field("namespace"), namespace);
    members.insert(event_payload_field("id"), action);
    Json::Object(members)
}

fn event_payload(event: &Event) -> Json {
    // `logged_leaves` emits records both whole and descended. The helper keeps
    // only complete top-level values and omits a scope alias only when scope
    // reconstruction installs the identical value.
    let logged = event_logged_payload(event);
    let context = event_context_payload(event);

    // Entity attributes and direct parents for every caller-supplied record.
    // This includes auxiliary and parent-only entities: Cedar membership can
    // traverse through entities other than the scope principal/resource.
    let (entities, parents) = event_entity_payload(event);

    // Keep the type path and opaque id separate. An action id may contain `::`,
    // so a flattened qualified string cannot be split back unambiguously.
    let action = event_action_payload(event);
    let kind = event_payload_text(event.kind());
    let principal_value = event.principal_uid();
    let resource_value = event.resource_uid();
    let principal = event_optional_text_payload(&principal_value);
    let resource = event_optional_text_payload(&resource_value);

    let mut payload = JsonMap::with_capacity(8);
    payload.insert(event_payload_field("action"), action);
    payload.insert(event_payload_field("kind"), kind);
    payload.insert(event_payload_field("principal"), principal);
    payload.insert(event_payload_field("resource"), resource);
    payload.insert(event_payload_field("logged"), Json::Object(logged));
    payload.insert(event_payload_field("context"), Json::Object(context));
    payload.insert(event_payload_field("entities"), Json::Object(entities));
    payload.insert(event_payload_field("parents"), Json::Object(parents));
    Json::Object(payload)
}

pub(crate) fn json_object_len(object: &JsonMap<String, Json>) -> usize {
    object.len()
}

pub(crate) fn json_object_contains(object: &JsonMap<String, Json>, name: &str) -> bool {
    object.contains_key(name)
}

pub(crate) fn json_object_index<'a>(object: &'a JsonMap<String, Json>, name: &str) -> &'a Json {
    &object[name]
}

#[inline(always)]
pub(crate) fn json_object_remove(object: &mut JsonMap<String, Json>, name: &str) -> Option<Json> {
    object.remove(name)
}

pub(crate) fn require_exact_fields(
    object: &JsonMap<String, Json>,
    expected: &[&str],
    context: &str,
) -> Result<(), String> {
    if json_object_len(object) != expected.len() {
        return Err(event_missing_or_unknown_fields(context));
    }
    let mut index = 0usize;
    while index < expected.len() {
        let field = expected[index];
        let contains = json_object_contains(object, field);
        if !contains {
            return Err(event_missing_or_unknown_fields(context));
        }
        index += 1;
    }
    Ok(())
}

fn require_event_fields(object: &JsonMap<String, Json>) -> Result<(), String> {
    let expected = [
        "action",
        "kind",
        "principal",
        "resource",
        "logged",
        "context",
        "entities",
        "parents",
    ];
    require_exact_fields(object, &expected, "record event")
}

fn require_action_fields(object: &JsonMap<String, Json>) -> Result<(), String> {
    let expected = ["namespace", "id"];
    require_exact_fields(object, &expected, "record event action")
}

fn parse_event_namespace(items: &Vec<Json>) -> Result<Vec<&str>, String> {
    let mut parts = Vec::with_capacity(items.len());
    let mut index = 0usize;
    while index < items.len() {
        let part = match items[index].as_str() {
            Some(part) => part,
            None => return Err(event_namespace_non_string_error()),
        };
        parts.push(part);
        index += 1;
    }
    Ok(parts)
}

fn optional_string<'a>(value: &'a Json, context: &str) -> Result<Option<&'a str>, String> {
    match value {
        Json::Null => Ok(None),
        Json::String(value) => Ok(Some(value.as_str())),
        _ => Err(event_optional_string_error(context)),
    }
}

fn event_scope_matches(event: &Event, principal: Option<&str>, resource: Option<&str>) -> bool {
    event.principal_uid().as_deref() == principal && event.resource_uid().as_deref() == resource
}

/// Reconstruct an [`Event`] from a log record.
fn decode_payload(ev: &Json, ts: i64) -> Result<Event, String> {
    let event = match ev {
        Json::Object(event) => event,
        _ => {
            return Err(event_decode_error("record event payload is not an object"));
        }
    };
    let exact_event = require_event_fields(event);
    if let Err(error) = exact_event {
        return Err(error);
    }

    let action_json = json_object_index(event, "action");
    let action = match action_json {
        Json::Object(action) => action,
        _ => {
            return Err(event_decode_error("record event `action` is not an object"));
        }
    };
    let exact_action = require_action_fields(action);
    if let Err(error) = exact_action {
        return Err(error);
    }

    let action_id_json = json_object_index(action, "id");
    let action_id = match action_id_json {
        Json::String(action_id) => action_id.as_str(),
        _ => {
            return Err(event_decode_error(
                "record event action `id` is not a string",
            ));
        }
    };
    let namespace_json = json_object_index(action, "namespace");
    let namespace_items = match namespace_json {
        Json::Array(items) => items,
        _ => {
            return Err(event_decode_error(
                "record event action `namespace` is not an array",
            ));
        }
    };
    let namespace_result = parse_event_namespace(namespace_items);
    let namespace = match namespace_result {
        Ok(namespace) => namespace,
        Err(error) => return Err(error),
    };

    let kind_json = json_object_index(event, "kind");
    let kind = match kind_json {
        Json::String(kind) => kind.as_str(),
        _ => return Err(event_decode_error("record event `kind` is not a string")),
    };

    let principal_json = json_object_index(event, "principal");
    let principal_result = optional_string(principal_json, "record event `principal`");
    let principal = match principal_result {
        Ok(principal) => principal,
        Err(error) => return Err(error),
    };
    let resource_json = json_object_index(event, "resource");
    let resource_result = optional_string(resource_json, "record event `resource`");
    let resource = match resource_result {
        Ok(resource) => resource,
        Err(error) => return Err(error),
    };

    let logged_json = json_object_index(event, "logged");
    let logged = match logged_json {
        Json::Object(logged) => logged,
        _ => return Err(event_bag_not_object("logged")),
    };
    let context_json = json_object_index(event, "context");
    let context = match context_json {
        Json::Object(context) => context,
        _ => return Err(event_bag_not_object("context")),
    };
    let entities_json = json_object_index(event, "entities");
    let entities = match entities_json {
        Json::Object(entities) => entities,
        _ => return Err(event_bag_not_object("entities")),
    };
    let parents_json = json_object_index(event, "parents");
    let parents = match parents_json {
        Json::Object(parents) => parents,
        _ => return Err(event_bag_not_object("parents")),
    };

    let namespace_slice = namespace.as_slice();
    let mut builder = restore_event_header(namespace_slice, action_id, kind, ts);
    // The scope is stored as the canonical uid string the event reported, so it
    // is re-parsed the same way `EventBuilder::principal` parses any uid.
    builder = restore_event_scope(builder, principal, resource);

    // Logged entries are complete top-level values, not necessarily grouped
    // records: requestId/sessionId are scalars, and an explicit empty object is
    // distinct from a missing field. `logged_field` preserves every shape.
    let after_logged = restore_logged_fields(builder, logged);
    builder = match after_logged {
        Ok(builder) => builder,
        Err(error) => return Err(error),
    };

    // Context entries are complete top-level values, not necessarily grouped
    // records: a scalar and an explicit empty object are both distinct from a
    // missing field. Restore the exact value admitted and persisted.
    let after_context = restore_context_fields(builder, context);
    builder = match after_context {
        Ok(builder) => builder,
        Err(error) => return Err(error),
    };

    let after_entities = restore_entities(builder, entities);
    builder = match after_entities {
        Ok(builder) => builder,
        Err(error) => return Err(error),
    };

    let after_parents = restore_parents(builder, parents);
    builder = match after_parents {
        Ok(builder) => builder,
        Err(error) => return Err(error),
    };

    let event = builder.build();
    if !event_scope_matches(&event, principal, resource) {
        return Err(event_decode_error(
            "record event contains an invalid scope entity",
        ));
    }
    Ok(event)
}

fn scope_reconstructs_logged(event: &Event, name: &str, value: &Value) -> bool {
    let expected = match name {
        "callerPrincipal" => event.principal_uid(),
        "callerResource" => event.resource_uid(),
        _ => return false,
    };
    let Value::Entity { ty, id } = value else {
        return false;
    };
    expected.as_deref() == Some(format!("{ty}::\"{}\"", escape_id(id)).as_str())
}

/// Escape an entity id back into the canonical Cedar literal form
/// `EventBuilder::entity_parents` expects.
fn escape_id(id: &str) -> String {
    id.escape_debug().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Record, event_from_json, event_to_json};

    /// Decimals keep their exact text. Dogwood compares decimals structurally,
    /// so canonicalizing `1.50` to `1.5` through a JSON number could flip a
    /// `==` comparison between a live and a recovered verdict.
    #[test]
    fn decimal_text_survives_the_record_round_trip() {
        let event = Event::builder("A", "request")
            .timestamp(1)
            .field("input", "amount", Value::Decimal("1.50".to_string()))
            .build();
        let back = event_from_json(&event_to_json(&event), 1).expect("decodes");
        assert_eq!(
            back.field("input", "amount"),
            Some(&Value::Decimal("1.50".to_string()))
        );
    }

    #[test]
    fn complete_top_level_logged_values_survive_the_record_round_trip() {
        let event = Event::builder("A", "request")
            .timestamp(1)
            .principal_for("User", "alice")
            .logged_field("requestId", Value::String("r-1".to_string()))
            .logged_field("metadata", Value::Object(std::collections::BTreeMap::new()))
            .logged_field(
                "callerPrincipal",
                Value::Entity {
                    ty: "User".to_string(),
                    id: "delegated".to_string(),
                },
            )
            .build();

        let back = event_from_json(&event_to_json(&event), 1).expect("decodes");
        assert_eq!(back, event);
    }

    #[test]
    fn scalar_top_level_request_context_survives_the_record_round_trip() {
        let event = Event::builder("A", "request")
            .timestamp(1)
            .request_context_field("authenticated", Value::Bool(true))
            .build();

        let back = event_from_json(&event_to_json(&event), 1).expect("decodes");
        assert_eq!(back, event);
    }

    #[test]
    fn empty_top_level_request_context_object_survives_the_record_round_trip() {
        let event = Event::builder("A", "request")
            .timestamp(1)
            .request_context_field("metadata", Value::Object(std::collections::BTreeMap::new()))
            .build();

        let back = event_from_json(&event_to_json(&event), 1).expect("decodes");
        assert_eq!(back, event);
    }

    #[test]
    fn structured_action_identity_survives_the_record_round_trip() {
        let event = Event::builder_for(&["Ns", "Action"], "read::special", "request")
            .timestamp(1)
            .build();
        let back = event_from_json(&event_to_json(&event), 1).expect("decodes");

        assert_eq!(back.namespace(), event.namespace());
        assert_eq!(back.action(), event.action());
    }

    #[test]
    fn encoded_payload_contains_auxiliary_entity_attributes() {
        let event = Event::builder("Svc::Action::Read", "request")
            .timestamp(1)
            .principal("Svc::User::\"alice\"")
            .entity(
                "Svc::Group::\"engineering\"",
                [("classification", Value::String("internal".to_string()))],
            )
            .build();

        let payload = event_to_json(&event);
        assert_eq!(
            payload["entities"]["Svc::Group::\"engineering\""]["classification"],
            serde_json::json!(["s", "internal"]),
            "the durable payload must contain non-scope entities accepted by EventBuilder"
        );
    }

    #[test]
    fn decoder_accepts_auxiliary_entity_attributes() {
        let event = Event::builder("Svc::Action::Read", "request")
            .timestamp(1)
            .principal("Svc::User::\"alice\"")
            .build();
        let mut payload = event_to_json(&event);
        payload["entities"]["Svc::Group::\"engineering\""] = serde_json::json!({
            "classification": ["s", "internal"],
        });

        let decoded =
            event_from_json(&payload, 1).expect("a complete persisted entity store must decode");
        assert_eq!(
            decoded
                .entity_attributes("Svc::Group::\"engineering\"")
                .collect::<Vec<_>>(),
            vec![("classification", &Value::String("internal".to_string()))]
        );
    }

    #[test]
    fn decoder_accepts_parent_only_auxiliary_entities() {
        let event = Event::builder("Svc::Action::Read", "request")
            .timestamp(1)
            .build();
        let mut payload = event_to_json(&event);
        payload["parents"]["Svc::Group::\"middle\""] = serde_json::json!([
            ["e", ["Svc::Group", "left"]],
            ["e", ["Svc::Group", "right"]],
        ]);

        let decoded = event_from_json(&payload, 1)
            .expect("an entity need not have attributes to carry hierarchy edges");
        assert_eq!(
            decoded.entity_parents("Svc::Group::\"middle\""),
            &[
                Value::Entity {
                    ty: "Svc::Group".to_string(),
                    id: "left".to_string(),
                },
                Value::Entity {
                    ty: "Svc::Group".to_string(),
                    id: "right".to_string(),
                },
            ]
        );
    }

    #[test]
    fn encoded_payload_preserves_explicit_empty_entity_record() {
        let event = Event::builder("Svc::Action::Read", "request")
            .timestamp(1)
            .principal_for("Svc::User", "alice")
            .entity_for("Svc::User", "alice", [])
            .build();

        let payload = event_to_json(&event);
        assert_eq!(
            payload["entities"]["Svc::User::\"alice\""],
            serde_json::json!({}),
            "an explicitly supplied empty entity is distinct from a bare scope entity"
        );
    }

    #[test]
    fn decoder_accepts_explicit_empty_entity_record() {
        let event = Event::builder("Svc::Action::Read", "request")
            .timestamp(1)
            .principal_for("Svc::User", "alice")
            .build();
        let mut payload = event_to_json(&event);
        payload["entities"]["Svc::User::\"alice\""] = serde_json::json!({});

        let decoded =
            event_from_json(&payload, 1).expect("an explicit empty entity record must decode");
        assert_eq!(
            decoded.entity_uids().collect::<Vec<_>>(),
            vec!["Svc::User::\"alice\""],
            "decoding must preserve that the caller supplied this entity"
        );
    }

    #[test]
    fn auxiliary_parent_graph_survives_the_record_round_trip() {
        let event = Event::builder("Svc::Action::Read", "request")
            .timestamp(1)
            .principal("Svc::User::\"alice\"")
            .parents_for("Svc::User", "alice", [("Svc::Group", "engineering")])
            .parents_for("Svc::Group", "engineering", [("Svc::Group", "admins")])
            .build();

        let decoded =
            Record::decode(&Record::Event(event).encode()).expect("the encoded record must decode");
        let Record::Event(decoded) = decoded else {
            panic!("an event record decoded as another kind");
        };
        assert_eq!(
            decoded.entity_parents("Svc::Group::\"engineering\""),
            &[Value::Entity {
                ty: "Svc::Group".to_string(),
                id: "admins".to_string(),
            }],
            "the middle edge of a transitive hierarchy must survive persistence"
        );
    }

    #[test]
    fn complete_auxiliary_graph_survives_the_record_round_trip() {
        let special_id = "quote\"slash\\snowman:\u{2603}";
        let special_uid = format!("Svc::Group::\"{}\"", special_id.escape_debug());
        let event = Event::builder("Svc::Action::Read", "request")
            .timestamp(1)
            .principal_for("Svc::User", "alice")
            .entity_for(
                "Svc::User",
                "alice",
                [("scope", Value::String("overlap".to_string()))],
            )
            .parents_for("Svc::User", "alice", [("Svc::Group", "one")])
            .parents_for(
                "Svc::Group",
                "one",
                [
                    ("Svc::Group", "two"),
                    ("Svc::Group", special_id),
                    ("Svc::Group", "two"),
                ],
            )
            .parents_for("Svc::Group", "two", [("Svc::Group", "one")])
            .entity_for(
                "Svc::Group",
                special_id,
                [("label", Value::String("unicode:\u{96ea}".to_string()))],
            )
            .entity_for(
                "Svc::Group",
                "disconnected",
                [("state", Value::String("present".to_string()))],
            )
            .build();

        let decoded =
            Record::decode(&Record::Event(event).encode()).expect("the encoded record must decode");
        let Record::Event(decoded) = decoded else {
            panic!("an event record decoded as another kind");
        };

        assert_eq!(
            decoded.entity_parents("Svc::Group::\"one\""),
            &[
                Value::Entity {
                    ty: "Svc::Group".to_string(),
                    id: "two".to_string(),
                },
                Value::Entity {
                    ty: "Svc::Group".to_string(),
                    id: special_id.to_string(),
                },
                Value::Entity {
                    ty: "Svc::Group".to_string(),
                    id: "two".to_string(),
                },
            ],
            "branches, duplicate edges, and their order must survive"
        );
        assert_eq!(
            decoded.entity_parents("Svc::Group::\"two\""),
            &[Value::Entity {
                ty: "Svc::Group".to_string(),
                id: "one".to_string(),
            }],
            "cycles must survive without traversal or normalization"
        );
        assert_eq!(
            decoded.entity_attributes(&special_uid).collect::<Vec<_>>(),
            vec![("label", &Value::String("unicode:\u{96ea}".to_string()))],
            "escaped auxiliary uids must survive"
        );
        assert_eq!(
            decoded
                .entity_attributes("Svc::Group::\"disconnected\"")
                .collect::<Vec<_>>(),
            vec![("state", &Value::String("present".to_string()))],
            "disconnected entities are still part of the supplied request"
        );
    }

    /// A malformed payload is an error, not a panic. The *envelope* cases — a
    /// record with no `ts`, or no `event` — moved to `dogwood-server`'s `record`
    /// module along with the envelope itself.
    #[test]
    fn malformed_payloads_are_rejected() {
        for bad in [
            serde_json::json!({}),
            serde_json::json!({ "kind": "request" }),
            serde_json::json!({ "action": "A" }),
            serde_json::json!("not an object"),
        ] {
            assert!(event_from_json(&bad, 1).is_err(), "{bad} must be rejected");
        }
    }
}
