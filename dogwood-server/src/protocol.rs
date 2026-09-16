//! The wire protocol: request/response types and their framing.
//!
//! Two sockets carry two disjoint verb sets (`DESIGN.md` §8.1), and the type
//! system enforces the split — the data socket deserializes [`DataRequest`],
//! which has **no variant that mutates policy**, so no amount of confusion on
//! the data path can reach a control verb. That is the wire-level expression of
//! §7's "the agent gets exactly two verbs and no verb to read, replace, or
//! disable a policy."
//!
//! # Framing
//!
//! One request per connection turn: a 4-byte big-endian length followed by that
//! many bytes of JSON. Length-prefixing (rather than newline-delimiting) means a
//! payload containing a newline — trivially reachable, since event field values
//! are arbitrary strings — cannot desynchronize the stream. A hard
//! [`MAX_FRAME`] cap makes a malicious length header a bounded rejection rather
//! than a multi-gigabyte allocation: the data socket is reachable by the very
//! process we do not trust.
//!
//! # Why JSON
//!
//! The wire is a **local** IPC boundary whose cost is dominated by the fsync in
//! the append path, so a compact binary encoding would buy nothing measurable
//! while costing the thing that matters here: any language can speak this
//! protocol with no generated bindings, which is the whole reason §2 chose a
//! server over a library-only deliverable.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

/// Maximum accepted frame size (16 MiB). Generous for any single event —
/// including one carrying a large entity store — while bounding what one
/// untrusted `submit` can make the server allocate.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

// ─── The event wire form ─────────────────────────────────────────────

/// An event as it crosses the wire — **schema-neutral by construction**
/// (`DESIGN.md` §3.4).
///
/// Nothing here privileges any event kind, field group, or field name: `kind` is
/// an arbitrary string the *installed schema* interprets (it decides which kinds
/// decide), and the field bags are free-form JSON objects whose dotted paths are
/// whatever the schema declares. The default schema's `request`/`resolution` and
/// `input`/`output` are values a client happens to send, not cases in this type.
///
/// Note what is **absent**: a timestamp. The store assigns it at append
/// (`DESIGN.md` §3.3) — the append point is simultaneously the sequencer and the
/// clock, so a client cannot backdate an event to slip outside a window or
/// reorder itself ahead of another caller. Omitting the field from the wire
/// makes that unforgeable rather than merely unenforced.
///
/// `deny_unknown_fields` makes that omission *legible*: a client that sends a
/// `ts` is told the field does not exist, rather than having it silently dropped
/// and being left believing it set the event's time. The same applies to any
/// misspelled field — a typo'd `logged` would otherwise become an event with no
/// history, which fails closed but for a reason nobody can see.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEvent {
    /// The qualified action, e.g. `"Example::Action::Login"`.
    pub action: String,
    /// The event kind, e.g. `"request"`. The installed schema decides whether a
    /// kind is a decision point.
    pub kind: String,
    /// The request principal's entity uid (`User::"alice"`), if this event
    /// wraps a request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// The request resource's entity uid, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// The **logged temporal record**: the durable history future timepoints
    /// correlate against. A JSON object of groups (`{"input": {"user": "alice"}}`).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub logged: serde_json::Map<String, serde_json::Value>,
    /// The **request-only context** a policy reads as `context.<group>.<name>`.
    /// A deliberately separate bag from `logged` (see `EventBuilder::field` vs
    /// `EventBuilder::request_context`): a field both need is sent in both.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub context: serde_json::Map<String, serde_json::Value>,
    /// Entity attributes for this decision, keyed by canonical uid:
    /// `{"User::\"alice\"": {"dept": "eng"}}`. Lets a policy read
    /// `principal.dept`.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub entities: serde_json::Map<String, serde_json::Value>,
    /// Direct parent uids per entity, for `principal in Group::"admins"`.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub parents: serde_json::Map<String, serde_json::Value>,
}

impl WireEvent {
    /// A minimal event of `action` / `kind`, for building up in tests and
    /// clients.
    pub fn new(action: &str, kind: &str) -> Self {
        WireEvent {
            action: action.to_string(),
            kind: kind.to_string(),
            principal: None,
            resource: None,
            logged: serde_json::Map::new(),
            context: serde_json::Map::new(),
            entities: serde_json::Map::new(),
            parents: serde_json::Map::new(),
        }
    }
}

// ─── The data plane (reachable by the monitored agent) ───────────────

/// A request on the **data** socket. The monitored agent's entire vocabulary.
///
/// There is deliberately no `GetPolicies`, `SetPolicy`, or `Shutdown` variant:
/// the agent can report events and ask for decisions, and cannot read, replace,
/// or disable the rules that govern it (`DESIGN.md` §7).
///
/// `Submit` is much larger than `Ping`, so the enum is `Submit`-sized. Boxing the
/// event to even them out would trade a stack copy for a heap allocation on the
/// *hot* path (every submit) to save one on the cold path (a handshake), and would
/// put a `Box` in a public wire type for no caller benefit — so the size
/// difference is accepted rather than papered over.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DataRequest {
    /// The one schema-driven primitive (`DESIGN.md` §10). The installed
    /// schema's `decision_kinds()` and the event's own kind decide the
    /// behaviour — there are not two hardcoded verbs:
    ///
    /// - a **decision-kind** event fuses durable append + monitor step +
    ///   verdict into one blocking round trip;
    /// - a **history-kind** event is a durable append + step, acked with no
    ///   verdict.
    Submit { event: WireEvent },
    /// Liveness / version handshake. Carries no policy information.
    Ping,
}

/// A response on the data socket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DataResponse {
    /// A decision-kind event's verdict.
    Decision {
        /// When the store recorded this event, in epoch **nanoseconds**.
        ///
        /// The verdict is only meaningful relative to a moment, and this is that
        /// moment: every window the rules declare is measured against it. The
        /// caller cannot derive it — the store assigns it (`DESIGN.md` §3.3) and
        /// the wire event carries no timestamp — so returning it is the only way a
        /// client can reason about when its own history ages out.
        ///
        /// The unit is in the name on purpose. The audit trail and the event clock
        /// once disagreed about seconds versus nanoseconds; a rename is a visible
        /// protocol change where a silent unit switch is a bug nobody sees.
        recorded_at_nanos: i64,
        /// `true` = Allow. Named `allowed` rather than a `decision` string so a
        /// client cannot mistake an unrecognized enum spelling for permission.
        allowed: bool,
        /// The determining policies' durable tokens.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reason: Vec<String>,
        /// Evaluation errors accompanying the decision. A Dogwood decision
        /// degrades rather than aborting: errors here travel *with* a
        /// fail-closed `Deny`, so a client must not treat their presence as a
        /// reason to retry-and-proceed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        errors: Vec<String>,
    },
    /// A history-kind event was durably recorded; no verdict applies.
    ///
    /// Deliberately empty. `DESIGN.md` §10 asks that history events not be
    /// fire-and-forget, and this variant's *arrival* is what satisfies that: the
    /// event is on disk before it is sent. The log offset used to travel here and
    /// no longer does — a client cannot act on the value (one that lost the
    /// response has no offset either way, so it aids neither retry nor dedup),
    /// while sending it leaked aggregate activity across all clients through a
    /// global counter and made the log's addressing scheme part of the contract.
    /// It is still available to an operator via `Status` on the privileged plane.
    ///
    /// Carries the assigned timestamp for the same reason [`DataResponse::Decision`]
    /// does: it is the one thing a client both needs and cannot work out itself.
    /// The log *offset* used to travel here and does not — a client cannot act on
    /// the value (one that lost the response has no offset either way, so it aids
    /// neither retry nor dedup), while sending it leaked aggregate activity across
    /// all clients through a global counter and made the log's addressing scheme
    /// part of the contract. An operator reads offsets from `Status` on the
    /// privileged plane.
    Recorded {
        /// When the store recorded this event, in epoch **nanoseconds**.
        recorded_at_nanos: i64,
    },
    /// `Ping` reply.
    Pong { version: String },
    /// The request could not be served. **Not** a `Deny`: a caller that treats
    /// an error as "denied" is safe, and one that treats it as "allowed" is the
    /// bug this variant's distinctness prevents.
    Error { message: String },
}

// ─── The control plane (privileged socket only) ──────────────────────

/// One policy-management verb on the wire (`POLICY_INSTALL_SEMANTICS.md` §2.1),
/// the transport form of `dogwood_local_engine::Verb`.
///
/// `Add` carries no id — the engine mints one and returns it in
/// [`ControlResponse::Batched`]. There is no event-schema verb: the event
/// schema and macro library are store configuration, fixed at first `Apply` and
/// immutable through the verbs (§2.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum WireVerb {
    /// Install a new policy — minted a fresh id, born with no history.
    Add { policy: String },
    /// Replace a policy's content by id — resets it, same id.
    Update { id: String, policy: String },
    /// Remove a policy by id.
    Delete { id: String },
    /// Clear one policy's accumulated history; content unchanged.
    Reset { id: String },
    /// Remove every policy; the schema is kept and the empty set stays installed
    /// (decisions then fail closed).
    DeleteAll,
    /// Clear every policy's history; all policies kept.
    ResetAll,
    /// Revalidate + re-lower the whole set under a new action schema (§2.7).
    SetActionSchema { action_schema: String },
    /// Append a fragment onto the current action schema, atomically (§2.7) — so a
    /// caller can add a new entity/action without a fetch-then-set round trip a
    /// concurrent change could invalidate.
    AppendActionSchema { fragment: String },
}

/// A policy's metadata, without its source — what [`ControlRequest::List`]
/// returns (§2.1: `list -> [PolicySummary]`). The full statement is fetched per
/// id with [`ControlRequest::GetPolicyById`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySummary {
    /// The opaque engine-minted handle. Non-sequential by design — to order
    /// policies, sort by `created`, not by this.
    pub id: String,
    /// Epoch-nanosecond timestamps the policy was created / last updated at.
    pub created: i64,
    pub updated: i64,
}

/// A request on the **control** socket — the privileged authoring path, gated
/// by peer-credential uid allowlist (`DESIGN.md` §8.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Install a complete policy set + schema, replacing whatever is installed
    /// — the declarative path (`[DeleteAll; Add …]`, `POLICY_INSTALL_SEMANTICS.md`
    /// §2.8). Also the store-configuration entry point: it sets the event schema
    /// (fixed thereafter, §2.7). Maps to the engine's `install`.
    ///
    /// The server **validates before accepting** and swaps atomically; a
    /// rejected install leaves the running set untouched.
    Install {
        /// The `.dw` policy source.
        policy: String,
        /// The Cedar action schema (`.cedarschema`).
        action_schema: String,
        /// The event-schema DSL (`.dwschema`). `None` uses the default schema.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_schema: Option<String>,
    },
    /// Apply a batch of policy verbs atomically over the current set (§2.1) —
    /// the incremental authoring path. All verbs take effect together or the
    /// whole batch is rejected and the running set is untouched.
    Batch { verbs: Vec<WireVerb> },
    /// List the installed policies' metadata, most-stable-id first, paginated
    /// (§2.7). `max_results` caps the page (all when absent); `next_token` is the
    /// handle to resume after (the last id of the previous page), echoed back in
    /// [`ControlResponse::PolicyList`] when more remain.
    List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_results: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_token: Option<String>,
    },
    /// Report what is installed: the rules, the temporal leaves, and the
    /// engine's current state. A control-plane-only verb — the agent has no way
    /// to enumerate the rules governing it.
    Status,
    /// Show the whole installed policy source verbatim (every policy's canonical
    /// statement, concatenated).
    GetPolicy,
    /// Show one policy's canonical statement by id (§2.1: `GetPolicy(id)`).
    GetPolicyById { id: String },
    /// Return the store's schemas (§2.1: `GetSchema`) — the **original** action
    /// schema the operator authored (not the augmented one) and the configured
    /// event schema (`None` = the built-in default).
    GetSchema,
    /// Force a state snapshot now (`DESIGN.md` §6.3's manual trigger).
    Checkpoint,
}

/// A response on the control socket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    /// An `Apply` succeeded, reporting the prospective-install consequences
    /// (`DESIGN.md` §9.2) so the operator sees which rules start cold.
    Applied {
        /// When the change took effect, in epoch **nanoseconds** — the moment the
        /// change record was assigned, on the same clock and the same sequence as
        /// every event's `recorded_at_nanos`. So an operator can say exactly which
        /// events this set governed: those stamped at or after it.
        ///
        /// The change record's log *offset* is the crisper boundary and stays
        /// in-process: an offset is only comparable to other offsets, and the data
        /// plane returns none.
        applied_at_nanos: i64,
        /// Rules in the newly installed set.
        rule_count: usize,
        /// Temporal leaves in the new set.
        leaf_count: usize,
        /// Leaves that kept their accumulated window (unchanged formulas).
        leaves_retained: usize,
        /// Leaves starting empty — new or edited formulas, subject to the
        /// warm-up window of §9.2.
        leaves_prospective: usize,
    },
    /// `Status` reply.
    Status {
        rule_count: usize,
        leaf_count: usize,
        /// Leaves running on the incremental path (vs. the scan fallback).
        incremental_leaves: usize,
        /// The event kinds the installed schema treats as decision points.
        decision_kinds: Vec<String>,
        /// The schema's partition key: the dotted field paths the event stream may
        /// be sharded on (`DESIGN.md` §3.3). **Empty means unshardable** — the
        /// schema declares no universal symmetric pin, so partitioning would
        /// change verdicts and the server runs a single instance.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        partition_key: Vec<String>,
        /// Events durably appended since the log was created (the next offset).
        log_offset: u64,
        /// The uids permitted on the control socket.
        control_uids: Vec<u32>,
    },
    /// A `Batch` succeeded. `minted` is the ids assigned to the batch's `Add`
    /// verbs, in listed order (§2.5), so a caller can address what it created.
    Batched {
        /// Engine-minted opaque handles for the batch's `Add` verbs, in order.
        minted: Vec<String>,
        /// When the batch landed, in epoch **nanoseconds** — same clock as
        /// `Applied::applied_at_nanos` and every event's `recorded_at_nanos`.
        applied_at_nanos: i64,
    },
    /// A `List` reply: a page of policy metadata and, when more remain, the id
    /// to resume after in a follow-up `List` (§2.7).
    PolicyList {
        policies: Vec<PolicySummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_token: Option<String>,
    },
    /// `GetPolicy` / `GetPolicyById` reply.
    Policy { source: String },
    /// `GetSchema` reply — the original action schema and the configured event
    /// schema (`None` = the built-in default).
    Schema {
        action_schema: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_schema: Option<String>,
    },
    /// A `Checkpoint` completed.
    Checkpointed { up_to_offset: u64 },
    /// The request was rejected. For `Apply` this carries the validation
    /// findings, and the previously-installed set is still running.
    Error { message: String },
}

// ─── Framing ─────────────────────────────────────────────────────────

/// A framing / transport failure.
#[derive(Debug)]
pub enum FrameError {
    /// The stream ended (cleanly, at a frame boundary, if `at_boundary`).
    Eof { at_boundary: bool },
    /// The declared length exceeds [`MAX_FRAME`].
    TooLarge(u32),
    /// An I/O error.
    Io(std::io::Error),
    /// The payload was not valid JSON for the expected type.
    Decode(String),
    /// The peer sent nothing for the connection's idle timeout. Distinct from
    /// [`Io`](FrameError::Io) because it is not a fault: it is the server
    /// reclaiming a slot from a silent connection, and the handler should close
    /// quietly rather than report an error the peer will never read.
    IdleTimeout,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Eof { at_boundary: true } => write!(f, "connection closed"),
            FrameError::Eof { at_boundary: false } => {
                write!(f, "connection closed mid-frame (truncated request)")
            }
            FrameError::TooLarge(n) => {
                write!(f, "frame of {n} bytes exceeds the {MAX_FRAME}-byte limit")
            }
            FrameError::Io(e) => write!(f, "io: {e}"),
            FrameError::Decode(e) => write!(f, "malformed request: {e}"),
            FrameError::IdleTimeout => write!(f, "connection idle timeout"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Write one length-prefixed JSON frame and flush it.
///
/// A value that fails to serialize is a bug in the server's own response types,
/// never client-controlled, so it surfaces as a `Decode` error rather than
/// panicking a connection thread.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<(), FrameError> {
    let body = serde_json::to_vec(value).map_err(|e| FrameError::Decode(e.to_string()))?;
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one length-prefixed JSON frame.
///
/// Distinguishes a clean close at a frame boundary (`Eof { at_boundary: true }`,
/// the normal end of a connection) from a truncated frame — the latter is a
/// protocol violation worth reporting, the former is not.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<T, FrameError> {
    let mut header = [0u8; 4];
    match read_exact_or_eof(r, &mut header)? {
        // Nothing at all: a clean close between frames.
        0 => return Err(FrameError::Eof { at_boundary: true }),
        4 => {}
        _ => return Err(FrameError::Eof { at_boundary: false }),
    }
    let len = u32::from_be_bytes(header);
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    // `len` is bounded by MAX_FRAME above, so this allocation is bounded even
    // for a hostile header.
    let mut body = vec![0u8; len as usize];
    if read_exact_or_eof(r, &mut body)? != body.len() {
        return Err(FrameError::Eof { at_boundary: false });
    }
    serde_json::from_slice(&body).map_err(|e| FrameError::Decode(e.to_string()))
}

/// Fill `buf`, returning how many bytes were read; a short count means EOF.
/// (`Read::read_exact` cannot distinguish "clean close at boundary" from
/// "truncated", which is exactly the distinction the caller needs.)
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return Ok(filled),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // A read timeout (set per-connection by the server to bound how long
            // a silent peer may hold a slot) surfaces as `WouldBlock` or
            // `TimedOut` depending on platform. Report it as its own variant so
            // the handler closes quietly instead of writing an error frame nobody
            // is reading.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(FrameError::IdleTimeout);
            }
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    Ok(filled)
}
