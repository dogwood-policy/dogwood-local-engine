//! The durable temporal engine: the installed policy set, the durable event log,
//! and the running monitor — plus the two operations that mutate them (`submit`
//! and `apply`) and the recovery that rebuilds them on open.
//!
//! This is the assembly that turns the crate's two lower-level primitives — the
//! [`DurableLog`](crate::DurableLog) and the [`LocalTemporalEngine`] monitor —
//! into a crash-consistent, event-sourced decision service. It owns the ordering
//! that makes a verdict and its history agree under a crash:
//! assign a timestamp, append durably *first*, then step the monitor, then
//! decide. `dogwood-server` wraps this behind a process boundary and a wire API;
//! everything durability-related lives here, so an embedder gets the whole
//! machine, not just the parts.
//!
//! # Why one caller-held mutex over the whole thing
//!
//! The concurrency model is **single-writer per monitor
//! instance**: the append point is simultaneously the sequencer and the clock,
//! so it must be a linearization point. Every `submit` therefore takes one lock
//! covering append + step + evaluate. Concurrent callers serialize at the append point and each
//! emerges with a distinct, strictly-increasing timestamp, which is precisely
//! what makes the trace order well-defined without synchronized client clocks.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
#[cfg(feature = "fault-injection")]
use std::sync::Arc;
use std::time::Duration;

use dogwood_language::{
    Authorizer, DogwoodRuleRef, EventBuilder, ParsedPolicySet, PolicySchema, ServiceSchema,
    TemporalEngine, Validator,
};

use crate::clock::{Clock, WallClock};
#[cfg(feature = "fault-injection")]
use crate::fault_injection::{FaultInjector, FaultPoint};
use crate::policy_store::{
    FoldedRecord, PolicyEntry, PolicyId, PolicySet, PolicyToken, Verb, append_action_schema,
};
use crate::record::{Record, SnapshotPayload};
use crate::shard::ShardPlan;
use crate::shared::SharedEngine;
use crate::{DurableLog, LeafStateTransferError, LocalTemporalEngine, Snapshot, TickRate, Write};

mod attribution;

pub use attribution::{DecisionDiagnostics, DecisionResponse, PolicyAttribution};
use attribution::{RuleAttribution, attribute_response, build_attributions};

/// Metadata slot recording the unit this store's timestamps were assigned in.
const META_TIME_UNIT: &str = "dogwood_server_time_unit";
/// Metadata slot holding the store's [`ServiceConfig`] — the service-provided,
/// customer-independent schema half.
const META_SERVICE_SCHEMA: &str = "dogwood_server_service_schema";

/// The **store-configuration** half of the schema: the parts a service fixes
/// once and reuses across every policy set.
///
/// Held here, not in [`Installed`], because it is **immutable through the
/// verbs**: the event schema drives relativization and the partition mode, and
/// the macro library re-lowers every leaf, so either changing would reborn the
/// whole set — the one genuinely reborn-all change, and a
/// deliberate store rebuild rather than an everyday verb. It is set once, at the
/// first [`install`](DurableTemporalEngine::install), and persisted in
/// [`META_SERVICE_SCHEMA`]; a later `install` that would change it is rejected.
///
/// `None` on either field means "use the built-in default"
/// (`DEFAULT_EVENT_SCHEMA` / `DEFAULT_MACROS`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ServiceConfig {
    #[serde(default)]
    event_schema: Option<String>,
    #[serde(default)]
    macros: Option<String>,
}

/// The resolution this server assigns timestamps at, and therefore the unit its
/// windows are compared in.
///
/// Nanoseconds.
const TIME_UNIT: TickRate = TickRate::NANOS;

/// Records reclaimed per prune transaction.
///
/// Bounded because redb permits one writer: a single transaction spanning a
/// whole retained window would block every `submit` for its duration.
const PRUNE_CHUNK: usize = 1_000;

/// Maximum encoded log payload retained for one recovery read.
const DEFAULT_REPLAY_BATCH_BYTES: usize = 16 * 1024 * 1024;

fn default_replay_batch_bytes() -> NonZeroUsize {
    NonZeroUsize::new(DEFAULT_REPLAY_BATCH_BYTES).expect("default replay batch size is nonzero")
}

/// The value stored under [`META_TIME_UNIT`] for [`TIME_UNIT`].
const TIME_UNIT_TAG: &[u8] = b"nanos";

/// Where a rebuilt engine's monitor state comes from.
enum StateSource<'a> {
    /// Load it from a snapshot payload. The payload names the policy set it was
    /// taken under, so the leaves being prepared are exactly the ones it
    /// describes and the positional restore is sound.
    Snapshot(&'a [u8]),
    /// Carry it across from whatever is running (or was last persisted), matched
    /// by composite `(stable policy id, within-policy clause ordinal)`. The `fresh`
    /// set is the ids that must **start empty** this rebuild — the fold's `Add`,
    /// `Update`, and `Reset` targets, all of `ResetAll`, none of just carrying —
    /// their entries are omitted from the carry set so their monitors keep the
    /// empty state `prepare` gave them.
    ///
    /// Used by every live verb batch AND by every replayed verb, so the rule
    /// lives in one place.
    Transplant { fresh: &'a BTreeSet<PolicyId> },
}

/// The installed policy bundle — everything needed to rebuild the authorizer.
///
/// Persisted so a restart recovers the *whole* engine, not just monitor state.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    /// The structured policy set: each policy a stable engine-minted id plus its
    /// canonical statement (`policy_store`). The ids are recorded here, so
    /// recovery restores them and never re-mints.
    pub policies: PolicySet,
    /// The action schema (entities / actions / `appliesTo`). **Mutable** through
    /// the verbs — a `SetActionSchema` re-lowers and re-validates the whole set
    /// — so it lives with the policies, not in the store-config
    /// `ServiceConfig`. The event schema and macro library, being immutable
    /// through the verbs, live there instead.
    pub action_schema: String,
}

impl Installed {
    /// The combined `.dw` source the authorizer lowers: the policies' canonical
    /// statements concatenated in installed order. Re-parsing/lowering this
    /// reproduces the same leaf set the structured entries describe.
    pub fn combined_source(&self) -> String {
        self.policies
            .entries()
            .map(|e| e.statement.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// An empty bundle — no policies, no schemas. The seed a cold-start replay
    /// begins folding into: the first `SetActionSchema`/`SetEventSchema` and
    /// `Add` records fill it in. Serving from this seed refuses every submit
    /// (no policy), which is exactly what `submit` already does.
    fn seed() -> Self {
        Installed {
            policies: PolicySet::new(),
            action_schema: String::new(),
        }
    }
}

/// Mint a fresh opaque policy handle: `SP`
/// followed by 22 base62 digits of 128 random bits. The 22 digits cover the full
/// 128-bit space (62²² > 2¹²⁸), so the id is unpredictable and — at 128 bits —
/// collision-free in practice (birthday bound ~2⁶⁴). Correctness never rests on
/// that, though: the caller ([`PolicySet::fold`]) also rejects a clash with a live
/// handle, and monitor state keys on the ordinal, not the token.
fn mint_policy_token() -> PolicyToken {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut bytes = [0u8; 16];
    // OS entropy. A failure here means the platform RNG is unavailable, which is
    // unrecoverable for minting a unique handle — far better to fail loudly than
    // to hand out a predictable or duplicate id.
    getrandom::fill(&mut bytes).expect("OS entropy for a policy handle");
    let mut n = u128::from_le_bytes(bytes);
    let mut digits = [0u8; 22];
    for slot in digits.iter_mut() {
        *slot = ALPHABET[(n % 62) as usize];
        n /= 62;
    }
    let mut s = String::with_capacity(24);
    s.push_str("SP");
    // `digits` is little-endian; order is irrelevant to opacity, so emit as-is.
    s.push_str(std::str::from_utf8(&digits).expect("base62 digits are ASCII"));
    PolicyToken(s)
}

/// Stamp a fold's [`FoldedRecord`] with the batch's single timestamp to get the
/// durable [`Record`]. The fold already resolved every handle to its ordinal and
/// minted the `Add` tokens, so this only attaches `ts` (one instant per
/// batch).
fn stamp_record(folded: &FoldedRecord, ts: i64) -> Record {
    match folded {
        FoldedRecord::Add {
            id,
            token,
            statement,
        } => Record::Add {
            ts,
            id: *id,
            token: token.clone(),
            statement: statement.clone(),
        },
        FoldedRecord::Update { id, statement } => Record::Update {
            ts,
            id: *id,
            statement: statement.clone(),
        },
        FoldedRecord::Delete { id } => Record::Delete { ts, id: *id },
        FoldedRecord::Reset { id } => Record::Reset { ts, id: *id },
        FoldedRecord::DeleteAll => Record::DeleteAll { ts },
        FoldedRecord::ResetAll => Record::ResetAll { ts },
        FoldedRecord::SetActionSchema { action_schema } => Record::SetActionSchema {
            ts,
            action_schema: action_schema.clone(),
        },
        FoldedRecord::AppendActionSchema { fragment } => Record::AppendActionSchema {
            ts,
            fragment: fragment.clone(),
        },
    }
}

/// Fold one durable verb record into `bundle`, updating `fresh` with the ids
/// that must start empty on the next rebuild. Semantics mirror the live [`PolicySet::fold`], with two differences:
///
/// - Ids come from the record, so replay never re-mints.
/// - An impossible Add identity (a non-next id or duplicate live token), or an
///   unresolvable target (`Update`/`Delete`/`Reset` on a missing id), is a
///   **log-corruption** error, not a control-plane rejection: the durable log
///   would have refused to commit an ill-formed batch. Recovery raises this
///   rather than normalizing or silently dropping the verb.
fn apply_verb_to(
    bundle: &mut Installed,
    verb: &Record,
    fresh: &mut BTreeSet<PolicyId>,
) -> Result<(), String> {
    match verb {
        Record::Event(_) => unreachable!("apply_verb_to called with an event record"),
        Record::Add {
            ts,
            id,
            token,
            statement,
        } => {
            let next_id = bundle.policies.next_id();
            if next_id == u64::MAX {
                return Err("add targets an exhausted policy id space".to_string());
            }
            if id.0 != next_id {
                return Err(format!(
                    "add id {} does not match next policy id {next_id}",
                    id.0
                ));
            }
            if bundle.policies.contains_token(token) {
                return Err(format!("add reuses live token {}", token.0));
            }
            bundle
                .policies
                .insert_recorded(*id, token.clone(), statement.clone(), *ts);
            fresh.insert(*id);
        }
        Record::Update { ts, id, statement } => {
            if !bundle
                .policies
                .update_statement(*id, statement.clone(), *ts)
            {
                return Err(format!("update targets missing id {}", id.0));
            }
            fresh.insert(*id);
        }
        Record::Delete { id, .. } => {
            if !bundle.policies.remove(*id) {
                return Err(format!("delete targets missing id {}", id.0));
            }
            // A deleted policy carries no state and needs no reset flag; if it
            // was made fresh earlier in this fold, drop that too (it's gone).
            fresh.remove(id);
        }
        Record::Reset { id, .. } => {
            if !bundle.policies.contains(*id) {
                return Err(format!("reset targets missing id {}", id.0));
            }
            fresh.insert(*id);
        }
        Record::DeleteAll { .. } => {
            bundle.policies.clear();
            fresh.clear();
        }
        Record::ResetAll { .. } => {
            for id in bundle.policies.ids() {
                fresh.insert(id);
            }
        }
        Record::SetActionSchema { action_schema, .. } => {
            bundle.action_schema = action_schema.clone();
        }
        Record::AppendActionSchema { fragment, .. } => {
            // The same concatenation the live fold used, so a replay reproduces
            // the identical merged schema.
            bundle.action_schema = append_action_schema(&bundle.action_schema, fragment);
        }
    }
    Ok(())
}

fn replay_record_stamp(record: &Record) -> (i64, bool) {
    let timestamp = record.timestamp();
    let is_event = match record {
        Record::Event(_) => true,
        _ => false,
    };
    (timestamp, is_event)
}

/// Return the malformed timestamp and the lower bound it violated.
///
/// The caller retains `previous` across storage batches, so read boundaries do
/// not weaken the ordering check.
fn invalid_replay_timestamp(
    record: &Record,
    previous: Option<(i64, bool)>,
    replay_floor: Option<i64>,
) -> Option<(i64, i64)> {
    let (timestamp, is_event) = replay_record_stamp(record);
    let invalid = match previous {
        Some((previous_timestamp, previous_was_event)) => {
            timestamp < previous_timestamp
                || (timestamp == previous_timestamp && (is_event || previous_was_event))
        }
        None => replay_floor.is_some_and(|floor| timestamp <= floor),
    };
    if invalid {
        let lower_bound = previous
            .map(|(timestamp, _)| timestamp)
            .or(replay_floor)
            .unwrap_or(i64::MIN);
        Some((timestamp, lower_bound))
    } else {
        None
    }
}

fn checked_next_timestamp(last_ts: Option<i64>, now: i64) -> Option<i64> {
    match last_ts {
        Some(last) if last >= now => last.checked_add(1),
        _ => Some(now),
    }
}

fn next_timestamp_after_skew(last_ts: Option<i64>, now: i64) -> Result<i64, DurableError> {
    checked_next_timestamp(last_ts, now).ok_or_else(|| {
        DurableError::Rejected(
            "durable timestamp space is exhausted at i64::MAX; \
             refusing the operation rather than reusing a timestamp"
                .to_string(),
        )
    })
}

fn future_skew_exceeds_allowed(last_ts: i64, now: i64, allowed: i128) -> (i128, bool) {
    let future_skew = i128::from(last_ts) - i128::from(now);
    (future_skew, future_skew > allowed)
}

fn future_skew_error(last_ts: i64, future_skew: i128, now: i64, allowed: i128) -> DurableError {
    DurableError::Rejected(format!(
        "durable timestamp {last_ts} is {future_skew} ns ahead of the current \
         clock {now}, exceeding the maximum allowed future skew of {allowed} ns; \
         refusing the operation rather than issuing future-dated timestamps"
    ))
}

fn validate_clock_skew_values(
    last_ts: Option<i64>,
    now: i64,
    allowed: i128,
) -> Result<(), DurableError> {
    let Some(last_ts) = last_ts else {
        return Ok(());
    };
    let (future_skew, exceeds_allowed) = future_skew_exceeds_allowed(last_ts, now, allowed);
    if exceeds_allowed {
        return Err(future_skew_error(last_ts, future_skew, now, allowed));
    }
    Ok(())
}

fn next_timestamp_values(
    last_ts: Option<i64>,
    now: i64,
    allowed: i128,
) -> Result<i64, DurableError> {
    validate_clock_skew_values(last_ts, now, allowed)?;
    next_timestamp_after_skew(last_ts, now)
}

fn inconsistent_snapshot_clock_error(restored_ts: i64, last_ts: i64) -> DurableError {
    DurableError::Log(format!(
        "snapshot durable timestamp {last_ts} is older than restored engine state \
         timestamp {restored_ts}"
    ))
}

fn validate_snapshot_clock_values(restored_ts: i64, last_ts: i64) -> Result<(), DurableError> {
    if restored_ts > last_ts {
        return Err(inconsistent_snapshot_clock_error(restored_ts, last_ts));
    }
    Ok(())
}

fn observed_timestamp_value(last_ts: Option<i64>, timestamp: i64) -> Option<i64> {
    match last_ts {
        Some(last) if timestamp <= last => Some(last),
        _ => Some(timestamp),
    }
}

/// A failure serving a request.
#[derive(Debug)]
pub enum DurableError {
    /// No policy set is installed yet; call `install` first.
    NoPolicy,
    /// The event's `(action, kind)` is not in the installed schema, or the event
    /// is otherwise unservable.
    BadEvent(String),
    /// A policy failed to parse / lower / validate. The running set is untouched.
    Rejected(String),
    /// The durable log failed. Fails closed: a decision that cannot be recorded
    /// is not answered.
    Log(String),
    /// Monitor state could not be transferred safely to a replacement engine.
    StateTransfer(LeafStateTransferError),
}

impl std::fmt::Display for DurableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DurableError::NoPolicy => write!(f, "no policy set installed; call install first"),
            DurableError::BadEvent(m) => write!(f, "{m}"),
            DurableError::Rejected(m) => write!(f, "{m}"),
            DurableError::Log(m) => write!(f, "durable log: {m}"),
            DurableError::StateTransfer(e) => write!(f, "state transfer: {e}"),
        }
    }
}

impl From<LeafStateTransferError> for DurableError {
    fn from(error: LeafStateTransferError) -> Self {
        DurableError::StateTransfer(error)
    }
}

/// An accepted [`DurableTemporalEngine::submit`]: where the event landed, and what — if
/// anything — the caller is owed beyond that.
///
/// The offset is on the outside because it is a property of *acceptance*, not of
/// one branch. Every accepted event is appended before it is evaluated, so a
/// verdict-bearing event has an offset exactly as a history event does, and a
/// deny — even a fail-closed deny carrying evaluation errors — is recorded like
/// any other. Hoisting it makes "accepted implies positioned" hold by
/// construction rather than by convention.
#[derive(Debug)]
pub struct Submitted {
    /// The log offset the event was appended at — its position in the total
    /// order, and the point its verdict was evaluated at.
    pub offset: u64,
    /// The timestamp the store assigned, in epoch **nanoseconds** — the instant
    /// every window that ever evaluates this event is measured against.
    pub ts: i64,
    /// What the caller is owed beyond the acknowledgement.
    pub outcome: Outcome,
}

/// The half of [`Submitted`] that depends on the event's kind.
#[derive(Debug)]
pub enum Outcome {
    /// A decision-kind event: its verdict, evaluated at
    /// [`Submitted::offset`].
    Decision(DecisionResponse),
    /// A history-kind event: recorded, no verdict applies.
    Recorded,
}

/// A projection of the running policy set, for `status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// Policies in the running set.
    pub rule_count: usize,
    /// Temporal leaves the running set lowers to.
    pub leaf_count: usize,
    /// Leaves running on the incremental path.
    pub incremental_leaves: usize,
    /// The event kinds the installed schema treats as decision points.
    pub decision_kinds: Vec<String>,
    /// The dotted paths of the schema's partition key, or
    /// empty when the schema declares no universal symmetric pin and the stream
    /// therefore cannot be safely partitioned.
    pub partition_key: Vec<String>,
}

/// What an `install` or `batch` changed, for the operator's benefit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// The **last** offset the batch's records were appended at — the exact
    /// linearization boundary: events at or below it were decided under the
    /// previous set, events strictly above it under this one.
    ///
    /// A batch is a *set* of durable per-verb records committed in one
    /// transaction, so an apply occupies a
    /// contiguous **range** `first_offset..=offset`, not a single point.
    /// `offset` names the range's tail because that is where the semantic
    /// boundary is; `first_offset` is exposed for tools that need to enumerate
    /// every record the batch wrote.
    pub offset: u64,
    /// The **first** offset the batch's records were appended at — the head of
    /// the contiguous range this batch occupies. Equals `offset` for a single-
    /// verb batch.
    pub first_offset: u64,
    /// The timestamp the change record was assigned, in epoch **nanoseconds**.
    ///
    /// `next_timestamp` is shared by `submit` and
    /// `apply`, so every record — event or policy change — draws from one
    /// strictly increasing sequence: the timestamp alone is a total order over
    /// all of them.
    pub ts: i64,
    /// Policies in the resulting set.
    pub rule_count: usize,
    /// Temporal leaves the resulting set lowers to.
    pub leaf_count: usize,
    /// Leaves that kept their accumulated window across the change.
    pub leaves_retained: usize,
    /// Leaves that start with an empty window, because their formula is new or edited.
    pub leaves_prospective: usize,
}

/// What a [`batch`](DurableTemporalEngine::batch) did.
///
/// Deliberately narrow. The **minted handles** are the one thing a caller cannot
/// learn any other way — they are engine-assigned (opaque, non-sequential) and
/// returned only here, so a client that
/// `Add`s a policy persists the returned handle to later `Update`/`Delete`/`Reset`
/// it. The full resulting set is available via [`list`](DurableTemporalEngine::list).
/// Counts are available via
/// [`status`](DurableTemporalEngine::status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResult {
    /// The opaque handles assigned to the batch's `Add` verbs, in the order the
    /// verbs were listed — so the k-th `Add` in the request got `minted[k]`.
    pub minted: Vec<PolicyToken>,
    /// The timestamp the batch's last record was assigned, in epoch nanoseconds
    /// — its position in the one order events and policy changes share.
    pub ts: i64,
    /// How many of the resulting set's leaves kept their accumulated window
    /// across the rebuild (the carry-over of monitor state from the previous
    /// set) — the counterpart of
    /// [`Applied::leaves_retained`]. `0` for an empty (no-op) batch, which
    /// rebuilds nothing.
    pub leaves_retained: usize,
}

/// What a rebuild established about a new set, before anything about it is
/// durable. `apply` completes it into an [`Applied`] once the change record has
/// an offset and a timestamp; the recovery paths discard it.
#[derive(Debug, Clone, Copy)]
struct Counts {
    rule_count: usize,
    leaf_count: usize,
    leaves_retained: usize,
}

/// The durable engine: a policy set, an event log, and the running monitor,
/// opened at a path. See the crate documentation for a walkthrough.
pub struct DurableTemporalEngine {
    /// The durable event log — the source of truth.
    log: DurableLog,
    /// The installed bundle and the authorizer built from it. `None` until the
    /// first `apply`.
    running: Option<Running>,
    /// Snapshot the monitor state every N events.
    snapshot_interval: u64,
    /// Events observed since the last snapshot.
    since_snapshot: u64,
    /// Where the log lives, for diagnostics.
    path: PathBuf,
    /// The highest timestamp this store has ever assigned, in epoch nanoseconds.
    /// `None` for a store that has never accepted anything.
    ///
    /// It is durable in the snapshot, whose job is to carry what resuming needs
    /// once the records are gone, and it is advanced by replay over whatever
    /// records survive.
    last_ts: Option<i64>,
    /// The store-configuration schema half — event schema + macro library.
    /// Loaded from [`META_SERVICE_SCHEMA`]
    /// at `open` (default = both built-in) and set once by the first `install`;
    /// immutable through the verbs, so a batch never touches it and every
    /// `rebuild` reads it from here rather than from [`Installed`].
    service_config: ServiceConfig,
    /// The source of assigned timestamps: [`WallClock`] in
    /// production, injectable so a test can place events at exact instants or
    /// step the clock backwards. Read only through [`next_timestamp`], whose
    /// monotonic clamp is what a backwards step is held to. See [`Clock`].
    clock: Box<dyn Clock>,
    /// Maximum tolerated distance between durable time and the current clock.
    max_future_skew: Duration,
    /// Encoded log payload read into memory at once during recovery.
    replay_batch_bytes: NonZeroUsize,
    /// Test-only controller for engine-level acknowledgement and pruning cuts.
    #[cfg(feature = "fault-injection")]
    faults: Option<Arc<FaultInjector>>,
}

/// The running policy set: the bundle, the authorizer serving decisions, and a
/// shared handle to the engine whose state we snapshot.
struct Running {
    installed: Installed,
    authorizer: Authorizer,
    /// Derived from the same lowered set as the authorizer, published with it.
    attributions: Vec<RuleAttribution>,
    /// The same engine the authorizer holds. See [`SharedEngine`] for why the
    /// server keeps a handle rather than the frontend exposing an accessor.
    engine: SharedEngine,
    /// The set of event kinds the installed schema treats as decision points.
    /// Read from the lowered policy set — **not** hardcoded.
    decision_kinds: Vec<String>,
    rule_count: usize,
    leaf_count: usize,
    incremental_leaves: usize,
    /// Content-derived leaf keys, in leaf order.
    leaf_keys: Vec<String>,
    /// How this policy set's event stream may be partitioned,
    /// derived from the installed schema's pins.
    shard_plan: ShardPlan,
    /// The partition key's field paths, rendered dotted, for `status`. Empty when
    /// the stream is unshardable.
    partition_key: Vec<String>,
}

/// How to open a [`DurableTemporalEngine`]: the snapshot cadence and the clock.
///
/// Kept separate from the store path so the same configuration can open either a
/// file-backed store ([`open_with_config`](DurableTemporalEngine::open_with_config))
/// or a caller-supplied backend
/// ([`open_with_log_config`](DurableTemporalEngine::open_with_log_config)). Build
/// one with [`new`](DurableConfig::new) — which defaults the clock to
/// [`WallClock`] — and override the clock only in a test.
pub struct DurableConfig {
    /// Snapshot the monitor state every N events; `0` disables
    /// the event-count trigger, leaving checkpoints to the caller.
    pub snapshot_interval: u64,
    /// The timestamp source. Defaults to [`WallClock`]; a test injects its own to
    /// drive time. Must emit epoch **nanoseconds** (see [`Clock`]).
    pub clock: Box<dyn Clock>,
    /// How far the durable timestamp may be ahead of the current clock.
    ///
    /// Defaults to five minutes. A larger gap indicates a badly skewed clock or
    /// corrupt durable state; recovery and new timestamp assignments are rejected
    /// rather than issuing future-dated timestamps or lowering the high-water mark.
    pub max_future_skew: Duration,
    /// Test-only override for encoded log payload read into memory at once.
    #[cfg(feature = "fault-injection")]
    replay_batch_bytes: Option<NonZeroUsize>,
    /// Test-only controller installed into both the engine and its durable log.
    #[cfg(feature = "fault-injection")]
    faults: Option<Arc<FaultInjector>>,
}

impl DurableConfig {
    /// A configuration with the given snapshot cadence and the system clock.
    pub fn new(snapshot_interval: u64) -> Self {
        DurableConfig {
            snapshot_interval,
            clock: Box::new(WallClock),
            max_future_skew: Duration::from_secs(5 * 60),
            #[cfg(feature = "fault-injection")]
            replay_batch_bytes: None,
            #[cfg(feature = "fault-injection")]
            faults: None,
        }
    }

    /// Replace the clock — the injection point for tests.
    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the maximum tolerated gap between recovered and current time.
    pub fn with_max_future_skew(mut self, max_future_skew: Duration) -> Self {
        self.max_future_skew = max_future_skew;
        self
    }

    /// Override the recovery read budget for boundary-focused tests.
    #[cfg(feature = "fault-injection")]
    #[doc(hidden)]
    pub fn with_replay_batch_bytes_for_test(mut self, bytes: NonZeroUsize) -> Self {
        self.replay_batch_bytes = Some(bytes);
        self
    }

    /// Install the controller used by deterministic crash tests.
    #[cfg(feature = "fault-injection")]
    #[doc(hidden)]
    pub fn with_fault_injector(mut self, faults: Arc<FaultInjector>) -> Self {
        self.faults = Some(faults);
        self
    }
}

impl DurableTemporalEngine {
    /// Open (creating if absent) the durable store at `path` and recover: the
    /// installed policy bundle and the monitor state (from snapshot + replay).
    pub fn open(path: impl AsRef<Path>, snapshot_interval: u64) -> Result<Self, DurableError> {
        Self::open_with_config(path, DurableConfig::new(snapshot_interval))
    }

    /// [`open`](Self::open) with an explicit [`DurableConfig`] — the seam a test
    /// uses to inject a clock. `open` is this with the default (system) clock.
    pub fn open_with_config(
        path: impl AsRef<Path>,
        config: DurableConfig,
    ) -> Result<Self, DurableError> {
        let path = path.as_ref().to_path_buf();
        let log = DurableLog::open(&path).map_err(|e| DurableError::Log(e.to_string()))?;
        Self::open_with_log_config(log, path, config)
    }

    /// Recover from an already-open [`DurableLog`], whatever it is stored on.
    ///
    /// [`open`](Self::open) is this with a file-backed log; `label` is only
    /// carried for diagnostics (a store that is not a file has no path, so any
    /// descriptive name will do). Every check `open` performs — the time-unit
    /// tag above all — happens here, so a store opened over a caller-supplied
    /// backend is validated exactly as a file-backed one is.
    pub fn open_with_log(
        log: DurableLog,
        label: PathBuf,
        snapshot_interval: u64,
    ) -> Result<Self, DurableError> {
        Self::open_with_log_config(log, label, DurableConfig::new(snapshot_interval))
    }

    /// [`open_with_log`](Self::open_with_log) with an explicit [`DurableConfig`].
    /// Every open-time check happens here, so a store opened over a
    /// caller-supplied backend and an injected clock is validated exactly as a
    /// file-backed, wall-clock one is.
    pub fn open_with_log_config(
        log: DurableLog,
        label: PathBuf,
        config: DurableConfig,
    ) -> Result<Self, DurableError> {
        let path = label;
        #[cfg(feature = "fault-injection")]
        let replay_batch_bytes = config
            .replay_batch_bytes
            .unwrap_or_else(default_replay_batch_bytes);
        #[cfg(not(feature = "fault-injection"))]
        let replay_batch_bytes = default_replay_batch_bytes();
        // Engine- and log-level hooks must share one controller so one armed
        // point can synchronously stop the operation that the child is running.
        #[cfg(feature = "fault-injection")]
        let log = {
            let mut log = log;
            log.set_fault_injector(config.faults.clone());
            log
        };

        // A store's timestamps are only comparable to windows in the unit they
        // were assigned in. Reading a seconds-era store as nanos would make every
        // existing event look ~57 years old, so the first append would prune the
        // entire history — silently, and in the fail-OPEN direction, since a
        // history-gated `forbid` with no history simply passes. Refuse instead.
        // An empty store is adopted (and tagged) rather than refused.
        match log
            .get_meta(META_TIME_UNIT)
            .map_err(|e| DurableError::Log(e.to_string()))?
        {
            Some(tag) if tag == TIME_UNIT_TAG => {}
            Some(tag) => {
                return Err(DurableError::Rejected(format!(
                    "store was written with timestamps in `{}`, but this build assigns `{}`; \
                     refusing to open rather than silently discarding its history",
                    String::from_utf8_lossy(&tag),
                    String::from_utf8_lossy(TIME_UNIT_TAG),
                )));
            }
            None if log.next_offset() > 0 => {
                return Err(DurableError::Rejected(format!(
                    "store has {} events but no recorded time unit, so it predates \
                     unit tagging and its timestamps are not in `{}`; refusing to open",
                    log.next_offset(),
                    String::from_utf8_lossy(TIME_UNIT_TAG),
                )));
            }
            None => {}
        }

        // The store-configuration schema half (event schema + macros). Read
        // BEFORE `recover`, because rebuilding the authorizer during replay lowers
        // against it. Absent slot = never configured = both built-in defaults; a
        // malformed slot is treated as absent (the same fail-safe as an
        // unreadable snapshot — the first `install` re-establishes it).
        let service_config = log
            .get_meta(META_SERVICE_SCHEMA)
            .map_err(|e| DurableError::Log(e.to_string()))?
            .and_then(|bytes| serde_json::from_slice::<ServiceConfig>(&bytes).ok())
            .unwrap_or_default();

        let mut state = DurableTemporalEngine {
            log,
            running: None,
            snapshot_interval: config.snapshot_interval,
            since_snapshot: 0,
            path,
            last_ts: None,
            service_config,
            clock: config.clock,
            max_future_skew: config.max_future_skew,
            replay_batch_bytes,
            #[cfg(feature = "fault-injection")]
            faults: config.faults,
        };

        // Tag a fresh (or already-matching) store, so a later build with a
        // different unit refuses it rather than misreading it.
        state
            .log
            .commit(&[Write::Meta {
                key: META_TIME_UNIT,
                value: TIME_UNIT_TAG,
            }])
            .map_err(|e| DurableError::Log(e.to_string()))?;

        state.recover()?;
        state.validate_clock_skew(state.clock.now_nanos())?;
        Ok(state)
    }

    /// Rebuild everything from what is durable: the state a snapshot describes,
    /// then every record after it, in order.
    ///
    /// Recovery **replays forward** rather than reconstructing the newest policy
    /// and pouring state into it. It starts from the policy the snapshot names —
    /// the only leaves that snapshot's state can be loaded into — and then walks
    /// the log, stepping the monitors on each event and *folding* each
    /// policy-management verb at its own
    /// position in the order.
    ///
    /// The fold is **lazy** rather than per-record: a run of consecutive verbs
    /// applies only to the working bundle and the accumulated `fresh` set, and the
    /// authorizer is rebuilt just before the next event (and at end). That is
    /// sound (consecutive verb records fold
    /// observationally-equivalently — no intermediate state was ever observed),
    /// and it is what makes the batch grouping-agnostic: neither the live path
    /// nor recovery needs to know which verb records were one batch.
    fn recover(&mut self) -> Result<(), DurableError> {
        // Records below this no longer exist, so replay cannot start earlier and
        // must not pretend to.
        let base = self.log.base_offset();
        let snapshot = self
            .log
            .get_snapshot()
            .map_err(|e| DurableError::Log(e.to_string()))?
            .and_then(|snap| {
                SnapshotPayload::decode(&snap.payload)
                    .ok()
                    .map(|p| (snap.up_to_offset, p))
            });

        let mut restored = false;
        let mut replay_from = base;
        if let Some((up_to, payload)) = snapshot {
            // A bundle that no longer lowers leaves the server policy-less rather
            // than half-configured: the control plane can re-apply, and meanwhile
            // every `submit` is refused rather than silently unmonitored.
            let rebuilt = self
                .rebuild(&payload.bundle, StateSource::Snapshot(&payload.engine))
                .and_then(|(running, counts)| {
                    let restored_ts = running
                        .engine
                        .with(LocalTemporalEngine::latest_state_timestamp)
                        .ok_or_else(|| {
                            DurableError::Log(
                                "snapshot restored into an unavailable temporal engine".to_string(),
                            )
                        })?;
                    validate_snapshot_clock_values(restored_ts, payload.last_ts)?;
                    Ok((running, counts))
                });
            match rebuilt {
                Ok((running, _)) => {
                    self.running = Some(running);
                    // The clock the snapshot was taken under. Records below
                    // `up_to` are gone, so this is the only thing that knows
                    // how far it had advanced.
                    self.observed_timestamp(payload.last_ts);
                    replay_from = up_to.max(base);
                    restored = true;
                }
                Err(e) if base == 0 => {
                    // Surface the degrade: a refused snapshot
                    // forces a full-log replay on EVERY restart until the
                    // next checkpoint supersedes it — invisible without
                    // this line. (The library has no logger; stderr is
                    // the server's existing diagnostic channel.)
                    eprintln!(
                        "dogwood-server: snapshot refused ({e}); \
                         recovering by full log replay"
                    );
                    // The snapshot refused (format/mode change across an
                    // upgrade) but the FULL log is still present: degrade to
                    // complete replay — correct, slower.
                    // The stale snapshot is superseded on the next
                    // checkpoint.
                    restored = false;
                }
                Err(e) => {
                    // Refused snapshot AND a pruned log: serving would mean
                    // a silent hole in history (a history-gated forbid just
                    // passes). Fail closed.
                    return Err(e);
                }
            }
        } else if base > 0 {
            // No usable snapshot, and the records that would have rebuilt the
            // state are gone. Refusing is the only honest answer: the alternative
            // is serving with a hole in the history, and a history-gated `forbid`
            // with missing history simply passes.
            return Err(DurableError::Log(format!(
                "no usable snapshot and the log is pruned to offset {base}; \
                 cannot reconstruct monitor state"
            )));
        }
        // Otherwise there is nothing to start from, and nothing needs to be: with
        // no snapshot the log still holds every record, and the verb that
        // installed the first policy is one of them. The replay below establishes
        // it.

        self.replay_from(replay_from, restored)
    }

    /// Walk records from `from`, stepping the monitors on events and folding
    /// policy-management verbs into a working bundle.
    ///
    /// `restored` says whether monitor state was already established (from the
    /// snapshot). When it was, events advance the monitors only
    /// (`step_monitors`).
    ///
    /// Verbs never rebuild eagerly: the authorizer is rebuilt only when an
    /// event needs it (or at end, if the log ends on a verb). This is the
    /// grouping-agnostic replay — a run of verb records folds the
    /// same whether it was one batch or several.
    fn replay_from(&mut self, from: u64, restored: bool) -> Result<(), DurableError> {
        let replay_floor = self.last_ts;
        let replay_end = self.log.next_offset();
        let mut cursor = from;
        let mut record_index = 0usize;
        let mut previous_stamp = None;

        // The bundle being folded — seeded from whatever is running (`None` on a
        // cold start with no snapshot). `pending` accumulates the `fresh` set
        // for the *next* rebuild, so an event flushes it and resets it.
        let mut pending_bundle: Option<Installed> =
            self.running.as_ref().map(|r| r.installed.clone());
        let mut pending_fresh: BTreeSet<PolicyId> = BTreeSet::new();
        let mut pending_dirty = false;
        let mut restored = restored;

        // Rebuild `pending_bundle` into the running set and swap it in. Called
        // just before each event (so its authorizer sees the folded verbs) and
        // once at the end (so the store's live view matches the log's tail).
        let flush = |this: &mut Self,
                     pending_bundle: &mut Option<Installed>,
                     pending_fresh: &mut BTreeSet<PolicyId>,
                     pending_dirty: &mut bool,
                     restored: &mut bool|
         -> Result<(), DurableError> {
            if !*pending_dirty {
                return Ok(());
            }
            let bundle = pending_bundle
                .as_ref()
                .expect("dirty implies a bundle was folded");
            let (running, _) = this.rebuild(
                bundle,
                StateSource::Transplant {
                    fresh: pending_fresh,
                },
            )?;
            this.running = Some(running);
            pending_fresh.clear();
            *pending_dirty = false;
            *restored = true;
            Ok(())
        };

        while cursor < replay_end {
            let batch = self
                .log
                .read_batch(cursor, replay_end, self.replay_batch_bytes)
                .map_err(|e| DurableError::Log(e.to_string()))?;
            if batch.records.is_empty() {
                return Err(DurableError::Log(format!(
                    "replay: durable range [{cursor}, {replay_end}) contains no record"
                )));
            }

            for (offset, encoded) in batch.records {
                if offset != cursor {
                    return Err(DurableError::Log(format!(
                        "replay: expected log offset {cursor}, found {offset}"
                    )));
                }
                let record = Record::decode(&encoded)
                    .map_err(|e| DurableError::Log(format!("replay: {e}")))?;
                if let Some((timestamp, lower_bound)) =
                    invalid_replay_timestamp(&record, previous_stamp, replay_floor)
                {
                    return Err(DurableError::Log(format!(
                        "replay timestamps are not in durable order: record {record_index} has \
                         timestamp {timestamp} after {lower_bound}"
                    )));
                }
                previous_stamp = Some(replay_record_stamp(&record));
                record_index += 1;
                cursor = offset + 1;

                // Every record carries the timestamp it was assigned, of either
                // kind, so the clock advances past a replayed verb as readily as
                // past an event.
                self.observed_timestamp(record.timestamp());
                match record {
                    Record::Event(ev) => {
                        // Any queued verbs must land before this event's monitors
                        // run. A storage-batch boundary deliberately does not
                        // flush them.
                        flush(
                            self,
                            &mut pending_bundle,
                            &mut pending_fresh,
                            &mut pending_dirty,
                            &mut restored,
                        )?;
                        let Some(running) = &self.running else {
                            // `submit` refuses without a policy, so an event can
                            // only have been recorded under one. Reaching here
                            // means the record that installed it is missing.
                            return Err(DurableError::Log(
                                "replay: an event precedes any policy set".to_string(),
                            ));
                        };
                        let stepped = running.engine.with_mut(|engine| {
                            if restored {
                                engine.step_monitors(&ev);
                            } else {
                                engine.observe(&ev);
                            }
                        });
                        if stepped.is_none() {
                            return Err(DurableError::Log(
                                "replay: temporal engine unavailable".to_string(),
                            ));
                        }
                    }
                    verb => {
                        // Fold the verb into the working bundle. The seed is the
                        // running bundle (or the empty seed built below), never
                        // the previous verb's bundle in isolation.
                        let bundle = pending_bundle.get_or_insert_with(Installed::seed);
                        match apply_verb_to(bundle, &verb, &mut pending_fresh) {
                            Ok(()) => pending_dirty = true,
                            Err(e) => {
                                return Err(DurableError::Log(format!("replay verb: {e}")));
                            }
                        }
                    }
                }
            }
            if cursor != batch.next_offset {
                return Err(DurableError::Log(format!(
                    "replay: batch cursor {} disagrees with decoded cursor {cursor}",
                    batch.next_offset
                )));
            }
        }
        // Flush anything queued at end so the live view reflects the log's tail.
        flush(
            self,
            &mut pending_bundle,
            &mut pending_fresh,
            &mut pending_dirty,
            &mut restored,
        )?;
        Ok(())
    }

    /// Whether a policy set is installed.
    pub fn has_policy(&self) -> bool {
        self.running.is_some()
    }

    /// The next log offset — the count of events ever durably appended.
    pub fn log_offset(&self) -> u64 {
        self.log.next_offset()
    }

    /// The installed policy source, if any — the policies' canonical statements
    /// combined in installed order.
    pub fn policy_source(&self) -> Option<String> {
        self.running.as_ref().map(|r| r.installed.combined_source())
    }

    /// The temporal engine's live shard count (0 when global / nothing
    /// running) — the observable that PINS partitioned mode being active.
    #[doc(hidden)]
    pub fn temporal_shard_count(&self) -> usize {
        self.running
            .as_ref()
            .and_then(|r| r.engine.with(|e| e.shard_count()))
            .unwrap_or(0)
    }

    /// A status projection of the running set.
    pub fn status(&self) -> Status {
        match &self.running {
            Some(r) => Status {
                rule_count: r.rule_count,
                leaf_count: r.leaf_count,
                incremental_leaves: r.incremental_leaves,
                decision_kinds: r.decision_kinds.clone(),
                partition_key: r.partition_key.clone(),
            },
            None => Status::default(),
        }
    }

    /// The store path, for diagnostics.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How this policy set's event stream may be partitioned.
    ///
    /// This is the **routing seam** for pin-sharded parallelism: a multi-instance
    /// server computes `plan.key_of(event)` and routes to the instance owning that
    /// key, which is sound precisely because a shardable plan means the frontend
    /// rewrote the formulas for key-local evaluation.
    pub fn shard_plan(&self) -> ShardPlan {
        self.running
            .as_ref()
            .map(|r| r.shard_plan.clone())
            .unwrap_or(ShardPlan::Unshardable)
    }

    // ─── The data plane ──────────────────────────────────────────────

    /// Submit one event: the single schema-driven primitive.
    ///
    /// The order of operations is the load-bearing part. The event is **durably
    /// appended first**, then stepped into the monitor, then (for a decision
    /// kind) evaluated. Appending first is what makes the verdict and the
    /// history consistent under a crash: if the process dies after the append,
    /// recovery replays the event and the next decision sees it; if it died
    /// after stepping but before the append, recovery would *lose* an event the
    /// caller may already have acted on, and a future history-gated deny would
    /// wrongly pass. A failed append therefore aborts the whole operation rather
    /// than proceeding in memory.
    ///
    /// The timestamp is assigned **here**, at the append point, never taken from
    /// the caller, and clamped strictly above the previous
    /// event's so the per-instance order the temporal operators require holds
    /// even if the wall clock steps backwards.
    ///
    /// The caller supplies not a finished [`Event`](dogwood_language::Event) but
    /// an [`EventBuilder`] — an event with content but no finalized timestamp.
    /// The engine owns the
    /// clock, so it stamps the builder with the timestamp it just assigned and
    /// then builds it. This keeps the stamp unforgeable — the engine's
    /// `.timestamp(..)` is the last one applied, so it overrides anything a
    /// caller set. The builder is finalized exactly once, only
    /// after a policy set is confirmed installed.
    pub fn submit(&mut self, event: EventBuilder) -> Result<Submitted, DurableError> {
        if self.running.is_none() {
            return Err(DurableError::NoPolicy);
        }

        let ts = self.next_timestamp()?;
        let event = event.timestamp(ts).build();
        let running = self.running.as_ref().expect("checked above");
        let is_decision = running
            .decision_kinds
            .iter()
            .any(|k| k.as_str() == event.kind());

        // 1. Durable append (fsync) — the transaction boundary.
        let offset = self
            .log
            .append(&Record::Event(event.clone()).encode())
            .map_err(|e| DurableError::Log(e.to_string()))?;
        // Durable, so the clock has really advanced. Only now: a failed append
        // assigned nothing, leaving the value free for the next attempt.
        self.observed_timestamp(ts);

        // 2. Advance the monitor and (for a decision kind) decide. The
        //    authorizer feeds the event to the temporal engine either way, so a
        //    history event still updates the window it does not read.
        let running = self.running.as_mut().expect("checked above");
        let response = running
            .authorizer
            .is_authorized(&event)
            .map(|response| attribute_response(&response, &running.attributions));

        // 3. Periodic snapshot (the event-count trigger). Best-effort: a
        //    failed checkpoint costs replay depth, never correctness.
        self.since_snapshot += 1;
        if self.snapshot_interval != 0 && self.since_snapshot >= self.snapshot_interval {
            let _ = self.checkpoint();
        }

        let submitted = match (is_decision, response) {
            (true, Some(r)) => Submitted {
                offset,
                ts,
                outcome: Outcome::Decision(r),
            },
            // A kind the schema calls a decision point that nonetheless produced
            // no response means the authorizer disagreed with our kind lookup —
            // report it rather than inventing a verdict either way.
            (true, None) => {
                // The fully-qualified action (`Ns::Action::id`), not the bare id,
                // so the message names what the operator would search for.
                let action = if event.namespace().is_empty() {
                    event.action().to_string()
                } else {
                    format!("{}::{}", event.namespace().join("::"), event.action())
                };
                return Err(DurableError::BadEvent(format!(
                    "event kind `{}` is a decision kind but yielded no decision \
                     (is `{action}` declared in the schema?)",
                    event.kind(),
                )));
            }
            (false, _) => Submitted {
                offset,
                ts,
                outcome: Outcome::Recorded,
            },
        };
        // Persistence and monitor evaluation are complete here, but the caller
        // has not received the Submitted acknowledgement.
        #[cfg(feature = "fault-injection")]
        if let Some(faults) = &self.faults {
            faults.reach(FaultPoint::SubmitBeforeAcknowledge);
        }
        Ok(submitted)
    }

    /// The timestamp to assign the next event, in epoch **nanoseconds**:
    /// `max(now, last + 1)`.
    ///
    /// The clamp guarantees strict increase, which window eviction and `previous`
    /// both depend on.
    fn next_timestamp(&self) -> Result<i64, DurableError> {
        let now = self.clock.now_nanos();
        let allowed = i128::try_from(self.max_future_skew.as_nanos()).unwrap_or(i128::MAX);
        next_timestamp_values(self.last_ts, now, allowed)
    }

    /// Record that `ts` is now durable. Called only after the commit that wrote
    /// it: a failed commit assigned no timestamp, so the value stays free for the
    /// next attempt.
    fn observed_timestamp(&mut self, ts: i64) {
        self.last_ts = observed_timestamp_value(self.last_ts, ts);
    }

    /// Refuse a durable high-water mark implausibly far ahead of wall time.
    ///
    /// Lowering `last_ts` would permit timestamps to go backwards, while accepting
    /// a large gap can prematurely expire temporal history. Recovery and writes
    /// therefore fail closed and leave correcting the host clock or store to an
    /// operator.
    fn validate_clock_skew(&self, now: i64) -> Result<(), DurableError> {
        let allowed = i128::try_from(self.max_future_skew.as_nanos()).unwrap_or(i128::MAX);
        validate_clock_skew_values(self.last_ts, now, allowed)
    }

    // ─── The control plane ───────────────────────────────────────────

    /// Install a bundle as a **declarative whole-set replace** — the private
    /// primitive [`install`](Self::install) finishes with.
    ///
    /// **Private on purpose.** It takes a pre-built [`Installed`], so a public
    /// caller could hand the engine a `PolicySet` whose entry does not
    /// correspond one-to-one with a Cedar policy — which would break the
    /// `(policy id, clause index)` transplant's assumption (see `rebuild`'s
    /// invariant). Every public entry point (`install`, `batch`) builds
    /// one-policy-per-entry sets instead, so this is only reachable through them.
    ///
    /// Semantics are **reborn-all**, not prospective: this models
    /// `[SetActionSchema; DeleteAll; Add each]` (the declarative path wipes and
    /// rebuilds, so *every* resulting
    /// policy is born fresh with an empty window). To *keep* unchanged policies'
    /// history, use `batch` with targeted verbs, which leaves unmentioned
    /// policies untouched; this method deliberately does not.
    ///
    /// Two non-negotiables, both realized here:
    ///
    /// - **Validate server-side.** The bundle is parsed, lowered, and
    ///   type-checked *here*, against the installed schema, before anything is
    ///   accepted (`commit_and_swap` → `rebuild`). A compromised control client
    ///   is exactly who would skip a client-side check.
    /// - **Atomic swap.** The replacement authorizer is fully built (and the
    ///   records durably committed) before `self.running` is reassigned, so a
    ///   decision never runs against a half-applied set and a rejected install
    ///   leaves the running set serving.
    ///
    /// The event schema / macros are store config, not part of this
    /// stream — it uses whatever the store was configured with and never changes
    /// them. `service_config_bytes` is the encoded [`ServiceConfig`] to persist
    /// in this same transaction on a *first* install (`None` otherwise); folding
    /// it into the record commit keeps a rejected install from stranding a durable
    /// config write.
    fn apply(
        &mut self,
        installed: Installed,
        now: i64,
        service_config_bytes: Option<&[u8]>,
    ) -> Result<Applied, DurableError> {
        // `[SetActionSchema; DeleteAll; Add each]` over the durable verb stream.
        // Every resulting policy is fresh, so `fresh` is the whole resulting id
        // set (reborn-all).
        //
        // A batch is one atomic transaction — "sequential in meaning, transactional
        // in effect" — so every record shares the batch's single timestamp
        // `now`, the same value `install_configured` stamped each entry's
        // `created`/`updated` with. Their order within the batch is carried by the
        // log **offset** (records occupy contiguous offsets), not by the
        // timestamp, so the timestamps need not advance. Sharing one `now` is what
        // makes the running set and its post-recovery rebuild agree: replay stamps
        // each entry from its record's `ts`, which is `now` for all of them.
        //
        // `now` is *observed* inside `commit_and_swap`, only after the log accepts
        // it — a rejected install claims no timestamp (the `observed_timestamp`
        // contract).
        let mut minted: Vec<Record> = Vec::new();
        minted.push(Record::SetActionSchema {
            ts: now,
            action_schema: installed.action_schema.clone(),
        });
        minted.push(Record::DeleteAll { ts: now });
        let mut fresh: BTreeSet<PolicyId> = BTreeSet::new();
        for entry in installed.policies.entries() {
            fresh.insert(entry.id);
            minted.push(Record::Add {
                ts: now,
                id: entry.id,
                token: entry.token.clone(),
                statement: entry.statement.clone(),
            });
        }
        let records: Vec<Vec<u8>> = minted.iter().map(Record::encode).collect();

        self.commit_and_swap(records, &installed, &fresh, now, service_config_bytes)
    }

    /// Install a whole policy set from source, replacing any current set — the
    /// first-configuration / declarative path (`[SetActionSchema; DeleteAll; Add
    /// each]`). The source is parsed and each policy rendered to its canonical
    /// statement via `expanded_source`; every policy is born fresh with a minted
    /// id.
    ///
    /// This is also the **store-configuration** entry point: the event schema and
    /// macro library are set here, once. Both are immutable through the
    /// verbs, so a later `install` that would *change* either is **rejected** —
    /// changing them reborns the whole set and is a deliberate store rebuild
    /// (open a fresh store), not an everyday operation. Passing `None` uses the
    /// built-in defaults; re-installing with the same config is idempotent.
    pub fn install(
        &mut self,
        policy_source: &str,
        action_schema: &str,
        event_schema: Option<&str>,
        macros: Option<&str>,
    ) -> Result<Applied, DurableError> {
        // Decide the store's service config *without* persisting it: validate the
        // set-once rule and compute the bytes to write, but commit nothing yet.
        // The bytes ride along in the same transaction as the policy records
        // (`apply` → `commit_and_swap`), so a policy that fails to canonicalize or
        // validate below leaves the store untouched — the event schema is not
        // locked in by a rejected install, and there is no separate transaction a
        // crash could strand (matches the
        // batch "a rejected change writes nothing" rule).
        let (desired_config, config_bytes) = self.plan_service_config(event_schema, macros)?;
        // Adopt in memory up front, because `rebuild` lowers the policy against
        // `self.service_config`, and this install's policy must lower against the
        // config being installed. The *durable* write still rides the record
        // commit, so if the install is rejected below, nothing was persisted and
        // the in-memory adoption is rolled back — leaving the store fully
        // reconfigurable by a later install.
        let previous_config = std::mem::replace(&mut self.service_config, desired_config);
        let result = self.install_configured(policy_source, action_schema, config_bytes.as_deref());
        if result.is_err() {
            self.service_config = previous_config;
        }
        result
    }

    /// The body of [`install`](Self::install) once the (already-adopted) service
    /// config has been decided: canonicalize the source against the current
    /// service, mint continued ids, and commit. Split out so `install` can roll
    /// the in-memory service-config adoption back on any failure here (the
    /// durable config write rides `apply`'s commit, so a rejection persists
    /// nothing).
    fn install_configured(
        &mut self,
        policy_source: &str,
        action_schema: &str,
        config_bytes: Option<&[u8]>,
    ) -> Result<Applied, DurableError> {
        let service = Self::build_service(&self.service_config)?;
        let statements = Self::canonicalize_source(policy_source, &service)
            .map_err(|e| DurableError::Rejected(format!("policy: {e}")))?;
        let now = self.next_timestamp()?;
        // A re-install is `[DeleteAll; Add each]`: it wipes the set but
        // must *continue* the id cursor, never restart it — otherwise a fresh
        // policy could reuse an id a caller still holds for a since-deleted one
        // Seed from the running set's cursor (0 on a first install).
        let next_id = self
            .running
            .as_ref()
            .map(|r| r.installed.policies.next_id())
            .unwrap_or(0);
        let installed = Installed {
            policies: PolicySet::from_statements_after(statements, now, next_id, mint_policy_token)
                .map_err(DurableError::Rejected)?,
            action_schema: action_schema.to_string(),
        };
        // The entries above are stamped `now`; `apply` stamps every record with the
        // same `now`, so the batch is one instant end to end.
        self.apply(installed, now, config_bytes)
    }

    /// Decide the store's service configuration — the event schema and macro
    /// library — without persisting anything. Returns the config to adopt
    /// and, on the *first* configuration, the encoded bytes to persist (`None`
    /// when a config is already established, so nothing needs writing).
    ///
    /// Set once on the first `install`; a later call that would *change* it is
    /// rejected. `None` means "the built-in default", and re-affirming the same
    /// config is a no-op. Deliberately does **not** commit: the caller folds the
    /// returned bytes into the same transaction as the policy records, so a
    /// rejected install leaves the config unwritten.
    fn plan_service_config(
        &self,
        event_schema: Option<&str>,
        macros: Option<&str>,
    ) -> Result<(ServiceConfig, Option<Vec<u8>>), DurableError> {
        let desired = ServiceConfig {
            event_schema: event_schema.map(str::to_string),
            macros: macros.map(str::to_string),
        };
        // Whether a config was ever written: the slot's presence is the flag, so
        // "configured with the defaults" is distinguishable from "never
        // configured". Absent slot AND a default in-memory config ⇒ first time.
        let already_set = self
            .log
            .get_meta(META_SERVICE_SCHEMA)
            .map_err(|e| DurableError::Log(e.to_string()))?
            .is_some();

        if already_set {
            if self.service_config != desired {
                return Err(DurableError::Rejected(
                    "the event schema and macro library are fixed at store \
                     configuration and cannot be changed by a later install; \
                     changing them reborns every policy and requires a fresh store"
                        .to_string(),
                ));
            }
            // Already established and unchanged — adopt as-is, write nothing.
            return Ok((desired, None));
        }

        // First configuration: hand back the bytes so the install's own commit
        // persists them atomically with the policy records.
        let bytes = serde_json::to_vec(&desired).map_err(|e| DurableError::Log(e.to_string()))?;
        Ok((desired, Some(bytes)))
    }

    /// Apply a batch of policy verbs atomically over the current set.
    /// The event schema is fixed; a `SetActionSchema` verb re-lowers the whole
    /// set. Rejected as a unit if any verb is invalid — the running set is
    /// untouched. Requires a prior [`install`](Self::install) (the schemas come
    /// from the current bundle).
    ///
    /// The fold happens on a working copy; only the resulting `Installed`
    /// validates and only the resulting run of records commits. Each verb is
    /// its own durable record (no `Batch` wrapper), so replay is
    /// grouping-agnostic.
    pub fn batch(&mut self, verbs: Vec<Verb>) -> Result<BatchResult, DurableError> {
        // An empty batch is a no-op: return without rebuilding the authorizer,
        // writing a record, or advancing the clock. (A degenerate but legal
        // request — e.g. a client that assembled zero verbs.) It changes nothing,
        // so it needs no installed set and reports the clock as it stands.
        if verbs.is_empty() {
            return Ok(BatchResult {
                minted: Vec::new(),
                ts: self.last_ts.unwrap_or(0),
                leaves_retained: 0,
            });
        }
        let current = self
            .running
            .as_ref()
            .ok_or(DurableError::NoPolicy)?
            .installed
            .clone();
        // The event schema / macros are store config, immutable through
        // the verbs — so the batch lowers against the store's fixed service
        // config, never anything carried in the bundle.
        let service = Self::build_service(&self.service_config)?;
        let now = self.next_timestamp()?;
        let canon = |src: &str| -> Result<Vec<String>, String> {
            let stmts = Self::canonicalize_source(src, &service)?;
            if stmts.is_empty() {
                return Err("source contains no policy".to_string());
            }
            Ok(stmts)
        };
        let outcome = current
            .policies
            .fold(
                &verbs,
                now,
                &current.action_schema,
                canon,
                mint_policy_token,
            )
            .map_err(|e| DurableError::Rejected(e.to_string()))?;
        let installed = Installed {
            policies: outcome.set,
            action_schema: outcome
                .action_schema
                .clone()
                .unwrap_or(current.action_schema),
        };

        // The fold already produced the ordered durable effects — including the
        // random `Add` handles a second pass could not reproduce — so we only
        // stamp each with the batch's single timestamp `now`. A batch is atomic
        // ("sequential in meaning, transactional in effect"), so it is one
        // instant; the records' order within it is carried by the log **offset**
        // (contiguous), not the timestamp. Sharing one `now` is what keeps
        // the running set and its post-recovery rebuild identical.
        //
        // `now` is *observed* inside `commit_and_swap`, only after the log accepts
        // it — a rejected rebuild or a failed commit claims no timestamp, so a
        // rejected batch leaves `last_ts` untouched (the `observed_timestamp`
        // contract). A prior fold rejection returned above, likewise advancing
        // nothing.
        let records: Vec<Vec<u8>> = outcome
            .records
            .iter()
            .map(|r| stamp_record(r, now).encode())
            .collect();

        // A batch never touches store config (event schema/macros are
        // fixed at the first install), so no config bytes ride along.
        let applied = self.commit_and_swap(records, &installed, &outcome.fresh, now, None)?;
        Ok(BatchResult {
            minted: outcome.minted,
            ts: applied.ts,
            leaves_retained: applied.leaves_retained,
        })
    }

    /// Build the new authorizer over `installed` with state transplanted from
    /// the running set (skipping the ids in `fresh`), atomically commit the
    /// prepared record bytes, and swap the running set in on success.
    ///
    /// Rebuild-then-commit is the load-bearing order: the authorizer is shown
    /// buildable and validatable *before* any record is durable, and the running
    /// set is only swapped *after* the log has accepted the whole batch — so a
    /// crash between the two either preserves the old set (commit not reached)
    /// or restores the new one from the log (commit made it, swap did not).
    fn commit_and_swap(
        &mut self,
        records: Vec<Vec<u8>>,
        installed: &Installed,
        fresh: &BTreeSet<PolicyId>,
        ts: i64,
        service_config_bytes: Option<&[u8]>,
    ) -> Result<Applied, DurableError> {
        let (running, counts) = self.rebuild(installed, StateSource::Transplant { fresh })?;

        // `ts` is the batch's single instant, already baked into every record. It
        // is the boundary "everything after this was decided under the new set"
        // points at. `records` is always non-empty here: `apply` emits at least
        // `[SetActionSchema; DeleteAll]`, and `batch` short-circuits an empty verb
        // list to a no-op before reaching this point.
        let mut writes: Vec<Write<'_>> = records.iter().map(|r| Write::Append(r)).collect();
        // On a first install, the store's service config is written in this same
        // transaction as the records it configures — all-or-nothing, so a crash
        // or a validation failure can never leave the config set without the set
        // it belongs to. `Meta` writes take no log offset, so
        // the `first`/`last` offset arithmetic below is unaffected.
        if let Some(bytes) = service_config_bytes {
            writes.push(Write::Meta {
                key: META_SERVICE_SCHEMA,
                value: bytes,
            });
        }
        let offsets = self
            .log
            .commit(&writes)
            .map_err(|e| DurableError::Log(e.to_string()))?;

        // Durable now — and only now, per the `observed_timestamp` contract: the
        // `ts` claimed by this batch is committed, so advance the shared sequence.
        // A rejected rebuild or a failed commit returned above, claiming nothing.
        self.observed_timestamp(ts);

        // The last verb's offset/ts is the boundary the batch is *for*: events
        // strictly after it are under the new set. An empty batch (no records)
        // reports the current log offset unchanged — degenerate, but explicit.
        let last_offset = offsets
            .last()
            .copied()
            .unwrap_or_else(|| self.log.next_offset());
        let first_offset = offsets.first().copied().unwrap_or(last_offset);
        let last_ts = self.last_ts.unwrap_or(0);

        self.running = Some(running);
        Ok(Applied {
            offset: last_offset,
            first_offset,
            ts: last_ts,
            rule_count: counts.rule_count,
            leaf_count: counts.leaf_count,
            leaves_retained: counts.leaves_retained,
            leaves_prospective: counts.leaf_count.saturating_sub(counts.leaves_retained),
        })
    }

    /// The installed policies in order — an owned snapshot.
    pub fn list(&self) -> Vec<PolicyEntry> {
        self.running
            .as_ref()
            .map(|r| r.installed.policies.entries().cloned().collect())
            .unwrap_or_default()
    }

    /// One policy's full entry by its handle.
    pub fn get_policy(&self, token: &PolicyToken) -> Option<PolicyEntry> {
        self.running
            .as_ref()
            .and_then(|r| r.installed.policies.get_by_token(token).cloned())
    }

    /// The running set's action schema — the **original** the operator authored,
    /// not the augmented one lowering derives. `None` when no
    /// policy set is installed.
    pub fn action_schema(&self) -> Option<String> {
        self.running
            .as_ref()
            .map(|r| r.installed.action_schema.clone())
    }

    /// The store's configured event schema. `None` means the
    /// built-in default (`DEFAULT_EVENT_SCHEMA`) is in force — the operator
    /// authored no override. This is store configuration, so it is available even
    /// before a policy set is installed.
    pub fn event_schema(&self) -> Option<String> {
        self.service_config.event_schema.clone()
    }

    /// Build the parsing service from the store's fixed [`ServiceConfig`] — the
    /// event schema and macro library. Each `None` field uses the
    /// frontend's built-in default (`DEFAULT_EVENT_SCHEMA` / `DEFAULT_MACROS`).
    fn build_service(config: &ServiceConfig) -> Result<ServiceSchema, DurableError> {
        let mut b = ServiceSchema::builder();
        if let Some(s) = &config.event_schema {
            b = b.event_schema_str(s);
        }
        if let Some(m) = &config.macros {
            b = b.macros_str(m);
        }
        b.build()
            .map_err(|e| DurableError::Rejected(format!("service schema: {e}")))
    }

    /// Parse `source` and render each policy to its canonical statement via
    /// `expanded_source` — the ironed-out canonicalization. Errors on invalid
    /// source (the caller maps it to a rejection).
    fn canonicalize_source(source: &str, service: &ServiceSchema) -> Result<Vec<String>, String> {
        let parsed = ParsedPolicySet::parse(source, service).map_err(|e| e.to_string())?;
        Ok(parsed.policies().map(|p| p.expanded_source()).collect())
    }

    /// Read positional state out of a running set's shared engine. `None` when
    /// the lock is poisoned: derived state may be torn, so checkpointing must
    /// fail rather than make it durable.
    fn capture(running: &Running) -> Option<Vec<u8>> {
        running.engine.with(|engine| engine.save_snapshot())
    }

    /// Reclaim records below `below`, a chunk per transaction, until done.
    ///
    /// Chunked because redb permits one writer: a single transaction spanning a
    /// whole retained window would block every submit for its duration.
    fn prune_to(&self, below: u64) -> Result<(), DurableError> {
        loop {
            let step = self
                .log
                .prune_below(below, PRUNE_CHUNK)
                .map_err(|e| DurableError::Log(e.to_string()))?;
            if step.done {
                return Ok(());
            }
        }
    }

    /// Build (or rebuild) the authorizer from `installed`.
    fn rebuild(
        &mut self,
        installed: &Installed,
        source: StateSource<'_>,
    ) -> Result<(Running, Counts), DurableError> {
        // Lower and validate. Any failure here is a rejection that leaves the
        // running set untouched (nothing below has mutated `self.running` yet).
        // The service schema (event schema + macros) is store config, held on
        // `self`, not carried in the bundle.
        let service = Self::build_service(&self.service_config)?;
        let policy_schema = PolicySchema::from_cedarschema_str(&installed.action_schema)
            .map_err(|e| DurableError::Rejected(format!("action schema: {e}")))?;
        let policy_src = installed.combined_source();
        let parsed = ParsedPolicySet::parse(&policy_src, &service)
            .map_err(|e| DurableError::Rejected(format!("policy: {e}")))?;
        let policy_ids = validate_policy_entry_alignment(installed, &service, &parsed)?;
        let lowered = parsed
            .lower(&policy_schema)
            .map_err(|e| DurableError::Rejected(format!("policy: {e}")))?;
        validate_lowered_rule_alignment(lowered.rules(), policy_ids.len())?;

        let result = Validator::new().validate(&lowered);
        if !result.validation_passed() {
            let findings: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
            return Err(DurableError::Rejected(format!(
                "policy set failed validation:\n{}",
                findings.join("\n")
            )));
        }

        let attributions =
            build_attributions(lowered.rules(), lowered.as_cedar(), &installed.policies)?;
        let rule_count = lowered.rules().count();
        // NATIVE PIN PARTITIONING, auto-enabled by the schema's pins:
        // with universal
        // symmetric pins declared, the engine runs one monitor shard
        // per pin value over the NON-relativized leaves — same verdicts
        // as the relativization rewrite, flat
        // per-key evaluation, and stale-key reclamation. Without pins
        // the two leaf sets coincide and the engine runs global.
        let partitioned = !lowered.partition_keys().is_empty();
        let leaves: Vec<_> = if partitioned {
            lowered.nonrelativized_temporal_fields().cloned().collect()
        } else {
            lowered.temporal_fields().cloned().collect()
        };
        let leaf_count = leaves.len();
        let decision_kinds: Vec<String> = lowered.decision_kinds().map(String::from).collect();
        let schema = lowered.cedar_schema().clone();
        // Whether this schema's event stream may be partitioned.
        // Derived from the schema's declared pins, so it changes with the
        // policy set — a schema edit that drops the universal pin makes the stream
        // unshardable from that apply forward.
        let shard_plan = ShardPlan::from_policies(&lowered);

        // The declared signature of every event the policy set can see. The
        // local engine interprets rather than compiles, so it does not use
        // these — but the trait requires them.
        let event_signatures: Vec<_> = lowered.event_signatures().collect();

        // Prepare a fresh engine over the new leaves, then give it state.
        let mut engine = LocalTemporalEngine::new().with_tick_rate(TIME_UNIT);
        if partitioned {
            engine.set_partition_keys(lowered.partition_keys());
        }
        engine
            .prepare(&leaves, &schema, &event_signatures)
            .map_err(|e| DurableError::Rejected(format!("prepare leaves: {e}")))?;
        let incremental_leaves = engine.incremental_leaf_count();
        let leaf_keys = engine.leaf_keys();

        // Feed the engine the validated id ↔ source-position map so
        // `save_keyed_state` / `share_leaf_state` key by
        // `(policy id, clause ordinal)`.
        engine.set_policy_ids(&policy_ids);

        let leaves_retained = match source {
            // The leaves are exactly the ones this snapshot was taken from — it
            // names them — so this is a direct restore, not a transplant.
            StateSource::Snapshot(bytes) => {
                if engine.load_snapshot(bytes) {
                    engine.incremental_leaf_count()
                } else {
                    // A PRESENT snapshot that refuses to load (format
                    // change, mode change, corruption). Surface it; recover() decides whether
                    // the log can still cover the gap.
                    return Err(DurableError::Log(
                        "snapshot present but refused by the engine \
                         (format or mode change?)"
                            .to_string(),
                    ));
                }
            }
            StateSource::Transplant { fresh } => {
                // A transplant carries monitor state keyed by the leaves'
                // composite keys. Even after the entry/rule alignment checks above,
                // reject a leaf whose generated origin cannot be resolved: a
                // frontend id-format change must fail closed rather than degrade to
                // the content-only `?:` key.
                reject_unresolved_transplant_origins(&engine)?;
                self.transplant_leaf_state(&mut engine, fresh)?
            }
        };

        // Share the engine so `checkpoint` can read its state; the authorizer
        // gets a clone of the handle, not a second engine.
        let shared = SharedEngine::new(engine);
        let authorizer = Authorizer::builder(lowered)
            .temporal_engine(shared.clone())
            .build()
            .map_err(|e| DurableError::Rejected(format!("build authorizer: {e}")))?;

        // Built, not installed. The caller decides when this starts serving —
        // `apply` makes it durable first, so a crash cannot leave decisions
        // having been made under a set that recovery will not restore.
        let running = Running {
            installed: installed.clone(),
            authorizer,
            attributions,
            engine: shared,
            decision_kinds,
            rule_count,
            leaf_count,
            incremental_leaves,
            leaf_keys,
            partition_key: match &shard_plan {
                ShardPlan::Sharded { key_paths } => key_paths.iter().map(|p| p.join(".")).collect(),
                ShardPlan::Unshardable => Vec::new(),
            },
            shard_plan,
        };

        Ok((
            running,
            Counts {
                rule_count,
                leaf_count,
                leaves_retained,
            },
        ))
    }

    /// Policy-change path: transplant state into the new leaves by composite
    /// `(policy id, clause ordinal)`, so
    /// unchanged policies keep their windows and policies in `fresh` (Add /
    /// Update / Reset / all of ResetAll) start empty. Returns how many leaves
    /// kept their state.
    ///
    /// State comes only from the **live engine**. Recovery first restores the
    /// positional snapshot or replays the complete log, so any subsequent policy
    /// change has a running source. With no running set this is the first install,
    /// whose leaves are necessarily prospective. A poisoned live source rejects
    /// any change that needs to retain a leaf: treating unavailable state as an
    /// empty window can turn a history-gated forbid into a wrong Allow. A change
    /// whose every destination leaf is fresh needs no source and remains safe.
    fn transplant_leaf_state(
        &self,
        engine: &mut LocalTemporalEngine,
        fresh: &BTreeSet<PolicyId>,
    ) -> Result<usize, DurableError> {
        let needs_source_state = engine.composite_leaf_keys().iter().any(|key| {
            parse_leading_id(key)
                .map(|id| !fresh.contains(&PolicyId(id)))
                .unwrap_or(true)
        });
        if !needs_source_state {
            return Ok(0);
        }

        if let Some(running) = &self.running {
            // MODE MATRIX (native partitioning):
            // the Arc fast path (share/adopt) exists only for global↔global.
            // Any cell involving a partitioned engine goes through the
            // KEYED-STATE path, whose per-entry pin-set fingerprint makes
            // cross-mode and cross-key transplants degrade to prospective
            // install (fail-safe: under-reported history, never a wrong
            // Allow) instead of panicking or misloading.
            let live_partitioned = running
                .engine
                .with(|live| live.is_partitioned())
                .ok_or_else(|| {
                    DurableError::Log(
                        "temporal engine unavailable; refusing to transplant monitor state"
                            .to_string(),
                    )
                })?;
            if live_partitioned || engine.is_partitioned() {
                let entries = running
                    .engine
                    .with(|live| live.save_keyed_state())
                    .ok_or_else(|| {
                        DurableError::Log(
                            "temporal engine unavailable; refusing to transplant monitor state"
                                .to_string(),
                        )
                    })?;
                let entries = filter_out_fresh(entries, fresh);
                return Ok(engine.load_keyed_state(&entries)?);
            }
            let entries = running
                .engine
                .with(|live| live.share_leaf_state())
                .ok_or_else(|| {
                    DurableError::Log(
                        "temporal engine unavailable; refusing to transplant monitor state"
                            .to_string(),
                    )
                })??;
            let entries = filter_out_fresh(entries, fresh);
            return Ok(engine.adopt_leaf_state(&entries)?);
        }

        Ok(0)
    }

    // ─── Checkpointing ───────────────────────────────────────────────

    /// Snapshot the monitor state now and prune the working log below it.
    /// The positional snapshot names its policy bundle, so
    /// recovery restores it only into the identical leaf order. Policy changes
    /// after recovery transplant from that restored live engine.
    pub fn checkpoint(&mut self) -> Result<u64, DurableError> {
        let Some(running) = &self.running else {
            return Ok(self.log.next_offset());
        };
        let up_to = self.log.next_offset();
        let Some(engine_state) = Self::capture(running) else {
            return Err(DurableError::Log(
                "temporal engine unavailable; skipped checkpoint".to_string(),
            ));
        };
        let payload = SnapshotPayload {
            bundle: running.installed.clone(),
            last_ts: self.last_ts.unwrap_or(0),
            engine: engine_state,
        }
        .encode()
        .map_err(DurableError::Log)?;

        // The policy bundle and monitor state share one snapshot envelope and
        // therefore become durable atomically.
        self.log
            .commit(&[Write::Snapshot(&Snapshot {
                up_to_offset: up_to,
                payload,
            })])
            .map_err(|e| DurableError::Log(e.to_string()))?;
        self.since_snapshot = 0;

        // Reclamation, after the snapshot that justifies it is durable.
        // At this hook the new snapshot is committed, while records retained
        // after earlier checkpoints have not yet been pruned by this checkpoint.
        #[cfg(feature = "fault-injection")]
        if let Some(faults) = &self.faults {
            faults.reach(FaultPoint::CheckpointBeforePrune);
        }
        self.prune_to(up_to)?;
        Ok(up_to)
    }

    /// The content-derived identities of the installed leaves, for
    /// diagnostics.
    pub fn leaf_keys(&self) -> Vec<String> {
        self.running
            .as_ref()
            .map(|r| r.leaf_keys.clone())
            .unwrap_or_default()
    }
}

/// Validate the correspondence between structured entries and the combined
/// source handed to lowering.
///
/// Each entry must independently parse to one policy. Its current canonical
/// rendering must then equal the policy at the same position in the combined
/// parse. This remains active in release builds and catches the otherwise
/// dangerous equal-total case where one entry contributes zero policies and a
/// later entry contributes two.
fn validate_policy_entry_alignment(
    installed: &Installed,
    service: &ServiceSchema,
    combined: &ParsedPolicySet,
) -> Result<Vec<PolicyId>, DurableError> {
    let mut policy_ids = Vec::with_capacity(installed.policies.len());
    let mut independently_parsed = Vec::with_capacity(installed.policies.len());

    for entry in installed.policies.entries() {
        let parsed = ParsedPolicySet::parse(&entry.statement, service).map_err(|error| {
            DurableError::Rejected(format!(
                "stored policy {} does not parse independently: {error}",
                entry.id
            ))
        })?;
        if parsed.policy_count() != 1 {
            return Err(DurableError::Rejected(format!(
                "stored policy {} contains {} policies; expected exactly one",
                entry.id,
                parsed.policy_count()
            )));
        }
        let normalized = parsed
            .policies()
            .next()
            .expect("policy_count was checked")
            .expanded_source();
        policy_ids.push(entry.id);
        independently_parsed.push(normalized);
    }

    let combined_policies: Vec<String> = combined
        .policies()
        .map(|policy| policy.expanded_source())
        .collect();
    if combined_policies != independently_parsed {
        return Err(DurableError::Rejected(
            "stored policy order does not match the combined lowering source".to_string(),
        ));
    }

    Ok(policy_ids)
}

/// Validate the frontend metadata that connects `policy_N` to entry position N.
///
/// The default lowering path promises one descriptor per source policy, in
/// source order, with the `policy_{N}` Cedar id. State transfer must reject a
/// frontend behavior change instead of associating a stable policy id with the
/// wrong leaf.
fn validate_lowered_rule_alignment(
    rules: impl IntoIterator<Item = DogwoodRuleRef>,
    expected_policy_count: usize,
) -> Result<(), DurableError> {
    let rules: Vec<DogwoodRuleRef> = rules.into_iter().collect();
    if rules.len() != expected_policy_count {
        return Err(DurableError::Rejected(format!(
            "lowering produced {} rules for {expected_policy_count} stored policies",
            rules.len()
        )));
    }

    for (expected_index, rule) in rules.iter().enumerate() {
        let expected_id = format!("policy_{expected_index}");
        if rule.rule_index != expected_index || rule.cedar_policy_id != expected_id {
            return Err(DurableError::Rejected(format!(
                "lowered rule {expected_index} has source index {} and Cedar id {:?}; \
                 expected source index {expected_index} and Cedar id {expected_id:?}",
                rule.rule_index, rule.cedar_policy_id
            )));
        }
    }

    Ok(())
}

/// Refuse to transplant state when a leaf cannot be scoped to a policy.
///
/// This is intentionally private: unresolved origins indicate an invariant
/// failure between lowering and the stored policy set, not caller input.
fn reject_unresolved_transplant_origins(engine: &LocalTemporalEngine) -> Result<(), DurableError> {
    if let Some(unresolved) = engine
        .composite_leaf_keys()
        .iter()
        .find(|key| key.starts_with("?:"))
    {
        return Err(DurableError::Rejected(format!(
            "a temporal leaf's policy origin could not be resolved \
             (key {unresolved:?}); refusing to transplant monitor state \
             that could bind one policy's window to another"
        )));
    }
    Ok(())
}

/// Drop entries whose composite key names a policy in `fresh`.
///
/// Composite keys begin with `"{policy_id}:{ordinal}:…"`
/// (the local engine's composite key builder), so filtering by the leading id
/// segment is exact — no substring or content-slice can imitate a numeric prefix
/// followed by a colon, since ids are digit-only. An entry whose key does not
/// parse this way is passed through: it did not come from a policy we can
/// resolve, and the fail-safe is to let the destination's key match decide
/// (which itself falls back to no-match under the same shape mismatch).
fn filter_out_fresh<T>(entries: Vec<(String, T)>, fresh: &BTreeSet<PolicyId>) -> Vec<(String, T)> {
    if fresh.is_empty() {
        return entries;
    }
    let mut retained = Vec::new();
    for entry in entries {
        let keep = match parse_leading_id(&entry.0) {
            Some(id) => !fresh.contains(&PolicyId(id)),
            None => true,
        };
        if keep {
            retained.push(entry);
        }
    }
    retained
}

/// The leading `{u64}:` segment of a composite key, if present. Case is exact —
/// `"12:3:…"` parses to `Some(12)`, `"foo:…"` yields `None`.
fn parse_leading_id(key: &str) -> Option<u64> {
    let (head, _rest) = key.split_once(':')?;
    head.parse().ok()
}

#[cfg(test)]
mod tests {
    mod attribution;

    use std::collections::BTreeSet;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use dogwood_language::cedar::Schema;
    use dogwood_language::{
        DogwoodRuleRef, Event, EventBuilder, LoweredPolicySet, ParsedPolicySet, PolicySchema,
        ServiceSchema, TemporalEngine, Value,
    };

    use super::{DurableError, DurableTemporalEngine, Installed, Outcome, PolicyId, Verb};
    use super::{
        filter_out_fresh, parse_leading_id, reject_unresolved_transplant_origins,
        validate_lowered_rule_alignment, validate_policy_entry_alignment,
    };
    use crate::{LocalTemporalEngine, PolicySet, composite_transplant_key};

    const ACTION_SCHEMA: &str = r#"
namespace Test {
  type Input = { doc: String };
  entity User;
  entity Doc;
  action "Read" appliesTo {
    principal: [User], resource: [Doc], context: { input: Input }
  };
  action "Export" appliesTo {
    principal: [User], resource: [Doc], context: { input: Input }
  };
}
"#;

    const POLICY: &str = r#"
forbid (
    principal,
    action == Test::Action::"Export",
    resource
)
when temporal {
    formerly within 1h Test::Action::"Read"::request{}
};
"#;

    #[test]
    fn composite_key_leading_id_round_trips_u64_boundaries() {
        for id in [0, 1, u64::MAX] {
            for ordinal in [0, 7, usize::MAX] {
                for content in ["", "leaf", "content:with:colons", "?:sentinel"] {
                    let key = composite_transplant_key(PolicyId(id), ordinal, content);
                    assert_eq!(parse_leading_id(&key), Some(id));
                }
            }
        }
    }

    #[test]
    fn leading_id_parser_rejects_missing_invalid_and_overflowing_heads() {
        assert_eq!(parse_leading_id("12:3:leaf"), Some(12));
        assert_eq!(
            parse_leading_id("18446744073709551615:0:leaf"),
            Some(u64::MAX),
        );
        assert_eq!(parse_leading_id(""), None);
        assert_eq!(parse_leading_id(":0:leaf"), None);
        assert_eq!(parse_leading_id("12"), None);
        assert_eq!(parse_leading_id("policy_12:0:leaf"), None);
        assert_eq!(parse_leading_id("18446744073709551616:0:leaf"), None,);
    }

    #[test]
    fn fresh_filter_preserves_order_values_and_malformed_passthrough() {
        let entries = vec![
            ("1:0:first".to_string(), 10),
            ("2:0:kept".to_string(), 20),
            ("malformed".to_string(), 30),
            ("1:1:second".to_string(), 40),
            ("18446744073709551616:0:overflow".to_string(), 50),
            (format!("{}:0:max", u64::MAX), 60),
        ];
        let fresh = BTreeSet::from([PolicyId(1), PolicyId(u64::MAX)]);

        assert_eq!(
            filter_out_fresh(entries, &fresh),
            vec![
                ("2:0:kept".to_string(), 20),
                ("malformed".to_string(), 30),
                ("18446744073709551616:0:overflow".to_string(), 50),
            ],
        );
    }

    #[test]
    fn empty_fresh_filter_returns_every_entry_unchanged() {
        let entries = vec![("1:0:first".to_string(), 10), ("malformed".to_string(), 20)];
        assert_eq!(filter_out_fresh(entries.clone(), &BTreeSet::new()), entries,);
    }

    const PERMIT_ALL: &str = r#"
permit (
    principal,
    action in [Test::Action::"Read", Test::Action::"Export"],
    resource
);
"#;

    fn prepared_engine() -> LocalTemporalEngine {
        let policy_schema =
            PolicySchema::from_cedarschema_str(ACTION_SCHEMA).expect("action schema builds");
        let lowered =
            LoweredPolicySet::from_str(POLICY, &ServiceSchema::defaults(), &policy_schema)
                .expect("policy lowers");
        let leaves: Vec<_> = lowered.temporal_fields().cloned().collect();
        let schema: Schema = lowered.cedar_schema().clone();
        let signatures: Vec<_> = lowered.event_signatures().collect();
        let mut engine = LocalTemporalEngine::new();
        engine
            .prepare(&leaves, &schema, &signatures)
            .expect("engine prepares");
        engine
    }

    fn store(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("dogwood_poison_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn event(action: &str, doc: &str) -> EventBuilder {
        Event::builder(&format!("Test::Action::{action}"), "request")
            .principal("Test::User::\"alice\"")
            .resource("Test::Doc::\"target\"")
            .field("input", "doc", Value::String(doc.to_string()))
            .request_context("input", "doc", Value::String(doc.to_string()))
    }

    fn allowed(engine: &mut DurableTemporalEngine, action: &str, doc: &str) -> bool {
        match engine.submit(event(action, doc)).expect("submit") {
            super::Submitted {
                outcome: Outcome::Decision(response),
                ..
            } => response.allowed(),
            other => panic!("expected a decision, got {other:?}"),
        }
    }

    fn poison_running_engine(engine: &DurableTemporalEngine) {
        let shared = engine
            .running
            .as_ref()
            .expect("installed running set")
            .engine
            .clone();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            shared.with_mut(|_| panic!("poison the live derived-state lock"));
        }));
        assert!(panic.is_err(), "the poison fixture did not panic");
        assert!(shared.with(|_| ()).is_none(), "lock was not poisoned");
    }

    #[test]
    fn unresolved_transplant_origins_are_rejected() {
        let mut engine = prepared_engine();
        let error = reject_unresolved_transplant_origins(&engine)
            .expect_err("an unset policy-id map must reject");
        assert!(
            error.to_string().contains("could not be resolved"),
            "unexpected rejection: {error}"
        );

        engine.set_policy_ids(&[PolicyId(7)]);
        reject_unresolved_transplant_origins(&engine)
            .expect("a complete policy-id map is accepted");
    }

    fn malformed_equal_total_bundle(service: &ServiceSchema) -> Installed {
        let statements =
            DurableTemporalEngine::canonicalize_source(&format!("{PERMIT_ALL}\n{POLICY}"), service)
                .expect("fixture canonicalizes");
        assert_eq!(statements.len(), 2);
        Installed {
            policies: PolicySet::from_statements(
                [
                    String::new(),
                    format!("{}\n\n{}", statements[0], statements[1]),
                ],
                0,
            ),
            action_schema: ACTION_SCHEMA.to_string(),
        }
    }

    #[test]
    fn policy_entry_alignment_rejects_equal_total_boundary_shift() {
        let service = ServiceSchema::defaults();
        let installed = malformed_equal_total_bundle(&service);
        let combined = ParsedPolicySet::parse(&installed.combined_source(), &service)
            .expect("the combined source still parses");
        assert_eq!(
            combined.policy_count(),
            installed.policies.len(),
            "the fixture must evade a total-count-only check"
        );

        let error = validate_policy_entry_alignment(&installed, &service, &combined)
            .expect_err("each structured entry must independently contain one policy");
        assert!(
            error.to_string().contains("contains 0 policies"),
            "unexpected rejection: {error}"
        );
    }

    #[test]
    fn lowered_rule_alignment_checks_count_order_and_generated_id() {
        let aligned = vec![
            DogwoodRuleRef {
                rule_index: 0,
                cedar_policy_id: "policy_0".to_string(),
            },
            DogwoodRuleRef {
                rule_index: 1,
                cedar_policy_id: "policy_1".to_string(),
            },
        ];
        validate_lowered_rule_alignment(aligned.clone(), 2)
            .expect("the documented lowering metadata is accepted");

        let count_error = validate_lowered_rule_alignment(aligned.clone(), 1)
            .expect_err("rule-count drift must reject");
        assert!(count_error.to_string().contains("2 rules for 1"));

        let mut reordered = aligned.clone();
        reordered[1].rule_index = 0;
        let order_error = validate_lowered_rule_alignment(reordered, 2)
            .expect_err("source-index drift must reject");
        assert!(order_error.to_string().contains("source index 0"));

        let mut renamed = aligned;
        renamed[1].cedar_policy_id = "changed_1".to_string();
        let id_error = validate_lowered_rule_alignment(renamed, 2)
            .expect_err("generated-id drift must reject");
        assert!(id_error.to_string().contains("changed_1"));
    }

    #[test]
    fn rebuild_rejects_entry_misalignment_before_commit() {
        let path = store("entry_alignment");
        let mut engine = DurableTemporalEngine::open(&path, 0).expect("open store");
        let installed = malformed_equal_total_bundle(&ServiceSchema::defaults());
        let original_offset = engine.log_offset();

        let error = engine
            .apply(installed, 0, None)
            .expect_err("misaligned entries must fail closed");
        assert!(
            error.to_string().contains("contains 0 policies"),
            "unexpected rejection: {error}"
        );
        assert_eq!(
            engine.log_offset(),
            original_offset,
            "a rejected rebuild must not write durable records"
        );
        assert!(
            engine.running.is_none(),
            "a rejected rebuild must not publish"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn poisoned_monitor_fails_decisions_and_checkpoints_closed_until_reopen() {
        let path = store("decision_checkpoint");
        let mut engine = DurableTemporalEngine::open(&path, 0).expect("open store");
        engine
            .install(
                &format!("{PERMIT_ALL}\n{POLICY}"),
                ACTION_SCHEMA,
                None,
                None,
            )
            .expect("install policies");
        assert!(allowed(&mut engine, "Read", "sensitive"));
        poison_running_engine(&engine);

        assert!(
            !allowed(&mut engine, "Export", "sensitive"),
            "a poisoned monitor must not permit a decision"
        );
        let next = engine.log.next_offset();
        let error = engine
            .checkpoint()
            .expect_err("checkpoint must reject poisoned derived state");
        assert!(
            error.to_string().contains("unavailable"),
            "unexpected checkpoint error: {error}"
        );
        assert_eq!(engine.log.next_offset(), next);
        assert_eq!(engine.log.base_offset(), 0);
        assert!(
            engine.log.get_snapshot().expect("read snapshot").is_none(),
            "a failed checkpoint wrote a snapshot"
        );

        drop(engine);
        let mut reopened = DurableTemporalEngine::open(&path, 0).expect("reopen store");
        assert!(
            !allowed(&mut reopened, "Export", "sensitive"),
            "replay must restore the armed history after poisoning"
        );
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn poisoned_monitor_rejects_state_carrying_policy_changes_without_mutation() {
        let path = store("policy_change");
        let mut engine = DurableTemporalEngine::open(&path, 0).expect("open store");
        engine
            .install(
                &format!("{PERMIT_ALL}\n{POLICY}"),
                ACTION_SCHEMA,
                None,
                None,
            )
            .expect("install policies");
        assert!(allowed(&mut engine, "Read", "sensitive"));
        assert!(
            !allowed(&mut engine, "Export", "sensitive"),
            "fixture history must arm the forbid"
        );
        let before_entries = engine.list();
        let before_offset = engine.log_offset();
        poison_running_engine(&engine);

        let error = engine
            .batch(vec![Verb::Add {
                policy: PERMIT_ALL.to_string(),
            }])
            .expect_err("policy change must reject unavailable source state");
        assert!(
            matches!(error, DurableError::Log(_)),
            "unexpected policy-change error: {error}"
        );
        assert_eq!(engine.log_offset(), before_offset);
        assert_eq!(engine.list(), before_entries);

        drop(engine);
        let mut reopened = DurableTemporalEngine::open(&path, 0).expect("reopen store");
        assert_eq!(reopened.list(), before_entries);
        assert!(
            !allowed(&mut reopened, "Export", "sensitive"),
            "a rejected change must leave armed history intact"
        );
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn poisoned_monitor_allows_a_reborn_all_install() {
        let path = store("reborn_all");
        let source = format!("{PERMIT_ALL}\n{POLICY}");
        let mut engine = DurableTemporalEngine::open(&path, 0).expect("open store");
        engine
            .install(&source, ACTION_SCHEMA, None, None)
            .expect("install policies");
        assert!(allowed(&mut engine, "Read", "sensitive"));
        assert!(
            !allowed(&mut engine, "Export", "sensitive"),
            "fixture history must arm the forbid"
        );
        poison_running_engine(&engine);

        let applied = engine
            .install(&source, ACTION_SCHEMA, None, None)
            .expect("reborn-all install needs no poisoned source state");
        assert_eq!(applied.leaves_retained, 0);
        assert!(
            allowed(&mut engine, "Export", "sensitive"),
            "reborn-all intentionally starts with empty history"
        );
        assert!(allowed(&mut engine, "Read", "sensitive"));
        assert!(
            !allowed(&mut engine, "Export", "sensitive"),
            "the replacement monitor must accumulate new history"
        );

        drop(engine);
        let _ = std::fs::remove_file(path);
    }
}
