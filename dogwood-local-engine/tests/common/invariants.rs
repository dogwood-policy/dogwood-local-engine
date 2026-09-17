//! The store's safety invariants, as first-class shared checks.
//!
//! Every test that examines a recovered store — a hand-written crash case, the
//! crash sweep, later the concurrency tests — calls *these* functions rather than
//! re-deriving assertions inline. When the retention rules change, they change in
//! one place.
//!
//! # Two inputs, because half of every invariant is not in the store
//!
//! [`LogFacts`] is what the store shows. [`Promises`](super::workload::Promises)
//! is what the caller was *told*, which no store records: only the test knows
//! that a client received `Ok` for a given offset. Every check here relates the
//! two, and `super::workload::Recorder` maintains the second half.
//!
//! # What is deliberately *not* an invariant
//!
//! Write these down, or a later reader adds a check that fails on correct
//! behaviour:
//!
//! * **Un-acknowledged records may survive.** A crash between the commit and the
//!   response leaves a durable record nobody was told about. That is at-least-once
//!   delivery, not corruption.
//! * **An acknowledged record may be gone.** The obligation is on the *effect*: a
//!   checkpoint may reclaim a record whose state a durable snapshot folded in.
//! * **Timestamp gaps are fine.** Only strict increase and tracking real time
//!   matter; the sequence is not dense.
//! * **An empty log is fine.** A prune may reclaim everything.
//! * **Refusing to open is fine** — required, in fact — for a store whose history
//!   is truncated beyond repair, so long as nothing was acknowledged from it.
//!
//! # What [`watermarks_ordered`] assumes about who prunes
//!
//! [`watermarks_ordered`] requires `base_offset <= snapshot.up_to_offset`:
//! pruning past what a snapshot summarizes leaves records neither present nor
//! folded in, which is unrecoverable. That holds for [`DurableTemporalEngine`],
//! whose *only* justification for pruning the log is a checkpoint — it snapshots
//! at `next_offset`, then prunes below it, so the watermark never overtakes the
//! snapshot. It is a property of that log-management discipline, which is why it
//! is checked here against the durable engine.
//!
//! It is a different thing from the window-pruning inside `LocalTemporalEngine`
//! (`DESIGN.md` §6.2), which drops *events from a monitor's in-memory trace* once
//! they fall outside every operator's lookback, with no snapshot involved. That
//! pruning never touches the durable log's offsets, so this invariant neither
//! constrains nor describes it.

#![allow(dead_code)] // Each consuming test uses a subset.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dogwood_local_engine::{DurableLog, DurableTemporalEngine, Record};

use super::workload::Promises;

// ---------------------------------------------------------------------------
// Input 1: what the store shows
// ---------------------------------------------------------------------------

/// Everything the invariants read from a store, collected in one pass.
///
/// A plain struct rather than a `&DurableLog` for one reason above all: a corrupt
/// state can be *constructed*. Making a real store satisfy `base > next` takes
/// the specific prune-then-append sequence that was once a bug; making a
/// `LogFacts` satisfy it takes one line, which is how each check below is shown
/// to detect its own violation rather than merely to pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogFacts {
    /// The prune watermark: no record below this survives.
    pub base_offset: u64,
    /// Where the next append will land.
    pub next_offset: u64,
    /// `up_to_offset` of the durable snapshot, if any. Recovery replays records
    /// at or above it, so it summarizes everything strictly below.
    pub snapshot_up_to: Option<u64>,
    /// Surviving records as `(offset, timestamp, is_event)`, in offset order.
    /// `is_event` distinguishes an ingested event from a policy verb record —
    /// events must have strictly-increasing timestamps (windows are measured
    /// against them), while a batch's policy records share one instant (§2.5).
    pub records: Vec<(u64, i64, bool)>,
}

impl LogFacts {
    /// Read the facts from a store. An undecodable record is itself a violation,
    /// so it is an error here — ahead of every check — rather than a skipped
    /// entry that each check would have to reason about separately.
    pub fn read(log: &DurableLog) -> Result<Self, String> {
        let mut records = Vec::new();
        let mut bad: Option<String> = None;
        log.scan_from(log.base_offset(), |offset, bytes| {
            if bad.is_some() {
                return;
            }
            match Record::decode(bytes) {
                Ok(r) => {
                    let is_event = matches!(r, Record::Event(_));
                    records.push((offset, r.timestamp(), is_event));
                }
                Err(e) => bad = Some(format!("record at offset {offset} does not decode: {e}")),
            }
        })
        .map_err(|e| e.to_string())?;
        if let Some(e) = bad {
            return Err(e);
        }
        Ok(LogFacts {
            base_offset: log.base_offset(),
            next_offset: log.next_offset(),
            snapshot_up_to: log
                .get_snapshot()
                .map_err(|e| e.to_string())?
                .map(|s| s.up_to_offset),
            records,
        })
    }

    /// Whether a store in this state is recoverable at all: history below
    /// `base_offset` is gone, so something must account for it.
    pub fn is_recoverable(&self) -> bool {
        self.base_offset == 0
            || self
                .snapshot_up_to
                .is_some_and(|up_to| up_to >= self.base_offset)
    }
}

// ---------------------------------------------------------------------------
// Violations
// ---------------------------------------------------------------------------

/// A violated invariant, with a reason a failing test can print as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// `base_offset` exceeds `next_offset` — the counter restarted behind the
    /// watermark, so appends land where recovery will not look.
    BaseAboveNext { base: u64, next: u64 },
    /// A snapshot claims to summarize past the end of the log. Defensive:
    /// `DurableLog::commit` already rejects this at write time.
    SnapshotBeyondNext { up_to: u64, next: u64 },
    /// Records were reclaimed past what the snapshot folded in, so they are
    /// neither present nor summarized.
    PrunedPastSnapshot { base: u64, up_to: u64 },
    /// An offset in `[base_offset, next_offset)` has no record. Impossible from a
    /// crash alone: `append` writes the record and the new `next_offset` in one
    /// transaction, so both survive or neither does.
    Hole { offset: u64 },
    /// A record exists at or beyond `next_offset`, so the next append would
    /// reissue an offset already in use.
    RecordBeyondNext { offset: u64, next: u64 },
    /// Timestamps do not strictly increase with offset. One critical section
    /// assigns both, so a decrease means the monotonicity clamp broke.
    TimestampNotIncreasing {
        offset: u64,
        timestamp: i64,
        previous: i64,
    },
    /// A timestamp lies outside the wall-clock interval the workload ran in. The
    /// sequence must track real time, not merely ascend — the clamp
    /// `max(now, last + 1)` at too coarse a resolution keeps ascending while
    /// running away from the clock, which silently redefines every window.
    TimestampOffWallClock {
        offset: u64,
        timestamp: i64,
        lower: i64,
        upper: i64,
    },
    /// A client was told about an offset that recovery neither has nor has folded
    /// into a snapshot. Acknowledged, then lost.
    AckedLost {
        offset: u64,
        base: u64,
        snapshot_up_to: Option<u64>,
    },
    /// Recovery opened a store whose history is truncated beyond repair. Serving
    /// from it means deciding against a hole — a history-gated `forbid` with no
    /// history simply passes.
    OpenedUnrecoverable {
        base: u64,
        snapshot_up_to: Option<u64>,
    },
    /// Recovery refused, which is right for an unrecoverable store — but offsets
    /// had been acknowledged from it, so the acknowledgements were premature.
    RefusedWithAckedWork { acked: Vec<u64>, reason: String },
    /// Recovery lost the installed policy that an `apply` had acknowledged.
    PolicyLost { expected_len: usize },
    /// Recovery came up under a different policy than the last one acknowledged.
    PolicyChanged,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Violation::BaseAboveNext { base, next } => write!(
                f,
                "base_offset {base} exceeds next_offset {next}: appends would land \
                 below the watermark recovery starts from, so their history would \
                 be durable and invisible"
            ),
            Violation::SnapshotBeyondNext { up_to, next } => write!(
                f,
                "snapshot summarizes up to {up_to} but the log ends at {next}; \
                 recovery starting there would skip records that exist"
            ),
            Violation::PrunedPastSnapshot { base, up_to } => write!(
                f,
                "log was pruned to {base} but the snapshot only summarizes below \
                 {up_to}; records in [{up_to}, {base}) are neither present nor \
                 folded in, so their history is unrecoverable"
            ),
            Violation::Hole { offset } => write!(
                f,
                "no record at offset {offset}, which is inside [base, next); \
                 append writes the record and next_offset in one transaction, so \
                 a hole cannot arise from a crash alone"
            ),
            Violation::RecordBeyondNext { offset, next } => write!(
                f,
                "record at offset {offset} is at or beyond next_offset {next}; \
                 the next append would reissue an offset already in use"
            ),
            Violation::TimestampNotIncreasing {
                offset,
                timestamp,
                previous,
            } => write!(
                f,
                "record at offset {offset} has timestamp {timestamp}, not above \
                 its predecessor's {previous}; windows are measured against this \
                 sequence, so it must strictly increase"
            ),
            Violation::TimestampOffWallClock {
                offset,
                timestamp,
                lower,
                upper,
            } => write!(
                f,
                "record at offset {offset} has timestamp {timestamp}, outside the \
                 [{lower}, {upper}] the workload actually ran in; the sequence has \
                 stopped tracking real time, so a declared window no longer means \
                 what it says"
            ),
            Violation::AckedLost {
                offset,
                base,
                snapshot_up_to,
            } => write!(
                f,
                "offset {offset} was acknowledged to a client but is absent after \
                 recovery: the log starts at {base} and the snapshot summarizes \
                 below {}",
                match snapshot_up_to {
                    Some(u) => u.to_string(),
                    None => "(no snapshot)".to_string(),
                }
            ),
            Violation::OpenedUnrecoverable {
                base,
                snapshot_up_to,
            } => write!(
                f,
                "recovery opened a store pruned to {base} with snapshot coverage \
                 {}; it must refuse rather than serve against a hole, since a \
                 history-gated `forbid` with no history passes",
                match snapshot_up_to {
                    Some(u) => u.to_string(),
                    None => "(none)".to_string(),
                }
            ),
            Violation::RefusedWithAckedWork { acked, reason } => write!(
                f,
                "recovery refused to open ({reason}) but {} offset(s) had been \
                 acknowledged: {acked:?}",
                acked.len()
            ),
            Violation::PolicyLost { expected_len } => write!(
                f,
                "no policy after recovery, but an apply of a {expected_len}-byte \
                 policy had been acknowledged"
            ),
            Violation::PolicyChanged => write!(
                f,
                "recovery came up under a different policy than the last one \
                 acknowledged"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Group A: log shape
// ---------------------------------------------------------------------------

/// `base_offset <= snapshot.up_to_offset <= next_offset`.
///
/// # Errors
/// [`Violation::BaseAboveNext`], [`Violation::SnapshotBeyondNext`], or
/// [`Violation::PrunedPastSnapshot`].
pub fn watermarks_ordered(f: &LogFacts) -> Result<(), Violation> {
    if f.base_offset > f.next_offset {
        return Err(Violation::BaseAboveNext {
            base: f.base_offset,
            next: f.next_offset,
        });
    }
    if let Some(up_to) = f.snapshot_up_to {
        if up_to > f.next_offset {
            return Err(Violation::SnapshotBeyondNext {
                up_to,
                next: f.next_offset,
            });
        }
        if f.base_offset > up_to {
            return Err(Violation::PrunedPastSnapshot {
                base: f.base_offset,
                up_to,
            });
        }
    }
    Ok(())
}

/// Every offset in `[base_offset, next_offset)` has a record, and none exists at
/// or beyond `next_offset`.
///
/// # Errors
/// [`Violation::RecordBeyondNext`] or [`Violation::Hole`].
pub fn records_dense(f: &LogFacts) -> Result<(), Violation> {
    for &(offset, _, _) in &f.records {
        if offset >= f.next_offset {
            return Err(Violation::RecordBeyondNext {
                offset,
                next: f.next_offset,
            });
        }
    }
    let present: std::collections::BTreeSet<u64> = f.records.iter().map(|&(o, _, _)| o).collect();
    for offset in f.base_offset..f.next_offset {
        if !present.contains(&offset) {
            return Err(Violation::Hole { offset });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Group D: time
// ---------------------------------------------------------------------------

/// Timestamps never fall, and strictly increase across events.
///
/// A decrease is always a violation. A **tie** is allowed only between two policy
/// records: a batch is one atomic instant ("sequential in meaning, transactional
/// in effect", §2.5), so its verb records share a timestamp and their order is
/// carried by the log offset, not the timestamp. Events must still strictly
/// increase — windows are measured against the event sequence — so any tie or
/// drop involving an event is a violation.
///
/// Necessary but weak on its own: the whole-second bug maintained strict increase
/// while running a second ahead per event. [`timestamps_track_wall_clock`] is what
/// catches that.
///
/// # Errors
/// [`Violation::TimestampNotIncreasing`].
pub fn timestamps_increase(f: &LogFacts) -> Result<(), Violation> {
    let mut previous: Option<(i64, bool)> = None; // (timestamp, is_event)
    for &(offset, timestamp, is_event) in &f.records {
        if let Some((prev_ts, prev_event)) = previous {
            let dropped = timestamp < prev_ts;
            let event_tie = timestamp == prev_ts && (is_event || prev_event);
            if dropped || event_tie {
                return Err(Violation::TimestampNotIncreasing {
                    offset,
                    timestamp,
                    previous: prev_ts,
                });
            }
        }
        previous = Some((timestamp, is_event));
    }
    Ok(())
}

/// Every timestamp lies within the wall-clock interval the workload ran in.
///
/// `slack` absorbs a slow host and the clamp's `last + 1` nudges; it must stay
/// far below the shortest window any policy declares, or the check stops meaning
/// anything. A second is ample here — the bug this exists for put twelve events
/// eleven *seconds* apart inside 0.108s of real time.
///
/// # Errors
/// [`Violation::TimestampOffWallClock`].
pub fn timestamps_track_wall_clock(
    f: &LogFacts,
    promises: &Promises,
    slack: Duration,
) -> Result<(), Violation> {
    let nanos = |t: SystemTime| -> i64 {
        t.duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    };
    let slack = i64::try_from(slack.as_nanos()).unwrap_or(i64::MAX);
    let lower = nanos(promises.started).saturating_sub(slack);
    let upper = nanos(promises.finished).saturating_add(slack);
    for &(offset, timestamp, _) in &f.records {
        if timestamp < lower || timestamp > upper {
            return Err(Violation::TimestampOffWallClock {
                offset,
                timestamp,
                lower,
                upper,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Group B: the durability obligation
// ---------------------------------------------------------------------------

/// Every acknowledged offset is still present, or folded into a durable
/// snapshot.
///
/// # Errors
/// [`Violation::AckedLost`].
pub fn acked_survive(f: &LogFacts, promises: &Promises) -> Result<(), Violation> {
    for offset in promises.acked_event_offsets() {
        let present = offset >= f.base_offset && offset < f.next_offset;
        let folded = f.snapshot_up_to.is_some_and(|up_to| offset < up_to);
        if !present && !folded {
            return Err(Violation::AckedLost {
                offset,
                base: f.base_offset,
                snapshot_up_to: f.snapshot_up_to,
            });
        }
    }
    Ok(())
}

/// Recovery refuses exactly when it must: it opens no unrecoverable store, and
/// it refuses none from which work was acknowledged.
///
/// # Errors
/// [`Violation::OpenedUnrecoverable`] or [`Violation::RefusedWithAckedWork`].
pub fn refuses_exactly_when_it_must<E: std::fmt::Display>(
    f: &LogFacts,
    recovered: Result<&DurableTemporalEngine, E>,
    promises: &Promises,
) -> Result<(), Violation> {
    match recovered {
        Ok(_) if !f.is_recoverable() => Err(Violation::OpenedUnrecoverable {
            base: f.base_offset,
            snapshot_up_to: f.snapshot_up_to,
        }),
        Ok(_) => Ok(()),
        Err(reason) if promises.acked_event_offsets().is_empty() => {
            let _ = reason;
            Ok(())
        }
        Err(reason) => Err(Violation::RefusedWithAckedWork {
            acked: promises.acked_event_offsets(),
            reason: reason.to_string(),
        }),
    }
}

/// The policy an acknowledged `apply` installed is the policy that comes back.
///
/// # Errors
/// [`Violation::PolicyLost`] or [`Violation::PolicyChanged`].
pub fn policy_survives(
    state: &DurableTemporalEngine,
    promises: &Promises,
) -> Result<(), Violation> {
    let Some(expected) = promises.last_policy() else {
        return Ok(());
    };
    match state.policy_source() {
        None => Err(Violation::PolicyLost {
            expected_len: expected.combined_source().len(),
        }),
        Some(actual) if actual != expected.combined_source() => Err(Violation::PolicyChanged),
        Some(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Every invariant computable from the store alone plus what was promised.
///
/// Ordered most-structural first, so the reported violation is the most
/// fundamental one present rather than a downstream symptom.
///
/// # Errors
/// The first [`Violation`] found.
pub fn check_all(f: &LogFacts, promises: &Promises) -> Result<(), Violation> {
    watermarks_ordered(f)?;
    records_dense(f)?;
    timestamps_increase(f)?;
    timestamps_track_wall_clock(f, promises, Duration::from_secs(1))?;
    acked_survive(f, promises)?;
    Ok(())
}

/// [`check_all`], panicking with the violation's own message.
#[track_caller]
pub fn assert_all(f: &LogFacts, promises: &Promises) {
    if let Err(v) = check_all(f, promises) {
        panic!("{v}");
    }
}

/// The whole obligation on one crash-and-recover cycle: what survived, what
/// recovery did about it — including refusing — and what was owed.
///
/// # Errors
/// The first [`Violation`] found.
pub fn check_cycle<E: std::fmt::Display>(
    frozen: &LogFacts,
    recovered: Result<&DurableTemporalEngine, E>,
    promises: &Promises,
) -> Result<(), Violation> {
    check_all(frozen, promises)?;
    let opened = recovered.as_ref().ok().copied();
    refuses_exactly_when_it_must(frozen, recovered, promises)?;
    if let Some(state) = opened {
        policy_survives(state, promises)?;
    }
    Ok(())
}

/// [`check_cycle`], panicking with the violation's own message.
#[track_caller]
pub fn assert_cycle<E: std::fmt::Display>(
    frozen: &LogFacts,
    recovered: Result<&DurableTemporalEngine, E>,
    promises: &Promises,
) {
    if let Err(v) = check_cycle(frozen, recovered, promises) {
        panic!("{v}");
    }
}
