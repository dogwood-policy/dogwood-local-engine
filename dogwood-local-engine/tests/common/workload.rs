//! What a test *did* to the server, recorded as the server linearized it.
//!
//! This is the half of every check that no store holds: only the harness knows
//! which operations were acknowledged, in what order, and what the server said
//! about them. [`invariants`](super::invariants) reads it to state the durability
//! obligation; [`oracle`](super::oracle) replays it through the reference
//! interpreter.
//!
//! # Driven through the production surface
//!
//! The harness drives the engine only through [`install`](Recorder::install)
//! (declarative whole-set replace) and [`batch`](Recorder::batch) (verb batch)
//! — the same entry points a deployment uses. So the differential exercises the
//! real `(policy id, clause index)` transplant, not the content-key fallback a
//! hand-built `Installed` blob would take.
//!
//! # Why retention is still typed
//!
//! Each policy change records a [`Retention`] class, because it is what keeps a
//! workload inside the oracle's domain: a single reference interpreter has one
//! shared history, so it can model "every leaf kept its window" or "every leaf
//! starts empty", but not a mixture. Leaves acquire different history start
//! points **iff** some change kept some leaves while resetting others, so making
//! mixed changes declare themselves is exactly sufficient (see `oracle`). Unlike
//! before, the caller *states* the retention (it issued the verbs and knows it);
//! the engine no longer infers it from a content diff.

#![allow(dead_code)] // Each consuming test uses a subset.

use std::time::SystemTime;

use dogwood_language::EventBuilder;
use dogwood_local_engine::{
    Applied, BatchResult, DurableError, DurableTemporalEngine, Installed, Outcome, PolicySet,
    Submitted, Verb,
};

/// What a policy change does to existing leaves — stated by the caller (which
/// issued the verbs), and the fact the oracle needs to pick the reference's
/// single history start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Every leaf keeps its accumulated window.
    AllKept,
    /// Every leaf starts empty.
    AllReset,
    /// Some kept, some reset — outside the oracle's domain, deliberately.
    Mixed,
}

/// One acknowledged operation, in the order the server linearized it.
///
/// Ordering is by `ts` alone and that is sound: `next_timestamp` is shared by
/// `submit` and every policy verb, so every record draws from one strictly
/// increasing sequence.
#[derive(Debug, Clone)]
pub enum Op {
    /// A policy change the server acknowledged.
    ///
    /// A change is a *contiguous range* of durable records
    /// (`POLICY_INSTALL_SEMANTICS.md` §2.6), so it names its boundary offset
    /// (`offset`, the tail) **and** the head (`first_offset`) — the oracle's
    /// quiescence check accounts for every record the change committed rather
    /// than pretending it cost one offset.
    Applied {
        ts: i64,
        offset: u64,
        first_offset: u64,
        /// The resulting policy set in force, as a **reference-only** carrier of
        /// its combined source + action schema: the oracle re-lowers this to
        /// build the reference interpreter. It is *not* fed back to the engine
        /// (the engine got the real split set through `install`/`batch`), so its
        /// internal entry shape does not matter.
        policy: Installed,
        /// What the change did to existing leaves.
        retention: Retention,
    },
    /// An event the server acknowledged.
    Submitted {
        ts: i64,
        offset: u64,
        /// The event as an **un-timestamped** builder — the engine assigned the
        /// timestamp (recorded in `ts`). The oracle re-stamps this at the
        /// reference interpreter's resolution when it replays the history.
        event: EventBuilder,
        /// The verdict the **live** server gave, if this was a decision event.
        ///
        /// Kept so a later disagreement can be attributed. If live already
        /// disagreed with the reference, recovery is not the culprit and the
        /// investigation belongs on the evaluation path instead — two completely
        /// different places to look.
        live: Option<bool>,
    },
}

impl Op {
    pub fn ts(&self) -> i64 {
        match self {
            Op::Applied { ts, .. } | Op::Submitted { ts, .. } => *ts,
        }
    }
}

/// The operations a workload performed and what it was promised.
#[derive(Debug, Clone)]
pub struct Promises {
    /// Every acknowledged operation, in linearization order.
    pub ops: Vec<Op>,
    /// Wall clock when the workload began.
    pub started: SystemTime,
    /// Wall clock when it stopped.
    pub finished: SystemTime,
}

impl Default for Promises {
    fn default() -> Self {
        let now = SystemTime::now();
        Promises {
            ops: Vec::new(),
            started: now,
            finished: now,
        }
    }
}

impl Promises {
    /// Nothing was promised, so nothing is owed.
    pub fn none() -> Self {
        Self::default()
    }

    /// Offsets of acknowledged *events* — the durability obligation.
    ///
    /// Policy changes are excluded deliberately: their records may be reclaimed
    /// by a checkpoint like any other, and the resulting set is recovered from
    /// the snapshot that names it, so their offsets carry no separate obligation.
    pub fn acked_event_offsets(&self) -> Vec<u64> {
        self.ops
            .iter()
            .filter_map(|op| match op {
                Op::Submitted { offset, .. } => Some(*offset),
                Op::Applied { .. } => None,
            })
            .collect()
    }

    /// The last policy set a change acknowledged, if any.
    pub fn last_policy(&self) -> Option<&Installed> {
        self.ops.iter().rev().find_map(|op| match op {
            Op::Applied { policy, .. } => Some(policy),
            Op::Submitted { .. } => None,
        })
    }
}

/// A reference-only snapshot of the running set: its combined source in one
/// entry, plus the action schema. The oracle re-lowers `combined_source()`, so
/// the entry shape is irrelevant — this never returns to the engine.
fn running_policy(state: &DurableTemporalEngine) -> Installed {
    Installed {
        policies: PolicySet::from_statements([state.policy_source().unwrap_or_default()], 0),
        action_schema: state.action_schema().unwrap_or_default(),
    }
}

/// Drives a [`DurableTemporalEngine`] while recording what it was told.
///
/// The recording is deliberately narrow: an operation is remembered **only** when
/// it returned `Ok`. A failed call creates no obligation — and that makes the
/// harness self-verifying, since a `submit` that acknowledged an event it had not
/// appended shows up as an acknowledged offset recovery cannot account for.
pub struct Recorder {
    state: DurableTemporalEngine,
    promises: Promises,
}

impl Recorder {
    pub fn new(state: DurableTemporalEngine) -> Self {
        Recorder {
            state,
            promises: Promises::default(),
        }
    }

    pub fn state(&mut self) -> &mut DurableTemporalEngine {
        &mut self.state
    }

    /// Install a whole policy set from source, replacing whatever is running —
    /// the declarative path, which is **reborn-all**: every leaf starts empty
    /// (`Retention::AllReset`). Records the change for the oracle.
    #[track_caller]
    pub fn install(&mut self, source: &str, action_schema: &str) -> Result<Applied, DurableError> {
        let applied = self.state.install(source, action_schema, None, None)?;
        assert_eq!(
            applied.leaves_retained, 0,
            "install is a declarative replace: every leaf must start fresh, but \
             the server kept {} of {}",
            applied.leaves_retained, applied.leaf_count,
        );
        self.promises.ops.push(Op::Applied {
            ts: applied.ts,
            offset: applied.offset,
            first_offset: applied.first_offset,
            policy: running_policy(&self.state),
            retention: Retention::AllReset,
        });
        Ok(applied)
    }

    /// Apply a verb batch, and record it under the retention the caller states.
    ///
    /// The caller knows the retention because it issued the verbs (`SetActionSchema`
    /// / a no-op-to-existing `Add` keeps all; `ResetAll` / a full `[DeleteAll; Add
    /// …]` resets all; adding a *temporal* leaf while keeping others is `Mixed`).
    /// `batch` returns only the minted ids and a timestamp, so the record's offset
    /// range is read from the log's advance across the call.
    #[track_caller]
    pub fn batch(
        &mut self,
        verbs: Vec<Verb>,
        retention: Retention,
    ) -> Result<BatchResult, DurableError> {
        let first_offset = self.state.log_offset();
        let result = self.state.batch(verbs)?;
        let offset = self.state.log_offset().saturating_sub(1);
        self.promises.ops.push(Op::Applied {
            ts: result.ts,
            offset,
            first_offset,
            policy: running_policy(&self.state),
            retention,
        });
        Ok(result)
    }

    pub fn submit(&mut self, event: EventBuilder) -> Result<Submitted, DurableError> {
        // Stash the un-timestamped builder before the engine consumes it: the
        // engine assigns the timestamp on `submit`, and the oracle re-stamps this
        // copy at the reference interpreter's resolution when it replays.
        let recorded = event.clone();
        let result = self.state.submit(event);
        if let Ok(s) = &result {
            self.promises.ops.push(Op::Submitted {
                ts: s.ts,
                offset: s.offset,
                event: recorded,
                live: match &s.outcome {
                    Outcome::Decision(r) => Some(r.allowed()),
                    Outcome::Recorded => None,
                },
            });
        }
        result
    }

    pub fn checkpoint(&mut self) -> Result<u64, DurableError> {
        self.state.checkpoint()
    }

    /// Stop the clock and hand back what was promised, dropping the state — the
    /// caller's next act is to recover, and holding the old state open would keep
    /// the store's file lock.
    pub fn finish(mut self) -> Promises {
        self.promises.finished = SystemTime::now();
        self.promises
    }
}
