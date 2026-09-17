//! Deterministic crash and storage-failure points for durability tests.
//!
//! This module exists only with the `fault-injection` feature. Enabling the
//! feature does nothing by itself: a test must install and arm a
//! [`FaultInjector`]. Production builds use no default features, so neither the
//! controller nor its hook calls are present.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// A logical point at which a durability test may pause the calling thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    /// An append transaction contains its record and next offset but has not
    /// committed.
    AppendBeforeCommit,
    /// The append is durable, but the in-memory offset and caller have not been
    /// updated.
    AppendAfterCommit,
    /// A multi-write transaction contains all requested writes but has not
    /// committed.
    CommitBeforeCommit,
    /// A multi-write transaction is durable, but its caller has not resumed.
    CommitAfterCommit,
    /// An event has been persisted and evaluated, but `submit` has not returned.
    SubmitBeforeAcknowledge,
    /// A checkpoint is durable but pruning has not begun.
    CheckpointBeforePrune,
    /// A bounded prune transaction contains its deletions and new base offset
    /// but has not committed.
    PruneBeforeCommit,
    /// A complete bounded prune transaction is durable, but its in-memory base
    /// offset has not been updated.
    PruneAfterCommit,
}

/// A transaction boundary at which a test may return a synthetic storage error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailurePoint {
    /// The complete multi-write transaction has been staged but not committed.
    CommitBeforeCommit,
    /// The bounded chunk has been staged but its transaction has not committed.
    /// Returning here must abort the complete chunk.
    PruneBeforeCommit,
    /// The bounded chunk has committed, but its in-memory watermark has not
    /// been published. This models an ambiguous commit result.
    PruneAfterCommit,
}

#[derive(Debug, Clone, Copy)]
struct ArmedFailure {
    point: StorageFailurePoint,
    remaining_occurrences: usize,
}

#[derive(Debug, Default)]
struct State {
    armed: Option<FaultPoint>,
    failure: Option<ArmedFailure>,
    reached: bool,
    released: bool,
}

/// One-shot controller shared by the durable engine and its log.
///
/// A crash test uses [`arm`](Self::arm) to pause an operation and either kills
/// the process or calls [`release`](Self::release). A storage-failure test uses
/// [`fail_on`](Self::fail_on) to make a selected bounded-prune occurrence return
/// an error without blocking.
#[derive(Debug, Default)]
pub struct FaultInjector {
    state: Mutex<State>,
    changed: Condvar,
}

impl FaultInjector {
    /// Construct a disarmed controller.
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm one crash point.
    ///
    /// A controller is intentionally one-shot. Use a fresh instance for each
    /// crash process so an old release cannot let a later operation escape.
    pub fn arm(&self, point: FaultPoint) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            state.armed.is_none() && state.failure.is_none() && !state.reached,
            "fault injector was already used"
        );
        state.armed = Some(point);
    }

    /// Return a synthetic storage error on the selected one-based occurrence.
    ///
    /// Selecting a later occurrence allows a multi-chunk prune to make durable
    /// progress before failing. A controller remains one-shot: use a fresh
    /// instance for each failure scenario.
    pub fn fail_on(&self, point: StorageFailurePoint, occurrence: usize) {
        assert!(occurrence > 0, "failure occurrence must be one-based");
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            state.armed.is_none() && state.failure.is_none() && !state.reached,
            "fault injector was already used"
        );
        state.failure = Some(ArmedFailure {
            point,
            remaining_occurrences: occurrence,
        });
    }

    /// Wait until an armed crash point is blocked, returning `false` on timeout.
    pub fn wait_until_reached(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        while !state.reached {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, result) = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|error| error.into_inner());
            state = next;
            if result.timed_out() && !state.reached {
                return false;
            }
        }
        true
    }

    /// Resume an operation paused at the armed point.
    pub fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.released = true;
        self.changed.notify_all();
    }

    pub(crate) fn reach(&self, point: FaultPoint) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.armed != Some(point) {
            return;
        }

        state.armed = None;
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    pub(crate) fn should_fail(&self, point: StorageFailurePoint) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Some(mut failure) = state.failure else {
            return false;
        };
        if failure.point != point {
            return false;
        }
        failure.remaining_occurrences -= 1;
        if failure.remaining_occurrences > 0 {
            state.failure = Some(failure);
            return false;
        }

        state.failure = None;
        state.reached = true;
        self.changed.notify_all();
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn armed_point_blocks_until_released() {
        let faults = Arc::new(FaultInjector::new());
        faults.arm(FaultPoint::AppendBeforeCommit);

        let worker_faults = Arc::clone(&faults);
        let worker = std::thread::spawn(move || {
            worker_faults.reach(FaultPoint::AppendBeforeCommit);
        });

        assert!(faults.wait_until_reached(Duration::from_secs(1)));
        assert!(!worker.is_finished());
        faults.release();
        worker.join().expect("released worker exits");
    }

    #[test]
    fn unarmed_point_does_not_block() {
        let faults = FaultInjector::new();
        faults.reach(FaultPoint::CommitBeforeCommit);
        assert!(!faults.wait_until_reached(Duration::from_millis(1)));
    }

    #[test]
    fn storage_failure_fires_only_on_the_selected_occurrence() {
        let faults = FaultInjector::new();
        faults.fail_on(StorageFailurePoint::PruneBeforeCommit, 2);
        assert!(!faults.should_fail(StorageFailurePoint::PruneBeforeCommit));
        assert!(faults.should_fail(StorageFailurePoint::PruneBeforeCommit));
        assert!(!faults.should_fail(StorageFailurePoint::PruneBeforeCommit));
        assert!(faults.wait_until_reached(Duration::from_millis(1)));
    }
}
