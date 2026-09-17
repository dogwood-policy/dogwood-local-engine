//! [`SharedEngine`] — a [`TemporalEngine`] the server can still reach after
//! handing it to an [`Authorizer`][dogwood_language::Authorizer].
//!
//! # The problem
//!
//! `AuthorizerBuilder::temporal_engine` takes the engine **by value** and stores
//! it as a private `Box<dyn TemporalEngine>`. That is the right library API: a
//! caller must not be able to reach into a running authorizer and mutate the
//! monitor out from under a decision. But the server needs one thing from the
//! engine that the authorizer will never ask for — to *read* its derived state
//! for a snapshot (`DESIGN.md` §6.3) and its keyed state for a policy change
//! (§9.1).
//!
//! # The approach
//!
//! Wrap the engine in an `Arc<Mutex<…>>` and give the authorizer a handle rather
//! than the engine. Both the authorizer and the server hold clones of the same
//! handle, so the server can snapshot without the frontend growing an accessor
//! that would let *any* consumer mutate a live monitor.
//!
//! This adds no locking beyond what §3.3 already requires. The caller serializes
//! every `submit` behind its own lock (the "one caller-held mutex" model of
//! [`DurableTemporalEngine`](crate::DurableTemporalEngine)), so this mutex is
//! never contended on the decision path; it exists to make the shared ownership
//! sound, not to coordinate concurrency. Contention would only arise from a
//! concurrent checkpoint, which is exactly the case where waiting is correct.
//!
//! Reentrancy is the one hazard: the authorizer calls `observe`/`evaluate`, each
//! of which takes the lock, so the holder must never keep it across
//! `is_authorized`. It does not — [`crate::DurableTemporalEngine::submit`] lets
//! the authorizer take it and only reacquires after the decision returns.

use std::sync::Arc;

use dogwood_language::cedar::Schema;
use dogwood_language::{
    Error, Event, EventSignature, TemporalBindings, TemporalEngine, TemporalField,
};

use crate::LocalTemporalEngine;
use crate::sync::Mutex;

/// A shared handle to a [`LocalTemporalEngine`]. Cheap to clone; all clones name
/// the same engine.
#[derive(Clone)]
pub struct SharedEngine {
    inner: Arc<Mutex<LocalTemporalEngine>>,
}

impl SharedEngine {
    /// Wrap a prepared (or unprepared) engine in a shared handle.
    pub fn new(engine: LocalTemporalEngine) -> Self {
        SharedEngine {
            inner: Arc::new(Mutex::new(engine)),
        }
    }

    /// Run `f` against the engine.
    ///
    /// A poisoned mutex means a previous holder panicked mid-operation, so the
    /// monitor's state may be torn. The state is *derived* (`DESIGN.md` §3), so
    /// the recovery for that is to rebuild from the log — never to read the torn
    /// state as if it were sound. Hence `None` rather than `unwrap()`: callers
    /// treat it as "no state available", which for a snapshot means skip and for
    /// a decision means fail closed.
    pub fn with<R>(&self, f: impl FnOnce(&LocalTemporalEngine) -> R) -> Option<R> {
        self.inner.lock().ok().map(|guard| f(&guard))
    }

    /// Run `f` against the engine mutably.
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut LocalTemporalEngine) -> R) -> Option<R> {
        self.inner.lock().ok().map(|mut guard| f(&mut guard))
    }
}

impl TemporalEngine for SharedEngine {
    fn prepare(
        &mut self,
        leaves: &[TemporalField],
        schema: &Schema,
        events: &[EventSignature],
    ) -> Result<(), Error> {
        // The server prepares the engine before wrapping it, so this call (made
        // by `AuthorizerBuilder::build`) is the second one for the same leaves.
        // `LocalTemporalEngine::prepare` rebuilds the monitors from scratch,
        // which would DISCARD the state the server just transplanted — so
        // re-preparing here would silently reset every rule's window on every
        // policy apply, the exact §9.1 bug. Report success without touching the
        // engine; the leaves are already installed and identical.
        let _ = (leaves, schema, events);
        Ok(())
    }

    fn observe(&mut self, event: &Event) {
        // A poisoned lock drops the event rather than panicking the connection.
        // The event is already durable in the log at this point (the server
        // appends first), so recovery replays it — the in-memory miss is
        // repaired by a restart, and meanwhile decisions fail closed because the
        // window is short, not because it is wrong.
        let _ = self.with_mut(|engine| engine.observe(event));
    }

    fn evaluate(&mut self) -> Result<TemporalBindings, String> {
        self.with_mut(|engine| engine.evaluate())
            .unwrap_or_else(|| Err("temporal engine unavailable (poisoned)".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use dogwood_language::TemporalEngine;

    use super::SharedEngine;
    use crate::LocalTemporalEngine;

    #[test]
    fn poisoned_engine_state_is_never_exposed() {
        let shared = SharedEngine::new(LocalTemporalEngine::new());
        let poisoner = shared.clone();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            poisoner.with_mut(|_| panic!("poison the derived-state lock"));
        }));
        assert!(panic.is_err(), "the poison fixture did not panic");

        assert!(
            shared.with(|_| ()).is_none(),
            "immutable access exposed poisoned state"
        );
        assert!(
            shared.with_mut(|_| ()).is_none(),
            "mutable access exposed poisoned state"
        );

        let mut temporal = shared;
        let error = temporal
            .evaluate()
            .expect_err("a poisoned temporal engine must fail closed");
        assert!(error.contains("poisoned"), "unexpected error: {error}");
    }

    #[cfg(feature = "shuttle")]
    #[test]
    fn lock_handoff_is_visible_to_the_shuttle_scheduler() {
        use shuttle::scheduler::DfsScheduler;
        use shuttle::thread;
        use shuttle::{Config, Runner};

        Runner::new(DfsScheduler::new(None, false), Config::default()).run(|| {
            let shared = SharedEngine::new(LocalTemporalEngine::new());
            let first = shared.clone();
            let first = thread::spawn(move || {
                first
                    .with_mut(|_| thread::yield_now())
                    .expect("first access is available");
            });
            let second = shared.clone();
            let second = thread::spawn(move || {
                second
                    .with(|_| ())
                    .expect("second access follows the handoff");
            });

            first.join().expect("first task completes");
            second.join().expect("second task completes");
        });
    }
}
