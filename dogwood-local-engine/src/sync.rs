//! Build-selected synchronization primitives for Dogwood-owned shared state.
//!
//! Production builds use the standard library. Shuttle builds substitute
//! scheduler-aware equivalents so each access becomes an explored scheduling
//! boundary; synchronization hidden inside dependencies such as redb remains
//! opaque and must be modeled at safe boundaries by the caller.

#[cfg(feature = "shuttle")]
pub(crate) use shuttle::sync::Mutex;
#[cfg(feature = "shuttle")]
pub(crate) use shuttle::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "shuttle")]
pub(crate) use shuttle::sync::mpsc;
#[cfg(feature = "shuttle")]
pub(crate) use shuttle::thread;
#[cfg(not(feature = "shuttle"))]
pub(crate) use std::sync::Mutex;
#[cfg(not(feature = "shuttle"))]
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(feature = "shuttle"))]
pub(crate) use std::sync::mpsc;
#[cfg(not(feature = "shuttle"))]
pub(crate) use std::thread;

/// Exposes a possible preemption at a storage operation hidden inside redb.
///
/// Shuttle cannot instrument dependency internals. Tests use these boundaries
/// to explore another thread running immediately before a transaction begins
/// or commits; production builds compile the boundary to a no-op.
#[cfg(feature = "shuttle")]
pub(crate) fn storage_boundary() {
    shuttle::thread::yield_now();
}

#[cfg(not(feature = "shuttle"))]
#[inline(always)]
pub(crate) fn storage_boundary() {}
