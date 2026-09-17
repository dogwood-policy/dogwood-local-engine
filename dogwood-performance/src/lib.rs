//! Performance comparison harness for Dogwood's engines.
//!
//! # What this crate is for
//!
//! Comparing the **in-memory reference implementation** against the **durable
//! server** across three axes: policy count (10 / 100 / 1000), session pinning
//! (on / off), and concurrent request rate.
//!
//! # The caveat that governs every number here
//!
//! The two implementations do different amounts of work *by design*, so a naive
//! "which is faster" reading is wrong in both directions:
//!
//! - The **server `fsync`s** every event before answering. Its per-event latency
//!   therefore cannot go below the storage floor, whatever the engine does — so
//!   [`driver::fsync_floor`] measures that floor explicitly and every report
//!   states it, letting a reader subtract storage cost from engine cost.
//! - The **reference is not durable at all** and rescans history at each decision.
//!   It wins on small workloads for a reason that does not survive a restart, and
//!   loses on large ones for an algorithmic reason that is a genuine finding.
//!
//! The comparisons worth trusting are therefore *within* an implementation across
//! an axis (does pinning help? does policy count hurt?) and, across
//! implementations, only once the durability floor is accounted for.
//!
//! # Layout
//!
//! - [`workload`] — deterministic policy sets, schemas, and event streams. Shared
//!   by both drivers so neither can be handed a different input.
//! - [`driver`] — uniform drivers plus the durability probe.
//! - `benches/` — criterion benchmarks for sequential per-decision latency and for
//!   policy installation.
//! - `src/bin/load.rs` — the open-loop concurrency harness. Criterion cannot
//!   express "offer N requests/second and report the resulting latency
//!   distribution", so that is a separate binary.

pub mod driver;
pub mod workload;
