//! Shared test support for `dogwood-server`'s integration tests.
//!
//! Included with `mod common;` from a test file, so it compiles into that test's
//! binary rather than becoming a test target of its own.
//!
//! * [`workload`] — what a test did to the server, recorded as the server ordered
//!   it. The half of every check that no store holds.
//! * [`invariants`] — structural checks over a recovered store: is it well-formed,
//!   and did everything acknowledged survive?
//! * [`oracle`] — the behavioural check: does a recovered store still *decide* the
//!   same way the reference interpreter does?

pub mod invariants;
pub mod oracle;
pub mod workload;
