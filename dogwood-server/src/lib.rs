//! The Dogwood policy **server**: the security-bearing half of the local stack.
//!
//! `dogwood-local-engine` is an embeddable library that gives correctness and
//! durability. What it cannot give is **tamper-resistance** — a process that
//! links it can rewrite the policy set it is being judged by, and you cannot
//! govern an agent with a rule it controls. This crate closes that by moving the
//! policy set, the compiled monitor, and the event log behind a **process
//! boundary enforced by the OS** (`DESIGN.md` §7), reached only through a small
//! local wire API.
//!
//! # Shape
//!
//! - [`protocol`] — the wire types. Two disjoint verb sets on two sockets: the
//!   data plane ([`DataRequest`](protocol::DataRequest)) has no policy-mutating
//!   variant, so the monitored agent's vocabulary *structurally* excludes
//!   authoring.
//! - [`server`] — the listener: binds both sockets, authorizes control callers
//!   by kernel peer-credential, and dispatches to a
//!   [`DurableTemporalEngine`](dogwood_local_engine::DurableTemporalEngine) it
//!   holds directly. The only work between wire and engine is mapping the wire
//!   [`WireEvent`](protocol::WireEvent) to an event builder
//!   ([`codec::to_event_builder`]); durability and recovery are the engine's.
//!   See `docs/design/DURABLE_ENGINE_REFACTOR.md`.
//! - [`peer`] — peer-credential attestation and the control-plane uid allowlist
//!   (§8.1). The mechanism the whole boundary rests on.
//! - [`codec`] — the event wire/log format.
//! - [`client`] — reference clients for both sockets.
//!
//! # The deployment prerequisite
//!
//! §7.1 is explicit and worth repeating wherever this crate is described: the
//! boundary is real only if the **server runs as a different, lower-privileged
//! uid than the monitored agent**. Same uid, no boundary — root and the server's
//! own operator are outside the threat model by construction.
//!
//! # Running it in-process
//!
//! [`Server::open`] + [`Server::serve`] is all the binary does, so a consumer
//! that wants the process boundary without a separate command can spawn the
//! server on a thread and stop it with [`Server::stop`]. That is also how the
//! end-to-end tests drive it.

pub mod client;
pub mod codec;
pub mod peer;
pub mod protocol;
pub mod routing;
pub mod server;

// The record envelope and snapshot payload moved into `dogwood-local-engine`
// with the durable engine. Re-exported as a module so the historical
// `dogwood_server::record::Record` path still resolves.
pub mod record {
    pub use dogwood_local_engine::{Record, SnapshotPayload};
}

pub use client::{ControlClient, DataClient};
pub use peer::{ControlAllowlist, PeerCred};
pub use routing::{ShardKey, key_of};
pub use server::{Paths, Server, VERSION};
// The durable-engine types live in `dogwood-local-engine`; re-exported for
// consumers that reach them through the server crate. There is no `ServerState`
// any more — the server holds a `DurableTemporalEngine` directly (see [`server`]).
pub use dogwood_local_engine::{Applied, Installed, Outcome, ShardPlan, Submitted};
