# Dogwood Local Engine

This repository contains the implementation of an authorization engine for
policies expressed in the [Dogwood](https://github.com/dogwood-policy/dogwood)
policy language. Dogwood policies can refer to an agent's past actions and
their outcomes; this engine keeps that history, durably and in order, and
decides each request against it.

For a walkthrough of the library, from a policy and a schema to a program that
opens a store, installs the policy and submits events, see
[`dogwood-local-engine/README.md`](dogwood-local-engine/README.md). The
language itself, its guide, and the reference interpreter live in
[dogwood-policy/dogwood](https://github.com/dogwood-policy/dogwood) and
[the Dogwood guide](https://dogwood-policy.github.io/dogwood/).

To use the engine, add it and the language crate to a project:

```toml
[dependencies]
dogwood-local-engine = "1.0"
dogwood-language = "1.0"
```

The repository is organized into three crates:

- `dogwood-local-engine`: this is the primary crate, containing the library
  implementing the authorization engine.
- `dogwood-server`: a demo showing how the library might be used to build a
  local service for issuing authorization verdicts.
- `dogwood-performance`: benchmarks for various aspects of the local engine.

Compared with the reference interpreter in the main Dogwood language repository,
the local engine library is designed to process events in an incremental
fashion, observing events and issuing authorization verdicts for requests as
they arrive, instead of processing the entire trace at once. It stores its
state in a durable way on the filesystem, so that if a process using the
library crashes or shuts down, subsequent authorization requests can be
processed after restart while accounting for events that preceded the crash.

The `dogwood-server` crate shows how one might build a local daemon service for
issuing authorization decisions using this library. This demo application
listens on two Unix sockets. One socket is used for *control plane* operations,
which edit the policy set that the engine is monitoring. The other is used for
*data plane* operations: incoming history and decision events. The engine
records all these events and issues verdicts for decision events.

## Embedding the engine safely

There are a few important precautions to keep in mind when constructing an
authorization service like the `dogwood-server` that uses the library. In
particular, the library is a minimal core focused solely on producing correct
authorization verdicts from the events it receives and the policies it
monitors. An application that uses the library remains responsible for several
tasks essential to its security and correct operation. These include, but are
not limited to, the following concerns:

- **Capturing all relevant events**: The local engine only processes events
  that are made visible to it. Thus, its decisions are only accurate to the
  extent that it has seen all events relevant to the policies it is tasked with
  enforcing. If a temporal policy depends on prior events that were not sent to
  the local engine, the engine cannot account for them, and its verdicts will
  not be accurate with respect to that larger history.

- **Event provenance and accuracy**: The application wrapping the library is
  responsible for ensuring that events passed to the engine are well-formed and
  have accurate fields. The library has no way to check that, for example, the
  principal recorded on an event accurately reflects the principal that
  initiated the action. The wrapping application must perform appropriate
  authentication to establish the provenance of this data.

- **Enforcing decisions**: The local engine issues *verdicts* about whether
  a request should be allowed or denied, but it has no mechanism to enforce
  those decisions. An application or client using the library is responsible
  for accurately applying the verdicts that the engine issues.

- **Restricting access to engine state**: Proper access controls must be placed
  on the files in which the local engine's durable state is stored. If these
  files can be modified by an unauthorized process, they could be altered to
  affect the event trace or the set of policies the engine is enforcing.
  Because this state may contain details about previous events and policy
  configuration, it may contain sensitive information. For similar reasons, an
  unauthorized process must not be able to directly alter the in-memory state
  of the local engine. The engine library uses safe Rust, but an application
  using the library must ensure that its own unsafe code or dependencies cannot
  corrupt this memory.

- **Securing control plane actions**: Control plane actions that affect the set
  of policies the engine is enforcing are particularly sensitive: a process
  that can affect the policy set could remove policies that forbid actions,
  thereby causing the engine to permit actions that should be denied. Thus, the
  control plane must be secured appropriately. For example, in the
  `dogwood-server` example, these operations are performed on a separate socket
  from data events, so that access to the control socket can be further
  restricted. Control plane actions may fail or raise errors when attempted.
  The local engine's default behavior in this case is to continue executing
  with the set of policies that was active immediately before the attempted
  control plane action. The application must account for this behavior and
  report the failure to authorized operators so that they can correct the error
  and try again. Silently dropping the error may give users the mistaken
  impression that their changes to the policy set succeeded.

- **Audit logging of data plane and control plane actions**: While the
  `dogwood-local-engine` durably stores its state, its internal log is
  periodically checkpointed and pruned. It therefore cannot be relied upon to
  audit past actions. It guarantees only that its durable state contains enough
  information to recover and issue future authorization decisions after a
  crash. Snapshots preserve derived monitor state rather than a complete event
  history, and decision results are not logged. The application using the
  library must maintain a separate audit log that meets the service's retention,
  attribution, and integrity requirements.

- **Timestamp accuracy**: Because Dogwood policies have a temporal component,
  the local engine uses the system clock to assign timestamps to events, and
  these timestamps can affect authorization decisions. The accuracy of the host
  clock is therefore critical. Unauthorized processes must not be allowed to
  alter the clock used by the local engine. As a basic precaution, the engine
  ensures that the timestamps it assigns are monotonically increasing, even if
  the system clock moves backwards. But monotonicity alone does not prevent
  clock dilation, contraction, or skew from affecting outcomes, so the host
  clock must still be secured and monitored.

## Design documents

- [`docs/design/DESIGN.md`](docs/design/DESIGN.md): the engine's architecture
  and the decisions behind it.

## Building and testing

The workspace builds with a recent stable Rust toolchain (edition 2024):

```bash
cargo build --workspace --all-targets
cargo test --workspace
```

## Contributing

This repository is a published, read-only mirror; see
[CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, follow
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
