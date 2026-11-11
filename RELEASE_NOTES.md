# Dogwood Local Engine — Release Notes

Release notes for the Dogwood local authorization engine
(`dogwood-local-engine`, `dogwood-server`, `dogwood-performance`).


## [1.1.2] — 2026-11-11

### Summary

This release adds an opt-in durability mode that trades a bounded window of
crash safety for throughput. The default is unchanged: every event is fsynced
before its verdict is returned, so consumers that do not opt in upgrade with no
behavioral change.

### Added

- **durable**: `Durability`, with `DurableTemporalEngine::set_durability`,
  `durability` and `flush`. `Durability::EveryEvent`, the default, fsyncs each
  event. `Durability::Periodic { max_events, max_interval }` writes each event
  but fsyncs only after `max_events` unsynced events, at the first submit once
  `max_interval` has passed since the oldest unsynced one (measured on the
  store's clock), and at `flush`, `checkpoint`, or clean close. The fsync is
  nearly the whole cost of a submit, so this is many times faster.

  The price is stated in the type's documentation: after a crash of any kind,
  events since the last fsync are lost, a verdict already acted on may have
  rested on one of them, and the offsets and timestamps of the lost events are
  handed out again. The interval is checked at submit, not by a timer, so an
  embedder that needs the bound to hold while idle calls `flush` on its own
  timer and before shutdown.

- **durable**: policy installs, batches, deletes, pruning and snapshots always
  fsync and make every earlier event durable. An empty `batch` now flushes, so
  this holds for every successful batch.

### Compatibility

- **dogwood-language**: unchanged; pairs with dogwood-language 1.1.
- No change to the store format. A store written under either mode opens under
  the other.

---

## [1.1.0] — 2026-10-09

### Summary

This release teaches the engine to evaluate arithmetic in temporal comparison
operands, matching the new `Term::Arith` in dogwood-language. The capability is
experimental and opt-in — a default build rejects arithmetic policies at the
frontend — so most consumers upgrade with no behavioral change.

### Compatibility

- **dogwood-language**: Pairs with the dogwood-language v1.1.0 that adds
  `Term::Arith` and the `experimental-arithmetic` feature. The engine's own
  `experimental-arithmetic` feature forwards to the frontend's.

### Experimental

These are non-official, opt-in features. Their syntax and behavior may change
or be removed in a future release, and they are off by default.

- **monitor**: Evaluation of arithmetic comparison operands. `Operand` grows an
  `Arith` variant built recursively from `Term::Arith`; values are per-operation
  saturating `i64` in tree order, matching the reference `resolve_term_at`. An
  atom that does not resolve to an integer falsifies the enclosing comparison,
  and a compound side never binds. Aggregates inside arithmetic stay
  `Operand::Agg` leaves, so memoization, history recording, and snapshot walks
  apply unchanged. The feature is gated behind the off-by-default
  `experimental-arithmetic` Cargo feature, which forwards to the frontend's; the
  evaluator stays compiled either way, and a feature-off frontend rejects
  arithmetic before it reaches `prepare`.

---

