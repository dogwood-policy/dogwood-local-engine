# Dogwood Local Engine — Release Notes

Release notes for the Dogwood local authorization engine
(`dogwood-local-engine`, `dogwood-server`, `dogwood-performance`).


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

