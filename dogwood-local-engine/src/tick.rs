//! The unit the store assigns timestamps in, and the conversion of a policy's
//! declared window into that unit.
//!
//! # Why this is a parameter and not a constant
//!
//! A window is declared in *seconds* (`within 1h` → `Interval::seconds() ==
//! 3600`), but every window test in this engine compares that length against a
//! difference of two `Event::timestamp()` values. So the two must share a unit,
//! and which unit that is belongs to whoever *assigns* the timestamps — not to
//! this engine.
//!
//! Two callers assign differently, and both are correct for their purpose:
//!
//! - `dogwood_language`'s in-memory interpreter (the oracle the corpus
//!   differential checks this engine against) compares in **seconds**, and the
//!   regression corpus's traces are authored in seconds. Tests that replay the
//!   corpus must therefore run in seconds, or they would be comparing two
//!   different time domains and calling the difference a bug.
//! - A live store wants **nanoseconds**. Its assignment clamps each timestamp to
//!   `max(now, last + 1)` to keep the sequence strictly increasing, and at
//!   one-second resolution a burst submitted faster than 1/s advances the
//!   sequence one whole second per event — manufacturing time that did not pass
//!   and running the timestamp domain ahead of the wall clock. At nanosecond
//!   resolution real elapsed time dominates and the clamp effectively never
//!   fires, so `within 1h` means an hour.
//!
//! Nanoseconds are the wider convention: `the cloud temporal compiler`'s DSQL
//! monitor stores `ts` in epoch nanos and clamps with
//! `GREATEST((EXTRACT(EPOCH FROM NOW()) * 1000000000)::BIGINT, ts + 1)`, and its
//! own differential scales the corpus's seconds up to nanos to compare against
//! the interpreter. This type is the same conversion, placed where a Rust engine
//! can apply it.
//!
//! # This is a migration seam, not permanent architecture
//!
//! The duplication exists because each backend converts for itself. If
//! `dogwood_language` were to compare in nanoseconds — a single line, its
//! interpreter's `delta <= within.seconds()` — then every backend could drop its
//! conversion and this parameter could go away. Until then it is how a store
//! chooses its own resolution without diverging from the oracle it is checked
//! against.

/// The resolution of the timestamps an engine will be fed: how many ticks make
/// up one second.
///
/// Used only to convert a policy's declared window (seconds) into the domain of
/// the `Event::timestamp()` values being compared. It does not itself assign or
/// alter any timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickRate {
    per_second: i64,
}

impl TickRate {
    /// Timestamps in whole seconds — the unit `dogwood_language`'s interpreter
    /// compares in, and the unit the regression corpus is authored in. The
    /// default, so an engine used as the corpus oracle's counterpart needs no
    /// configuration.
    pub const SECONDS: TickRate = TickRate { per_second: 1 };

    /// Timestamps in epoch nanoseconds — what a live store should assign, and
    /// what the DSQL backend already stores.
    pub const NANOS: TickRate = TickRate {
        per_second: 1_000_000_000,
    };

    /// A custom resolution. `per_second` is clamped to at least 1: a
    /// non-positive rate would collapse every window to zero (or negative) and
    /// silently make history invisible, which is the fail-*open* direction for a
    /// history-gated rule.
    pub fn per_second(per_second: i64) -> TickRate {
        TickRate {
            per_second: per_second.max(1),
        }
    }

    /// Convert a window length in seconds into ticks.
    ///
    /// Saturating in both senses, because both saturations are load-bearing:
    ///
    /// - `i64::MAX` seconds is the "effectively unbounded window" sentinel that
    ///   disables pruning (`reach`), so it must survive conversion unchanged
    ///   rather than wrapping into some finite value that would start dropping
    ///   live events.
    /// - A large-but-finite window must clamp to `i64::MAX` rather than
    ///   overflowing into a small positive number, for the same reason. At
    ///   nanosecond resolution `i64` spans only ~292 years, so this is reachable
    ///   by a policy the frontend's validator accepts.
    pub fn ticks_from_seconds(self, seconds: i64) -> i64 {
        if seconds == i64::MAX {
            return i64::MAX;
        }
        seconds.saturating_mul(self.per_second)
    }
}

impl Default for TickRate {
    fn default() -> Self {
        TickRate::SECONDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_is_the_identity() {
        assert_eq!(TickRate::SECONDS.ticks_from_seconds(3600), 3600);
    }

    #[test]
    fn nanos_scales_by_a_billion() {
        assert_eq!(
            TickRate::NANOS.ticks_from_seconds(3600),
            3_600_000_000_000i64
        );
    }

    /// The unbounded sentinel must survive conversion, or pruning would switch
    /// itself on for a windowless operator and drop events it still needs.
    #[test]
    fn the_unbounded_sentinel_is_preserved() {
        assert_eq!(TickRate::NANOS.ticks_from_seconds(i64::MAX), i64::MAX);
        assert_eq!(TickRate::SECONDS.ticks_from_seconds(i64::MAX), i64::MAX);
    }

    /// A finite window too large for the target unit must clamp UP to the
    /// unbounded sentinel, never wrap down to a small window.
    #[test]
    fn overflow_clamps_to_unbounded_rather_than_wrapping() {
        let huge = i64::MAX / 2;
        assert_eq!(TickRate::NANOS.ticks_from_seconds(huge), i64::MAX);
    }

    #[test]
    fn a_non_positive_rate_cannot_collapse_windows() {
        assert_eq!(TickRate::per_second(0).ticks_from_seconds(60), 60);
        assert_eq!(TickRate::per_second(-5).ticks_from_seconds(60), 60);
    }
}
