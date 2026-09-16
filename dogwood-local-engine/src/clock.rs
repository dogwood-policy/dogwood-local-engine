//! The timestamp source for the durable engine.
//!
//! [`DurableTemporalEngine`](crate::DurableTemporalEngine) assigns every record
//! its timestamp at the append point (`DESIGN.md` §3.3) — never the caller — and
//! it reads the current instant only through a [`Clock`]. In production that is
//! the system clock ([`WallClock`]); a test supplies its own so it can place
//! events at exact instants, or step the clock *backwards* to prove the engine's
//! monotonic clamp holds, without sleeping through real time.
//!
//! # The unit is part of the contract
//!
//! A `Clock` must return **epoch nanoseconds**. The engine compares these against
//! windows converted to the same unit (`TickRate::NANOS`), so a clock in any
//! other unit would silently redefine every `within` window. This is the one
//! invariant an injected clock must honour; everything else about *when* it
//! advances is the caller's business.

/// A source of the current instant, in epoch **nanoseconds**.
///
/// `Send + Sync` because the durable engine is driven behind a mutex and may be
/// shared across threads; a clock held inside it must cross the same boundary.
pub trait Clock: Send + Sync {
    /// The current instant as epoch nanoseconds, saturating rather than wrapping
    /// at the extremes (see [`WallClock`]).
    fn now_nanos(&self) -> i64;
}

/// The system clock: `SystemTime::now()` as epoch nanoseconds. The default, and
/// the only clock a production deployment uses.
///
/// Saturates rather than wrapping: a time before the epoch reads as `0` and one
/// past `i64::MAX` nanoseconds (year 2262) as `i64::MAX`, so the engine's
/// monotonic clamp never sees a wrapped, apparently-backwards value.
#[derive(Debug, Clone, Copy, Default)]
pub struct WallClock;

impl Clock for WallClock {
    fn now_nanos(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}
