//! The one time-indexed relation every monitor node propagates up, and the
//! predicate-leaf history that feeds it.
//!
//! [`crate::incremental`] evaluates a condition over an inclusive *range* of
//! timepoints and returns, for each timepoint, the witness rows the node
//! produces there — a [`RelRead`]. Leaf and interior nodes are the same kind of
//! thing: a producer of rows-per-timepoint. A history-scanning operator
//! (`formerly`, `since`, `previous`) evaluates its child **once** over a widened
//! range, then rolls the child's relation up per output timepoint — rather than
//! re-invoking the child once per point as a point-wise walk would.
//!
//! The operator algebra reads children through [`RelRead`] alone, never a
//! concrete container, so the representation is a swappable impl behind the
//! [`Rel`] / [`LeafStore`] aliases: sparse today, dense later, with no operator
//! change. `PERFORMANCE.md` §5 records the representation choices deliberately
//! deferred behind these aliases (dense interiors, per-node rep selection) and
//! why.
//!
//! # How the two roles connect
//!
//! Both an interior relation and a predicate leaf are read the same way — that
//! shared [`RelRead`] interface (`at` / `range` / `iter`) is the connection, and
//! it is why the `Pred` arm has no special read path: it consumes a leaf as a
//! relation like any child. They differ only in how they are *built*:
//!
//! - [`TimeRel`]`: RelRead` — an interior relation, **constructed** fresh per
//!   evaluation (`empty` + `put`), then dropped.
//! - [`LeafHistory`]`: RelRead` — a persisted leaf stream, **maintained** across
//!   events (`push` / `drop_front`) and snapshotted (`logical_len`).

use crate::rows::Row;

/// The read interface shared by every rows-per-timepoint producer — the one an
/// operator uses on any child, leaf or interior.
///
/// Invariants every impl must uphold:
/// - A timepoint is observable via [`at`](Self::at) / [`range`](Self::range) /
///   [`iter`](Self::iter) only if its relation is non-empty — measured on the
///   number of rows, not the inner [`Row`]. A single empty row (`vec![vec![]]`)
///   is "holds here, no bindings": a non-empty relation that *is* present.
/// - [`range`](Self::range) and [`iter`](Self::iter) yield cells in ascending
///   timepoint order.
pub(crate) trait RelRead {
    /// Whether no timepoint holds any row.
    fn is_empty(&self) -> bool;

    /// The witness rows at timepoint `i`, or `&[]`.
    fn at(&self, i: usize) -> &[Row];

    /// The non-empty cells in `[lo, hi]` inclusive, ascending — used to roll up
    /// a *sub-window* of an already-computed relation.
    fn range(&self, lo: usize, hi: usize) -> impl Iterator<Item = (usize, &[Row])>;

    /// Every non-empty cell, ascending. Use when consuming a child over the
    /// *same* range it was computed for (`and` / `exists`), where bounding by
    /// `range` would be a no-op; reserve [`range`](Self::range) for the temporal
    /// sub-window roll-ups where the iterate range differs from the compute one.
    fn iter(&self) -> impl Iterator<Item = (usize, &[Row])>;
}

/// A [`RelRead`] an operator **constructs** fresh: start [`empty`](Self::empty),
/// [`put`](Self::put) each timepoint's rows in ascending order, propagate up,
/// drop. This is the value that flows through the tree.
pub(crate) trait TimeRel: RelRead {
    fn empty() -> Self
    where
        Self: Sized;

    /// Record the relation at timepoint `i` (an empty relation is not stored).
    /// Callers build in ascending `i`; impls may rely on that.
    fn put(&mut self, i: usize, rows: Vec<Row>);
}

/// A [`RelRead`] the monitor **maintains**: a predicate leaf's stored,
/// window-pruned match history. On top of the shared read interface it adds the
/// upkeep a persisted stream needs and an interior relation does not:
/// [`push`](Self::push) one observed event, [`drop_front`](Self::drop_front) to
/// expire on window prune, and [`logical_len`](Self::logical_len) — the retained
/// timepoint count (matched *or not*), which the fixed-format snapshot walk
/// needs and which differs from [`RelRead::is_empty`] (about matches).
pub(crate) trait LeafHistory: RelRead {
    fn new() -> Self
    where
        Self: Sized;

    /// Record one observed event's match (`Some`) or absence (`None`) at the
    /// newest retained timepoint, extending the retained length by one.
    fn push(&mut self, row: Option<Row>);

    /// Expire the oldest `n` retained timepoints.
    fn drop_front(&mut self, n: usize);

    /// Retained timepoint count, matched or not.
    fn logical_len(&self) -> usize;
}

/// The interior-relation representation the monitor uses. Swap to another
/// [`TimeRel`] impl to change representations; the operator algebra is unchanged.
pub(crate) type Rel = SparseRel;

/// The predicate-leaf representation. Swap to another [`LeafHistory`] impl to
/// change representations; the `Pred` arm and snapshot walk are unchanged.
pub(crate) type LeafStore = SparseLeaf;

/// Sparse interior relation: only non-empty timepoints, sorted ascending. `at`
/// binary-searches; `range` partition-points then walks — the empty span
/// between matches is never materialized.
pub(crate) struct SparseRel {
    cells: Vec<(usize, Vec<Row>)>,
}

impl RelRead for SparseRel {
    fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    fn at(&self, i: usize) -> &[Row] {
        match self.cells.binary_search_by_key(&i, |(k, _)| *k) {
            Ok(idx) => &self.cells[idx].1,
            Err(_) => &[],
        }
    }

    fn range(&self, lo: usize, hi: usize) -> impl Iterator<Item = (usize, &[Row])> {
        let from = self.cells.partition_point(|(k, _)| *k < lo);
        self.cells[from..]
            .iter()
            .take_while(move |(k, _)| *k <= hi)
            .map(|(k, rows)| (*k, rows.as_slice()))
    }

    fn iter(&self) -> impl Iterator<Item = (usize, &[Row])> {
        self.cells.iter().map(|(k, rows)| (*k, rows.as_slice()))
    }
}

impl TimeRel for SparseRel {
    fn empty() -> Self {
        Self { cells: Vec::new() }
    }

    fn put(&mut self, i: usize, rows: Vec<Row>) {
        if rows.is_empty() {
            return;
        }
        debug_assert!(
            self.cells.last().is_none_or(|(k, _)| *k < i),
            "TimeRel::put must be called in ascending timepoint order"
        );
        self.cells.push((i, rows));
    }
}

/// Sparse predicate history: only matched timepoints, each tagged with its
/// **absolute** timepoint index, sorted ascending. A `base` offset makes
/// [`drop_front`](LeafHistory::drop_front) O(expired) without rewriting the
/// survivors' indices; `next` counts timepoints ever pushed, so `next - base`
/// is the retained length. Each match reads as a length-1 cell (a predicate
/// binds at most one row per timepoint), so the leaf satisfies [`RelRead`].
#[derive(Clone)]
pub(crate) struct SparseLeaf {
    entries: Vec<(usize, Row)>,
    /// The DEAD-PREFIX CURSOR (amortized pruning): `entries[..start]`
    /// are expired but not yet physically removed. `drop_front` only
    /// advances this cursor; the vector is compacted (one drain +
    /// memmove) when the dead prefix outgrows the live tail — O(1)
    /// amortized per expired match. The eager `drain(..keep)` design
    /// memmoved the WHOLE tail per prune, and in steady state pruning
    /// fires on ~every observe: O(in-window matches) PER EVENT
    /// (exhibited by tests/leaf_prune.rs `p1`).
    start: usize,
    base: usize,
    next: usize,
}

impl RelRead for SparseLeaf {
    fn is_empty(&self) -> bool {
        self.entries.len() == self.start
    }

    fn at(&self, i: usize) -> &[Row] {
        let abs = i + self.base;
        let live = &self.entries[self.start..];
        match live.binary_search_by_key(&abs, |(k, _)| *k) {
            Ok(idx) => std::slice::from_ref(&live[idx].1),
            Err(_) => &[],
        }
    }

    fn range(&self, lo: usize, hi: usize) -> impl Iterator<Item = (usize, &[Row])> {
        let (abs_lo, abs_hi, base) = (lo + self.base, hi + self.base, self.base);
        let live = &self.entries[self.start..];
        let from = live.partition_point(|(k, _)| *k < abs_lo);
        live[from..]
            .iter()
            .take_while(move |(k, _)| *k <= abs_hi)
            .map(move |(k, row)| (*k - base, std::slice::from_ref(row)))
    }

    fn iter(&self) -> impl Iterator<Item = (usize, &[Row])> {
        let base = self.base;
        self.entries[self.start..]
            .iter()
            .map(move |(k, row)| (*k - base, std::slice::from_ref(row)))
    }
}

impl LeafHistory for SparseLeaf {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            start: 0,
            base: 0,
            next: 0,
        }
    }

    fn push(&mut self, row: Option<Row>) {
        if let Some(r) = row {
            self.entries.push((self.next, r));
        }
        self.next += 1;
    }

    fn drop_front(&mut self, n: usize) {
        self.base += n;
        // Advance the dead-prefix cursor (binary search over the live
        // slice only), deferring the physical removal.
        self.start += self.entries[self.start..].partition_point(|(k, _)| *k < self.base);
        // Compact when the dead prefix outgrows the live tail: each
        // entry is memmoved at most once per doubling — O(1) amortized.
        if self.start > self.entries.len() - self.start {
            self.entries.drain(..self.start);
            self.start = 0;
        }
    }

    fn logical_len(&self) -> usize {
        self.next - self.base
    }
}
