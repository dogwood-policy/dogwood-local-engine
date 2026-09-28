//! The binding-row algebra the incremental monitor evaluates over.
//!
//! A *row* is one variable assignment; a relation is a set of them. Temporal
//! operators compose by joining, projecting and comparing relations, and
//! [`crate::incremental`] maintains those relations incrementally over a
//! windowed timeline rather than rebuilding them by scanning.

use std::collections::HashMap;

use dogwood_language::Value;
use dogwood_language::temporal_ast::TypedBinder;

/// A binding row: ordered `(name, value)` pairs. Order matters, because the
/// positional distinctness `count` relies on it.
pub(crate) type Row = Vec<(String, Value)>;

/// A growing set of distinct rows under [`rows_eq`] (`dom_eq` per column), built
/// by insertion — the single dedup primitive every interior operator and the
/// aggregate fold share. It preserves the exact "deduped set per timepoint"
/// semantics the operators already maintained; it only makes maintaining it
/// cheap.
///
/// **Small-relation fast path.** Below [`INDEX_THRESHOLD`] distinct rows it is a
/// plain `Vec` scanned linearly on insert, and *no* hash allocation. Only once a
/// relation grows past the threshold (a wide aggregate window) does it build the
/// hash index and switch to O(1)-amortized inserts, turning the operators'
/// O(n²) dedup into O(n) where it matters.
///
/// The index is a coarse `dom_eq`-consistent hash → bucket of row indices. Coarse
/// because `Value::dom_eq` is not structural (`Decimal("1.0")` equals `"1.00"`;
/// arrays/objects recurse under it): hashing a value's *spelling* would split
/// `dom_eq`-equal rows into different buckets. Hashing only what `dom_eq` treats
/// verbatim — and lumping every decimal into one bucket — keeps the hash
/// consistent with `dom_eq`; exact equality is then settled by [`rows_eq`] within
/// the bucket. Rows are stored **once** (in `rows`); the index holds only
/// `usize` positions, so the extra footprint is one index entry per distinct row,
/// not a second copy.
pub(crate) struct DistinctRows {
    rows: Vec<Row>,
    /// `dom_hash(row) -> positions in `rows``. Built lazily once `rows` grows
    /// past [`INDEX_THRESHOLD`]; `None` while the linear scan is cheaper.
    index: Option<HashMap<u64, Vec<usize>>>,
}

/// Distinct-row count at which [`DistinctRows`] promotes from linear scan to the
/// hash index. Below this the scan is cheaper than hashing and avoids allocating
/// a map; the boolean decision path (tiny relations) never crosses it.
const INDEX_THRESHOLD: usize = 16;

impl DistinctRows {
    pub(crate) fn new() -> Self {
        Self {
            rows: Vec::new(),
            index: None,
        }
    }

    /// Insert `row` if no `rows_eq`-equal row is present; return `true` iff it was
    /// newly distinct.
    pub(crate) fn insert(&mut self, row: Row) -> bool {
        match &mut self.index {
            Some(index) => {
                let h = dom_hash_row(&row);
                let bucket = index.entry(h).or_default();
                if bucket.iter().any(|&i| rows_eq(&self.rows[i], &row)) {
                    return false;
                }
                bucket.push(self.rows.len());
                self.rows.push(row);
                true
            }
            None => {
                if self.rows.iter().any(|r| rows_eq(r, &row)) {
                    return false;
                }
                self.rows.push(row);
                // Crossed the threshold: build the index for subsequent inserts.
                if self.rows.len() > INDEX_THRESHOLD {
                    let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
                    for (i, r) in self.rows.iter().enumerate() {
                        index.entry(dom_hash_row(r)).or_default().push(i);
                    }
                    self.index = Some(index);
                }
                true
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn into_vec(self) -> Vec<Row> {
        self.rows
    }
}

/// A `dom_eq`-consistent hash of one value.
///
/// # How rows get hashed at all
///
/// `Value` (and hence [`Row`]) is **not** `Hash`, and can't cleanly be: `dom_eq`
/// is not structural equality, so a derived `Hash` would disagree with it (e.g.
/// `Decimal("1.0")` equals `"1.00"` under `dom_eq` but has a different spelling).
/// So we do not hash rows *as keys*. Instead:
///
/// 1. This function folds a value's primitive innards (`bool` / `i64` / `&str`,
///    which *are* `Hash`), tagged by a per-variant discriminant byte, into a
///    caller-supplied hasher; [`dom_hash_row`] does the same over a row's cells.
///    The result is a plain `u64`.
/// 2. [`DistinctRows`] keys its map on that `u64` (`HashMap<u64, Vec<usize>>`),
///    never on `Row` — so the standard library only needs `u64: Hash`.
/// 3. The hash is a *bucketing hint*, not the equality: within a bucket, exact
///    membership is settled by [`rows_eq`] (which uses `dom_eq`). The hash may be
///    coarse; collisions are merely slower, never wrong.
///
/// The one invariant that must hold for correctness is therefore
/// **`a.dom_eq(b)` ⇒ `hash(a) == hash(b)`** (equal values must not land in
/// different buckets). The converse is not required. To uphold it this hashes
/// only what `dom_eq` compares verbatim and folds every `Decimal` (and any
/// decimal nested in an array/object) to a single sentinel, so numerically-equal
/// spellings collide rather than split.
pub(crate) fn dom_hash_value(v: &Value, h: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    match v {
        Value::Bool(b) => (0u8, b).hash(h),
        Value::Int(n) => (1u8, n).hash(h),
        // All decimals share one bucket: `dom_eq` compares them numerically, so
        // their spellings must not distinguish them here. `rows_eq` inside the
        // bucket restores exact equality.
        Value::Decimal(_) => 2u8.hash(h),
        Value::String(s) => (3u8, s).hash(h),
        Value::Entity { ty, id } => (4u8, ty, id).hash(h),
        // `dom_eq` treats `Null` structurally (`Null == Null`), so one sentinel.
        Value::Null => 7u8.hash(h),
        Value::Array(items) => {
            5u8.hash(h);
            items.len().hash(h);
            for it in items {
                dom_hash_value(it, h);
            }
        }
        Value::Object(map) => {
            6u8.hash(h);
            map.len().hash(h);
            for (k, val) in map {
                k.hash(h);
                dom_hash_value(val, h);
            }
        }
    }
}

/// [`dom_hash_value`] folded over a `Row`'s values, with column names, so rows
/// differing only in a column name land in different buckets.
fn dom_hash_row(row: &Row) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    row.len().hash(&mut h);
    for (k, v) in row {
        k.hash(&mut h);
        dom_hash_value(v, &mut h);
    }
    h.finish()
}

/// Deduplicate `rows` under [`rows_eq`], preserving first-seen order — the shared
/// primitive the interior operator arms build their per-timepoint relation with.
/// Linear for small relations, hash-indexed once large (see [`DistinctRows`]).
pub(crate) fn dedup_rows(rows: impl IntoIterator<Item = Row>) -> Vec<Row> {
    let mut distinct = DistinctRows::new();
    for row in rows {
        distinct.insert(row);
    }
    distinct.into_vec()
}

/// Project `row` onto `vars` (in order), as a `Row` (name + value) — the per-row
/// step shared by [`project_count`] and [`project_sum`].
fn project_row(row: &Row, vars: &[TypedBinder]) -> Row {
    vars.iter()
        .filter_map(|v| {
            let name = v.name();
            row.iter()
                .find(|(k, _)| k == name)
                .map(|(k, val)| (k.clone(), val.clone()))
        })
        .collect()
}

/// `count` of the distinct projection of `rel` onto `vars`: the number of
/// `dom_eq`-distinct projected keys — folded in one pass through [`DistinctRows`],
/// without materializing the deduped relation as an owned result.
pub(crate) fn project_count(rel: &[Row], vars: &[TypedBinder]) -> i64 {
    let mut distinct = DistinctRows::new();
    for row in rel {
        distinct.insert(project_row(row, vars));
    }
    distinct.len() as i64
}

/// `sum` of `bound` over the distinct projection of `rel` onto `vars`: for each
/// `dom_eq`-distinct projected key, its `bound` column's integer value, summed
/// and folded in one pass.
///
/// Accumulated in **128 bits**, then clamped to `i64` ONCE, at the end — matching
/// the reference interpreter (`dogwood-language` `sum_column`). Accumulating in the
/// result's own `i64` width (e.g. a per-row `saturating_add`) would break the
/// aggregate's order-independence: a partial total can leave `i64` range while the
/// final total sits well inside it, and a clamp/saturation applied mid-fold never
/// recovers — so the answer would depend on the order rows happen to be folded in.
/// `i128` cannot overflow here (every summand is an `i64`, so it would take ~2^64
/// rows to exceed it); a total that genuinely does not fit `i64` is clamped to the
/// range (the language leaves the out-of-range case implementation-defined, and the
/// reference clamps too, so the two stay in lockstep).
pub(crate) fn project_sum(rel: &[Row], vars: &[TypedBinder], bound: &str) -> i64 {
    let mut distinct = DistinctRows::new();
    let mut total: i128 = 0;
    for row in rel {
        let projected = project_row(row, vars);
        // The summed column's value comes from the projected key (it is one of
        // the `for_vars`), matching a sum over the deduped relation.
        let add = projected
            .iter()
            .find(|(k, _)| k == bound)
            .and_then(|(_, v)| v.as_int())
            .unwrap_or(0);
        if distinct.insert(projected) {
            total += i128::from(add);
        }
    }
    total.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

/// Join two rows: union of columns, failing if they disagree on a shared one.
pub(crate) fn join_rows(a: &Row, b: &Row) -> Option<Row> {
    let mut out = a.clone();
    for (k, v) in b {
        if let Some((_, existing)) = out.iter().find(|(ek, _)| ek == k) {
            if !existing.dom_eq(v) {
                return None;
            }
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    Some(out)
}

/// Row equality up to domain equality of each value.
pub(crate) fn rows_eq(a: &Row, b: &Row) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|((ka, va), (kb, vb))| ka == kb && va.dom_eq(vb))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A single-column row, the building block for these cases.
    fn col(name: &str, v: Value) -> Row {
        vec![(name.to_string(), v)]
    }

    /// One row per `Value` variant, so hashing them during index construction
    /// exercises every arm of `dom_hash_value` (Bool/Null/Object included).
    fn one_of_each_variant() -> Vec<Row> {
        vec![
            col("b", Value::Bool(true)),
            col("i", Value::Int(7)),
            col("d", Value::Decimal("1.5".to_string())),
            col("s", Value::String("x".to_string())),
            col(
                "e",
                Value::Entity {
                    ty: "User".to_string(),
                    id: "alice".to_string(),
                },
            ),
            col("n", Value::Null),
            col(
                "a",
                Value::Array(vec![Value::Int(1), Value::Decimal("2.0".to_string())]),
            ),
            col(
                "o",
                Value::Object(BTreeMap::from([
                    ("flag".to_string(), Value::Bool(false)),
                    ("amount".to_string(), Value::Decimal("3.0".to_string())),
                ])),
            ),
        ]
    }

    /// Fill `d` with distinct filler rows until it promotes to the hash index.
    fn fill_past_threshold(d: &mut DistinctRows) {
        let mut i = 0i64;
        while d.len() <= INDEX_THRESHOLD {
            assert!(
                d.insert(col("fill", Value::Int(i))),
                "filler rows are distinct"
            );
            i += 1;
        }
        assert!(
            d.index.is_some(),
            "must have promoted to the hash index once past the threshold"
        );
    }

    #[test]
    fn promotes_to_the_hash_index_past_the_threshold_and_keeps_deduping() {
        let mut d = DistinctRows::new();

        // A spread of value types goes in first, so the lazy index build hashes
        // every variant (covers dom_hash_row and every dom_hash_value arm).
        let variants = one_of_each_variant();
        for r in &variants {
            assert!(d.insert(r.clone()), "each variant row is distinct");
        }
        assert!(d.index.is_none(), "still on the linear fast path");

        fill_past_threshold(&mut d);
        let after_promotion = d.len();

        // Re-inserts now traverse the indexed path and must still dedup.
        assert!(
            !d.insert(variants[0].clone()),
            "the indexed path dedups an exact repeat of a variant row"
        );
        assert!(
            !d.insert(col("fill", Value::Int(0))),
            "the indexed path dedups a filler repeat"
        );
        assert_eq!(d.len(), after_promotion, "no duplicate was admitted");

        // A genuinely new row through the indexed path is accepted.
        assert!(d.insert(col("s", Value::String("new".to_string()))));
        assert_eq!(d.len(), after_promotion + 1);
    }

    #[test]
    fn the_index_dedups_dom_eq_equal_rows_spelled_differently() {
        // The invariant the coarse, dom_eq-consistent hash exists to uphold:
        // `a.dom_eq(b)` must imply `hash(a) == hash(b)`, or a differently-spelled
        // duplicate would land in another bucket and slip past dedup.
        let mut d = DistinctRows::new();
        fill_past_threshold(&mut d);

        assert!(
            d.insert(col("price", Value::Decimal("1.5".to_string()))),
            "the first spelling is new"
        );
        let n = d.len();
        assert!(
            !d.insert(col("price", Value::Decimal("1.50".to_string()))),
            "1.50 is dom_eq to 1.5 and must dedup through the index"
        );
        assert!(!d.insert(col("price", Value::Decimal("1.5000".to_string()))));
        assert_eq!(
            d.len(),
            n,
            "no dom_eq-equal duplicate admitted through the index"
        );
    }

    #[test]
    fn the_linear_path_dedups_dom_eq_equal_rows_spelled_differently() {
        // The same guarantee below the threshold, so the two paths agree.
        let mut d = DistinctRows::new();
        assert!(d.insert(col("price", Value::Decimal("1.5".to_string()))));
        assert!(
            !d.insert(col("price", Value::Decimal("1.50".to_string()))),
            "1.50 is dom_eq to 1.5 and must dedup on the linear path too"
        );
        assert!(d.index.is_none(), "stayed on the linear fast path");
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn dom_eq_equal_values_hash_equal_even_when_spelled_differently() {
        // Directly pins `a.dom_eq(b) => hash(a) == hash(b)`, including nesting,
        // and confirms rows_eq agrees so the in-bucket equality check settles it.
        let bare_a = col("p", Value::Decimal("2.0".to_string()));
        let bare_b = col("p", Value::Decimal("2.00".to_string()));
        assert_eq!(dom_hash_row(&bare_a), dom_hash_row(&bare_b));
        assert!(rows_eq(&bare_a, &bare_b));

        let arr_a = col("p", Value::Array(vec![Value::Decimal("1.0".to_string())]));
        let arr_b = col("p", Value::Array(vec![Value::Decimal("1.000".to_string())]));
        assert_eq!(dom_hash_row(&arr_a), dom_hash_row(&arr_b));
        assert!(rows_eq(&arr_a, &arr_b));

        let obj_a = col(
            "p",
            Value::Object(BTreeMap::from([(
                "k".to_string(),
                Value::Decimal("3.5".to_string()),
            )])),
        );
        let obj_b = col(
            "p",
            Value::Object(BTreeMap::from([(
                "k".to_string(),
                Value::Decimal("3.50".to_string()),
            )])),
        );
        assert_eq!(dom_hash_row(&obj_a), dom_hash_row(&obj_b));
        assert!(rows_eq(&obj_a, &obj_b));
    }

    #[test]
    fn join_rows_unions_disjoint_and_agreeing_columns() {
        let a = vec![
            ("x".to_string(), Value::Int(1)),
            ("y".to_string(), Value::String("k".to_string())),
        ];
        let b = vec![
            ("y".to_string(), Value::String("k".to_string())),
            ("z".to_string(), Value::Bool(true)),
        ];
        let joined = join_rows(&a, &b).expect("agreeing rows join");
        assert_eq!(joined.len(), 3, "union of x, y, z");
    }

    #[test]
    fn join_rows_rejects_a_shared_column_conflict() {
        let a = col("x", Value::Int(1));
        let b = col("x", Value::Int(2));
        assert!(
            join_rows(&a, &b).is_none(),
            "a disagreeing shared column must not join"
        );
    }

    #[test]
    fn join_rows_treats_dom_eq_equal_decimals_as_agreement() {
        // The shared-column check uses dom_eq, so 1.5 and 1.50 are agreement.
        let a = col("x", Value::Decimal("1.5".to_string()));
        let b = col("x", Value::Decimal("1.50".to_string()));
        assert!(
            join_rows(&a, &b).is_some(),
            "a dom_eq-equal shared column is agreement, not a conflict"
        );
    }
}
