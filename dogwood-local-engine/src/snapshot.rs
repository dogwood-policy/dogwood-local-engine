//! Compact, reversible binary codec for the incremental monitors' derived
//! state — the bytes stored in the durable log's snapshot slot (`DESIGN.md`
//! §6.3).
//!
//! # Why a hand-rolled codec
//!
//! The monitor state is built from [`dogwood_language::Value`] (inside every
//! [`crate::rows::Row`]), which — like `Event` — is not `serde`-serializable
//! from this crate. So this module provides a small tagged binary encoding for
//! `Value` / `Row` and the pieces of monitor state that need it. It is
//! deliberately minimal and exact: `decode` of `encode(x)` yields a `Value`
//! that is `dom_eq` (indeed bit-identical) to `x`.
//!
//! # What a snapshot contains
//!
//! Only the **mutable** monitor state: the shared timeline (`ts` / `tp_id` /
//! `next_tp`) and each predicate's per-timepoint match history. The `Node` tree
//! *shape* is not stored — it is rebuilt deterministically from the installed
//! leaves at `prepare`, and the state is loaded into it in a fixed tree-walk
//! order. This keeps snapshots small and avoids serializing the AST.

use dogwood_language::Value;
use std::mem::size_of;
use std::num::NonZeroUsize;

use crate::rows::Row;

/// A cursor over encoded bytes, for the `decode_*` functions.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// A validated, fixed-width block of little-endian `u64` words.
///
/// Construction is kept inside [`Reader::u64_block`], so consumers cannot
/// accidentally disagree with the snapshot framing about the block's length.
pub(crate) struct U64Block<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl U64Block<'_> {
    /// Decode this block as bit-preserving `i64` values with fallible allocation.
    pub(crate) fn decode_i64s(self) -> Option<Vec<i64>> {
        let mut values = Vec::new();
        values.try_reserve_exact(self.count).ok()?;
        for bytes in self.bytes.chunks_exact(size_of::<u64>()) {
            values.push(i64::from_le_bytes(bytes.try_into().ok()?));
        }
        debug_assert_eq!(values.len(), self.count);
        Some(values)
    }
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    pub(crate) fn u64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }
    pub(crate) fn usize(&mut self) -> Option<usize> {
        usize::try_from(self.u64()?).ok()
    }
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    /// Read a collection count and reject values impossible for the bytes left.
    pub(crate) fn count(&mut self, min_item_bytes: usize) -> Option<usize> {
        let min_item_bytes = NonZeroUsize::new(min_item_bytes)?;
        let count = self.usize()?;
        (count <= self.remaining() / min_item_bytes.get()).then_some(count)
    }
    /// Consume exactly `count` little-endian `u64` words.
    ///
    /// The checked multiplication is the single source of truth for this
    /// fixed-width framing. Failure does not advance the reader.
    pub(crate) fn u64_block(&mut self, count: usize) -> Option<U64Block<'a>> {
        let byte_len = count.checked_mul(size_of::<u64>())?;
        let bytes = self.bytes(byte_len)?;
        Some(U64Block { bytes, count })
    }
    fn i64(&mut self) -> Option<i64> {
        Some(self.u64()? as i64)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let b = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }
    fn string(&mut self) -> Option<String> {
        let len = self.usize()?;
        let b = self.bytes(len)?;
        let text = std::str::from_utf8(b).ok()?;
        let mut owned = String::new();
        owned.try_reserve_exact(len).ok()?;
        owned.push_str(text);
        Some(owned)
    }
    /// True once all bytes are consumed (a well-formed snapshot ends exactly).
    pub(crate) fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Allocate only a small initial chunk of an encoded collection.
fn bounded_vec<T>(target_len: usize) -> Option<Vec<T>> {
    let mut items = Vec::new();
    items.try_reserve_exact(target_len.min(64)).ok()?;
    Some(items)
}

/// Append one decoded item without trusting the encoded final count as an
/// up-front allocation request. Capacity grows geometrically but never beyond
/// `target_len`; allocation failure becomes an ordinary decode failure.
fn try_push<T>(items: &mut Vec<T>, item: T, target_len: usize) -> Option<()> {
    if items.len() == items.capacity() {
        let remaining = target_len.checked_sub(items.len())?;
        if remaining == 0 {
            return None;
        }
        let additional = items.capacity().max(64).min(remaining);
        items.try_reserve_exact(additional).ok()?;
    }
    items.push(item);
    Some(())
}

// ─── writers ─────────────────────────────────────────────────────────

pub(crate) fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub(crate) fn put_i64(out: &mut Vec<u8>, v: i64) {
    put_u64(out, v as u64);
}
fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u64(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Encode a [`Value`] (tagged union; composites recurse).
pub(crate) fn encode_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.push(0),
        Value::Bool(b) => {
            out.push(1);
            out.push(*b as u8);
        }
        Value::Int(n) => {
            out.push(2);
            put_i64(out, *n);
        }
        Value::Decimal(s) => {
            out.push(3);
            put_str(out, s);
        }
        Value::String(s) => {
            out.push(4);
            put_str(out, s);
        }
        Value::Entity { ty, id } => {
            out.push(5);
            put_str(out, ty);
            put_str(out, id);
        }
        Value::Array(items) => {
            out.push(6);
            put_u64(out, items.len() as u64);
            for it in items {
                encode_value(out, it);
            }
        }
        Value::Object(members) => {
            out.push(7);
            put_u64(out, members.len() as u64);
            for (k, val) in members {
                put_str(out, k);
                encode_value(out, val);
            }
        }
    }
}

/// Decode a [`Value`]; `None` on malformed input.
pub(crate) fn decode_value(r: &mut Reader) -> Option<Value> {
    Some(match r.u8()? {
        0 => Value::Null,
        1 => Value::Bool(r.u8()? != 0),
        2 => Value::Int(r.i64()?),
        3 => Value::Decimal(r.string()?),
        4 => Value::String(r.string()?),
        5 => Value::Entity {
            ty: r.string()?,
            id: r.string()?,
        },
        6 => {
            // Every encoded Value consumes at least its one-byte tag.
            let n = r.count(1)?;
            let mut items = bounded_vec(n)?;
            for _ in 0..n {
                let item = decode_value(r)?;
                try_push(&mut items, item, n)?;
            }
            Value::Array(items)
        }
        7 => {
            // Each member has an eight-byte key length and a value tag.
            let n = r.count(9)?;
            let mut members = std::collections::BTreeMap::new();
            for _ in 0..n {
                let k = r.string()?;
                members.insert(k, decode_value(r)?);
            }
            Value::Object(members)
        }
        _ => return None,
    })
}

/// Encode a [`Row`] (`Vec<(String, Value)>`).
pub(crate) fn encode_row(out: &mut Vec<u8>, row: &Row) {
    put_u64(out, row.len() as u64);
    for (k, v) in row {
        put_str(out, k);
        encode_value(out, v);
    }
}

/// Decode a [`Row`].
pub(crate) fn decode_row(r: &mut Reader) -> Option<Row> {
    // Each column has an eight-byte name length and a value tag.
    let n = r.count(9)?;
    let mut row = bounded_vec(n)?;
    for _ in 0..n {
        let k = r.string()?;
        let value = decode_value(r)?;
        try_push(&mut row, (k, value), n)?;
    }
    Some(row)
}

/// Encode an optional row (a predicate's per-timepoint match).
pub(crate) fn encode_time_row(out: &mut Vec<u8>, tr: &Option<Row>) {
    match tr {
        None => out.push(0),
        Some(row) => {
            out.push(1);
            encode_row(out, row);
        }
    }
}

/// Decode an optional row.
pub(crate) fn decode_time_row(r: &mut Reader) -> Option<Option<Row>> {
    Some(match r.u8()? {
        0 => None,
        1 => Some(decode_row(r)?),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dogwood_language::Value;
    use std::collections::BTreeMap;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    const COLLECTION_SIZES: &[usize] = &[
        0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513,
        1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097,
    ];

    fn roundtrip(v: &Value) {
        let mut buf = Vec::new();
        encode_value(&mut buf, v);
        let mut r = Reader::new(&buf);
        let got = decode_value(&mut r).expect("decodes");
        assert!(r.at_end(), "consumed all bytes for {v:?}");
        assert_eq!(&got, v, "round-trip {v:?}");
    }

    #[test]
    fn u64_blocks_decode_exactly_across_size_boundaries() {
        for &size in COLLECTION_SIZES {
            let expected: Vec<i64> = (0..size)
                .map(|index| match index % 4 {
                    0 => i64::MIN,
                    1 => -1,
                    2 => index as i64,
                    _ => i64::MAX,
                })
                .collect();
            let mut encoded = Vec::new();
            for &value in &expected {
                put_i64(&mut encoded, value);
            }
            put_u64(&mut encoded, 0xfeed_beef);

            let mut reader = Reader::new(&encoded);
            let decoded = reader
                .u64_block(size)
                .and_then(U64Block::decode_i64s)
                .expect("fixed-width block decodes");
            assert_eq!(decoded, expected, "block of size {size} changed");
            assert_eq!(
                reader.remaining(),
                size_of::<u64>(),
                "block of size {size} consumed the wrong byte count"
            );
            assert_eq!(reader.u64(), Some(0xfeed_beef));
            assert!(reader.at_end());
        }
    }

    #[test]
    fn truncated_u64_blocks_fail_without_advancing() {
        const WORDS: usize = 3;
        let full_len = WORDS * size_of::<u64>();
        for available in 0..full_len {
            let encoded = vec![0xa5; available];
            let mut reader = Reader::new(&encoded);

            assert!(
                reader.u64_block(WORDS).is_none(),
                "{available} bytes satisfied a {full_len}-byte block"
            );
            assert_eq!(
                reader.remaining(),
                available,
                "failed block read advanced with {available} bytes available"
            );
        }
    }

    #[test]
    fn impossible_u64_block_sizes_fail_without_advancing() {
        let encoded = 42u64.to_le_bytes();
        for count in [
            usize::MAX / size_of::<u64>(),
            usize::MAX / size_of::<u64>() + 1,
            usize::MAX,
        ] {
            let mut reader = Reader::new(&encoded);
            assert!(
                reader.u64_block(count).is_none(),
                "impossible block of {count} words was accepted"
            );
            assert_eq!(reader.remaining(), encoded.len());
            assert_eq!(reader.u64(), Some(42));
            assert!(reader.at_end());
        }
    }

    #[test]
    fn empty_u64_block_consumes_nothing() {
        let encoded = 42u64.to_le_bytes();
        let mut reader = Reader::new(&encoded);

        assert_eq!(
            reader.u64_block(0).and_then(U64Block::decode_i64s),
            Some(Vec::new())
        );
        assert_eq!(reader.remaining(), encoded.len());
        assert_eq!(reader.u64(), Some(42));
    }

    #[test]
    fn collection_count_rejects_zero_width_without_advancing() {
        let mut encoded = Vec::new();
        put_u64(&mut encoded, 1);
        encoded.push(0);
        let mut reader = Reader::new(&encoded);

        assert_eq!(reader.count(0), None);
        assert_eq!(reader.remaining(), encoded.len());
        assert_eq!(reader.u64(), Some(1));
    }

    #[test]
    fn collection_count_checks_item_width_at_exact_boundaries() {
        for item_width in [1usize, 8, 9, 16, 64] {
            for count in [0usize, 1, 2, 63, 64, 65] {
                let required = count * item_width;
                for available in required.saturating_sub(1)..=required {
                    let mut encoded = Vec::new();
                    put_u64(&mut encoded, count as u64);
                    encoded.resize(encoded.len() + available, 0);
                    let mut reader = Reader::new(&encoded);

                    assert_eq!(
                        reader.count(item_width),
                        (available >= required).then_some(count),
                        "count={count}, width={item_width}, available={available}"
                    );
                    assert_eq!(reader.remaining(), available);
                }
            }
        }
    }

    #[test]
    fn value_codec_round_trips_all_variants() {
        roundtrip(&Value::Null);
        roundtrip(&Value::Bool(true));
        roundtrip(&Value::Bool(false));
        roundtrip(&Value::Int(0));
        roundtrip(&Value::Int(-42));
        roundtrip(&Value::Int(i64::MIN));
        roundtrip(&Value::Int(i64::MAX));
        roundtrip(&Value::Decimal("1.50".into()));
        roundtrip(&Value::String(String::new()));
        roundtrip(&Value::String("héllo — utf8 ✓".into()));
        roundtrip(&Value::Entity {
            ty: "Ns::User".into(),
            id: "a\"b\\c".into(),
        });
        roundtrip(&Value::Array(vec![
            Value::Int(1),
            Value::String("x".into()),
            Value::Null,
        ]));
        let mut m = BTreeMap::new();
        m.insert("k1".to_string(), Value::Int(7));
        m.insert("k2".to_string(), Value::Array(vec![Value::Bool(true)]));
        roundtrip(&Value::Object(m));
        // Nested composite.
        roundtrip(&Value::Array(vec![Value::Object(BTreeMap::from([(
            "inner".to_string(),
            Value::Decimal("0.001".into()),
        )]))]));
    }

    #[test]
    fn strings_round_trip_across_length_boundaries() {
        for size in [
            0usize, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023,
            1024, 1025, 4095, 4096, 4097, 65_535, 65_536, 65_537,
        ] {
            roundtrip(&Value::String("x".repeat(size)));
        }
    }

    #[test]
    fn arrays_round_trip_across_collection_boundaries() {
        for &size in COLLECTION_SIZES {
            let value = Value::Array(
                (0..size)
                    .map(|index| match index % 4 {
                        0 => Value::Null,
                        1 => Value::Bool(index % 2 == 0),
                        2 => Value::Int(index as i64),
                        _ => Value::String(format!("value-{index}")),
                    })
                    .collect(),
            );
            roundtrip(&value);
        }
    }

    #[test]
    fn objects_round_trip_across_collection_boundaries() {
        for &size in COLLECTION_SIZES {
            let value = Value::Object(
                (0..size)
                    .map(|index| {
                        (
                            format!("key-{index:05}"),
                            Value::Array(vec![
                                Value::Int(index as i64),
                                Value::String(format!("value-{index}")),
                            ]),
                        )
                    })
                    .collect(),
            );
            roundtrip(&value);
        }
    }

    #[test]
    fn rows_round_trip_across_collection_boundaries() {
        for &size in COLLECTION_SIZES {
            let row: Row = (0..size)
                .map(|index| {
                    (
                        format!("column-{index:05}"),
                        Value::Entity {
                            ty: format!("Type{}", index % 7),
                            id: format!("id-{index}"),
                        },
                    )
                })
                .collect();
            let mut buf = Vec::new();
            encode_row(&mut buf, &row);
            let mut reader = Reader::new(&buf);
            assert_eq!(
                decode_row(&mut reader).as_ref(),
                Some(&row),
                "row of size {size} changed"
            );
            assert!(reader.at_end(), "row of size {size} left trailing bytes");
        }
    }

    #[test]
    fn row_and_time_row_round_trip() {
        let row: Row = vec![
            ("user".to_string(), Value::String("alice".into())),
            ("n".to_string(), Value::Int(3)),
        ];
        let mut buf = Vec::new();
        encode_row(&mut buf, &row);
        let mut r = Reader::new(&buf);
        assert_eq!(decode_row(&mut r).unwrap(), row);
        assert!(r.at_end());

        for tr in [None, Some(row.clone())] {
            let mut b = Vec::new();
            encode_time_row(&mut b, &tr);
            let mut r = Reader::new(&b);
            assert_eq!(decode_time_row(&mut r).unwrap(), tr);
            assert!(r.at_end());
        }
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let mut buf = Vec::new();
        encode_value(&mut buf, &Value::String("abc".into()));
        buf.truncate(buf.len() - 1); // corrupt
        let mut r = Reader::new(&buf);
        assert!(decode_value(&mut r).is_none());
    }

    #[test]
    fn impossible_lengths_reject_without_panicking() {
        let mut cases = Vec::new();
        for tag in [3u8, 4, 6, 7] {
            let mut encoded = vec![tag];
            put_u64(&mut encoded, u64::MAX);
            cases.push(encoded);
        }

        for encoded in cases {
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                decode_value(&mut Reader::new(&encoded))
            }));
            assert!(attempt.is_ok(), "malformed value length panicked");
            assert!(attempt.unwrap().is_none(), "malformed value decoded");
        }

        let mut encoded_row = Vec::new();
        put_u64(&mut encoded_row, u64::MAX);
        let attempt = catch_unwind(AssertUnwindSafe(|| {
            decode_row(&mut Reader::new(&encoded_row))
        }));
        assert!(attempt.is_ok(), "malformed row length panicked");
        assert!(attempt.unwrap().is_none(), "malformed row decoded");
    }
}
