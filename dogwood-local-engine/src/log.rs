//! The durable event log — a redb-backed, append-only, ordered store of opaque
//! records.
//!
//! # Payload-agnostic by design
//!
//! This log stores **opaque byte records** keyed by a monotonic `u64`
//! offset. A caller encodes its record to bytes, appends, and on recovery
//! decodes each record back.
//!
//! That extends to *kinds* of record. A caller that logs more than events — a
//! server also recording its policy changes, so that an install and the events
//! around it share one order — puts the discriminant in its own payload. This
//! log neither knows nor needs to know, and every record is retained and pruned
//! alike.
//!
//! # Guarantees (the "serious" bar)
//!
//! - **Durable atomic append**: [`append`](DurableLog::append) commits the new
//!   record in one redb write transaction with `Durability::Immediate` (fsync
//!   before returning).
//! - **Durable atomic *write set***: [`commit`](DurableLog::commit) puts several
//!   writes in one such transaction, so facts that must not be seen apart never
//!   are.
//! - **Total order**: offsets are strictly increasing; the log defines the one
//!   order of records.
//! - **Recovery**: [`scan_from`](DurableLog::scan_from) replays records in
//!   offset order for rebuilding derived state.
//! - **Prunable, in bounded steps**: [`prune_below`](DurableLog::prune_below)
//!   reclaims a prefix without ever holding a long write
//!   transaction.
//! - **Snapshot slot**: a reserved slot holds the latest snapshot pointer
//!   (offset + opaque payload) so recovery can start mid-log.
//!
//! # Sharing
//!
//! Every method takes `&self`, so an appending request path and a background
//! snapshotter can hold one `Arc<DurableLog>` with no outer mutex. redb permits
//! a single write transaction at a time, so writes serialize inside — which is
//! why no method here holds a transaction open for unbounded work.

#[cfg(not(feature = "shuttle"))]
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::path::Path;
#[cfg(feature = "fault-injection")]
use std::sync::Arc;

use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, StorageBackend, TableDefinition,
    WriteTransaction as RedbWriteTransaction,
};
use thiserror::Error;

#[cfg(feature = "fault-injection")]
use crate::fault_injection::{FaultInjector, FaultPoint, StorageFailurePoint};
use crate::sync::{AtomicU64, Mutex, Ordering, storage_boundary};

/// The append-only record table: monotonic `u64` offset → opaque record bytes.
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("dogwood_log");
/// The metadata table: small fixed keys → bytes.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("dogwood_meta");

/// The metadata key holding the latest snapshot record: an 8-byte big-endian
/// offset followed by the opaque payload.
const SNAPSHOT_KEY: &str = "snapshot";
/// The metadata key holding the next offset to assign.
const NEXT_OFFSET_KEY: &str = "next_offset";
/// The metadata key holding the prune watermark.
const BASE_OFFSET_KEY: &str = "base_offset";

/// Maximum number of owned records materialized by one bounded read.
///
/// The byte budget alone cannot bound the outer `Vec`: empty records consume no
/// payload bytes but still need one offset and one vector descriptor each.
const MAX_READ_BATCH_RECORDS: usize = 16 * 1024;

/// Keys this log owns. A caller writing one would corrupt recovery, so
/// [`Write::Meta`] rejects them.
const RESERVED_KEYS: [&str; 3] = [SNAPSHOT_KEY, NEXT_OFFSET_KEY, BASE_OFFSET_KEY];

/// A failure operating the durable log.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum LogError {
    #[error("open durable log: {0}")]
    Open(#[source] redb::DatabaseError),
    #[error("durable log transaction: {0}")]
    Txn(#[source] redb::TransactionError),
    #[error("durable log table: {0}")]
    Table(#[source] redb::TableError),
    #[error("durable log storage: {0}")]
    Storage(#[source] redb::StorageError),
    #[error("durable log commit: {0}")]
    Commit(#[source] redb::CommitError),
    #[error("corrupt snapshot record: {0}")]
    CorruptSnapshot(String),
    #[error("metadata key `{0}` is reserved by the log")]
    ReservedMetaKey(String),
    #[error("durability: {0}")]
    Durability(String),
    #[error("durable log writer lock is poisoned")]
    WriterPoisoned,
    #[error("prune limit must be greater than zero")]
    ZeroPruneLimit,
    #[cfg(feature = "fault-injection")]
    #[error("injected storage failure at {0:?}")]
    InjectedStorageFailure(StorageFailurePoint),
    /// A snapshot claiming to summarize records that do not exist, or a prune
    /// reaching past the end of the log. Either would make recovery skip real
    /// records, so both are refused rather than stored.
    #[error("offset {offset} is beyond the end of the log ({next_offset})")]
    OffsetBeyondEnd { offset: u64, next_offset: u64 },
}

#[cfg(feature = "shuttle")]
type StorageWriterGuard<'a> = shuttle::sync::MutexGuard<'a, ()>;
#[cfg(not(feature = "shuttle"))]
type StorageWriterGuard<'a> = PhantomData<&'a ()>;

/// Dogwood's local write-transaction abstraction.
///
/// Shuttle cannot observe redb's internal single-writer condition variable.
/// Its build therefore retains a scheduler-aware mirror guard for exactly the
/// lifetime redb reserves its writer slot. Production carries only a zero-sized
/// lifetime marker and uses redb's transaction directly.
struct WriteTransaction<'a> {
    inner: Option<RedbWriteTransaction>,
    _writer: StorageWriterGuard<'a>,
}

impl Deref for WriteTransaction<'_> {
    type Target = RedbWriteTransaction;

    fn deref(&self) -> &Self::Target {
        self.inner
            .as_ref()
            .expect("write transaction is present until commit")
    }
}

impl DerefMut for WriteTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
            .as_mut()
            .expect("write transaction is present until commit")
    }
}

impl WriteTransaction<'_> {
    fn commit(mut self) -> Result<(), redb::CommitError> {
        // `self` (and therefore `_writer`) remains alive until redb's commit
        // returns. Taking the inner transaction prevents Drop from aborting it.
        self.inner
            .take()
            .expect("write transaction may commit only once")
            .commit()
    }
}

impl Drop for WriteTransaction<'_> {
    fn drop(&mut self) {
        // Abort an uncommitted redb transaction before releasing its mirrored
        // writer reservation.
        drop(self.inner.take());
    }
}

/// Scheduler-visible mirror of redb's single-writer reservation.
struct StorageWriter {
    #[cfg(feature = "shuttle")]
    gate: Mutex<()>,
}

impl StorageWriter {
    fn new() -> Self {
        Self {
            #[cfg(feature = "shuttle")]
            gate: Mutex::new(()),
        }
    }

    /// Acquire the Shuttle mirror and redb's real writer reservation as one
    /// inseparable operation. Do not expose or acquire `gate` separately: it
    /// models only redb's transaction lifetime, while [`DurableLog::writer`]
    /// protects Dogwood's cached-read-through-publication protocol.
    fn begin<'a>(&'a self, db: &Database) -> Result<WriteTransaction<'a>, LogError> {
        // Let Shuttle choose which contender reaches redb's writer reservation.
        storage_boundary();
        #[cfg(feature = "shuttle")]
        let writer = self.gate.lock().map_err(|_| LogError::WriterPoisoned)?;
        let inner = db.begin_write().map_err(LogError::Txn)?;
        Ok(WriteTransaction {
            inner: Some(inner),
            #[cfg(feature = "shuttle")]
            _writer: writer,
            #[cfg(not(feature = "shuttle"))]
            _writer: PhantomData,
        })
    }
}

fn commit_write(txn: WriteTransaction<'_>) -> Result<(), LogError> {
    storage_boundary();
    txn.commit().map_err(LogError::Commit)
}

/// A snapshot of derived state: the offset it summarizes, and an opaque payload.
///
/// The payload must carry everything needed to *interpret* the state, not just
/// the state — for a policy-bearing caller, which policy was in force, and any
/// fingerprint identifying the shape the bytes were serialized for. The log
/// guarantees only that the two are written together and read back together;
/// it never looks inside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Recovery replays records with offset `>= up_to_offset`.
    pub up_to_offset: u64,
    /// The caller's serialized derived state, plus whatever it needs to
    /// interpret it.
    pub payload: Vec<u8>,
}

/// One write in a [`commit`](DurableLog::commit) set.
pub enum Write<'a> {
    /// Append a record, assigning it the next offset.
    Append(&'a [u8]),
    /// Store an opaque value under a caller-chosen metadata key.
    Meta { key: &'a str, value: &'a [u8] },
    /// Replace the snapshot slot.
    Snapshot(&'a Snapshot),
}

/// The outcome of a [`prune_below`](DurableLog::prune_below) step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pruned {
    /// Records removed by this call.
    pub removed: usize,
    /// `false` if the per-call limit was reached before `below`; call again.
    pub done: bool,
    /// The prune watermark after this call.
    pub base_offset: u64,
}

/// One bounded read of a stable log range.
pub(crate) struct ReadBatch {
    /// Owned records in ascending offset order.
    pub(crate) records: Vec<(u64, Vec<u8>)>,
    /// The first offset not represented by this batch.
    pub(crate) next_offset: u64,
}

/// A durable, ordered, append-only log of opaque records over redb.
pub struct DurableLog {
    db: Database,
    /// Mirrors redb's writer reservation only in Shuttle builds.
    storage_writer: StorageWriter,
    /// Covers cached offset/watermark selection through durable commit and
    /// publication for every write operation.
    ///
    /// redb serializes write transactions, but offset selection happens before
    /// a transaction and the in-memory watermark is published after it. This
    /// gate makes those three steps one writer protocol.
    writer: Mutex<()>,
    /// Test-only controller for pausing at redb transaction boundaries.
    #[cfg(feature = "fault-injection")]
    faults: Option<Arc<FaultInjector>>,
    /// The next offset to assign.
    ///
    /// **Persisted**, not derived from the highest surviving record. Pruning can
    /// empty the table entirely, and a derived counter would then restart at 0
    /// and reissue offsets *below* the snapshot watermark — so recovery, which
    /// starts at that watermark, would skip those records and silently lose the
    /// history they carry.
    next_offset: AtomicU64,
    /// The offset below which records have been pruned.
    ///
    /// **Persisted** so recovery can tell a complete replay from a truncated
    /// one. Without it, a caller whose snapshot is missing or unusable falls
    /// back to "replay from 0" and reconstructs partial state without noticing.
    base_offset: AtomicU64,
}

impl DurableLog {
    /// Open (creating if absent) the durable log at `path`.
    ///
    /// Recovers both offsets from their slots.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LogError> {
        Self::from_database(Database::create(path).map_err(LogError::Open)?)
    }

    /// Create an empty, in-memory log.
    ///
    /// The log has the same transactional and ordering semantics as a
    /// file-backed log, but its contents are lost when it is dropped and cannot
    /// survive a process crash.
    pub fn ephemeral() -> Result<Self, LogError> {
        Self::open_with_backend(redb::backends::InMemoryBackend::new())
    }

    /// Open a log over a supplied [`StorageBackend`] instead of a file.
    ///
    /// Recovery is identical to [`open`](Self::open) — the backend only decides
    /// where the bytes live. Two things this makes possible:
    ///
    /// * **An ephemeral log.** redb's `InMemoryBackend` holds the store in
    ///   memory, where `sync_data` is a no-op, so a store costs no fsyncs.
    /// * **Opening a frozen image.** A caller that owns the bytes can copy them
    ///   at any instant and open *this* constructor over the copy. That models a
    ///   crash, which reopening a file cannot: dropping a file-backed
    ///   [`Database`] lets redb shut down cleanly (it is the one point
    ///   [`StorageBackend::close`] is called), so a reopen after a drop
    ///   exercises restart, not recovery. Freezing the bytes *before* teardown
    ///   and opening them here keeps the two distinct.
    ///
    /// This stays private: accepting redb's backend trait publicly would expose
    /// the log's storage implementation as a consumer API.
    fn open_with_backend(backend: impl StorageBackend) -> Result<Self, LogError> {
        Self::from_database(
            Database::builder()
                .create_with_backend(backend)
                .map_err(LogError::Open)?,
        )
    }

    /// Recover both offsets from an already-open database.
    ///
    /// Shared by both constructors, so neither can drift from the other — in
    /// particular neither can skip persisting a derived `next_offset`.
    fn from_database(db: Database) -> Result<Self, LogError> {
        let storage_writer = StorageWriter::new();
        // The write txn MUST be committed — an uncommitted `open_table` rolls
        // back, leaving the table absent for later read transactions.
        let mut txn = storage_writer.begin(&db)?;
        txn.set_durability(Durability::Immediate)
            .map_err(|e| LogError::Durability(e.to_string()))?;
        let (next_offset, base_offset) = {
            let log = txn.open_table(LOG).map_err(LogError::Table)?;
            let mut meta = txn.open_table(META).map_err(LogError::Table)?;

            let read =
                |m: &redb::Table<'_, &str, &[u8]>, key: &str| -> Result<Option<u64>, LogError> {
                    let Some(v) = m.get(key).map_err(LogError::Storage)? else {
                        return Ok(None);
                    };
                    let bytes = v.value();
                    if bytes.len() != 8 {
                        return Err(LogError::CorruptSnapshot(format!(
                            "metadata `{key}` is {} bytes, expected 8",
                            bytes.len()
                        )));
                    }
                    let mut b = [0u8; 8];
                    b.copy_from_slice(bytes);
                    Ok(Some(u64::from_be_bytes(b)))
                };

            let next = match read(&meta, NEXT_OFFSET_KEY)? {
                Some(v) => v,
                None => match log.last().map_err(LogError::Storage)? {
                    Some((k, _)) => k.value() + 1,
                    None => 0,
                },
            };
            let base = read(&meta, BASE_OFFSET_KEY)?.unwrap_or(0);
            meta.insert(NEXT_OFFSET_KEY, &next.to_be_bytes()[..])
                .map_err(LogError::Storage)?;
            meta.insert(BASE_OFFSET_KEY, &base.to_be_bytes()[..])
                .map_err(LogError::Storage)?;
            (next, base)
        };
        commit_write(txn)?;

        Ok(DurableLog {
            db,
            storage_writer,
            writer: Mutex::new(()),
            #[cfg(feature = "fault-injection")]
            faults: None,
            next_offset: AtomicU64::new(next_offset),
            base_offset: AtomicU64::new(base_offset),
        })
    }

    #[cfg(feature = "fault-injection")]
    pub(crate) fn set_fault_injector(&mut self, faults: Option<Arc<FaultInjector>>) {
        self.faults = faults;
    }

    #[cfg(feature = "fault-injection")]
    fn reach(&self, point: FaultPoint) {
        if let Some(faults) = &self.faults {
            faults.reach(point);
        }
    }

    #[cfg(feature = "fault-injection")]
    fn fail_if_armed(&self, point: StorageFailurePoint) -> Result<(), LogError> {
        if self
            .faults
            .as_ref()
            .is_some_and(|faults| faults.should_fail(point))
        {
            return Err(LogError::InjectedStorageFailure(point));
        }
        Ok(())
    }

    /// The offset the next [`append`](Self::append) will assign.
    pub fn next_offset(&self) -> u64 {
        self.next_offset.load(Ordering::SeqCst)
    }

    /// The prune watermark: no record below this exists any more.
    ///
    /// Recovery must not expect to replay from before this point. A caller with
    /// no usable snapshot at or above it cannot reconstruct its state and should
    /// say so rather than proceed with a hole in the history.
    pub fn base_offset(&self) -> u64 {
        self.base_offset.load(Ordering::SeqCst)
    }

    /// Durably append one record, returning its assigned offset. Commits with
    /// `Durability::Immediate` (fsync) so the record survives a crash before
    /// this returns — the atomic transaction boundary.
    ///
    /// The single-write fast path; equivalent to a one-element
    /// [`commit`](Self::commit) without building a slice.
    pub fn append(&self, record: &[u8]) -> Result<u64, LogError> {
        let _writer = self.writer.lock().map_err(|_| LogError::WriterPoisoned)?;
        let offset = self.next_offset.load(Ordering::SeqCst);
        let mut txn = self.storage_writer.begin(&self.db)?;
        txn.set_durability(Durability::Immediate)
            .map_err(|e| LogError::Durability(e.to_string()))?;
        {
            let mut log = txn.open_table(LOG).map_err(LogError::Table)?;
            log.insert(offset, record).map_err(LogError::Storage)?;
            let mut meta = txn.open_table(META).map_err(LogError::Table)?;
            meta.insert(NEXT_OFFSET_KEY, &(offset + 1).to_be_bytes()[..])
                .map_err(LogError::Storage)?;
        }
        // Keep these hooks adjacent to commit: before it neither the record nor
        // offset is durable; after it both are durable but unpublished in memory.
        #[cfg(feature = "fault-injection")]
        self.reach(FaultPoint::AppendBeforeCommit);
        commit_write(txn)?;
        #[cfg(feature = "fault-injection")]
        self.reach(FaultPoint::AppendAfterCommit);
        self.next_offset.store(offset + 1, Ordering::SeqCst);
        Ok(offset)
    }

    /// Commit several writes in **one** transaction with one fsync: all of them
    /// or none. Returns the offsets assigned to each [`Write::Append`], in order.
    ///
    /// This takes a set rather than handing out a transaction handle on purpose.
    /// A handle lets a caller commit a snapshot without the record that explains
    /// it, or a policy without the state derived under it — and a crash between
    /// two such commits leaves a combination recovery was never written to
    /// expect. Passing the whole set makes the partial state unrepresentable.
    ///
    /// Rejects a snapshot whose `up_to_offset` exceeds the end of the log, since
    /// recovery starting there would skip records that really exist.
    pub fn commit(&self, writes: &[Write<'_>]) -> Result<Vec<u64>, LogError> {
        for w in writes {
            match w {
                Write::Meta { key, .. } if RESERVED_KEYS.contains(key) => {
                    return Err(LogError::ReservedMetaKey((*key).to_string()));
                }
                _ => {}
            }
        }

        let _writer = self.writer.lock().map_err(|_| LogError::WriterPoisoned)?;
        let start = self.next_offset.load(Ordering::SeqCst);
        let appends = writes
            .iter()
            .filter(|w| matches!(w, Write::Append(_)))
            .count() as u64;
        let end = start + appends;
        for w in writes {
            if let Write::Snapshot(snap) = w
                && snap.up_to_offset > end
            {
                return Err(LogError::OffsetBeyondEnd {
                    offset: snap.up_to_offset,
                    next_offset: end,
                });
            }
        }

        let mut assigned = Vec::with_capacity(appends as usize);
        let mut txn = self.storage_writer.begin(&self.db)?;
        txn.set_durability(Durability::Immediate)
            .map_err(|e| LogError::Durability(e.to_string()))?;
        {
            let mut log = txn.open_table(LOG).map_err(LogError::Table)?;
            let mut meta = txn.open_table(META).map_err(LogError::Table)?;
            let mut offset = start;
            for w in writes {
                match w {
                    Write::Append(record) => {
                        log.insert(offset, *record).map_err(LogError::Storage)?;
                        assigned.push(offset);
                        offset += 1;
                    }
                    Write::Meta { key, value } => {
                        meta.insert(*key, *value).map_err(LogError::Storage)?;
                    }
                    Write::Snapshot(snap) => {
                        meta.insert(SNAPSHOT_KEY, encode_snapshot(snap).as_slice())
                            .map_err(LogError::Storage)?;
                    }
                }
            }
            if appends > 0 {
                meta.insert(NEXT_OFFSET_KEY, &offset.to_be_bytes()[..])
                    .map_err(LogError::Storage)?;
            }
        }
        // A checkpoint uses this multi-write path. These hooks distinguish an
        // entirely uncommitted write set from one durably committed as a unit.
        #[cfg(feature = "fault-injection")]
        self.reach(FaultPoint::CommitBeforeCommit);
        #[cfg(feature = "fault-injection")]
        self.fail_if_armed(StorageFailurePoint::CommitBeforeCommit)?;
        commit_write(txn)?;
        #[cfg(feature = "fault-injection")]
        self.reach(FaultPoint::CommitAfterCommit);
        if appends > 0 {
            self.next_offset.store(end, Ordering::SeqCst);
        }
        Ok(assigned)
    }

    /// Replay records with offset `>= from`, in ascending offset order, calling
    /// `f(offset, record)` for each. Used at recovery to rebuild derived state.
    pub fn scan_from(&self, from: u64, mut f: impl FnMut(u64, &[u8])) -> Result<(), LogError> {
        let txn = self.db.begin_read().map_err(LogError::Txn)?;
        let log = txn.open_table(LOG).map_err(LogError::Table)?;
        for entry in log.range(from..).map_err(LogError::Storage)? {
            let (k, v) = entry.map_err(LogError::Storage)?;
            f(k.value(), v.value());
        }
        Ok(())
    }

    /// Read an owned batch from the stable range `[from, until)`.
    ///
    /// The sum of record payload lengths does not exceed `max_bytes`, and no
    /// batch contains more than [`MAX_READ_BATCH_RECORDS`] records. The byte
    /// limit has one exception: when the first available record is itself
    /// larger, it is returned alone so every call over a nonempty range advances
    /// the cursor.
    pub(crate) fn read_batch(
        &self,
        from: u64,
        until: u64,
        max_bytes: NonZeroUsize,
    ) -> Result<ReadBatch, LogError> {
        if from >= until {
            return Ok(ReadBatch {
                records: Vec::new(),
                next_offset: from,
            });
        }

        let txn = self.db.begin_read().map_err(LogError::Txn)?;
        let log = txn.open_table(LOG).map_err(LogError::Table)?;
        let mut records = Vec::new();
        let mut used_bytes = 0usize;
        for entry in log.range(from..until).map_err(LogError::Storage)? {
            let (key, value) = entry.map_err(LogError::Storage)?;
            if records.len() == MAX_READ_BATCH_RECORDS {
                break;
            }
            let record = value.value();
            let fits = used_bytes
                .checked_add(record.len())
                .is_some_and(|total| total <= max_bytes.get());
            if !fits && !records.is_empty() {
                break;
            }
            used_bytes = used_bytes.saturating_add(record.len());
            records.push((key.value(), record.to_vec()));
        }
        let next_offset = records
            .last()
            .map(|(offset, _)| offset + 1)
            .unwrap_or(until);
        Ok(ReadBatch {
            records,
            next_offset,
        })
    }

    /// Drop up to `max_records` records below `below`, advancing the persisted
    /// prune watermark in the same transaction. Call until [`Pruned::done`].
    ///
    /// Bounded per call because redb allows one writer: deleting a whole window
    /// in a single transaction would block every append for its duration, and a
    /// background snapshotter must not do that. Pruning is idempotent and
    /// monotone, so stopping part-way — or crashing part-way — is always safe:
    /// surviving records below a snapshot's `up_to_offset` are skipped on
    /// replay, never re-applied.
    ///
    /// The caller is responsible for pruning only records it can justify
    /// dropping: summarized by a durable snapshot. The log cannot check that,
    /// so it enforces only that `below` is within the log.
    pub fn prune_below(&self, below: u64, max_records: usize) -> Result<Pruned, LogError> {
        if max_records == 0 {
            return Err(LogError::ZeroPruneLimit);
        }
        let _writer = self.writer.lock().map_err(|_| LogError::WriterPoisoned)?;
        let next = self.next_offset.load(Ordering::SeqCst);
        if below > next {
            return Err(LogError::OffsetBeyondEnd {
                offset: below,
                next_offset: next,
            });
        }
        let base = self.base_offset.load(Ordering::SeqCst);
        if below <= base {
            return Ok(Pruned {
                removed: 0,
                done: true,
                base_offset: base,
            });
        }

        let mut txn = self.storage_writer.begin(&self.db)?;
        txn.set_durability(Durability::Immediate)
            .map_err(|e| LogError::Durability(e.to_string()))?;
        let (removed, new_base, done) = {
            let mut log = txn.open_table(LOG).map_err(LogError::Table)?;
            // Collect first: the range iterator borrows the table immutably.
            let doomed: Vec<u64> = log
                .range(base..below)
                .map_err(LogError::Storage)?
                .filter_map(|e| e.ok().map(|(k, _)| k.value()))
                .take(max_records)
                .collect();
            let exhausted_range = doomed.len() < max_records;
            // Everything below this is gone: one past the last we removed, or
            // `below` itself once nothing is left in range.
            let new_base = if exhausted_range {
                below
            } else {
                doomed.last().map(|k| k + 1).unwrap_or(base)
            };
            let done = new_base == below;
            for k in &doomed {
                log.remove(*k).map_err(LogError::Storage)?;
            }
            let mut meta = txn.open_table(META).map_err(LogError::Table)?;
            meta.insert(BASE_OFFSET_KEY, &new_base.to_be_bytes()[..])
                .map_err(LogError::Storage)?;
            (doomed.len(), new_base, done)
        };
        // Prune fault points surround the transaction that atomically deletes
        // one bounded prefix and advances its persisted watermark. They are
        // separate from the generic multi-write hooks so a concurrent append
        // cannot consume a prune crash injection.
        #[cfg(feature = "fault-injection")]
        self.fail_if_armed(StorageFailurePoint::PruneBeforeCommit)?;
        #[cfg(feature = "fault-injection")]
        self.reach(FaultPoint::PruneBeforeCommit);
        commit_write(txn)?;
        #[cfg(feature = "fault-injection")]
        self.fail_if_armed(StorageFailurePoint::PruneAfterCommit)?;
        #[cfg(feature = "fault-injection")]
        self.reach(FaultPoint::PruneAfterCommit);
        self.base_offset.store(new_base, Ordering::SeqCst);
        Ok(Pruned {
            removed,
            done,
            base_offset: new_base,
        })
    }

    /// Read the opaque value stored under metadata `key`, or `None` if unset.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, LogError> {
        let txn = self.db.begin_read().map_err(LogError::Txn)?;
        let meta = txn.open_table(META).map_err(LogError::Table)?;
        Ok(meta
            .get(key)
            .map_err(LogError::Storage)?
            .map(|v| v.value().to_vec()))
    }

    /// The latest stored snapshot, if any.
    pub fn get_snapshot(&self) -> Result<Option<Snapshot>, LogError> {
        let txn = self.db.begin_read().map_err(LogError::Txn)?;
        let meta = txn.open_table(META).map_err(LogError::Table)?;
        let Some(raw) = meta.get(SNAPSHOT_KEY).map_err(LogError::Storage)? else {
            return Ok(None);
        };
        decode_snapshot(raw.value()).map(Some)
    }
}

fn encode_snapshot(snap: &Snapshot) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + snap.payload.len());
    buf.extend_from_slice(&snap.up_to_offset.to_be_bytes());
    buf.extend_from_slice(&snap.payload);
    buf
}

fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, LogError> {
    if bytes.len() < 8 {
        return Err(LogError::CorruptSnapshot(format!(
            "snapshot record too short: {} bytes",
            bytes.len()
        )));
    }
    let mut off = [0u8; 8];
    off.copy_from_slice(&bytes[..8]);
    Ok(Snapshot {
        up_to_offset: u64::from_be_bytes(off),
        payload: bytes[8..].to_vec(),
    })
}

#[cfg(test)]
mod backend_tests;

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    #[cfg(feature = "fault-injection")]
    use std::sync::Arc;
    #[cfg(feature = "fault-injection")]
    use std::time::Duration;

    #[cfg(feature = "fault-injection")]
    use crate::fault_injection::{FaultInjector, FaultPoint, StorageFailurePoint};

    use super::*;

    /// A unique temp path under the system temp dir (no external tempdir dep).
    fn temp_db(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "dogwood_log_test_{tag}_{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn append_assigns_monotonic_offsets_and_scans_in_order() {
        let path = temp_db("append");
        let log = DurableLog::open(&path).expect("open");
        assert_eq!(log.append(b"a").unwrap(), 0);
        assert_eq!(log.append(b"b").unwrap(), 1);
        assert_eq!(log.append(b"c").unwrap(), 2);
        assert_eq!(log.next_offset(), 3);

        let mut seen = Vec::new();
        log.scan_from(0, |off, rec| seen.push((off, rec.to_vec())))
            .unwrap();
        assert_eq!(
            seen,
            vec![(0, b"a".to_vec()), (1, b"b".to_vec()), (2, b"c".to_vec())]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn append_before_commit_exposes_no_record() {
        let path = temp_db("append-before-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        log.set_fault_injector(Some(Arc::clone(&faults)));
        let log = Arc::new(log);
        faults.arm(FaultPoint::AppendBeforeCommit);

        let worker_log = Arc::clone(&log);
        let worker = std::thread::spawn(move || worker_log.append(b"pending"));
        assert!(faults.wait_until_reached(Duration::from_secs(1)));

        assert_eq!(log.next_offset(), 0);
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .expect("scan");
        assert!(records.is_empty());

        faults.release();
        assert_eq!(worker.join().expect("worker exits").expect("append"), 0);
        assert_eq!(log.next_offset(), 1);
        drop(log);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn append_after_commit_exposes_durable_record_before_publication() {
        let path = temp_db("append-after-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        log.set_fault_injector(Some(Arc::clone(&faults)));
        let log = Arc::new(log);
        faults.arm(FaultPoint::AppendAfterCommit);

        let worker_log = Arc::clone(&log);
        let worker = std::thread::spawn(move || worker_log.append(b"durable"));
        assert!(faults.wait_until_reached(Duration::from_secs(1)));

        assert_eq!(log.next_offset(), 0);
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .expect("scan");
        assert_eq!(records, vec![(0, b"durable".to_vec())]);

        faults.release();
        assert_eq!(worker.join().expect("worker exits").expect("append"), 0);
        assert_eq!(log.next_offset(), 1);
        drop(log);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn mixed_write_set_is_absent_before_commit() {
        let path = temp_db("mixed-before-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        log.set_fault_injector(Some(Arc::clone(&faults)));
        let log = Arc::new(log);
        faults.arm(FaultPoint::CommitBeforeCommit);

        let worker_log = Arc::clone(&log);
        let worker = std::thread::spawn(move || {
            let snapshot = Snapshot {
                up_to_offset: 1,
                payload: b"state".to_vec(),
            };
            worker_log.commit(&[
                Write::Append(b"record"),
                Write::Meta {
                    key: "owner",
                    value: b"metadata",
                },
                Write::Snapshot(&snapshot),
            ])
        });
        assert!(faults.wait_until_reached(Duration::from_secs(1)));

        assert_eq!(log.next_offset(), 0);
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .expect("scan");
        assert!(records.is_empty());
        assert_eq!(log.get_meta("owner").unwrap(), None);
        assert_eq!(log.get_snapshot().unwrap(), None);

        faults.release();
        assert_eq!(
            worker.join().expect("worker exits").expect("commit"),
            vec![0]
        );
        drop(log);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn mixed_write_set_is_durable_after_commit_before_publication() {
        let path = temp_db("mixed-after-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        log.set_fault_injector(Some(Arc::clone(&faults)));
        let log = Arc::new(log);
        faults.arm(FaultPoint::CommitAfterCommit);

        let worker_log = Arc::clone(&log);
        let worker = std::thread::spawn(move || {
            let snapshot = Snapshot {
                up_to_offset: 1,
                payload: b"state".to_vec(),
            };
            worker_log.commit(&[
                Write::Append(b"record"),
                Write::Meta {
                    key: "owner",
                    value: b"metadata",
                },
                Write::Snapshot(&snapshot),
            ])
        });
        assert!(faults.wait_until_reached(Duration::from_secs(1)));

        assert_eq!(log.next_offset(), 0);
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .expect("scan");
        assert_eq!(records, vec![(0, b"record".to_vec())]);
        assert_eq!(log.get_meta("owner").unwrap(), Some(b"metadata".to_vec()));
        assert_eq!(
            log.get_snapshot().unwrap(),
            Some(Snapshot {
                up_to_offset: 1,
                payload: b"state".to_vec(),
            })
        );

        faults.release();
        assert_eq!(
            worker.join().expect("worker exits").expect("commit"),
            vec![0]
        );
        assert_eq!(log.next_offset(), 1);
        drop(log);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reopen_recovers_next_offset() {
        let path = temp_db("reopen");
        {
            let log = DurableLog::open(&path).expect("open");
            log.append(b"x").unwrap();
            log.append(b"y").unwrap();
        }
        let log = DurableLog::open(&path).expect("reopen");
        assert_eq!(log.next_offset(), 2);
        assert_eq!(log.append(b"z").unwrap(), 2);
        let _ = std::fs::remove_file(&path);
    }

    /// **The offset counter must survive an emptied log.**
    ///
    /// Deriving it from the highest surviving record restarts it at 0 once
    /// pruning removes everything, so subsequent appends land *below* a
    /// snapshot's watermark and recovery — which starts at that watermark —
    /// skips them. Durable history, invisible to the monitor: a history-gated
    /// rule silently stops firing.
    #[test]
    fn the_offset_counter_survives_an_emptied_log() {
        let path = temp_db("emptied");
        {
            let log = DurableLog::open(&path).expect("open");
            log.append(b"a").unwrap();
            log.append(b"b").unwrap();
            let p = log.prune_below(2, 100).unwrap();
            assert!(p.done && p.removed == 2);
            let mut seen = 0;
            log.scan_from(0, |_, _| seen += 1).unwrap();
            assert_eq!(seen, 0, "fixture: the log is now empty");
        }
        let log = DurableLog::open(&path).expect("reopen");
        assert_eq!(log.next_offset(), 2, "must NOT restart at 0");
        assert_eq!(log.base_offset(), 2, "the prune watermark is durable too");
        assert_eq!(log.append(b"c").unwrap(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn scan_from_offset_skips_the_prefix() {
        let path = temp_db("scanfrom");
        let log = DurableLog::open(&path).expect("open");
        for i in 0..5u8 {
            log.append(&[i]).unwrap();
        }
        let mut seen = Vec::new();
        log.scan_from(3, |off, _| seen.push(off)).unwrap();
        assert_eq!(seen, vec![3, 4]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_batch_honors_byte_boundaries_and_makes_oversized_progress() {
        let path = temp_db("read_batch_boundaries");
        let log = DurableLog::open(&path).expect("open");
        for record in [b"aa".as_slice(), b"bbb", b"cccc", b"d"] {
            log.append(record).expect("append fixture");
        }

        let exact = log
            .read_batch(0, 4, NonZeroUsize::new(5).unwrap())
            .expect("read exact batch");
        assert_eq!(
            exact.records,
            vec![(0, b"aa".to_vec()), (1, b"bbb".to_vec())]
        );
        assert_eq!(exact.next_offset, 2);

        let before_oversized = log
            .read_batch(exact.next_offset, 4, NonZeroUsize::new(3).unwrap())
            .expect("read oversized batch");
        assert_eq!(
            before_oversized.records,
            vec![(2, b"cccc".to_vec())],
            "the first record must be returned alone when it exceeds the limit"
        );
        assert_eq!(before_oversized.next_offset, 3);

        let tail = log
            .read_batch(
                before_oversized.next_offset,
                4,
                NonZeroUsize::new(3).unwrap(),
            )
            .expect("read tail");
        assert_eq!(tail.records, vec![(3, b"d".to_vec())]);
        assert_eq!(tail.next_offset, 4);

        let empty = log
            .read_batch(4, 4, NonZeroUsize::new(3).unwrap())
            .expect("read empty tail");
        assert!(empty.records.is_empty());
        assert_eq!(empty.next_offset, 4);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn repeated_read_batches_cover_the_stable_range_exactly_once() {
        let path = temp_db("read_batch_coverage");
        let log = DurableLog::open(&path).expect("open");
        let expected = vec![
            (0, b"a".to_vec()),
            (1, b"bc".to_vec()),
            (2, b"def".to_vec()),
            (3, b"ghijklmnop".to_vec()),
            (4, b"q".to_vec()),
        ];
        for (_, record) in &expected {
            log.append(record).expect("append fixture");
        }
        let end = log.next_offset();

        for max_bytes in [1, 2, 3, 4, 5, 10, 11, 64] {
            let mut cursor = 0;
            let mut actual = Vec::new();
            while cursor < end {
                let batch = log
                    .read_batch(cursor, end, NonZeroUsize::new(max_bytes).unwrap())
                    .expect("read bounded batch");
                assert!(
                    !batch.records.is_empty(),
                    "a nonempty stable range must make progress"
                );
                let bytes = batch
                    .records
                    .iter()
                    .map(|(_, record)| record.len())
                    .sum::<usize>();
                assert!(
                    bytes <= max_bytes || batch.records.len() == 1,
                    "batch used {bytes} bytes with a {max_bytes}-byte limit"
                );
                assert!(
                    batch.next_offset > cursor && batch.next_offset <= end,
                    "cursor must advance within the captured range"
                );
                cursor = batch.next_offset;
                actual.extend(batch.records);
            }
            assert_eq!(actual, expected, "coverage differs at limit {max_bytes}");
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_batch_stops_at_the_captured_range_end() {
        let path = temp_db("read_batch_stable_end");
        let log = DurableLog::open(&path).expect("open");
        log.append(b"before-0").expect("append fixture");
        log.append(b"before-1").expect("append fixture");
        let captured_end = log.next_offset();
        log.append(b"after").expect("append after capture");

        let batch = log
            .read_batch(0, captured_end, NonZeroUsize::new(usize::MAX).unwrap())
            .expect("read captured range");
        assert_eq!(
            batch.records,
            vec![(0, b"before-0".to_vec()), (1, b"before-1".to_vec())]
        );
        assert_eq!(batch.next_offset, captured_end);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_batch_caps_empty_record_count_and_preserves_coverage() {
        const EXPECTED_BATCH_RECORD_LIMIT: usize = 16_384;
        let log = DurableLog::ephemeral().expect("open ephemeral log");
        let record_count = EXPECTED_BATCH_RECORD_LIMIT + 3;
        let writes = (0..record_count)
            .map(|_| Write::Append(b""))
            .collect::<Vec<_>>();
        log.commit(&writes).expect("append empty fixture records");
        let end = log.next_offset();

        let first = log
            .read_batch(0, end, NonZeroUsize::new(usize::MAX).unwrap())
            .expect("read first count-bounded batch");
        assert_eq!(first.records.len(), EXPECTED_BATCH_RECORD_LIMIT);
        assert_eq!(
            first.next_offset, EXPECTED_BATCH_RECORD_LIMIT as u64,
            "the cursor must stop at the record-count boundary"
        );

        let second = log
            .read_batch(
                first.next_offset,
                end,
                NonZeroUsize::new(usize::MAX).unwrap(),
            )
            .expect("read remaining empty records");
        assert_eq!(second.records.len(), 3);
        assert_eq!(second.next_offset, end);

        let offsets = first
            .records
            .into_iter()
            .chain(second.records)
            .map(|(offset, record)| {
                assert!(record.is_empty());
                offset
            })
            .collect::<Vec<_>>();
        assert_eq!(offsets, (0..end).collect::<Vec<_>>());
    }

    #[test]
    fn prune_below_drops_the_prefix_only() {
        let path = temp_db("prune");
        let log = DurableLog::open(&path).expect("open");
        for i in 0..5u8 {
            log.append(&[i]).unwrap();
        }
        let p = log.prune_below(3, 100).unwrap();
        assert_eq!((p.removed, p.done, p.base_offset), (3, true, 3));
        let mut seen = Vec::new();
        log.scan_from(0, |off, _| seen.push(off)).unwrap();
        assert_eq!(seen, vec![3, 4], "records below 3 dropped, suffix intact");
        assert_eq!(log.next_offset(), 5, "pruning does not disturb the order");
        assert_eq!(log.append(b"5").unwrap(), 5);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn prune_before_commit_exposes_old_prefix_and_watermark() {
        let path = temp_db("prune-before-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        for value in 0..5u8 {
            log.append(&[value]).expect("seed record");
        }
        log.set_fault_injector(Some(Arc::clone(&faults)));
        let log = Arc::new(log);
        faults.arm(FaultPoint::PruneBeforeCommit);

        let worker_log = Arc::clone(&log);
        let worker = std::thread::spawn(move || worker_log.prune_below(4, 2));
        assert!(faults.wait_until_reached(Duration::from_secs(1)));

        assert_eq!(log.base_offset(), 0);
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .expect("scan");
        assert_eq!(
            records,
            vec![
                (0, vec![0]),
                (1, vec![1]),
                (2, vec![2]),
                (3, vec![3]),
                (4, vec![4]),
            ]
        );

        faults.release();
        assert_eq!(
            worker.join().expect("worker exits").expect("prune"),
            Pruned {
                removed: 2,
                done: false,
                base_offset: 2,
            }
        );
        drop(log);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn prune_after_commit_exposes_complete_chunk_before_publication() {
        let path = temp_db("prune-after-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        for value in 0..5u8 {
            log.append(&[value]).expect("seed record");
        }
        log.set_fault_injector(Some(Arc::clone(&faults)));
        let log = Arc::new(log);
        faults.arm(FaultPoint::PruneAfterCommit);

        let worker_log = Arc::clone(&log);
        let worker = std::thread::spawn(move || worker_log.prune_below(4, 2));
        assert!(faults.wait_until_reached(Duration::from_secs(1)));

        assert_eq!(
            log.base_offset(),
            0,
            "in-memory watermark is published after the hook"
        );
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .expect("scan");
        assert_eq!(
            records,
            vec![(2, vec![2]), (3, vec![3]), (4, vec![4])],
            "the entire bounded prune chunk is durable"
        );

        faults.release();
        assert_eq!(
            worker.join().expect("worker exits").expect("prune"),
            Pruned {
                removed: 2,
                done: false,
                base_offset: 2,
            }
        );
        assert_eq!(log.base_offset(), 2);
        drop(log);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_prune_failure_before_commit_aborts_and_releases_the_writer() {
        let path = temp_db("prune-failure-before-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        for value in 0..5u8 {
            log.append(&[value]).expect("seed record");
        }
        log.set_fault_injector(Some(Arc::clone(&faults)));
        faults.fail_on(StorageFailurePoint::PruneBeforeCommit, 1);

        assert!(matches!(
            log.prune_below(4, 2),
            Err(LogError::InjectedStorageFailure(
                StorageFailurePoint::PruneBeforeCommit
            ))
        ));
        assert_eq!(log.base_offset(), 0);
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .expect("scan");
        assert_eq!(
            records,
            vec![
                (0, vec![0]),
                (1, vec![1]),
                (2, vec![2]),
                (3, vec![3]),
                (4, vec![4]),
            ],
            "the staged prune transaction must abort completely"
        );

        assert_eq!(
            log.append(b"after-failure").expect("writer was released"),
            5
        );
        assert_eq!(
            log.prune_below(4, 2)
                .expect("one-shot failure permits retry"),
            Pruned {
                removed: 2,
                done: false,
                base_offset: 2,
            }
        );
        drop(log);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_failure_on_a_later_chunk_preserves_prior_progress_only() {
        let path = temp_db("prune-failure-later-chunk");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        for value in 0..6u8 {
            log.append(&[value]).expect("seed record");
        }
        log.set_fault_injector(Some(Arc::clone(&faults)));
        faults.fail_on(StorageFailurePoint::PruneBeforeCommit, 2);

        assert_eq!(
            log.prune_below(6, 2).expect("first chunk"),
            Pruned {
                removed: 2,
                done: false,
                base_offset: 2,
            }
        );
        assert!(matches!(
            log.prune_below(6, 2),
            Err(LogError::InjectedStorageFailure(
                StorageFailurePoint::PruneBeforeCommit
            ))
        ));
        assert_eq!(log.base_offset(), 2);
        let mut offsets = Vec::new();
        log.scan_from(0, |offset, _| offsets.push(offset))
            .expect("scan");
        assert_eq!(offsets, vec![2, 3, 4, 5]);

        drop(log);
        let reopened = DurableLog::open(&path).expect("reopen");
        assert_eq!(reopened.base_offset(), 2);
        let mut reopened_offsets = Vec::new();
        reopened
            .scan_from(0, |offset, _| reopened_offsets.push(offset))
            .expect("scan reopened");
        assert_eq!(reopened_offsets, offsets);
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_failure_after_commit_recovers_the_complete_chunk() {
        let path = temp_db("prune-failure-after-commit");
        let faults = Arc::new(FaultInjector::new());
        let mut log = DurableLog::open(&path).expect("open");
        for value in 0..5u8 {
            log.append(&[value]).expect("seed record");
        }
        log.set_fault_injector(Some(Arc::clone(&faults)));
        faults.fail_on(StorageFailurePoint::PruneAfterCommit, 1);

        assert!(matches!(
            log.prune_below(4, 2),
            Err(LogError::InjectedStorageFailure(
                StorageFailurePoint::PruneAfterCommit
            ))
        ));
        assert_eq!(
            log.base_offset(),
            0,
            "the ambiguous error occurs before in-memory publication"
        );
        let mut offsets = Vec::new();
        log.scan_from(0, |offset, _| offsets.push(offset))
            .expect("scan");
        assert_eq!(offsets, vec![2, 3, 4]);

        drop(log);
        let reopened = DurableLog::open(&path).expect("reopen");
        assert_eq!(reopened.base_offset(), 2);
        let mut reopened_offsets = Vec::new();
        reopened
            .scan_from(0, |offset, _| reopened_offsets.push(offset))
            .expect("scan reopened");
        assert_eq!(reopened_offsets, offsets);
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn exact_sized_prune_reports_completion() {
        let path = temp_db("exact-sized-prune");
        let log = DurableLog::open(&path).expect("open");
        log.append(b"a").unwrap();
        log.append(b"b").unwrap();

        let pruned = log.prune_below(2, 2).unwrap();
        assert_eq!(
            pruned,
            Pruned {
                removed: 2,
                done: true,
                base_offset: 2,
            }
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn zero_prune_limit_is_rejected_without_mutation() {
        let path = temp_db("zero-prune-limit");
        let log = DurableLog::open(&path).expect("open");
        log.append(b"a").unwrap();
        log.append(b"b").unwrap();

        let error = log.prune_below(2, 0).unwrap_err();
        assert!(matches!(error, LogError::ZeroPruneLimit));
        assert_eq!(log.base_offset(), 0);
        assert_eq!(log.next_offset(), 2);

        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .unwrap();
        assert_eq!(records, vec![(0, b"a".to_vec()), (1, b"b".to_vec())]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prune_beyond_end_is_rejected_without_mutation() {
        let path = temp_db("prune-beyond-end");
        let log = DurableLog::open(&path).expect("open");
        log.append(b"a").unwrap();
        log.append(b"b").unwrap();

        let error = log.prune_below(3, 1).unwrap_err();
        assert!(matches!(
            error,
            LogError::OffsetBeyondEnd {
                offset: 3,
                next_offset: 2,
            }
        ));
        assert_eq!(log.base_offset(), 0);
        assert_eq!(log.next_offset(), 2);

        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .unwrap();
        assert_eq!(records, vec![(0, b"a".to_vec()), (1, b"b".to_vec())]);
        let _ = std::fs::remove_file(&path);
    }

    /// Pruning in bounded steps is what keeps a background snapshotter from
    /// holding redb's single write transaction for a whole window.
    #[test]
    fn prune_is_chunked_and_resumable() {
        let path = temp_db("chunked");
        let log = DurableLog::open(&path).expect("open");
        for i in 0..10u8 {
            log.append(&[i]).unwrap();
        }
        let first = log.prune_below(8, 3).unwrap();
        assert_eq!(
            (first.removed, first.done, first.base_offset),
            (3, false, 3)
        );
        // Appends interleave between chunks.
        assert_eq!(log.append(b"x").unwrap(), 10);

        let mut total = first.removed;
        let mut guard = 0;
        loop {
            let p = log.prune_below(8, 3).unwrap();
            total += p.removed;
            guard += 1;
            assert!(guard < 10, "prune did not converge");
            if p.done {
                assert_eq!(p.base_offset, 8);
                break;
            }
        }
        assert_eq!(total, 8);
        let mut seen = Vec::new();
        log.scan_from(0, |off, _| seen.push(off)).unwrap();
        assert_eq!(seen, vec![8, 9, 10]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn snapshot_round_trips_and_survives_reopen() {
        let path = temp_db("snap");
        {
            let log = DurableLog::open(&path).expect("open");
            assert_eq!(log.get_snapshot().unwrap(), None);
            for _ in 0..8 {
                log.append(b".").unwrap();
            }
            log.commit(&[Write::Snapshot(&Snapshot {
                up_to_offset: 7,
                payload: vec![1, 2, 3],
            })])
            .unwrap();
        }
        let log = DurableLog::open(&path).expect("reopen");
        assert_eq!(
            log.get_snapshot().unwrap(),
            Some(Snapshot {
                up_to_offset: 7,
                payload: vec![1, 2, 3]
            })
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A write set is all-or-nothing: that is the whole reason it exists.
    #[test]
    fn a_commit_set_lands_together() {
        let path = temp_db("commitset");
        let log = DurableLog::open(&path).expect("open");
        let snap = Snapshot {
            up_to_offset: 1,
            payload: b"state".to_vec(),
        };
        let offsets = log
            .commit(&[
                Write::Append(b"record"),
                Write::Meta {
                    key: "bundle",
                    value: b"policy",
                },
                Write::Snapshot(&snap),
            ])
            .unwrap();
        assert_eq!(offsets, vec![0]);
        assert_eq!(log.next_offset(), 1);
        assert_eq!(log.get_meta("bundle").unwrap().unwrap(), b"policy");
        assert_eq!(log.get_snapshot().unwrap().unwrap(), snap);
        let _ = std::fs::remove_file(&path);
    }

    /// A snapshot summarizing records that do not exist would make recovery skip
    /// real ones, so it is refused rather than stored.
    #[test]
    fn a_snapshot_beyond_the_end_is_refused() {
        let path = temp_db("beyond");
        let log = DurableLog::open(&path).expect("open");
        log.append(b"a").unwrap();
        let err = log
            .commit(&[Write::Snapshot(&Snapshot {
                up_to_offset: 99,
                payload: vec![],
            })])
            .expect_err("must refuse");
        assert!(matches!(err, LogError::OffsetBeyondEnd { .. }), "{err}");
        // ...but one covering the appends in the SAME set is fine.
        log.commit(&[
            Write::Append(b"b"),
            Write::Snapshot(&Snapshot {
                up_to_offset: 2,
                payload: vec![],
            }),
        ])
        .expect("same-set append counts");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reserved_keys_are_refused() {
        let path = temp_db("reserved");
        let log = DurableLog::open(&path).expect("open");
        for key in ["snapshot", "next_offset", "base_offset"] {
            let err = log
                .commit(&[Write::Meta { key, value: b"x" }])
                .expect_err("must refuse");
            assert!(matches!(err, LogError::ReservedMetaKey(_)), "{err}");
        }
        let _ = std::fs::remove_file(&path);
    }
}
