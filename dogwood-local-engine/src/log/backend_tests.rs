//! [`DurableLog::open_with_backend`]: an ephemeral store, and recovery from a
//! byte image frozen at an arbitrary instant.
//!
//! The second is the one that needs proving. Reopening a *file* cannot model a
//! crash, because dropping the `Database` is exactly when redb is allowed to
//! shut down cleanly — so a reopen after a drop exercises restart. Freezing the
//! bytes before teardown and opening a fresh log over the copy is a cut the
//! process cannot influence afterwards, which is what these tests pin.

use std::io;
use std::sync::{Arc, Mutex};

use redb::StorageBackend;

use super::{DurableLog, Write};

/// An in-memory backend whose bytes the test owns, so they can be copied at any
/// instant and reopened.
///
/// redb ships `InMemoryBackend`, but it keeps its `Vec<u8>` private with no way
/// to seed or extract it, so it cannot express "recover from *these* bytes".
/// Sharing an `Arc<Mutex<Vec<u8>>>` with the caller is the whole difference.
///
/// Lives in this private test module because custom redb backends are an
/// implementation-level test seam, not a consumer API.
#[derive(Debug)]
struct SharedMem(Arc<Mutex<Vec<u8>>>);

impl SharedMem {
    fn empty() -> (Self, Arc<Mutex<Vec<u8>>>) {
        let image = Arc::new(Mutex::new(Vec::new()));
        (Self(Arc::clone(&image)), image)
    }

    /// A backend over a private copy of `bytes` — the recovering "process".
    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(bytes)))
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
        self.0.lock().expect("image mutex poisoned")
    }
}

impl StorageBackend for SharedMem {
    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.guard().len() as u64)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        let image = self.guard();
        let start = usize::try_from(offset).expect("offset fits usize");
        let end = start + out.len();
        if end > image.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read past end of image",
            ));
        }
        out.copy_from_slice(&image[start..end]);
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        // New space must read as zero, which `resize` guarantees.
        self.guard()
            .resize(usize::try_from(len).expect("len fits usize"), 0);
        Ok(())
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        // Nothing to flush: the image *is* the durable medium. This is why an
        // in-memory store costs no fsyncs.
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let mut image = self.guard();
        let start = usize::try_from(offset).expect("offset fits usize");
        let end = start + data.len();
        if end > image.len() {
            image.resize(end, 0);
        }
        image[start..end].copy_from_slice(data);
        Ok(())
    }
}

/// Collect every record from `from` onwards as `(offset, bytes)`.
fn records(log: &DurableLog, from: u64) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    log.scan_from(from, |offset, bytes| out.push((offset, bytes.to_vec())))
        .expect("scan");
    out
}

#[test]
fn ephemeral_logs_are_empty_and_isolated() {
    let first = DurableLog::ephemeral().expect("open first ephemeral log");
    assert_eq!(first.append(b"first").expect("append"), 0);
    assert_eq!(records(&first, 0), vec![(0, b"first".to_vec())]);

    let second = DurableLog::ephemeral().expect("open second ephemeral log");
    assert_eq!(second.next_offset(), 0);
    assert!(records(&second, 0).is_empty());
}

#[test]
fn a_log_on_a_caller_supplied_backend_round_trips() {
    let (backend, _image) = SharedMem::empty();
    let log = DurableLog::open_with_backend(backend).expect("open");

    assert_eq!(log.append(b"first").expect("append"), 0);
    assert_eq!(log.append(b"second").expect("append"), 1);

    assert_eq!(
        records(&log, 0),
        vec![(0, b"first".to_vec()), (1, b"second".to_vec())]
    );
    assert_eq!(log.next_offset(), 2);
    assert_eq!(log.base_offset(), 0);
}

#[test]
fn a_frozen_image_recovers_the_records_and_both_offsets() {
    let (backend, image) = SharedMem::empty();
    let log = DurableLog::open_with_backend(backend).expect("open");
    log.append(b"a").expect("append");
    log.append(b"b").expect("append");
    log.append(b"c").expect("append");

    // Freeze BEFORE teardown: this copy is what the next "process" recovers.
    let frozen = image.lock().expect("image").clone();
    drop(log);

    let recovered = DurableLog::open_with_backend(SharedMem::from_bytes(frozen)).expect("recover");
    assert_eq!(
        records(&recovered, 0),
        vec![(0, b"a".to_vec()), (1, b"b".to_vec()), (2, b"c".to_vec())]
    );
    // Persisted, not derived — a derived counter is the bug this guards.
    assert_eq!(recovered.next_offset(), 3);
    assert_eq!(recovered.base_offset(), 0);
}

#[test]
fn nothing_written_after_the_freeze_appears_in_the_recovered_image() {
    let (backend, image) = SharedMem::empty();
    let log = DurableLog::open_with_backend(backend).expect("open");
    log.append(b"before").expect("append");

    let frozen = image.lock().expect("image").clone();

    // The doomed process keeps going. In a crash these never reach the medium;
    // here they land in the *live* image, which nobody reads again.
    log.append(b"after-1").expect("append");
    log.append(b"after-2").expect("append");
    assert_eq!(log.next_offset(), 3, "the live log did advance");
    drop(log);

    let recovered = DurableLog::open_with_backend(SharedMem::from_bytes(frozen)).expect("recover");
    assert_eq!(
        records(&recovered, 0),
        vec![(0, b"before".to_vec())],
        "the freeze is a cut the process cannot reach past"
    );
    assert_eq!(recovered.next_offset(), 1);
}

#[test]
fn the_prune_watermark_survives_a_freeze() {
    let (backend, image) = SharedMem::empty();
    let log = DurableLog::open_with_backend(backend).expect("open");
    for i in 0..5u8 {
        log.append(&[i]).expect("append");
    }
    let pruned = log.prune_below(3, 1_000).expect("prune");
    assert!(pruned.done);
    assert_eq!(pruned.base_offset, 3);

    let frozen = image.lock().expect("image").clone();
    drop(log);

    // Both counters must come back from their slots. A recovery that read
    // "replay from 0" here would silently reconstruct partial state.
    let recovered = DurableLog::open_with_backend(SharedMem::from_bytes(frozen)).expect("recover");
    assert_eq!(recovered.base_offset(), 3);
    assert_eq!(recovered.next_offset(), 5);
    assert_eq!(
        records(&recovered, 0)
            .into_iter()
            .map(|(o, _)| o)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
}

#[test]
fn an_emptying_prune_does_not_restart_offsets_across_a_freeze() {
    // A prune can empty
    // the table, and a counter derived from the highest surviving record would
    // then restart at 0 and reissue offsets below the snapshot watermark.
    let (backend, image) = SharedMem::empty();
    let log = DurableLog::open_with_backend(backend).expect("open");
    log.append(b"x").expect("append");
    log.append(b"y").expect("append");
    let pruned = log.prune_below(2, 1_000).expect("prune");
    assert!(pruned.done);
    assert!(records(&log, 0).is_empty(), "the log is now empty");

    let frozen = image.lock().expect("image").clone();
    drop(log);

    let recovered = DurableLog::open_with_backend(SharedMem::from_bytes(frozen)).expect("recover");
    assert_eq!(recovered.next_offset(), 2, "must not restart at 0");
    assert_eq!(recovered.base_offset(), 2);
    assert_eq!(recovered.append(b"z").expect("append"), 2);
}

#[test]
fn both_constructors_share_one_recovery_path() {
    // `open` and `open_with_backend` must agree, or a store validated on one
    // route could be misread on the other. Same operations, same observations.
    let mut file = std::env::temp_dir();
    file.push(format!(
        "dogwood_backend_parity_{}.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&file);
    let file_log = DurableLog::open(&file).expect("open file");
    let (backend, _image) = SharedMem::empty();
    let mem_log = DurableLog::open_with_backend(backend).expect("open mem");

    for log in [&file_log, &mem_log] {
        assert_eq!(log.next_offset(), 0);
        assert_eq!(log.base_offset(), 0);
        assert_eq!(log.append(b"one").expect("append"), 0);
        log.commit(&[
            Write::Append(b"two"),
            Write::Meta {
                key: "k",
                value: b"v",
            },
        ])
        .expect("commit");
        assert_eq!(log.next_offset(), 2);
        assert_eq!(log.get_meta("k").expect("meta").as_deref(), Some(&b"v"[..]));
        assert_eq!(
            records(log, 0),
            vec![(0, b"one".to_vec()), (1, b"two".to_vec())]
        );
    }

    drop(file_log);
    let _ = std::fs::remove_file(&file);
}
