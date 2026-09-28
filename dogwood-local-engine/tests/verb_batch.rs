//! The verb-batch policy-management surface:
//! `install` (whole-set) + `batch` (Add/Update/Delete) over stable
//! engine-minted ids, plus the `list`/`get_policy` reads. Exercises the real
//! `expanded_source` canonicalization and — the key durability guarantee —
//! that a policy's id survives a restart.

use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{
    DurableError, DurableLog, DurableTemporalEngine, Outcome, PolicyId, PolicySet, PolicyToken,
    Snapshot, SnapshotPayload, Verb, Write,
};

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
"#;

// Two policies, so `install` splits the source into two structured entries.
const TWO_POLICIES: &str = r#"
permit (principal, action == Action::"Read", resource);
forbid (principal, action == Action::"Read", resource)
when { context.input.doc == "secret" };
"#;

const THIRD: &str = r#"permit (principal, action == Action::"Read", resource) when { context.input.doc == "public" };"#;

fn store(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dogwood_verb_batch_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// A `Read` decision event on `doc` — permitted by `TWO_POLICIES` unless `doc`
/// is `"secret"`. Submitted (not built) so the engine assigns the timestamp.
fn ev(doc: &str) -> EventBuilder {
    Event::builder("Action::Read", "request")
        .principal("User::\"alice\"")
        .resource("Doc::\"d\"")
        .field("input", "doc", Value::String(doc.to_string()))
        .request_context("input", "doc", Value::String(doc.to_string()))
}

/// The opaque handle of the policy at internal ordinal `ordinal` — how a test
/// names a policy for `Update`/`Delete`/`Reset`/`get_policy` now that the handle
/// is opaque. Ordinals stay observable through `list()` for ordering assertions.
fn tok(engine: &DurableTemporalEngine, ordinal: u64) -> PolicyToken {
    engine
        .list()
        .into_iter()
        .find(|e| e.id == PolicyId(ordinal))
        .unwrap_or_else(|| panic!("no policy at ordinal {ordinal}"))
        .token
}

#[test]
fn declarative_reinstall_rejects_ordinal_exhaustion_without_writing() {
    let dir = store("install_ordinal_exhaustion");

    // Start from a real policy and monitor snapshot, then move only its persisted
    // monotone cursor to the exhausted value. This reaches the otherwise
    // impractical state without fabricating an impossible jump in Add ids.
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(THIRD, ACTION_SCHEMA, None, None)
            .expect("installs");
        engine.checkpoint().expect("checkpoints");
    }
    {
        let log = DurableLog::open(&dir).expect("opens log");
        let snapshot = log
            .get_snapshot()
            .expect("reads snapshot")
            .expect("snapshot exists");
        let mut payload = SnapshotPayload::decode(&snapshot.payload).expect("decodes snapshot");
        let entries = payload.bundle.policies.entries().cloned().collect();
        payload.bundle.policies = PolicySet::from_recorded(entries, u64::MAX);
        let exhausted = Snapshot {
            up_to_offset: snapshot.up_to_offset,
            payload: payload.encode().expect("encodes exhausted cursor"),
        };
        log.commit(&[Write::Snapshot(&exhausted)])
            .expect("stores exhausted cursor");
    }

    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("recovers exhausted cursor");
    let original = engine.list();
    let original_offset = engine.log_offset();
    let error = engine
        .install(THIRD, ACTION_SCHEMA, None, None)
        .expect_err("reinstall must reject ordinal exhaustion");

    match error {
        DurableError::Rejected(message) => {
            assert_eq!(message, "policy ordinal space exhausted");
        }
        other => panic!("expected a policy rejection, got {other}"),
    }
    assert_eq!(engine.list(), original, "running set changed on rejection");
    assert_eq!(
        engine.log_offset(),
        original_offset,
        "rejected reinstall wrote durable records"
    );

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn install_splits_into_structured_entries_with_canonical_statements() {
    let dir = store("install");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");

    engine
        .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
        .expect("installs");

    let list = engine.list();
    assert_eq!(list.len(), 2, "two source policies -> two entries");
    assert_eq!(
        list.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![PolicyId(0), PolicyId(1)],
        "ids minted 0,1 in order"
    );
    // Statements are the canonical `expanded_source` rendering: non-empty, one
    // policy each, and a stable fixed point (rendering the stored statement
    // reproduces it).
    assert!(list[0].statement.contains("permit"));
    assert!(list[1].statement.contains("forbid"));
    assert_eq!(
        engine.get_policy(&tok(&engine, 1)).unwrap().statement,
        list[1].statement
    );
    assert!(engine.get_policy(&PolicyToken("SPabsent".into())).is_none());

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn batch_add_update_delete_over_stable_ids() {
    let dir = store("batch");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    engine
        .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
        .expect("installs");
    // Capture the two install handles up front (their ordinals are 0 and 1).
    let (h0, h1) = (tok(&engine, 0), tok(&engine, 1));

    // Add mints a new policy (ordinal 2), keeping the others — and the batch
    // returns the handle it minted so the caller can address it later (§2.5).
    let result = engine
        .batch(vec![Verb::Add {
            policy: THIRD.to_string(),
        }])
        .expect("add");
    assert_eq!(result.minted.len(), 1, "one Add minted one handle");
    let h2 = result.minted[0].clone();
    assert_eq!(
        engine.list().iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![PolicyId(0), PolicyId(1), PolicyId(2)]
    );

    // Delete the first policy.
    engine
        .batch(vec![Verb::Delete { id: h0.clone() }])
        .expect("delete");
    assert!(engine.get_policy(&h0).is_none());
    assert_eq!(
        engine.list().iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![PolicyId(1), PolicyId(2)]
    );

    // Update the second: same handle, new content.
    let before = engine.get_policy(&h1).unwrap().statement;
    engine
        .batch(vec![Verb::Update {
            id: h1.clone(),
            policy: THIRD.to_string(),
        }])
        .expect("update");
    let after = engine.get_policy(&h1).unwrap().statement;
    assert_ne!(before, after, "update changed the statement");
    assert_eq!(
        engine.list().len(),
        2,
        "update keeps the handle, no new entry"
    );
    // The minted handle still addresses its policy.
    assert!(engine.get_policy(&h2).is_some());

    // An unknown handle rejects the whole batch (nothing changes).
    let err = engine.batch(vec![Verb::Delete {
        id: PolicyToken("SPnope".into()),
    }]);
    assert!(err.is_err(), "unknown handle must reject");
    assert_eq!(engine.list().len(), 2, "rejected batch left the set intact");

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn add_slices_a_multi_policy_source_and_update_rejects_one() {
    // §2.4/AVP: `Add` is a bulk add — a multi-policy source slices into one entry
    // (and one minted id) per policy. `Update` targets a single id, so a
    // multi-policy source is rejected.
    let dir = store("slice");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    engine
        .install(THIRD, ACTION_SCHEMA, None, None)
        .expect("installs"); // THIRD is one policy -> id 0

    // A single Add whose source holds TWO policies -> two entries, two ids.
    let r = engine
        .batch(vec![Verb::Add {
            policy: TWO_POLICIES.to_string(),
        }])
        .expect("bulk add");
    assert_eq!(
        r.minted.len(),
        2,
        "the two policies in the source each minted a handle"
    );
    assert_eq!(
        engine.list().iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![PolicyId(0), PolicyId(1), PolicyId(2)]
    );
    // Each stored entry is a single policy (one permit, one forbid).
    assert!(
        engine
            .get_policy(&tok(&engine, 1))
            .unwrap()
            .statement
            .contains("permit")
    );
    assert!(
        engine
            .get_policy(&tok(&engine, 2))
            .unwrap()
            .statement
            .contains("forbid")
    );

    // Update with a multi-policy source is rejected; nothing changes.
    let err = engine.batch(vec![Verb::Update {
        id: tok(&engine, 1),
        policy: TWO_POLICIES.to_string(),
    }]);
    assert!(err.is_err(), "a multi-policy update must reject");
    assert_eq!(
        engine.list().len(),
        3,
        "the rejected update changed nothing"
    );

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn a_multi_add_batch_returns_minted_ids_in_listed_order() {
    // §2.5: each `Add` is assigned an id and the batch returns them in the order
    // the Adds were listed, so `minted[k]` is the k-th Add's id. Verbs that mint
    // nothing (Delete/Reset/…) do not contribute an entry.
    let dir = store("minted_order");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    engine
        .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
        .expect("installs"); // ordinals 0, 1
    let h0 = tok(&engine, 0);

    let result = engine
        .batch(vec![
            Verb::Add {
                policy: THIRD.to_string(),
            },
            Verb::Delete { id: h0 },
            Verb::Add {
                policy: THIRD.to_string(),
            },
        ])
        .expect("batch");
    // Two Adds → two minted handles, returned in Add order; Delete mints nothing.
    assert_eq!(result.minted.len(), 2, "two Adds mint two handles");
    // `minted[k]` is the k-th Add's policy: the first got the continued ordinal 2,
    // the second got 3 (both past the wiped 0). This pins the *order* the name
    // promises — a reversed `minted` would fail here even though both Adds are
    // byte-identical.
    assert_eq!(
        engine.get_policy(&result.minted[0]).unwrap().id,
        PolicyId(2),
        "the first Add's handle maps to the first continued ordinal"
    );
    assert_eq!(
        engine.get_policy(&result.minted[1]).unwrap().id,
        PolicyId(3),
        "the second Add's handle maps to the next ordinal"
    );
    assert_eq!(
        engine.list().iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![PolicyId(1), PolicyId(2), PolicyId(3)]
    );

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn reset_and_reset_all_are_accepted() {
    // Under the composite (id, clause-index) transplant (§2.3), a Reset marks a
    // policy `fresh` and its window drops on the next rebuild — content
    // unchanged, id unchanged. This is exactly what the retention model gives
    // up when it stops inferring intent from a content diff.
    let dir = store("reset");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    engine
        .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
        .expect("installs");

    engine
        .batch(vec![Verb::Reset {
            id: tok(&engine, 0),
        }])
        .expect("Reset must be accepted");
    engine
        .batch(vec![Verb::ResetAll])
        .expect("ResetAll must be accepted");

    // Both policies are still installed at their original ordinals.
    let ids: Vec<_> = engine.list().iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![PolicyId(0), PolicyId(1)]);

    // Reset targeting an unknown handle still rejects the whole batch.
    let err = engine.batch(vec![Verb::Reset {
        id: PolicyToken("SPnope".into()),
    }]);
    assert!(err.is_err(), "unknown handle must reject");

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn policy_ids_survive_a_restart() {
    let dir = store("restart");
    let (h0, h1);
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
            .expect("installs");
        h0 = tok(&engine, 0);
        h1 = tok(&engine, 1);
        engine
            .batch(vec![Verb::Add {
                policy: THIRD.to_string(),
            }])
            .expect("add");
        engine
            .batch(vec![Verb::Delete { id: h0.clone() }])
            .expect("delete");
        // Set is now ordinals [1, 2].
    }

    // Reopen: recovery replays the records, and the durably-recorded ordinals AND
    // handles must be restored exactly — not re-minted from position (§2.4).
    let engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
    let ids: Vec<PolicyId> = engine.list().iter().map(|e| e.id).collect();
    assert_eq!(
        ids,
        vec![PolicyId(1), PolicyId(2)],
        "ordinals survive a restart (durably recorded, never re-minted)"
    );
    // The surviving handle still resolves; the deleted one is gone — both across
    // the restart, so handles are durable too.
    assert!(engine.get_policy(&h1).is_some());
    assert!(engine.get_policy(&h0).is_none());

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn a_batch_is_one_timestamp_instant_that_survives_a_replay_restart() {
    // Option A (§2.5): a batch is atomic — "sequential in meaning, transactional
    // in effect" — so it is ONE instant. Every policy it touches shares one
    // store-assigned created/updated, and that value is exactly what the durable
    // records carry. So a restart that rebuilds the set from the log (no snapshot)
    // reports byte-identical metadata: replay stamps each entry from its record's
    // ts, which is the batch's single `now`.
    //
    // The recovery assertions below are the discriminating ones. Before Option A
    // the live set stamped a flat `now` while the records advanced per-record, so
    // the second add and the update came back with *larger* timestamps after a
    // replay than `list()` had reported live — `list()` disagreeing with itself
    // across a restart.
    let dir = store("one_instant_replay");

    let (install_ts, batch_ts) = {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");

        // An install splits into two entries, both born in the one install instant.
        engine
            .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
            .expect("installs"); // ids 0, 1
        let after_install = engine.list();
        assert_eq!(after_install.len(), 2);
        assert!(
            after_install.iter().all(|e| e.created == e.updated),
            "a freshly added entry has created == updated"
        );
        assert_eq!(
            after_install[0].created, after_install[1].created,
            "an install is one instant: every entry shares one created timestamp"
        );
        let install_ts = after_install[0].created;
        let h0 = tok(&engine, 0);

        // One batch, several records: two Adds (ordinals 2, 3) and an Update of 0.
        engine
            .batch(vec![
                Verb::Add {
                    policy: THIRD.to_string(),
                },
                Verb::Add {
                    policy: THIRD.to_string(),
                },
                Verb::Update {
                    id: h0,
                    policy: THIRD.to_string(),
                },
            ])
            .expect("batch");

        let list = engine.list();
        let by_id = |id: PolicyId| list.iter().find(|e| e.id == id).unwrap().clone();
        let (a2, a3, u0) = (by_id(PolicyId(2)), by_id(PolicyId(3)), by_id(PolicyId(0)));

        // The two adds in the batch share one instant (created == updated == it).
        assert_eq!(
            a2.created, a3.created,
            "adds in one batch share a single created timestamp"
        );
        assert!(a2.created == a2.updated && a3.created == a3.updated);
        let batch_ts = a2.created;
        // The batch is a strictly later instant than the install.
        assert!(
            batch_ts > install_ts,
            "the batch instant ({batch_ts}) advances past the install ({install_ts})"
        );
        // The updated policy keeps its original created and stamps updated at the
        // batch instant — same single `now`, so the two halves stay consistent.
        assert_eq!(u0.created, install_ts, "update preserves created");
        assert_eq!(
            u0.updated, batch_ts,
            "update stamps updated at the batch instant"
        );

        (install_ts, batch_ts)
        // Dropped WITHOUT a checkpoint: recovery replays the log rather than
        // loading a snapshot, so it re-stamps every entry from its record's ts —
        // the path Option A brings into agreement with the live set.
    };

    // Reopen and compare: every entry's created/updated must match what `list()`
    // reported live. A snapshot would trivially agree (it serializes the live
    // set); this is the log-replay path, where the timestamps are reconstructed.
    let engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
    let list = engine.list();
    let by_id = |id: PolicyId| list.iter().find(|e| e.id == id).unwrap().clone();

    assert_eq!(
        (by_id(PolicyId(0)).created, by_id(PolicyId(0)).updated),
        (install_ts, batch_ts),
        "the updated policy's metadata survives a replay restart unchanged"
    );
    for id in [PolicyId(2), PolicyId(3)] {
        let e = by_id(id);
        assert_eq!(
            (e.created, e.updated),
            (batch_ts, batch_ts),
            "a batch-added policy's metadata survives a replay restart unchanged"
        );
    }

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn re_install_continues_the_mint_cursor_never_reusing_an_id() {
    // §2.4: a stable id must never be reused. A declarative re-install wipes the
    // set (`[DeleteAll; Add each]`) but must *continue* the cursor — otherwise a
    // fresh policy could take an id a caller still holds for a since-deleted one.
    let dir = store("reinstall_cursor");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");

    engine
        .install(THIRD, ACTION_SCHEMA, None, None)
        .expect("first install"); // ordinal 0
    engine
        .batch(vec![Verb::Add {
            policy: THIRD.to_string(),
        }])
        .expect("add"); // ordinal 1; cursor now 2

    // Re-install a single policy. It replaces the set, but its ordinal must
    // continue past every one ever minted — 2, NOT a reused 0 or 1.
    engine
        .install(THIRD, ACTION_SCHEMA, None, None)
        .expect("re-install");
    let ids: Vec<_> = engine.list().iter().map(|e| e.id).collect();
    assert_eq!(
        ids,
        vec![PolicyId(2)],
        "the re-installed policy must get a continued ordinal, not a reused one"
    );

    // And a following Add continues from there.
    let r = engine
        .batch(vec![Verb::Add {
            policy: THIRD.to_string(),
        }])
        .expect("add after re-install");
    assert_eq!(r.minted.len(), 1);
    assert_eq!(
        engine.get_policy(&r.minted[0]).unwrap().id,
        PolicyId(3),
        "cursor keeps advancing"
    );

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn the_mint_cursor_continues_after_a_restart() {
    // §2.4: a restart must never re-mint — the next id continues past every id
    // ever assigned, even ones since deleted or wiped. This is the durable
    // counterpart of the `PolicySet` unit test; it checks the recovery wiring
    // (recorded ids advancing `next_id`, and Delete/DeleteAll preserving it).
    let dir = store("mint_cursor");

    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
            .expect("installs"); // ids 0, 1
        engine
            .batch(vec![Verb::Add {
                policy: THIRD.to_string(),
            }])
            .expect("add"); // ordinal 2
        let h0 = tok(&engine, 0);
        engine
            .batch(vec![Verb::Delete { id: h0 }])
            .expect("delete 0");
    }

    // Reopen and add: the new ordinal must be 3 — not 0, and not a reused one.
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
        let result = engine
            .batch(vec![Verb::Add {
                policy: THIRD.to_string(),
            }])
            .expect("add after restart");
        assert_eq!(
            engine.get_policy(&result.minted[0]).unwrap().id,
            PolicyId(3),
            "the mint cursor continues past the restart, never re-minting"
        );
        // Wipe everything, restart again, and add: the cursor still continues
        // (DeleteAll keeps the monotone cursor, §2.1).
        engine.batch(vec![Verb::DeleteAll]).expect("delete all");
    }
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens again");
        let result = engine
            .batch(vec![Verb::Add {
                policy: THIRD.to_string(),
            }])
            .expect("add after wipe + restart");
        assert_eq!(
            engine.get_policy(&result.minted[0]).unwrap().id,
            PolicyId(4),
            "DeleteAll + restart still continues the cursor, never resets to 0"
        );
    }

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn handles_agree_across_a_checkpoint_boundary() {
    // Recovery reconstructs handles from two sources that must agree: a policy
    // *below* the snapshot comes back from the serialized `PolicySet` (snapshot
    // restore), while a policy added *after* the snapshot comes back from its
    // replayed `Add` record (log replay). This crosses a checkpoint so both paths
    // run in one recovery — the durable-handle counterpart of the ordinal cursor
    // test, exercising snapshot + replay handle agreement together.
    let dir = store("checkpoint_handles");
    let (h_pre, h_post);
    {
        let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
        engine
            .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
            .expect("installs"); // ordinals 0, 1 — will be snapshot-covered
        h_pre = tok(&engine, 0);
        // Snapshot the installed set, then add AFTER it (a post-snapshot record).
        engine.checkpoint().expect("checkpoint");
        let r = engine
            .batch(vec![Verb::Add {
                policy: THIRD.to_string(),
            }])
            .expect("add after checkpoint");
        h_post = r.minted[0].clone(); // ordinal 2, only in the replayed log tail
    }

    // Reopen: snapshot restores h_pre's entry; replay reconstructs h_post's.
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("reopens");
    assert_eq!(
        engine
            .get_policy(&h_pre)
            .expect("snapshot-restored handle")
            .id,
        PolicyId(0),
        "a handle below the snapshot survives via snapshot restore"
    );
    assert_eq!(
        engine.get_policy(&h_post).expect("replayed handle").id,
        PolicyId(2),
        "a handle added after the snapshot survives via log replay"
    );
    // The cursor continued across both paths — the next Add is ordinal 3.
    let r = engine
        .batch(vec![Verb::Add {
            policy: THIRD.to_string(),
        }])
        .expect("add after recovery");
    assert_eq!(
        engine.get_policy(&r.minted[0]).unwrap().id,
        PolicyId(3),
        "the ordinal cursor continues past a snapshot + replay recovery"
    );

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn an_empty_batch_is_a_no_op() {
    let dir = store("empty_batch");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");

    // An empty batch before any install succeeds and does nothing — a no-op
    // needs no installed set (it can't fail).
    let r = engine
        .batch(vec![])
        .expect("empty batch is a no-op, not NoPolicy");
    assert!(r.minted.is_empty(), "an empty batch mints nothing");
    assert_eq!(engine.log_offset(), 0, "a no-op writes no record");

    engine
        .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
        .expect("installs");
    let offset_before = engine.log_offset();
    let ids_before = engine.list().iter().map(|e| e.id).collect::<Vec<_>>();

    // An empty batch over an installed set: still nothing written, set intact,
    // no rebuild/fsync/clock advance.
    let r = engine.batch(vec![]).expect("empty batch is a no-op");
    assert!(r.minted.is_empty());
    assert_eq!(
        engine.log_offset(),
        offset_before,
        "a no-op writes no record over an installed set"
    );
    assert_eq!(
        engine.list().iter().map(|e| e.id).collect::<Vec<_>>(),
        ids_before,
        "a no-op leaves the set unchanged"
    );

    let _ = std::fs::remove_file(&dir);
}

#[test]
fn an_empty_batch_is_transparent_to_the_event_stream() {
    // Interleaved with real work, an empty batch must be invisible to it: it
    // writes no record, consumes no timestamp, and leaves the running set intact,
    // so events on either side stay contiguously offset and strictly increasing
    // in ts — the no-op neither advances nor rewinds the shared clock.
    let dir = store("empty_interleave");
    let mut engine = DurableTemporalEngine::open(&dir, 0).expect("opens");
    engine
        .install(TWO_POLICIES, ACTION_SCHEMA, None, None)
        .expect("installs");

    let off0 = engine.log_offset();
    let s1 = engine.submit(ev("public")).expect("submit 1");
    assert_eq!(s1.offset, off0, "the first event takes the next offset");

    // Empty batch: no record, and it reports the clock *as it stands* (== s1.ts),
    // not an advance — proof it consumed no timestamp. (A regression routing the
    // no-op back through the commit path would mint a fresh `now > s1.ts` here.)
    let e = engine.batch(vec![]).expect("empty batch");
    assert!(e.minted.is_empty());
    assert_eq!(engine.log_offset(), off0 + 1, "the no-op wrote no record");
    assert_eq!(
        e.ts, s1.ts,
        "the no-op reports the current clock, not an advance"
    );

    // The next event takes the contiguous offset and a strictly greater ts — the
    // no-op skipped neither an offset nor a tick.
    let s2 = engine.submit(ev("public")).expect("submit 2");
    assert_eq!(
        s2.offset,
        off0 + 1,
        "the event after the no-op is contiguous"
    );
    assert!(
        s2.ts > s1.ts,
        "the clock advanced for the real event; the no-op consumed nothing"
    );

    // Another no-op, then the running set must still decide correctly.
    engine.batch(vec![]).expect("empty batch");
    assert_eq!(engine.log_offset(), off0 + 2, "still no phantom record");
    match engine.submit(ev("public")).expect("submit 3").outcome {
        Outcome::Decision(r) => assert!(
            r.allowed(),
            "the running set still decides after the no-ops (permit Read of a non-secret doc)"
        ),
        other => panic!("expected a decision, got {other:?}"),
    }

    let _ = std::fs::remove_file(&dir);
}
