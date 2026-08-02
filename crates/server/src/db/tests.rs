//! Storage tests: round-trips, at-rest properties, and the blind-index migration.

use super::*;
use protocol_types::{IdentityHash, PayloadKind};
use std::collections::VecDeque;

fn temp_path() -> String {
    let mut n = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut n);
    std::env::temp_dir()
        .join(format!("sc-db-test-{}.sqlite", hex(&n)))
        .to_string_lossy()
        .into_owned()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sample_envelope(to: &str, id: &str) -> Envelope {
    Envelope {
        to: IdentityHash::from_identifier(to),
        ciphertext: "opaque-e2e-ciphertext".into(),
        kind: PayloadKind::Message,
        msg_id: id.into(),
        expires_at: None,
        wake: Default::default(),
        raw_identifier: None,
    }
}

#[test]
fn messages_survive_reopen_and_need_the_key() {
    let path = temp_path();
    let key = [7u8; 32];
    let env = sample_envelope("bob", "m1");

    // Write, then close the connection.
    {
        let db = Db::open(&path, &key).unwrap();
        db.insert_message(&env, None).unwrap();
    }

    // Reopen with the SAME key — the message is recovered and decrypts.
    {
        let db = Db::open(&path, &key).unwrap();
        let msgs = db.load_messages(1000).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg_id, "m1");
        assert_eq!(msgs[0].ciphertext, "opaque-e2e-ciphertext");
    }

    // Reopen with a DIFFERENT key — the encrypted blob cannot be read (skipped).
    // This is the at-rest "inability": a stolen DB without the off-disk key is inert.
    {
        let wrong = Db::open(&path, &[9u8; 32]).unwrap();
        assert!(wrong.load_messages(1000).unwrap().is_empty());
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn stored_blob_does_not_contain_plaintext() {
    let path = temp_path();
    let db = Db::open(&path, &[1u8; 32]).unwrap();
    db.insert_message(&sample_envelope("bob", "secret-id"), None)
        .unwrap();
    // Read the raw blob column straight from SQLite — it must be ciphertext.
    let raw: Vec<u8> = db
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT blob FROM messages", [], |r| r.get(0))
        .unwrap();
    let needle = b"opaque-e2e-ciphertext";
    assert!(!raw.windows(needle.len()).any(|w| w == needle));
    let _ = std::fs::remove_file(&path);
}

/// Every byte of the file, for a needle. The point of the at-rest work is what a thief
/// with the *file* can grep for, so the test looks at the file, not at columns.
fn file_contains(path: &str, needle: &str) -> bool {
    let bytes = std::fs::read(path).unwrap();
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// SP-04. The mailbox hash is an unsalted SHA-256 of a published username, so any
/// plaintext copy of it in the database is a username a thief recovers offline — and,
/// worse, a handle to *link* rows to that user. No table may store it.
#[test]
fn no_mailbox_hash_is_stored_in_the_clear() {
    let path = temp_path();
    let hash = IdentityHash::from_identifier("bob").as_str().to_string();
    {
        let db = Db::open(&path, &[3u8; 32]).unwrap();
        db.upsert_directory(
            &hash,
            &DirectoryEntry {
                identity_key: "idk".into(),
                signing_key: "sk".into(),
                one_time_keys: VecDeque::new(),
                fallback_key: None,
            },
        )
        .unwrap();
        db.insert_message(&sample_envelope("bob", "m1"), None)
            .unwrap();
        db.upsert_push(&hash, "https://push.example/endpoint")
            .unwrap();
        db.upsert_call_key(&hash, "{\"device_id\":\"d1\"}").unwrap();
    }
    // WAL: force everything into the main file before grepping it.
    Db::open(&path, &[3u8; 32])
        .unwrap()
        .conn
        .lock()
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();

    assert!(
        !file_contains(&path, &hash),
        "the mailbox hash must not appear anywhere on disk"
    );
    // The records sealed alongside it are gone too — a plaintext directory row could be
    // matched to a public KT entry on its key material and re-identified.
    assert!(!file_contains(&path, "push.example"));
    assert!(!file_contains(&path, "device_id"));
    let _ = std::fs::remove_file(&path);
}

/// The de-blinding attack the joint message key exists to stop: `msg_id` is minted by
/// the SENDER, so anyone who ever messaged the victim knows one by heart. If it were
/// stored in the clear, finding that one row in a stolen database would hand over the
/// victim's `target_idx` — and with it every other row that mailbox owns.
#[test]
fn a_msg_id_the_sender_chose_cannot_be_found_in_the_file() {
    let path = temp_path();
    {
        let db = Db::open(&path, &[4u8; 32]).unwrap();
        db.insert_message(&sample_envelope("bob", "sender-chosen-id"), None)
            .unwrap();
    }
    Db::open(&path, &[4u8; 32])
        .unwrap()
        .conn
        .lock()
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    assert!(!file_contains(&path, "sender-chosen-id"));
    let _ = std::fs::remove_file(&path);
}

/// One logical message fanned to several mailboxes must not share a visible token
/// across them — that would relink the rows the index just unlinked.
#[test]
fn the_same_msg_id_in_two_mailboxes_stores_two_unrelated_keys() {
    let path = temp_path();
    let db = Db::open(&path, &[5u8; 32]).unwrap();
    db.insert_message(&sample_envelope("bob-phone", "shared-id"), None)
        .unwrap();
    db.insert_message(&sample_envelope("bob-laptop", "shared-id"), None)
        .unwrap();
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT msg_key, target_idx FROM messages")
        .unwrap();
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].0, rows[1].0, "row keys must not collide");
    assert_ne!(rows[0].1, rows[1].1, "different mailboxes, different index");
    drop(stmt);
    drop(conn);
    let _ = std::fs::remove_file(&path);
}

/// One mailbox hash indexes differently in every table, so a thief cannot join the
/// tables to each other ("this unknown account also has push registered").
#[test]
fn one_hash_indexes_differently_per_table() {
    let path = temp_path();
    let db = Db::open(&path, &[6u8; 32]).unwrap();
    let h = "bob";
    let idx = [
        db.blind(IDX_DIRECTORY, h),
        db.blind(IDX_MESSAGE_TARGET, h),
        db.blind(IDX_PUSH, h),
        db.blind(IDX_CALL_KEY, h),
    ];
    let unique: std::collections::HashSet<_> = idx.iter().collect();
    assert_eq!(unique.len(), idx.len());
    // …and deterministic, or lookups would not work at all.
    assert_eq!(db.blind(IDX_PUSH, h), idx[2]);
    let _ = std::fs::remove_file(&path);
}

/// A relay upgrading in place must not lose its database. The migration rewrites the
/// legacy plaintext-hash tables under one transaction, keeping every readable row.
#[test]
fn a_legacy_database_migrates_in_place() {
    let path = temp_path();
    let key = [7u8; 32];
    let hash = IdentityHash::from_identifier("bob").as_str().to_string();

    // Build a pre-SP-04 file by hand: the exact schema and column names the relay
    // shipped with, including the two blobs that were already AEAD-sealed.
    let sealer = Db::open(&temp_path(), &key).unwrap();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
                "CREATE TABLE directory (hash TEXT PRIMARY KEY, json TEXT NOT NULL);
                 CREATE TABLE messages (
                     msg_id TEXT NOT NULL, target_hash TEXT NOT NULL,
                     blob BLOB NOT NULL, expires_at INTEGER,
                     PRIMARY KEY (target_hash, msg_id));
                 CREATE INDEX idx_messages_target ON messages(target_hash);
                 CREATE TABLE kt_entries (idx INTEGER PRIMARY KEY AUTOINCREMENT, json TEXT NOT NULL);
                 CREATE TABLE push (hash TEXT PRIMARY KEY, endpoint_blob BLOB NOT NULL);
                 CREATE TABLE call_keys (hash TEXT PRIMARY KEY, binding_json TEXT NOT NULL);",
            )
            .unwrap();
        let entry = DirectoryEntry {
            identity_key: "idk".into(),
            signing_key: "sk".into(),
            one_time_keys: VecDeque::from(vec!["otk1".to_string()]),
            fallback_key: Some("fbk".into()),
        };
        conn.execute(
            "INSERT INTO directory (hash, json) VALUES (?1, ?2)",
            params![hash, serde_json::to_string(&entry).unwrap()],
        )
        .unwrap();
        let env = sample_envelope("bob", "legacy-msg");
        conn.execute(
            "INSERT INTO messages (msg_id, target_hash, blob, expires_at)
                 VALUES (?1, ?2, ?3, ?4)",
            params![
                env.msg_id,
                env.to.as_str(),
                sealer.encrypt(&serde_json::to_vec(&env).unwrap()),
                None::<i64>
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO push (hash, endpoint_blob) VALUES (?1, ?2)",
            params![hash, sealer.encrypt(b"https://push.example/legacy")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO call_keys (hash, binding_json) VALUES (?1, ?2)",
            params![hash, "{\"device_id\":\"legacy-device\"}"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO kt_entries (json) VALUES (?1)",
            params!["{\"legacy\":true}"],
        )
        .unwrap();
    }

    // Opening it migrates it. Every row survives, addressed the same way as before.
    let db = Db::open(&path, &key).unwrap();
    let dir = db.load_directory().unwrap();
    assert_eq!(dir.len(), 1);
    assert_eq!(dir[0].0, hash);
    assert_eq!(dir[0].1.fallback_key.as_deref(), Some("fbk"));
    let msgs = db.load_messages(1000).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].msg_id, "legacy-msg");
    assert_eq!(
        db.load_push().unwrap(),
        vec![(hash.clone(), "https://push.example/legacy".to_string())]
    );
    assert_eq!(
        db.load_call_keys().unwrap(),
        vec![(
            hash.clone(),
            "{\"device_id\":\"legacy-device\"}".to_string()
        )]
    );
    // The KT log is deliberately untouched — it is the one table an independent
    // auditor has to be able to read.
    assert_eq!(
        db.conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM kt_entries", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    // The migrated rows are addressable by the normal API.
    db.delete_message(&hash, "legacy-msg").unwrap();
    assert!(db.load_messages(1000).unwrap().is_empty());
    // And the plaintext hash is gone from the FILE, not merely from the live rows:
    // the rewrite frees the old pages with their bytes intact, so the migration
    // reclaims them or it delivers nothing against a stolen disk.
    db.conn
        .lock()
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    assert!(!file_contains(&path, &hash));

    // Re-opening is a no-op: the version marker stops it running twice.
    drop(db);
    let again = Db::open(&path, &key).unwrap();
    assert_eq!(again.load_directory().unwrap().len(), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_and_prune_remove_messages() {
    let path = temp_path();
    let db = Db::open(&path, &[2u8; 32]).unwrap();
    db.insert_message(&sample_envelope("bob", "keep"), None)
        .unwrap();
    db.insert_message(&sample_envelope("bob", "expired"), Some(500))
        .unwrap();
    db.insert_message(&sample_envelope("bob", "acked"), None)
        .unwrap();
    let bob = IdentityHash::from_identifier("bob");
    db.delete_message(bob.as_str(), "acked").unwrap();
    db.prune_expired(1000).unwrap();
    let msgs = db.load_messages(1000).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].msg_id, "keep");
    let _ = std::fs::remove_file(&path);
}

/// SP-05: one logical message carries ONE `msg_id` into every recipient device's
/// mailbox and every sender self-sync copy. An ack from one mailbox must not delete
/// the durable row of another — that was silent multi-device data loss on restart,
/// and a way for any account to delete a message out of someone else's mailbox.
#[test]
fn an_ack_deletes_only_the_acking_mailboxs_copy() {
    let path = temp_path();
    let db = Db::open(&path, &[9u8; 32]).unwrap();
    // Same msg_id fanned to two mailboxes, exactly as `prepare_fanout` does.
    db.insert_message(&sample_envelope("bob-phone", "shared-id"), None)
        .unwrap();
    db.insert_message(&sample_envelope("bob-laptop", "shared-id"), None)
        .unwrap();

    let phone = IdentityHash::from_identifier("bob-phone");
    db.delete_message(phone.as_str(), "shared-id").unwrap();

    let msgs = db.load_messages(1000).unwrap();
    assert_eq!(msgs.len(), 1, "only the acking mailbox's copy is deleted");
    assert_eq!(
        msgs[0].to.as_str(),
        IdentityHash::from_identifier("bob-laptop").as_str(),
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn directory_and_kt_entries_round_trip_in_order() {
    let path = temp_path();
    let db = Db::open(&path, &[3u8; 32]).unwrap();

    let entry = DirectoryEntry {
        identity_key: "idk".into(),
        signing_key: "sk".into(),
        one_time_keys: VecDeque::from(vec!["otk1".to_string(), "otk2".to_string()]),
        fallback_key: Some("fbk".into()),
    };
    db.upsert_directory("hash1", &entry).unwrap();
    let dir = db.load_directory().unwrap();
    assert_eq!(dir.len(), 1);
    assert_eq!(dir[0].1.one_time_keys.len(), 2);

    // KT entries must come back in append order (the Merkle leaf order).
    for i in 0..3 {
        let e = KtEntry {
            seq: i,
            username_hash: format!("u{i}"),
            identity_key: "k".into(),
            signing_key: "s".into(),
            prev_signing_key: None,
            timestamp: 0,
            released: false,
            signature: "sig".into(),
        };
        db.append_kt_entry(&e).unwrap();
    }
    let entries = db.load_kt_entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].username_hash, "u0");
    assert_eq!(entries[2].username_hash, "u2");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn mixed_kt_records_replay_in_leaf_order() {
    let path = temp_path();
    let db = Db::open(&path, &[4u8; 32]).unwrap();

    let entry = KtEntry {
        seq: 0,
        username_hash: "u0".into(),
        identity_key: "k".into(),
        signing_key: "s".into(),
        prev_signing_key: None,
        timestamp: 0,
        released: false,
        signature: "sig".into(),
    };
    let roster = KtRosterEntry {
        seq: 0,
        username_hash: "u0".into(),
        devices: vec![],
        timestamp: 1,
        signature: "rsig".into(),
    };
    // Interleave: binding, roster, binding — replay must preserve exact leaf order.
    db.append_kt_entry(&entry).unwrap();
    db.append_kt_roster(&roster).unwrap();
    let mut entry2 = entry.clone();
    entry2.username_hash = "u1".into();
    db.append_kt_entry(&entry2).unwrap();

    let records = db.load_kt_records().unwrap();
    assert_eq!(records.len(), 3);
    assert!(matches!(&records[0], KtRecord::Binding(e) if e.username_hash == "u0"));
    assert!(matches!(&records[1], KtRecord::Roster(r) if r.username_hash == "u0"));
    assert!(matches!(&records[2], KtRecord::Binding(e) if e.username_hash == "u1"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn sync_blobs_round_trip_and_expire() {
    let path = temp_path();
    let db = Db::open(&path, &[5u8; 32]).unwrap();
    db.insert_sync("id1", b"opaque-ciphertext", 2000).unwrap();

    // Present before expiry, absent after; prune deletes the row.
    assert_eq!(
        db.get_sync("id1", 1000).unwrap().as_deref(),
        Some(b"opaque-ciphertext".as_slice())
    );
    assert!(db.get_sync("id1", 2000).unwrap().is_none());
    assert!(db.get_sync("missing", 1000).unwrap().is_none());
    db.prune_sync(2000).unwrap();
    assert!(db.get_sync("id1", 1000).unwrap().is_none());
    let _ = std::fs::remove_file(&path);
}
