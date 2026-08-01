//! Durable, encrypted-at-rest storage (SQLite).
//!
//! Design follows the zero-knowledge principle: the relay persists only what it must,
//! and what it persists reveals as little as possible to a stolen disk or backup.
//!
//! * **Message bodies** are stored as an AEAD blob (XChaCha20-Poly1305) under a key held
//!   in the server's environment — **not on the data disk**. A leaked database file is
//!   undecryptable without that key. (The message *content* is already end-to-end
//!   encrypted; this protects the remaining at-rest metadata and keeps the blob opaque.)
//! * **Recipient hash, msg_id, expiry** are stored in the clear because the relay must
//!   query by them to deliver and prune. The recipient hash is already a one-way
//!   SHA-256 — it is not a username, and cannot be reversed to one.
//! * **The directory and the KT log are public by design** (peers fetch bundles; a
//!   transparency log is meant to be auditable), so they are stored as plaintext JSON.
//!
//! Net at-rest exposure to a disk thief: recipient hashes, timing, and counts — the
//! irreducible minimum for a store-and-forward relay. No content, no sender, no
//! usernames, no message bodies.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use kt_log::{KtEntry, KtRecord, KtRosterEntry};
use protocol_types::Envelope;
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::sync::Mutex;

use crate::state::DirectoryEntry;

const NONCE_LEN: usize = 24;

pub struct Db {
    conn: Mutex<Connection>,
    cipher: XChaCha20Poly1305,
}

impl Db {
    /// Open (creating if absent) the database at `path`, using `storage_key` (32 bytes,
    /// held off-disk) to encrypt message blobs.
    pub fn open(path: &str, storage_key: &[u8; 32]) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS directory (
                 hash TEXT PRIMARY KEY,
                 json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS messages (
                 msg_id TEXT NOT NULL,
                 target_hash TEXT NOT NULL,
                 blob BLOB NOT NULL,
                 expires_at INTEGER,
                 PRIMARY KEY (target_hash, msg_id)
             );
             CREATE INDEX IF NOT EXISTS idx_messages_target ON messages(target_hash);
             CREATE TABLE IF NOT EXISTS kt_entries (
                 idx INTEGER PRIMARY KEY AUTOINCREMENT,
                 json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS blobs (
                 blob_id TEXT PRIMARY KEY,
                 data BLOB NOT NULL,
                 expires_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS push (
                 hash TEXT PRIMARY KEY,
                 endpoint_blob BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_blobs (
                 sync_id TEXT PRIMARY KEY,
                 data BLOB NOT NULL,
                 expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS call_keys (
                 hash TEXT PRIMARY KEY,
                 binding_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS used_invites (
                 code_hash TEXT PRIMARY KEY
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            cipher: XChaCha20Poly1305::new(storage_key.into()),
        })
    }

    fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), plain)
            .expect("XChaCha20-Poly1305 encryption does not fail");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    fn decrypt(&self, blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < NONCE_LEN {
            return None;
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        self.cipher.decrypt(XNonce::from_slice(nonce), ct).ok()
    }

    // ── Directory (public keys — plaintext JSON) ──────────────────────────────

    pub fn upsert_directory(&self, hash: &str, entry: &DirectoryEntry) -> rusqlite::Result<()> {
        let json = serde_json::to_string(entry).expect("DirectoryEntry serializes");
        self.conn.lock().unwrap().execute(
            "INSERT INTO directory (hash, json) VALUES (?1, ?2)
             ON CONFLICT(hash) DO UPDATE SET json = excluded.json",
            params![hash, json],
        )?;
        Ok(())
    }

    /// Remove a directory record (a device revoked from its account's roster).
    pub fn delete_directory(&self, hash: &str) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM directory WHERE hash = ?1", params![hash])?;
        Ok(())
    }

    pub fn load_directory(&self) -> rusqlite::Result<Vec<(String, DirectoryEntry)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash, json FROM directory")?;
        let rows = stmt.query_map([], |r| {
            let hash: String = r.get(0)?;
            let json: String = r.get(1)?;
            Ok((hash, json))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (hash, json) = row?;
            if let Ok(entry) = serde_json::from_str(&json) {
                out.push((hash, entry));
            }
        }
        Ok(out)
    }

    // ── Messages (envelope encrypted at rest) ─────────────────────────────────

    pub fn insert_message(&self, env: &Envelope, expires_at: Option<u64>) -> rusqlite::Result<()> {
        let plain = serde_json::to_vec(env).expect("Envelope serializes");
        let blob = self.encrypt(&plain);
        self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO messages (msg_id, target_hash, blob, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                env.msg_id,
                env.to.as_str(),
                blob,
                expires_at.map(|e| e as i64)
            ],
        )?;
        Ok(())
    }

    pub fn delete_message(&self, msg_id: &str) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM messages WHERE msg_id = ?1", params![msg_id])?;
        Ok(())
    }

    /// Drop every queued message for one mailbox (account deletion).
    pub fn delete_messages_for(&self, target_hash: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM messages WHERE target_hash = ?1",
            params![target_hash],
        )?;
        Ok(())
    }

    pub fn prune_expired(&self, now: u64) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now as i64],
        )?;
        Ok(())
    }

    /// Clamp legacy rows with no expiry (written before the server-side TTL ceiling) to
    /// `ceiling`, so they too eventually prune. New inserts always carry a clamped expiry,
    /// so this only affects rows migrated from an older schema (M-3).
    pub fn clamp_null_expiry(&self, ceiling: u64) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE messages SET expires_at = ?1 WHERE expires_at IS NULL",
            params![ceiling as i64],
        )?;
        Ok(())
    }

    /// Load all non-expired messages (decrypting each). Corrupt/undecryptable rows are
    /// skipped rather than aborting startup.
    pub fn load_messages(&self, now: u64) -> rusqlite::Result<Vec<Envelope>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT blob FROM messages WHERE expires_at IS NULL OR expires_at > ?1")?;
        let rows = stmt.query_map(params![now as i64], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let blob = row?;
            if let Some(plain) = self.decrypt(&blob) {
                if let Ok(env) = serde_json::from_slice::<Envelope>(&plain) {
                    out.push(env);
                }
            }
        }
        Ok(out)
    }

    // ── KT entries (public log — plaintext JSON, global append order) ─────────

    pub fn append_kt_entry(&self, entry: &KtEntry) -> rusqlite::Result<()> {
        let json = serde_json::to_string(entry).expect("KtEntry serializes");
        self.conn
            .lock()
            .unwrap()
            .execute("INSERT INTO kt_entries (json) VALUES (?1)", params![json])?;
        Ok(())
    }

    /// Append a device-roster epoch to the same ordered table as the KT entries, so the
    /// boot replay rebuilds the Merkle tree in exactly the original leaf order. Stored
    /// as a tagged wrapper (`{"roster": …}`) that cannot deserialize as a `KtEntry`.
    pub fn append_kt_roster(&self, roster: &KtRosterEntry) -> rusqlite::Result<()> {
        let json = serde_json::to_string(&serde_json::json!({ "roster": roster }))
            .expect("KtRosterEntry serializes");
        self.conn
            .lock()
            .unwrap()
            .execute("INSERT INTO kt_entries (json) VALUES (?1)", params![json])?;
        Ok(())
    }

    /// Load every KT leaf (bindings and rosters) in append order. Legacy databases hold
    /// only plain `KtEntry` rows; roster rows carry the tagged wrapper.
    pub fn load_kt_records(&self) -> rusqlite::Result<Vec<KtRecord>> {
        #[derive(Deserialize)]
        struct RosterRow {
            roster: KtRosterEntry,
        }
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT json FROM kt_entries ORDER BY idx ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            if let Ok(entry) = serde_json::from_str::<KtEntry>(&json) {
                out.push(KtRecord::Binding(entry));
            } else if let Ok(row) = serde_json::from_str::<RosterRow>(&json) {
                out.push(KtRecord::Roster(row.roster));
            }
        }
        Ok(out)
    }

    // ── History-sync blobs (opaque, sealed under the account password/PIN + link
    //    secret on the client — the relay never holds either input) ────────────

    pub fn insert_sync(&self, id: &str, data: &[u8], expires_at: u64) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO sync_blobs (sync_id, data, expires_at) VALUES (?1, ?2, ?3)",
            params![id, data, expires_at as i64],
        )?;
        Ok(())
    }

    pub fn get_sync(&self, id: &str, now: u64) -> rusqlite::Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM sync_blobs WHERE sync_id = ?1 AND expires_at > ?2",
            params![id, now as i64],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
    }

    pub fn prune_sync(&self, now: u64) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM sync_blobs WHERE expires_at <= ?1",
            params![now as i64],
        )?;
        Ok(())
    }

    // ── Attachment blobs (opaque client ciphertext — already E2E encrypted) ───

    pub fn insert_blob(
        &self,
        id: &str,
        data: &[u8],
        expires_at: Option<u64>,
    ) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO blobs (blob_id, data, expires_at) VALUES (?1, ?2, ?3)",
            params![id, data, expires_at.map(|e| e as i64)],
        )?;
        Ok(())
    }

    /// Fetch a blob if present and not expired.
    pub fn get_blob(&self, id: &str, now: u64) -> rusqlite::Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM blobs WHERE blob_id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
            params![id, now as i64],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
    }

    pub fn prune_blobs(&self, now: u64) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM blobs WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now as i64],
        )?;
        Ok(())
    }

    // ── Push subscriptions (endpoint URL encrypted at rest) ───────────────────
    // The endpoint URL links a mailbox hash to a push-provider account, so it gets the
    // same at-rest treatment as message blobs: unreadable off a stolen disk.

    pub fn upsert_push(&self, hash: &str, endpoint: &str) -> rusqlite::Result<()> {
        let blob = self.encrypt(endpoint.as_bytes());
        self.conn.lock().unwrap().execute(
            "INSERT INTO push (hash, endpoint_blob) VALUES (?1, ?2)
             ON CONFLICT(hash) DO UPDATE SET endpoint_blob = excluded.endpoint_blob",
            params![hash, blob],
        )?;
        Ok(())
    }

    pub fn delete_push(&self, hash: &str) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM push WHERE hash = ?1", params![hash])?;
        Ok(())
    }

    /// Total bytes held in the two big object stores (attachment + sync blobs), for the
    /// global storage quota. `LENGTH()` on a BLOB column reads the stored size, not the
    /// payload, and both tables are small (row counts bounded by the quota itself), so
    /// this is cheap enough per upload.
    pub fn storage_bytes(&self) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE((SELECT SUM(LENGTH(data)) FROM blobs), 0)
                  + COALESCE((SELECT SUM(LENGTH(data)) FROM sync_blobs), 0)",
            [],
            |r| r.get::<_, i64>(0).map(|v| v.max(0) as u64),
        )
    }

    // ── Call-control key bindings ─────────────────────────────────────────────
    // Public, self-authenticating material (each binding is signed by the device's own
    // roster key and verified by fetchers against the KT roster), so it is stored in the
    // clear like the directory — encrypting it would protect nothing.

    pub fn upsert_call_key(&self, hash: &str, binding_json: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO call_keys (hash, binding_json) VALUES (?1, ?2)
             ON CONFLICT(hash) DO UPDATE SET binding_json = excluded.binding_json",
            params![hash, binding_json],
        )?;
        Ok(())
    }

    pub fn delete_call_key(&self, hash: &str) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM call_keys WHERE hash = ?1", params![hash])?;
        Ok(())
    }

    pub fn load_call_keys(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash, binding_json FROM call_keys")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.collect()
    }

    // ── Registration invite codes (hex SHA-256 of consumed codes — never the codes) ──

    /// Mark an invite code (by digest) as consumed. Idempotent.
    pub fn consume_invite(&self, code_hash: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO used_invites (code_hash) VALUES (?1)",
            params![code_hash],
        )?;
        Ok(())
    }

    /// Has this invite code (by digest) already been consumed?
    pub fn invite_used(&self, code_hash: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM used_invites WHERE code_hash = ?1")?;
        stmt.exists(params![code_hash])
    }

    pub fn load_push(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash, endpoint_blob FROM push")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (hash, blob) = row?;
            if let Some(plain) = self.decrypt(&blob) {
                if let Ok(endpoint) = String::from_utf8(plain) {
                    out.push((hash, endpoint));
                }
            }
        }
        Ok(out)
    }

    pub fn load_kt_entries(&self) -> rusqlite::Result<Vec<KtEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT json FROM kt_entries ORDER BY idx ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(entry) = serde_json::from_str(&row?) {
                out.push(entry);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
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
            .query_row(
                "SELECT blob FROM messages WHERE msg_id='secret-id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let needle = b"opaque-e2e-ciphertext";
        assert!(!raw.windows(needle.len()).any(|w| w == needle));
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
        db.delete_message("acked").unwrap();
        db.prune_expired(1000).unwrap();
        let msgs = db.load_messages(1000).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg_id, "keep");
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
}
