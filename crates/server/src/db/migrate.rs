//! One-time rewrite of a pre-blind-index database (SP-04).
//!
//! Split out of `db/mod.rs` because it is upgrade-only code with a different lifetime
//! from the schema it migrates *to*: it runs at most once per database and is dead
//! weight on every boot after that. Keeping it beside the live queries also made the
//! module read as if the legacy shape were still a thing the relay supports. It is not —
//! nothing else in the crate may reference the plaintext-hash columns.

use rusqlite::{params, Connection};

use super::{Db, IDX_CALL_KEY, IDX_DIRECTORY, IDX_MESSAGE_TARGET, IDX_PUSH, SCHEMA_VERSION};

impl Db {
    // ── Migration: plaintext hash columns → keyed blind index (SP-04) ─────────

    /// Rewrite a pre-[`SCHEMA_VERSION`] database in place: every mailbox-hash column
    /// becomes a blind index, and the records that carried a hash in a plaintext column
    /// (directory, push, call keys) are re-sealed with the hash inside the ciphertext.
    ///
    /// Runs in ONE transaction — a crash mid-migration leaves the old file intact rather
    /// than a half-blinded one nothing can read. `kt_entries`, `blobs`, `sync_blobs` and
    /// `used_invites` are untouched by design.
    ///
    /// Rows whose existing AEAD blob does not open (written under a different
    /// `STORAGE_KEY`) are dropped, not carried forward: they were already unreadable, and
    /// the migration cannot re-seal what it cannot decrypt.
    ///
    /// Returns whether it rewrote anything — the caller then has to reclaim the freed
    /// pages, which still hold the old plaintext.
    pub(super) fn migrate_blind_index(&self) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version >= SCHEMA_VERSION {
            return Ok(false);
        }
        // A fresh file has no legacy tables at all; `create_schema` handles it.
        let legacy = ["directory", "messages", "push", "call_keys"]
            .iter()
            .try_fold(false, |acc, t| {
                Ok::<_, rusqlite::Error>(acc || has_legacy_hash_column(&conn, t)?)
            })?;
        if !legacy {
            return Ok(false);
        }
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        let result = (|| -> rusqlite::Result<()> {
            if has_legacy_hash_column(&conn, "directory")? {
                conn.execute_batch(
                    "CREATE TABLE directory_v1 (
                         hash_idx TEXT PRIMARY KEY,
                         entry_blob BLOB NOT NULL
                     );",
                )?;
                let mut read = conn.prepare("SELECT hash, json FROM directory")?;
                let mut write = conn
                    .prepare("INSERT INTO directory_v1 (hash_idx, entry_blob) VALUES (?1, ?2)")?;
                let mut rows = read.query([])?;
                while let Some(row) = rows.next()? {
                    let hash: String = row.get(0)?;
                    let json: String = row.get(1)?;
                    write.execute(params![
                        self.blind(IDX_DIRECTORY, &hash),
                        self.seal_record(&hash, &json)
                    ])?;
                }
                drop(rows);
                conn.execute_batch(
                    "DROP TABLE directory; ALTER TABLE directory_v1 RENAME TO directory;",
                )?;
            }
            if has_legacy_hash_column(&conn, "messages")? {
                conn.execute_batch(
                    "CREATE TABLE messages_v1 (
                         msg_key TEXT PRIMARY KEY,
                         target_idx TEXT NOT NULL,
                         blob BLOB NOT NULL,
                         expires_at INTEGER
                     );",
                )?;
                // Streamed, not collected: the message table is the big one and a relay
                // holding a month of undelivered mail must not need it all in memory to
                // start. The envelope blob is copied verbatim — same AEAD key, so this
                // never re-encrypts message bodies.
                let mut read =
                    conn.prepare("SELECT msg_id, target_hash, blob, expires_at FROM messages")?;
                let mut write = conn.prepare(
                    "INSERT OR IGNORE INTO messages_v1 (msg_key, target_idx, blob, expires_at)
                     VALUES (?1, ?2, ?3, ?4)",
                )?;
                let mut rows = read.query([])?;
                while let Some(row) = rows.next()? {
                    let msg_id: String = row.get(0)?;
                    let target: String = row.get(1)?;
                    let blob: Vec<u8> = row.get(2)?;
                    let expires: Option<i64> = row.get(3)?;
                    write.execute(params![
                        self.blind_row(&target, &msg_id),
                        self.blind(IDX_MESSAGE_TARGET, &target),
                        blob,
                        expires
                    ])?;
                }
                drop(rows);
                conn.execute_batch(
                    "DROP TABLE messages;
                     ALTER TABLE messages_v1 RENAME TO messages;
                     CREATE INDEX IF NOT EXISTS idx_messages_target ON messages(target_idx);",
                )?;
            }
            if has_legacy_hash_column(&conn, "push")? {
                conn.execute_batch(
                    "CREATE TABLE push_v1 (
                         hash_idx TEXT PRIMARY KEY,
                         sub_blob BLOB NOT NULL
                     );",
                )?;
                let mut read = conn.prepare("SELECT hash, endpoint_blob FROM push")?;
                let mut write =
                    conn.prepare("INSERT INTO push_v1 (hash_idx, sub_blob) VALUES (?1, ?2)")?;
                let mut rows = read.query([])?;
                while let Some(row) = rows.next()? {
                    let hash: String = row.get(0)?;
                    let blob: Vec<u8> = row.get(1)?;
                    // The endpoint was already AEAD-sealed on its own; re-seal it together
                    // with the hash so the record carries its own address.
                    let Some(plain) = self.decrypt(&blob) else {
                        continue;
                    };
                    let Ok(endpoint) = String::from_utf8(plain) else {
                        continue;
                    };
                    write.execute(params![
                        self.blind(IDX_PUSH, &hash),
                        self.seal_record(&hash, &endpoint)
                    ])?;
                }
                drop(rows);
                conn.execute_batch("DROP TABLE push; ALTER TABLE push_v1 RENAME TO push;")?;
            }
            if has_legacy_hash_column(&conn, "call_keys")? {
                conn.execute_batch(
                    "CREATE TABLE call_keys_v1 (
                         hash_idx TEXT PRIMARY KEY,
                         binding_blob BLOB NOT NULL
                     );",
                )?;
                let mut read = conn.prepare("SELECT hash, binding_json FROM call_keys")?;
                let mut write = conn
                    .prepare("INSERT INTO call_keys_v1 (hash_idx, binding_blob) VALUES (?1, ?2)")?;
                let mut rows = read.query([])?;
                while let Some(row) = rows.next()? {
                    let hash: String = row.get(0)?;
                    let json: String = row.get(1)?;
                    write.execute(params![
                        self.blind(IDX_CALL_KEY, &hash),
                        self.seal_record(&hash, &json)
                    ])?;
                }
                drop(rows);
                conn.execute_batch(
                    "DROP TABLE call_keys; ALTER TABLE call_keys_v1 RENAME TO call_keys;",
                )?;
            }
            conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
        })();
        match result {
            Ok(()) => conn.execute_batch("COMMIT;").map(|()| true),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        }
    }
}

/// Does `table` still carry a plaintext mailbox-hash column (`hash` / `target_hash`)?
/// That is exactly what the pre-[`SCHEMA_VERSION`] schema had and the blinded one does
/// not, so it is the migration trigger. A table that does not exist yields no rows and
/// therefore `false` — a fresh database needs no migration.
fn has_legacy_hash_column(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    // `table` is one of this module's own constants, never user input.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == "hash" || name == "target_hash" {
            return Ok(true);
        }
    }
    Ok(false)
}
