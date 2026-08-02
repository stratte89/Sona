//! Durable, encrypted-at-rest storage (SQLite).
//!
//! Design follows the zero-knowledge principle: the relay persists only what it must,
//! and what it persists reveals as little as possible to a stolen disk or backup.
//!
//! * **Message bodies, push endpoints, directory records and call-key bindings** are
//!   stored as AEAD blobs (XChaCha20-Poly1305) under a key held in the server's
//!   environment — **not on the data disk**. A leaked database file is undecryptable
//!   without that key. (Message *content* is already end-to-end encrypted; this protects
//!   the remaining at-rest metadata and keeps the blob opaque.)
//! * **Every mailbox-hash column is a keyed blind index**, not the hash itself (SP-04):
//!   `HMAC-SHA256(index_key, table_tag | hash)`, where `index_key` is derived from the
//!   same off-disk `storage_key`. The relay must be able to *look up* by hash on every
//!   route and every directory read, so those columns cannot simply be encrypted with a
//!   random nonce — but they do not have to be the hash. A deterministic keyed index
//!   answers the same equality queries, costs nothing at boot (no full-table decrypt),
//!   and is meaningless to anyone without the key.
//!
//!   This matters because the hash is **not secret against an offline dictionary**.
//!   `identity_hash() = SHA-256(username)`, unsalted, and it cannot be salted: senders
//!   have to compute it from the username alone. Usernames are short, human-chosen, and
//!   published on purpose (they are the discovery handle), so the whole ≤8-character
//!   lowercase-alphanumeric space is a sub-minute GPU search and a wordlist of real
//!   handles is seconds. Device mailboxes are equally computable: `device_mailbox_hash`
//!   mixes in a random device id, but the roster is published in the public KT log.
//!
//!   **What the blind index does and does not buy.** It does not hide *who has an
//!   account* — the KT log is public by design (below) and every mailbox address is
//!   derivable from it. It breaks the *linkage* from those public identities to the rows:
//!   a thief with the database but not the key cannot tell which mailbox a queued message,
//!   a push subscription, or a directory record belongs to, so per-user message counts and
//!   timing stop being attributable. That is a **cold-disk / backup** defence only: a live
//!   host compromise, or the operator, has the key.
//! * **`messages.msg_id` is keyed too**, jointly with the target hash. A plaintext
//!   `msg_id` would undo the whole thing: `msg_id` is chosen by the *sender*, so anyone
//!   who has ever messaged the victim knows one, and finding that row in a stolen database
//!   would re-identify the victim's blind index and with it every other row they own.
//! * **The KT log stays plaintext, deliberately.** Public auditability is the entire point
//!   of having it — an independent auditor must be able to read the log — so `kt_entries`
//!   is untouched. The identity leak there is inherent to Key Transparency and is accepted
//!   design. `blobs` / `sync_blobs` carry opaque client ciphertext under random
//!   capability ids and are not addressed by any mailbox, so there is no linkage to break.
//!
//! Net at-rest exposure to a disk thief: the public KT log, plus timing and counts that
//! are no longer attributable to a user. No content, no sender, no message bodies.
//!
//! > **Operational consequence: `STORAGE_KEY` is now load-bearing for the whole
//! > database.** It always was for message blobs and push endpoints; it now also keys the
//! > index and the directory/call-key records. Changing or losing it does not corrupt
//! > anything, but every row except the KT log becomes unreadable and unreachable —
//! > accounts would have to re-register. Back it up with the KT signing key.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use kt_log::{KtEntry, KtRecord, KtRosterEntry};
use protocol_types::Envelope;
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Mutex;

use crate::state::DirectoryEntry;

/// Upgrade-only: rewrites a pre-blind-index database in place on first open. Everything
/// it touches is the *old* schema, so it is kept out of this file.
mod migrate;
#[cfg(test)]
mod tests;

const NONCE_LEN: usize = 24;

type HmacSha256 = Hmac<Sha256>;

/// On-disk schema generation. `1` = mailbox-hash columns replaced by keyed blind indexes
/// (SP-04). Bumping this runs [`Db::migrate_blind_index`] on an older file in place.
const SCHEMA_VERSION: i64 = 1;

/// HKDF context for the blind-index key. Separates it from the AEAD use of
/// `storage_key`, which stays the raw key so existing blobs keep decrypting.
const INDEX_KEY_INFO: &[u8] = b"sona-db-blind-index-v1";

// Per-table domain tags for the blind index. One mailbox hash therefore indexes to a
// *different* value in each table, so a thief cannot even join the tables to each other
// ("this unknown account also has push registered") without the key. Within the messages
// table the target index is shared on purpose — deleting a whole mailbox needs it.
const IDX_DIRECTORY: &str = "directory";
const IDX_MESSAGE_TARGET: &str = "messages.target";
const IDX_MESSAGE_ROW: &str = "messages.row";
const IDX_PUSH: &str = "push";
const IDX_CALL_KEY: &str = "call_keys";

pub struct Db {
    conn: Mutex<Connection>,
    cipher: XChaCha20Poly1305,
    index_key: [u8; 32],
}

impl Db {
    /// Open (creating if absent) the database at `path`, using `storage_key` (32 bytes,
    /// held off-disk) to encrypt stored blobs and to key the blind index over every
    /// mailbox-hash column. An older, plaintext-hash database is migrated in place.
    pub fn open(path: &str, storage_key: &[u8; 32]) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let mut index_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, storage_key)
            .expand(INDEX_KEY_INFO, &mut index_key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let db = Self {
            conn: Mutex::new(conn),
            cipher: XChaCha20Poly1305::new(storage_key.into()),
            index_key,
        };
        // Order matters: rewrite any legacy tables FIRST (they exist under the same names
        // with the old columns, so `CREATE TABLE IF NOT EXISTS` would silently leave them
        // alone), then create whatever is missing.
        if db.migrate_blind_index()? {
            // Reclaim what the rewrite freed. SQLite keeps freed pages in the file with
            // their old bytes intact, so a migrated database would still contain every
            // plaintext hash column verbatim — the migration would look done and deliver
            // nothing against the disk thief it exists for. One full rewrite, on the
            // upgrade boot only; VACUUM cannot run inside the migration's transaction.
            if let Err(e) = db.conn.lock().unwrap().execute_batch("VACUUM;") {
                eprintln!(
                    "[db] blind-index migration committed, but VACUUM failed ({e}). \
                     The freed pages still hold the old plaintext hash columns — run \
                     `VACUUM` on the database (needs free space ≈ its size) to finish."
                );
            }
        }
        db.create_schema()?;
        Ok(db)
    }

    fn create_schema(&self) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS directory (
                 hash_idx TEXT PRIMARY KEY,
                 entry_blob BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS messages (
                 msg_key TEXT PRIMARY KEY,
                 target_idx TEXT NOT NULL,
                 blob BLOB NOT NULL,
                 expires_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_messages_target ON messages(target_idx);
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
                 hash_idx TEXT PRIMARY KEY,
                 sub_blob BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_blobs (
                 sync_id TEXT PRIMARY KEY,
                 data BLOB NOT NULL,
                 expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS call_keys (
                 hash_idx TEXT PRIMARY KEY,
                 binding_blob BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS used_invites (
                 code_hash TEXT PRIMARY KEY
             );
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))
    }

    // ── Blind index + sealed records ──────────────────────────────────────────

    /// Keyed, deterministic index for a mailbox hash in one table. Same input ⇒ same
    /// output, so `WHERE hash_idx = ?` still works; without `index_key` the mapping is a
    /// PRF and the offline dictionary that recovers a username from a SHA-256 does not
    /// apply. `tag` is a fixed internal constant and the hash is 64 hex chars, so the two
    /// cannot run together ambiguously.
    fn blind(&self, tag: &str, hash: &str) -> String {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.index_key).expect("HMAC takes any key");
        mac.update(tag.as_bytes());
        mac.update(b"|");
        mac.update(hash.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Row key for one queued message: keyed over **both** halves of the old primary key.
    ///
    /// `msg_id` must not survive in the clear. It is minted by the sender, so an attacker
    /// who has ever messaged the victim knows one of the victim's row ids by heart; a
    /// plaintext column would let them find that row in a stolen database and read off the
    /// victim's `target_idx`, re-identifying every other row that mailbox owns. Keying the
    /// two together also keeps the fan-out unlinkable: one logical message delivered to
    /// several mailboxes no longer shares a visible token across them.
    fn blind_row(&self, target_hash: &str, msg_id: &str) -> String {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.index_key).expect("HMAC takes any key");
        mac.update(IDX_MESSAGE_ROW.as_bytes());
        mac.update(b"|");
        // Fixed-width (64 hex chars, validated on the wire) — no separator ambiguity with
        // an attacker-chosen msg_id.
        mac.update(target_hash.as_bytes());
        mac.update(b"|");
        mac.update(msg_id.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Seal a record together with the plaintext mailbox hash it belongs to. The hash has
    /// to come back at boot (the in-memory maps are keyed by it) and the blind index is
    /// one-way, so it rides *inside* the ciphertext rather than in a second column.
    fn seal_record(&self, hash: &str, payload: &str) -> Vec<u8> {
        self.encrypt(&serde_json::to_vec(&(hash, payload)).expect("two strings serialize"))
    }

    /// Inverse of [`Self::seal_record`]. `None` for a row written under a different
    /// `STORAGE_KEY` (or a corrupt one) — callers skip it rather than abort startup.
    fn open_record(&self, blob: &[u8]) -> Option<(String, String)> {
        serde_json::from_slice(&self.decrypt(blob)?).ok()
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

    // ── Directory (public key material, sealed so the row cannot be linked back
    //    to the account that owns it) ──────────────────────────────────────────

    pub fn upsert_directory(&self, hash: &str, entry: &DirectoryEntry) -> rusqlite::Result<()> {
        let json = serde_json::to_string(entry).expect("DirectoryEntry serializes");
        // The record itself is public material, but leaving it in the clear would undo the
        // blind index: `kt_entries` publishes (username_hash, identity_key) pairs, so a
        // plaintext directory row could be matched to one on its keys and re-identified.
        let blob = self.seal_record(hash, &json);
        self.conn.lock().unwrap().execute(
            "INSERT INTO directory (hash_idx, entry_blob) VALUES (?1, ?2)
             ON CONFLICT(hash_idx) DO UPDATE SET entry_blob = excluded.entry_blob",
            params![self.blind(IDX_DIRECTORY, hash), blob],
        )?;
        Ok(())
    }

    /// Remove a directory record (a device revoked from its account's roster).
    pub fn delete_directory(&self, hash: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM directory WHERE hash_idx = ?1",
            params![self.blind(IDX_DIRECTORY, hash)],
        )?;
        Ok(())
    }

    pub fn load_directory(&self) -> rusqlite::Result<Vec<(String, DirectoryEntry)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT entry_blob FROM directory")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let Some((hash, json)) = self.open_record(&row?) else {
                continue;
            };
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
            "INSERT OR IGNORE INTO messages (msg_key, target_idx, blob, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                self.blind_row(env.to.as_str(), &env.msg_id),
                self.blind(IDX_MESSAGE_TARGET, env.to.as_str()),
                blob,
                expires_at.map(|e| e as i64)
            ],
        )?;
        Ok(())
    }

    /// Drop one delivered message from **one** mailbox, on that mailbox's own ack.
    ///
    /// Both halves of the key are required (SP-05). The row key is keyed over
    /// `(target_hash, msg_id)` and `msg_id` is deliberately shared across mailboxes —
    /// `prepare_fanout` mints one id per logical message and reuses it for every
    /// recipient device *and* every sender self-sync copy. Deleting on `msg_id` alone
    /// therefore erased the durable rows for every other device that had not yet acked:
    /// silent multi-device data loss on the next relay restart, and — since a sender
    /// knows every id it sent — a way for any account to delete a message out of
    /// someone else's mailbox by acking that id on its own socket.
    pub fn delete_message(&self, target_hash: &str, msg_id: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM messages WHERE msg_key = ?1",
            params![self.blind_row(target_hash, msg_id)],
        )?;
        Ok(())
    }

    /// Drop every queued message for one mailbox (account deletion).
    pub fn delete_messages_for(&self, target_hash: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM messages WHERE target_idx = ?1",
            params![self.blind(IDX_MESSAGE_TARGET, target_hash)],
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
        let blob = self.seal_record(hash, endpoint);
        self.conn.lock().unwrap().execute(
            "INSERT INTO push (hash_idx, sub_blob) VALUES (?1, ?2)
             ON CONFLICT(hash_idx) DO UPDATE SET sub_blob = excluded.sub_blob",
            params![self.blind(IDX_PUSH, hash), blob],
        )?;
        Ok(())
    }

    pub fn delete_push(&self, hash: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM push WHERE hash_idx = ?1",
            params![self.blind(IDX_PUSH, hash)],
        )?;
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
    // The binding is public, self-authenticating material (signed by the device's own
    // roster key and verified by fetchers against the KT roster) — but it names its
    // `device_id`, and the roster that publishes that id is public too, so a plaintext row
    // would re-identify the mailbox the blind index is hiding. Sealed like the directory.

    pub fn upsert_call_key(&self, hash: &str, binding_json: &str) -> rusqlite::Result<()> {
        let blob = self.seal_record(hash, binding_json);
        self.conn.lock().unwrap().execute(
            "INSERT INTO call_keys (hash_idx, binding_blob) VALUES (?1, ?2)
             ON CONFLICT(hash_idx) DO UPDATE SET binding_blob = excluded.binding_blob",
            params![self.blind(IDX_CALL_KEY, hash), blob],
        )?;
        Ok(())
    }

    pub fn delete_call_key(&self, hash: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM call_keys WHERE hash_idx = ?1",
            params![self.blind(IDX_CALL_KEY, hash)],
        )?;
        Ok(())
    }

    pub fn load_call_keys(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT binding_blob FROM call_keys")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Some(pair) = self.open_record(&row?) {
                out.push(pair);
            }
        }
        Ok(out)
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
        let mut stmt = conn.prepare("SELECT sub_blob FROM push")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Some(pair) = self.open_record(&row?) {
                out.push(pair);
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
