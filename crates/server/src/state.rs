//! Shared server state. Everything the relay knows lives here — and notably, what it
//! knows is deliberately tiny: public key bundles addressed by hash, opaque queued
//! ciphertext, short-lived login nonces, and live delivery channels. No plaintext, no
//! sender index, no password.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;

use kt_log::KtLog;
use serde::{Deserialize, Serialize};

use crate::access::{AccessMode, Cidr};
use crate::auth::{ByteBudget, ChallengeStore, RateLimiter};
use crate::db::Db;
use crate::store::MessageStore;

/// Fixed window for the per-client byte budgets.
pub const BYTE_WINDOW_SECS: u64 = 600;
/// Blob/sync upload bytes allowed per client per window.
pub const UPLOAD_BYTES_PER_WINDOW: u64 = 256 * 1024 * 1024;
/// Blob/sync download bytes allowed per client per window.
pub const DOWNLOAD_BYTES_PER_WINDOW: u64 = 1024 * 1024 * 1024;

/// A user's published directory record. All values are public key material (base64).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub identity_key: String,
    pub signing_key: String,
    /// Unused one-time keys, consumed one per new inbound session.
    pub one_time_keys: VecDeque<String>,
    /// Reusable last-resort pre-key, served when `one_time_keys` is empty so sessions can
    /// still be established. Not consumed. `None` until the client uploads one.
    #[serde(default)]
    pub fallback_key: Option<String>,
}

/// A registered content-free push subscription: where to send the wake POST, and when
/// we last did (for debouncing — a message flood must not become an HTTP flood at the
/// push provider). Wake timestamps are per class: a chat-message burst must not eat a
/// call offer's immediate wake, and vice versa.
#[derive(Clone, Debug, Default)]
pub struct PushSub {
    pub endpoint: String,
    /// Last `WakeClass::Normal` wake (debounced by `Config::wake_debounce_secs`).
    pub last_wake_normal: u64,
    /// Last `WakeClass::Call` wake (own min-interval `Config::call_wake_min_secs`).
    pub last_wake_call: u64,
}

/// Everything behind the global lock.
pub struct Inner {
    pub directory: HashMap<String, DirectoryEntry>,
    pub store: MessageStore,
    pub challenges: ChallengeStore,
    /// Live WebSocket delivery channels, keyed by recipient hash. A user may have
    /// several (multiple devices / tabs), so each hash maps to a list of senders.
    pub live: HashMap<String, Vec<UnboundedSender<String>>>,
    pub rate: RateLimiter,
    /// Separate, stricter limiter for the account-creation surface (`/register`,
    /// `/challenge`). These grow permanent/at-rest state, so they get their own tighter
    /// budget independent of the message-send limiter (M-3).
    pub auth_rate: RateLimiter,
    /// Username-change backstop: release entries per **signing key** (a release is the
    /// rename's signature move), capped per rolling week. The client enforces the same
    /// product limit locally; this stops a modified client from spamming the log.
    pub rename_rate: RateLimiter,
    /// The append-only Key Transparency log. Every key binding/rotation goes here, so
    /// the server can never silently hand out a forged key without leaving evidence.
    pub kt: KtLog,
    /// Durable backing store. `None` = in-memory only (tests / ephemeral runs); `Some`
    /// = write-through to encrypted SQLite so state survives a restart.
    pub db: Option<Db>,
    /// In-memory attachment blobs (opaque client ciphertext), used only when there is no
    /// `db`. With a `db`, blobs live there instead. Value = (bytes, expires_at).
    pub blobs: HashMap<String, (Vec<u8>, Option<u64>)>,
    /// Content-free push subscriptions, keyed by recipient hash. The wake carries no
    /// content and no identity — the push provider learns only "this endpoint got poked".
    pub push: HashMap<String, PushSub>,
    /// In-memory history-sync blobs (opaque client ciphertext, capability-addressed by
    /// random id), used only when there is no `db`. Value = (bytes, expires_at).
    pub sync_blobs: HashMap<String, (Vec<u8>, u64)>,
    /// Live delivery-socket count per pseudonymized client, capped at
    /// [`Config::max_ws_per_client`] so one address cannot hold thousands of sockets.
    pub ws_count: HashMap<String, usize>,
    /// Byte budget for blob/sync **uploads** per client (the request-count limiter alone
    /// would still allow a multi-GiB/min disk fill).
    pub upload_bytes: ByteBudget,
    /// Byte budget for blob/sync **downloads** per client (bounds egress amplification:
    /// upload once, hammer downloads).
    pub download_bytes: ByteBudget,
    /// Consumed registration invite codes (hex digests) — in-memory fallback used only
    /// when there is no `db` (tests / ephemeral runs); with a `db` the durable
    /// `used_invites` table is authoritative, so a restart cannot resurrect a code.
    pub used_invites: std::collections::HashSet<String>,
}

/// Static-ish configuration. `prod` turns on origin enforcement; `rate_salt` keys the
/// rate-limiter pseudonymization.
#[derive(Clone)]
pub struct Config {
    pub prod: bool,
    pub allowed_origins: Vec<String>,
    pub rate_salt: String,
    /// Minimum seconds between `WakeClass::Normal` wake POSTs to one recipient's push
    /// endpoint. Messages arriving inside the window ride on the previous wake (the
    /// client drains its whole mailbox when poked), so nothing is lost — only
    /// duplicate pokes.
    pub wake_debounce_secs: u64,
    /// Minimum seconds between `WakeClass::Call` wakes per recipient. Deliberately tiny
    /// (a call must ring *now*), but non-zero so a hostile peer spamming offers cannot
    /// turn the relay into a battery-DoS amplifier (sender envelope rate limits apply
    /// upstream as well).
    pub call_wake_min_secs: u64,
    /// Max concurrent call rooms (M-4). Configurable via the `MAX_ROOMS` env var.
    pub max_rooms: usize,
    /// Giphy API key for the GIF-search privacy proxy (`/v1/gif/*`). `None` disables
    /// both endpoints and drops the capability advert — clients then hide the GIF UI.
    /// The relay proxies search AND media so user IPs never reach the GIF provider.
    pub giphy_key: Option<String>,
    /// How long a released username stays reserved to its old owner before anyone may
    /// take it over. Defaults to [`kt_log::RELEASE_GRACE_SECS`] (7 days); configurable
    /// via the `RELEASE_GRACE_SECS` env var so a test relay can exercise the flow.
    pub release_grace_secs: u64,
    /// Discoverability tier (`ACCESS_MODE`): open / token / stealth. See [`crate::access`].
    pub access_mode: AccessMode,
    /// SHA-256 digests of the accepted shared access tokens (`RELAY_ACCESS_TOKENS`,
    /// comma-separated — a list so rotation can overlap). Digests only; the tokens
    /// themselves are never held.
    pub access_token_hashes: Vec<[u8; 32]>,
    /// Optional IP allowlist (`IP_ALLOWLIST`, comma-separated CIDRs). Empty = off.
    pub ip_allowlist: Vec<Cidr>,
    /// Max concurrent delivery sockets per client address (`MAX_WS_PER_IP`). Generous —
    /// several devices/tabs share one NAT address — while stopping a socket-hoard DoS.
    pub max_ws_per_client: usize,
    /// Global ceiling on stored blob + sync bytes (`MAX_STORAGE_BYTES`, default 10 GiB).
    /// The per-client byte budgets bound one address; this bounds the sum — a botnet
    /// spreading uploads across many addresses must not fill the disk. Uploads over the
    /// ceiling get `507 Insufficient Storage`; expiry (TTL reaper) frees space.
    pub max_storage_bytes: u64,
    /// Hard retention ceiling for attachment blobs, seconds (`BLOB_TTL_DAYS`, default
    /// 30 days). Every upload is stamped `now + this` and the periodic reaper deletes
    /// past-due rows unconditionally. This is the ONLY server-side deletion mechanism
    /// for attachments: message/chat deletion signals are end-to-end encrypted and
    /// uploads are sealed-sender, so the relay cannot map a blob to a message — by
    /// design it deletes on schedule, never on chat activity.
    pub blob_ttl_secs: u64,
    /// Hex SHA-256 digests of single-use registration invite codes
    /// (`REGISTRATION_CODES`). Non-empty = brand-new account claims require an unused
    /// code in `x-sona-invite`; rotations/renames/rosters are never gated. Empty = off.
    /// Separate from the access token on purpose: this controls who may *join* (and so
    /// grow the permanent KT log), the token controls who may *reach* the relay at all.
    pub registration_code_hashes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            prod: false,
            allowed_origins: Vec::new(),
            rate_salt: "dev-rate-salt".to_string(),
            wake_debounce_secs: 30,
            call_wake_min_secs: 2,
            max_rooms: crate::call::DEFAULT_MAX_ROOMS,
            giphy_key: None,
            release_grace_secs: kt_log::RELEASE_GRACE_SECS,
            access_mode: AccessMode::Open,
            access_token_hashes: Vec::new(),
            ip_allowlist: Vec::new(),
            max_ws_per_client: 16,
            max_storage_bytes: 10 * 1024 * 1024 * 1024,
            blob_ttl_secs: 30 * 24 * 3600,
            registration_code_hashes: Vec::new(),
        }
    }
}

/// Cloneable handle to shared state (Arc inside), as required by axum's `State`.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Mutex<Inner>>,
    pub config: Arc<Config>,
    /// FCM wake sender (`fcm:<token>` push endpoints). `None` = the relay has no
    /// Firebase service account configured; `fcm:` registrations are refused and the
    /// `push-fcm-v1` capability is not advertised.
    pub fcm: Option<Arc<crate::push::FcmSender>>,
    /// Live call rooms (voice relay). Own mutex: a media frame arrives every 20 ms per
    /// call leg and must never queue behind message-store work.
    pub calls: Arc<Mutex<crate::call::CallRooms>>,
    /// The QUIC media endpoint's discovery info (`GET /v1/call/quic`), set once at
    /// startup when the endpoint binds. `None` = QUIC disabled, clients use WebSocket.
    pub quic: Arc<Mutex<Option<crate::quic::QuicInfo>>>,
}

impl AppState {
    /// Build state with a freshly generated Key Transparency key. Fine for tests and a
    /// first boot; production should persist and reload the key via [`Self::with_kt`].
    pub fn new(config: Config) -> Self {
        Self::with_kt(config, KtLog::generate())
    }

    /// Build state with a specific Key Transparency log (e.g. one loaded from a
    /// persisted signing key, so the pinned public key is stable across restarts).
    pub fn with_kt(config: Config, kt: KtLog) -> Self {
        Self::assemble(config, kt, MessageStore::new(), HashMap::new(), None)
    }

    /// Build durable state: replay the KT log, message queue, and directory from the
    /// encrypted database so a restart resumes exactly where it left off. `kt` must
    /// already carry the persisted signing key (so the pinned public key is stable).
    pub fn persistent(config: Config, mut kt: KtLog, db: Db) -> Self {
        let t = now();
        let _ = db.prune_expired(t);
        // Before replay: a takeover accepted under a shorter configured grace must
        // revalidate under the same grace, or the rebuilt log would silently drop it.
        kt.set_release_grace_secs(config.release_grace_secs);

        // Rebuild the Merkle log by replaying leaves (bindings AND rosters) in their
        // original append order. append()/append_roster() re-validate each record, so a
        // tampered DB row cannot corrupt the log.
        if let Ok(records) = db.load_kt_records() {
            for record in records {
                let result = match record {
                    kt_log::KtRecord::Binding(entry) => kt.append(entry).map(|_| ()),
                    kt_log::KtRecord::Roster(roster) => kt.append_roster(roster).map(|_| ()),
                };
                if let Err(e) = result {
                    eprintln!("[db] skipping invalid KT record on load: {e}");
                }
            }
        }

        let mut directory = HashMap::new();
        if let Ok(rows) = db.load_directory() {
            for (hash, entry) in rows {
                directory.insert(hash, entry);
            }
        }

        let mut store = MessageStore::new();
        if let Ok(messages) = db.load_messages(t) {
            for env in messages {
                let _ = store.enqueue(env, t);
            }
        }

        let mut push = HashMap::new();
        if let Ok(rows) = db.load_push() {
            for (hash, endpoint) in rows {
                push.insert(
                    hash,
                    PushSub {
                        endpoint,
                        ..PushSub::default()
                    },
                );
            }
        }

        let state = Self::assemble(config, kt, store, directory, Some(db));
        state.inner.lock().unwrap().push = push;
        state
    }

    fn assemble(
        config: Config,
        mut kt: KtLog,
        store: MessageStore,
        directory: HashMap<String, DirectoryEntry>,
        db: Option<Db>,
    ) -> Self {
        kt.set_release_grace_secs(config.release_grace_secs);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                directory,
                store,
                challenges: ChallengeStore::default(),
                live: HashMap::new(),
                // 60 message-sends per minute per client is generous for a human and
                // still bounds a flood. Fail-closed once exceeded.
                rate: RateLimiter::new(60, 60),
                // Registration/challenge are rarer and grow permanent state — 20/min per
                // client is plenty for real logins while blunting a mass-claim flood.
                auth_rate: RateLimiter::new(20, 60),
                // 5 username changes (= releases) per key per rolling week.
                rename_rate: RateLimiter::new(5, 7 * 86400),
                kt,
                db,
                blobs: HashMap::new(),
                push: HashMap::new(),
                sync_blobs: HashMap::new(),
                ws_count: HashMap::new(),
                // Byte budgets (10-minute windows). Uploads: 256 MiB — dozens of max-size
                // attachments or several full history syncs, but no multi-GiB disk fill.
                // Downloads: 1 GiB — a device re-fetching plenty of media, but no
                // unmetered egress drain.
                upload_bytes: ByteBudget::new(UPLOAD_BYTES_PER_WINDOW, BYTE_WINDOW_SECS),
                download_bytes: ByteBudget::new(DOWNLOAD_BYTES_PER_WINDOW, BYTE_WINDOW_SECS),
                used_invites: std::collections::HashSet::new(),
            })),
            config: Arc::new(config),
            fcm: None,
            calls: Arc::new(Mutex::new(crate::call::CallRooms::default())),
            quic: Arc::new(Mutex::new(None)),
        }
    }

    /// Attach an FCM wake sender (call before the state is cloned into the router).
    pub fn with_fcm(mut self, fcm: crate::push::FcmSender) -> Self {
        self.fcm = Some(Arc::new(fcm));
        self
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Current unix time in seconds. Single choke-point so it is easy to find/replace.
pub fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
