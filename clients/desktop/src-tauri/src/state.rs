use crate::*;

/// The process-global delivery engine (see `engine.rs`).
pub(crate) fn eng() -> &'static engine::Engine {
    engine::global()
}

/// Relay trust config. Persisted as plaintext `config.json` — the pinned KT key is a
/// *public* key and the whole point is that it's fixed and inspectable. The optional
/// access token is a shared relay-membership secret (private relays, `ACCESS_MODE=
/// token/stealth`); it gates *reaching* the relay, not any account or vault, so plain
/// config-file storage is the right tier for it (same as the relay URL it belongs to).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RelayConfig {
    pub(crate) base_url: String,
    pub(crate) ws_url: String,
    pub(crate) pinned_kt_key: String,
    #[serde(default)]
    pub(crate) access_token: Option<String>,
}

/// Tauri-side handle to the engine's session. The unlocked [`Account`], the relay
/// [`Client`], and the decrypted [`History`] live in the ENGINE's session (the same
/// `Arc` — see `engine.rs`); commands reach them through this state exactly as before.
/// Focus, the open chat, and the media UI channel moved onto the engine so the
/// delivery path works with no Tauri at all (headless Android starts). Focus starts
/// FALSE on the engine (RC-5): a headless start must never suppress notifications.
pub(crate) struct AppState {
    pub(crate) inner: Arc<Mutex<Session>>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            inner: engine::global().session.clone(),
        }
    }
}

/// Non-secret local security preferences. Plaintext on disk (`prefs.json`) because they
/// are needed *before* unlock (the lock screen must know which unlock methods to offer).
/// Nothing here weakens the vault: the wrapped seal-key blobs are separate files, and the
/// PIN attempt counter is defense-in-depth against casual guessing, not against root
/// (a root attacker is outside the lock screen's threat model — see docs).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Prefs {
    /// Auto-lock after this many seconds of inactivity. `None` = disabled (default).
    #[serde(default)]
    pub(crate) lock_after_secs: Option<u64>,
    /// Ask the user to re-enter their PIN every Nth app open (so it isn't forgotten,
    /// Signal-style). `None` = off (default).
    #[serde(default)]
    pub(crate) pin_reminder_every: Option<u32>,
    #[serde(default)]
    pub(crate) opens_since_pin_check: u32,
    /// Consecutive failed PIN entries. At [`MAX_PIN_ATTEMPTS`] the PIN blob is wiped and
    /// only the password unlocks.
    #[serde(default)]
    pub(crate) pin_attempts: u32,
    /// Open the vault at startup with the device-key-wrapped blob — no prompt at all.
    #[serde(default)]
    pub(crate) auto_unlock: bool,
    /// A biometric-gated Keystore blob exists (Android only).
    #[serde(default)]
    pub(crate) bio_enabled: bool,
    /// Privacy: send "typing…" indicators to peers (default ON). When off, this device
    /// sends nothing — it never sends-then-hides.
    #[serde(default = "default_true")]
    pub(crate) send_typing: bool,
    /// Privacy: send read (seen) receipts (default ON). Gates the seen-receipt send path
    /// only; incoming receipts are still displayed.
    #[serde(default = "default_true")]
    pub(crate) send_receipts: bool,
    /// Notification content level: `"sender_message"`, `"sender"` (default), or `"generic"`.
    #[serde(default = "default_notif_level")]
    pub(crate) notif_level: String,
    /// Delivery mode: `"c"` connection (Google-free), `"cp"` connection + push
    /// fallback, `"p"` push only. Applied live by the engine (docs/NOTIFICATIONS.md §7.1).
    /// Until the user picks one (`delivery_mode_set`), the stored value is an
    /// auto-resolved DEFAULT: connection + push fallback where a wake transport is
    /// usable, else the connection alone — see `maybe_auto_delivery_mode`. The default
    /// is never `"p"`: push-only is an explicit choice (`internal/CALL_PLAN.md` §9).
    #[serde(default = "default_delivery_mode")]
    pub(crate) delivery_mode: String,
    /// The user explicitly chose a delivery mode in settings. From then on the
    /// auto-default logic never touches `delivery_mode` again.
    #[serde(default)]
    pub(crate) delivery_mode_set: bool,
    /// The push endpoint we last registered with the relay (e.g. `fcm:<token>`), so a
    /// rotated FCM token is re-registered on the next unlock. `None` = not registered.
    #[serde(default)]
    pub(crate) push_endpoint: Option<String>,
    /// Require a human check before this device may answer a call **over the OS keyguard**.
    /// Default on: a call answered from the lock screen would otherwise be a call answered
    /// by whoever is holding the phone.
    ///
    /// The state that matters is the *device* being locked, not the vault. Reading the vault
    /// instead made this inert in the default configuration, because `lock_after_secs`
    /// defaults to `None` and the vault therefore stays open from the user's last unlock
    /// (A-19). Android-specific in the UI (`internal/CALL_PLAN.md` §8); elsewhere there is no
    /// keyguard between the user and a ring they can see, so it changes nothing.
    #[serde(default = "default_true")]
    pub(crate) require_unlock_to_answer: bool,
    /// How long this device keeps internal call-control records — terminal tombstones in
    /// the call-only store, never call audio or the visible call-history chips. Seconds;
    /// `0` means "no historical retention", and the store still enforces the short
    /// anti-replay window a late offer needs (`MIN_TOMBSTONE_SECS`). Android-specific in
    /// the UI; harmless elsewhere.
    #[serde(default = "default_call_retention")]
    pub(crate) call_retention_secs: u64,
    /// SOCKS5 proxy for every relay connection (`socks5://host:port` — Tor/Orbot).
    /// `None` = direct. Applied at `Client` construction; while set, the QUIC call
    /// media path is disabled in client-core (UDP bypasses SOCKS) and calls use
    /// relay-bridged WebSocket media.
    #[serde(default)]
    pub(crate) socks_proxy: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_notif_level() -> String {
    "sender".into()
}
fn default_delivery_mode() -> String {
    "c".into()
}
/// Seven days, per `internal/CALL_PLAN.md` §2. There is deliberately no "forever" choice.
fn default_call_retention() -> u64 {
    7 * 24 * 3600
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            lock_after_secs: None,
            pin_reminder_every: None,
            opens_since_pin_check: 0,
            pin_attempts: 0,
            auto_unlock: false,
            bio_enabled: false,
            send_typing: true,
            send_receipts: true,
            notif_level: default_notif_level(),
            delivery_mode: default_delivery_mode(),
            delivery_mode_set: false,
            push_endpoint: None,
            require_unlock_to_answer: true,
            call_retention_secs: default_call_retention(),
            socks_proxy: None,
        }
    }
}

/// Wipe the PIN blob after this many consecutive wrong entries.
pub(crate) const MAX_PIN_ATTEMPTS: u32 = 5;
/// How long an OS presence check (fingerprint / device credential) authorizes the final
/// step of a change ceremony.
pub(crate) const PRESENCE_WINDOW_SECS: u64 = 120;

#[derive(Default)]
pub(crate) struct Session {
    /// App-data directory; set once at startup.
    pub(crate) data_dir: PathBuf,
    pub(crate) config: Option<RelayConfig>,
    pub(crate) client: Option<Arc<Client>>,
    pub(crate) account: Option<Account>,
    pub(crate) history: History,
    pub(crate) prefs: Prefs,
    /// When the last successful OS presence check happened (change-ceremony step 2).
    /// Cleared on lock.
    pub(crate) last_presence_ok: Option<std::time::Instant>,
    /// Shutdown signal for the live-delivery task. Sending `true` (or dropping) makes it
    /// exit promptly; replaced on every unlock. The password itself is NOT kept in
    /// memory — the account caches the derived vault key for cheap re-seals.
    pub(crate) stop: Option<tokio::sync::watch::Sender<bool>>,
    /// The live (or ringing-outbound) voice call, if any. One at a time.
    pub(crate) call: Option<CallCtl>,
    /// An outbound call whose offers are already on the wire but whose media room is not
    /// up yet, and the claims that arrived in that window (E-6).
    ///
    /// `call_start_inner` posts the offers, and only *then* runs `spawn_call` — a mic open
    /// and a room join, which the code itself calls "the slower" part. `s.call` is installed
    /// at the end of that. The claim handler requires `s.call`, so a callee that answered
    /// promptly had its claim dropped on the floor with no retry: no winner was ever sent,
    /// the callee sat on "establishing secure connection…" until the signal TTL, and the
    /// caller went on showing "ringing…". Being a race is why it was intermittent.
    pub(crate) outgoing_setup: Option<OutgoingSetup>,
    /// An unanswered inbound ring. Never persisted: the call key must not touch disk.
    pub(crate) incoming: Option<PendingOffer>,
    /// An answer claim awaiting the caller's matching winner acknowledgement. Keeping
    /// media material only in memory prevents a losing sibling from joining the room.
    pub(crate) claiming: Option<PendingClaim>,
    /// This device's call-control secret, once loaded. Opens incoming-call capsules and
    /// nothing else; sealed on disk under the device key rather than the vault, so the
    /// call subsystem can work while the chat vault is locked. `None` = this device has
    /// no key store, so it has no call-control identity.
    /// Shared so a capsule drain can run with the session lock released.
    pub(crate) call_key: Option<Arc<crypto_core::CallKey>>,
    /// Monotonic, non-secret call-control state: pending capsule rings, bounded terminal
    /// tombstones, and the capsule outbox. Sealed to disk under the **device** key (never
    /// the vault), so it survives a process death and can be opened while the chat vault
    /// is locked. In memory even when this device has no key store — persistence is what
    /// needs the key, not the state.
    pub(crate) call_store: client_core::callstore::CallStore,
    /// The store has changes not yet sealed to disk.
    ///
    /// Interior-mutable because [`Session::persist`] takes `&self` and so could not clear
    /// it: the flag stayed set after the first call, and every later persist — one per
    /// message, per receipt, per state-mutating command — re-sealed and re-`fsync`ed the
    /// store for nothing (A-24). `AtomicBool` rather than `RefCell` so `Session` stays
    /// `Send` and a double borrow cannot panic at runtime in a struct this widely borrowed.
    pub(crate) call_store_dirty: std::sync::atomic::AtomicBool,
    /// An answer this device accepted from the platform but may not act on yet, because
    /// the vault is locked. Correlated to the exact call and presentation handle — never
    /// a "answer whatever rings next" flag — and bounded, so the system call cannot sit
    /// connecting forever.
    pub(crate) pending_unlock: Option<PendingUnlock>,
    /// Verified call-control key bindings, per account, warmed off-lock before a call so
    /// capsules can be sealed without a relay round trip inside the lock. Public,
    /// self-authenticating material — cached only to keep call setup fast, and bounded
    /// and time-limited so a rotated key is picked up (see `call::capsule`).
    pub(crate) call_bindings: std::collections::HashMap<String, CallBindings>,
    /// An outgoing call is being set up right now. Starting one releases the session
    /// mutex across roster/discovery/relay waits, and this reservation keeps the single
    /// call slot taken across those gaps: a second start, or an inbound offer, sees the
    /// account as busy instead of racing into the same slot. Held only by
    /// `call::route::CallSlot`, which clears it on every exit path.
    pub(crate) call_setup: bool,
    /// A connected 1:1 call whose media leg died without a terminal control (network
    /// drop), waiting for a v2 silent resume. Never persisted; cleared by resume,
    /// terminal, timeout, or lock.
    pub(crate) reconnect: Option<PendingReconnect>,
    /// The live group call, if any. Mutually exclusive with `call` (one call at a time,
    /// either kind).
    pub(crate) group_call: Option<GroupCallCtl>,
    /// An unanswered inbound group-call ring. Never persisted: pair tickets are key
    /// material and must not touch disk.
    pub(crate) group_incoming: Option<PendingGroupOffer>,
    /// A group answer claim awaiting the stable coordinator's exact winner decision.
    pub(crate) group_claiming: Option<PendingGroupClaim>,
    /// The relay advertises the multi-device surface (`/v1/capabilities`). Gates every
    /// multi-device code path — false ⇒ the exact single-device behavior.
    pub(crate) multi_device: bool,
    /// A device-linking ceremony in progress on THIS (new) device: the freshly created
    /// account + the link request it generated, held until the user completes linking.
    pub(crate) pending_link: Option<(Account, client_core::multidevice::LinkRequest)>,
    /// Attribution quarantine: inbound events from a device key we can't attribute yet
    /// while their claimed username IS a pinned contact (they linked a new device, or
    /// their key rotated). Held per claimed username until a KT roster re-resolve
    /// settles it (`runtime::resolve_attr_and_replay`); in-memory only — the frames
    /// were acked, so a crash before resolution loses them (same as the silent drop
    /// this replaces, but recoverable in every live path).
    pub(crate) pending_attr: std::collections::HashMap<String, Vec<client_core::InboundEvent>>,
    /// Usernames with a roster re-resolve already in flight (dedup for the spawn).
    pub(crate) attr_inflight: std::collections::HashSet<String>,
}

/// An answered-but-locked call, waiting for the vault (`internal/CALL_PLAN.md` §3.3).
///
/// Correlated on `call_instance_id` alone, and that is enough: it is 128 random bits minted
/// per call, so a stale unlock cannot answer a later one. (An `offer_id` was carried here
/// too and never read — every consumer matches on the call instance — so it was removed
/// rather than left looking load-bearing. A re-offer within the *same* call is still the
/// call the user chose to answer.)
///
/// An unlock that arrives after this call ended must do nothing at all, which is the
/// terminal check in `resume_pending_unlock` rather than an identifier.
pub(crate) struct PendingUnlock {
    pub(crate) call_instance_id: String,
    pub(crate) ring_handle: String,
    pub(crate) group: bool,
    /// This answer still owes a **human check** before it may be acted on.
    ///
    /// Set when the gate is the OS keyguard rather than the vault: the vault is already
    /// open (or can open itself silently), so nothing about opening it proves a person is
    /// there, and the resume's own readiness test would otherwise be satisfied the instant
    /// this state is armed — answering immediately and making the whole setting decoration.
    /// Cleared only by a presence check newer than the arming, or by Sona's own
    /// password/PIN where the OS has no factor to offer.
    pub(crate) needs_presence: bool,
    /// Sona's own credential is the fallback when the OS has neither a biometric nor a
    /// device credential enrolled: the UI is asked for it, and until it arrives this stays
    /// set so a webview that appears late still knows to ask.
    pub(crate) wants_credential: bool,
    /// Absolute deadline for the whole attempt: the shorter of the ring's own window and
    /// [`UNLOCK_TO_ANSWER_SECS`].
    pub(crate) expires_at: u64,
}

/// How long an unlock-to-answer attempt may take before the system call is disconnected.
/// Long enough for a fingerprint that misreads twice or a typed password, short enough
/// that Telecom is never left connecting.
pub(crate) const UNLOCK_TO_ANSWER_SECS: u64 = 45;

/// One account's published call-control bindings, as last verified against its pinned
/// KT roster.
pub(crate) struct CallBindings {
    /// When the warm that produced this ran; entries older than
    /// `call::capsule::BINDING_TTL_SECS` are re-fetched rather than reused.
    pub(crate) fetched_at: u64,
    /// `(device_id, binding)` for every device of that account that published one.
    pub(crate) devices: Vec<(String, client_core::CallKeyBinding)>,
}

/// Handle to a running call session (outgoing ring or connected either way).
pub(crate) struct CallCtl {
    pub(crate) call_instance_id: String,
    pub(crate) offer_id: String,
    /// The presentation handle this call's system call is keyed by (see [`PendingOffer`]).
    pub(crate) ring_handle: String,
    pub(crate) call_id: String,
    pub(crate) peer_username: String,
    /// Conversation/contact key used for attribution and account-wide fanout.
    pub(crate) peer_key: String,
    /// Exact device identity that won the answer race (or sent the inbound offer).
    pub(crate) peer_device_key: String,
    /// Exact peer device mailbox authenticated by the offer; non-empty on a callee.
    pub(crate) peer_reply_to_mailbox: String,
    pub(crate) caller: bool,
    /// Mic mute + camera/screen/screen-audio toggles, read live by the engine.
    pub(crate) toggles: client_core::media::MediaToggles,
    pub(crate) connected: Arc<std::sync::atomic::AtomicBool>,
    /// Unix time the media leg first connected (0 = never) — drives the call-history
    /// chip's duration and the answered/unanswered outcome split.
    pub(crate) connected_at: Arc<std::sync::atomic::AtomicU64>,
    /// Flipped when the peer's offer/answer caps advertise media v2.
    pub(crate) peer_media2: Arc<std::sync::atomic::AtomicBool>,
    /// Video negotiated end-to-end (peer caps + relay level) — gates the UI buttons.
    pub(crate) video_ready: Arc<std::sync::atomic::AtomicBool>,
    /// Peer track state, mirrored from engine events for `call_status` reloads.
    pub(crate) peer_camera: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) peer_screen: Arc<std::sync::atomic::AtomicBool>,
    /// Media transport this call rides ("quic" preferred, "ws" fallback).
    pub(crate) transport: &'static str,
    /// Caller-side first-answer arbiter; absent on the callee.
    pub(crate) answer_arbiter: Option<client_core::callstate::AnswerArbiter>,
    /// (Caller) how many callee devices were rung and have not yet reported busy.
    pub(crate) ring_fanout: usize,
    /// Deduplicate at-least-once busy controls before decrementing `ring_fanout`.
    pub(crate) busy_devices: std::collections::HashSet<String>,
    pub(crate) stop: tokio::sync::watch::Sender<bool>,
}

/// A dropped-but-resumable 1:1 call (see `Session::reconnect`).
pub(crate) struct PendingReconnect {
    pub(crate) call_instance_id: String,
    pub(crate) offer_id: String,
    /// The system call stays up across a silent resume; this is the handle it is keyed by.
    pub(crate) ring_handle: String,
    pub(crate) old_call_id: String,
    pub(crate) peer_username: String,
    pub(crate) peer_key: String,
    pub(crate) peer_device_key: String,
    pub(crate) peer_reply_to_mailbox: String,
    pub(crate) caller: bool,
    /// Whether the peer had advertised media v2 — carried into the resumed session.
    pub(crate) peer_media2: bool,
    /// When the dropped call originally connected — carried into the resumed session
    /// so the history chip's duration spans the whole call, not the last segment.
    pub(crate) connected_at: u64,
}

/// How long a dropped 1:1 leg waits for the peer's terminal control before treating the
/// loss as a network drop and starting the silent resume. A deliberate hangup closes
/// the media room first and the terminal lands within this window — so a normal
/// hangup still shows "call ended", never "reconnecting".
pub(crate) const RECONNECT_GRACE_MS: u64 = 2000;
/// How long a silent resume may take end-to-end before the call is declared dead.
pub(crate) const RECONNECT_WINDOW_SECS: u64 = 15;

/// An inbound call offer waiting for the user's accept/decline.
pub(crate) struct PendingOffer {
    pub(crate) call_instance_id: String,
    pub(crate) offer_id: String,
    /// This device's opaque, single-use handle for *presenting* the ring — the id the
    /// notification and the Telecom call are keyed by. Never the media `call_id`: a room
    /// id must not end up in the platform's call log (`internal/CALL_PLAN.md` §5.1).
    pub(crate) ring_handle: String,
    pub(crate) call_id: String,
    pub(crate) key_b64: String,
    pub(crate) username: String,
    pub(crate) peer_key: String,
    pub(crate) caller_device_id: String,
    pub(crate) caller_reply_to_mailbox: String,
    pub(crate) expires_at: u64,
    /// Caller's media caps from the offer (decides `peer_media2` on accept).
    pub(crate) caps: Vec<String>,
}

/// An outbound call between "the offers are posted" and "the media room is up" (E-6).
///
/// It exists for one reason: a claim that arrives in that window must not be lost. The
/// claim is **buffered raw** and replayed through the ordinary handler once `s.call` is
/// installed, so every check that handler makes — the peer's identity key, the answering
/// device against the verified roster, the reply mailbox derivation, the arbiter — is made
/// exactly once, against real call state, and none of it is duplicated here. Buffering is
/// deliberately not deciding: this type never picks a winner.
pub(crate) struct OutgoingSetup {
    pub(crate) call_instance_id: String,
    pub(crate) offer_id: String,
    /// Claims that landed before the room came up, in arrival order — the arbiter's own
    /// tie-break still decides, this only preserves what it has to decide between.
    pub(crate) claims: Vec<BufferedClaim>,
}

/// Bounded, so a peer that floods claims for a call it was offered cannot grow this
/// without limit while the room comes up. Far above any real fan-out: one claim per
/// callee device, and the roster itself caps that at `MAX_SCREEN_DEVICES`-scale numbers.
pub(crate) const MAX_BUFFERED_CLAIMS: usize = 16;

/// One `CallAnswerClaimedV2` held verbatim for replay. Nothing is trusted here — these are
/// the wire fields, checked by the handler when it replays them.
pub(crate) struct BufferedClaim {
    pub(crate) sender_identity_key: String,
    pub(crate) call_instance_id: String,
    pub(crate) offer_id: String,
    pub(crate) claim_nonce: String,
    pub(crate) answering_device_id: String,
    pub(crate) reply_to_mailbox: String,
    pub(crate) caps: Vec<String>,
    pub(crate) expires_at: u64,
}

/// An accepted offer waiting for the caller to name this device as winner.
pub(crate) struct PendingClaim {
    pub(crate) offer: PendingOffer,
    pub(crate) claim_nonce: String,
    pub(crate) answering_device_id: String,
}

/// Cap on group-call size. A mesh participant uploads one constant-rate voice leg
/// (~112 kb/s with padding) per other participant; 8 keeps the worst case under
/// ~0.8 Mb/s up — see client-core/src/groupcall.rs for why groups mesh instead of
/// using a server mixer.
pub(crate) const MAX_GROUP_CALL_MEMBERS: usize = 8;

/// How many times a dropped (not deliberately ended) pair leg is automatically
/// re-offered by its owner before giving up on that member for this call.
pub(crate) const MAX_LEG_REOFFERS: u32 = 3;
/// Grace before an owner re-offers a dropped leg: long enough for the peer's
/// a group terminal (deliberate leave) to arrive and cancel the re-offer, short enough
/// that a genuine drop reconnects almost seamlessly.
pub(crate) const LEG_REOFFER_DELAY_MS: u64 = 2000;

/// Handle to a running group-call session (ringing-outbound or connected).
pub(crate) struct GroupCallCtl {
    /// The call's identity across all participants (random 32 hex, from the starter).
    pub(crate) call_instance: String,
    pub(crate) ring_id: String,
    /// Presentation handle for this device's system call (see [`PendingOffer`]).
    pub(crate) ring_handle: String,
    pub(crate) group_id: String,
    pub(crate) group_name: String,
    pub(crate) coordinator: GroupCoordinator,
    pub(crate) deadline: GroupRingDeadline,
    /// Our own sending identity key — one side of every pair-ownership comparison.
    pub(crate) my_key: String,
    pub(crate) muted: Arc<std::sync::atomic::AtomicBool>,
    /// Per-listener playout gain for each member, keyed by identity key. Shared with the
    /// group engine, which reads it while mixing. See `call::volume`.
    pub(crate) gains: client_core::groupcall::PeerGains,
    /// Peer device keys whose pair leg was already handed to the engine (join once).
    pub(crate) legs_added: std::collections::HashSet<String>,
    /// Our minted per-pair tickets, keyed by member username: (call_id, key_b64). Used
    /// when WE are the pair's owner (our key sorts first); the peer joins our room.
    pub(crate) my_tickets: std::collections::HashMap<String, (String, String)>,
    /// Every room id this call ever joined. A pair room is joinable ONCE per call:
    /// re-deriving its keys would restart the seal counter at zero — nonce reuse under
    /// the same key — so a replayed offer (e.g. by a malicious relay after the leg
    /// died) must never re-open a room. A genuine rejoin arrives as a fresh ticket.
    pub(crate) used_call_ids: std::collections::HashSet<String>,
    /// Members (by username) who deliberately left/declined (v2 terminal). A dead
    /// leg to them is NOT re-offered; their own fresh offer clears the entry (rejoin).
    pub(crate) departed: std::collections::HashSet<String>,
    /// Automatic re-offer attempts per member since their last connect — a dropped leg
    /// is re-established at most [`MAX_LEG_REOFFERS`] times (a peer that crashed
    /// without a terminal must not be re-rung forever).
    pub(crate) reoffer_attempts: std::collections::HashMap<String, u32>,
    /// Coordinator-only, one first-answer arbiter per participant account key.
    pub(crate) answer_arbiters:
        std::collections::HashMap<String, client_core::callstate::AnswerArbiter>,
    /// Peers with flowing audio (device key -> username) — for `call_status` reloads.
    pub(crate) connected: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    /// Unix time the FIRST leg's audio connected (0 = never) — call-history duration.
    pub(crate) connected_at: Arc<std::sync::atomic::AtomicU64>,
    /// Feed of new pair legs into the running engine.
    pub(crate) leg_tx: tokio::sync::mpsc::UnboundedSender<client_core::groupcall::GroupLeg>,
    pub(crate) stop: tokio::sync::watch::Sender<bool>,
}

/// An inbound group-call ring waiting for accept/decline. Collects every pair ticket
/// that arrives while ringing, so an accept can join all present members at once.
pub(crate) struct PendingGroupOffer {
    pub(crate) call_instance: String,
    pub(crate) ring_id: String,
    /// Presentation handle for this device's group ring (see [`PendingOffer`]).
    pub(crate) ring_handle: String,
    pub(crate) group_id: String,
    pub(crate) group_name: String,
    pub(crate) rang_by_username: String,
    pub(crate) coordinator: GroupCoordinator,
    pub(crate) deadline: GroupRingDeadline,
    /// sender device key -> (username, call_id, key_b64).
    pub(crate) offers: std::collections::HashMap<String, (String, String, String)>,
}

pub(crate) struct PendingGroupClaim {
    pub(crate) offer: PendingGroupOffer,
    pub(crate) claim_nonce: String,
    pub(crate) answering_device_id: String,
}

#[derive(Clone)]
pub(crate) struct GroupCoordinator {
    pub(crate) username: String,
    pub(crate) identity_key: String,
    pub(crate) device_id: String,
    pub(crate) reply_to_mailbox: String,
}

#[derive(Clone, Copy)]
pub(crate) struct GroupRingDeadline {
    pub(crate) created_at: u64,
    pub(crate) ring_expires_at: u64,
    pub(crate) expires_at: u64,
}

impl Session {
    pub(crate) fn config_path(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }
    pub(crate) fn vault_path(&self) -> PathBuf {
        self.data_dir.join("vault.bin")
    }
    pub(crate) fn history_path(&self) -> PathBuf {
        self.data_dir.join("history.bin")
    }
    /// The call-control secret, sealed under the device key (never the vault key).
    pub(crate) fn call_key_path(&self) -> PathBuf {
        self.data_dir.join("call_key.bin")
    }
    /// Pending rings, terminal tombstones, and the capsule outbox, sealed under the same
    /// call-only store key.
    pub(crate) fn call_store_path(&self) -> PathBuf {
        self.data_dir.join("call_store.bin")
    }
    /// The approved-caller screening index, sealed under the same call-only store key.
    pub(crate) fn call_screen_path(&self) -> PathBuf {
        self.data_dir.join("call_screen.bin")
    }
    pub(crate) fn prefs_path(&self) -> PathBuf {
        self.data_dir.join("prefs.json")
    }
    /// Seal key wrapped under PIN + device key (see `crypto_core::quick`).
    pub(crate) fn quick_pin_path(&self) -> PathBuf {
        self.data_dir.join("quick_pin.bin")
    }
    /// Seal key wrapped under the device key alone (auto-unlock).
    pub(crate) fn quick_auto_path(&self) -> PathBuf {
        self.data_dir.join("quick_auto.bin")
    }
    /// Seal key wrapped by the biometric-gated Android Keystore key.
    pub(crate) fn quick_bio_path(&self) -> PathBuf {
        self.data_dir.join("quick_bio.bin")
    }

    pub(crate) fn save_prefs(&self) -> Result<(), String> {
        std::fs::write(
            self.prefs_path(),
            serde_json::to_vec_pretty(&self.prefs).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }

    /// Re-seal the vault (after ratchet advance) and the history, writing both to disk.
    /// No-op silently if we're somehow locked. Called after any state-mutating command.
    /// Cheap: the vault key was derived once at create/unlock (`Account::reseal` runs no
    /// KDF), so this is safe to do per message.
    /// The call-control store, marked for sealing. Every mutation goes through here so
    /// `persist` knows there is something to write — the store is the only call state
    /// that must outlive the process.
    pub(crate) fn calls(&mut self) -> &mut client_core::callstore::CallStore {
        self.mark_calls_dirty();
        &mut self.call_store
    }

    /// The store changed and owes a seal. Separate from [`calls`](Self::calls) for the paths
    /// that mutate `call_store` directly.
    pub(crate) fn mark_calls_dirty(&self) {
        self.call_store_dirty
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn persist(&self) -> Result<(), String> {
        let Some(account) = &self.account else {
            return Ok(());
        };
        let vault = account.reseal().map_err(|e| e.to_string())?;
        std::fs::write(self.vault_path(), vault).map_err(|e| e.to_string())?;
        let hist = self.history.seal(&account.data_key());
        std::fs::write(self.history_path(), hist).map_err(|e| e.to_string())?;
        // The call-control store rides along whenever it changed, so a tombstone written
        // by the encrypted signalling path survives a restart exactly like one written by
        // a capsule. Through the same helper `save_call_store` uses, so the two cannot drift
        // on which of them owns the dirty flag — and so this one clears it, which is what
        // stops every later persist re-sealing and re-`fsync`ing the store for nothing.
        crate::call::store::save_call_store(self);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Device key (unchanged): binds the vault to this device when a key store is present.
// ---------------------------------------------------------------------------------------

// READ-ONLY device-key fetch — never mints a key. Every unlock / re-seal / availability
// path uses this: a locked or not-yet-ready keyring returns None (→ a recoverable failed
// unlock) instead of regenerating the key and destroying the device-bound vault it protects.
#[cfg(not(target_os = "android"))]
pub(crate) fn device_key() -> Option<[u8; DEVICE_KEY_LEN]> {
    client_core::devicekey::OsKeyring::default()
        .get()
        .ok()
        .flatten()
}

#[cfg(target_os = "android")]
pub(crate) fn device_key() -> Option<[u8; DEVICE_KEY_LEN]> {
    client_core::devicekey::AndroidKeystore.get().ok().flatten()
}

// Mint-if-absent variant — ONLY for account creation / device linking, never on unlock.
#[cfg(not(target_os = "android"))]
pub(crate) fn device_key_or_create() -> Option<[u8; DEVICE_KEY_LEN]> {
    client_core::devicekey::OsKeyring::default()
        .get_or_create()
        .ok()
}

#[cfg(target_os = "android")]
pub(crate) fn device_key_or_create() -> Option<[u8; DEVICE_KEY_LEN]> {
    client_core::devicekey::AndroidKeystore.get_or_create().ok()
}

/// Ask the relay whether it supports multi-device (`/v1/capabilities`). Best-effort: an
/// old relay 404s and we stay single-device. Sets `s.multi_device`.
pub(crate) async fn detect_capabilities(client: &Client) -> bool {
    client
        .server_capabilities()
        .await
        .map(|caps| caps.iter().any(|c| c == multidevice::CAP_MULTI_DEVICE))
        .unwrap_or(false)
}
