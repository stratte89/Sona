//! Local, encrypted chat history — the client's own record of conversations, plus the
//! disappearing-messages machinery.
//!
//! History lives **only on the client** (the server never stores message content). It is
//! encrypted at rest with the account's `data_key` via [`crypto_core::localbox`].
//!
//! Disappearing messages: each conversation has an optional timer. When set, every
//! message recorded gets a `delete_at = sent_at + timer`, and [`History::reap`] removes
//! expired messages. Because both parties share the same timer (synced by a control
//! message) and the sender's timestamp travels inside the ciphertext, both sides compute
//! the **same** delete time and drop the message together.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use kt_log::{DeviceRecord, GroupEpoch, GroupEpochError, KtEntry, SignedTreeHead};
use serde::{Deserialize, Serialize};

use crate::{GroupMember, InboundEvent};

mod model;
pub use model::*;

/// The result of adopting a signed group-membership epoch (see
/// [`History::adopt_group_epoch`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEpochOutcome {
    /// A new admin-model group was created from this epoch (our own genesis, or a mid-life
    /// join). Members + admin pin were set.
    Created,
    /// An existing admin-model group's chain advanced. Members + admin pin were updated.
    Advanced,
    /// Refused: bad signature, malformed structure, rollback/replay, or a broken chain. No
    /// state changed. Carries the specific reason.
    Refused(GroupEpochError),
}

/// Stable-insert `m` into a thread kept ordered by `sent_at`. Messages normally arrive
/// in order (a plain append), but a **jittered multi-device self-sync copy** can land
/// out of order — device A recorded A-then-B, while device B's outbox delivered B's copy
/// before A's. Placing each message by its timestamp keeps every device's thread
/// identical instead of one of them drifting into arrival order. Ties (same wall-clock
/// second) keep arrival order, so a device's own same-second burst never reshuffles.
/// Walks back only over strictly-later messages, so an in-order append stays O(1).
fn insert_message_ordered(msgs: &mut Vec<StoredMessage>, m: StoredMessage) {
    let mut i = msgs.len();
    while i > 0 && msgs[i - 1].sent_at > m.sent_at {
        i -= 1;
    }
    msgs.insert(i, m);
}

/// Convert an epoch's member entries to the display [`GroupMember`] roster.
fn members_from_epoch(epoch: &GroupEpoch) -> Vec<GroupMember> {
    epoch
        .members
        .iter()
        .map(|m| GroupMember {
            username: m.username.clone(),
            identity_key: m.identity_key.clone(),
        })
        .collect()
}

/// All conversations, keyed by the peer's identity key (the same id ratchet sessions use).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct History {
    conversations: HashMap<String, Conversation>,
    /// username -> the key we've pinned for them. Drives key-change detection.
    #[serde(default)]
    contacts: HashMap<String, ContactPin>,
    /// group_id -> the group and its message thread.
    #[serde(default)]
    groups: HashMap<String, GroupRecord>,
    /// The last Key Transparency tree head we accepted — our gossip witness. Each new head
    /// must be a consistent, append-only continuation of this one.
    #[serde(default)]
    witness: Option<SignedTreeHead>,
    /// Our OWN former usernames (most recent last), kept after a rename so the client can
    /// keep draining their mailboxes (peers that missed the rename still send there).
    #[serde(default)]
    previous_usernames: Vec<String>,
    /// Unix timestamps of our own username changes (most recent last, pruned), enforcing
    /// the [`MAX_RENAMES_PER_WEEK`] product limit.
    #[serde(default)]
    own_rename_times: Vec<u64>,
    /// This device's identity within its multi-device account (`None` = legacy
    /// single-device, treated as primary).
    #[serde(default)]
    self_device: Option<SelfDevice>,
    /// The epoch of our OWN account's roster we last published/observed (self-audit
    /// rollback anchor). `None` = we have never published a roster (single-device).
    #[serde(default)]
    self_roster_seq: Option<u64>,
    /// Per-contact pinned device roster, keyed by username. Anti-rollback + fan-out.
    #[serde(default)]
    contact_rosters: HashMap<String, RosterPin>,
    /// device identity key -> owning account's primary identity key, learned from
    /// verified rosters. Drives inbound device→account attribution.
    #[serde(default)]
    device_owner: HashMap<String, String>,
    /// This account's own primary (KT-bound) identity key, so a self-sync from one of our
    /// own devices can be authenticated as ours. Set once we know our roster.
    #[serde(default)]
    self_primary_key: Option<String>,
    /// Set on the old primary while a primary-ownership transfer it offered is pending
    /// (see [`PendingDemotion`]). Cleared when the transfer is observed complete.
    #[serde(default)]
    pending_demotion: Option<PendingDemotion>,
    /// Set on a linked device that received (but has not completed) a primary-transfer
    /// offer (see [`PendingPromotion`]). Cleared when the transfer completes.
    #[serde(default)]
    pending_promotion: Option<PendingPromotion>,
    /// The relay told us this device was revoked from its account's roster. Terminal:
    /// the UI must lock messaging and offer relink/re-register. Persisted so a restart
    /// lands on the locked screen without needing to hit the network first.
    #[serde(default)]
    revoked: bool,
    /// Sealed envelopes not yet accepted by the relay — self-sync copies awaiting their
    /// jitter and failed forwards awaiting retry. Durable: an in-memory timer alone
    /// silently loses the linked-device copy when the app closes/is killed first, which
    /// is exactly how cross-device history drifts apart.
    #[serde(default)]
    outbox: Vec<OutboxItem>,
    /// What this device last published as its call-control key, so a later unlock can
    /// tell "already published" from "must publish", and so a fresh publication always
    /// carries a `created_at` the relay will accept as newer (its shelf is monotonic).
    /// Lives in the sealed history because publishing only ever happens while unlocked —
    /// the locked call subsystem needs the secret, not this bookkeeping.
    #[serde(default)]
    call_key_published: Option<CallKeyPublication>,
    /// Short-lived winner/terminal/control envelopes. Separate from general deferred
    /// history traffic so retry count, TTL cleanup, and capacity are strictly bounded.
    #[serde(default)]
    call_outbox: Vec<CallOutboxItem>,
    /// This account's own profile picture (a `data:image/…;base64,…` URI, [`valid_avatar`]),
    /// shown in our own settings and broadcast to contacts via [`ChatPayload::Profile`]. Lives
    /// only inside the sealed history. `None` = no picture.
    #[serde(default)]
    my_avatar: Option<String>,
    /// Message-request gate master switch, stored INVERTED so both `Default` and a
    /// pre-feature history deserialize to the protective default (requests ON).
    /// `true` = the user chose open messaging: anyone can message them directly and
    /// the requests surface disappears.
    #[serde(default)]
    open_messaging: bool,
    /// While a request is pending, `true` lets the requester's texts/attachments into
    /// the (hidden) conversation so they appear once accepted; `false` (default) =
    /// request only — content is withheld, only the request row exists.
    #[serde(default)]
    request_text_allowed: bool,
    /// Quarantined group content by group_id: events whose sender the roster does not
    /// (yet) vouch for. Never rendered; replayed by [`replay_held_group_content`]
    /// (Self::replay_held_group_content) when an adopted epoch proves the sender was
    /// added, expired otherwise (see [`HeldGroupEvent`]).
    #[serde(default)]
    held_group_content: HashMap<String, Vec<HeldGroupEvent>>,
}

/// Dead-session self-heal thresholds (see [`History::session_looks_dead`]). Tuned so a
/// merely-offline peer never trips them: three unacknowledged sends, the oldest at least
/// ten minutes old, and at most one automatic reset per contact per hour.
const DEAD_SESSION_MIN_UNACKED: usize = 3;
const DEAD_SESSION_MIN_AGE_SECS: u64 = 600;
const DEAD_SESSION_RETRY_SECS: u64 = 3600;

/// Outbox depth cap: beyond this the OLDEST entries drop first. Bounds vault growth if
/// the relay is unreachable for a long time; 512 sealed copies is days of traffic.
const MAX_OUTBOX: usize = 512;
/// A burst may contain one control per verified device. Keep enough room for several
/// simultaneous 1:1/group outcomes without letting an unreachable relay grow the vault.
const MAX_CALL_OUTBOX: usize = 128;
/// Initial post plus five retries at 1/2/4/8/16 seconds.
const MAX_CALL_OUTBOX_ATTEMPTS: u8 = 6;

/// How many of our former usernames' mailboxes we keep draining after renames.
const MAX_PREVIOUS_USERNAMES: usize = 5;

impl History {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current disappearing timer for a conversation (`None` = off / unknown peer).
    pub fn timer(&self, peer: &str) -> Option<u64> {
        self.conversations
            .get(peer)
            .and_then(|c| c.disappearing_secs)
    }

    /// Set (or clear) the disappearing timer for a conversation. The caller sends the
    /// matching control message to the peer so both sides agree (see
    /// [`crate::Client::set_disappearing`]).
    pub fn set_timer(&mut self, peer: &str, secs: Option<u64>) {
        self.conversations
            .entry(peer.to_string())
            .or_default()
            .disappearing_secs = secs;
    }

    /// Record a message. `delete_at` is derived from the conversation's current timer, so
    /// an outgoing message the sender records and the incoming copy the recipient records
    /// (same `sent_at`, same synced timer) get the same delete time. Idempotent by msg_id.
    pub fn record(
        &mut self,
        peer: &str,
        direction: Direction,
        msg_id: &str,
        body: &str,
        sent_at: u64,
    ) {
        self.record_full(peer, direction, msg_id, body, sent_at, None, None);
    }

    /// [`record`](Self::record) with an optional quoted-reply reference and an optional
    /// timer CARRIED inside the message (see [`carried_delete_at`]); the carried value
    /// beats the stored conversation timer.
    #[allow(clippy::too_many_arguments)]
    pub fn record_full(
        &mut self,
        peer: &str,
        direction: Direction,
        msg_id: &str,
        body: &str,
        sent_at: u64,
        reply: Option<crate::ReplyRef>,
        expire_secs: Option<u64>,
    ) {
        let convo = self.conversations.entry(peer.to_string()).or_default();
        if convo.messages.iter().any(|m| m.msg_id == msg_id) {
            return; // dedup re-delivery
        }
        let delete_at = carried_delete_at(convo.disappearing_secs, expire_secs, sent_at);
        insert_message_ordered(
            &mut convo.messages,
            StoredMessage {
                msg_id: msg_id.to_string(),
                direction,
                body: body.to_string(),
                sent_at,
                delete_at,
                attachment: None,
                sender: None,
                status: DeliveryStatus::default(),
                seen_receipted: false,
                edited: false,
                reply,
                reactions: Vec::new(),
                system: false,
                pinned: false,
                forwarded: false,
            },
        );
    }

    /// Record a local, centered system-event chip in a conversation (disappearing-timer
    /// changed, contact key changed/verified, group member added/removed). Never sent over
    /// the wire — purely a local timeline annotation. Deduped by identical `text` when it is
    /// the current last entry, so a repeated event (e.g. re-verify) doesn't stack.
    pub fn record_system(&mut self, peer: &str, text: &str, at: u64) {
        let convo = self.conversations.entry(peer.to_string()).or_default();
        if convo
            .messages
            .last()
            .is_some_and(|m| m.system && m.body == text)
        {
            return;
        }
        convo.messages.push(StoredMessage {
            msg_id: format!("sys-{at}-{}", convo.messages.len()),
            direction: Direction::Incoming,
            body: text.to_string(),
            sent_at: at,
            delete_at: None,
            attachment: None,
            sender: None,
            status: DeliveryStatus::default(),
            seen_receipted: true,
            edited: false,
            reply: None,
            reactions: Vec::new(),
            system: true,
            pinned: false,
            forwarded: false,
        });
    }

    /// Record a call-outcome chip ("Missed call", "Call · 4:12") in a 1:1 conversation.
    /// Same local-only shape as [`record_system`] but NEVER deduped — every call is its
    /// own event; two missed calls in a row must both leave a trace.
    pub fn record_call_event(&mut self, peer: &str, text: &str, at: u64) {
        let convo = self.conversations.entry(peer.to_string()).or_default();
        convo.messages.push(StoredMessage {
            msg_id: format!("call-{at}-{}", convo.messages.len()),
            direction: Direction::Incoming,
            body: text.to_string(),
            sent_at: at,
            delete_at: None,
            attachment: None,
            sender: None,
            status: DeliveryStatus::default(),
            seen_receipted: true,
            edited: false,
            reply: None,
            reactions: Vec::new(),
            system: true,
            pinned: false,
            forwarded: false,
        });
    }

    /// Group flavor of [`record_call_event`] — same no-dedupe rule.
    pub fn record_group_call_event(&mut self, group_id: &str, text: &str, at: u64) {
        let Some(g) = self.groups.get_mut(group_id) else {
            return;
        };
        g.messages.push(StoredMessage {
            msg_id: format!("call-{at}-{}", g.messages.len()),
            direction: Direction::Incoming,
            body: text.to_string(),
            sent_at: at,
            delete_at: None,
            attachment: None,
            sender: None,
            status: DeliveryStatus::default(),
            seen_receipted: true,
            edited: false,
            reply: None,
            reactions: Vec::new(),
            system: true,
            pinned: false,
            forwarded: false,
        });
    }

    /// Toggle a reaction on a message in a 1:1 conversation. `reactor` is the reactor's
    /// identity key, or the empty string for our own reaction. `add` inserts (idempotent),
    /// `!add` removes. Returns true if the message existed.
    pub fn react(
        &mut self,
        peer: &str,
        target_msg_id: &str,
        reactor: &str,
        emoji: &str,
        add: bool,
    ) -> bool {
        let Some(c) = self.conversations.get_mut(peer) else {
            return false;
        };
        let Some(m) = c.messages.iter_mut().find(|m| m.msg_id == target_msg_id) else {
            return false;
        };
        apply_reaction(&mut m.reactions, reactor, emoji, add);
        true
    }

    /// Toggle a reaction on a message in a group thread (see [`react`](Self::react)).
    pub fn react_group(
        &mut self,
        group_id: &str,
        target_msg_id: &str,
        reactor: &str,
        emoji: &str,
        add: bool,
    ) -> bool {
        let Some(g) = self.groups.get_mut(group_id) else {
            return false;
        };
        let Some(m) = g.messages.iter_mut().find(|m| m.msg_id == target_msg_id) else {
            return false;
        };
        apply_reaction(&mut m.reactions, reactor, emoji, add);
        true
    }

    /// Pin (or unpin) a 1:1 message. Shared conversation metadata — either side may pin
    /// (both already hold the plaintext). Returns true if the message existed.
    pub fn set_msg_pinned(&mut self, peer: &str, msg_id: &str, pin: bool) -> bool {
        if let Some(c) = self.conversations.get_mut(peer) {
            if let Some(m) = c.messages.iter_mut().find(|m| m.msg_id == msg_id) {
                m.pinned = pin;
                return true;
            }
        }
        false
    }

    /// Pin (or unpin) a group message (any member may — roster trust model).
    pub fn set_group_msg_pinned(&mut self, group_id: &str, msg_id: &str, pin: bool) -> bool {
        if let Some(g) = self.groups.get_mut(group_id) {
            if let Some(m) = g.messages.iter_mut().find(|m| m.msg_id == msg_id) {
                m.pinned = pin;
                return true;
            }
        }
        false
    }

    /// Mark a 1:1 message as forwarded-from-elsewhere (drives the "Forwarded" tag).
    pub fn set_forwarded(&mut self, peer: &str, msg_id: &str) {
        if let Some(c) = self.conversations.get_mut(peer) {
            if let Some(m) = c.messages.iter_mut().find(|m| m.msg_id == msg_id) {
                m.forwarded = true;
            }
        }
    }

    /// Mark a group message as forwarded-from-elsewhere.
    pub fn set_group_forwarded(&mut self, group_id: &str, msg_id: &str) {
        if let Some(g) = self.groups.get_mut(group_id) {
            if let Some(m) = g.messages.iter_mut().find(|m| m.msg_id == msg_id) {
                m.forwarded = true;
            }
        }
    }

    /// One message by id (for previews / edit-window checks).
    pub fn message(&self, peer: &str, msg_id: &str) -> Option<&StoredMessage> {
        self.messages(peer).iter().find(|m| m.msg_id == msg_id)
    }

    /// Locally edit an *outgoing* message (pair with [`crate::Client::send_edit`]).
    pub fn edit_local(&mut self, peer: &str, msg_id: &str, body: &str) -> bool {
        if let Some(c) = self.conversations.get_mut(peer) {
            if let Some(m) = c
                .messages
                .iter_mut()
                .find(|m| m.msg_id == msg_id && m.direction == Direction::Outgoing)
            {
                m.body = body.to_string();
                m.edited = true;
                return true;
            }
        }
        false
    }

    /// Apply an inbound edit: only messages the *sender* sent (Incoming on our side).
    pub fn apply_incoming_edit(&mut self, peer: &str, msg_id: &str, body: &str) {
        if let Some(c) = self.conversations.get_mut(peer) {
            if let Some(m) = c
                .messages
                .iter_mut()
                .find(|m| m.msg_id == msg_id && m.direction == Direction::Incoming)
            {
                m.body = body.to_string();
                m.edited = true;
            }
        }
    }

    /// Delete one message locally (either direction — "delete for me").
    pub fn delete_message(&mut self, peer: &str, msg_id: &str) {
        if let Some(c) = self.conversations.get_mut(peer) {
            c.messages.retain(|m| m.msg_id != msg_id);
        }
    }

    /// Apply an inbound "delete for everyone": only the sender's own messages
    /// (Incoming on our side) can be deleted by them.
    pub fn apply_incoming_delete(&mut self, peer: &str, msg_id: &str) {
        if let Some(c) = self.conversations.get_mut(peer) {
            c.messages
                .retain(|m| !(m.msg_id == msg_id && m.direction == Direction::Incoming));
        }
    }

    /// Current disappearing timer for a group (`None` = off / unknown group).
    pub fn group_timer(&self, group_id: &str) -> Option<u64> {
        self.groups.get(group_id).and_then(|g| g.disappearing_secs)
    }

    /// Set (or clear) the disappearing timer for a group. Returns false for an unknown
    /// group. The caller fans the matching `GroupTimer` control message out to the
    /// members so everyone agrees.
    pub fn set_group_timer(&mut self, group_id: &str, secs: Option<u64>) -> bool {
        match self.groups.get_mut(group_id) {
            Some(g) => {
                g.disappearing_secs = secs;
                true
            }
            None => false,
        }
    }

    /// Our own profile picture (`data:` image URI), if set.
    pub fn my_avatar(&self) -> Option<&str> {
        self.my_avatar.as_deref()
    }

    /// Set (or clear with an invalid/`None` value) our own profile picture. Passes through
    /// [`sanitize_avatar`], so a malformed value silently clears it rather than storing junk.
    /// The caller broadcasts [`ChatPayload::Profile`] to contacts so they see the change.
    pub fn set_my_avatar(&mut self, avatar: Option<String>) {
        self.my_avatar = sanitize_avatar(avatar);
    }

    /// Fingerprint of our current avatar for profile-send reconciliation bookkeeping:
    /// a short hash of the stored value, `""` when no picture is set. Stored per contact
    /// in [`ContactPin::profile_sent`] after a successful send, so a changed (or newly
    /// set) picture reads as "not sent yet" everywhere.
    pub fn my_avatar_fingerprint(&self) -> String {
        match &self.my_avatar {
            Some(a) => {
                use sha2::{Digest, Sha256};
                let d = Sha256::digest(a.as_bytes());
                d.iter().take(12).map(|b| format!("{b:02x}")).collect()
            }
            None => String::new(),
        }
    }

    /// Whether this contact still needs a [`ChatPayload::Profile`](crate::wire) send to
    /// see our current picture. False for blocked contacts and **pending requests** (a
    /// stranger must not learn our picture before we accept them), and false when there
    /// is no picture and none was ever announced (nothing to clear).
    pub fn profile_send_needed(&self, username: &str) -> bool {
        let Some(p) = self.contacts.get(username) else {
            return false;
        };
        if p.blocked || p.request.is_some() {
            return false;
        }
        let fp = self.my_avatar_fingerprint();
        if fp.is_empty() && p.profile_sent.is_none() {
            return false;
        }
        p.profile_sent.as_deref() != Some(fp.as_str())
    }

    /// Record that this contact was successfully sent our current picture.
    pub fn mark_profile_sent(&mut self, username: &str) {
        let fp = self.my_avatar_fingerprint();
        if let Some(p) = self.contacts.get_mut(username) {
            p.profile_sent = Some(fp);
        }
    }

    /// A peer's profile picture, resolved by conversation (primary) identity key.
    pub fn avatar_for_peer(&self, peer: &str) -> Option<String> {
        self.contacts
            .values()
            .find(|p| p.identity_key == peer)
            .and_then(|p| p.avatar.clone())
    }

    /// Store a peer's broadcast profile picture against the contact with this identity key.
    /// Sanitized on the way in; a no-op for an unknown key (we only track pictures for
    /// contacts we've pinned). Returns whether a contact matched.
    pub fn set_contact_avatar(&mut self, identity_key: &str, avatar: Option<String>) -> bool {
        let clean = sanitize_avatar(avatar);
        if let Some(p) = self
            .contacts
            .values_mut()
            .find(|p| p.identity_key == identity_key)
        {
            p.avatar = clean;
            true
        } else {
            false
        }
    }

    /// A group's picture, if set.
    pub fn group_avatar(&self, group_id: &str) -> Option<String> {
        self.groups.get(group_id).and_then(|g| g.avatar.clone())
    }

    /// Set (or clear) a group's picture. Sanitized; a no-op for an unknown group.
    pub fn set_group_avatar(&mut self, group_id: &str, avatar: Option<String>) -> bool {
        let clean = sanitize_avatar(avatar);
        match self.groups.get_mut(group_id) {
            Some(g) => {
                g.avatar = clean;
                true
            }
            None => false,
        }
    }

    /// Mute (or unmute with `None`) a group.
    pub fn set_group_muted(&mut self, group_id: &str, until: Option<u64>) -> bool {
        match self.groups.get_mut(group_id) {
            Some(g) => {
                g.muted_until = until;
                true
            }
            None => false,
        }
    }

    /// Record an attachment in the timeline (same disappearing-timer treatment as a
    /// message; `expire_secs` as in [`record_full`](Self::record_full)).
    pub fn record_attachment(
        &mut self,
        peer: &str,
        direction: Direction,
        msg_id: &str,
        attachment: crate::AttachmentRef,
        sent_at: u64,
        expire_secs: Option<u64>,
    ) {
        let convo = self.conversations.entry(peer.to_string()).or_default();
        if convo.messages.iter().any(|m| m.msg_id == msg_id) {
            return;
        }
        let delete_at = carried_delete_at(convo.disappearing_secs, expire_secs, sent_at);
        insert_message_ordered(
            &mut convo.messages,
            StoredMessage {
                msg_id: msg_id.to_string(),
                direction,
                body: attachment.filename.clone(),
                sent_at,
                delete_at,
                attachment: Some(attachment),
                sender: None,
                status: DeliveryStatus::default(),
                seen_receipted: false,
                edited: false,
                reply: None,
                reactions: Vec::new(),
                system: false,
                pinned: false,
                forwarded: false,
            },
        );
    }

    /// The pinned admin/epoch state for a group (`None` = an unknown group).
    pub fn group_admin(&self, group_id: &str) -> Option<&GroupAdmin> {
        self.groups.get(group_id).and_then(|g| g.admin.as_ref())
    }

    /// Whether `my_identity_key` (our account primary/identity key) is the current admin of
    /// this group. Always false for a legacy group (no admin) or an unknown group.
    pub fn is_group_admin(&self, my_identity_key: &str, group_id: &str) -> bool {
        self.group_admin(group_id)
            .is_some_and(|a| a.admin_identity_key == my_identity_key)
    }

    /// Set the group's display name (used when a validated epoch first creates a group —
    /// the epoch itself never carries the name, which stays an egalitarian field).
    pub fn set_group_name(&mut self, group_id: &str, name: &str) {
        if let Some(g) = self.groups.get_mut(group_id) {
            if !name.trim().is_empty() {
                g.name = name.to_string();
            }
        }
    }

    /// Validate and adopt a signed group-membership [`GroupEpoch`]. Every group is
    /// admin-model, so this is the ONLY path by which a group is created OR its membership
    /// changes. The rules mirror [`pin_roster`](Self::pin_roster)'s anti-rollback:
    ///
    /// * **New group** (we don't have it yet): accept the epoch as our baseline — the
    ///   genesis we just minted, or the current epoch of a group we're being invited into
    ///   (trust-on-first-epoch; the epoch rides an end-to-end-authenticated invite). Records
    ///   the genesis admin immutably when `seq == 0`.
    /// * **Existing group**: the epoch must be a valid successor — strictly `pinned_seq + 1`,
    ///   chaining from (and signed by) the pinned admin key. A lower/equal seq (a relay
    ///   replaying an old epoch to resurrect a kicked member) is refused.
    ///
    /// Returns the outcome; on [`GroupEpochOutcome::Created`]/`Advanced` the group's members
    /// (and admin pin) are updated to the epoch's. Never touches name/avatar/timer — those
    /// stay egalitarian and are handled by the caller/their own events.
    pub fn adopt_group_epoch(&mut self, epoch: &GroupEpoch) -> GroupEpochOutcome {
        let members: Vec<GroupMember> = epoch
            .members
            .iter()
            .map(|m| GroupMember {
                username: m.username.clone(),
                identity_key: m.identity_key.clone(),
            })
            .collect();
        match self
            .groups
            .get(&epoch.group_id)
            .and_then(|g| g.admin.clone())
        {
            // Existing group: the epoch must be a valid successor of our pin.
            Some(pin) => {
                if let Err(e) = epoch.verify_succession(pin.epoch_seq, &pin.admin_key) {
                    return GroupEpochOutcome::Refused(e);
                }
                let creator = pin.creator_admin_key.clone();
                let g = self.groups.get_mut(&epoch.group_id).expect("group present");
                g.members = members;
                g.admin = Some(GroupAdmin {
                    epoch_seq: epoch.seq,
                    admin_key: epoch.admin_key.clone(),
                    admin_identity_key: epoch.admin_identity_key.clone(),
                    creator_admin_key: creator,
                });
                // The roster just changed: any quarantined content whose sender it now
                // vouches for (the add-race) replays losslessly.
                self.replay_held_group_content(&epoch.group_id, unix_now());
                GroupEpochOutcome::Advanced
            }
            // Brand-new group: adopt this epoch as the baseline.
            None => {
                if let Err(e) = epoch.validate_baseline() {
                    return GroupEpochOutcome::Refused(e);
                }
                let creator_admin_key = (epoch.seq == 0).then(|| epoch.admin_key.clone());
                let g = self.groups.entry(epoch.group_id.clone()).or_default();
                g.members = members;
                g.admin = Some(GroupAdmin {
                    epoch_seq: epoch.seq,
                    admin_key: epoch.admin_key.clone(),
                    admin_identity_key: epoch.admin_identity_key.clone(),
                    creator_admin_key,
                });
                // First messages may have beaten the creating epoch here (or sat out a
                // pending message request) — replay them now that the roster exists.
                self.replay_held_group_content(&epoch.group_id, unix_now());
                GroupEpochOutcome::Created
            }
        }
    }

    /// Append a message to a group thread. `sender` is the sender's identity key. Idempotent
    /// by msg_id. Silently ignored for an unknown group (we weren't invited).
    /// `expire_secs` is the timer carried inside the message ([`record_full`](Self::record_full));
    /// `reply` is set when the message quotes another in the same thread.
    #[allow(clippy::too_many_arguments)]
    pub fn record_group_message(
        &mut self,
        group_id: &str,
        sender: &str,
        msg_id: &str,
        body: &str,
        sent_at: u64,
        expire_secs: Option<u64>,
        reply: Option<crate::ReplyRef>,
    ) {
        let Some(g) = self.groups.get_mut(group_id) else {
            return;
        };
        if g.messages.iter().any(|m| m.msg_id == msg_id) {
            return;
        }
        let delete_at = carried_delete_at(g.disappearing_secs, expire_secs, sent_at);
        insert_message_ordered(
            &mut g.messages,
            StoredMessage {
                msg_id: msg_id.to_string(),
                direction: Direction::Incoming,
                body: body.to_string(),
                sent_at,
                delete_at,
                attachment: None,
                sender: Some(sender.to_string()),
                status: DeliveryStatus::default(),
                seen_receipted: false,
                edited: false,
                reply,
                reactions: Vec::new(),
                system: false,
                pinned: false,
                forwarded: false,
            },
        );
    }

    /// One group message by id (for reply previews / edit-window checks).
    pub fn group_message(&self, group_id: &str, msg_id: &str) -> Option<&StoredMessage> {
        self.groups
            .get(group_id)?
            .messages
            .iter()
            .find(|m| m.msg_id == msg_id)
    }

    /// Locally edit one of OUR OWN group messages (pair with the `GroupEdit` fan-out).
    /// The caller verifies ownership; this only touches the stored copy.
    pub fn edit_group_local(&mut self, group_id: &str, msg_id: &str, body: &str) -> bool {
        if let Some(g) = self.groups.get_mut(group_id) {
            if let Some(m) = g.messages.iter_mut().find(|m| m.msg_id == msg_id) {
                m.body = body.to_string();
                m.edited = true;
                return true;
            }
        }
        false
    }

    /// Apply an inbound group edit: only messages stored under `sender` (the attributed
    /// account key) may be edited by them — a member can never rewrite someone else's.
    pub fn apply_incoming_group_edit(
        &mut self,
        group_id: &str,
        msg_id: &str,
        body: &str,
        sender: &str,
    ) {
        if let Some(g) = self.groups.get_mut(group_id) {
            if let Some(m) = g
                .messages
                .iter_mut()
                .find(|m| m.msg_id == msg_id && m.sender.as_deref() == Some(sender))
            {
                m.body = body.to_string();
                m.edited = true;
            }
        }
    }

    /// Delete one group message locally (any sender — "delete for me").
    pub fn delete_group_message(&mut self, group_id: &str, msg_id: &str) {
        if let Some(g) = self.groups.get_mut(group_id) {
            g.messages.retain(|m| m.msg_id != msg_id);
        }
    }

    /// Apply an inbound group "delete for everyone": only messages stored under `sender`
    /// may be deleted by them.
    pub fn apply_incoming_group_delete(&mut self, group_id: &str, msg_id: &str, sender: &str) {
        if let Some(g) = self.groups.get_mut(group_id) {
            g.messages
                .retain(|m| !(m.msg_id == msg_id && m.sender.as_deref() == Some(sender)));
        }
    }

    /// Rename a group. Returns false for an unknown group.
    pub fn rename_group(&mut self, group_id: &str, name: &str) -> bool {
        match self.groups.get_mut(group_id) {
            Some(g) if !name.trim().is_empty() => {
                g.name = name.trim().to_string();
                true
            }
            _ => false,
        }
    }

    /// Remove a member (by roster identity key) from a group's roster. Returns the
    /// removed record so the caller can name them in a system chip.
    pub fn remove_group_member(&mut self, group_id: &str, member_key: &str) -> Option<GroupMember> {
        let g = self.groups.get_mut(group_id)?;
        let i = g
            .members
            .iter()
            .position(|m| m.identity_key == member_key)?;
        Some(g.members.remove(i))
    }

    /// Mark a group left (we left or were removed): history stays, sends are blocked.
    pub fn set_group_left(&mut self, group_id: &str, left: bool) -> bool {
        match self.groups.get_mut(group_id) {
            Some(g) => {
                g.left = left;
                true
            }
            None => false,
        }
    }

    /// Pin/unpin a group in the chat list (local-only).
    pub fn set_group_pinned(&mut self, group_id: &str, pinned: bool) -> bool {
        match self.groups.get_mut(group_id) {
            Some(g) => {
                g.pinned = pinned;
                true
            }
            None => false,
        }
    }

    /// Archive/unarchive a group (local-only). Archiving clears any manual-unread mark.
    pub fn set_group_archived(&mut self, group_id: &str, archived: bool) -> bool {
        match self.groups.get_mut(group_id) {
            Some(g) => {
                g.archived = archived;
                if archived {
                    g.unread = false;
                }
                true
            }
            None => false,
        }
    }

    /// Manually mark a group unread (or clear it). Marking unread un-archives.
    pub fn set_group_manual_unread(&mut self, group_id: &str, unread: bool) -> bool {
        match self.groups.get_mut(group_id) {
            Some(g) => {
                g.unread = unread;
                if unread {
                    g.archived = false;
                }
                true
            }
            None => false,
        }
    }

    /// Append an attachment to a group thread — [`record_group_message`]'s shape with
    /// the [`AttachmentRef`](crate::AttachmentRef) attached (body = filename, same
    /// timer treatment, idempotent by msg_id, unknown group ignored).
    pub fn record_group_attachment(
        &mut self,
        group_id: &str,
        sender: &str,
        msg_id: &str,
        attachment: crate::AttachmentRef,
        sent_at: u64,
        expire_secs: Option<u64>,
    ) {
        let Some(g) = self.groups.get_mut(group_id) else {
            return;
        };
        if g.messages.iter().any(|m| m.msg_id == msg_id) {
            return;
        }
        let delete_at = carried_delete_at(g.disappearing_secs, expire_secs, sent_at);
        insert_message_ordered(
            &mut g.messages,
            StoredMessage {
                msg_id: msg_id.to_string(),
                direction: Direction::Incoming,
                body: attachment.filename.clone(),
                sent_at,
                delete_at,
                attachment: Some(attachment),
                sender: Some(sender.to_string()),
                status: DeliveryStatus::default(),
                seen_receipted: false,
                edited: false,
                reply: None,
                reactions: Vec::new(),
                system: false,
                pinned: false,
                forwarded: false,
            },
        );
    }

    /// Record a local, centered system-event chip in a group thread (member added/removed).
    /// Never transmitted. Deduped against an identical current-last entry.
    pub fn record_group_system(&mut self, group_id: &str, text: &str, at: u64) {
        let Some(g) = self.groups.get_mut(group_id) else {
            return;
        };
        if g.messages
            .last()
            .is_some_and(|m| m.system && m.body == text)
        {
            return;
        }
        g.messages.push(StoredMessage {
            msg_id: format!("sys-{at}-{}", g.messages.len()),
            direction: Direction::Incoming,
            body: text.to_string(),
            sent_at: at,
            delete_at: None,
            attachment: None,
            sender: None,
            status: DeliveryStatus::default(),
            seen_receipted: true,
            edited: false,
            reply: None,
            reactions: Vec::new(),
            system: true,
            pinned: false,
            forwarded: false,
        });
    }

    /// The groups we belong to (group_id -> record).
    pub fn group(&self, group_id: &str) -> Option<&GroupRecord> {
        self.groups.get(group_id)
    }

    /// Display label for an attributed account key acting on a group: `"You"` for our
    /// own account, the roster username for a member, `None` for a non-member (whose
    /// roster/name changes must be refused).
    fn group_member_label(&self, group_id: &str, account_key: &str) -> Option<String> {
        if self.self_primary_key() == Some(account_key) || self.is_own_device(account_key) {
            return Some("You".to_string());
        }
        self.groups
            .get(group_id)?
            .members
            .iter()
            .find(|m| m.identity_key == account_key)
            .map(|m| m.username.clone())
    }

    /// Quarantine one group-content event from a sender the roster does not (yet) vouch
    /// for — never rendered, replayed only if an adopted epoch proves the sender was
    /// added (see [`HeldGroupEvent`]). Bounded per group and across groups.
    fn hold_group_content(
        &mut self,
        group_id: &str,
        sender: &str,
        content: HeldGroupContent,
        now: u64,
    ) {
        self.prune_held_group_content(now);
        let held = self
            .held_group_content
            .entry(group_id.to_string())
            .or_default();
        if held.len() >= MAX_HELD_GROUP_EVENTS {
            held.remove(0);
        }
        held.push(HeldGroupEvent {
            sender: sender.to_string(),
            received_at: now,
            content,
        });
        if self.held_group_content.len() > MAX_HELD_GROUP_CONTENT_GROUPS {
            if let Some(stalest) = self
                .held_group_content
                .iter()
                .min_by_key(|(_, v)| v.last().map(|h| h.received_at).unwrap_or(0))
                .map(|(k, _)| k.clone())
            {
                self.held_group_content.remove(&stalest);
            }
        }
    }

    /// Drop quarantined events past their TTL: short for a group we know (the add-race it
    /// insures against resolves in seconds), long for an unknown group (its creating epoch
    /// may sit behind a pending message request until the user accepts).
    fn prune_held_group_content(&mut self, now: u64) {
        let groups = &self.groups;
        self.held_group_content.retain(|gid, held| {
            let ttl = if groups.contains_key(gid) {
                HELD_GROUP_CONTENT_TTL_SECS
            } else {
                HELD_GROUP_CONTENT_UNKNOWN_TTL_SECS
            };
            held.retain(|h| now.saturating_sub(h.received_at) <= ttl);
            !held.is_empty()
        });
    }

    /// Replay quarantined content whose sender the (just-updated) roster now vouches for,
    /// in arrival order — called after every successful epoch adoption, so the add-race
    /// (newcomer's first message beats the admin's epoch) is lossless. Unexpired events
    /// from senders the epoch did NOT add stay quarantined.
    fn replay_held_group_content(&mut self, group_id: &str, now: u64) {
        self.prune_held_group_content(now);
        let Some(held) = self.held_group_content.remove(group_id) else {
            return;
        };
        let mut keep = Vec::new();
        for h in held {
            if self.group_member_label(group_id, &h.sender).is_none() {
                keep.push(h);
                continue;
            }
            let HeldGroupEvent {
                sender, content, ..
            } = h;
            match content {
                HeldGroupContent::Message {
                    msg_id,
                    body,
                    sent_at,
                    expire_secs,
                    reply,
                    forwarded,
                } => {
                    self.record_group_message(
                        group_id,
                        &sender,
                        &msg_id,
                        &body,
                        sent_at,
                        expire_secs,
                        reply,
                    );
                    if forwarded {
                        self.set_group_forwarded(group_id, &msg_id);
                    }
                }
                HeldGroupContent::Attachment {
                    msg_id,
                    attachment,
                    sent_at,
                    expire_secs,
                    forwarded,
                } => {
                    self.record_group_attachment(
                        group_id,
                        &sender,
                        &msg_id,
                        attachment,
                        sent_at,
                        expire_secs,
                    );
                    if forwarded {
                        self.set_group_forwarded(group_id, &msg_id);
                    }
                }
                HeldGroupContent::Reaction {
                    target_msg_id,
                    emoji,
                    add,
                } => {
                    self.react_group(group_id, &target_msg_id, &sender, &emoji, add);
                }
                HeldGroupContent::Edit { msg_id, body } => {
                    self.apply_incoming_group_edit(group_id, &msg_id, &body, &sender);
                }
                HeldGroupContent::Delete { msg_id } => {
                    self.apply_incoming_group_delete(group_id, &msg_id, &sender);
                }
            }
        }
        if !keep.is_empty() {
            self.held_group_content.insert(group_id.to_string(), keep);
        }
    }

    /// Apply a decrypted inbound event: append a message/attachment, or adopt a timer
    /// change. Peer events are **attributed device→account**: a message from any of a
    /// contact's linked devices is filed under the contact's stable primary key (a verified
    /// roster teaches the mapping), so all of a contact's devices appear as one chat.
    pub fn apply(&mut self, event: &InboundEvent) {
        match event {
            InboundEvent::Message {
                sender_identity_key,
                sender_username,
                msg_id,
                body,
                sent_at,
                reply,
                expire_secs,
                forwarded,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                // The message-request gate first: a stranger's text either rides along
                // with their request (Held), or only the request row appears (Dropped).
                if self.screen_inbound(&convo, sender_username, unix_now())
                    == InboundScreen::Dropped
                {
                    return;
                }
                // Auto-add the sender to the address book so the conversation is visible and
                // replyable. Keep any existing verified flag — receiving a message must never
                // downgrade a contact we already confirmed out-of-band. The claimed username
                // is unverified until a KT re-check happens on the first reply.
                if !sender_username.is_empty() {
                    self.auto_pin_contact(sender_username, &convo);
                }
                self.record_full(
                    &convo,
                    Direction::Incoming,
                    msg_id,
                    body,
                    *sent_at,
                    reply.clone(),
                    *expire_secs,
                );
                if *forwarded {
                    self.set_forwarded(&convo, msg_id);
                }
            }
            InboundEvent::MessageEdited {
                sender_identity_key,
                msg_id,
                body,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                self.apply_incoming_edit(&convo, msg_id, body)
            }
            InboundEvent::MessageDeleted {
                sender_identity_key,
                msg_id,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                self.apply_incoming_delete(&convo, msg_id)
            }
            InboundEvent::TimerUpdate {
                sender_identity_key,
                disappearing_secs,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                // A stranger / pending requester must not set our disappearing timer.
                if !self.control_gated(&convo) {
                    self.set_timer(&convo, *disappearing_secs)
                }
            }
            InboundEvent::Attachment {
                sender_identity_key,
                sender_username,
                msg_id,
                attachment,
                sent_at,
                expire_secs,
                forwarded,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                // Same request gate as a text message — an attachment reference from a
                // stranger is content like any other.
                if self.screen_inbound(&convo, sender_username, unix_now())
                    == InboundScreen::Dropped
                {
                    return;
                }
                // Same auto-add as a text message: an attachment from a new sender must
                // surface in the chat list too.
                if !sender_username.is_empty() {
                    self.auto_pin_contact(sender_username, &convo);
                }
                self.record_attachment(
                    &convo,
                    Direction::Incoming,
                    msg_id,
                    attachment.clone(),
                    *sent_at,
                    *expire_secs,
                );
                if *forwarded {
                    self.set_forwarded(&convo, msg_id);
                }
            }
            InboundEvent::Receipt {
                sender_identity_key,
                ids,
                seen,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                self.mark_receipt(&convo, ids, *seen)
            }
            InboundEvent::ChatDeleted {
                sender_identity_key,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                self.delete_conversation(&convo)
            }
            // An explicit chat request: surface the pending-request row (no content).
            InboundEvent::Knock {
                sender_identity_key,
                sender_username,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                self.screen_knock(&convo, sender_username, unix_now());
            }
            // Multi-device self-sync: a copy of something WE sent from another of our
            // devices. Honored only when the sending device is a verified member of our own
            // roster (else it is an impersonation attempt and dropped).
            InboundEvent::SelfSentText {
                sender_identity_key,
                peer_key,
                peer_username,
                msg_id,
                body,
                sent_at,
                reply,
                expire_secs,
                forwarded,
            } => {
                if self.is_own_device(sender_identity_key) {
                    // WE replied to this peer from another device — that is consent:
                    // any pending request they had clears everywhere.
                    self.accept_request_for_key(peer_key);
                    if !peer_username.is_empty() {
                        self.auto_pin_contact(peer_username, peer_key);
                    }
                    self.record_full(
                        peer_key,
                        Direction::Outgoing,
                        msg_id,
                        body,
                        *sent_at,
                        reply.clone(),
                        *expire_secs,
                    );
                    if *forwarded {
                        self.set_forwarded(peer_key, msg_id);
                    }
                }
            }
            InboundEvent::SelfSentFile {
                sender_identity_key,
                peer_key,
                peer_username,
                msg_id,
                attachment,
                expire_secs,
                forwarded,
            } => {
                if self.is_own_device(sender_identity_key) {
                    // Same consent rule as SelfSentText.
                    self.accept_request_for_key(peer_key);
                    if !peer_username.is_empty() {
                        self.auto_pin_contact(peer_username, peer_key);
                    }
                    let ts = attachment.ts;
                    self.record_attachment(
                        peer_key,
                        Direction::Outgoing,
                        msg_id,
                        attachment.clone(),
                        ts,
                        *expire_secs,
                    );
                    if *forwarded {
                        self.set_forwarded(peer_key, msg_id);
                    }
                }
            }
            InboundEvent::SelfReadSeen {
                sender_identity_key,
                peer_key,
                ids,
            } => {
                if self.is_own_device(sender_identity_key) {
                    self.mark_seen_receipted(peer_key, ids);
                }
            }
            // Our primary forwarded a legacy sender's message to us; record it as incoming
            // from the ORIGINAL sender (attributed to their account). Honored only from our
            // own primary device; idempotent by msg_id so a direct fan-out copy dedups.
            InboundEvent::ForwardedIncoming {
                sender_identity_key,
                from_key,
                from_username,
                msg_id,
                body,
                sent_at,
                reply,
                attachment,
                expire_secs,
            } => {
                if self.is_own_device(sender_identity_key) {
                    let convo = self.attribute_device(from_key);
                    // The ORIGINAL sender is what the gate screens here — our primary
                    // forwarding a stranger's message must not smuggle it past the
                    // request gate on this device.
                    if self.screen_inbound(&convo, from_username, unix_now())
                        == InboundScreen::Dropped
                    {
                        return;
                    }
                    if !from_username.is_empty() {
                        self.auto_pin_contact(from_username, &convo);
                    }
                    match attachment {
                        Some(att) => self.record_attachment(
                            &convo,
                            Direction::Incoming,
                            msg_id,
                            att.clone(),
                            *sent_at,
                            *expire_secs,
                        ),
                        None => self.record_full(
                            &convo,
                            Direction::Incoming,
                            msg_id,
                            body,
                            *sent_at,
                            reply.clone(),
                            *expire_secs,
                        ),
                    }
                }
            }
            // A gossip head is not timeline content — the client handles it out of band.
            InboundEvent::PeerHead { .. } => {}
            // An admin-model group's signed membership epoch: the ONLY path that creates a
            // group or changes its roster. Authority is the epoch's admin signature
            // (validated in `adopt_group_epoch`), NOT the relaying sender — so a removed
            // member cannot forge one. A brand-new group from a pending/unknown sender is
            // request-screened first; the epoch rides along and replays on accept.
            InboundEvent::GroupRosterUpdate {
                sender_identity_key,
                epoch,
                name,
                disappearing_secs,
                avatar,
            } => {
                if !self.groups.contains_key(&epoch.group_id) {
                    let convo = self.attribute_device(sender_identity_key);
                    let held = HeldInvite {
                        group_id: epoch.group_id.clone(),
                        name: name.clone(),
                        members: members_from_epoch(epoch),
                        disappearing_secs: *disappearing_secs,
                        avatar: sanitize_avatar(avatar.clone()),
                        epoch: epoch.clone(),
                    };
                    if self.screen_group_invite(&convo, held, unix_now()) {
                        return;
                    }
                }
                // Snapshot our pre-adoption membership: re-entering the roster after a kick
                // (below) is only a REJOIN if we were actually out before this epoch.
                let was_member = self
                    .self_primary_key()
                    .map(str::to_string)
                    .zip(self.groups.get(&epoch.group_id))
                    .is_some_and(|(me, g)| g.members.iter().any(|m| m.identity_key == me));
                match self.adopt_group_epoch(epoch) {
                    // Brand-new admin-model group: adopt the carried meta so a newcomer sees
                    // the group fully (name/avatar/timer are egalitarian and travel here only
                    // on creation, never on a later membership advance).
                    GroupEpochOutcome::Created => {
                        self.set_group_name(&epoch.group_id, name);
                        if let Some(a) = avatar {
                            self.set_group_avatar(&epoch.group_id, Some(a.clone()));
                        }
                        match disappearing_secs {
                            None => {}
                            Some(0) => {
                                self.set_group_timer(&epoch.group_id, None);
                            }
                            Some(n) => {
                                self.set_group_timer(&epoch.group_id, Some(*n));
                            }
                        }
                    }
                    // The chain advanced. If WE are no longer in the roster, the admin kicked
                    // us: keep the thread readable but block sends. The pin still advanced,
                    // so a relay replay of the old epoch cannot silently un-remove us. The
                    // mirror case — the admin re-ADDED us after a kick (we re-enter a roster
                    // we had fallen out of) — clears the block again. `was_member` keeps a
                    // unilateral self-leave sticky: there we never left the epoch roster, so
                    // a later epoch that still lists us must not silently rejoin us.
                    GroupEpochOutcome::Advanced => {
                        let is_member = self
                            .self_primary_key()
                            .is_some_and(|me| epoch.is_member(me));
                        if was_member && !is_member {
                            self.set_group_left(&epoch.group_id, true);
                            self.record_group_system(
                                &epoch.group_id,
                                "You were removed from the group",
                                unix_now(),
                            );
                        } else if !was_member && is_member {
                            self.set_group_left(&epoch.group_id, false);
                            self.record_group_system(
                                &epoch.group_id,
                                "You were added back to the group",
                                unix_now(),
                            );
                        }
                    }
                    // Refused (bad signature / rollback / broken chain): ignore.
                    GroupEpochOutcome::Refused(_) => {}
                }
            }
            // Group content is roster-gated: a sender the members list doesn't vouch for is
            // QUARANTINED, not rendered — and not dropped either, so the add-race (their
            // membership epoch is still in flight) replays losslessly on adoption while a
            // kicked member's post-kick spam expires unseen.
            InboundEvent::GroupMessage {
                sender_identity_key,
                group_id,
                msg_id,
                body,
                sent_at,
                expire_secs,
                reply,
                forwarded,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_none() {
                    self.hold_group_content(
                        group_id,
                        &sender,
                        HeldGroupContent::Message {
                            msg_id: msg_id.clone(),
                            body: body.clone(),
                            sent_at: *sent_at,
                            expire_secs: *expire_secs,
                            reply: reply.clone(),
                            forwarded: *forwarded,
                        },
                        unix_now(),
                    );
                    return;
                }
                self.record_group_message(
                    group_id,
                    &sender,
                    msg_id,
                    body,
                    *sent_at,
                    *expire_secs,
                    reply.clone(),
                );
                if *forwarded {
                    self.set_group_forwarded(group_id, msg_id);
                }
            }
            // A member edited/deleted one of THEIR OWN group messages — the stored-sender
            // match inside the apply_* helpers is the ownership check (a member can never
            // rewrite or remove someone else's message). Non-members quarantine like any
            // other content (their target may itself still be in quarantine).
            InboundEvent::GroupMessageEdited {
                sender_identity_key,
                group_id,
                msg_id,
                body,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_none() {
                    self.hold_group_content(
                        group_id,
                        &sender,
                        HeldGroupContent::Edit {
                            msg_id: msg_id.clone(),
                            body: body.clone(),
                        },
                        unix_now(),
                    );
                    return;
                }
                self.apply_incoming_group_edit(group_id, msg_id, body, &sender);
            }
            InboundEvent::GroupMessageDeleted {
                sender_identity_key,
                group_id,
                msg_id,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_none() {
                    self.hold_group_content(
                        group_id,
                        &sender,
                        HeldGroupContent::Delete {
                            msg_id: msg_id.clone(),
                        },
                        unix_now(),
                    );
                    return;
                }
                self.apply_incoming_group_delete(group_id, msg_id, &sender);
            }
            // Roster/name changes: honored only from a current member (same egalitarian
            // trust model as the roster itself). Each drops a system chip so the change
            // is visible in the transcript.
            InboundEvent::GroupRenamed {
                sender_identity_key,
                group_id,
                name,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                let who = self.group_member_label(group_id, &sender);
                let (Some(who), false) = (who, name.trim().is_empty()) else {
                    return;
                };
                if self.rename_group(group_id, name) {
                    let chip = format!("{} renamed the group to \"{}\"", who, name.trim());
                    self.record_group_system(group_id, &chip, unix_now());
                }
            }
            InboundEvent::GroupMemberLeft {
                sender_identity_key,
                group_id,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                let Some(who) = self.group_member_label(group_id, &sender) else {
                    return;
                };
                if who == "You" {
                    // Our own other device left the group: converge (block sends here too).
                    self.set_group_left(group_id, true);
                    self.record_group_system(group_id, "You left the group", unix_now());
                } else if self.remove_group_member(group_id, &sender).is_some() {
                    self.record_group_system(
                        group_id,
                        &format!("{who} left the group"),
                        unix_now(),
                    );
                }
            }
            InboundEvent::GroupAttachment {
                sender_identity_key,
                group_id,
                msg_id,
                attachment,
                sent_at,
                expire_secs,
                forwarded,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_none() {
                    self.hold_group_content(
                        group_id,
                        &sender,
                        HeldGroupContent::Attachment {
                            msg_id: msg_id.clone(),
                            attachment: attachment.clone(),
                            sent_at: *sent_at,
                            expire_secs: *expire_secs,
                            forwarded: *forwarded,
                        },
                        unix_now(),
                    );
                    return;
                }
                self.record_group_attachment(
                    group_id,
                    &sender,
                    msg_id,
                    attachment.clone(),
                    *sent_at,
                    *expire_secs,
                );
                if *forwarded {
                    self.set_group_forwarded(group_id, msg_id);
                }
            }
            // A member changed the group's disappearing timer — adopt it. Honored only
            // from a CURRENT member (roster trust model): a removed member must not be
            // able to force near-immediate reap or disable expiry on our device.
            InboundEvent::GroupTimerUpdate {
                sender_identity_key,
                group_id,
                disappearing_secs,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_some() {
                    self.set_group_timer(group_id, *disappearing_secs);
                }
            }
            InboundEvent::Renamed {
                sender_identity_key,
                new_username,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if !new_username.trim().is_empty() {
                    self.rename_contact(&sender, new_username.trim());
                }
            }
            // A reaction from the peer: attribute the reactor to their account and toggle.
            InboundEvent::Reaction {
                sender_identity_key,
                target_msg_id,
                emoji,
                add,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                let reactor = convo.clone();
                self.react(&convo, target_msg_id, &reactor, emoji, *add);
            }
            // Self-sync of a disappearing-timer change WE made from another of our
            // devices — adopt the same timer. Honored only from a verified own device
            // (else a peer could silently extend/kill our timer).
            InboundEvent::SelfTimerUpdate {
                sender_identity_key,
                peer_key,
                disappearing_secs,
            } => {
                if self.is_own_device(sender_identity_key) {
                    self.set_timer(peer_key, *disappearing_secs);
                }
            }
            // Self-sync of a reaction WE made from another of our devices — stored as ours
            // (empty reactor), honored only from a verified own device.
            InboundEvent::SelfReaction {
                sender_identity_key,
                peer_key,
                target_msg_id,
                emoji,
                add,
            } => {
                if self.is_own_device(sender_identity_key) {
                    self.react(peer_key, target_msg_id, "", emoji, *add);
                }
            }
            // A group reaction: ours (from another own device) is stored as ours; anyone
            // else's is keyed by their attributed account — and roster-gated like every
            // other piece of group content (quarantined, not dropped).
            InboundEvent::GroupReaction {
                sender_identity_key,
                group_id,
                target_msg_id,
                emoji,
                add,
            } => {
                if self.is_own_device(sender_identity_key) {
                    self.react_group(group_id, target_msg_id, "", emoji, *add);
                    return;
                }
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_none() {
                    self.hold_group_content(
                        group_id,
                        &sender,
                        HeldGroupContent::Reaction {
                            target_msg_id: target_msg_id.clone(),
                            emoji: emoji.clone(),
                            add: *add,
                        },
                        unix_now(),
                    );
                    return;
                }
                self.react_group(group_id, target_msg_id, &sender, emoji, *add);
            }
            // A peer broadcast a new (or cleared) profile picture — store it against their
            // contact. Attribute the sending device to its account so a picture set on the
            // peer's phone shows for the conversation we track under their primary key.
            InboundEvent::ProfileUpdate {
                sender_identity_key,
                avatar,
            } => {
                let peer = self.attribute_device(sender_identity_key);
                self.set_contact_avatar(&peer, avatar.clone());
            }
            // A member set (or cleared) the group's picture. Honored only from a CURRENT
            // member (roster trust model), same as the timer/roster changes.
            InboundEvent::GroupAvatarUpdate {
                sender_identity_key,
                group_id,
                avatar,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_some() {
                    self.set_group_avatar(group_id, avatar.clone());
                }
            }
            // Self-sync of OUR OWN picture from another of our devices — adopt it (sanitized).
            // Gated on a verified own device so a peer can't overwrite our own-profile picture.
            InboundEvent::SelfProfileUpdate {
                sender_identity_key,
                avatar,
            } => {
                if self.is_own_device(sender_identity_key) {
                    self.set_my_avatar(avatar.clone());
                }
            }
            // A pin from the peer (1:1): shared metadata, either side may toggle it.
            InboundEvent::MessagePinned {
                sender_identity_key,
                msg_id,
                pin,
            } => {
                let convo = self.attribute_device(sender_identity_key);
                // Pins are shared conversation metadata — not something a pending
                // requester or stranger gets to toggle before being accepted.
                if !self.control_gated(&convo) {
                    self.set_msg_pinned(&convo, msg_id, *pin);
                }
            }
            // A pin WE toggled on another of our own devices — mirror it. Gated on a
            // verified own device (else a peer could rewrite our pins in ANY chat).
            InboundEvent::SelfMessagePinned {
                sender_identity_key,
                peer_key,
                msg_id,
                pin,
            } => {
                if self.is_own_device(sender_identity_key) {
                    self.set_msg_pinned(peer_key, msg_id, *pin);
                }
            }
            // A group pin: honored only from a current member (roster trust model).
            InboundEvent::GroupMessagePinned {
                sender_identity_key,
                group_id,
                msg_id,
                pin,
            } => {
                let sender = self.attribute_device(sender_identity_key);
                if self.group_member_label(group_id, &sender).is_some() {
                    self.set_group_msg_pinned(group_id, msg_id, *pin);
                }
            }
            // Typing indicators are ephemeral by design and never touch the timeline.
            InboundEvent::Typing { .. } | InboundEvent::GroupTyping { .. } => {}
            // Call signaling is ephemeral by design: the offer carries the call key, and
            // key material must never be written into the (persisted) history. The shell
            // handles ringing/answering directly off the inbound event. A history re-export
            // request is likewise handled by the shell, not the timeline.
            InboundEvent::CallOfferedV2 { .. }
            | InboundEvent::CallAnswerClaimedV2 { .. }
            | InboundEvent::CallWinnerV2 { .. }
            | InboundEvent::CallBusyV2 { .. }
            | InboundEvent::CallTerminalV2 { .. }
            | InboundEvent::GroupCallOfferedV2 { .. }
            | InboundEvent::GroupCallAnswerClaimedV2 { .. }
            | InboundEvent::GroupCallWinnerV2 { .. }
            | InboundEvent::GroupCallTerminalV2 { .. }
            | InboundEvent::SelfCallTerminalV2 { .. }
            | InboundEvent::SyncRequested { .. }
            | InboundEvent::PrimaryTransferOffered { .. } => {}
        }
    }

    /// Delete every message whose delete time has passed — 1:1 conversations AND group
    /// threads. Returns how many were removed. Call periodically (a reaper tick) and on
    /// load.
    pub fn reap(&mut self, now: u64) -> usize {
        self.reap_with_chats(now).0
    }

    /// Like [`reap`](Self::reap), also reporting WHICH chats lost messages (peer
    /// identity keys / group ids) — the notification pipeline uses this to pull the
    /// expired content out of the OS shade so it never outlives its timer there.
    pub fn reap_with_chats(&mut self, now: u64) -> (usize, Vec<String>) {
        let expired = |m: &StoredMessage| matches!(m.delete_at, Some(t) if t <= now);
        let mut removed = 0;
        let mut chats = Vec::new();
        for (peer, convo) in self.conversations.iter_mut() {
            let before = convo.messages.len();
            convo.messages.retain(|m| !expired(m));
            if convo.messages.len() != before {
                removed += before - convo.messages.len();
                chats.push(peer.clone());
            }
        }
        for (group_id, g) in self.groups.iter_mut() {
            let before = g.messages.len();
            g.messages.retain(|m| !expired(m));
            if g.messages.len() != before {
                removed += before - g.messages.len();
                chats.push(group_id.clone());
            }
        }
        // Quarantined group content ages out on the same periodic sweep (it was never
        // rendered, so it is not reported as a lost chat).
        self.prune_held_group_content(now);
        (removed, chats)
    }

    /// The messages in a conversation (empty slice if none).
    pub fn messages(&self, peer: &str) -> &[StoredMessage] {
        self.conversations.get(peer).map_or(&[], |c| &c.messages)
    }

    /// The last message in a conversation, if any (for a chat-list preview).
    pub fn last_message(&self, peer: &str) -> Option<&StoredMessage> {
        self.conversations.get(peer).and_then(|c| c.messages.last())
    }

    /// Does this conversation look like it is talking into a DEAD ratchet session?
    ///
    /// A desynced session is invisible to its sender: we keep encrypting happily, the peer's
    /// decrypt yields `NoSession` and drops the message, and nothing ever comes back. The
    /// only trustworthy signal is local and private — the recipient acknowledges every
    /// message that lands in their timeline, so a run of recent sends that never reached
    /// `Delivered` is strong evidence the session is dead.
    ///
    /// Deliberately sender-local: the alternative (the receiver asking peers to reset when
    /// it sees undecryptable traffic) is exploitable, because anyone — including the relay —
    /// can post junk ciphertext into a mailbox, and the resulting burst of reset requests
    /// would enumerate that user's contacts. Nothing here is remotely triggerable, and a
    /// false positive costs only a re-handshake.
    ///
    /// Conservative on purpose:
    /// * requires at least one INCOMING message ever — a peer who never replied may simply
    ///   not have accepted us, and a pending message request withholds receipts *by design*;
    /// * requires a run of unacknowledged sends whose oldest is past a grace period, so a
    ///   brief offline peer or a fast burst cannot trip it;
    /// * stops at the first acknowledged send or any inbound message — either proves the
    ///   session is alive;
    /// * rate-limited per contact by `last_session_reset`, so it can never churn.
    pub fn session_looks_dead(&self, peer: &str, now: u64) -> bool {
        let Some(convo) = self.conversations.get(peer) else {
            return false;
        };
        // Never auto-reset a conversation we have never actually received anything on.
        if !convo
            .messages
            .iter()
            .any(|m| m.direction == Direction::Incoming && !m.system)
        {
            return false;
        }
        if self
            .contacts
            .values()
            .find(|p| p.identity_key == peer)
            .and_then(|p| p.last_session_reset)
            .is_some_and(|t| now.saturating_sub(t) < DEAD_SESSION_RETRY_SECS)
        {
            return false;
        }
        // Walk back over the trailing run of unacknowledged outgoing messages.
        let mut unacked = 0usize;
        let mut oldest = now;
        for m in convo.messages.iter().rev() {
            if m.system {
                continue;
            }
            match m.direction {
                // Anything acknowledged means the session is fine.
                Direction::Outgoing if m.status != DeliveryStatus::Sent => break,
                Direction::Outgoing => {
                    unacked += 1;
                    oldest = oldest.min(m.sent_at);
                }
                // They reached us after these sends — the session is alive.
                Direction::Incoming => break,
            }
        }
        unacked >= DEAD_SESSION_MIN_UNACKED
            && now.saturating_sub(oldest) >= DEAD_SESSION_MIN_AGE_SECS
    }

    /// Anchor the dead-session rate limit after an automatic reset.
    pub fn mark_session_reset(&mut self, peer: &str, now: u64) {
        if let Some(pin) = self.contacts.values_mut().find(|p| p.identity_key == peer) {
            pin.last_session_reset = Some(now);
        }
    }

    /// One-time heal for vaults written before ordered inserts existed: stable-sort every
    /// 1:1 and group thread by `sent_at`, so a history that had drifted into multi-device
    /// self-sync *arrival* order snaps back to chronological order. Stable, so a same-second
    /// burst keeps its existing relative order. Cheap on an already-ordered thread. Called
    /// once at unlock; new messages stay ordered via [`insert_message_ordered`].
    pub fn normalize_message_order(&mut self) {
        for c in self.conversations.values_mut() {
            c.messages.sort_by_key(|m| m.sent_at);
        }
        for g in self.groups.values_mut() {
            g.messages.sort_by_key(|m| m.sent_at);
        }
    }

    /// Apply a delivery receipt from the peer: upgrade the status of our matching outgoing
    /// messages (never downgrade — `Seen` sticks even if a stale `Delivered` arrives late).
    pub fn mark_receipt(&mut self, peer: &str, ids: &[String], seen: bool) {
        let target = if seen {
            DeliveryStatus::Seen
        } else {
            DeliveryStatus::Delivered
        };
        if let Some(c) = self.conversations.get_mut(peer) {
            for m in c.messages.iter_mut() {
                if m.direction == Direction::Outgoing && ids.iter().any(|i| i == &m.msg_id) {
                    m.status = m.status.max(target);
                }
            }
        }
    }

    /// The ids of the incoming messages in a conversation (to acknowledge as seen).
    pub fn incoming_ids(&self, peer: &str) -> Vec<String> {
        self.messages(peer)
            .iter()
            .filter(|m| m.direction == Direction::Incoming)
            .map(|m| m.msg_id.clone())
            .collect()
    }

    /// The incoming messages we have NOT yet sent a "seen" receipt for. Send one receipt
    /// covering these, then confirm with [`mark_seen_receipted`](Self::mark_seen_receipted).
    pub fn unseen_incoming_ids(&self, peer: &str) -> Vec<String> {
        self.messages(peer)
            .iter()
            .filter(|m| m.direction == Direction::Incoming && !m.seen_receipted)
            .map(|m| m.msg_id.clone())
            .collect()
    }

    /// Record that a "seen" receipt for these incoming messages was sent (they are now
    /// "read" locally too).
    pub fn mark_seen_receipted(&mut self, peer: &str, ids: &[String]) {
        if let Some(c) = self.conversations.get_mut(peer) {
            for m in c.messages.iter_mut() {
                if m.direction == Direction::Incoming && ids.iter().any(|i| i == &m.msg_id) {
                    m.seen_receipted = true;
                }
            }
        }
    }

    /// How many incoming messages the user hasn't seen yet (drives the unread badge).
    pub fn unread_count(&self, peer: &str) -> usize {
        self.messages(peer)
            .iter()
            .filter(|m| m.direction == Direction::Incoming && !m.seen_receipted)
            .count()
    }

    /// The address book: every pinned contact as `(username, pin)`. Drives the chat list
    /// and lets the UI map a conversation's peer key back to a username.
    pub fn contacts(&self) -> Vec<(String, ContactPin)> {
        self.contacts
            .iter()
            .map(|(u, p)| (u.clone(), p.clone()))
            .collect()
    }

    /// The groups the user belongs to as `(group_id, record)`.
    pub fn groups(&self) -> Vec<(String, GroupRecord)> {
        self.groups
            .iter()
            .map(|(id, g)| (id.clone(), g.clone()))
            .collect()
    }

    /// The identity key we've pinned for a username (`None` if never added). Pass this to
    /// [`crate::Client::add_contact_checked`] to detect a key change.
    pub fn pinned_contact_key(&self, username: &str) -> Option<&str> {
        self.contacts.get(username).map(|c| c.identity_key.as_str())
    }

    /// Reverse lookup: the username pinned for a peer identity key, if any. Lets the
    /// client name (and receipt) a conversation it only knows by key.
    pub fn username_for_peer(&self, peer: &str) -> Option<String> {
        self.contacts
            .iter()
            .find(|(_, p)| p.identity_key == peer)
            .map(|(u, _)| u.clone())
    }

    /// Whether the user has confirmed this contact's key out-of-band.
    pub fn contact_verified(&self, username: &str) -> bool {
        self.contacts.get(username).is_some_and(|c| c.verified)
    }

    /// The last accepted Key Transparency tree head (gossip witness), if any.
    pub fn witness(&self) -> Option<&SignedTreeHead> {
        self.witness.as_ref()
    }

    /// Advance the gossip witness to a newly-accepted tree head.
    pub fn set_witness(&mut self, head: SignedTreeHead) {
        self.witness = Some(head);
    }

    /// Pin (or re-pin, after an accepted key change) a contact's identity key. Local
    /// preferences (pin/mute/nickname/block) survive a re-pin.
    pub fn pin_contact(&mut self, username: &str, identity_key: &str, verified: bool) {
        let e = self
            .contacts
            .entry(username.to_string())
            .or_insert_with(|| ContactPin {
                identity_key: identity_key.to_string(),
                verified,
                ..Default::default()
            });
        e.identity_key = identity_key.to_string();
        e.verified = verified;
    }

    /// Fail-closed auto-add for the inbound message/attachment path, where `username` is
    /// the sender-claimed (attacker-controlled) `from` string. Unlike [`pin_contact`],
    /// this NEVER overwrites an existing pin that maps to a *different* identity key, and
    /// never carries a `verified` flag onto a key that isn't already the verified one.
    ///
    /// Without this guard, an attacker who knows a victim's contact name could send
    /// `from:"alice"` and rewrite the victim's verified `alice` pin to the attacker's key
    /// while keeping the verified shield. A genuine key rotation is handled deliberately
    /// by the KT-checked `open_chat` / `add_contact_checked` path — not here.
    pub fn auto_pin_contact(&mut self, username: &str, identity_key: &str) {
        // Name already pinned: authoritative, leave it untouched — a matching key is the
        // same contact (nothing to change) and a mismatch is a spoof or un-accepted key
        // change that must not overwrite the pin or its verified flag. First sighting of a
        // name: pin unverified.
        if self.contacts.contains_key(username) {
            return;
        }
        self.contacts.insert(
            username.to_string(),
            ContactPin {
                identity_key: identity_key.to_string(),
                ..Default::default()
            },
        );
    }

    // ── Message requests ─────────────────────────────────────────────────────────
    //
    // The gate is CLIENT-side by necessity: sealed sender means the relay never learns
    // who a message is from, so only the recipient's own client can decide whether a
    // sender is a stranger. Every inbound path funnels through [`History::apply`] (and
    // the shell's call-signal hook), which makes this the single choke point — there is
    // no route into the timeline that skips it.

    /// The message-request settings as `(requests_enabled, text_with_request_allowed)`.
    pub fn request_prefs(&self) -> (bool, bool) {
        (!self.open_messaging, self.request_text_allowed)
    }

    /// Set the message-request settings. Turning requests OFF accepts every pending
    /// request in the same breath — open mode must never leave invisible pending pins
    /// behind (their chats surface, held invites replay).
    pub fn set_request_prefs(&mut self, enabled: bool, allow_text: bool) {
        self.open_messaging = !enabled;
        self.request_text_allowed = allow_text;
        if !enabled {
            let pending: Vec<String> = self
                .contacts
                .iter()
                .filter(|(_, p)| p.request.is_some())
                .map(|(u, _)| u.clone())
                .collect();
            for username in pending {
                self.accept_request(&username);
            }
        }
    }

    fn requests_enabled(&self) -> bool {
        !self.open_messaging
    }

    /// Whether this conversation key is exempt from the gate: our own account/devices
    /// (self-sync must never be screened) always pass.
    fn request_exempt(&self, convo: &str) -> bool {
        self.is_own_device(convo) || self.self_primary_key() == Some(convo)
    }

    /// Is this conversation key a pending (not yet accepted) message request?
    pub fn request_pending_for_key(&self, convo: &str) -> bool {
        self.contacts
            .values()
            .any(|p| p.identity_key == convo && p.request.is_some())
    }

    /// Is this username a pending message request?
    pub fn is_request_pending(&self, username: &str) -> bool {
        self.contacts
            .get(username)
            .is_some_and(|p| p.request.is_some())
    }

    /// Screen one inbound content event (text / attachment / forwarded copy) from the
    /// attributed conversation key `convo`, claiming `claimed` as its username.
    /// Creates or refreshes the pending request when the sender is a stranger.
    pub(crate) fn screen_inbound(&mut self, convo: &str, claimed: &str, now: u64) -> InboundScreen {
        if !self.requests_enabled() || self.request_exempt(convo) {
            return InboundScreen::Allow;
        }
        // Content is HELD in both modes — recorded into the hidden conversation so it
        // surfaces the moment the user accepts (a request-only recipient must still see
        // the first message AFTER approving; losing it made accepted chats start empty).
        // The mode only controls presentation: in request-only mode the `withheld`
        // counter grows and the UI shows a count, never a preview.
        let allow_text = self.request_text_allowed;
        if let Some(pin) = self.contacts.values_mut().find(|p| p.identity_key == convo) {
            return match &mut pin.request {
                None => InboundScreen::Allow,
                Some(req) => {
                    req.last = now;
                    req.seen = false;
                    if !allow_text {
                        req.withheld = req.withheld.saturating_add(1);
                    }
                    InboundScreen::Held
                }
            };
        }
        // Unknown sender. A request must be actionable: with no claimed username — or a
        // name already pinned to a DIFFERENT key (a spoof `auto_pin_contact` would
        // refuse too) — withhold entirely; no request row, nothing recorded.
        if claimed.is_empty() || self.contacts.contains_key(claimed) {
            return InboundScreen::Dropped;
        }
        let req = PendingRequest {
            since: now,
            last: now,
            withheld: if allow_text { 0 } else { 1 },
            ..Default::default()
        };
        self.contacts.insert(
            claimed.to_string(),
            ContactPin {
                identity_key: convo.to_string(),
                request: Some(req),
                ..Default::default()
            },
        );
        InboundScreen::Held
    }

    /// Screen an explicit chat request ("knock") from `convo` claiming `claimed`: create
    /// or refresh the pending-request row — no content is held, there is none. Ignored
    /// for accepted contacts (nothing to request), unactionable strangers (same
    /// actionability rule as [`screen_inbound`](Self::screen_inbound)), and when the
    /// gate is off (the sender can simply message).
    pub(crate) fn screen_knock(&mut self, convo: &str, claimed: &str, now: u64) {
        if !self.requests_enabled() || self.request_exempt(convo) {
            return;
        }
        if let Some(pin) = self.contacts.values_mut().find(|p| p.identity_key == convo) {
            if let Some(req) = &mut pin.request {
                req.last = now;
                req.seen = false;
            }
            return;
        }
        if claimed.is_empty() || self.contacts.contains_key(claimed) {
            return;
        }
        self.contacts.insert(
            claimed.to_string(),
            ContactPin {
                identity_key: convo.to_string(),
                request: Some(PendingRequest {
                    since: now,
                    last: now,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }

    /// Screen an inbound 1:1 call offer. `true` = let it ring; `false` = suppressed —
    /// a stranger's call never rings, the attempt is folded into their pending request
    /// instead (same actionability rule as [`screen_inbound`](Self::screen_inbound)).
    pub fn screen_call_offer(&mut self, sender_key: &str, claimed: &str, now: u64) -> bool {
        let convo = self.attribute_device(sender_key);
        if !self.requests_enabled() || self.request_exempt(&convo) {
            return true;
        }
        if let Some(pin) = self.contacts.values_mut().find(|p| p.identity_key == convo) {
            return match &mut pin.request {
                None => true,
                Some(req) => {
                    req.last = now;
                    req.seen = false;
                    req.calls = req.calls.saturating_add(1);
                    false
                }
            };
        }
        if claimed.is_empty() || self.contacts.contains_key(claimed) {
            return false;
        }
        self.contacts.insert(
            claimed.to_string(),
            ContactPin {
                identity_key: convo.clone(),
                request: Some(PendingRequest {
                    since: now,
                    last: now,
                    calls: 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        false
    }

    /// Screen a group invite from `convo` for a group we are NOT in. Returns `true`
    /// when the gate consumed it (held on the pending request, or withheld from an
    /// unnameable stranger); `false` = apply the invite normally.
    fn screen_group_invite(&mut self, convo: &str, invite: HeldInvite, now: u64) -> bool {
        if !self.requests_enabled() || self.request_exempt(convo) {
            return false;
        }
        let Some(pin) = self.contacts.values_mut().find(|p| p.identity_key == convo) else {
            // A stranger with no name on file (invites carry none): withheld. Nothing
            // actionable to show, and a spammer never lands a group in the UI.
            return true;
        };
        match &mut pin.request {
            None => false,
            Some(req) => {
                req.last = now;
                req.seen = false;
                req.invites.retain(|i| i.group_id != invite.group_id);
                if req.invites.len() < MAX_HELD_INVITES {
                    req.invites.push(invite);
                }
                true
            }
        }
    }

    /// True when the gate blocks non-content control traffic (timer changes, pins)
    /// from this key: requests on AND the sender is unknown or still pending.
    fn control_gated(&self, convo: &str) -> bool {
        if !self.requests_enabled() || self.request_exempt(convo) {
            return false;
        }
        self.contacts
            .values()
            .find(|p| p.identity_key == convo)
            .is_none_or(|p| p.request.is_some())
    }

    /// Accept a pending message request: the contact becomes a normal chat and every
    /// held group invite replays. Returns `false` for an unknown / non-pending name.
    pub fn accept_request(&mut self, username: &str) -> bool {
        let Some(pin) = self.contacts.get_mut(username) else {
            return false;
        };
        let Some(req) = pin.request.take() else {
            return false;
        };
        let peer = pin.identity_key.clone();
        for inv in req.invites {
            // Validate + adopt the signed epoch (the chain is checked on replay too —
            // accepting a request never bypasses membership authority). A refused epoch never
            // surfaces the group.
            match self.adopt_group_epoch(&inv.epoch) {
                GroupEpochOutcome::Refused(_) => continue,
                GroupEpochOutcome::Created | GroupEpochOutcome::Advanced => {
                    self.set_group_name(&inv.group_id, &inv.name)
                }
            }
            if let Some(a) = inv.avatar {
                self.set_group_avatar(&inv.group_id, Some(a));
            }
            match inv.disappearing_secs {
                None => {}
                Some(0) => {
                    self.set_group_timer(&inv.group_id, None);
                }
                Some(n) => {
                    self.set_group_timer(&inv.group_id, Some(n));
                }
            }
        }
        self.record_system(&peer, "You accepted the message request", unix_now());
        true
    }

    /// Accept by conversation key — replying from any of our devices is consent (the
    /// self-sync path only knows the peer key). No-op unless actually pending.
    pub fn accept_request_for_key(&mut self, convo: &str) -> bool {
        let name = self
            .contacts
            .iter()
            .find(|(_, p)| p.identity_key == convo && p.request.is_some())
            .map(|(u, _)| u.clone());
        match name {
            Some(u) => self.accept_request(&u),
            None => false,
        }
    }

    /// Decline a pending request. `block` keeps the pin (blocked) so this key's future
    /// traffic drops silently; otherwise pin and held conversation vanish entirely
    /// (they may request again later).
    pub fn decline_request(&mut self, username: &str, block: bool) -> bool {
        let Some(pin) = self.contacts.get_mut(username) else {
            return false;
        };
        let Some(req) = pin.request.as_ref() else {
            return false;
        };
        // Declining the requester also voids their held invites' quarantined first
        // messages — but never a group that became real through someone else meanwhile.
        let dead_invite_groups: Vec<String> = req
            .invites
            .iter()
            .map(|i| i.group_id.clone())
            .filter(|gid| !self.groups.contains_key(gid))
            .collect();
        let peer = pin.identity_key.clone();
        if block {
            pin.request = None;
            pin.blocked = true;
        } else {
            self.contacts.remove(username);
        }
        for gid in dead_invite_groups {
            self.held_group_content.remove(&gid);
        }
        self.delete_conversation(&peer);
        true
    }

    /// Every pending request as `(username, pin)`, newest activity first.
    pub fn pending_requests(&self) -> Vec<(String, ContactPin)> {
        let mut out: Vec<(String, ContactPin)> = self
            .contacts
            .iter()
            .filter(|(_, p)| p.request.is_some())
            .map(|(u, p)| (u.clone(), p.clone()))
            .collect();
        out.sort_by(|a, b| {
            let t = |p: &ContactPin| p.request.as_ref().map_or(0, |r| r.last);
            t(&b.1).cmp(&t(&a.1))
        });
        out
    }

    /// How many requests are pending.
    pub fn request_count(&self) -> usize {
        self.contacts
            .values()
            .filter(|p| p.request.is_some())
            .count()
    }

    /// How many pending requests the user has not viewed yet (drives the red dot).
    pub fn requests_unseen(&self) -> usize {
        self.contacts
            .values()
            .filter(|p| p.request.as_ref().is_some_and(|r| !r.seen))
            .count()
    }

    /// Mark every pending request viewed (clears the red dot; the rows stay).
    pub fn mark_requests_seen(&mut self) {
        for p in self.contacts.values_mut() {
            if let Some(req) = &mut p.request {
                req.seen = true;
            }
        }
    }

    /// One-shot notification latch: `true` exactly once per request lifecycle, so a
    /// stranger burst produces ONE "message request" notification, not one per event.
    pub fn request_needs_notify(&mut self, convo: &str) -> bool {
        if let Some(pin) = self.contacts.values_mut().find(|p| p.identity_key == convo) {
            if let Some(req) = &mut pin.request {
                if !req.notified {
                    req.notified = true;
                    return true;
                }
            }
        }
        false
    }

    /// Apply a peer's authenticated rename: move their pin (verified flag and local
    /// preferences intact — the identity key is unchanged, so an out-of-band verification
    /// still holds) from the old username to the new one.
    ///
    /// Shadowing guard: refused (`false`) when the new name is already pinned to a
    /// *different* key — a rename claim must never overwrite an existing contact. And a
    /// false claim buys nothing anyway: the send path re-resolves every username through
    /// the KT log against the pinned key before sending.
    pub fn rename_contact(&mut self, identity_key: &str, new_username: &str) -> bool {
        if let Some(existing) = self.contacts.get(new_username) {
            return existing.identity_key == identity_key; // already renamed = ok; shadowing = refused
        }
        let Some(old) = self
            .contacts
            .iter()
            .find(|(_, p)| p.identity_key == identity_key)
            .map(|(u, _)| u.clone())
        else {
            return false; // unknown peer — nothing to rename
        };
        let pin = self.contacts.remove(&old).expect("key just found");
        self.contacts.insert(new_username.to_string(), pin);
        true
    }

    /// Record one of our OWN former usernames after a rename (deduped, capped). A
    /// reclaimed name (`new_username` was itself a former name) leaves the alias list —
    /// it is the MAIN mailbox again, and an alias drain on the same hash would
    /// double-subscribe it.
    pub fn note_own_rename(&mut self, old_username: &str, new_username: &str) {
        self.previous_usernames
            .retain(|u| u != old_username && u != new_username);
        self.previous_usernames.push(old_username.to_string());
        if self.previous_usernames.len() > MAX_PREVIOUS_USERNAMES {
            let excess = self.previous_usernames.len() - MAX_PREVIOUS_USERNAMES;
            self.previous_usernames.drain(..excess);
        }
    }

    /// Our former usernames (oldest first) — their mailboxes are still drained.
    pub fn previous_usernames(&self) -> &[String] {
        &self.previous_usernames
    }

    /// Stop treating a former username as ours (its released grace ran out and someone
    /// else took the name over — the KT log no longer binds it to our keys).
    pub fn remove_previous_username(&mut self, username: &str) {
        self.previous_usernames.retain(|u| u != username);
    }

    /// Record a completed username change at `now` (unix secs) for the weekly limit.
    pub fn note_rename_time(&mut self, now: u64) {
        self.own_rename_times.push(now);
        let cutoff = now.saturating_sub(RENAME_LIMIT_WINDOW_SECS);
        self.own_rename_times.retain(|&t| t >= cutoff);
    }

    /// How many username changes happened inside the rolling limit window ending at
    /// `now`, plus the unix time the OLDEST of them leaves the window (when the count
    /// is at the cap, that is when the next rename becomes possible).
    pub fn renames_in_window(&self, now: u64) -> (usize, Option<u64>) {
        let cutoff = now.saturating_sub(RENAME_LIMIT_WINDOW_SECS);
        let in_window: Vec<u64> = self
            .own_rename_times
            .iter()
            .copied()
            .filter(|&t| t >= cutoff && t <= now)
            .collect();
        let next_free = in_window
            .iter()
            .min()
            .map(|&t| t + RENAME_LIMIT_WINDOW_SECS);
        (in_window.len(), next_free)
    }

    /// Mutate a contact's local preferences. Returns false if the contact is unknown.
    /// This contact's saved voice volume in percent, or [`crate::call::GAIN_UNITY`] if
    /// they have never been adjusted.
    pub fn voice_gain(&self, username: &str) -> u32 {
        self.contacts
            .get(username)
            .and_then(|c| c.voice_gain)
            .unwrap_or(crate::call::GAIN_UNITY)
    }

    /// Remember how loud to play this contact. Clamped, because the value arrives from
    /// a UI slider and the vault should not be able to hold one nothing can produce.
    ///
    /// Returns false for an unknown contact — a volume set for somebody who is not a
    /// pinned contact has nowhere to live, and silently doing nothing would leave the
    /// UI showing a setting that will not survive the call.
    pub fn set_voice_gain(&mut self, username: &str, percent: u32) -> bool {
        self.with_contact_mut(username, |c| {
            c.voice_gain = Some(percent.min(crate::call::GAIN_MAX));
        })
    }

    pub fn with_contact_mut(&mut self, username: &str, f: impl FnOnce(&mut ContactPin)) -> bool {
        match self.contacts.get_mut(username) {
            Some(pin) => {
                f(pin);
                true
            }
            None => false,
        }
    }

    /// Is the peer with this identity key blocked?
    pub fn peer_blocked(&self, identity_key: &str) -> bool {
        self.contacts
            .values()
            .any(|p| p.identity_key == identity_key && p.blocked)
    }

    /// Wipe a conversation's messages and timer. The contact pin (and its local
    /// preferences) stays, so the chat can restart cleanly.
    pub fn delete_conversation(&mut self, peer: &str) {
        self.conversations.remove(peer);
    }

    /// Remove a contact pin entirely (used together with delete_conversation when the
    /// user deletes a chat and doesn't want the contact around).
    pub fn remove_contact(&mut self, username: &str) {
        self.contacts.remove(username);
    }

    /// Mark all of a group's messages as locally seen (no receipts for groups).
    pub fn mark_group_seen(&mut self, group_id: &str) {
        if let Some(g) = self.groups.get_mut(group_id) {
            for m in g.messages.iter_mut() {
                m.seen_receipted = true;
            }
        }
    }

    /// Unseen messages in a group (drives its unread badge).
    pub fn group_unread(&self, group_id: &str) -> usize {
        self.groups.get(group_id).map_or(0, |g| {
            g.messages.iter().filter(|m| !m.seen_receipted).count()
        })
    }

    /// Delete a group and its thread locally.
    pub fn delete_group(&mut self, group_id: &str) {
        self.groups.remove(group_id);
        self.held_group_content.remove(group_id);
    }

    // ── Multi-device ─────────────────────────────────────────────────────────

    /// This device's identity within its account (`None` = legacy single-device).
    pub fn self_device(&self) -> Option<&SelfDevice> {
        self.self_device.as_ref()
    }

    /// The local device id (`"0"` for a primary or legacy single device).
    pub fn self_device_id(&self) -> String {
        self.self_device
            .as_ref()
            .map(|d| d.device_id.clone())
            .unwrap_or_else(|| kt_log::PRIMARY_DEVICE_ID.to_string())
    }

    /// Is this device the account's primary (holds the KT-bound account keys)? A legacy
    /// single-device account is its own primary.
    pub fn is_primary_device(&self) -> bool {
        self.self_device
            .as_ref()
            .map(|d| d.is_primary)
            .unwrap_or(true)
    }

    /// Record this device's own identity (set on link / on first roster publish).
    pub fn set_self_device(&mut self, device_id: &str, is_primary: bool) {
        self.self_device = Some(SelfDevice {
            device_id: device_id.to_string(),
            is_primary,
        });
    }

    /// Our account's own primary (KT-bound) identity key, if known.
    pub fn self_primary_key(&self) -> Option<&str> {
        self.self_primary_key.as_deref()
    }

    pub fn set_self_primary_key(&mut self, key: &str) {
        self.self_primary_key = Some(key.to_string());
    }

    /// Is `device_key` one of our OWN account's devices (per the verified self roster)?
    /// Used to authenticate self-sync messages before honoring them.
    pub fn is_own_device(&self, device_key: &str) -> bool {
        match &self.self_primary_key {
            Some(pk) => self.device_owner.get(device_key).map(String::as_str) == Some(pk.as_str()),
            None => false,
        }
    }

    /// The epoch of our own account's roster we last published/observed.
    pub fn self_roster_seq(&self) -> Option<u64> {
        self.self_roster_seq
    }

    pub fn set_self_roster_seq(&mut self, seq: u64) {
        self.self_roster_seq = Some(seq);
    }

    /// The primary transfer this (old primary) device offered and is waiting out.
    pub fn pending_demotion(&self) -> Option<&PendingDemotion> {
        self.pending_demotion.as_ref()
    }

    pub fn set_pending_demotion(&mut self, new_device_id: &str, target_device_id: &str) {
        self.pending_demotion = Some(PendingDemotion {
            new_device_id: new_device_id.to_string(),
            target_device_id: target_device_id.to_string(),
        });
    }

    pub fn clear_pending_demotion(&mut self) {
        self.pending_demotion = None;
    }

    /// The primary-transfer offer this (linked) device holds, if any.
    pub fn pending_promotion(&self) -> Option<&PendingPromotion> {
        self.pending_promotion.as_ref()
    }

    pub fn set_pending_promotion(&mut self, entry: KtEntry, demoted: DeviceRecord) {
        self.pending_promotion = Some(PendingPromotion { entry, demoted });
    }

    pub fn clear_pending_promotion(&mut self) {
        self.pending_promotion = None;
    }

    /// What this device last published on its call-control shelf, if anything.
    pub fn call_key_published(&self) -> Option<&CallKeyPublication> {
        self.call_key_published.as_ref()
    }

    /// Record a successful call-key publication.
    pub fn set_call_key_published(&mut self, public_key: &str, created_at: u64, device_id: &str) {
        self.call_key_published = Some(CallKeyPublication {
            public_key: public_key.to_string(),
            created_at,
            device_id: device_id.to_string(),
        });
    }

    /// Forget the published call key (local wipe, revocation, or a fresh identity).
    pub fn clear_call_key_published(&mut self) {
        self.call_key_published = None;
    }

    /// Whether the relay has told this device it was revoked from the account roster.
    pub fn revoked(&self) -> bool {
        self.revoked
    }

    /// Mark this device revoked (set) or cleared after a successful relink (unset).
    pub fn set_revoked(&mut self, revoked: bool) {
        self.revoked = revoked;
    }

    /// Queue sealed envelopes for durable delivery at/after `due_at` (unix seconds).
    /// The caller persists; the drain loop posts them and [`Self::outbox_ack`]s each
    /// accepted one. Oldest entries drop first past the cap.
    pub fn outbox_push(&mut self, envelopes: Vec<protocol_types::Envelope>, due_at: u64) {
        self.outbox.extend(
            envelopes
                .into_iter()
                .map(|envelope| OutboxItem { envelope, due_at }),
        );
        if self.outbox.len() > MAX_OUTBOX {
            let excess = self.outbox.len() - MAX_OUTBOX;
            self.outbox.drain(..excess);
        }
    }

    /// Every queued envelope that is due at `now`, oldest first.
    pub fn outbox_due(&self, now: u64) -> Vec<protocol_types::Envelope> {
        self.outbox
            .iter()
            .filter(|i| i.due_at <= now)
            .map(|i| i.envelope.clone())
            .collect()
    }

    /// Drop a posted envelope from the outbox (matched by recipient + message id).
    pub fn outbox_ack(&mut self, env: &protocol_types::Envelope) {
        self.outbox
            .retain(|i| !(i.envelope.msg_id == env.msg_id && i.envelope.to == env.to));
    }

    /// Whether anything is waiting in the outbox (due or not).
    pub fn outbox_is_empty(&self) -> bool {
        self.outbox.is_empty()
    }

    /// Durably queue urgent call-control envelopes before their first post. Only
    /// short-lived `CallControl` traffic is admitted; duplicate recipient/message pairs
    /// are idempotent.
    pub fn call_outbox_push(
        &mut self,
        envelopes: &[protocol_types::Envelope],
        now: u64,
    ) -> Vec<bool> {
        for envelope in envelopes {
            if !matches!(envelope.wake, protocol_types::WakeClass::CallControl)
                || envelope
                    .expires_at
                    .is_none_or(|expires_at| expires_at <= now)
                || self.call_outbox.iter().any(|item| {
                    item.envelope.msg_id == envelope.msg_id && item.envelope.to == envelope.to
                })
            {
                continue;
            }
            self.call_outbox.push(CallOutboxItem {
                envelope: envelope.clone(),
                due_at: now,
                attempts: 0,
            });
        }
        if self.call_outbox.len() > MAX_CALL_OUTBOX {
            let excess = self.call_outbox.len() - MAX_CALL_OUTBOX;
            self.call_outbox.drain(..excess);
        }
        envelopes
            .iter()
            .map(|envelope| {
                self.call_outbox.iter().any(|item| {
                    item.envelope.msg_id == envelope.msg_id && item.envelope.to == envelope.to
                })
            })
            .collect()
    }

    /// Remove locally expired controls; the relay would reject them too, but retaining
    /// ciphertext after its useful lifetime only wastes encrypted-vault space.
    pub fn call_outbox_reap(&mut self, now: u64) -> usize {
        let before = self.call_outbox.len();
        self.call_outbox
            .retain(|item| item.envelope.expires_at.is_some_and(|expiry| expiry > now));
        before - self.call_outbox.len()
    }

    /// Every call control whose bounded retry deadline has arrived.
    pub fn call_outbox_due(&self, now: u64) -> Vec<protocol_types::Envelope> {
        self.call_outbox
            .iter()
            .filter(|item| {
                item.due_at <= now && item.envelope.expires_at.is_some_and(|expiry| expiry > now)
            })
            .map(|item| item.envelope.clone())
            .collect()
    }

    /// Apply one batch's relay results. Accepted entries disappear; failures back off
    /// 1/2/4/8/16 seconds and disappear after the sixth total attempt or envelope expiry.
    pub fn call_outbox_settle(&mut self, attempted: &[(protocol_types::Envelope, bool)], now: u64) {
        for (envelope, accepted) in attempted {
            let Some(index) = self.call_outbox.iter().position(|item| {
                item.envelope.msg_id == envelope.msg_id && item.envelope.to == envelope.to
            }) else {
                continue;
            };
            if *accepted {
                self.call_outbox.remove(index);
                continue;
            }
            let item = &mut self.call_outbox[index];
            item.attempts = item.attempts.saturating_add(1);
            if item.attempts >= MAX_CALL_OUTBOX_ATTEMPTS
                || item.envelope.expires_at.is_none_or(|expiry| expiry <= now)
            {
                self.call_outbox.remove(index);
                continue;
            }
            let shift = item.attempts.saturating_sub(1).min(4);
            item.due_at = now.saturating_add(1u64 << shift);
        }
        self.call_outbox_reap(now);
    }

    /// Earliest pending retry, excluding already-expired entries.
    pub fn call_outbox_next_due(&self, now: u64) -> Option<u64> {
        self.call_outbox
            .iter()
            .filter(|item| item.envelope.expires_at.is_some_and(|expiry| expiry > now))
            .map(|item| item.due_at)
            .min()
    }

    pub fn call_outbox_is_empty(&self) -> bool {
        self.call_outbox.is_empty()
    }

    /// The pinned roster for a contact (`None` = single-device / never fetched).
    pub fn pinned_roster(&self, username: &str) -> Option<&RosterPin> {
        self.contact_rosters.get(username)
    }

    /// Drop a contact's pinned roster. Only for a verified ownership change (the KT
    /// binding advanced to a new key with no roster yet) — never on relay say-so.
    pub fn clear_pinned_roster(&mut self, username: &str) {
        if let Some(pin) = self.contact_rosters.remove(username) {
            for d in &pin.devices {
                self.device_owner.remove(&d.identity_key);
            }
        }
    }

    /// Pin (or advance) a contact's verified roster. **Anti-rollback**, two chains:
    /// * within one account key, a roster `seq` lower than the pinned one is refused — a
    ///   relay replaying an older epoch (e.g. to resurrect a revoked device) is caught
    ///   here and the caller must fail closed;
    /// * a primary-key change (account-key rotation, or a released name taken over by a
    ///   new owner whose roster chain legitimately restarts at epoch 0) is accepted only
    ///   with a **strictly higher `binding_seq`** — the relay cannot roll the combined
    ///   view back to a previous key era, because that era's binding sits lower on the
    ///   (KT-verified) chain.
    ///
    /// Also refreshes the device→account attribution map.
    pub fn pin_roster(
        &mut self,
        username: &str,
        binding_seq: u64,
        seq: u64,
        primary_key: &str,
        devices: Vec<RosterDevice>,
    ) -> Result<(), RosterRollback> {
        if let Some(existing) = self.contact_rosters.get(username) {
            let rolled_back = if existing.primary_key == primary_key {
                binding_seq < existing.binding_seq || seq < existing.seq
            } else {
                binding_seq <= existing.binding_seq
            };
            if rolled_back {
                return Err(RosterRollback {
                    username: username.to_string(),
                    pinned_seq: existing.seq,
                    served_seq: seq,
                });
            }
            // Drop attribution for devices that left the previous roster.
            for old in &existing.devices {
                if !devices.iter().any(|d| d.identity_key == old.identity_key) {
                    self.device_owner.remove(&old.identity_key);
                }
            }
        }
        for d in &devices {
            self.device_owner
                .insert(d.identity_key.clone(), primary_key.to_string());
        }
        self.contact_rosters.insert(
            username.to_string(),
            RosterPin {
                seq,
                binding_seq,
                primary_key: primary_key.to_string(),
                devices,
            },
        );
        Ok(())
    }

    /// The account primary identity key a device identity key belongs to, if known from a
    /// verified roster. `None` = attribute the device to itself (single-device / unknown).
    pub fn device_owner(&self, device_key: &str) -> Option<&str> {
        self.device_owner.get(device_key).map(String::as_str)
    }

    /// A silent drop that a KT roster refresh could repair: `sender_key` is completely
    /// unattributed (no roster maps it, no contact pins it) while `claimed` is a pinned
    /// contact or known group member — they may have linked a device we have not resolved
    /// yet, or rotated their key. Without a refresh,
    /// [`screen_inbound`](Self::screen_inbound)'s spoof rule drops the content.
    /// Returns the username whose roster should be re-resolved.
    pub fn device_resolution_candidate(&self, sender_key: &str, claimed: &str) -> Option<String> {
        if claimed.is_empty()
            || self.device_owner.contains_key(sender_key)
            || self.contacts.values().any(|p| p.identity_key == sender_key)
        {
            return None;
        }
        let known_account = self.contacts.contains_key(claimed)
            || self.groups.values().any(|group| {
                !group.left
                    && group
                        .members
                        .iter()
                        .any(|member| member.username == claimed)
            });
        known_account.then(|| claimed.to_string())
    }

    /// Resolve a sending device key to the conversation key to file it under: the owning
    /// account's primary key when known, else the device key itself (unchanged legacy
    /// behavior).
    pub fn attribute_device(&self, device_key: &str) -> String {
        self.device_owner
            .get(device_key)
            .cloned()
            .unwrap_or_else(|| device_key.to_string())
    }

    /// Encrypt the whole history under the account's `data_key` (see [`crypto_core::localbox`]).
    pub fn seal(&self, data_key: &[u8; 32]) -> Vec<u8> {
        let plain = serde_json::to_vec(self).expect("History serializes");
        crypto_core::localbox::seal(data_key, &plain)
    }

    /// Decrypt history sealed by [`seal`](Self::seal). Returns an empty history if the
    /// blob is absent/corrupt so the UI never breaks (fail-soft on load).
    pub fn open(data_key: &[u8; 32], blob: &[u8]) -> Self {
        crypto_core::localbox::open(data_key, blob)
            .and_then(|plain| serde_json::from_slice(&plain).ok())
            .unwrap_or_default()
    }

    /// Serialize history to plaintext JSON for **cross-device** transfer. Device-local
    /// state (this device's identity, contact rosters, device-owner map) is *stripped*:
    /// the receiving device holds its own identity and re-fetches rosters from KT itself.
    /// The caller seals this with [`crypto_core::sync::seal_history`] (password/PIN + link
    /// secret) before it ever leaves the device.
    pub fn export_plaintext(&self) -> Vec<u8> {
        let mut shared = self.clone();
        shared.self_device = None;
        shared.self_roster_seq = None;
        shared.self_primary_key = None;
        shared.contact_rosters.clear();
        shared.device_owner.clear();
        // Device-local transfer state must never travel to another device.
        shared.pending_demotion = None;
        shared.pending_promotion = None;
        serde_json::to_vec(&shared).expect("History serializes")
    }

    /// Import a history exported by [`export_plaintext`] and decrypted on the new device.
    /// `None` if the plaintext is malformed.
    pub fn import_plaintext(plaintext: &[u8]) -> Option<Self> {
        serde_json::from_slice(plaintext).ok()
    }

    /// Merge another history (e.g. imported from a linked device) into this one without
    /// losing local device state. Conversations, contacts, and groups are unioned;
    /// messages dedup by id. Used when a device already had some local history before
    /// linking, or on a re-sync.
    pub fn merge_from(&mut self, other: &History) {
        for (peer, convo) in &other.conversations {
            let dst = self.conversations.entry(peer.clone()).or_default();
            if dst.disappearing_secs.is_none() {
                dst.disappearing_secs = convo.disappearing_secs;
            }
            for m in &convo.messages {
                if !dst.messages.iter().any(|x| x.msg_id == m.msg_id) {
                    dst.messages.push(m.clone());
                }
            }
            dst.messages.sort_by_key(|m| m.sent_at);
        }
        for (u, pin) in &other.contacts {
            self.contacts
                .entry(u.clone())
                .or_insert_with(|| pin.clone());
        }
        for (id, g) in &other.groups {
            self.groups.entry(id.clone()).or_insert_with(|| g.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_control_envelope(msg_id: &str, expires_at: u64) -> protocol_types::Envelope {
        protocol_types::Envelope {
            to: protocol_types::IdentityHash::from_identifier("call-outbox-target"),
            ciphertext: "sealed".into(),
            kind: protocol_types::PayloadKind::Message,
            msg_id: msg_id.into(),
            expires_at: Some(expires_at),
            wake: protocol_types::WakeClass::CallControl,
            raw_identifier: None,
        }
    }

    #[test]
    fn call_outbox_is_ttl_attempt_and_capacity_bounded() {
        let mut history = History::new();
        let envelope = call_control_envelope("control", 200);
        assert_eq!(
            history.call_outbox_push(std::slice::from_ref(&envelope), 100),
            vec![true]
        );
        assert_eq!(
            history.call_outbox_push(std::slice::from_ref(&envelope), 100),
            vec![true]
        );
        assert_eq!(history.call_outbox_due(100).len(), 1);
        let restored = History::open(&[9u8; 32], &history.seal(&[9u8; 32]));
        assert_eq!(
            restored.call_outbox_due(100).len(),
            1,
            "pending controls survive process restart"
        );

        let mut normal = envelope.clone();
        normal.msg_id = "not-a-control".into();
        normal.wake = protocol_types::WakeClass::Normal;
        assert_eq!(history.call_outbox_push(&[normal], 100), vec![false]);
        assert_eq!(history.call_outbox_due(100).len(), 1);

        let expected_due = [101, 103, 107, 115, 131];
        let mut attempt_at = 100;
        for next_due in expected_due {
            history.call_outbox_settle(&[(envelope.clone(), false)], attempt_at);
            assert!(history.call_outbox_due(next_due - 1).is_empty());
            assert_eq!(history.call_outbox_next_due(next_due - 1), Some(next_due));
            attempt_at = next_due;
        }
        history.call_outbox_settle(&[(envelope.clone(), false)], attempt_at);
        assert!(history.call_outbox_is_empty());

        let mut accepted = History::new();
        let _ = accepted.call_outbox_push(std::slice::from_ref(&envelope), 100);
        accepted.call_outbox_settle(&[(envelope.clone(), true)], 100);
        assert!(accepted.call_outbox_is_empty());

        let mut expired = History::new();
        let _ = expired.call_outbox_push(&[call_control_envelope("expired", 101)], 100);
        assert_eq!(expired.call_outbox_reap(101), 1);
        assert!(expired.call_outbox_is_empty());

        let many: Vec<_> = (0..MAX_CALL_OUTBOX + 7)
            .map(|index| call_control_envelope(&format!("control-{index}"), 200))
            .collect();
        let mut bounded = History::new();
        let admitted = bounded.call_outbox_push(&many, 100);
        assert!(admitted[..7].iter().all(|admitted| !admitted));
        assert!(admitted[7..].iter().all(|admitted| *admitted));
        assert_eq!(bounded.call_outbox_due(100).len(), MAX_CALL_OUTBOX);
        assert_eq!(
            bounded.call_outbox_due(100)[0].msg_id,
            "control-7",
            "oldest entries drop first"
        );
    }

    // Build an admin-model group "g1" with the given members (the FIRST member is the
    // admin, with a fresh signing key). Every group is admin-model now; the egalitarian-op
    // tests below don't depend on the admin key, only on the roster/membership.
    fn group_with(members: &[(&str, &str)]) -> History {
        let mut h = History::new();
        let (admin_sk, admin_key) = epoch_keypair();
        let admin_idk = members[0].1.to_string();
        let eps: Vec<kt_log::GroupMemberEntry> = members
            .iter()
            .map(|(u, k)| kt_log::GroupMemberEntry {
                username: u.to_string(),
                identity_key: k.to_string(),
            })
            .collect();
        let g0 = GroupEpoch::genesis("g1".into(), eps, admin_key, admin_idk, 1000, |p| {
            epsig(&admin_sk, p)
        });
        assert_eq!(h.adopt_group_epoch(&g0), GroupEpochOutcome::Created);
        h.set_group_name("g1", "escape committee");
        h
    }

    #[test]
    fn group_edit_and_delete_enforce_stored_sender() {
        let mut h = group_with(&[("alice", "alicekey"), ("bob", "bobkey")]);
        h.record_group_message("g1", "alicekey", "m1", "original", 100, None, None);
        // Bob tries to edit Alice's message — refused (sender mismatch).
        h.apply(&InboundEvent::GroupMessageEdited {
            sender_identity_key: "bobkey".into(),
            group_id: "g1".into(),
            msg_id: "m1".into(),
            body: "forged".into(),
        });
        assert_eq!(h.group_message("g1", "m1").unwrap().body, "original");
        // Alice edits her own — applied and flagged.
        h.apply(&InboundEvent::GroupMessageEdited {
            sender_identity_key: "alicekey".into(),
            group_id: "g1".into(),
            msg_id: "m1".into(),
            body: "fixed".into(),
        });
        let m = h.group_message("g1", "m1").unwrap();
        assert_eq!(m.body, "fixed");
        assert!(m.edited);
        // Bob tries to delete Alice's message — refused; Alice's own delete lands.
        h.apply(&InboundEvent::GroupMessageDeleted {
            sender_identity_key: "bobkey".into(),
            group_id: "g1".into(),
            msg_id: "m1".into(),
        });
        assert!(h.group_message("g1", "m1").is_some());
        h.apply(&InboundEvent::GroupMessageDeleted {
            sender_identity_key: "alicekey".into(),
            group_id: "g1".into(),
            msg_id: "m1".into(),
        });
        assert!(h.group_message("g1", "m1").is_none());
    }

    #[test]
    fn group_rename_only_from_members_and_chips() {
        let mut h = group_with(&[("alice", "alicekey"), ("bob", "bobkey")]);
        // A non-member's rename is refused.
        h.apply(&InboundEvent::GroupRenamed {
            sender_identity_key: "mallorykey".into(),
            group_id: "g1".into(),
            name: "pwned".into(),
        });
        assert_eq!(h.group("g1").unwrap().name, "escape committee");
        // A member's rename applies and drops a system chip.
        h.apply(&InboundEvent::GroupRenamed {
            sender_identity_key: "alicekey".into(),
            group_id: "g1".into(),
            name: "tunnel crew".into(),
        });
        let g = h.group("g1").unwrap();
        assert_eq!(g.name, "tunnel crew");
        assert!(g
            .messages
            .iter()
            .any(|m| m.system && m.body.contains("renamed")));
    }

    #[test]
    fn group_leave_drops_sender_and_nonmember_leave_is_refused() {
        let mut h = group_with(&[("alice", "alicekey"), ("bob", "bobkey"), ("me", "mykey")]);
        h.set_self_primary_key("mykey");
        // Bob leaves: dropped from the roster, chip recorded.
        h.apply(&InboundEvent::GroupMemberLeft {
            sender_identity_key: "bobkey".into(),
            group_id: "g1".into(),
        });
        let g = h.group("g1").unwrap();
        assert!(!g.members.iter().any(|m| m.identity_key == "bobkey"));
        assert!(g
            .messages
            .iter()
            .any(|m| m.system && m.body.contains("left")));
        // A non-member's "leave" is refused (no roster change, no chip spam).
        let before = h.group("g1").unwrap().messages.len();
        h.apply(&InboundEvent::GroupMemberLeft {
            sender_identity_key: "mallorykey".into(),
            group_id: "g1".into(),
        });
        assert_eq!(h.group("g1").unwrap().members.len(), 2);
        assert_eq!(h.group("g1").unwrap().messages.len(), before);
    }

    // A unilateral self-leave synced from our own other device stays sticky: a later admin
    // epoch that still lists us (the admin hasn't processed our leave yet) must NOT silently
    // rejoin us — only an actual kick-then-re-add transition clears `left`.
    #[test]
    fn self_leave_is_not_undone_by_a_later_epoch_still_listing_us() {
        let (admin_sk, admin_key) = epoch_keypair();
        let mut h = History::new();
        h.set_self_primary_key("me-idk");
        h.pin_contact("admin", "admin-idk", false);
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("me", "me-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g0,
            name: "trip".into(),
            disappearing_secs: Some(0),
            avatar: None,
        });
        // Our other device left the group → left, thread kept.
        h.apply(&InboundEvent::GroupMemberLeft {
            sender_identity_key: "me-idk".into(),
            group_id: "g1".into(),
        });
        assert!(h.group("g1").unwrap().left);
        // Admin adds carol at seq 1, roster still listing us — we stay left.
        let g1 = GroupEpoch::next(
            1,
            "g1".into(),
            vec![
                epm("admin", "admin-idk"),
                epm("me", "me-idk"),
                epm("carol", "carol-idk"),
            ],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g1,
            name: String::new(),
            disappearing_secs: None,
            avatar: None,
        });
        assert!(h.group("g1").unwrap().left);
    }

    #[test]
    fn pins_apply_with_the_right_trust_gates() {
        // 1:1: either side may pin (shared metadata) — once the contact is accepted.
        let mut h = History::new();
        h.pin_contact("alice", "alicekey", false);
        h.record("alicekey", Direction::Incoming, "m1", "important", 100);
        h.apply(&InboundEvent::MessagePinned {
            sender_identity_key: "alicekey".into(),
            msg_id: "m1".into(),
            pin: true,
        });
        assert!(h.message("alicekey", "m1").unwrap().pinned);
        // Self-sync pin: honored only from a verified own device.
        let mut h2 = History::new();
        h2.record("peerkey", Direction::Outgoing, "m1", "mine", 100);
        h2.apply(&InboundEvent::SelfMessagePinned {
            sender_identity_key: "strangerkey".into(),
            peer_key: "peerkey".into(),
            msg_id: "m1".into(),
            pin: true,
        });
        assert!(!h2.message("peerkey", "m1").unwrap().pinned);
        // Group: a non-member's pin is refused, a member's lands.
        let mut h3 = group_with(&[("alice", "alicekey"), ("bob", "bobkey")]);
        h3.record_group_message("g1", "bobkey", "gm1", "hello", 100, None, None);
        h3.apply(&InboundEvent::GroupMessagePinned {
            sender_identity_key: "mallorykey".into(),
            group_id: "g1".into(),
            msg_id: "gm1".into(),
            pin: true,
        });
        assert!(!h3.group_message("g1", "gm1").unwrap().pinned);
        h3.apply(&InboundEvent::GroupMessagePinned {
            sender_identity_key: "alicekey".into(),
            group_id: "g1".into(),
            msg_id: "gm1".into(),
            pin: true,
        });
        assert!(h3.group_message("g1", "gm1").unwrap().pinned);
    }

    // Membership changes flow ONLY through admin-signed epochs delivered as a
    // GroupRosterUpdate: a forged (non-admin) epoch is refused at the apply() boundary, a
    // valid admin epoch advances the roster. (Replaces the old egalitarian finding-0 test —
    // there is no longer any unsigned invite path to gate.)
    #[test]
    fn group_roster_update_gated_on_admin_signature() {
        let (admin_sk, admin_key) = epoch_keypair();
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![epm("alice", "alicekey"), epm("bob", "bobkey")],
            admin_key.clone(),
            "alicekey".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        let mut h = History::new();
        h.pin_contact("alice", "alicekey", false); // known sender ⇒ not request-withheld
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "alicekey".into(),
            epoch: g0,
            name: "escape committee".into(),
            disappearing_secs: Some(0),
            avatar: None,
        });
        assert_eq!(h.group("g1").unwrap().members.len(), 2);
        // (a) A non-admin (mallory) forges an "add mallory" epoch, signing with her own key.
        let (mallory_sk, _mk) = epoch_keypair();
        let forged = GroupEpoch::next(
            1,
            "g1".into(),
            vec![
                epm("alice", "alicekey"),
                epm("bob", "bobkey"),
                epm("mallory", "mallorykey"),
            ],
            admin_key.clone(),
            "alicekey".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&mallory_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "mallorykey".into(),
            epoch: forged,
            name: "pwned".into(),
            disappearing_secs: None,
            avatar: None,
        });
        assert!(!h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "mallorykey"));
        assert_eq!(h.group_admin("g1").unwrap().epoch_seq, 0);
        // (b) The admin's valid epoch advances the roster (adds carol).
        let valid = GroupEpoch::next(
            1,
            "g1".into(),
            vec![
                epm("alice", "alicekey"),
                epm("bob", "bobkey"),
                epm("carol", "carolkey"),
            ],
            admin_key.clone(),
            "alicekey".into(),
            admin_key.clone(),
            1002,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "alicekey".into(),
            epoch: valid,
            name: String::new(),
            disappearing_secs: None,
            avatar: None,
        });
        assert!(h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "carolkey"));
        assert_eq!(h.group_admin("g1").unwrap().epoch_seq, 1);
    }

    // Finding 1: a non-member cannot change a group's disappearing timer (force
    // near-immediate reap = data loss, or disable expiry). Finding 2: same gate for the
    // group picture. Members (and our own devices) still apply.
    #[test]
    fn group_timer_and_avatar_updates_gated_on_membership() {
        let png = "data:image/png;base64,iVBORw0KGgo=";
        let mut h = group_with(&[("alice", "alicekey")]);
        assert!(h.set_group_timer("g1", Some(60)));
        // (c) Non-member timer change refused — timer unchanged.
        h.apply(&InboundEvent::GroupTimerUpdate {
            sender_identity_key: "mallorykey".into(),
            group_id: "g1".into(),
            disappearing_secs: Some(1),
        });
        assert_eq!(h.group_timer("g1"), Some(60));
        // (c) A current member's timer change applies.
        h.apply(&InboundEvent::GroupTimerUpdate {
            sender_identity_key: "alicekey".into(),
            group_id: "g1".into(),
            disappearing_secs: Some(300),
        });
        assert_eq!(h.group_timer("g1"), Some(300));
        // Our own other device (self) is authorized even when not in the roster list.
        h.set_self_primary_key("mykey");
        h.apply(&InboundEvent::GroupTimerUpdate {
            sender_identity_key: "mykey".into(),
            group_id: "g1".into(),
            disappearing_secs: None,
        });
        assert_eq!(h.group_timer("g1"), None);
        // (d) Non-member avatar change refused, member's applies.
        h.apply(&InboundEvent::GroupAvatarUpdate {
            sender_identity_key: "mallorykey".into(),
            group_id: "g1".into(),
            avatar: Some(png.into()),
        });
        assert_eq!(h.group_avatar("g1"), None);
        h.apply(&InboundEvent::GroupAvatarUpdate {
            sender_identity_key: "alicekey".into(),
            group_id: "g1".into(),
            avatar: Some(png.into()),
        });
        assert_eq!(h.group_avatar("g1"), Some(png.to_string()));
    }

    // Minor: a peer-supplied timer near u64::MAX must saturate, not wrap (release) /
    // panic (debug) — a wrapped deadline reaps the message almost immediately.
    #[test]
    fn disappear_at_saturates_on_huge_timer() {
        let mut h = group_with(&[("bob", "bobkey")]);
        assert!(h.set_group_timer("g1", Some(u64::MAX)));
        // Pre-fix this overflows `base + d`; post-fix it saturates.
        h.record_group_message("g1", "bobkey", "m1", "hi", 1000, None, None);
        let del = h.group("g1").unwrap().messages[0].delete_at.unwrap();
        assert_eq!(del, u64::MAX);
        assert!(del >= 1000);
    }

    // ── Cryptographic admin-authorized group membership (signed epoch chain) ──────────

    use ed25519_dalek::{Signer, SigningKey};

    fn epoch_keypair() -> (SigningKey, String) {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        (
            sk.clone(),
            STANDARD_NO_PAD.encode(sk.verifying_key().as_bytes()),
        )
    }
    fn epm(name: &str, idk: &str) -> kt_log::GroupMemberEntry {
        kt_log::GroupMemberEntry {
            username: name.into(),
            identity_key: idk.into(),
        }
    }
    fn epsig(sk: &SigningKey, p: &[u8]) -> String {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        STANDARD_NO_PAD.encode(sk.sign(p).to_bytes())
    }

    // Genesis creates an admin-model group and pins the creator as admin; the admin's later
    // epoch advances the roster. `is_group_admin` reflects the pinned admin.
    #[test]
    fn group_epoch_creates_and_advances_membership() {
        let (admin_sk, admin_key) = epoch_keypair();
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("bob", "bob-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        let mut h = History::new();
        assert_eq!(h.adopt_group_epoch(&g0), GroupEpochOutcome::Created);
        assert_eq!(h.group("g1").unwrap().members.len(), 2);
        assert_eq!(h.group_admin("g1").unwrap().admin_key, admin_key);
        assert_eq!(
            h.group_admin("g1").unwrap().creator_admin_key.as_deref(),
            Some(admin_key.as_str())
        );
        assert!(h.is_group_admin("admin-idk", "g1"));
        assert!(!h.is_group_admin("bob-idk", "g1"));

        let g1 = GroupEpoch::next(
            1,
            "g1".into(),
            vec![
                epm("admin", "admin-idk"),
                epm("bob", "bob-idk"),
                epm("carol", "carol-idk"),
            ],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&admin_sk, p),
        );
        assert_eq!(h.adopt_group_epoch(&g1), GroupEpochOutcome::Advanced);
        assert_eq!(h.group_admin("g1").unwrap().epoch_seq, 1);
        assert!(h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "carol-idk"));
    }

    // A non-admin member cannot add/remove: a seq-1 epoch signed by anyone but the pinned
    // admin fails verification and the roster is untouched.
    #[test]
    fn non_admin_group_epoch_is_refused() {
        let (admin_sk, admin_key) = epoch_keypair();
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("bob", "bob-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        let mut h = History::new();
        h.adopt_group_epoch(&g0);
        // Mallory forges an "add mallory" epoch, claiming to chain from the real admin but
        // signing with her own key.
        let (mallory_sk, _mk) = epoch_keypair();
        let forged = GroupEpoch::next(
            1,
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("mallory", "mallory-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&mallory_sk, p),
        );
        assert_eq!(
            h.adopt_group_epoch(&forged),
            GroupEpochOutcome::Refused(GroupEpochError::BadSignature)
        );
        assert_eq!(h.group_admin("g1").unwrap().epoch_seq, 0);
        assert!(!h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "mallory-idk"));
    }

    // A relay replaying an OLD epoch (or the current one) to resurrect a kicked member is
    // caught by the monotonic seq pin.
    #[test]
    fn group_epoch_rollback_and_replay_refused() {
        let (admin_sk, admin_key) = epoch_keypair();
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("bob", "bob-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        let mut h = History::new();
        h.adopt_group_epoch(&g0);
        // seq 1 kicks bob.
        let g1 = GroupEpoch::next(
            1,
            "g1".into(),
            vec![epm("admin", "admin-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&admin_sk, p),
        );
        assert_eq!(h.adopt_group_epoch(&g1), GroupEpochOutcome::Advanced);
        assert!(!h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "bob-idk"));
        // Replay the genesis to bring bob back — refused (rollback), bob stays out.
        assert!(matches!(
            h.adopt_group_epoch(&g0),
            GroupEpochOutcome::Refused(GroupEpochError::Rollback { .. })
        ));
        assert!(!h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "bob-idk"));
        // Replaying the CURRENT epoch (equal seq) is likewise refused.
        assert!(matches!(
            h.adopt_group_epoch(&g1),
            GroupEpochOutcome::Refused(GroupEpochError::Rollback { .. })
        ));
    }

    // Admin transfer: the outgoing admin hands the role to a member; afterwards only the new
    // admin can advance the chain and the old admin's signature no longer carries authority.
    #[test]
    fn group_admin_transfer_moves_authority() {
        let (old_sk, old_key) = epoch_keypair();
        let (new_sk, new_key) = epoch_keypair();
        let members = vec![epm("old", "old-idk"), epm("bob", "bob-idk")];
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            members.clone(),
            old_key.clone(),
            "old-idk".into(),
            1000,
            |p| epsig(&old_sk, p),
        );
        let mut h = History::new();
        h.adopt_group_epoch(&g0);
        // Transfer to bob, signed by the OLD admin.
        let transfer = GroupEpoch::next(
            1,
            "g1".into(),
            members.clone(),
            new_key.clone(),
            "bob-idk".into(),
            old_key.clone(),
            1001,
            |p| epsig(&old_sk, p),
        );
        assert_eq!(h.adopt_group_epoch(&transfer), GroupEpochOutcome::Advanced);
        assert_eq!(h.group_admin("g1").unwrap().admin_key, new_key);
        assert_eq!(h.group_admin("g1").unwrap().admin_identity_key, "bob-idk");

        let carol_members = vec![
            epm("old", "old-idk"),
            epm("bob", "bob-idk"),
            epm("carol", "carol-idk"),
        ];
        // Old admin tries to keep changing membership → refused (lost authority).
        let old_try = GroupEpoch::next(
            2,
            "g1".into(),
            carol_members.clone(),
            new_key.clone(),
            "bob-idk".into(),
            new_key.clone(),
            1002,
            |p| epsig(&old_sk, p),
        );
        assert_eq!(
            h.adopt_group_epoch(&old_try),
            GroupEpochOutcome::Refused(GroupEpochError::BadSignature)
        );
        // The NEW admin can.
        let new_try = GroupEpoch::next(
            2,
            "g1".into(),
            carol_members,
            new_key.clone(),
            "bob-idk".into(),
            new_key.clone(),
            1003,
            |p| epsig(&new_sk, p),
        );
        assert_eq!(h.adopt_group_epoch(&new_try), GroupEpochOutcome::Advanced);
        assert!(h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "carol-idk"));
    }

    // The apply() path: a GroupRoster epoch creates a group (adopting its meta), and a later
    // admin kick of us marks the group left with a chip.
    #[test]
    fn group_roster_update_apply_creates_and_kicks_self() {
        let (admin_sk, admin_key) = epoch_keypair();
        let mut h = History::new();
        h.set_self_primary_key("me-idk");
        h.pin_contact("admin", "admin-idk", false); // known sender ⇒ not request-withheld
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("me", "me-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g0,
            name: "trip".into(),
            disappearing_secs: Some(0),
            avatar: None,
        });
        assert_eq!(h.group("g1").unwrap().name, "trip");
        assert!(h.group_admin("g1").is_some());
        assert!(h
            .group("g1")
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_key == "me-idk"));

        // The admin kicks us at seq 1 → the group is marked left with a chip.
        let g1 = GroupEpoch::next(
            1,
            "g1".into(),
            vec![epm("admin", "admin-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g1,
            name: "trip".into(),
            disappearing_secs: None,
            avatar: None,
        });
        assert!(h.group("g1").unwrap().left);
        assert!(h
            .group("g1")
            .unwrap()
            .messages
            .iter()
            .any(|m| m.system && m.body.contains("removed")));

        // The admin re-adds us later at seq 3 — a seq GAP (we were never fanned seq 2, being
        // out of the roster), bridged because the epoch chains from the same pinned admin.
        // The rejoin clears `left` (sends unblocked) and drops a chip.
        let g3 = GroupEpoch::next(
            3,
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("me", "me-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1003,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g3,
            name: "trip".into(),
            disappearing_secs: None,
            avatar: None,
        });
        let g = h.group("g1").unwrap();
        assert!(!g.left);
        assert!(g.members.iter().any(|m| m.identity_key == "me-idk"));
        assert!(g
            .messages
            .iter()
            .any(|m| m.system && m.body.contains("added back")));
        assert_eq!(h.group_admin("g1").unwrap().epoch_seq, 3);
    }

    // The content roster-gate + quarantine: a non-member's message/attachment/reaction
    // never renders, but the add-race (their epoch still in flight) replays losslessly
    // once the admin's epoch lands.
    #[test]
    fn nonmember_content_quarantined_then_replayed_when_epoch_adds_them() {
        let (admin_sk, admin_key) = epoch_keypair();
        let mut h = History::new();
        h.set_self_primary_key("me-idk");
        h.pin_contact("admin", "admin-idk", false);
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("me", "me-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g0,
            name: "trip".into(),
            disappearing_secs: Some(0),
            avatar: None,
        });
        // Carol (added by the admin, but her epoch hasn't reached us yet) says hi and
        // reacts to her own message — nothing renders yet.
        h.apply(&InboundEvent::GroupMessage {
            sender_identity_key: "carol-idk".into(),
            group_id: "g1".into(),
            msg_id: "c1".into(),
            body: "hi everyone".into(),
            sent_at: 2000,
            expire_secs: None,
            reply: None,
            forwarded: false,
        });
        h.apply(&InboundEvent::GroupReaction {
            sender_identity_key: "carol-idk".into(),
            group_id: "g1".into(),
            target_msg_id: "c1".into(),
            emoji: "👋".into(),
            add: true,
        });
        assert!(h.group_message("g1", "c1").is_none());
        // The admin's epoch adding carol arrives — the held content replays in order.
        let g1 = GroupEpoch::next(
            1,
            "g1".into(),
            vec![
                epm("admin", "admin-idk"),
                epm("me", "me-idk"),
                epm("carol", "carol-idk"),
            ],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g1,
            name: String::new(),
            disappearing_secs: None,
            avatar: None,
        });
        let m = h.group_message("g1", "c1").expect("replayed");
        assert_eq!(m.body, "hi everyone");
        assert_eq!(m.sent_at, 2000);
        assert_eq!(m.sender.as_deref(), Some("carol-idk"));
        assert_eq!(m.reactions.len(), 1);
    }

    #[test]
    fn kicked_member_content_stays_invisible_and_expires() {
        let (admin_sk, admin_key) = epoch_keypair();
        let mut h = History::new();
        h.set_self_primary_key("me-idk");
        h.pin_contact("admin", "admin-idk", false);
        let members = vec![
            epm("admin", "admin-idk"),
            epm("me", "me-idk"),
            epm("bob", "bob-idk"),
        ];
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            members.clone(),
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g0,
            name: "trip".into(),
            disappearing_secs: Some(0),
            avatar: None,
        });
        h.apply(&InboundEvent::GroupMessage {
            sender_identity_key: "bob-idk".into(),
            group_id: "g1".into(),
            msg_id: "b1".into(),
            body: "pre-kick".into(),
            sent_at: 2000,
            expire_secs: None,
            reply: None,
            forwarded: false,
        });
        assert!(h.group_message("g1", "b1").is_some());
        // Admin kicks bob at seq 1.
        let g1 = GroupEpoch::next(
            1,
            "g1".into(),
            vec![epm("admin", "admin-idk"), epm("me", "me-idk")],
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1001,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g1,
            name: String::new(),
            disappearing_secs: None,
            avatar: None,
        });
        // Bob still has the group_id + live sessions and spams — invisible; and his edit
        // of his own pre-kick message is quarantined too, not applied.
        h.apply(&InboundEvent::GroupMessage {
            sender_identity_key: "bob-idk".into(),
            group_id: "g1".into(),
            msg_id: "b2".into(),
            body: "let me back in".into(),
            sent_at: 3000,
            expire_secs: None,
            reply: None,
            forwarded: false,
        });
        h.apply(&InboundEvent::GroupMessageEdited {
            sender_identity_key: "bob-idk".into(),
            group_id: "g1".into(),
            msg_id: "b1".into(),
            body: "rewritten".into(),
        });
        assert!(h.group_message("g1", "b2").is_none());
        assert_eq!(h.group_message("g1", "b1").unwrap().body, "pre-kick");
        // The quarantine expires on the periodic sweep; a much-later re-add replays nothing.
        h.reap(unix_now() + HELD_GROUP_CONTENT_TTL_SECS + 5);
        let g2 = GroupEpoch::next(
            2,
            "g1".into(),
            members,
            admin_key.clone(),
            "admin-idk".into(),
            admin_key.clone(),
            1002,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g2,
            name: String::new(),
            disappearing_secs: None,
            avatar: None,
        });
        assert!(h.group_message("g1", "b2").is_none());
        assert_eq!(h.group_message("g1", "b1").unwrap().body, "pre-kick");
    }

    // The other side of the race: content for a group we don't know at all (the creating
    // epoch is still in flight) is held and replays when the epoch lands.
    #[test]
    fn unknown_group_content_replays_once_the_creating_epoch_lands() {
        let (admin_sk, admin_key) = epoch_keypair();
        let mut h = History::new();
        h.set_self_primary_key("me-idk");
        h.pin_contact("admin", "admin-idk", false);
        h.pin_contact("carol", "carol-idk", false);
        h.apply(&InboundEvent::GroupMessage {
            sender_identity_key: "carol-idk".into(),
            group_id: "g1".into(),
            msg_id: "c1".into(),
            body: "first!".into(),
            sent_at: 2000,
            expire_secs: None,
            reply: None,
            forwarded: false,
        });
        assert!(h.group("g1").is_none());
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![
                epm("admin", "admin-idk"),
                epm("me", "me-idk"),
                epm("carol", "carol-idk"),
            ],
            admin_key.clone(),
            "admin-idk".into(),
            1000,
            |p| epsig(&admin_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "admin-idk".into(),
            epoch: g0,
            name: "trip".into(),
            disappearing_secs: Some(0),
            avatar: None,
        });
        assert_eq!(h.group_message("g1", "c1").unwrap().body, "first!");
    }

    #[test]
    fn quarantine_is_bounded_per_group() {
        let mut h = group_with(&[("alice", "alicekey")]);
        for i in 0..(MAX_HELD_GROUP_EVENTS + 8) {
            h.apply(&InboundEvent::GroupMessage {
                sender_identity_key: "spammer".into(),
                group_id: "g1".into(),
                msg_id: format!("s{i}"),
                body: "spam".into(),
                sent_at: 1000 + i as u64,
                expire_secs: None,
                reply: None,
                forwarded: false,
            });
        }
        let held = h.held_group_content.get("g1").expect("held");
        assert_eq!(held.len(), MAX_HELD_GROUP_EVENTS);
        // Oldest evicted first.
        assert!(matches!(
            &held[0].content,
            HeldGroupContent::Message { msg_id, .. } if msg_id == "s8"
        ));
    }

    #[test]
    fn forwarded_flag_lands_from_the_wire() {
        let mut h = History::new();
        h.pin_contact("alice", "alicekey", false);
        h.apply(&InboundEvent::Message {
            sender_identity_key: "alicekey".into(),
            sender_username: "alice".into(),
            msg_id: "m1".into(),
            body: "passed along".into(),
            sent_at: 100,
            reply: None,
            expire_secs: None,
            forwarded: true,
        });
        assert!(h.message("alicekey", "m1").unwrap().forwarded);
    }

    #[test]
    fn group_local_prefs_flip_and_interact() {
        let mut h = group_with(&[("alice", "alicekey")]);
        assert!(h.set_group_pinned("g1", true));
        assert!(h.group("g1").unwrap().pinned);
        // Manual unread un-archives; archiving clears manual unread.
        assert!(h.set_group_archived("g1", true));
        assert!(h.set_group_manual_unread("g1", true));
        assert!(!h.group("g1").unwrap().archived);
        assert!(h.set_group_archived("g1", true));
        assert!(!h.group("g1").unwrap().unread);
        // Unknown group: every setter refuses.
        assert!(!h.set_group_pinned("nope", true));
    }

    #[test]
    fn disappearing_timer_sets_delete_at_and_reaps() {
        let mut h = History::new();
        let peer = "peerkey";
        h.set_timer(peer, Some(60)); // 60-second disappearing messages
        h.record(peer, Direction::Outgoing, "m1", "hi", 1000);
        assert_eq!(h.messages(peer).len(), 1);
        assert_eq!(h.messages(peer)[0].delete_at, Some(1060));

        assert_eq!(h.reap(1059), 0); // not yet
        assert_eq!(h.reap(1060), 1); // now it goes
        assert!(h.messages(peer).is_empty());
    }

    #[test]
    fn timer_off_means_messages_persist() {
        let mut h = History::new();
        h.record("p", Direction::Incoming, "m1", "keep me", 1000);
        assert_eq!(h.messages("p")[0].delete_at, None);
        assert_eq!(h.reap(9_999_999), 0);
    }

    #[test]
    fn apply_timer_update_then_message_is_synced() {
        // Simulates the recipient side: adopt the peer's timer, then store their message.
        let mut h = History::new();
        h.pin_contact("alice", "alice", false);
        h.apply(&InboundEvent::TimerUpdate {
            sender_identity_key: "alice".into(),
            disappearing_secs: Some(30),
        });
        h.apply(&InboundEvent::Message {
            sender_identity_key: "alice".into(),
            sender_username: "alice".into(),
            msg_id: "m1".into(),
            body: "secret".into(),
            sent_at: 500,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        assert_eq!(h.timer("alice"), Some(30));
        assert_eq!(h.messages("alice")[0].delete_at, Some(530));
    }

    #[test]
    fn record_is_idempotent_by_msg_id() {
        let mut h = History::new();
        h.record("p", Direction::Incoming, "m1", "x", 1);
        h.record("p", Direction::Incoming, "m1", "x", 1); // duplicate delivery
        assert_eq!(h.messages("p").len(), 1);
    }

    #[test]
    fn contact_pins_persist_and_detect_change() {
        let mut h = History::new();
        assert_eq!(h.pinned_contact_key("bob"), None);
        h.pin_contact("bob", "bobkey", false);
        assert_eq!(h.pinned_contact_key("bob"), Some("bobkey"));
        assert!(!h.contact_verified("bob"));
        h.pin_contact("bob", "bobkey", true); // after out-of-band verification
        assert!(h.contact_verified("bob"));
        // Pins survive a seal/open round trip alongside messages.
        let key = [1u8; 32];
        let restored = History::open(&key, &h.seal(&key));
        assert_eq!(restored.pinned_contact_key("bob"), Some("bobkey"));
    }

    #[test]
    fn rename_contact_moves_pin_and_guards_shadowing() {
        let mut h = History::new();
        h.pin_contact("bob", "bobkey", true);
        h.with_contact_mut("bob", |c| c.nickname = Some("bobby".into()));
        // Rename moves the pin, keeping verification and local prefs.
        assert!(h.rename_contact("bobkey", "robert"));
        assert_eq!(h.pinned_contact_key("bob"), None);
        assert_eq!(h.pinned_contact_key("robert"), Some("bobkey"));
        assert!(h.contact_verified("robert"));
        // Idempotent re-application (redelivered rename) stays ok.
        assert!(h.rename_contact("bobkey", "robert"));
        // Shadowing guard: someone else cannot rename onto an existing contact.
        h.pin_contact("carol", "carolkey", false);
        assert!(!h.rename_contact("carolkey", "robert"));
        assert_eq!(h.pinned_contact_key("robert"), Some("bobkey"));
        // Unknown key renames nothing.
        assert!(!h.rename_contact("nokey", "whoever"));
        // Applying the inbound event does the same thing.
        h.apply(&InboundEvent::Renamed {
            sender_identity_key: "carolkey".into(),
            new_username: "caroline".into(),
        });
        assert_eq!(h.pinned_contact_key("caroline"), Some("carolkey"));
    }

    #[test]
    fn auto_pin_never_overwrites_a_verified_pin_with_a_spoofed_key() {
        let mut h = History::new();
        // Victim verified alice out-of-band.
        h.pin_contact("alice", "alice-real-key", true);
        // Attacker sends a message claiming from:"alice" with their own identity key.
        h.apply(&InboundEvent::Message {
            sender_identity_key: "attacker-key".into(),
            sender_username: "alice".into(),
            msg_id: "m1".into(),
            body: "hi".into(),
            sent_at: 0,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        // The verified pin is untouched: still alice's real key, still verified.
        assert_eq!(h.pinned_contact_key("alice"), Some("alice-real-key"));
        assert!(h.contact_verified("alice"));
    }

    #[test]
    fn auto_pin_adds_a_new_sender_as_unverified() {
        let mut h = History::new();
        h.apply(&InboundEvent::Message {
            sender_identity_key: "dave-key".into(),
            sender_username: "dave".into(),
            msg_id: "m1".into(),
            body: "first contact".into(),
            sent_at: 0,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        // New name: pinned so the chat is visible, but never auto-verified.
        assert_eq!(h.pinned_contact_key("dave"), Some("dave-key"));
        assert!(!h.contact_verified("dave"));
    }

    #[test]
    fn own_previous_usernames_dedupe_and_cap() {
        let mut h = History::new();
        // alice -> alice2 -> alice3 -> alice: the reclaimed name leaves the alias list
        // (it is the main mailbox again — an alias drain would double-subscribe it).
        h.note_own_rename("alice", "alice2");
        h.note_own_rename("alice2", "alice3");
        h.note_own_rename("alice3", "alice");
        assert_eq!(h.previous_usernames(), &["alice2", "alice3"]);
        for i in 0..10 {
            h.note_own_rename(&format!("n{i}"), "current");
        }
        assert_eq!(h.previous_usernames().len(), 5);
        // Survives the encrypted round trip.
        let key = [3u8; 32];
        let restored = History::open(&key, &h.seal(&key));
        assert_eq!(restored.previous_usernames().len(), 5);
    }

    #[test]
    fn rename_limit_window_counts_and_frees_up() {
        let mut h = History::new();
        let day = 86400;
        // Five renames on consecutive days: at the cap.
        for i in 0..5u64 {
            h.note_rename_time(1_000_000 + i * day);
        }
        let now = 1_000_000 + 4 * day + 10;
        let (used, next_free) = h.renames_in_window(now);
        assert_eq!(used, MAX_RENAMES_PER_WEEK);
        // The oldest leaves the window exactly one week after it happened.
        assert_eq!(next_free, Some(1_000_000 + RENAME_LIMIT_WINDOW_SECS));
        // Past that moment only four remain in the window.
        let (used, _) = h.renames_in_window(1_000_000 + RENAME_LIMIT_WINDOW_SECS + 1);
        assert_eq!(used, 4);
        // Survives the encrypted round trip.
        let key = [7u8; 32];
        let restored = History::open(&key, &h.seal(&key));
        assert_eq!(restored.renames_in_window(now).0, MAX_RENAMES_PER_WEEK);
    }

    #[test]
    fn device_resolution_candidate_flags_only_the_repairable_drop() {
        let mut h = History::new();
        h.pin_contact("alice", "alice-key", false);
        // Unattributed key + pinned name = the repairable silent-drop (linked device
        // we never resolved, or a rotated key) → re-resolve alice's roster.
        assert_eq!(
            h.device_resolution_candidate("mystery-key", "alice"),
            Some("alice".to_string())
        );
        // Not repairable: unknown name (plain stranger request path handles it)…
        assert_eq!(h.device_resolution_candidate("mystery-key", "bob"), None);
        assert_eq!(h.device_resolution_candidate("mystery-key", ""), None);
        // A current group member is safe to resolve even when they are not a direct
        // contact; otherwise calls from their newly linked devices would be dropped.
        h.groups.insert(
            "group".into(),
            GroupRecord {
                members: vec![GroupMember {
                    username: "bob".into(),
                    identity_key: "bob-key".into(),
                }],
                ..GroupRecord::default()
            },
        );
        assert_eq!(
            h.device_resolution_candidate("mystery-key", "bob"),
            Some("bob".to_string())
        );
        // …the pinned key itself…
        assert_eq!(h.device_resolution_candidate("alice-key", "alice"), None);
        // …or a key a verified roster already attributes.
        let devs = vec![RosterDevice {
            device_id: "aa".repeat(16),
            identity_key: "mystery-key".into(),
            signing_key: String::new(),
        }];
        h.pin_roster("alice", 0, 0, "alice-key", devs).unwrap();
        assert_eq!(h.device_resolution_candidate("mystery-key", "alice"), None);
    }

    #[test]
    fn roster_pin_is_monotonic_and_maps_device_owner() {
        let mut h = History::new();
        let devs = vec![
            RosterDevice {
                device_id: "0".into(),
                identity_key: "primary".into(),
                signing_key: String::new(),
            },
            RosterDevice {
                device_id: "aa".repeat(16),
                identity_key: "linked".into(),
                signing_key: String::new(),
            },
        ];
        h.pin_roster("alice", 0, 0, "primary", devs.clone())
            .unwrap();
        // Both devices attribute to the account primary key.
        assert_eq!(h.attribute_device("primary"), "primary");
        assert_eq!(h.attribute_device("linked"), "primary");
        // An unknown device attributes to itself (legacy single-device path).
        assert_eq!(h.attribute_device("stranger"), "stranger");
        // Advancing the epoch is fine; a rollback is refused.
        h.pin_roster("alice", 0, 1, "primary", devs.clone())
            .unwrap();
        let err = h
            .pin_roster("alice", 0, 0, "primary", devs.clone())
            .unwrap_err();
        assert_eq!(err.pinned_seq, 1);
        assert_eq!(err.served_seq, 0);

        // Ownership change (new primary key, roster chain restarts at 0): accepted only
        // with a strictly advanced binding chain — a relay cannot roll the combined
        // binding+roster view back to a previous key era.
        let new_owner = vec![RosterDevice {
            device_id: "0".into(),
            identity_key: "new-primary".into(),
            signing_key: String::new(),
        }];
        assert!(h
            .pin_roster("alice", 0, 0, "new-primary", new_owner.clone())
            .is_err());
        h.pin_roster("alice", 1, 0, "new-primary", new_owner)
            .unwrap();
        assert_eq!(h.attribute_device("new-primary"), "new-primary");
        // The old era's attribution is gone with its pin.
        assert_eq!(h.attribute_device("linked"), "linked");
        // ...and the old era itself can no longer be re-pinned.
        assert!(h.pin_roster("alice", 0, 5, "primary", devs).is_err());
    }

    #[test]
    fn removing_a_device_from_the_roster_drops_its_attribution() {
        let mut h = History::new();
        let with_linked = vec![
            RosterDevice {
                device_id: "0".into(),
                identity_key: "primary".into(),
                signing_key: String::new(),
            },
            RosterDevice {
                device_id: "bb".repeat(16),
                identity_key: "linked".into(),
                signing_key: String::new(),
            },
        ];
        h.pin_roster("alice", 0, 0, "primary", with_linked).unwrap();
        assert_eq!(h.attribute_device("linked"), "primary");
        // Epoch 1 without the linked device: it no longer attributes to the account.
        let only_primary = vec![RosterDevice {
            device_id: "0".into(),
            identity_key: "primary".into(),
            signing_key: String::new(),
        }];
        h.pin_roster("alice", 0, 1, "primary", only_primary)
            .unwrap();
        assert_eq!(h.attribute_device("linked"), "linked");
    }

    #[test]
    fn self_sync_only_honored_from_own_verified_device() {
        let mut h = History::new();
        // We are the primary; our own roster maps our devices to our primary key.
        h.set_self_device("0", true);
        h.set_self_primary_key("myprimary");
        h.pin_roster(
            "me",
            0,
            0,
            "myprimary",
            vec![
                RosterDevice {
                    device_id: "0".into(),
                    identity_key: "myprimary".into(),
                    signing_key: String::new(),
                },
                RosterDevice {
                    device_id: "cc".repeat(16),
                    identity_key: "mydevice2".into(),
                    signing_key: String::new(),
                },
            ],
        )
        .unwrap();

        // A self-sync from our OWN second device is recorded as outgoing.
        h.apply(&InboundEvent::SelfSentText {
            sender_identity_key: "mydevice2".into(),
            peer_key: "bobkey".into(),
            peer_username: "bob".into(),
            msg_id: "m1".into(),
            body: "sent from my phone".into(),
            sent_at: 100,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        let msgs = h.messages("bobkey");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Outgoing);

        // A forged self-sync from a stranger key is dropped (not our device).
        h.apply(&InboundEvent::SelfSentText {
            sender_identity_key: "attacker".into(),
            peer_key: "bobkey".into(),
            peer_username: "bob".into(),
            msg_id: "m2".into(),
            body: "forged".into(),
            sent_at: 200,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        assert_eq!(
            h.messages("bobkey").len(),
            1,
            "forged self-sync must be ignored"
        );
    }

    #[test]
    fn self_timer_update_only_honored_from_own_verified_device() {
        let mut h = History::new();
        h.set_self_device("0", true);
        h.set_self_primary_key("myprimary");
        h.pin_roster(
            "me",
            0,
            0,
            "myprimary",
            vec![
                RosterDevice {
                    device_id: "0".into(),
                    identity_key: "myprimary".into(),
                    signing_key: String::new(),
                },
                RosterDevice {
                    device_id: "cc".repeat(16),
                    identity_key: "mydevice2".into(),
                    signing_key: String::new(),
                },
            ],
        )
        .unwrap();

        // Our own second device set a 60s timer for the bob conversation: adopt it,
        // and messages recorded after it carry the matching delete_at.
        h.apply(&InboundEvent::SelfTimerUpdate {
            sender_identity_key: "mydevice2".into(),
            peer_key: "bobkey".into(),
            disappearing_secs: Some(60),
        });
        assert_eq!(h.timer("bobkey"), Some(60));
        h.record("bobkey", Direction::Incoming, "m1", "hi", 1000);
        assert_eq!(h.messages("bobkey")[0].delete_at, Some(1060));

        // A forged self-timer from a stranger key must NOT touch the timer (it could
        // otherwise silently disable — or shorten — disappearing messages).
        h.apply(&InboundEvent::SelfTimerUpdate {
            sender_identity_key: "attacker".into(),
            peer_key: "bobkey".into(),
            disappearing_secs: None,
        });
        assert_eq!(h.timer("bobkey"), Some(60), "forged timer must be ignored");
    }

    #[test]
    fn self_profile_update_only_honored_from_own_verified_device() {
        let mut h = History::new();
        h.set_self_device("0", true);
        h.set_self_primary_key("myprimary");
        h.pin_roster(
            "me",
            0,
            0,
            "myprimary",
            vec![
                RosterDevice {
                    device_id: "0".into(),
                    identity_key: "myprimary".into(),
                    signing_key: String::new(),
                },
                RosterDevice {
                    device_id: "cc".repeat(16),
                    identity_key: "mydevice2".into(),
                    signing_key: String::new(),
                },
            ],
        )
        .unwrap();
        let png = "data:image/png;base64,iVBORw0KGgo=";
        // Our own second device set a picture → adopt it.
        h.apply(&InboundEvent::SelfProfileUpdate {
            sender_identity_key: "mydevice2".into(),
            avatar: Some(png.into()),
        });
        assert_eq!(h.my_avatar(), Some(png));
        // A forged self-profile from a stranger must NOT overwrite our own picture.
        h.apply(&InboundEvent::SelfProfileUpdate {
            sender_identity_key: "attacker".into(),
            avatar: None,
        });
        assert_eq!(
            h.my_avatar(),
            Some(png),
            "forged self-profile must be ignored"
        );
    }

    #[test]
    fn carried_expire_beats_stale_stored_timer() {
        // The message can outrun the Timer control copy (different mailboxes, outbox
        // retries). The timer carried INSIDE the message must win over the stored one.
        let mut h = History::new();
        h.pin_contact("alice", "alice", false);
        // Stored timer still "off", but the message says 60s → it must expire.
        h.apply(&InboundEvent::Message {
            sender_identity_key: "alice".into(),
            sender_username: "alice".into(),
            msg_id: "m1".into(),
            body: "raced ahead".into(),
            sent_at: 1000,
            reply: None,
            expire_secs: Some(60),
            forwarded: false,
        });
        assert_eq!(h.messages("alice")[0].delete_at, Some(1060));

        // Stored timer on, but the sender had already turned it OFF (Some(0)) → no expiry.
        h.set_timer("alice", Some(30));
        h.apply(&InboundEvent::Message {
            sender_identity_key: "alice".into(),
            sender_username: "alice".into(),
            msg_id: "m2".into(),
            body: "timer was off at send".into(),
            sent_at: 2000,
            reply: None,
            expire_secs: Some(0),
            forwarded: false,
        });
        assert_eq!(h.message("alice", "m2").unwrap().delete_at, None);

        // Legacy sender (no carried field) → fall back to the stored timer.
        h.apply(&InboundEvent::Message {
            sender_identity_key: "alice".into(),
            sender_username: "alice".into(),
            msg_id: "m3".into(),
            body: "legacy".into(),
            sent_at: 3000,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        assert_eq!(h.message("alice", "m3").unwrap().delete_at, Some(3030));
    }

    #[test]
    fn group_timer_stamps_delete_at_and_reap_covers_groups() {
        let mut h = group_with(&[("bob", "bobkey")]);
        assert!(h.set_group_timer("g1", Some(60)));
        assert_eq!(h.group_timer("g1"), Some(60));
        h.record_group_message("g1", "bobkey", "m1", "burns", 1000, None, None);
        assert_eq!(h.group("g1").unwrap().messages[0].delete_at, Some(1060));
        // Carried expire wins in groups too (sender had the timer off at send time).
        h.record_group_message("g1", "bobkey", "m2", "keeps", 1000, Some(0), None);
        assert_eq!(h.group("g1").unwrap().messages[1].delete_at, None);
        // The reaper covers group threads.
        assert_eq!(h.reap(1059), 0);
        assert_eq!(h.reap(1060), 1);
        assert_eq!(h.group("g1").unwrap().messages.len(), 1);
        // Unknown group: timer set refused.
        assert!(!h.set_group_timer("nope", Some(5)));
    }

    #[test]
    fn group_roster_create_adopts_carried_timer_encoding() {
        // The timer carried in a group-CREATING GroupRoster is adopted per its encoding
        // (`Some(0)` = off, `Some(n)` = n seconds, `None` = leave untouched). It travels only
        // on creation; later timer changes ride GroupTimerUpdate.
        let make = |gid: &str, carried: Option<u64>| -> History {
            let (sk, key) = epoch_keypair();
            let g0 = GroupEpoch::genesis(
                gid.into(),
                vec![epm("alice", "alice")],
                key,
                "alice".into(),
                1000,
                |p| epsig(&sk, p),
            );
            let mut h = History::new();
            h.pin_contact("alice", "alice", false);
            h.apply(&InboundEvent::GroupRosterUpdate {
                sender_identity_key: "alice".into(),
                epoch: g0,
                name: "trip".into(),
                disappearing_secs: carried,
                avatar: None,
            });
            h
        };
        assert_eq!(make("g60", Some(60)).group_timer("g60"), Some(60));
        assert_eq!(make("g0", Some(0)).group_timer("g0"), None);
        assert_eq!(make("gnone", None).group_timer("gnone"), None);
    }

    #[test]
    fn group_timer_update_event_sets_timer() {
        let mut h = group_with(&[("bob", "bobkey")]);
        h.apply(&InboundEvent::GroupTimerUpdate {
            sender_identity_key: "bobkey".into(),
            group_id: "g1".into(),
            disappearing_secs: Some(300),
        });
        assert_eq!(h.group_timer("g1"), Some(300));
        // Unknown group id: ignored, nothing created.
        h.apply(&InboundEvent::GroupTimerUpdate {
            sender_identity_key: "bobkey".into(),
            group_id: "unknown".into(),
            disappearing_secs: Some(300),
        });
        assert!(h.group("unknown").is_none());
    }

    #[test]
    fn valid_avatar_gate() {
        let png = "data:image/png;base64,iVBORw0KGgo=";
        assert!(valid_avatar(png));
        assert!(valid_avatar("data:image/jpeg;base64,AAAA"));
        // Wrong scheme / remote URL / markup are all rejected.
        assert!(!valid_avatar("https://evil.example/x.png"));
        assert!(!valid_avatar("data:text/html;base64,PHNjcmlwdD4="));
        assert!(!valid_avatar("<img src=x>"));
        assert!(!valid_avatar("data:image/png;base64,not*base64"));
        // Oversized is refused (DoS / history-bloat guard).
        let huge = format!("data:image/png;base64,{}", "A".repeat(MAX_AVATAR_BYTES));
        assert!(!valid_avatar(&huge));
        // sanitize turns junk (and empty) into None, keeps a valid one.
        assert_eq!(sanitize_avatar(Some("nope".into())), None);
        assert_eq!(sanitize_avatar(Some("   ".into())), None);
        assert_eq!(sanitize_avatar(Some(png.into())), Some(png.to_string()));
    }

    #[test]
    fn profile_update_stores_peer_avatar_only_for_a_known_contact() {
        let mut h = History::new();
        h.pin_contact("bob", "bobkey", true);
        let png = "data:image/png;base64,iVBORw0KGgo=";
        h.apply(&InboundEvent::ProfileUpdate {
            sender_identity_key: "bobkey".into(),
            avatar: Some(png.into()),
        });
        assert_eq!(h.avatar_for_peer("bobkey"), Some(png.to_string()));
        // A malformed picture from the peer clears rather than stores junk.
        h.apply(&InboundEvent::ProfileUpdate {
            sender_identity_key: "bobkey".into(),
            avatar: Some("javascript:alert(1)".into()),
        });
        assert_eq!(h.avatar_for_peer("bobkey"), None);
        // An unknown sender never creates a contact.
        h.apply(&InboundEvent::ProfileUpdate {
            sender_identity_key: "strangerkey".into(),
            avatar: Some(png.into()),
        });
        assert!(h.username_for_peer("strangerkey").is_none());
    }

    #[test]
    fn group_avatar_update_and_invite_carry_the_picture() {
        let mut h = group_with(&[("alice", "alice")]);
        let png = "data:image/png;base64,iVBORw0KGgo=";
        h.apply(&InboundEvent::GroupAvatarUpdate {
            sender_identity_key: "alice".into(),
            group_id: "g1".into(),
            avatar: Some(png.into()),
        });
        assert_eq!(h.group_avatar("g1"), Some(png.to_string()));
        // A newcomer adopts the picture carried in the group-creating roster.
        let (sk, key) = epoch_keypair();
        let g0 = GroupEpoch::genesis(
            "g2".into(),
            vec![epm("alice", "alice")],
            key,
            "alice".into(),
            1000,
            |p| epsig(&sk, p),
        );
        let mut fresh = History::new();
        fresh.pin_contact("alice", "alice", false);
        fresh.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "alice".into(),
            epoch: g0,
            name: "trip".into(),
            disappearing_secs: Some(0),
            avatar: Some(png.into()),
        });
        assert_eq!(fresh.group_avatar("g2"), Some(png.to_string()));
    }

    #[test]
    fn incoming_from_a_linked_device_is_attributed_to_the_account() {
        let mut h = History::new();
        h.pin_contact("bob", "bob-primary", false);
        // We learned Bob's roster: his phone key maps to his account (primary) key.
        h.pin_roster(
            "bob",
            0,
            0,
            "bob-primary",
            vec![
                RosterDevice {
                    device_id: "0".into(),
                    identity_key: "bob-primary".into(),
                    signing_key: String::new(),
                },
                RosterDevice {
                    device_id: "dd".repeat(16),
                    identity_key: "bob-phone".into(),
                    signing_key: String::new(),
                },
            ],
        )
        .unwrap();
        // A message arrives from Bob's PHONE device key.
        h.apply(&InboundEvent::Message {
            sender_identity_key: "bob-phone".into(),
            sender_username: "bob".into(),
            msg_id: "m1".into(),
            body: "hi from my phone".into(),
            sent_at: 1,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        // It is filed under Bob's stable account (primary) key, not the device key.
        assert!(h
            .messages("bob-primary")
            .iter()
            .any(|m| m.body == "hi from my phone"));
        assert!(h.messages("bob-phone").is_empty());
        assert_eq!(h.pinned_contact_key("bob"), Some("bob-primary"));
    }

    #[test]
    fn export_plaintext_strips_device_local_state() {
        let mut h = History::new();
        h.set_self_device("ee".repeat(16).as_str(), false);
        h.set_self_primary_key("primary");
        h.pin_roster(
            "bob",
            0,
            0,
            "bob-primary",
            vec![RosterDevice {
                device_id: "0".into(),
                identity_key: "bob-primary".into(),
                signing_key: String::new(),
            }],
        )
        .unwrap();
        h.pin_contact("bob", "bob-primary", true);
        h.record("bob-primary", Direction::Incoming, "m1", "hi", 1);
        let plain = h.export_plaintext();
        let imported = History::import_plaintext(&plain).unwrap();
        // Contacts + messages travel; device-local identity/rosters do NOT.
        assert_eq!(imported.pinned_contact_key("bob"), Some("bob-primary"));
        assert_eq!(imported.messages("bob-primary").len(), 1);
        assert!(imported.self_device().is_none());
        assert!(imported.pinned_roster("bob").is_none());
        assert!(imported.self_primary_key().is_none());
    }

    #[test]
    fn seal_open_round_trip_and_wrong_key() {
        let mut h = History::new();
        h.set_timer("p", Some(10));
        h.record("p", Direction::Outgoing, "m1", "hello", 1000);
        let key = [7u8; 32];
        let blob = h.seal(&key);
        let restored = History::open(&key, &blob);
        assert_eq!(restored.messages("p").len(), 1);
        assert_eq!(restored.timer("p"), Some(10));
        // Wrong key → fail-soft to empty history (not a panic, not garbage).
        assert!(History::open(&[0u8; 32], &blob).messages("p").is_empty());
    }

    #[test]
    fn reaction_toggle_semantics_and_dedup() {
        let mut h = History::new();
        h.record("p", Direction::Incoming, "m1", "hi", 1000);
        // Add our own reaction (empty reactor).
        assert!(h.react("p", "m1", "", "👍", true));
        assert_eq!(h.messages("p")[0].reactions.len(), 1);
        // Re-adding the same (reactor, emoji) is idempotent.
        h.react("p", "m1", "", "👍", true);
        assert_eq!(h.messages("p")[0].reactions.len(), 1);
        // A different reactor with the same emoji is a distinct reaction.
        h.react("p", "m1", "peerkey", "👍", true);
        assert_eq!(h.messages("p")[0].reactions.len(), 2);
        // Removing our reaction leaves only the peer's.
        assert!(h.react("p", "m1", "", "👍", false));
        assert_eq!(h.messages("p")[0].reactions.len(), 1);
        assert_eq!(h.messages("p")[0].reactions[0].reactor, "peerkey");
        // Toggling an unknown message returns false and changes nothing.
        assert!(!h.react("p", "nope", "", "🔥", true));
    }

    #[test]
    fn incoming_reaction_attributes_to_peer_account() {
        let mut h = History::new();
        h.record("alice", Direction::Outgoing, "m1", "hey", 500);
        h.apply(&InboundEvent::Reaction {
            sender_identity_key: "alice".into(),
            target_msg_id: "m1".into(),
            emoji: "❤️".into(),
            add: true,
        });
        let r = &h.messages("alice")[0].reactions;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].reactor, "alice"); // not empty — it's the peer's, not ours
        assert_eq!(r[0].emoji, "❤️");
    }

    #[test]
    fn typing_events_never_touch_the_timeline() {
        let mut h = History::new();
        h.apply(&InboundEvent::Typing {
            sender_identity_key: "alice".into(),
            typing: true,
        });
        assert!(h.messages("alice").is_empty());
    }

    #[test]
    fn system_events_persist_are_seen_and_dedup() {
        let mut h = History::new();
        h.record_system("p", "You marked Bob verified", 1000);
        h.record_system("p", "You marked Bob verified", 1001); // repeat as last → deduped
        assert_eq!(h.messages("p").len(), 1);
        let m = &h.messages("p")[0];
        assert!(m.system);
        assert!(m.seen_receipted); // never contributes to the unread badge
        assert!(h.unseen_incoming_ids("p").is_empty());
        // A different event does append.
        h.record_system("p", "Disappearing messages: 1 day", 1002);
        assert_eq!(h.messages("p").len(), 2);
    }

    #[test]
    fn call_events_never_dedup() {
        // Two missed calls in a row are two events — the call-history chips must not
        // collapse like ordinary system chips do.
        let mut h = History::new();
        h.record_call_event("p", "📞 Missed call", 1000);
        h.record_call_event("p", "📞 Missed call", 1001);
        assert_eq!(h.messages("p").len(), 2);
        assert!(h.messages("p").iter().all(|m| m.system && m.seen_receipted));
        assert!(h.unseen_incoming_ids("p").is_empty()); // no unread badge from calls
                                                        // Group flavor: same rule (and a no-op for an unknown group).
        h.record_group_call_event("nope", "📞 Missed group call", 1002);
        let (sk, key) = epoch_keypair();
        let g0 = GroupEpoch::genesis(
            "g".into(),
            vec![epm("teammate", "tm")],
            key,
            "tm".into(),
            1000,
            |p| epsig(&sk, p),
        );
        h.adopt_group_epoch(&g0);
        h.record_group_call_event("g", "📞 Missed group call", 1003);
        h.record_group_call_event("g", "📞 Missed group call", 1004);
        assert_eq!(h.group("g").unwrap().messages.len(), 2);
    }

    #[test]
    fn archived_and_unread_flags_round_trip() {
        let mut h = History::new();
        h.pin_contact("bob", "bobkey", false);
        h.with_contact_mut("bob", |c| {
            c.archived = true;
            c.unread = true;
        });
        let key = [3u8; 32];
        let restored = History::open(&key, &h.seal(&key));
        let (_, pin) = restored
            .contacts()
            .into_iter()
            .find(|(u, _)| u == "bob")
            .unwrap();
        assert!(pin.archived);
        assert!(pin.unread);
    }

    // ── Message requests ─────────────────────────────────────────────────────────

    fn stranger_msg(id: &str, body: &str) -> InboundEvent {
        InboundEvent::Message {
            sender_identity_key: "strangerkey".into(),
            sender_username: "mallory".into(),
            msg_id: id.into(),
            body: body.into(),
            sent_at: 100,
            reply: None,
            expire_secs: None,
            forwarded: false,
        }
    }

    #[test]
    fn request_gate_defaults_are_protective() {
        let h = History::new();
        // Requests ON, request-only (no text rides along) — the spec's defaults, and
        // what every pre-feature history must deserialize to.
        assert_eq!(h.request_prefs(), (true, false));
        let key = [9u8; 32];
        let restored = History::open(&key, &h.seal(&key));
        assert_eq!(restored.request_prefs(), (true, false));
    }

    #[test]
    fn stranger_text_becomes_request_only_by_default() {
        let mut h = History::new();
        h.apply(&stranger_msg("m1", "hi, buy my coin"));
        h.apply(&stranger_msg("m2", "hello??"));
        // Content is HELD (hidden behind the request row) — never dropped, so an accept
        // surfaces it; the withheld counter is what the request-only UI shows instead
        // of a preview.
        assert_eq!(h.messages("strangerkey").len(), 2);
        assert!(h.is_request_pending("mallory"));
        assert_eq!(h.request_count(), 1);
        let (_, pin) = h.pending_requests().pop().unwrap();
        assert_eq!(pin.request.as_ref().unwrap().withheld, 2);
        // The one-shot notification latch fires exactly once.
        assert!(h.request_needs_notify("strangerkey"));
        assert!(!h.request_needs_notify("strangerkey"));
        // Accepting surfaces the held texts — the chat must not start empty.
        assert!(h.accept_request("mallory"));
        assert_eq!(
            h.messages("strangerkey")
                .iter()
                .filter(|m| !m.system)
                .count(),
            2
        );
    }

    #[test]
    fn knock_creates_a_request_without_content() {
        let mut h = History::new();
        h.apply(&InboundEvent::Knock {
            sender_identity_key: "strangerkey".into(),
            sender_username: "mallory".into(),
        });
        assert!(h.is_request_pending("mallory"));
        assert!(h.messages("strangerkey").is_empty());
        assert!(h.request_needs_notify("strangerkey"));
        // Knocking an accepted contact is a no-op (no new request row).
        assert!(h.accept_request("mallory"));
        h.apply(&InboundEvent::Knock {
            sender_identity_key: "strangerkey".into(),
            sender_username: "mallory".into(),
        });
        assert!(!h.is_request_pending("mallory"));
    }

    #[test]
    fn stranger_text_rides_along_when_allowed() {
        let mut h = History::new();
        h.set_request_prefs(true, true); // requests on, text-with-request allowed
        h.apply(&stranger_msg("m1", "hello there"));
        // The text is held in the (hidden) conversation AND the request is pending.
        assert_eq!(h.messages("strangerkey").len(), 1);
        assert!(h.is_request_pending("mallory"));
        assert_eq!(
            h.pending_requests()[0].1.request.as_ref().unwrap().withheld,
            0
        );
    }

    #[test]
    fn accepted_contacts_and_open_mode_bypass_the_gate() {
        // Known contact: untouched by the gate.
        let mut h = History::new();
        h.pin_contact("mallory", "strangerkey", false);
        h.apply(&stranger_msg("m1", "hi"));
        assert_eq!(h.messages("strangerkey").len(), 1);
        assert!(!h.is_request_pending("mallory"));
        // Open mode: strangers land directly (today's behavior).
        let mut h2 = History::new();
        h2.set_request_prefs(false, false);
        h2.apply(&stranger_msg("m1", "hi"));
        assert_eq!(h2.messages("strangerkey").len(), 1);
        assert!(!h2.is_request_pending("mallory"));
    }

    #[test]
    fn accept_surfaces_the_chat_and_replays_held_invites() {
        let mut h = History::new();
        h.set_request_prefs(true, true);
        h.apply(&stranger_msg("m1", "join my group?"));
        // Their group roster (signed genesis epoch) is held on the request, not applied.
        let (mal_sk, mal_key) = epoch_keypair();
        let g0 = GroupEpoch::genesis(
            "g9".into(),
            vec![epm("mallory", "strangerkey"), epm("me", "mykey")],
            mal_key,
            "strangerkey".into(),
            1000,
            |p| epsig(&mal_sk, p),
        );
        h.apply(&InboundEvent::GroupRosterUpdate {
            sender_identity_key: "strangerkey".into(),
            epoch: g0,
            name: "crew".into(),
            disappearing_secs: Some(60),
            avatar: None,
        });
        assert!(h.group("g9").is_none());
        assert!(h.accept_request("mallory"));
        assert!(!h.is_request_pending("mallory"));
        // Replayed on accept: the group exists with the carried timer.
        assert!(h.group("g9").is_some());
        assert_eq!(h.group_timer("g9"), Some(60));
        // Accepting twice is a no-op.
        assert!(!h.accept_request("mallory"));
    }

    #[test]
    fn decline_forgets_and_block_keeps_dropping() {
        let mut h = History::new();
        h.set_request_prefs(true, true);
        h.apply(&stranger_msg("m1", "spam"));
        // Plain decline: pin and held conversation vanish; they may ask again.
        assert!(h.decline_request("mallory", false));
        assert!(h.messages("strangerkey").is_empty());
        assert_eq!(h.request_count(), 0);
        h.apply(&stranger_msg("m2", "spam again"));
        assert_eq!(h.request_count(), 1);
        // Decline-and-block: the pin stays blocked, so the delivery loop drops them.
        assert!(h.decline_request("mallory", true));
        assert!(h.peer_blocked("strangerkey"));
        assert_eq!(h.request_count(), 0);
        assert!(h.messages("strangerkey").is_empty());
    }

    #[test]
    fn disabling_requests_accepts_everything_pending() {
        let mut h = History::new();
        h.set_request_prefs(true, true);
        h.apply(&stranger_msg("m1", "waiting"));
        assert!(h.is_request_pending("mallory"));
        h.set_request_prefs(false, false);
        assert!(!h.is_request_pending("mallory"));
        assert_eq!(h.request_count(), 0);
        // The held text is still there, now visible as a normal chat (the accept also
        // drops its system chip).
        assert_eq!(
            h.messages("strangerkey")
                .iter()
                .filter(|m| !m.system)
                .count(),
            1
        );
    }

    #[test]
    fn stranger_calls_never_ring_and_fold_into_the_request() {
        let mut h = History::new();
        assert!(!h.screen_call_offer("strangerkey", "mallory", 100));
        assert!(h.is_request_pending("mallory"));
        assert_eq!(h.pending_requests()[0].1.request.as_ref().unwrap().calls, 1);
        // Accepted contact rings; open mode rings.
        let mut h2 = History::new();
        h2.pin_contact("mallory", "strangerkey", false);
        assert!(h2.screen_call_offer("strangerkey", "mallory", 100));
        let mut h3 = History::new();
        h3.set_request_prefs(false, false);
        assert!(h3.screen_call_offer("strangerkey", "mallory", 100));
    }

    #[test]
    fn spoofed_or_nameless_strangers_get_no_request_row() {
        let mut h = History::new();
        h.pin_contact("alice", "alicekey", true);
        // Claims alice's name from a different key: withheld outright — the verified
        // pin is untouched and no request row appears under alice's name.
        h.apply(&InboundEvent::Message {
            sender_identity_key: "evilkey".into(),
            sender_username: "alice".into(),
            msg_id: "m1".into(),
            body: "it's me, alice".into(),
            sent_at: 100,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        assert!(h.messages("evilkey").is_empty());
        assert_eq!(h.request_count(), 0);
        assert_eq!(h.pinned_contact_key("alice"), Some("alicekey"));
        assert!(h.contact_verified("alice"));
        // No claimed name at all: nothing actionable, nothing recorded.
        h.apply(&InboundEvent::Message {
            sender_identity_key: "ghostkey".into(),
            sender_username: String::new(),
            msg_id: "m2".into(),
            body: "anon".into(),
            sent_at: 100,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        assert!(h.messages("ghostkey").is_empty());
        assert_eq!(h.request_count(), 0);
    }

    #[test]
    fn stranger_control_traffic_is_gated() {
        let mut h = History::new();
        // A stranger cannot set our disappearing timer…
        h.apply(&InboundEvent::TimerUpdate {
            sender_identity_key: "strangerkey".into(),
            disappearing_secs: Some(5),
        });
        assert_eq!(h.timer("strangerkey"), None);
        // …and a pending requester cannot pin messages in the held conversation.
        h.set_request_prefs(true, true);
        h.apply(&stranger_msg("m1", "pin me"));
        h.apply(&InboundEvent::MessagePinned {
            sender_identity_key: "strangerkey".into(),
            msg_id: "m1".into(),
            pin: true,
        });
        assert!(!h.message("strangerkey", "m1").unwrap().pinned);
    }

    #[test]
    fn replying_from_own_device_is_consent() {
        let mut h = History::new();
        h.set_self_device("0", true);
        h.set_self_primary_key("myprimary");
        h.pin_roster(
            "me",
            0,
            0,
            "myprimary",
            vec![
                RosterDevice {
                    device_id: "0".into(),
                    identity_key: "myprimary".into(),
                    signing_key: String::new(),
                },
                RosterDevice {
                    device_id: "cc".repeat(16),
                    identity_key: "mydevice2".into(),
                    signing_key: String::new(),
                },
            ],
        )
        .unwrap();
        h.apply(&stranger_msg("m1", "hello"));
        assert!(h.is_request_pending("mallory"));
        // Our own other device replied to them (self-sync copy): request clears.
        h.apply(&InboundEvent::SelfSentText {
            sender_identity_key: "mydevice2".into(),
            peer_key: "strangerkey".into(),
            peer_username: "mallory".into(),
            msg_id: "s1".into(),
            body: "hey mallory".into(),
            sent_at: 200,
            reply: None,
            expire_secs: None,
            forwarded: false,
        });
        assert!(!h.is_request_pending("mallory"));
    }

    #[test]
    fn dead_session_detection_is_conservative() {
        let now = 1_000_000u64;
        let peer = "peer-key";
        // A conversation they HAVE replied on, plus `n` unacknowledged sends `age` old.
        let convo = |n: usize, age: u64| -> History {
            let mut h = History::new();
            h.pin_contact("bob", peer, false);
            h.record(peer, Direction::Incoming, "in1", "hi", now - age - 60);
            for i in 0..n {
                h.record(
                    peer,
                    Direction::Outgoing,
                    &format!("out{i}"),
                    "hello?",
                    now - age,
                );
            }
            h
        };

        // The real failure: a run of old sends nobody ever acknowledged.
        assert!(convo(3, 900).session_looks_dead(peer, now));

        // Too few unacknowledged sends to be sure.
        assert!(!convo(2, 900).session_looks_dead(peer, now));
        // A fast burst inside the grace period (they may simply be offline).
        assert!(!convo(5, 60).session_looks_dead(peer, now));

        // Never heard from them at all — could just be an unaccepted message request,
        // which withholds delivery receipts by design. Must NOT auto-reset.
        let mut never = History::new();
        never.pin_contact("bob", peer, false);
        for i in 0..5 {
            never.record(peer, Direction::Outgoing, &format!("o{i}"), "hi", now - 900);
        }
        assert!(!never.session_looks_dead(peer, now));

        // One acknowledged send in the trailing run proves the session is alive.
        let mut acked = convo(3, 900);
        acked.mark_receipt(peer, &["out2".to_string()], false);
        assert!(!acked.session_looks_dead(peer, now));

        // So does anything inbound after the run.
        let mut replied = convo(3, 900);
        replied.record(peer, Direction::Incoming, "in2", "still here", now - 10);
        assert!(!replied.session_looks_dead(peer, now));

        // Rate limited right after an automatic reset, so it can never churn…
        let mut just_reset = convo(3, 900);
        just_reset.mark_session_reset(peer, now - 60);
        assert!(!just_reset.session_looks_dead(peer, now));
        // …and allowed again once the window has passed.
        let mut long_ago = convo(3, 900);
        long_ago.mark_session_reset(peer, now - 4000);
        assert!(long_ago.session_looks_dead(peer, now));
    }

    #[test]
    fn requests_unseen_drives_the_red_dot() {
        let mut h = History::new();
        h.apply(&stranger_msg("m1", "one"));
        assert_eq!(h.requests_unseen(), 1);
        h.mark_requests_seen();
        assert_eq!(h.requests_unseen(), 0);
        assert_eq!(h.request_count(), 1); // still pending, just viewed
                                          // New activity re-arms the dot.
        h.apply(&stranger_msg("m2", "two"));
        assert_eq!(h.requests_unseen(), 1);
    }

    #[test]
    fn held_invites_are_bounded_and_deduped() {
        let mut h = History::new();
        h.apply(&stranger_msg("m1", "invites incoming"));
        let make = |gid: &str| -> InboundEvent {
            let (sk, key) = epoch_keypair();
            let g0 = GroupEpoch::genesis(
                gid.into(),
                vec![epm("mallory", "strangerkey")],
                key,
                "strangerkey".into(),
                1000,
                |p| epsig(&sk, p),
            );
            InboundEvent::GroupRosterUpdate {
                sender_identity_key: "strangerkey".into(),
                epoch: g0,
                name: format!("group {gid}"),
                disappearing_secs: None,
                avatar: None,
            }
        };
        for i in 0..(MAX_HELD_INVITES + 4) {
            h.apply(&make(&format!("g{i}")));
        }
        // Re-inviting an already-held group replaces, never duplicates.
        h.apply(&make("g0"));
        let (_, pin) = h.pending_requests().pop().unwrap();
        let invites = &pin.request.as_ref().unwrap().invites;
        assert!(invites.len() <= MAX_HELD_INVITES);
        assert!(invites.iter().filter(|i| i.group_id == "g0").count() <= 1);
    }
}
