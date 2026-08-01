use super::*;

/// How far a sender-supplied timestamp may run ahead of local receipt before we clamp it
/// for the disappearing-message reaper. A malicious sender could otherwise set a far-future
/// `ts` so the message *never* disappears despite the timer; clamping the reaper's base to
/// `now + skew` closes that (L-9). Generous enough to absorb honest clock skew.
const MAX_FUTURE_TS_SKEW_SECS: u64 = 300;

/// Upper bound on a stored avatar's encoded size (bytes of the data-URI string). Avatars are
/// client-resized to a small square before send, so a genuine one is well under this; the cap
/// stops a hostile peer from bloating our (persisted, sealed) history with a huge "picture".
pub const MAX_AVATAR_BYTES: usize = 262_144;

/// Whether `s` is an acceptable profile picture: a base64 `data:` image URI of a known type,
/// within [`MAX_AVATAR_BYTES`]. This is the single gate every avatar — our own and every peer's
/// — passes before it is stored or shown, so an attacker-supplied string can only ever be an
/// inert image the webview renders in an `<img>`, never markup or an external URL (no SSRF, no
/// script, no unbounded blob). `None`/empty is always valid (clears the picture).
pub fn valid_avatar(s: &str) -> bool {
    if s.len() > MAX_AVATAR_BYTES {
        return false;
    }
    let Some(rest) = s.strip_prefix("data:image/") else {
        return false;
    };
    let Some((kind, data)) = rest.split_once(";base64,") else {
        return false;
    };
    matches!(kind, "png" | "jpeg" | "jpg" | "webp" | "gif")
        && !data.is_empty()
        && data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Normalize an incoming avatar choice: an empty/whitespace or invalid value becomes `None`
/// (no picture), a valid data-URI is kept. Used on both the set-my-own and receive-a-peer's
/// paths so the [`valid_avatar`] gate is impossible to bypass.
pub fn sanitize_avatar(avatar: Option<String>) -> Option<String> {
    avatar.filter(|a| !a.trim().is_empty() && valid_avatar(a))
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute a disappearing message's `delete_at`. The base is the sender's `sent_at`, but
/// clamped so it cannot be set arbitrarily far in the future to defeat the timer (L-9). A
/// far-*past* `ts` is left as-is: it only makes the sender's own message reap sooner.
pub(crate) fn disappear_at(disappearing_secs: Option<u64>, sent_at: u64) -> Option<u64> {
    // `d` is a peer-supplied timer (message/group `expire_secs`); a value near u64::MAX
    // must not wrap the deadline in release builds (two's-complement wrap → a bogus
    // near-past `delete_at` = premature reap). Saturate instead.
    disappearing_secs.map(|d| {
        sent_at
            .min(unix_now().saturating_add(MAX_FUTURE_TS_SKEW_SECS))
            .saturating_add(d)
    })
}

/// `delete_at` for an inbound message that may CARRY the sender's timer inside it
/// (`expire_secs`: `None` = legacy sender → fall back to the stored conversation timer;
/// `Some(0)` = timer explicitly off; `Some(n)` = n seconds). The carried value wins so a
/// message that races ahead of its `Timer`/`GroupTimer` control copy — different mailbox,
/// outbox retry, jitter — still expires exactly when the sender intended. The same L-9
/// clamp applies: a carried timer never lets `sent_at` push the deadline past
/// `now + skew + timer`.
pub(crate) fn carried_delete_at(
    stored_secs: Option<u64>,
    expire_secs: Option<u64>,
    sent_at: u64,
) -> Option<u64> {
    match expire_secs {
        Some(0) => None,
        Some(n) => disappear_at(Some(n), sent_at),
        None => disappear_at(stored_secs, sent_at),
    }
}

/// Insert or remove a `(reactor, emoji)` reaction on a message's reaction list. Each
/// `(reactor, emoji)` pair is unique; adding an existing pair is a no-op, so re-delivered
/// reaction events converge (idempotent) and a toggle can't double-count.
/// Hard ceiling on stored reactions per message: a peer's client is untrusted input, and
/// without a cap one hostile contact can bloat the sealed history (and the chip row)
/// without bound. Removals are always honored.
const MAX_REACTIONS_PER_MESSAGE: usize = 64;

pub(crate) fn apply_reaction(reactions: &mut Vec<Reaction>, reactor: &str, emoji: &str, add: bool) {
    // Same bounds the shell enforces on our own outgoing reactions — inbound must not
    // get to store what we would refuse to send.
    if emoji.is_empty() || emoji.chars().count() > 8 {
        return;
    }
    let existing = reactions
        .iter()
        .position(|r| r.reactor == reactor && r.emoji == emoji);
    if add && existing.is_none() && reactions.len() >= MAX_REACTIONS_PER_MESSAGE {
        return;
    }
    match (add, existing) {
        (true, None) => reactions.push(Reaction {
            reactor: reactor.to_string(),
            emoji: emoji.to_string(),
        }),
        (false, Some(i)) => {
            reactions.remove(i);
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outgoing,
    Incoming,
}

/// A relay served a contact's device roster at a **lower** epoch than the one we already
/// pinned — an append-only roster never goes backwards, so this is a rollback / split-view
/// attempt. The caller must fail closed (do not fan out to the served list).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("roster rollback for {username}: pinned epoch {pinned_seq}, server served {served_seq}")]
pub struct RosterRollback {
    pub username: String,
    pub pinned_seq: u64,
    pub served_seq: u64,
}

/// Delivery state of an *outgoing* message, driven by receipts the recipient sends back
/// (inside the ratchet, so the server never sees them). Monotonic: only ever upgrades.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Handed to the relay.
    #[default]
    Sent,
    /// The recipient's device drained it.
    Delivered,
    /// The recipient opened the conversation.
    Seen,
}

/// One reaction on a stored message: who reacted (their identity key) and the emoji. Our
/// own reaction uses the empty string as `reactor` so it renders highlighted without the
/// timeline needing to know this device's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    /// The reactor's identity key. Empty string = us (the local user).
    pub reactor: String,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub msg_id: String,
    pub direction: Direction,
    /// For a text message, the text. For an attachment, the filename (see `attachment`).
    pub body: String,
    pub sent_at: u64,
    /// Unix time after which this message must be deleted on both sides. `None` when the
    /// conversation's disappearing timer was off at send time.
    pub delete_at: Option<u64>,
    /// Present when this timeline entry is an attachment (download via the client).
    #[serde(default)]
    pub attachment: Option<crate::AttachmentRef>,
    /// The sender's identity key, set for group messages (which have many senders). `None`
    /// for 1:1, where the conversation peer + direction already identify the sender.
    #[serde(default)]
    pub sender: Option<String>,
    /// Delivery state (outgoing messages only; recipient-driven via receipts).
    #[serde(default)]
    pub status: DeliveryStatus,
    /// Incoming messages only: whether we've already sent the peer a "seen" receipt for
    /// this message. Lets the client send each read receipt exactly once (instead of
    /// re-sending receipts for the whole thread every time it's opened) and doubles as
    /// the local unread marker.
    #[serde(default)]
    pub seen_receipted: bool,
    /// The message body was edited after sending.
    #[serde(default)]
    pub edited: bool,
    /// Set when this message quotes another.
    #[serde(default)]
    pub reply: Option<crate::ReplyRef>,
    /// Emoji reactions on this message (from us and/or the peer/group members).
    #[serde(default)]
    pub reactions: Vec<Reaction>,
    /// A local, centered system-event chip (timer changed, key changed, member added…),
    /// never sent over the wire. `body` holds the display text; `direction` is unused.
    #[serde(default)]
    pub system: bool,
    /// Pinned in this conversation (shared metadata — either side / any member may pin).
    #[serde(default)]
    pub pinned: bool,
    /// Forwarded from another conversation (drives the "Forwarded" tag).
    #[serde(default)]
    pub forwarded: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conversation {
    /// The agreed disappearing-messages timer, in seconds. `None` = off. Kept in sync
    /// with the peer via [`InboundEvent::TimerUpdate`].
    pub disappearing_secs: Option<u64>,
    pub messages: Vec<StoredMessage>,
}

/// A group invite held back by the message-request gate: everything needed to replay
/// it if (and only if) the user accepts the requester. Public roster material only —
/// no key material ever sits in a held invite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldInvite {
    pub group_id: String,
    pub name: String,
    pub members: Vec<crate::GroupMember>,
    /// The inviter's timer encoding (`None` legacy / `Some(0)` off / `Some(n)` secs).
    pub disappearing_secs: Option<u64>,
    /// The group picture as carried by the invite (already [`valid_avatar`]-sanitized
    /// before it is held).
    pub avatar: Option<String>,
    /// The signed membership epoch this invite carries. Every group is admin-model, so a
    /// held invite always has one; it is replayed through
    /// [`History::adopt_group_epoch`](crate::History::adopt_group_epoch) on accept, so the
    /// chain is validated even for an invite that waited on a pending request.
    pub epoch: kt_log::GroupEpoch,
}

/// Cap on invites held inside one pending request — a stranger must not be able to
/// bloat the sealed history by spraying invites. Newest wins (deduped by group id).
pub const MAX_HELD_INVITES: usize = 8;

/// One quarantined group-content event: content whose sender is not (yet) a member of the
/// group it addresses. It never renders while quarantined. If a signed roster epoch soon
/// proves the sender WAS legitimately added (the classic race: the admin's epoch and the
/// newcomer's first message ride different mailboxes, so either may arrive first), the
/// event replays losslessly in arrival order; otherwise it expires unseen — which is how a
/// kicked member's post-kick spam dies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldGroupEvent {
    /// The attributed sender (account primary key) at hold time.
    pub sender: String,
    /// OUR receive time (unix secs) — TTL anchor, so relay queueing never eats the window.
    pub received_at: u64,
    pub content: HeldGroupContent,
}

/// The content shapes that can sit in quarantine (mirrors the group content arms of
/// [`InboundEvent`](crate::InboundEvent)).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeldGroupContent {
    Message {
        msg_id: String,
        body: String,
        sent_at: u64,
        expire_secs: Option<u64>,
        reply: Option<crate::ReplyRef>,
        forwarded: bool,
    },
    Attachment {
        msg_id: String,
        attachment: crate::AttachmentRef,
        sent_at: u64,
        expire_secs: Option<u64>,
        forwarded: bool,
    },
    Reaction {
        target_msg_id: String,
        emoji: String,
        add: bool,
    },
    Edit {
        msg_id: String,
        body: String,
    },
    Delete {
        msg_id: String,
    },
}

/// Quarantine TTL for a group we already KNOW: the add-race it insures against resolves in
/// seconds (the epoch is fanned in the same breath as the add), so anything older is a
/// non-member talking into a group they're not in — let it die. Short enough that a kicked
/// member re-added much later does not resurrect their out-of-roster backlog.
pub const HELD_GROUP_CONTENT_TTL_SECS: u64 = 600;
/// Quarantine TTL for an UNKNOWN group: the creating epoch may sit behind a pending
/// message request until the user accepts, so match the patience of a held invite
/// (days, not minutes) — accepting then replays the first messages instead of losing them.
pub const HELD_GROUP_CONTENT_UNKNOWN_TTL_SECS: u64 = 7 * 24 * 3600;
/// Per-group quarantine cap (oldest evicted first) — bounds what a spammer with a live
/// session can park in the sealed history.
pub const MAX_HELD_GROUP_EVENTS: usize = 64;
/// Cap on how many distinct groups may hold quarantined content at once (stalest-activity
/// group evicted) — bounds group_id spraying.
pub const MAX_HELD_GROUP_CONTENT_GROUPS: usize = 32;

/// How the message-request gate disposed of one inbound content event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundScreen {
    /// Sender is an accepted contact (or the gate is off): apply normally.
    Allow,
    /// Sender is pending and text-with-request is allowed: record the content — it
    /// stays hidden behind the request row until the user accepts.
    Held,
    /// Withheld: request-only mode, or an unactionable/spoofed sender — record nothing.
    Dropped,
}

/// The message-request state of a not-yet-accepted contact. Present on a [`ContactPin`]
/// ⇒ the contact is **pending**: hidden from the chat list, surfaced in the requests
/// list instead, and everything they send is screened until the user accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// Unix time the request first appeared.
    pub since: u64,
    /// Unix time of the requester's latest activity.
    pub last: u64,
    /// Texts/attachments withheld entirely (request-only mode) — the user sees the
    /// count, never the content.
    pub withheld: u32,
    /// Call attempts suppressed while pending (never rings).
    pub calls: u32,
    /// One OS notification per request lifecycle — set once fired.
    pub notified: bool,
    /// The user has viewed the requests list since `last` (drives the red dot).
    pub seen: bool,
    /// Group invites held for replay on accept (bounded, deduped by group id).
    pub invites: Vec<HeldInvite>,
}

/// A pinned contact: the identity key we trust for a username, whether the user has
/// confirmed it out-of-band (safety-number check), plus local, never-transmitted
/// preferences (pin/mute/nickname/block). All of it lives inside the encrypted history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContactPin {
    pub identity_key: String,
    pub verified: bool,
    /// Keep this chat at the top of the list.
    #[serde(default)]
    pub pinned: bool,
    /// Unix time until which the chat is muted; `u64::MAX` = muted forever.
    #[serde(default)]
    pub muted_until: Option<u64>,
    /// Local display-name override. Never sent anywhere.
    #[serde(default)]
    pub nickname: Option<String>,
    /// The contact's profile picture as a small `data:image/…;base64,…` URI, learned from
    /// their [`ChatPayload::Profile`](crate::wire) broadcast (ratchet-authenticated). Bounded
    /// and format-checked by [`valid_avatar`] before it is ever stored. `None` = no picture
    /// (the UI falls back to a generated initial). Never leaves this device.
    #[serde(default)]
    pub avatar: Option<String>,
    /// Drop everything this contact sends (no record, no receipts) and refuse sends.
    #[serde(default)]
    pub blocked: bool,
    /// How loud to play this contact's voice, in percent
    /// ([`crate::call::GAIN_UNITY`] = as sent). `None` — the default every existing
    /// vault deserializes to — means untouched.
    ///
    /// Persisted, unlike every other call control: a voice that is too quiet is a
    /// property of a person's microphone and room, not of one call, so being made to
    /// fix it again every time you ring them is the bug. Purely local — it is applied
    /// after decode and never reaches the wire, so the other side cannot tell.
    #[serde(default)]
    pub voice_gain: Option<u32>,
    /// Hidden behind the collapsed "Archived" row at the bottom of the chat list. Cleared
    /// automatically when the chat is opened. Local-only, never transmitted.
    #[serde(default)]
    pub archived: bool,
    /// Manually marked unread (badge shown even with no unseen messages), cleared on open.
    /// Local-only, never transmitted.
    #[serde(default)]
    pub unread: bool,
    /// Fingerprint of the last own-avatar value **successfully sent** to this contact
    /// (`""` = an explicit "no picture" was sent). `None` = never sent — the reconcile
    /// pass ([`crate::History::profile_send_needed`]) sends our current picture on the
    /// next opportunity (first message, request accept). Local-only, never transmitted.
    #[serde(default)]
    pub profile_sent: Option<String>,
    /// `Some` ⇒ this contact is a **pending message request**: hidden from the chat
    /// list, shown in the requests list, screened by the request gate. `None` (the
    /// default — every pre-existing pin deserializes to it) ⇒ accepted contact, full
    /// behavior. Local-only, never transmitted.
    #[serde(default)]
    pub request: Option<PendingRequest>,
    /// When we last auto-reset the ratchet session with this contact, rate-limiting the
    /// dead-session self-heal (see [`crate::History::session_looks_dead`]) so a peer who
    /// is merely offline can never make it churn. Local-only, never transmitted.
    #[serde(default)]
    pub last_session_reset: Option<u64>,
}

/// This device's own identity inside a multi-device account. Absent = a legacy
/// single-device account, which behaves exactly as the primary device (`device_id "0"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfDevice {
    /// [`kt_log::PRIMARY_DEVICE_ID`] on the primary; a 32-hex id on a linked device.
    pub device_id: String,
    /// True only on the device holding the account (KT-bound) keys.
    pub is_primary: bool,
}

/// An in-flight primary-ownership transfer, recorded on the OLD primary at offer time.
/// The old primary keeps acting as primary until it observes (in the KT log) that the
/// target accepted — the rotation + new roster are published by the *target*, never by
/// us — and then demotes itself to this pre-minted linked-device identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDemotion {
    /// The device id this (old primary) device takes once the transfer completes. The
    /// signed record for it was handed to the target inside the transfer offer.
    pub new_device_id: String,
    /// The device id of the linked device offered the primary role.
    pub target_device_id: String,
}

/// A primary-ownership transfer offered TO this device, persisted until the user
/// accepts or a newer offer replaces it. Holding it in (sealed) history — not in
/// process memory — matters for crash safety: the accept publishes the KT rotation
/// *then* the roster, and if the process dies between the two, this record is the only
/// thing that lets the retry complete the transfer (the old primary can no longer
/// re-send it — the binding already moved). Public material only (signed entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPromotion {
    pub entry: KtEntry,
    pub demoted: DeviceRecord,
}

/// The call-control key this device last published, and when. The `created_at` is kept
/// so the next publication can be minted strictly newer than the live one — the relay's
/// shelf refuses anything that does not supersede what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallKeyPublication {
    pub public_key: String,
    pub created_at: u64,
    /// The device id the binding was minted for. A primary transfer re-ids this device,
    /// and a binding for the old id verifies against nothing — so the id is part of
    /// "already published".
    #[serde(default)]
    pub device_id: String,
}

/// One device of some account, as learned from a KT-verified roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterDevice {
    pub device_id: String,
    pub identity_key: String,
    /// The device's Ed25519 roster key. Pinned alongside the identity key because it is
    /// what verifies material the *device itself* signs — today its call-control key
    /// binding. Empty on a pin written before this field existed; the next roster
    /// resolve fills it in, and until then device-signed material simply does not verify.
    #[serde(default)]
    pub signing_key: String,
}

/// Product limit: at most this many username changes per rolling week (client-enforced
/// here; the relay backstops the release side per signing key).
pub const MAX_RENAMES_PER_WEEK: usize = 5;
/// The rolling window for [`MAX_RENAMES_PER_WEEK`].
pub const RENAME_LIMIT_WINDOW_SECS: u64 = 7 * 86400;

/// A contact's device roster, pinned locally. The `seq` is the anti-rollback anchor:
/// a later fetch that serves a **lower** epoch is treated as equivocation and refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterPin {
    pub seq: u64,
    /// The KT binding-chain position (`KtEntry::seq`) the roster was validated against.
    /// Pinned monotonically alongside the roster epoch: a primary-key change (rotation,
    /// or a released-name takeover) is only accepted together with a binding that
    /// *advanced* this chain — which is what stops a relay from rolling the whole view
    /// (binding + roster) back to a previous owner/key era.
    #[serde(default)]
    pub binding_seq: u64,
    /// The account's primary (KT-bound) identity key — the stable conversation id all of
    /// this account's devices are attributed to.
    pub primary_key: String,
    pub devices: Vec<RosterDevice>,
}

/// A group the user belongs to, plus its message thread.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupRecord {
    pub name: String,
    pub members: Vec<GroupMember>,
    pub messages: Vec<StoredMessage>,
    /// The group's picture as a small `data:image/…;base64,…` URI. Any member may set it
    /// (same trust model as the name/roster); it rides [`ChatPayload::GroupAvatar`] and the
    /// invite. Bounded + format-checked by [`valid_avatar`]. `None` = generated fallback.
    #[serde(default)]
    pub avatar: Option<String>,
    /// Unix time until which this group is muted; `u64::MAX`-ish = forever.
    #[serde(default)]
    pub muted_until: Option<u64>,
    /// The group's disappearing-messages timer, in seconds. `None` = off. Synced with
    /// the other members via [`InboundEvent::GroupTimerUpdate`].
    #[serde(default)]
    pub disappearing_secs: Option<u64>,
    /// Keep this group at the top of the chat list. Local-only, never transmitted.
    #[serde(default)]
    pub pinned: bool,
    /// Hidden behind the collapsed "Archived" row. Cleared on open. Local-only.
    #[serde(default)]
    pub archived: bool,
    /// Manually marked unread (badge shown even with no unseen messages). Local-only.
    #[serde(default)]
    pub unread: bool,
    /// We left the group or were removed: the thread stays readable but sends are
    /// blocked and no roster fan-out happens anymore.
    #[serde(default)]
    pub left: bool,
    /// The pinned cryptographic membership state for an **admin-model** group: the highest
    /// epoch we have adopted, plus the current admin. `None` = a **legacy** group (created
    /// before admin-authorized membership, or by an old client) — it is grandfathered under
    /// the egalitarian, current-member-gated rules and is never retrofitted with an admin.
    /// `Some` = a new-model group whose membership only ever advances via a validated
    /// [`kt_log::GroupEpoch`] (see [`History::adopt_group_epoch`]).
    #[serde(default)]
    pub admin: Option<GroupAdmin>,
}

/// Pinned admin/epoch state for one admin-model group. Mirrors the anti-rollback pin in
/// [`RosterPin`]: the highest `epoch_seq` we adopted and the admin authorized from it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupAdmin {
    /// Highest membership-epoch seq we have adopted (monotonic; lower/equal is refused).
    pub epoch_seq: u64,
    /// The current admin's Ed25519 account signing key (base64) — the authority that must
    /// sign the next epoch.
    pub admin_key: String,
    /// The current admin's Curve25519 account identity key (base64) — identifies which
    /// member is the admin (for display and the local "am I admin" check).
    pub admin_identity_key: String,
    /// The genesis (epoch-0) admin key, recorded immutably when we pinned from seq 0 so the
    /// group's creator can never silently change. `None` when we joined mid-life and never
    /// witnessed the genesis.
    #[serde(default)]
    pub creator_admin_key: Option<String>,
}

/// One queued envelope and when it becomes postable (unix seconds; self-sync jitter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxItem {
    pub envelope: protocol_types::Envelope,
    pub due_at: u64,
}

/// One short-lived call-control delivery attempt. Unlike the general history outbox,
/// these entries have a strict retry budget and inherit the envelope's call-scale TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallOutboxItem {
    pub envelope: protocol_types::Envelope,
    pub due_at: u64,
    pub attempts: u8,
}
