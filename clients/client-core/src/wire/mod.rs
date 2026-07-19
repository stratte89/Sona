use super::*;

/// The plaintext that actually travels inside the ratchet ciphertext. The server never
/// sees this — it's the end-to-end payload. A conversation carries messages, control
/// messages (disappearing-messages timer), and attachment references over one channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum ChatPayload {
    /// A chat message. `ts` is the sender's send time — both sides use it so a
    /// disappearing-messages delete time matches exactly. `from` is the sender's username,
    /// carried *inside* the ciphertext so the recipient can name and reply to the sender
    /// (sealed sender means the server never learns it, and the ratchet authenticates who
    /// actually sent it — the claimed `from` is only trusted after a KT re-check on reply).
    Text {
        body: String,
        ts: u64,
        #[serde(default)]
        from: String,
        /// Present when this message quotes another.
        #[serde(default)]
        reply: Option<ReplyRef>,
        /// The sender's disappearing timer at send time, carried **inside the message**
        /// so a copy that races ahead of the `Timer` control message still gets the
        /// right delete time. `None` = legacy sender (recipient falls back to its stored
        /// conversation timer); `Some(0)` = timer explicitly off; `Some(n)` = n seconds.
        #[serde(default)]
        expire_secs: Option<u64>,
        /// This message was forwarded from another conversation (drives the recipient's
        /// "Forwarded" tag). Old clients ignore the unknown field.
        #[serde(default)]
        fwd: bool,
    },
    /// Replace the body of a message this sender previously sent (client-enforced
    /// send window; the recipient applies it only to messages from this sender).
    Edit { msg_id: String, body: String },
    /// Delete a message this sender previously sent, on both sides ("delete for
    /// everyone"). Recipients only honor it for messages from this sender.
    DeleteMsg { msg_id: String },
    /// A disappearing-messages timer change for this conversation. `None` = off.
    /// Applying it on both sides keeps the timer synchronized end-to-end.
    Timer { secs: Option<u64> },
    /// An attachment reference (the ciphertext lives in a relay blob). `from` is the
    /// sender's username, carried inside the ciphertext (same rules as `Text::from`).
    File {
        attachment: AttachmentRef,
        #[serde(default)]
        from: String,
        /// Sender's timer at send time (see [`ChatPayload::Text::expire_secs`]).
        #[serde(default)]
        expire_secs: Option<u64>,
        /// Forwarded from another conversation (see [`ChatPayload::Text::fwd`]).
        #[serde(default)]
        fwd: bool,
    },
    /// The sender deleted the conversation on their side and asks ours to do the same
    /// ("delete for both"). Honored because both parties already hold the plaintext —
    /// this is cooperative hygiene, not a security boundary.
    DeleteChat {},
    /// An explicit chat request ("knock"): no content, just "I'd like to chat". The
    /// recipient's request gate surfaces a pending-request row exactly as if a first
    /// message had arrived — without the sender having to compose one. A knock to an
    /// already-accepted contact is a no-op. Old clients fail-soft decode → acked away.
    Knock {
        #[serde(default)]
        from: String,
    },
    /// A delivery receipt for one or more of the peer's messages. `seen == false` means
    /// "delivered to my device"; `seen == true` means "I opened the conversation". Travels
    /// inside the ratchet, so the server never learns read state.
    Receipt { ids: Vec<String>, seen: bool },
    /// A gossip carrier: the sender's current Key Transparency tree head. The recipient
    /// compares it against its own view to catch an equivocating server (split view).
    Gossip { head: SignedTreeHead },
    /// A group's signed membership epoch — the sole wire vehicle for creating a group,
    /// adding/removing a member, and admin transfer. Every group is admin-model: the
    /// recipient validates the epoch against its pinned chain before adopting any member
    /// change (see [`History::adopt_group_epoch`]). `name`/`disappearing_secs`/`avatar`
    /// carry the (egalitarian) group meta so a newcomer sees the group fully on first sight;
    /// they are adopted only when the epoch CREATES the group, never on a later advance.
    GroupRoster {
        epoch: GroupEpoch,
        name: String,
        #[serde(default)]
        disappearing_secs: Option<u64>,
        #[serde(default)]
        avatar: Option<String>,
    },
    /// A message to a group (fanned out pairwise to every member).
    GroupText {
        group_id: String,
        body: String,
        ts: u64,
        /// Sender's group timer at send time (see [`ChatPayload::Text::expire_secs`]).
        #[serde(default)]
        expire_secs: Option<u64>,
        /// Present when this message quotes another in the same group thread. Old
        /// clients ignore the unknown field (serde default) — the message still lands.
        #[serde(default)]
        reply: Option<ReplyRef>,
        /// Forwarded from another conversation (see [`ChatPayload::Text::fwd`]).
        #[serde(default)]
        fwd: bool,
    },
    /// Replace the body of a group message this sender previously sent (same
    /// client-enforced send window as [`ChatPayload::Edit`]; recipients apply it only
    /// to messages stored under this sender).
    GroupEdit {
        group_id: String,
        msg_id: String,
        body: String,
    },
    /// Delete a group message this sender previously sent, for everyone. Recipients
    /// only honor it for messages stored under this sender.
    GroupDeleteMsg { group_id: String, msg_id: String },
    /// Rename a group. Any member may rename — same trust model as the roster/timer.
    GroupRename { group_id: String, name: String },
    /// The sender left the group. Recipients drop the sender from their roster.
    GroupLeave { group_id: String },
    /// An attachment to a group (fanned out pairwise like [`ChatPayload::GroupText`];
    /// every member gets the same [`AttachmentRef`] — one shared ciphertext blob whose
    /// key travels only inside each pair's ratchet).
    GroupFile {
        group_id: String,
        attachment: AttachmentRef,
        ts: u64,
        /// Sender's group timer at send time (see [`ChatPayload::Text::expire_secs`]).
        #[serde(default)]
        expire_secs: Option<u64>,
        /// Forwarded from another conversation (see [`ChatPayload::Text::fwd`]).
        #[serde(default)]
        fwd: bool,
    },
    /// A disappearing-messages timer change for a group thread (fanned out pairwise to
    /// every member, and to the sender's own other devices). `None` = off. Any member
    /// may change it — same trust model as membership itself.
    GroupTimer { group_id: String, secs: Option<u64> },
    /// The sender changed their username. The ratchet authenticates *who* sent this; the
    /// claimed name is applied only under the recipient's shadowing guard
    /// ([`History::rename_contact`]) and is re-proven against Key Transparency on the
    /// next send anyway (the send path resolves the username through the KT log and
    /// compares against the pinned key), so a false claim can't route messages elsewhere.
    Rename { new_username: String },
    /// The sender set (or cleared with `None`) their profile picture, broadcast to each
    /// contact over the existing E2E session. The picture is a small `data:` image URI; the
    /// recipient bounds + format-checks it ([`crate::history::valid_avatar`]) before storing,
    /// so a hostile value is at worst an inert image, never markup or an external fetch. An
    /// old client that doesn't know this variant fails to decode and acks it away (no poison).
    Profile { avatar: Option<String> },
    /// A group's picture change, fanned out pairwise to every member (same trust model as
    /// [`ChatPayload::GroupTimer`] — any member may set it). `None` clears it.
    GroupAvatar {
        group_id: String,
        avatar: Option<String>,
    },
    /// Invite the recipient to a voice call: the relay-room capability (`call_id`) and
    /// the root call key. Both are random per call, travel only inside the ratchet, and
    /// die with the call — see [`call`]. `from` as in [`ChatPayload::Text`].
    CallOffer {
        call_id: String,
        key_b64: String,
        ts: u64,
        #[serde(default)]
        from: String,
        /// Media capabilities of the offering client (e.g. [`media::MEDIA2_CAP`]).
        /// Absent from old clients ⇒ voice-only; unknown strings are ignored.
        #[serde(default)]
        caps: Vec<String>,
        /// Non-empty ⇒ this offer resumes the call whose id it names after a network
        /// drop: a **fresh** room + key (a call key is never reused), sent by the
        /// pair's owner (lexicographically smaller identity key). The device that was
        /// in the dropped call auto-accepts silently; every other recipient ignores it
        /// — a reconnect must never ring. Old clients don't know the field and treat
        /// the offer as a normal ring (degrades, doesn't break).
        #[serde(default)]
        reconnect_of: String,
    },
    /// Accept/decline a pending call offer. `caps` as in [`ChatPayload::CallOffer`].
    /// `busy` marks an *automatic* decline (device already in a call / already ringing):
    /// with ring-all-devices the caller must not end the ring while the callee's other
    /// devices can still answer, so only the last busy decline — or any explicit
    /// (`busy == false`) decline — ends it. Old clients omit the field (⇒ `false`),
    /// keeping their declines explicit, exactly as today.
    CallAnswer {
        call_id: String,
        accept: bool,
        #[serde(default)]
        caps: Vec<String>,
        #[serde(default)]
        busy: bool,
    },
    /// Hang up / cancel a call (also sent when a ring times out).
    CallEnd { call_id: String },
    /// Invite the recipient to **one pair leg** of a group call. Group calls are a full
    /// mesh of the existing two-member blind relay rooms: every participant pair gets its
    /// own random room id + 32-byte key, minted fresh and carried only inside that pair's
    /// Double Ratchet session — so each leg has *exactly* the 1:1 call's security
    /// properties (E2E, forward-secret, relay learns no identities), and the relay needs
    /// no changes. `call_instance` (random 32 hex) names the group call itself and groups
    /// its legs; receiving any offer for an instance also means "the sender is in that
    /// call". Glare rule: for each pair, the ticket minted by the lexicographically
    /// **smaller** identity key wins; the other side's ticket is ignored (its lonely room
    /// is reaped by the relay's GC). Both sides apply the rule locally, so every pair
    /// deterministically converges on one room with no extra round trip.
    GroupCallOffer {
        group_id: String,
        call_instance: String,
        call_id: String,
        key_b64: String,
        ts: u64,
        #[serde(default)]
        from: String,
    },
    /// The sender is not (or no longer) in group call `call_instance`: sent on decline,
    /// on hangup, and on ring timeout. Recipients drop the sender's leg and stop ringing
    /// if nobody remains. One message covers all three cases — the wire never
    /// distinguishes "declined" from "left", which is also the right privacy default.
    GroupCallEnd {
        group_id: String,
        call_instance: String,
    },
    /// **Multi-device self-sync.** A copy, sent to the account's *own other devices*, of a
    /// text message this account sent to `peer_key`. The receiving own-device records it as
    /// an outgoing message so all of a user's devices show the same sent history. Only
    /// honored when the sending device is a verified member of our own roster.
    SelfText {
        peer_key: String,
        #[serde(default)]
        peer_username: String,
        msg_id: String,
        body: String,
        ts: u64,
        #[serde(default)]
        reply: Option<ReplyRef>,
        /// Our timer at send time (see [`ChatPayload::Text::expire_secs`]), so the
        /// mirrored copy expires identically even if the device's timer is stale.
        #[serde(default)]
        expire_secs: Option<u64>,
        /// Forwarded from another conversation (mirrored so every device shows the tag).
        #[serde(default)]
        fwd: bool,
    },
    /// Multi-device self-sync of an attachment we sent (see [`ChatPayload::SelfText`]).
    SelfFile {
        peer_key: String,
        #[serde(default)]
        peer_username: String,
        msg_id: String,
        attachment: AttachmentRef,
        /// Our timer at send time (see [`ChatPayload::Text::expire_secs`]).
        #[serde(default)]
        expire_secs: Option<u64>,
        /// Forwarded from another conversation (mirrored so every device shows the tag).
        #[serde(default)]
        fwd: bool,
    },
    /// Multi-device self-sync of a read (`seen`) marker: another of our devices opened the
    /// `peer_key` conversation, so this device marks those incoming messages read too.
    SelfSeen { peer_key: String, ids: Vec<String> },
    /// Multi-device self-sync: another of our own devices answered or declined the ring
    /// for `call_id`, so this device stops ringing. Ephemeral (never enters history) and
    /// honored only from a verified own device. Carries no call key.
    SelfCallHandled { call_id: String },
    /// **History re-export request.** A linked device whose synced history blob expired
    /// asks its primary to re-seal + re-upload history. Carries a fresh capability id and a
    /// fresh link secret (E2E-encrypted, so the relay never sees the link secret). Honored
    /// only from our own verified device.
    SyncRequest {
        provisioning_id: String,
        link_secret_b64: String,
    },
    /// **Primary-ownership transfer offer**, sent by the current primary to ONE of its
    /// linked devices. Carries a KT **rotation entry** (binding the account to the
    /// target device's keys, signed by the current account key) and the old primary's
    /// **demoted device record** (its same keys under a fresh linked-device id, signed
    /// by itself). No private key ever travels: the target *becomes* the primary by
    /// publishing the rotation + a fresh roster naming itself device "0". Honored only
    /// when the ratchet-authenticated sender is our own account's current primary.
    PrimaryTransfer {
        entry: KtEntry,
        demoted: kt_log::DeviceRecord,
    },
    /// **Primary→linked forwarding** of a message that arrived from a *legacy* sender
    /// (one that only addresses the account mailbox, so linked devices never got a direct
    /// copy). The primary re-encrypts it to each linked device, which records it as an
    /// incoming message from `from_key`. Idempotent by `msg_id`, so a device that also got
    /// a direct fan-out copy dedups. Honored only from our own primary device.
    ForwardIncoming {
        from_key: String,
        #[serde(default)]
        from_username: String,
        msg_id: String,
        body: String,
        ts: u64,
        #[serde(default)]
        reply: Option<ReplyRef>,
        #[serde(default)]
        attachment: Option<AttachmentRef>,
        /// The original message's carried timer (see [`ChatPayload::Text::expire_secs`]),
        /// passed through so the forwarded copy expires like the original.
        #[serde(default)]
        expire_secs: Option<u64>,
    },
    /// Toggle an emoji reaction on one of the peer's (or our own) messages in this 1:1
    /// conversation. `add` sets the reaction, `!add` removes it. The reactor is the
    /// ratchet-authenticated sender; `emoji` is a short unicode string. Old clients that
    /// don't know this variant fail to decode it and ack it away — no reaction shown, no
    /// mailbox poison (the `None =>` decode arm).
    Reaction {
        target_msg_id: String,
        emoji: String,
        add: bool,
        ts: u64,
    },
    /// Multi-device self-sync of a reaction WE made (mirrors it to our own other devices,
    /// keyed by the conversation `peer_key`). Honored only from a verified own device.
    SelfReaction {
        peer_key: String,
        target_msg_id: String,
        emoji: String,
        add: bool,
    },
    /// Multi-device self-sync of a disappearing-timer change WE made for the `peer_key`
    /// conversation (mirrors it to our own other devices so every device stamps the same
    /// `delete_at` on subsequent messages). Honored only from a verified own device.
    SelfTimer { peer_key: String, secs: Option<u64> },
    /// Multi-device self-sync of OUR OWN profile picture (mirrors a change made on one of our
    /// devices to all the others so every device shows the same picture in its own settings).
    /// Bounded + format-checked, and applied only from a verified own device — a peer forging
    /// this could otherwise overwrite the picture we show for ourselves. `None` clears it.
    SelfProfile { avatar: Option<String> },
    /// Toggle an emoji reaction on a message in a group thread (fanned out pairwise like a
    /// group message).
    GroupReaction {
        group_id: String,
        target_msg_id: String,
        emoji: String,
        add: bool,
        ts: u64,
    },
    /// Pin (or unpin) a message in this 1:1 conversation. Either side may pin — both
    /// already hold the plaintext, so a pin is shared conversation metadata, not a
    /// privilege. Old clients fail-soft decode and ack it away (no mailbox poison).
    PinMsg { msg_id: String, pin: bool },
    /// Multi-device self-sync of a pin WE toggled (mirrors it to our own other devices,
    /// keyed by the conversation `peer_key`). Honored only from a verified own device.
    SelfPinMsg {
        peer_key: String,
        msg_id: String,
        pin: bool,
    },
    /// Pin (or unpin) a message in a group thread (fanned out pairwise like a group
    /// message). Any member may pin — same trust model as the roster/timer.
    GroupPinMsg {
        group_id: String,
        msg_id: String,
        pin: bool,
    },
    /// Ephemeral "I am typing" signal for this 1:1 conversation. **Never** persisted to
    /// history — it exists only to drive the transient indicator and expires on a timer at
    /// the recipient. `typing == false` is an explicit stop.
    Typing { typing: bool },
    /// Ephemeral typing signal for a group thread (fanned out pairwise). Never persisted.
    GroupTyping { group_id: String, typing: bool },
}

/// Encrypt a [`ChatPayload`] into a sealed-sender [`Envelope`]: serialize, pad to a
/// length bucket (so ciphertext length reveals only the bucket), base64, ratchet-encrypt.
pub(crate) fn build_envelope(
    account: &mut Account,
    contact: &Contact,
    payload: &ChatPayload,
) -> Result<Envelope> {
    seal_payload_to(
        account,
        &contact.identity_hash,
        &contact.identity_key,
        payload,
        &random_msg_id(),
    )
}

/// The sender-declared wake class for a payload (see [`protocol_types::WakeClass`]):
/// the ONE coarse routing bit the relay may read. Content-bearing traffic (texts,
/// attachments, group messages/invites, primary→linked forwards) earns a debounced
/// `Normal` wake; call and group-call offers earn an immediate `Call` wake — except
/// silent reconnect offers, which must never ring a locked device and ride `Normal`.
/// Everything else (receipts, typing, reactions, edits, timers, gossip, self-sync,
/// call answer/end signaling) is `None`: an offline device has nothing user-visible
/// to show for it, so the relay must not burn a wake — it all drains with the next
/// real wake or app open. Stale-offer rings are prevented downstream by
/// `used_call_ids` + offer expiry; a `CallEnded` needing to cancel a ring is handled
/// by the FCM TTL + the drain.
pub(crate) fn wake_class_for(payload: &ChatPayload) -> WakeClass {
    match payload {
        ChatPayload::Text { .. }
        | ChatPayload::File { .. }
        | ChatPayload::GroupText { .. }
        | ChatPayload::GroupFile { .. }
        | ChatPayload::GroupRoster { .. }
        | ChatPayload::Knock { .. }
        | ChatPayload::ForwardIncoming { .. } => WakeClass::Normal,
        ChatPayload::CallOffer { reconnect_of, .. } => {
            if reconnect_of.is_empty() {
                WakeClass::Call
            } else {
                WakeClass::Normal
            }
        }
        ChatPayload::GroupCallOffer { .. } => WakeClass::Call,
        _ => WakeClass::None,
    }
}

mod decode;
pub(crate) use decode::ack_frame;
pub use decode::{decode_frame, Decoded};
