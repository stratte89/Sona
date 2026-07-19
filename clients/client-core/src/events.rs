use super::*;

/// A decrypted inbound event: either a message or a control message, plus who sent it.
#[derive(Debug, Clone)]
pub enum InboundEvent {
    Message {
        sender_identity_key: String,
        /// The sender's username, carried inside the ciphertext (see [`ChatPayload::Text`]).
        /// Authenticated identity is `sender_identity_key`; this is the human name to show.
        sender_username: String,
        msg_id: String,
        body: String,
        sent_at: u64,
        /// Set when the message quotes another.
        reply: Option<ReplyRef>,
        /// The sender's timer carried inside the message (`None` = legacy sender,
        /// `Some(0)` = off, `Some(n)` = n secs) — see [`ChatPayload::Text::expire_secs`].
        expire_secs: Option<u64>,
        /// The sender forwarded this from another conversation ("Forwarded" tag).
        forwarded: bool,
    },
    /// The sender edited one of their earlier messages.
    MessageEdited {
        sender_identity_key: String,
        msg_id: String,
        body: String,
    },
    /// The sender deleted one of their earlier messages for everyone.
    MessageDeleted {
        sender_identity_key: String,
        msg_id: String,
    },
    /// The peer changed the disappearing-messages timer for the conversation.
    TimerUpdate {
        sender_identity_key: String,
        disappearing_secs: Option<u64>,
    },
    /// The peer deleted the conversation for both sides.
    ChatDeleted { sender_identity_key: String },
    /// An explicit chat request (no content): surface a pending-request row for the
    /// sender exactly as a first message would, without holding any text.
    Knock {
        sender_identity_key: String,
        sender_username: String,
    },
    /// The peer acknowledged our messages: `seen == false` = delivered to their device,
    /// `seen == true` = they opened the conversation. `ids` are our outgoing message ids.
    Receipt {
        sender_identity_key: String,
        ids: Vec<String>,
        seen: bool,
    },
    /// An attachment was received. Download + decrypt it with [`Client::download_attachment`].
    Attachment {
        sender_identity_key: String,
        /// Sender's username from inside the ciphertext (see [`InboundEvent::Message`]).
        sender_username: String,
        msg_id: String,
        attachment: AttachmentRef,
        sent_at: u64,
        /// The sender's carried timer (see [`InboundEvent::Message::expire_secs`]).
        expire_secs: Option<u64>,
        /// Forwarded from another conversation ("Forwarded" tag).
        forwarded: bool,
    },
    /// A peer shared the Key Transparency tree head they observed. Pass `head` to
    /// [`Client::compare_foreign_head`] to check the server didn't show you two histories.
    PeerHead {
        sender_identity_key: String,
        head: SignedTreeHead,
    },
    /// A group's signed membership epoch (create / add / remove / admin transfer).
    /// `sender_identity_key` is the ratchet-authenticated sender, but authority comes from
    /// the epoch's own admin signature, not from who relayed it. The recipient validates the
    /// epoch against its pinned chain in [`History::adopt_group_epoch`] before adopting any
    /// membership change.
    GroupRosterUpdate {
        sender_identity_key: String,
        epoch: GroupEpoch,
        /// Group meta carried for a newcomer (adopted only when the epoch creates the group).
        name: String,
        disappearing_secs: Option<u64>,
        avatar: Option<String>,
    },
    /// A message sent to a group we're in.
    GroupMessage {
        sender_identity_key: String,
        group_id: String,
        msg_id: String,
        body: String,
        sent_at: u64,
        /// The sender's carried group timer (see [`InboundEvent::Message::expire_secs`]).
        expire_secs: Option<u64>,
        /// Set when the message quotes another in the same group thread.
        reply: Option<ReplyRef>,
        /// Forwarded from another conversation ("Forwarded" tag).
        forwarded: bool,
    },
    /// A member edited one of their earlier group messages.
    GroupMessageEdited {
        sender_identity_key: String,
        group_id: String,
        msg_id: String,
        body: String,
    },
    /// A member deleted one of their earlier group messages for everyone.
    GroupMessageDeleted {
        sender_identity_key: String,
        group_id: String,
        msg_id: String,
    },
    /// A member renamed the group (any member may — same trust model as the roster).
    GroupRenamed {
        sender_identity_key: String,
        group_id: String,
        name: String,
    },
    /// The sender left the group; drop them from the roster.
    GroupMemberLeft {
        sender_identity_key: String,
        group_id: String,
    },
    /// An attachment sent to a group we're in. Download + decrypt with
    /// [`Client::download_attachment`], exactly like a 1:1 [`InboundEvent::Attachment`].
    GroupAttachment {
        sender_identity_key: String,
        group_id: String,
        msg_id: String,
        attachment: AttachmentRef,
        sent_at: u64,
        /// The sender's carried group timer (see [`InboundEvent::Message::expire_secs`]).
        expire_secs: Option<u64>,
        /// Forwarded from another conversation ("Forwarded" tag).
        forwarded: bool,
    },
    /// A member changed the group's disappearing-messages timer. `None` = off.
    GroupTimerUpdate {
        sender_identity_key: String,
        group_id: String,
        disappearing_secs: Option<u64>,
    },
    /// The peer changed their username (same identity key, new name).
    Renamed {
        sender_identity_key: String,
        new_username: String,
    },
    /// The peer set (or cleared) their profile picture. Applied under the same authenticated
    /// identity as everything else on the ratchet; the value is bounded + format-checked
    /// before it is stored (see [`crate::history::valid_avatar`]). `avatar == None` clears it.
    ProfileUpdate {
        sender_identity_key: String,
        avatar: Option<String>,
    },
    /// A group member set (or cleared) the group's picture (fanned out pairwise like the
    /// group timer). Any member may change it — same trust model as the roster/name.
    GroupAvatarUpdate {
        sender_identity_key: String,
        group_id: String,
        avatar: Option<String>,
    },
    /// One of our OWN other devices changed our profile picture (self-sync); adopt it so
    /// every device shows the same picture. Honored only from a verified own device.
    SelfProfileUpdate {
        sender_identity_key: String,
        avatar: Option<String>,
    },
    /// The peer is calling. Ephemeral: never stored in history (the key must not touch
    /// disk); the shell rings and answers over the ratchet.
    CallOffered {
        sender_identity_key: String,
        sender_username: String,
        call_id: String,
        key_b64: String,
        ts: u64,
        /// The caller's media capabilities (see [`media::peer_supports_media2`]).
        caps: Vec<String>,
        /// Non-empty ⇒ silent resume of the named dropped call (see
        /// [`ChatPayload::CallOffer::reconnect_of`]); never ring on it.
        reconnect_of: String,
    },
    /// The peer accepted/declined our call offer.
    CallAnswered {
        sender_identity_key: String,
        call_id: String,
        accept: bool,
        /// The callee's media capabilities.
        caps: Vec<String>,
        /// `true` = automatic busy decline from one of the callee's devices; the ring
        /// ends only when every ringed device declined (see [`ChatPayload::CallAnswer`]).
        busy: bool,
    },
    /// The peer hung up / cancelled the call.
    CallEnded {
        sender_identity_key: String,
        call_id: String,
    },
    /// A group member offered us our pair leg of a group call (see
    /// [`ChatPayload::GroupCallOffer`]). Ephemeral: never stored (the key must not touch
    /// disk). Doubles as presence: the sender is in call `call_instance`.
    GroupCallOffered {
        sender_identity_key: String,
        sender_username: String,
        group_id: String,
        call_instance: String,
        call_id: String,
        key_b64: String,
        ts: u64,
    },
    /// A group member declined / left / cancelled group call `call_instance`.
    GroupCallEnded {
        sender_identity_key: String,
        group_id: String,
        call_instance: String,
    },
    /// One of our OWN other devices sent a message we should show as outgoing (self-sync).
    /// `sender_identity_key` is the originating own-device's key (verified as ours).
    SelfSentText {
        sender_identity_key: String,
        peer_key: String,
        peer_username: String,
        msg_id: String,
        body: String,
        sent_at: u64,
        reply: Option<ReplyRef>,
        /// Our timer at send time (see [`InboundEvent::Message::expire_secs`]).
        expire_secs: Option<u64>,
        /// Forwarded from another conversation (mirrored tag).
        forwarded: bool,
    },
    /// One of our own devices sent an attachment (self-sync).
    SelfSentFile {
        sender_identity_key: String,
        peer_key: String,
        peer_username: String,
        msg_id: String,
        attachment: AttachmentRef,
        /// Our timer at send time (see [`InboundEvent::Message::expire_secs`]).
        expire_secs: Option<u64>,
        /// Forwarded from another conversation (mirrored tag).
        forwarded: bool,
    },
    /// One of our own devices marked a conversation read (self-sync).
    SelfReadSeen {
        sender_identity_key: String,
        peer_key: String,
        ids: Vec<String>,
    },
    /// One of our own devices answered/declined the ring for `call_id` — stop ringing
    /// here. Ephemeral; the shell must verify the sender is a verified own device.
    SelfCallHandled {
        sender_identity_key: String,
        call_id: String,
    },
    /// One of our own (linked) devices asked us (the primary) to re-export history because
    /// its transfer expired. The shell prompts for the account password and calls
    /// [`Client::fulfill_resync`]. Honored only from our own verified device.
    SyncRequested {
        sender_identity_key: String,
        provisioning_id: String,
        link_secret_b64: String,
    },
    /// Our primary device offered to make THIS device the account's primary (see
    /// [`ChatPayload::PrimaryTransfer`]). The shell must verify the sender is our own
    /// current primary, confirm with the user + account password, then call
    /// [`Client::accept_primary_transfer`](crate::Client::accept_primary_transfer).
    PrimaryTransferOffered {
        sender_identity_key: String,
        entry: KtEntry,
        demoted: DeviceRecord,
    },
    /// Our primary device forwarded a message it received from a legacy sender (see
    /// [`ChatPayload::ForwardIncoming`]). Recorded as an incoming message from `from_key`.
    ForwardedIncoming {
        sender_identity_key: String,
        from_key: String,
        from_username: String,
        msg_id: String,
        body: String,
        sent_at: u64,
        reply: Option<ReplyRef>,
        attachment: Option<AttachmentRef>,
        /// The original message's carried timer, passed through by our primary.
        expire_secs: Option<u64>,
    },
    /// The peer toggled an emoji reaction on a 1:1 message (see [`ChatPayload::Reaction`]).
    Reaction {
        sender_identity_key: String,
        target_msg_id: String,
        emoji: String,
        add: bool,
    },
    /// One of our own devices toggled a reaction (self-sync); mirror it locally.
    SelfReaction {
        sender_identity_key: String,
        peer_key: String,
        target_msg_id: String,
        emoji: String,
        add: bool,
    },
    /// One of our own devices changed the disappearing-timer for a conversation
    /// (self-sync); adopt the same timer locally. Only honored when the sender is a
    /// verified member of our own roster.
    SelfTimerUpdate {
        sender_identity_key: String,
        peer_key: String,
        disappearing_secs: Option<u64>,
    },
    /// A group member toggled an emoji reaction on a group message.
    GroupReaction {
        sender_identity_key: String,
        group_id: String,
        target_msg_id: String,
        emoji: String,
        add: bool,
    },
    /// The peer (or we, from another device via the 1:1 fan-out) pinned/unpinned a
    /// message in a 1:1 conversation. Either side may pin — shared metadata.
    MessagePinned {
        sender_identity_key: String,
        msg_id: String,
        pin: bool,
    },
    /// One of our own devices pinned/unpinned a message (self-sync); mirror it locally.
    SelfMessagePinned {
        sender_identity_key: String,
        peer_key: String,
        msg_id: String,
        pin: bool,
    },
    /// A group member pinned/unpinned a message in a group thread.
    GroupMessagePinned {
        sender_identity_key: String,
        group_id: String,
        msg_id: String,
        pin: bool,
    },
    /// The peer is (or stopped) typing in a 1:1 conversation. Ephemeral — never persisted.
    Typing {
        sender_identity_key: String,
        typing: bool,
    },
    /// A group member is (or stopped) typing. Ephemeral — never persisted.
    GroupTyping {
        sender_identity_key: String,
        group_id: String,
        typing: bool,
    },
}

impl InboundEvent {
    /// The authenticated sender (ratchet identity key) of any inbound event — the value
    /// block lists key on.
    pub fn sender_identity_key(&self) -> &str {
        match self {
            InboundEvent::Message {
                sender_identity_key,
                ..
            }
            | InboundEvent::TimerUpdate {
                sender_identity_key,
                ..
            }
            | InboundEvent::ChatDeleted {
                sender_identity_key,
            }
            | InboundEvent::Knock {
                sender_identity_key,
                ..
            }
            | InboundEvent::MessageEdited {
                sender_identity_key,
                ..
            }
            | InboundEvent::MessageDeleted {
                sender_identity_key,
                ..
            }
            | InboundEvent::Receipt {
                sender_identity_key,
                ..
            }
            | InboundEvent::Attachment {
                sender_identity_key,
                ..
            }
            | InboundEvent::PeerHead {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupRosterUpdate {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupMessage {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupMessageEdited {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupMessageDeleted {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupRenamed {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupMemberLeft {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupAttachment {
                sender_identity_key,
                ..
            }
            | InboundEvent::Renamed {
                sender_identity_key,
                ..
            }
            | InboundEvent::ProfileUpdate {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupAvatarUpdate {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfProfileUpdate {
                sender_identity_key,
                ..
            }
            | InboundEvent::CallOffered {
                sender_identity_key,
                ..
            }
            | InboundEvent::CallAnswered {
                sender_identity_key,
                ..
            }
            | InboundEvent::CallEnded {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupCallOffered {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupCallEnded {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfSentText {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfSentFile {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfReadSeen {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfCallHandled {
                sender_identity_key,
                ..
            }
            | InboundEvent::ForwardedIncoming {
                sender_identity_key,
                ..
            }
            | InboundEvent::SyncRequested {
                sender_identity_key,
                ..
            }
            | InboundEvent::PrimaryTransferOffered {
                sender_identity_key,
                ..
            }
            | InboundEvent::Reaction {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfReaction {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfTimerUpdate {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupTimerUpdate {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupReaction {
                sender_identity_key,
                ..
            }
            | InboundEvent::MessagePinned {
                sender_identity_key,
                ..
            }
            | InboundEvent::SelfMessagePinned {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupMessagePinned {
                sender_identity_key,
                ..
            }
            | InboundEvent::Typing {
                sender_identity_key,
                ..
            }
            | InboundEvent::GroupTyping {
                sender_identity_key,
                ..
            } => sender_identity_key,
        }
    }
}
