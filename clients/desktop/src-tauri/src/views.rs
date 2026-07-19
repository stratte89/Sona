use super::*;

#[derive(Serialize)]
pub(crate) struct StrengthView {
    pub(crate) acceptable: bool,
    pub(crate) problems: Vec<String>,
}

/// What screen the UI should show on launch / after a command.
#[derive(Serialize, Default)]
pub(crate) struct StatusView {
    pub(crate) configured: bool,
    pub(crate) has_vault: bool,
    pub(crate) unlocked: bool,
    pub(crate) account_id: Option<String>,
    pub(crate) base_url: Option<String>,
    /// The relay told this (unlocked) device it was revoked from its account — the UI
    /// must show the lockout screen instead of chats.
    pub(crate) revoked: bool,
    /// An access token is configured for this relay (private relay). Drives the
    /// invite-QR button in settings — meaningless to show for an open relay.
    pub(crate) private_relay: bool,
}

/// One row in the chat list — a 1:1 chat or a group.
#[derive(Serialize)]
pub(crate) struct ConvView {
    /// "chat" or "group".
    pub(crate) kind: &'static str,
    /// 1:1: peer identity key. Group: the group id.
    pub(crate) peer: String,
    /// 1:1: the username. Group: the group name.
    pub(crate) username: String,
    pub(crate) last_body: String,
    pub(crate) last_ts: u64,
    pub(crate) last_outgoing: bool,
    pub(crate) verified: bool,
    pub(crate) timer_secs: Option<u64>,
    pub(crate) has_messages: bool,
    /// Incoming messages not yet seen (drives the chat-list unread badge).
    pub(crate) unread: usize,
    /// The last message is an attachment (the UI shows "Sent an image/file", not the name).
    pub(crate) last_attachment: bool,
    /// The last message is a voice message (preview shows "Voice message").
    pub(crate) last_voice: bool,
    /// Local prefs (1:1 only; all stored inside the encrypted history).
    pub(crate) pinned: bool,
    pub(crate) muted_until: Option<u64>,
    pub(crate) nickname: Option<String>,
    pub(crate) blocked: bool,
    /// Profile picture (`data:` image URI) for this row: the peer's broadcast picture for a
    /// 1:1, or the group's picture for a group. `None` ⇒ the UI renders a generated initial.
    pub(crate) avatar: Option<String>,
    /// Group only: member count.
    pub(crate) members: usize,
    /// Hidden behind the collapsed "Archived" row (1:1 only).
    pub(crate) archived: bool,
    /// Manually marked unread — show the badge even with no unseen messages.
    pub(crate) manual_unread: bool,
    /// The reserved note-to-self row (special icon, no verify/call surface).
    pub(crate) note: bool,
}

/// One message in a thread.
#[derive(Serialize)]
pub(crate) struct MsgView {
    pub(crate) msg_id: String,
    pub(crate) direction: &'static str,
    pub(crate) body: String,
    pub(crate) sent_at: u64,
    /// Unix time this message disappears (drives the per-message countdown badge).
    /// `None` = the conversation's timer was off when it was sent.
    pub(crate) delete_at: Option<u64>,
    pub(crate) attachment: bool,
    /// The attachment is a voice message (render a player, not a file chip).
    pub(crate) voice: bool,
    /// Voice messages: recorded length in seconds.
    pub(crate) duration_secs: u32,
    /// Delivery state for outgoing messages: "sent" | "delivered" | "seen".
    pub(crate) status: &'static str,
    pub(crate) edited: bool,
    pub(crate) reply_to_id: Option<String>,
    pub(crate) reply_preview: Option<String>,
    /// Emoji reactions grouped by emoji with a count; `mine` marks our own.
    pub(crate) reactions: Vec<ReactionView>,
    /// Optional caption sent with an attachment.
    pub(crate) caption: Option<String>,
    /// Voice waveform peaks (0–255); empty ⇒ the player uses a flat bar.
    pub(crate) peaks: Vec<u8>,
    /// A local system-event chip (rendered centered, not as a bubble).
    pub(crate) system: bool,
    /// Incoming and not yet seen — drives the "new messages" divider on open.
    pub(crate) unread: bool,
    /// Pinned in this conversation (drives the pinned banner).
    pub(crate) pinned: bool,
    /// Forwarded from another conversation (drives the "Forwarded" tag).
    pub(crate) forwarded: bool,
}

/// One emoji reaction group for the UI: the emoji, how many reacted with it, and whether
/// one of them is us.
#[derive(Serialize)]
pub(crate) struct ReactionView {
    pub(crate) emoji: String,
    pub(crate) count: usize,
    pub(crate) mine: bool,
    /// Who reacted, as display names (drives the "+N more" details sheet). Built with
    /// raw reactor keys ("" = us) by [`group_reactions`]; the thread commands resolve
    /// them to names before serializing (only they can see the roster).
    pub(crate) reactors: Vec<String>,
}

/// Group a message's flat reaction list into per-emoji counts, flagging our own (the
/// reactor stored as the empty string). `reactors` holds the raw keys — callers map
/// them to display names via [`resolve_reactors`].
pub(crate) fn group_reactions(reactions: &[client_core::history::Reaction]) -> Vec<ReactionView> {
    let mut out: Vec<ReactionView> = Vec::new();
    for r in reactions {
        if let Some(v) = out.iter_mut().find(|v| v.emoji == r.emoji) {
            v.count += 1;
            v.mine |= r.reactor.is_empty();
            v.reactors.push(r.reactor.clone());
        } else {
            out.push(ReactionView {
                emoji: r.emoji.clone(),
                count: 1,
                mine: r.reactor.is_empty(),
                reactors: vec![r.reactor.clone()],
            });
        }
    }
    out
}

/// Replace raw reactor keys with display names ("" = the local user → "You").
pub(crate) fn resolve_reactors(reactions: &mut [ReactionView], name_of: impl Fn(&str) -> String) {
    for r in reactions {
        for who in &mut r.reactors {
            *who = if who.is_empty() {
                "You".to_string()
            } else {
                name_of(who)
            };
        }
    }
}

pub(crate) fn status_str(s: DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Sent => "sent",
        DeliveryStatus::Delivered => "delivered",
        DeliveryStatus::Seen => "seen",
    }
}

impl From<&StoredMessage> for MsgView {
    fn from(m: &StoredMessage) -> Self {
        MsgView {
            msg_id: m.msg_id.clone(),
            direction: match m.direction {
                Direction::Outgoing => "outgoing",
                Direction::Incoming => "incoming",
            },
            body: m.body.clone(),
            sent_at: m.sent_at,
            delete_at: m.delete_at,
            attachment: m.attachment.is_some(),
            voice: m.attachment.as_ref().is_some_and(|a| a.voice),
            duration_secs: m.attachment.as_ref().map_or(0, |a| a.duration_secs),
            status: status_str(m.status),
            edited: m.edited,
            reply_to_id: m.reply.as_ref().map(|r| r.msg_id.clone()),
            reply_preview: m.reply.as_ref().map(|r| r.preview.clone()),
            reactions: group_reactions(&m.reactions),
            caption: m.attachment.as_ref().and_then(|a| a.caption.clone()),
            peaks: m
                .attachment
                .as_ref()
                .map(|a| a.peaks.clone())
                .unwrap_or_default(),
            system: m.system,
            unread: matches!(m.direction, Direction::Incoming) && !m.seen_receipted && !m.system,
            pinned: m.pinned,
            forwarded: m.forwarded,
        }
    }
}

/// Refuse to open/send/call a conversation with ourselves. Checked by name (cheap,
/// catches the common case before any network round-trip) and by identity key after
/// resolution (catches our own former usernames, which still resolve to our key).
pub(crate) fn ensure_not_self(
    account: &Account,
    username: &str,
    identity_key: Option<&str>,
) -> Result<(), String> {
    if username == account.account_id()
        || identity_key.is_some_and(|k| k == account.ratchet_ref().identity_key())
    {
        return Err("that's your own account — you can't message yourself".into());
    }
    Ok(())
}

/// Result of opening / resolving a contact by username. `status` is the discriminator:
/// `new` (first contact, session started), `unchanged` (known key, session started), or
/// `key_changed` (the published key differs from the pin — **no session started**; the UI
/// must have the user compare `safety_number` out-of-band and explicitly accept).
#[derive(Serialize)]
pub(crate) struct OpenChatView {
    pub(crate) status: &'static str,
    pub(crate) peer: String,
    pub(crate) username: String,
    pub(crate) safety_number: String,
    pub(crate) verified: bool,
    pub(crate) previous_key: Option<String>,
}

/// A conversation's messages (oldest first) plus its settings the thread UI shows
/// (disappearing timer). `messages` is a WINDOW — the newest `limit` messages, extended
/// backwards to include the first unread and the requested anchor — so a years-long
/// thread never serializes whole on every repaint. `pinned` is window-independent (the
/// pin banner must show a pin however old it is).
#[derive(Serialize)]
pub(crate) struct ThreadView {
    pub(crate) messages: Vec<MsgView>,
    pub(crate) timer_secs: Option<u64>,
    /// Total messages in the conversation (drives the new-arrivals counter).
    pub(crate) total: usize,
    /// Older messages exist above the returned window (drives load-earlier).
    pub(crate) more: bool,
    /// Every pinned message, oldest first, regardless of the window.
    pub(crate) pinned: Vec<MsgView>,
}

#[derive(Serialize)]
pub(crate) struct GroupMsgView {
    pub(crate) msg_id: String,
    pub(crate) body: String,
    pub(crate) sent_at: u64,
    /// Unix time this message disappears (per-message countdown badge). `None` = the
    /// group's timer was off when it was sent.
    pub(crate) delete_at: Option<u64>,
    /// Display name of the sender (from the roster), or a key prefix if unknown.
    pub(crate) sender_name: String,
    pub(crate) mine: bool,
    pub(crate) reactions: Vec<ReactionView>,
    pub(crate) system: bool,
    /// Attachment fields — same shape as the 1:1 `MsgView` so the webview reuses the
    /// exact same renderers (image preview, file chip, voice player).
    pub(crate) attachment: bool,
    pub(crate) voice: bool,
    pub(crate) duration_secs: u32,
    pub(crate) caption: Option<String>,
    pub(crate) peaks: Vec<u8>,
    /// The body was edited after sending.
    pub(crate) edited: bool,
    /// Set when this message quotes another (same shape as the 1:1 `MsgView`).
    pub(crate) reply_to_id: Option<String>,
    pub(crate) reply_preview: Option<String>,
    /// Incoming and not yet seen — drives the "new messages" divider on open.
    pub(crate) unread: bool,
    /// Pinned in this group (drives the pinned banner).
    pub(crate) pinned: bool,
    /// Forwarded from another conversation ("Forwarded" tag).
    pub(crate) forwarded: bool,
}

#[derive(Serialize)]
pub(crate) struct GroupThreadView {
    pub(crate) name: String,
    pub(crate) members: Vec<String>,
    pub(crate) messages: Vec<GroupMsgView>,
    /// The group's disappearing-messages timer (drives the header chip + settings).
    pub(crate) timer_secs: Option<u64>,
    /// The group's picture (`data:` image URI), or `None` for the generated fallback.
    pub(crate) avatar: Option<String>,
    /// We left (or were removed from) this group: thread readable, composer disabled.
    pub(crate) left: bool,
    /// For an admin-model group, the admin's username; `None` for a legacy (egalitarian)
    /// group. Drives the "Admin: <name>" affordance.
    pub(crate) admin: Option<String>,
    /// This device is the group's admin (may add/remove members and transfer the role). The
    /// UI gates the add/remove/transfer affordances on this.
    pub(crate) is_admin: bool,
    /// Total messages in the group (drives the new-arrivals counter).
    pub(crate) total: usize,
    /// Older messages exist above the returned window (drives load-earlier).
    pub(crate) more: bool,
    /// Every pinned message, oldest first, regardless of the window.
    pub(crate) pinned: Vec<GroupMsgView>,
}

/// Start index of a thread window: the newest `limit` messages, extended backwards so
/// the first unread (the "new messages" divider) and an explicitly requested anchor
/// (jump-to-quote / jump-to-pin) always render.
pub(crate) fn window_start(
    len: usize,
    limit: Option<usize>,
    first_unread: Option<usize>,
    anchor_idx: Option<usize>,
) -> usize {
    let mut start = len.saturating_sub(limit.unwrap_or(usize::MAX).max(1));
    if let Some(i) = first_unread {
        start = start.min(i);
    }
    if let Some(i) = anchor_idx {
        start = start.min(i);
    }
    start
}

pub(crate) fn group_from_record(group_id: &str, g: &client_core::GroupRecord) -> Group {
    Group {
        id: group_id.to_string(),
        name: g.name.clone(),
        members: g.members.clone(),
    }
}

/// The names of groups this user belongs to (for the "Add to group" picker).
#[derive(Serialize)]
pub(crate) struct GroupListItem {
    pub(crate) group_id: String,
    pub(crate) name: String,
    pub(crate) members: usize,
}

#[derive(Serialize)]
pub(crate) struct DeviceView {
    pub(crate) device_id: String,
    pub(crate) is_this_device: bool,
    pub(crate) is_primary: bool,
}

/// Hardware-attestation verdict for a scanned link request (advisory, shown in the
/// authorize dialog). `status`: "verified" | "failed" | "absent" (no attestation —
/// desktop/older linkers) | "unavailable" (promised but couldn't be fetched/unsealed).
#[derive(Serialize)]
pub(crate) struct AttestView {
    pub(crate) status: String,
    /// Human detail: hardware level + boot state on "verified", the reason otherwise.
    pub(crate) detail: String,
}

#[derive(Serialize)]
pub(crate) struct LinkCompleteView {
    pub(crate) account_id: String,
    /// `false` = the device is linked and works, but pre-existing history did not transfer
    /// (blob expired) — the UI should offer a re-sync.
    pub(crate) history_synced: bool,
}

/// Everything the lock screen and the settings' security section need in one shot.
#[derive(Serialize)]
pub(crate) struct SecurityView {
    pub(crate) pin_set: bool,
    pub(crate) pin_attempts_left: u32,
    pub(crate) auto_unlock: bool,
    pub(crate) bio_enabled: bool,
    /// This build/device can offer biometric unlock (Android + strong biometric enrolled).
    pub(crate) bio_available: bool,
    /// What the OS presence step of a change ceremony would use:
    /// "biometric" | "credential" | "none" (skipped).
    pub(crate) os_auth: &'static str,
    /// PIN and auto-unlock need the OS keyring / Keystore device key.
    pub(crate) device_key_available: bool,
    pub(crate) lock_after_secs: Option<u64>,
    pub(crate) pin_reminder_every: Option<u32>,
    /// Minimum PIN length that authorizes username/password changes.
    pub(crate) ceremony_min_pin_len: usize,
}

/// The Privacy settings the UI renders (typing indicators, read receipts, notification
/// content level).
#[derive(Serialize)]
pub(crate) struct PrivacyView {
    pub(crate) send_typing: bool,
    pub(crate) send_receipts: bool,
    pub(crate) notif_level: String,
}

/// What the UI needs to render call state after a reload.
#[derive(Serialize)]
pub(crate) struct CallStatusView {
    pub(crate) active: Option<serde_json::Value>,
    pub(crate) incoming: Option<serde_json::Value>,
    pub(crate) reconnecting: Option<serde_json::Value>,
    pub(crate) group_active: Option<serde_json::Value>,
    pub(crate) group_incoming: Option<serde_json::Value>,
}

/// What the notifications-settings screen renders (mode, live state, capabilities,
/// Android health probes).
#[derive(Serialize)]
pub(crate) struct DeliveryView {
    pub(crate) mode: String,
    /// "connected" | "reconnecting" | "locked" | "off"
    pub(crate) conn: &'static str,
    /// The relay accepts `fcm:` endpoints (advertised capability).
    pub(crate) relay_fcm: bool,
    /// The relay fires webhook wakes (always true on this relay version).
    pub(crate) relay_webhook: bool,
    /// A registered push endpoint exists for this device.
    pub(crate) push_registered: bool,
    /// An FCM token is available on this device (Play Services answered).
    pub(crate) push_token: bool,
    /// A live UnifiedPush endpoint from the chosen distributor exists.
    pub(crate) up_endpoint: bool,
    /// Android health probes (battery exemption, notif permission, FSI, Play
    /// Services); `null` on desktop.
    pub(crate) health: Option<serde_json::Value>,
}
