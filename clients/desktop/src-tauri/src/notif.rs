//! OS-notification planning: turn an inbound event into (or suppress) a notification,
//! honoring the user's privacy level and mute state. Split from `runtime.rs` (ratchet).

use crate::*;

/// A pending OS notification: which chat it belongs to (peer key or group id, so the
/// delivery loop can suppress it when that exact chat is already open), plus the title and
/// body already tailored to the user's notification privacy level. `msg_id` feeds the
/// engine's dedup ring (drain-vs-socket handoff insurance).
pub(crate) struct NotifPlan {
    pub(crate) chat_key: String,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) msg_id: String,
}

/// True when `body` @-mentions `me` as a whole token: `@me` followed by end-of-text or a
/// character that can't be part of a username. Case-insensitive, so `@Lincoln` still
/// reaches lincoln.
pub(crate) fn mentions_user(body: &str, me: &str) -> bool {
    if me.is_empty() {
        return false;
    }
    let body = body.to_lowercase();
    let me = me.to_lowercase();
    let is_name_char = |c: char| c.is_alphanumeric() || matches!(c, '_' | '.' | '-');
    for (i, _) in body.match_indices('@') {
        // Token boundary on both sides: nothing name-like before the '@' (so an email
        // address never counts), nothing name-like right after the matched name.
        let before_ok = body[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !is_name_char(c) && c != '@');
        let after = &body[i + 1..];
        if before_ok && after.starts_with(me.as_str()) {
            let tail = &after[me.len()..];
            if tail.chars().next().is_none_or(|c| !is_name_char(c)) {
                return true;
            }
        }
    }
    false
}

/// Build the OS-notification content for an inbound event, honoring the user's privacy
/// `level` (`"sender_message"` | `"sender"` | `"generic"`). Returns `None` when it
/// shouldn't notify (muted chat/group, receipts and other non-message traffic). The
/// **default level is "sender"** — sender name, no message text; "generic" reveals nothing
/// but "New message"; "sender_message" includes a short body preview. Blocked senders never
/// reach here (dropped earlier in the delivery loop). See docs/ANDROID_HARDENING.md — the
/// content-free default matters on lock screens, so we never go above the chosen level.
/// `my_username` powers the one mute exception: an @-mention of the user in a muted group
/// still notifies (a direct call-out beats the mute, Signal-style).
pub(crate) fn notif_for_event(
    history: &History,
    event: &InboundEvent,
    level: &str,
    my_username: &str,
) -> Option<NotifPlan> {
    let now = now_secs();
    let peer_muted = |key: &str| {
        history
            .contacts()
            .into_iter()
            .any(|(_, p)| p.identity_key == key && p.muted_until.is_some_and(|t| t > now))
    };
    // The display name for a sender key (nickname > pinned username > claimed username).
    // A pending-request row is keyed by identity key, so its name comes off the request
    // via `display_name` — never from the map key (SP-02).
    let name_for = |key: &str, claimed: &str| -> String {
        for (u, p) in history.contacts() {
            if p.identity_key == key {
                return p
                    .nickname
                    .clone()
                    .unwrap_or_else(|| History::display_name(&u, &p));
            }
        }
        if claimed.is_empty() {
            "Someone".to_string()
        } else {
            claimed.to_string()
        }
    };
    let preview = |s: &str| -> String {
        let t: String = s.chars().take(120).collect();
        if s.chars().count() > 120 {
            format!("{t}…")
        } else {
            t
        }
    };
    // A message already expired on arrival (its carried timer elapsed while it sat in
    // the mailbox) must never be shown — the reaper deletes it in the same breath.
    let already_expired = |sent_at: u64, expire: &Option<u64>| match expire {
        Some(secs) if *secs > 0 => sent_at.saturating_add(*secs) <= now,
        _ => false,
    };
    let (chat_key, sender, kind_body, msg_id): (String, String, String, String) = match event {
        InboundEvent::Message {
            sender_identity_key,
            sender_username,
            body,
            msg_id,
            sent_at,
            expire_secs,
            ..
        } if !peer_muted(sender_identity_key) && !already_expired(*sent_at, expire_secs) => (
            sender_identity_key.clone(),
            name_for(sender_identity_key, sender_username),
            preview(body),
            msg_id.clone(),
        ),
        InboundEvent::Attachment {
            sender_identity_key,
            sender_username,
            attachment,
            msg_id,
            sent_at,
            expire_secs,
            ..
        } if !peer_muted(sender_identity_key) && !already_expired(*sent_at, expire_secs) => (
            sender_identity_key.clone(),
            name_for(sender_identity_key, sender_username),
            if attachment.voice {
                "Voice message".into()
            } else {
                "Sent an attachment".into()
            },
            msg_id.clone(),
        ),
        InboundEvent::GroupMessage {
            group_id,
            sender_identity_key,
            body,
            msg_id,
            sent_at,
            expire_secs,
            ..
        } if !already_expired(*sent_at, expire_secs) => {
            let g = history.group(group_id)?;
            // apply() already ran: content the roster gate quarantined (non-member
            // sender) never landed in the thread and must not notify either.
            history.group_message(group_id, msg_id)?;
            // Muted group: silent — unless the message @-mentions this user by name.
            if g.muted_until.is_some_and(|t| t > now) && !mentions_user(body, my_username) {
                return None;
            }
            (
                group_id.clone(),
                format!("{} · {}", g.name, name_for(sender_identity_key, "")),
                preview(body),
                msg_id.clone(),
            )
        }
        InboundEvent::GroupAttachment {
            group_id,
            sender_identity_key,
            attachment,
            msg_id,
            sent_at,
            expire_secs,
            ..
        } if !already_expired(*sent_at, expire_secs) => {
            let g = history.group(group_id)?;
            // Same roster-gate rule as GroupMessage: only notify what actually landed.
            history.group_message(group_id, msg_id)?;
            if g.muted_until.is_some_and(|t| t > now) {
                return None;
            }
            (
                group_id.clone(),
                format!("{} · {}", g.name, name_for(sender_identity_key, "")),
                if attachment.voice {
                    "Voice message".into()
                } else {
                    "Sent an attachment".into()
                },
                msg_id.clone(),
            )
        }
        _ => return None,
    };
    let (title, body) = match level {
        "generic" => ("Sona".to_string(), "New message".to_string()),
        "sender_message" => (sender, kind_body),
        // "sender" (default) — who, not what.
        _ => (sender, "New message".to_string()),
    };
    Some(NotifPlan {
        chat_key,
        title,
        body,
        msg_id,
    })
}

/// Notification for a NEW message request (a stranger reached out while the request
/// gate is on). Fired at most once per request lifecycle — the caller consumes the
/// history's one-shot latch first. Content-free by design at every level: the request's
/// text (if any) stays behind the requests screen, so even "sender & message" reveals
/// only who asked.
pub(crate) fn request_notif_plan(history: &History, convo: &str, level: &str) -> NotifPlan {
    let name = history
        .contacts()
        .into_iter()
        .find(|(_, p)| p.identity_key == convo)
        // Pending rows are keyed by identity key; the claimed name lives on the request.
        .map(|(k, p)| History::display_name(&k, &p))
        .unwrap_or_else(|| "Someone".to_string());
    let (title, body) = match level {
        "generic" => ("Sona".to_string(), "New message request".to_string()),
        _ => (name, "sent you a message request".to_string()),
    };
    NotifPlan {
        chat_key: convo.to_string(),
        title,
        body,
        msg_id: format!("req-{}", now_secs()),
    }
}

/// Show an OS notification unless the user is already looking at *this* chat (mobile)
/// or at the app at all (desktop) — the suppression rule lives on the engine, the
/// posting goes through the platform pipeline in `notifier.rs` (Android: the
/// activity-independent NotificationBridge, which is what makes notifications work
/// with the task removed or the process restarted headless — RC-2).
pub(crate) fn notify_now(plan: &NotifPlan) {
    if eng().suppress_notif(&plan.chat_key) {
        return;
    }
    eng().notify_message(plan);
}

#[cfg(test)]
mod tests {
    use super::{mentions_user, notif_for_event};
    use client_core::{AttachmentRef, History, InboundEvent};

    /// Voice messages and file attachments must produce a notification plan at every
    /// privacy level, exactly like a text message — a push-only device that drained an
    /// attachment event shows something, not nothing.
    #[test]
    fn attachments_and_voice_produce_notifications() {
        let history = History::new();
        let mk = |voice: bool| InboundEvent::Attachment {
            sender_identity_key: "peer-key".into(),
            sender_username: "alice".into(),
            msg_id: "m1".into(),
            attachment: AttachmentRef {
                blob_id: "b1".into(),
                key: "k".into(),
                filename: if voice { "voice.webm" } else { "pic.jpg" }.into(),
                size: 10,
                content_hash: "h".into(),
                ts: crate::now_secs(),
                voice,
                duration_secs: if voice { 3 } else { 0 },
                caption: None,
                peaks: Vec::new(),
            },
            sent_at: crate::now_secs(),
            expire_secs: None,
            forwarded: false,
        };
        // Full-preview level names the kind.
        let plan = notif_for_event(&history, &mk(true), "sender_message", "me")
            .expect("voice must notify");
        assert_eq!(plan.body, "Voice message");
        let plan = notif_for_event(&history, &mk(false), "sender_message", "me")
            .expect("file must notify");
        assert_eq!(plan.body, "Sent an attachment");
        // Default and generic levels still notify (content-free bodies).
        assert!(notif_for_event(&history, &mk(true), "sender", "me").is_some());
        assert!(notif_for_event(&history, &mk(true), "generic", "me").is_some());
        // An attachment whose carried timer already expired in the mailbox stays silent.
        let mut expired = mk(true);
        if let InboundEvent::Attachment {
            sent_at,
            expire_secs,
            ..
        } = &mut expired
        {
            *sent_at = 1;
            *expire_secs = Some(1);
        }
        assert!(notif_for_event(&history, &expired, "sender", "me").is_none());
    }

    #[test]
    fn mention_detection_respects_token_boundaries() {
        assert!(mentions_user("hey @lincoln look at this", "lincoln"));
        assert!(mentions_user("@Lincoln!", "lincoln"));
        assert!(mentions_user("@lincoln", "LINCOLN"));
        assert!(mentions_user("(@lincoln)", "lincoln"));
        assert!(!mentions_user("@lincolnburrows escaped", "lincoln")); // longer name
        assert!(!mentions_user("mail@lincoln.example", "lincoln")); // email, not a mention
        assert!(!mentions_user("no mention here", "lincoln"));
        assert!(!mentions_user("@lincoln", ""));
    }
}
