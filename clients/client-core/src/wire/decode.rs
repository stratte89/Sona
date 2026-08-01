//! Server-frame decoding: one WS frame in, one [`Decoded`] out. Split from the
//! payload definitions in `wire/mod.rs` so neither side grows back into a monolith.

use super::ChatPayload;
use crate::*;

/// What a decoded server WS frame means to the client.
// `Event` wraps an `InboundEvent`, which is intentionally a wide enum (every message and
// control-message shape). A `Decoded` is a short-lived, one-at-a-time value in the delivery
// loop, never stored in bulk, so the size spread is not worth a `Box` (which would ripple
// deref/clone changes through every shell match site).
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Decoded {
    /// The server has flushed the queued backlog; frames after this are real-time.
    Ready,
    /// The server rejected our signed challenge — reconnect with a fresh nonce.
    AuthFailed,
    /// This device's mailbox no longer exists: revoked from the roster (or account
    /// deleted). Terminal — unlink locally, do not reconnect.
    Revoked,
    /// A decrypted inbound event. Apply it, then [`Subscription::ack`] `ack_msg_id`.
    Event {
        event: InboundEvent,
        ack_msg_id: String,
    },
    /// Nothing to deliver. When `ack_msg_id` is `Some`, the frame was a message this
    /// account can **never** decrypt (corrupt, replayed after the ratchet advanced, or
    /// not for us) — ack it anyway, or it sits in the mailbox forever, is redelivered on
    /// every reconnect, and eventually fills the mailbox cap so *new* messages bounce.
    Ignore { ack_msg_id: Option<String> },
}

pub(crate) fn ack_frame(msg_id: &str) -> String {
    json!({ "type": "ack", "msg_id": msg_id }).to_string()
}

/// Parse one server frame: an inbound message becomes a decrypted [`InboundEvent`] to
/// deliver + ack. Undecryptable/malformed message frames come back as
/// [`Decoded::Ignore`] *with their msg_id* so the caller can purge them (see enum docs).
pub fn decode_frame(text: &str, account: &mut Account) -> Decoded {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Decoded::Ignore { ack_msg_id: None };
    };
    match v["type"].as_str() {
        Some("ready") => Decoded::Ready,
        Some("auth_failed") => Decoded::AuthFailed,
        Some("revoked") => Decoded::Revoked,
        Some("message") => {
            // Salvage the msg_id even off frames we end up unable to decode, so they can
            // still be acked out of the mailbox.
            let raw_id = v["envelope"]["msg_id"].as_str().map(str::to_string);
            let ignore = |id: Option<String>| Decoded::Ignore { ack_msg_id: id };
            let Ok(envelope) = serde_json::from_value::<Envelope>(v["envelope"].clone()) else {
                return ignore(raw_id);
            };
            let Ok(cipher) = serde_json::from_str::<CiphertextMessage>(&envelope.ciphertext) else {
                return ignore(raw_id);
            };
            let Ok((sender, wire)) = account.ratchet().decrypt_unattributed(&cipher) else {
                return ignore(raw_id); // not for us / corrupt / already consumed
            };
            let parsed = STANDARD_NO_PAD
                .decode(&wire)
                .ok()
                .and_then(|padded| padding::unpad(&padded))
                .and_then(|json| serde_json::from_slice::<ChatPayload>(&json).ok());
            let event = match parsed {
                Some(ChatPayload::Text {
                    body,
                    ts,
                    from,
                    reply,
                    expire_secs,
                    fwd,
                }) => InboundEvent::Message {
                    sender_identity_key: sender,
                    sender_username: from,
                    msg_id: envelope.msg_id.clone(),
                    body,
                    sent_at: ts,
                    reply,
                    expire_secs,
                    forwarded: fwd,
                },
                Some(ChatPayload::Knock { from }) => InboundEvent::Knock {
                    sender_identity_key: sender,
                    sender_username: from,
                },
                Some(ChatPayload::Edit { msg_id, body }) => InboundEvent::MessageEdited {
                    sender_identity_key: sender,
                    msg_id,
                    body,
                },
                Some(ChatPayload::DeleteMsg { msg_id }) => InboundEvent::MessageDeleted {
                    sender_identity_key: sender,
                    msg_id,
                },
                Some(ChatPayload::Timer { secs }) => InboundEvent::TimerUpdate {
                    sender_identity_key: sender,
                    disappearing_secs: secs,
                },
                Some(ChatPayload::File {
                    attachment,
                    from,
                    expire_secs,
                    fwd,
                }) => {
                    let sent_at = attachment.ts;
                    InboundEvent::Attachment {
                        sender_identity_key: sender,
                        sender_username: from,
                        msg_id: envelope.msg_id.clone(),
                        attachment,
                        sent_at,
                        expire_secs,
                        forwarded: fwd,
                    }
                }
                Some(ChatPayload::DeleteChat {}) => InboundEvent::ChatDeleted {
                    sender_identity_key: sender,
                },
                Some(ChatPayload::Receipt { ids, seen }) => InboundEvent::Receipt {
                    sender_identity_key: sender,
                    ids,
                    seen,
                },
                Some(ChatPayload::Gossip { head }) => InboundEvent::PeerHead {
                    sender_identity_key: sender,
                    head,
                },
                Some(ChatPayload::GroupRoster {
                    epoch,
                    name,
                    disappearing_secs,
                    avatar,
                }) => InboundEvent::GroupRosterUpdate {
                    sender_identity_key: sender,
                    epoch,
                    name,
                    disappearing_secs,
                    avatar,
                },
                Some(ChatPayload::GroupText {
                    group_id,
                    body,
                    ts,
                    expire_secs,
                    reply,
                    fwd,
                }) => InboundEvent::GroupMessage {
                    sender_identity_key: sender,
                    group_id,
                    msg_id: envelope.msg_id.clone(),
                    body,
                    sent_at: ts,
                    expire_secs,
                    reply,
                    forwarded: fwd,
                },
                Some(ChatPayload::GroupEdit {
                    group_id,
                    msg_id,
                    body,
                }) => InboundEvent::GroupMessageEdited {
                    sender_identity_key: sender,
                    group_id,
                    msg_id,
                    body,
                },
                Some(ChatPayload::GroupDeleteMsg { group_id, msg_id }) => {
                    InboundEvent::GroupMessageDeleted {
                        sender_identity_key: sender,
                        group_id,
                        msg_id,
                    }
                }
                Some(ChatPayload::GroupRename { group_id, name }) => InboundEvent::GroupRenamed {
                    sender_identity_key: sender,
                    group_id,
                    name,
                },
                Some(ChatPayload::GroupLeave { group_id }) => InboundEvent::GroupMemberLeft {
                    sender_identity_key: sender,
                    group_id,
                },
                Some(ChatPayload::GroupFile {
                    group_id,
                    attachment,
                    ts,
                    expire_secs,
                    fwd,
                }) => InboundEvent::GroupAttachment {
                    sender_identity_key: sender,
                    group_id,
                    msg_id: envelope.msg_id.clone(),
                    attachment,
                    sent_at: ts,
                    expire_secs,
                    forwarded: fwd,
                },
                Some(ChatPayload::GroupTimer { group_id, secs }) => {
                    InboundEvent::GroupTimerUpdate {
                        sender_identity_key: sender,
                        group_id,
                        disappearing_secs: secs,
                    }
                }
                Some(ChatPayload::Rename { new_username }) => InboundEvent::Renamed {
                    sender_identity_key: sender,
                    new_username,
                },
                Some(ChatPayload::Profile { avatar }) => InboundEvent::ProfileUpdate {
                    sender_identity_key: sender,
                    avatar,
                },
                Some(ChatPayload::GroupAvatar { group_id, avatar }) => {
                    InboundEvent::GroupAvatarUpdate {
                        sender_identity_key: sender,
                        group_id,
                        avatar,
                    }
                }
                Some(ChatPayload::CallOfferV2 {
                    call_instance_id,
                    offer_id,
                    call_id,
                    key_b64,
                    created_at,
                    ring_expires_at,
                    expires_at,
                    from,
                    caller_device_id,
                    reply_to_mailbox,
                    caps,
                    resume_of,
                }) => InboundEvent::CallOfferedV2 {
                    sender_identity_key: sender,
                    sender_username: from,
                    call_instance_id,
                    offer_id,
                    call_id,
                    key_b64,
                    created_at,
                    ring_expires_at,
                    expires_at,
                    caller_device_id,
                    reply_to_mailbox,
                    caps,
                    resume_of,
                },
                Some(ChatPayload::CallAnswerClaimV2 {
                    call_instance_id,
                    offer_id,
                    claim_nonce,
                    answering_device_id,
                    reply_to_mailbox,
                    caps,
                    expires_at,
                }) => InboundEvent::CallAnswerClaimedV2 {
                    sender_identity_key: sender,
                    call_instance_id,
                    offer_id,
                    claim_nonce,
                    answering_device_id,
                    reply_to_mailbox,
                    caps,
                    expires_at,
                },
                Some(ChatPayload::CallWinnerV2 {
                    call_instance_id,
                    offer_id,
                    claim_nonce,
                    winner_device_id,
                    expires_at,
                }) => InboundEvent::CallWinnerV2 {
                    sender_identity_key: sender,
                    call_instance_id,
                    offer_id,
                    claim_nonce,
                    winner_device_id,
                    expires_at,
                },
                Some(ChatPayload::CallBusyV2 {
                    call_instance_id,
                    offer_id,
                    device_id,
                    expires_at,
                }) => InboundEvent::CallBusyV2 {
                    sender_identity_key: sender,
                    call_instance_id,
                    offer_id,
                    device_id,
                    expires_at,
                },
                Some(ChatPayload::CallTerminalV2 {
                    call_instance_id,
                    offer_id,
                    reason,
                    from,
                    actor_device_id,
                    expires_at,
                }) => InboundEvent::CallTerminalV2 {
                    sender_identity_key: sender,
                    sender_username: from,
                    call_instance_id,
                    offer_id,
                    reason,
                    actor_device_id,
                    expires_at,
                },
                Some(ChatPayload::GroupCallOfferV2 {
                    group_id,
                    call_instance_id,
                    ring_id,
                    offer_id,
                    call_id,
                    key_b64,
                    created_at,
                    ring_expires_at,
                    expires_at,
                    from,
                    caller_device_id,
                    coordinator_username,
                    coordinator_identity_key,
                    coordinator_device_id,
                    coordinator_reply_to_mailbox,
                    resume,
                }) => InboundEvent::GroupCallOfferedV2 {
                    sender_identity_key: sender,
                    sender_username: from,
                    group_id,
                    call_instance_id,
                    ring_id,
                    offer_id,
                    call_id,
                    key_b64,
                    created_at,
                    ring_expires_at,
                    expires_at,
                    caller_device_id,
                    coordinator_username,
                    coordinator_identity_key,
                    coordinator_device_id,
                    coordinator_reply_to_mailbox,
                    resume,
                },
                Some(ChatPayload::GroupCallAnswerClaimV2 {
                    group_id,
                    call_instance_id,
                    ring_id,
                    claim_nonce,
                    answering_device_id,
                    reply_to_mailbox,
                    expires_at,
                }) => InboundEvent::GroupCallAnswerClaimedV2 {
                    sender_identity_key: sender,
                    group_id,
                    call_instance_id,
                    ring_id,
                    claim_nonce,
                    answering_device_id,
                    reply_to_mailbox,
                    expires_at,
                },
                Some(ChatPayload::GroupCallWinnerV2 {
                    group_id,
                    call_instance_id,
                    ring_id,
                    claim_nonce,
                    winner_device_id,
                    expires_at,
                }) => InboundEvent::GroupCallWinnerV2 {
                    sender_identity_key: sender,
                    group_id,
                    call_instance_id,
                    ring_id,
                    claim_nonce,
                    winner_device_id,
                    expires_at,
                },
                Some(ChatPayload::GroupCallTerminalV2 {
                    group_id,
                    call_instance_id,
                    ring_id,
                    reason,
                    actor_device_id,
                    coordinator_username,
                    coordinator_identity_key,
                    coordinator_device_id,
                    expires_at,
                }) => InboundEvent::GroupCallTerminalV2 {
                    sender_identity_key: sender,
                    group_id,
                    call_instance_id,
                    ring_id,
                    reason,
                    actor_device_id,
                    coordinator_username,
                    coordinator_identity_key,
                    coordinator_device_id,
                    expires_at,
                },
                Some(ChatPayload::SelfText {
                    peer_key,
                    peer_username,
                    msg_id,
                    body,
                    ts,
                    reply,
                    expire_secs,
                    fwd,
                }) => InboundEvent::SelfSentText {
                    sender_identity_key: sender,
                    peer_key,
                    peer_username,
                    msg_id,
                    body,
                    sent_at: ts,
                    reply,
                    expire_secs,
                    forwarded: fwd,
                },
                Some(ChatPayload::SelfFile {
                    peer_key,
                    peer_username,
                    msg_id,
                    attachment,
                    expire_secs,
                    fwd,
                }) => InboundEvent::SelfSentFile {
                    sender_identity_key: sender,
                    peer_key,
                    peer_username,
                    msg_id,
                    attachment,
                    expire_secs,
                    forwarded: fwd,
                },
                Some(ChatPayload::SelfSeen { peer_key, ids }) => InboundEvent::SelfReadSeen {
                    sender_identity_key: sender,
                    peer_key,
                    ids,
                },
                Some(ChatPayload::SelfCallTerminalV2 {
                    call_instance_id,
                    offer_id,
                    reason,
                    actor_device_id,
                    expires_at,
                }) => InboundEvent::SelfCallTerminalV2 {
                    sender_identity_key: sender,
                    call_instance_id,
                    offer_id,
                    reason,
                    actor_device_id,
                    expires_at,
                },
                Some(ChatPayload::SyncRequest {
                    provisioning_id,
                    link_secret_b64,
                }) => InboundEvent::SyncRequested {
                    sender_identity_key: sender,
                    provisioning_id,
                    link_secret_b64,
                },
                Some(ChatPayload::PrimaryTransfer { entry, demoted }) => {
                    InboundEvent::PrimaryTransferOffered {
                        sender_identity_key: sender,
                        entry,
                        demoted,
                    }
                }
                Some(ChatPayload::ForwardIncoming {
                    from_key,
                    from_username,
                    msg_id,
                    body,
                    ts,
                    reply,
                    attachment,
                    expire_secs,
                }) => InboundEvent::ForwardedIncoming {
                    sender_identity_key: sender,
                    from_key,
                    from_username,
                    msg_id,
                    body,
                    sent_at: ts,
                    reply,
                    attachment,
                    expire_secs,
                },
                Some(ChatPayload::Reaction {
                    target_msg_id,
                    emoji,
                    add,
                    ..
                }) => InboundEvent::Reaction {
                    sender_identity_key: sender,
                    target_msg_id,
                    emoji,
                    add,
                },
                Some(ChatPayload::SelfReaction {
                    peer_key,
                    target_msg_id,
                    emoji,
                    add,
                }) => InboundEvent::SelfReaction {
                    sender_identity_key: sender,
                    peer_key,
                    target_msg_id,
                    emoji,
                    add,
                },
                Some(ChatPayload::SelfTimer { peer_key, secs }) => InboundEvent::SelfTimerUpdate {
                    sender_identity_key: sender,
                    peer_key,
                    disappearing_secs: secs,
                },
                Some(ChatPayload::SelfProfile { avatar }) => InboundEvent::SelfProfileUpdate {
                    sender_identity_key: sender,
                    avatar,
                },
                Some(ChatPayload::GroupReaction {
                    group_id,
                    target_msg_id,
                    emoji,
                    add,
                    ..
                }) => InboundEvent::GroupReaction {
                    sender_identity_key: sender,
                    group_id,
                    target_msg_id,
                    emoji,
                    add,
                },
                Some(ChatPayload::PinMsg { msg_id, pin }) => InboundEvent::MessagePinned {
                    sender_identity_key: sender,
                    msg_id,
                    pin,
                },
                Some(ChatPayload::SelfPinMsg {
                    peer_key,
                    msg_id,
                    pin,
                }) => InboundEvent::SelfMessagePinned {
                    sender_identity_key: sender,
                    peer_key,
                    msg_id,
                    pin,
                },
                Some(ChatPayload::GroupPinMsg {
                    group_id,
                    msg_id,
                    pin,
                }) => InboundEvent::GroupMessagePinned {
                    sender_identity_key: sender,
                    group_id,
                    msg_id,
                    pin,
                },
                Some(ChatPayload::Typing { typing }) => InboundEvent::Typing {
                    sender_identity_key: sender,
                    typing,
                },
                Some(ChatPayload::GroupTyping { group_id, typing }) => InboundEvent::GroupTyping {
                    sender_identity_key: sender,
                    group_id,
                    typing,
                },
                None => return ignore(Some(envelope.msg_id)),
            };
            Decoded::Event {
                event,
                ack_msg_id: envelope.msg_id,
            }
        }
        _ => Decoded::Ignore { ack_msg_id: None },
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    // A reaction body serializes internally-tagged ("t") and round-trips.
    #[test]
    fn reaction_payload_round_trips() {
        let p = ChatPayload::Reaction {
            target_msg_id: "abc".into(),
            emoji: "🔥".into(),
            add: true,
            ts: 42,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"t\":\"reaction\""));
        match serde_json::from_str::<ChatPayload>(&json).unwrap() {
            ChatPayload::Reaction {
                target_msg_id,
                emoji,
                add,
                ..
            } => {
                assert_eq!(target_msg_id, "abc");
                assert_eq!(emoji, "🔥");
                assert!(add);
            }
            _ => panic!("wrong variant"),
        }
    }

    // An old client decoding a NEW variant it doesn't know must fail-soft (parse error),
    // which the delivery loop turns into an acked-away Ignore — never a poisoned mailbox.
    #[test]
    fn unknown_variant_degrades_gracefully() {
        let future = r#"{"t":"some_future_variant","x":1}"#;
        let parsed: Option<ChatPayload> = serde_json::from_str(future).ok();
        assert!(parsed.is_none());
    }

    // Typing is ephemeral wire-only; it still round-trips as a body.
    #[test]
    fn typing_payload_round_trips() {
        let json = serde_json::to_string(&ChatPayload::Typing { typing: true }).unwrap();
        assert!(matches!(
            serde_json::from_str::<ChatPayload>(&json).unwrap(),
            ChatPayload::Typing { typing: true }
        ));
    }

    // Every v2 call signal is explicitly short-lived and requests either a ring wake or
    // an urgent silent control wake.
    #[test]
    fn wake_classes_per_payload() {
        let text = ChatPayload::Text {
            body: "hi".into(),
            ts: 1,
            from: "a".into(),
            reply: None,
            expire_secs: None,
            fwd: false,
        };
        assert_eq!(wake_class_for(&text), WakeClass::Normal);
        let offer = |resume_of: &str| ChatPayload::CallOfferV2 {
            call_instance_id: "1".repeat(32),
            offer_id: "2".repeat(32),
            call_id: "c".into(),
            key_b64: "k".into(),
            created_at: 1,
            ring_expires_at: 46,
            expires_at: 61,
            from: "a".into(),
            caller_device_id: "0".into(),
            reply_to_mailbox: "a".repeat(64),
            caps: vec![],
            resume_of: resume_of.into(),
        };
        assert_eq!(wake_class_for(&offer("")), WakeClass::Call);
        assert_eq!(
            wake_class_for(&offer("old-media-call")),
            WakeClass::CallControl
        );
        assert_eq!(envelope_expiry_for(&offer("")), Some(61));
        let mut group_offer = ChatPayload::GroupCallOfferV2 {
            group_id: "g".into(),
            call_instance_id: "1".repeat(32),
            ring_id: "4".repeat(32),
            offer_id: "2".repeat(32),
            call_id: "c".into(),
            key_b64: "k".into(),
            created_at: 1,
            ring_expires_at: 46,
            expires_at: 61,
            from: "a".into(),
            caller_device_id: "0".into(),
            coordinator_username: "a".into(),
            coordinator_identity_key: "key".into(),
            coordinator_device_id: "0".into(),
            coordinator_reply_to_mailbox: "b".repeat(64),
            resume: false,
        };
        assert_eq!(wake_class_for(&group_offer), WakeClass::Call);
        if let ChatPayload::GroupCallOfferV2 { resume, .. } = &mut group_offer {
            *resume = true;
        }
        assert_eq!(wake_class_for(&group_offer), WakeClass::CallControl);
        for silent in [
            ChatPayload::Typing { typing: true },
            ChatPayload::Receipt {
                ids: vec!["m".into()],
                seen: true,
            },
            ChatPayload::SelfSeen {
                peer_key: "p".into(),
                ids: vec!["m".into()],
            },
        ] {
            assert_eq!(wake_class_for(&silent), WakeClass::None);
        }
        for control in [
            ChatPayload::CallAnswerClaimV2 {
                call_instance_id: "1".repeat(32),
                offer_id: "2".repeat(32),
                claim_nonce: "3".repeat(32),
                answering_device_id: "0".into(),
                reply_to_mailbox: "a".repeat(64),
                caps: vec![],
                expires_at: 61,
            },
            ChatPayload::CallWinnerV2 {
                call_instance_id: "1".repeat(32),
                offer_id: "2".repeat(32),
                claim_nonce: "3".repeat(32),
                winner_device_id: "0".into(),
                expires_at: 61,
            },
            ChatPayload::CallBusyV2 {
                call_instance_id: "1".repeat(32),
                offer_id: "2".repeat(32),
                device_id: "0".into(),
                expires_at: 61,
            },
            ChatPayload::CallTerminalV2 {
                call_instance_id: "1".repeat(32),
                offer_id: "2".repeat(32),
                reason: callstate::CallTerminalReason::CallerCancelled,
                from: "alice".into(),
                actor_device_id: "0".into(),
                expires_at: 61,
            },
            ChatPayload::GroupCallTerminalV2 {
                group_id: "g".into(),
                call_instance_id: "1".repeat(32),
                ring_id: "4".repeat(32),
                reason: callstate::CallTerminalReason::DeclinedHere,
                actor_device_id: "0".into(),
                coordinator_username: "a".into(),
                coordinator_identity_key: "key".into(),
                coordinator_device_id: "0".into(),
                expires_at: 61,
            },
            ChatPayload::GroupCallAnswerClaimV2 {
                group_id: "g".into(),
                call_instance_id: "1".repeat(32),
                ring_id: "4".repeat(32),
                claim_nonce: "3".repeat(32),
                answering_device_id: "0".into(),
                reply_to_mailbox: "a".repeat(64),
                expires_at: 61,
            },
            ChatPayload::GroupCallWinnerV2 {
                group_id: "g".into(),
                call_instance_id: "1".repeat(32),
                ring_id: "4".repeat(32),
                claim_nonce: "3".repeat(32),
                winner_device_id: "0".into(),
                expires_at: 61,
            },
            ChatPayload::SelfCallTerminalV2 {
                call_instance_id: "1".repeat(32),
                offer_id: "2".repeat(32),
                reason: callstate::CallTerminalReason::AnsweredElsewhere,
                actor_device_id: "0".into(),
                expires_at: 61,
            },
        ] {
            assert_eq!(wake_class_for(&control), WakeClass::CallControl);
            assert_eq!(envelope_expiry_for(&control), Some(61));
        }
    }

    #[test]
    fn v1_call_payloads_are_rejected() {
        for old in [
            r#"{"t":"call_offer","call_id":"c","key_b64":"k","ts":1}"#,
            r#"{"t":"call_answer","call_id":"c","accept":true}"#,
            r#"{"t":"call_end","call_id":"c"}"#,
            r#"{"t":"group_call_offer","group_id":"g","call_id":"c","key_b64":"k"}"#,
            r#"{"t":"group_call_end","group_id":"g","call_instance":"c"}"#,
            r#"{"t":"self_call_handled","call_id":"c"}"#,
        ] {
            assert!(serde_json::from_str::<ChatPayload>(old).is_err());
        }
    }

    // A caption + waveform peaks survive a round trip, and an OLD attachment JSON (without
    // either field) still decodes — backward compatible optional fields.
    #[test]
    fn attachment_caption_and_peaks_backward_compatible() {
        let a = AttachmentRef {
            blob_id: "b".into(),
            key: "k".into(),
            filename: "pic.png".into(),
            size: 10,
            content_hash: "h".into(),
            ts: 1,
            voice: false,
            duration_secs: 0,
            caption: Some("look at this".into()),
            peaks: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: AttachmentRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.caption.as_deref(), Some("look at this"));
        assert_eq!(back.peaks, vec![1, 2, 3]);

        // Legacy attachment: no caption/peaks keys at all.
        let legacy =
            r#"{"blob_id":"b","key":"k","filename":"f","size":1,"content_hash":"h","ts":1}"#;
        let old: AttachmentRef = serde_json::from_str(legacy).unwrap();
        assert_eq!(old.caption, None);
        assert!(old.peaks.is_empty());
    }
}
