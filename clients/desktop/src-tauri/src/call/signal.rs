//! Inbound **encrypted** call signalling: the offers, answers, winners and terminals that
//! ride the ratchet, dispatched from the delivery loop and converged with this device's
//! call state.
//!
//! [`handle_call_signal`] is the one entry point, and it hands the shapes that own enough
//! rules to be their own subject straight on — group signalling to [`super::group_signal`]
//! and [`super::group_offer`], self-sync to [`super::self_signal`], and the answer race to
//! [`super::claim`]. What stays is the 1:1 path plus [`end_local_call_state`], the single
//! cascade that ends a call whichever delivery layer said so.

use super::auth::{same_peer, valid_offer_shape, verified_sender_device, verified_sender_route};
use crate::*;

/// Inbound call signaling, forwarded by the delivery loop (after its lock is released).
pub(crate) async fn handle_call_signal(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    event: InboundEvent,
) {
    if matches!(&event, InboundEvent::SelfCallTerminalV2 { .. }) {
        super::self_signal::handle_self_call_terminal(inner, event).await;
        return;
    }
    if matches!(
        &event,
        InboundEvent::GroupCallAnswerClaimedV2 { .. }
            | InboundEvent::GroupCallWinnerV2 { .. }
            | InboundEvent::GroupCallTerminalV2 { .. }
    ) {
        super::group_signal::handle_group_answer_signal(inner, client, event).await;
        return;
    }
    if matches!(&event, InboundEvent::GroupCallOfferedV2 { .. }) {
        super::group_offer::handle_group_call_offer(inner, client, event).await;
        return;
    }
    match event {
        InboundEvent::CallOfferedV2 {
            sender_identity_key,
            sender_username,
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
        } => {
            let mut s = inner.lock().await;
            if !valid_offer_shape(
                &[&call_instance_id, &offer_id],
                &call_id,
                &key_b64,
                created_at,
                ring_expires_at,
                expires_at,
                now_secs(),
            ) || (!resume_of.is_empty() && !client_core::callstate::valid_call_id(&resume_of))
                || !verified_sender_route(
                    client,
                    &s.history,
                    &sender_username,
                    &sender_identity_key,
                    &caller_device_id,
                    &reply_to_mailbox,
                )
            {
                return;
            }
            // A reconnect-marked offer NEVER rings and is never declined: it either
            // silently resumes the dropped call it names — same authenticated peer
            // device only — or it is silently dropped (this device wasn't in that
            // call: another of our devices was, or the call is long gone).
            if !resume_of.is_empty() {
                let matches = s.reconnect.as_ref().is_some_and(|r| {
                    r.old_call_id == resume_of
                        && r.call_instance_id == call_instance_id
                        && same_peer(&s.history, &sender_identity_key, &r.peer_key)
                });
                if !matches {
                    return;
                }
                match s.calls().registry.receive_resume(
                    &call_instance_id,
                    &offer_id,
                    created_at,
                    expires_at,
                    now_secs(),
                ) {
                    client_core::callstate::ResumeDecision::Accepted
                    | client_core::callstate::ResumeDecision::Duplicate => {}
                    client_core::callstate::ResumeDecision::Suppressed(_)
                    | client_core::callstate::ResumeDecision::Expired
                    | client_core::callstate::ResumeDecision::Invalid
                    | client_core::callstate::ResumeDecision::Stale
                    | client_core::callstate::ResumeDecision::Missing => return,
                }
                let rc = s.reconnect.take().expect("checked above");
                let peer_media2 = client_core::media::peer_supports_media2(&caps);
                // Joining the resumed room is a network wait: release the lock for it.
                drop(s);
                if spawn_call(
                    inner,
                    client,
                    call_instance_id,
                    offer_id,
                    rc.ring_handle.clone(),
                    call_id.clone(),
                    key_b64,
                    rc.peer_username,
                    rc.peer_key.clone(),
                    reply_to_mailbox,
                    false,
                    peer_media2,
                    1,
                )
                .await
                .is_err()
                {
                    let mut s = inner.lock().await;
                    log_call_event(
                        &mut s,
                        &rc.peer_key,
                        &call_end_label("Call", false, rc.connected_at),
                    );
                    eng().emit("call", serde_json::json!({ "kind": "ended" }));
                    return;
                }
                // Resumed session: keep the original connect time for the history chip.
                if let Some(c) = inner
                    .lock()
                    .await
                    .call
                    .as_mut()
                    .filter(|c| c.call_id == call_id)
                {
                    c.connected_at
                        .store(rc.connected_at, std::sync::atomic::Ordering::Relaxed);
                    c.peer_device_key = sender_identity_key;
                }
                spawn_reconnect_window(inner.clone(), call_id);
                return;
            }
            let retention = call_retention_secs(&s);
            let decision = s.calls().registry.receive_offer(
                &call_instance_id,
                &offer_id,
                created_at,
                ring_expires_at,
                now_secs(),
                retention,
            );
            // Both layers key one registry record, so a capsule that announced this same
            // ring first makes the encrypted offer a "duplicate". It is not one: it is the
            // layer that carries the media capability, and therefore the only one that can
            // produce an answerable ring. It takes the pending capsule ring — and its
            // presentation handle — over, so one logical call rings once.
            let adopted = adopt_capsule_ring(&mut s, &call_instance_id, &offer_id);
            match decision {
                client_core::callstate::OfferDecision::Ring => {}
                client_core::callstate::OfferDecision::Duplicate if adopted.is_some() => {}
                client_core::callstate::OfferDecision::Duplicate
                | client_core::callstate::OfferDecision::Suppressed(_)
                | client_core::callstate::OfferDecision::Expired
                | client_core::callstate::OfferDecision::Invalid
                | client_core::callstate::OfferDecision::Capacity => return,
            }
            // Opaque, single-use, and never the media room id: this is what the
            // notification, the Telecom call, and every cancellation are keyed by.
            let ring_handle = adopted.unwrap_or_else(client_core::callstate::random_call_id);
            let username = if sender_username.is_empty() {
                s.history
                    .username_for_peer(&sender_identity_key)
                    .unwrap_or_else(|| sender_identity_key.chars().take(8).collect())
            } else {
                sender_username
            };
            // Busy (in a call, reconnecting one, or already ringing), or blocked:
            // auto-decline.
            let blocked = s.history.peer_blocked(&sender_identity_key);
            if !call_slot_free(&s) || blocked {
                if blocked {
                    let _ = send_call_terminal_to_device(
                        client,
                        &mut s,
                        &sender_identity_key,
                        &reply_to_mailbox,
                        &call_instance_id,
                        &offer_id,
                        client_core::callstate::CallTerminalReason::DeclinedHere,
                    );
                } else {
                    let _ = send_call_busy_to_origin(
                        client,
                        &mut s,
                        &sender_identity_key,
                        &reply_to_mailbox,
                        &call_instance_id,
                        &offer_id,
                    );
                }
                let _ = s.persist();
                return;
            }
            s.incoming = Some(PendingOffer {
                call_instance_id: call_instance_id.clone(),
                offer_id: offer_id.clone(),
                ring_handle: ring_handle.clone(),
                call_id: call_id.clone(),
                key_b64,
                username: username.clone(),
                peer_key: sender_identity_key,
                caller_device_id,
                caller_reply_to_mailbox: reply_to_mailbox,
                expires_at,
                caps,
            });
            eng().emit(
                "call",
                serde_json::json!({ "kind": "incoming", "username": username }),
            );
            let ring_name = ring_title(&s, &username);
            // Core-Telecom owns the call itself — it rings on the phone, the watch, the
            // headset and the car, and it survives this Activity. The notification below
            // is its presentation, skipped when the app is already on screen (the in-app
            // ring UI handles that, avoiding double audio).
            eng().start_system_call(&ring_handle, &ring_name, false, true);
            if !eng().on_screen() {
                eng().show_ring(&ring_handle, &ring_name, false);
            }
            // This device already accepted the platform's answer and was waiting for the
            // vault; the offer it needs has just arrived.
            resume_unlock_for(inner, &s, &call_instance_id);
            // Unanswered ring expires by itself (the caller times out too).
            let inner = inner.clone();
            eng().spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(
                    ring_expires_at.saturating_sub(now_secs()),
                ))
                .await;
                let mut s = inner.lock().await;
                if let Some(o) = s
                    .incoming
                    .take_if(|o| o.call_instance_id == call_instance_id)
                {
                    eng().cancel_ring(&o.ring_handle, &ring_name);
                    record_call_terminal(
                        &mut s,
                        &o.call_instance_id,
                        &o.offer_id,
                        client_core::callstate::CallTerminalReason::Expired,
                    );
                    log_call_event(&mut s, &o.peer_key, "📞 Missed call");
                    eng().emit("call", serde_json::json!({ "kind": "missed" }));
                }
            });
        }
        InboundEvent::CallAnswerClaimedV2 {
            sender_identity_key,
            call_instance_id,
            offer_id,
            claim_nonce,
            answering_device_id,
            reply_to_mailbox,
            caps,
            expires_at,
        } => {
            apply_answer_claim(
                inner,
                client,
                BufferedClaim {
                    sender_identity_key,
                    call_instance_id,
                    offer_id,
                    claim_nonce,
                    answering_device_id,
                    reply_to_mailbox,
                    caps,
                    expires_at,
                },
            )
            .await;
        }
        InboundEvent::CallWinnerV2 {
            sender_identity_key,
            call_instance_id,
            offer_id,
            claim_nonce,
            winner_device_id,
            expires_at,
        } => {
            let mut s = inner.lock().await;
            if !client_core::callstate::valid_control_expiry(expires_at, now_secs()) {
                return;
            }
            let my_device_id = s.history.self_device_id();
            let Some(origin) = s
                .claiming
                .as_ref()
                .map(|pending| &pending.offer)
                .or(s.incoming.as_ref())
                .filter(|offer| {
                    offer.call_instance_id == call_instance_id
                        && offer.offer_id == offer_id
                        && offer.peer_key == sender_identity_key
                        && offer.expires_at >= now_secs()
                })
            else {
                return;
            };
            if !verified_sender_device(
                &s.history,
                &origin.username,
                &sender_identity_key,
                &origin.caller_device_id,
            ) {
                return;
            }
            if winner_device_id == my_device_id {
                let Some(pending) = s.claiming.take_if(|pending| {
                    pending.offer.call_instance_id == call_instance_id
                        && pending.offer.offer_id == offer_id
                        && pending.offer.peer_key == sender_identity_key
                        && pending.claim_nonce == claim_nonce
                        && pending.answering_device_id == winner_device_id
                        && pending.offer.expires_at >= now_secs()
                }) else {
                    return;
                };
                let offer = pending.offer;
                let _ = s.calls().registry.transition(
                    &call_instance_id,
                    &offer_id,
                    client_core::callstate::CallPhase::Winner,
                    now_secs(),
                );
                let peer_media2 = client_core::media::peer_supports_media2(&offer.caps);
                // We won: join the room with the lock released, then take it back to
                // install the call and tell our siblings to stop ringing.
                //
                // The claim has been taken out of `s.claiming`, so nothing but this task
                // holds the ring handle any more, and `spawn_call` installs `s.call` only on
                // success — its `Err` is the proof that this device gave up, and the system
                // call the ring created has to go with it or the next `addCall` meets an
                // occupied slot.
                let ring_handle = offer.ring_handle.clone();
                // Kept back from the move below, so a failed setup can tell the caller. See
                // the `is_err` branch.
                let caller_key = offer.peer_key.clone();
                let caller_mailbox = offer.caller_reply_to_mailbox.clone();
                drop(s);
                if spawn_call(
                    inner,
                    client,
                    call_instance_id.clone(),
                    offer_id.clone(),
                    ring_handle.clone(),
                    offer.call_id,
                    offer.key_b64,
                    offer.username,
                    offer.peer_key,
                    offer.caller_reply_to_mailbox,
                    false,
                    peer_media2,
                    1,
                )
                .await
                .is_err()
                {
                    let mut s = inner.lock().await;
                    record_call_terminal(
                        &mut s,
                        &call_instance_id,
                        &offer_id,
                        client_core::callstate::CallTerminalReason::TransportError,
                    );
                    // Tell the caller we gave up. It named us the winner and is waiting for
                    // media that is never coming, and nothing else on this path would ever
                    // say so — it would sit on "ringing…" until its own timeout while this
                    // device had already given up and cleared its screen.
                    crate::diag!(
                        "[call] we won the answer but could not bring the call up — telling \
                         the caller (TransportError)"
                    );
                    let _ = send_call_terminal_to_device(
                        client,
                        &mut s,
                        &caller_key,
                        &caller_mailbox,
                        &call_instance_id,
                        &offer_id,
                        client_core::callstate::CallTerminalReason::TransportError,
                    );
                    drop(s);
                    eng().end_system_call(&ring_handle, telecom::cause::ERROR);
                    eng().emit("call", serde_json::json!({ "kind": "ended" }));
                    return;
                }
                eng().emit("call", serde_json::json!({ "kind": "accepted" }));
                ring_terminal_selfsync(
                    client,
                    &mut *inner.lock().await,
                    &call_instance_id,
                    &offer_id,
                    client_core::callstate::CallTerminalReason::AnsweredElsewhere,
                );
            } else {
                let mut cancelled_ring = None;
                if let Some(offer) = s
                    .incoming
                    .take_if(|offer| offer.call_instance_id == call_instance_id)
                {
                    cancelled_ring = Some(offer.ring_handle);
                }
                // We answered and lost. The ring lives in `claiming` by then, not in
                // `incoming`, so this is the branch that used to leave the loser's system
                // call connecting forever — the simultaneous-answer case of §3.5.
                if let Some(pending) = s
                    .claiming
                    .take_if(|pending| pending.offer.call_instance_id == call_instance_id)
                {
                    eng().end_system_call(
                        &pending.offer.ring_handle,
                        telecom::cause::ANSWERED_ELSEWHERE,
                    );
                }
                record_call_terminal(
                    &mut s,
                    &call_instance_id,
                    &offer_id,
                    client_core::callstate::CallTerminalReason::AnsweredElsewhere,
                );
                if let Some(ring_handle) = cancelled_ring {
                    eng().cancel_ring(&ring_handle, "");
                }
                eng().emit(
                    "call",
                    handled_event(client_core::callstate::CallTerminalReason::AnsweredElsewhere),
                );
            }
        }
        InboundEvent::CallBusyV2 {
            sender_identity_key,
            call_instance_id,
            offer_id,
            device_id,
            expires_at,
            ..
        } => {
            let mut s = inner.lock().await;
            if !client_core::callstate::valid_control_expiry(expires_at, now_secs()) {
                return;
            }
            let Some((peer_username, peer_key)) = s
                .call
                .as_ref()
                .filter(|call| call.call_instance_id == call_instance_id)
                .map(|call| (call.peer_username.clone(), call.peer_key.clone()))
            else {
                return;
            };
            if !same_peer(&s.history, &sender_identity_key, &peer_key)
                || !verified_sender_device(
                    &s.history,
                    &peer_username,
                    &sender_identity_key,
                    &device_id,
                )
            {
                return;
            }
            let end_ring = s
                .call
                .as_mut()
                .filter(|call| {
                    call.caller
                        && call.call_instance_id == call_instance_id
                        && call.offer_id == offer_id
                        && !call.connected.load(std::sync::atomic::Ordering::Relaxed)
                })
                .is_some_and(|call| {
                    if call.busy_devices.insert(device_id) {
                        call.ring_fanout = call.ring_fanout.saturating_sub(1);
                    }
                    call.ring_fanout == 0
                });
            if end_ring {
                if let Some(call) = s
                    .call
                    .take_if(|call| call.call_instance_id == call_instance_id)
                {
                    let _ = call.stop.send(true);
                    record_call_terminal(
                        &mut s,
                        &call_instance_id,
                        &offer_id,
                        client_core::callstate::CallTerminalReason::Busy,
                    );
                    log_call_event(&mut s, &call.peer_key, &call_end_label("Call", true, 0));
                    eng().emit("call", serde_json::json!({ "kind": "no_answer" }));
                }
            }
        }
        InboundEvent::CallTerminalV2 {
            sender_identity_key,
            sender_username,
            call_instance_id,
            offer_id,
            reason,
            actor_device_id,
            expires_at,
        } => {
            let mut s = inner.lock().await;
            if !client_core::callstate::valid_control_expiry(expires_at, now_secs()) {
                return;
            }
            let expected_peer = s
                .call
                .as_ref()
                .filter(|call| call.call_instance_id == call_instance_id)
                .map(|call| (call.peer_key.clone(), call.peer_username.clone()))
                .or_else(|| {
                    s.incoming
                        .as_ref()
                        .filter(|offer| offer.call_instance_id == call_instance_id)
                        .map(|offer| (offer.peer_key.clone(), offer.username.clone()))
                })
                .or_else(|| {
                    s.claiming
                        .as_ref()
                        .filter(|claim| claim.offer.call_instance_id == call_instance_id)
                        .map(|claim| (claim.offer.peer_key.clone(), claim.offer.username.clone()))
                })
                .or_else(|| {
                    s.reconnect
                        .as_ref()
                        .filter(|reconnect| reconnect.call_instance_id == call_instance_id)
                        .map(|reconnect| {
                            (reconnect.peer_key.clone(), reconnect.peer_username.clone())
                        })
                });
            let expected_username = if let Some((peer_key, username)) = expected_peer {
                if !same_peer(&s.history, &sender_identity_key, &peer_key) {
                    return;
                }
                username
            } else {
                sender_username
            };
            if !verified_sender_device(
                &s.history,
                &expected_username,
                &sender_identity_key,
                &actor_device_id,
            ) {
                return;
            }
            let terminal = match record_call_terminal(&mut s, &call_instance_id, &offer_id, reason)
            {
                client_core::callstate::TerminalDecision::Applied(reason)
                | client_core::callstate::TerminalDecision::Duplicate(reason) => reason,
                client_core::callstate::TerminalDecision::Conflict
                | client_core::callstate::TerminalDecision::Invalid
                | client_core::callstate::TerminalDecision::Capacity => return,
            };
            // A capsule may have announced this call before the offer arrived; the
            // terminal ends it on both layers.
            adopt_capsule_ring(&mut s, &call_instance_id, &offer_id);
            end_local_call_state(&mut s, &call_instance_id, terminal);
        }
        _ => {}
    }
}

/// End whatever this device holds for `call_instance_id`, with an authenticated reason.
///
/// One cascade, reached from both delivery layers: the encrypted terminal control and a
/// terminal **capsule**. Keeping it in one place is the point — the capsule layer exists
/// precisely for the cases the encrypted one cannot reach, so the two drifting apart
/// would be invisible until a phone was left ringing.
///
/// Every branch owes the same three things: drop the state, take the system call down
/// with an honest cause, and tell the user which of the six outcomes actually happened.
pub(crate) fn end_local_call_state(
    s: &mut Session,
    call_instance_id: &str,
    terminal: client_core::callstate::CallTerminalReason,
) {
    // A call ending logged **nothing**, anywhere, which is the hole the 2026-08-01 round
    // fell into: the caller's own log went silent between placing a call and refusing the
    // answer to it, so "who ended this, and which of my states was holding it" could not be
    // asked at all. E-14 gave the *claim* path this treatment and stopped there.
    crate::diag!(
        "[call] ending local call state ({terminal:?}) — holds: call={} incoming={} \
         claiming={} reconnect={}",
        s.call
            .as_ref()
            .is_some_and(|c| c.call_instance_id == call_instance_id),
        s.incoming
            .as_ref()
            .is_some_and(|o| o.call_instance_id == call_instance_id),
        s.claiming
            .as_ref()
            .is_some_and(|c| c.offer.call_instance_id == call_instance_id),
        s.reconnect
            .as_ref()
            .is_some_and(|r| r.call_instance_id == call_instance_id),
    );
    if let Some(call) = s
        .call
        .take_if(|call| call.call_instance_id == call_instance_id)
    {
        let _ = call.stop.send(true);
        // The system call ends with the authenticated reason, not a generic one:
        // the platform's call log is user-visible, and "answered on another
        // device" is not "rejected here".
        eng().end_system_call(&call.ring_handle, disconnect_cause(terminal));
        log_call_event(
            s,
            &call.peer_key,
            &call_end_label(
                "Call",
                call.caller,
                call.connected_at.load(std::sync::atomic::Ordering::Relaxed),
            ),
        );
        eng().emit("call", serde_json::json!({ "kind": "ended" }));
    } else if let Some(offer) = s
        .incoming
        .take_if(|offer| offer.call_instance_id == call_instance_id)
    {
        let name = ring_title(s, &offer.username);
        eng().cancel_ring(&offer.ring_handle, &name);
        if terminal == client_core::callstate::CallTerminalReason::CallerCancelled {
            log_call_event(s, &offer.peer_key, "📞 Missed call");
            eng().emit("call", serde_json::json!({ "kind": "missed" }));
        } else {
            eng().emit("call", handled_event(terminal));
        }
    } else if let Some(pending) = s
        .claiming
        .take_if(|pending| pending.offer.call_instance_id == call_instance_id)
    {
        // This device answered and was waiting to hear whether it won. The ring
        // notification is already gone (`accept_ring` cleared it) but the system
        // call is still up — it must not outlive the claim.
        eng().end_system_call(&pending.offer.ring_handle, disconnect_cause(terminal));
        eng().emit("call", handled_event(terminal));
        log_call_event(s, &pending.offer.peer_key, "📞 Call ended");
    } else if let Some(rc) = s
        .reconnect
        .take_if(|reconnect| reconnect.call_instance_id == call_instance_id)
    {
        eng().end_system_call(&rc.ring_handle, disconnect_cause(terminal));
        // The drop was actually the peer hanging up — end, don't resume.
        log_call_event(
            s,
            &rc.peer_key,
            &call_end_label("Call", true, rc.connected_at),
        );
        eng().emit("call", serde_json::json!({ "kind": "ended" }));
    }
}
