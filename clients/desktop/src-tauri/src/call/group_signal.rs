use crate::*;

use super::auth::verified_sender_device;
use super::group_control::send_group_call_winner_everywhere;

pub(super) async fn handle_group_answer_signal(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    event: InboundEvent,
) {
    match event {
        InboundEvent::GroupCallAnswerClaimedV2 {
            sender_identity_key,
            group_id,
            call_instance_id,
            ring_id,
            claim_nonce,
            answering_device_id,
            reply_to_mailbox,
            expires_at,
        } => {
            let mut s = inner.lock().await;
            if !client_core::callstate::valid_call_id(&call_instance_id)
                || !client_core::callstate::valid_call_id(&ring_id)
                || !client_core::callstate::valid_control_expiry(expires_at, now_secs())
            {
                return;
            }
            let Some(group) = s.history.group(&group_id).cloned() else {
                return;
            };
            let sender_account = s.history.attribute_device(&sender_identity_key);
            let Some(member) = group.members.iter().find(|member| {
                member.identity_key == sender_account || member.identity_key == sender_identity_key
            }) else {
                return;
            };
            let Some(ring_matches) = s
                .group_call
                .as_ref()
                .filter(|call| {
                    call.group_id == group_id
                        && call.call_instance == call_instance_id
                        && call.ring_id == ring_id
                        && call.deadline.ring_expires_at >= now_secs()
                })
                .map(|call| {
                    call.coordinator.identity_key
                        == s.account
                            .as_ref()
                            .map(|account| account.ratchet_ref().identity_key())
                            .unwrap_or_default()
                        && call.coordinator.device_id == s.history.self_device_id()
                })
            else {
                return;
            };
            if !ring_matches
                || !verified_sender_device(
                    &s.history,
                    &member.username,
                    &sender_identity_key,
                    &answering_device_id,
                )
                || client
                    .device_mailbox(&member.username, &answering_device_id)
                    .ok()
                    .as_deref()
                    != Some(reply_to_mailbox.as_str())
            {
                return;
            }
            let claim = client_core::callstate::AnswerClaim {
                call_instance_id: call_instance_id.clone(),
                offer_id: ring_id.clone(),
                claim_nonce,
                answering_device_id,
                reply_to_mailbox,
            };
            let decision = {
                let call = s.group_call.as_mut().expect("checked above");
                call.answer_arbiters
                    .entry(sender_account)
                    .or_insert_with(|| {
                        client_core::callstate::AnswerArbiter::new(
                            call_instance_id.clone(),
                            ring_id.clone(),
                        )
                    })
                    .claim(&claim)
            };
            let winner = match decision {
                client_core::callstate::ClaimDecision::Winner(ref winner)
                | client_core::callstate::ClaimDecision::Duplicate(ref winner)
                | client_core::callstate::ClaimDecision::Lost(ref winner) => winner.clone(),
                client_core::callstate::ClaimDecision::Invalid => return,
            };
            let _ = send_group_call_winner_everywhere(
                client,
                &mut s,
                &member.username,
                &sender_identity_key,
                &group_id,
                &call_instance_id,
                &ring_id,
                &winner.claim_nonce,
                &winner.answering_device_id,
                &winner.reply_to_mailbox,
            );
        }
        InboundEvent::GroupCallWinnerV2 {
            sender_identity_key,
            group_id,
            call_instance_id,
            ring_id,
            claim_nonce,
            winner_device_id,
            expires_at,
        } => {
            let mut s = inner.lock().await;
            if !client_core::callstate::valid_call_id(&call_instance_id)
                || !client_core::callstate::valid_call_id(&ring_id)
                || !client_core::callstate::valid_control_expiry(expires_at, now_secs())
            {
                return;
            }
            let my_device_id = s.history.self_device_id();
            let origin = s
                .group_claiming
                .as_ref()
                .map(|pending| &pending.offer)
                .or(s.group_incoming.as_ref())
                .filter(|offer| {
                    offer.group_id == group_id
                        && offer.call_instance == call_instance_id
                        && offer.ring_id == ring_id
                        && offer.coordinator.identity_key == sender_identity_key
                        && offer.deadline.expires_at >= now_secs()
                });
            let Some(origin) = origin else {
                return;
            };
            if !verified_sender_device(
                &s.history,
                &origin.coordinator.username,
                &sender_identity_key,
                &origin.coordinator.device_id,
            ) {
                return;
            }
            if winner_device_id == my_device_id {
                let Some(pending) = s.group_claiming.take_if(|pending| {
                    pending.offer.group_id == group_id
                        && pending.offer.call_instance == call_instance_id
                        && pending.offer.ring_id == ring_id
                        && pending.claim_nonce == claim_nonce
                        && pending.answering_device_id == winner_device_id
                }) else {
                    return;
                };
                let _ = s.calls().registry.transition(
                    &call_instance_id,
                    &ring_id,
                    client_core::callstate::CallPhase::Winner,
                    now_secs(),
                );
                // Announcing ourselves to the mesh is roster + relay + room-join work:
                // release the lock for it.
                //
                // The claim is out of `s.group_claiming`, so this task is the only holder of
                // the ring handle; a failure here is this device giving up, and the system
                // call the ring created has to go with it — the group half of the same leak.
                let ring_handle = pending.offer.ring_handle.clone();
                drop(s);
                if finish_group_call_accept(inner, client, pending.offer)
                    .await
                    .is_err()
                {
                    let mut s = inner.lock().await;
                    let _ = record_call_terminal(
                        &mut s,
                        &call_instance_id,
                        &ring_id,
                        client_core::callstate::CallTerminalReason::TransportError,
                    );
                    eng().end_system_call(&ring_handle, telecom::cause::ERROR);
                    eng().emit("group_call", serde_json::json!({ "kind": "ended" }));
                    return;
                }
                eng().emit("group_call", serde_json::json!({ "kind": "accepted" }));
            } else {
                let mut cancelled_ring = None;
                if let Some(offer) = s.group_incoming.take_if(|offer| {
                    offer.group_id == group_id
                        && offer.call_instance == call_instance_id
                        && offer.ring_id == ring_id
                }) {
                    cancelled_ring = Some(offer.ring_handle);
                }
                // We answered and another of our devices won: the ring notification went
                // with `accept_ring`, but the system call is ours to take down.
                if let Some(pending) = s.group_claiming.take_if(|pending| {
                    pending.offer.group_id == group_id
                        && pending.offer.call_instance == call_instance_id
                        && pending.offer.ring_id == ring_id
                }) {
                    eng().end_system_call(
                        &pending.offer.ring_handle,
                        telecom::cause::ANSWERED_ELSEWHERE,
                    );
                }
                let _ = record_call_terminal(
                    &mut s,
                    &call_instance_id,
                    &ring_id,
                    client_core::callstate::CallTerminalReason::AnsweredElsewhere,
                );
                if let Some(ring_handle) = cancelled_ring {
                    eng().cancel_ring(&ring_handle, "");
                }
                eng().emit(
                    "group_call",
                    handled_event(client_core::callstate::CallTerminalReason::AnsweredElsewhere),
                );
            }
        }
        InboundEvent::GroupCallTerminalV2 {
            sender_identity_key,
            group_id,
            call_instance_id: call_instance,
            ring_id,
            reason,
            actor_device_id,
            coordinator_username,
            coordinator_identity_key,
            coordinator_device_id,
            expires_at,
        } => {
            let mut s = inner.lock().await;
            let Some(sender_username) = s.history.username_for_peer(&sender_identity_key) else {
                return;
            };
            let Some(group) = s.history.group(&group_id) else {
                return;
            };
            let sender_account = s.history.attribute_device(&sender_identity_key);
            let coordinator_account = s.history.attribute_device(&coordinator_identity_key);
            let is_member = group.members.iter().any(|member| {
                member.identity_key == sender_account || member.identity_key == sender_identity_key
            });
            let coordinator_is_member = group.members.iter().any(|member| {
                member.username == coordinator_username
                    && (member.identity_key == coordinator_account
                        || member.identity_key == coordinator_identity_key)
            });
            if !client_core::callstate::valid_call_id(&call_instance)
                || !client_core::callstate::valid_call_id(&ring_id)
                || !client_core::callstate::valid_control_expiry(expires_at, now_secs())
                || !is_member
                || !coordinator_is_member
                || !verified_sender_device(
                    &s.history,
                    &sender_username,
                    &sender_identity_key,
                    &actor_device_id,
                )
                || !verified_sender_device(
                    &s.history,
                    &coordinator_username,
                    &coordinator_identity_key,
                    &coordinator_device_id,
                )
            {
                return;
            }
            let coordinator_terminal = sender_identity_key == coordinator_identity_key
                && actor_device_id == coordinator_device_id
                && matches!(
                    reason,
                    client_core::callstate::CallTerminalReason::CallerCancelled
                        | client_core::callstate::CallTerminalReason::Expired
                        | client_core::callstate::CallTerminalReason::TransportError
                );
            if coordinator_terminal
                && matches!(
                    record_call_terminal(&mut s, &call_instance, &ring_id, reason),
                    client_core::callstate::TerminalDecision::Conflict
                        | client_core::callstate::TerminalDecision::Invalid
                        | client_core::callstate::TerminalDecision::Capacity
                )
            {
                return;
            }
            if coordinator_terminal {
                if let Some(call) = s.group_call.take_if(|call| {
                    call.call_instance == call_instance
                        && call.ring_id == ring_id
                        && call.group_id == group_id
                        && call.coordinator.identity_key == coordinator_identity_key
                        && call.coordinator.device_id == coordinator_device_id
                }) {
                    let _ = call.stop.send(true);
                    eng().end_system_call(&call.ring_handle, disconnect_cause(reason));
                    log_group_call_event(
                        &mut s,
                        &call.group_id,
                        &call_end_label(
                            "Group call",
                            false,
                            call.connected_at.load(std::sync::atomic::Ordering::Relaxed),
                        ),
                    );
                    eng().emit("group_call", serde_json::json!({ "kind": "ended" }));
                    return;
                }
            }
            if let Some(call) = s.group_call.as_mut().filter(|call| {
                call.call_instance == call_instance
                    && call.ring_id == ring_id
                    && call.group_id == group_id
                    && call.coordinator.identity_key == coordinator_identity_key
                    && call.coordinator.device_id == coordinator_device_id
            }) {
                call.legs_added.remove(&sender_identity_key);
                if !sender_username.is_empty() {
                    call.departed.insert(sender_username.clone());
                }
                if !call
                    .connected
                    .lock()
                    .unwrap()
                    .contains_key(&sender_identity_key)
                {
                    eng().emit(
                        "group_call",
                        serde_json::json!({
                            "kind": "peer_declined",
                            "username": sender_username,
                        }),
                    );
                }
            } else if coordinator_terminal {
                if let Some(pending) = s.group_incoming.take_if(|pending| {
                    pending.call_instance == call_instance
                        && pending.ring_id == ring_id
                        && pending.group_id == group_id
                        && pending.coordinator.identity_key == coordinator_identity_key
                        && pending.coordinator.device_id == coordinator_device_id
                }) {
                    let name = ring_title(&s, &pending.group_name);
                    eng().cancel_ring(&pending.ring_handle, &name);
                    log_group_call_event(
                        &mut s,
                        &pending.group_id,
                        &format!("📞 Missed group call from {}", pending.rang_by_username),
                    );
                    eng().emit("group_call", serde_json::json!({ "kind": "missed" }));
                } else if let Some(pending) = s.group_claiming.take_if(|pending| {
                    pending.offer.call_instance == call_instance
                        && pending.offer.ring_id == ring_id
                        && pending.offer.group_id == group_id
                        && pending.offer.coordinator.identity_key == coordinator_identity_key
                        && pending.offer.coordinator.device_id == coordinator_device_id
                }) {
                    eng().end_system_call(&pending.offer.ring_handle, disconnect_cause(reason));
                    log_group_call_event(&mut s, &pending.offer.group_id, "📞 Group call ended");
                    eng().emit("group_call", handled_event(reason));
                }
            } else if let Some(pending) = s.group_incoming.as_mut().filter(|pending| {
                pending.call_instance == call_instance
                    && pending.ring_id == ring_id
                    && pending.group_id == group_id
            }) {
                pending.offers.remove(&sender_identity_key);
            } else if let Some(pending) = s.group_claiming.as_mut().filter(|pending| {
                pending.offer.call_instance == call_instance
                    && pending.offer.ring_id == ring_id
                    && pending.offer.group_id == group_id
            }) {
                pending.offer.offers.remove(&sender_identity_key);
            }
        }
        _ => {}
    }
}
