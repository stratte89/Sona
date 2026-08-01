use super::auth::{
    valid_offer_shape, verified_group_coordinator, verified_group_member, verified_sender_device,
};
use crate::*;

/// An inbound group-call OFFER: the ring itself, and every later member's leg for a call
/// already accepted. Split out of `signal.rs` (size ratchet) — the answer-side group
/// controls live in `group_signal.rs`, and everything here is the offer path.
pub(crate) async fn handle_group_call_offer(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    event: InboundEvent,
) {
    match event {
        InboundEvent::GroupCallOfferedV2 {
            sender_identity_key,
            sender_username,
            group_id,
            call_instance_id: call_instance,
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
        } => {
            let mut s = inner.lock().await;
            if !valid_offer_shape(
                &[&call_instance, &ring_id, &offer_id],
                &call_id,
                &key_b64,
                created_at,
                ring_expires_at,
                expires_at,
                now_secs(),
            ) || !verified_sender_device(
                &s.history,
                &sender_username,
                &sender_identity_key,
                &caller_device_id,
            ) {
                return;
            }
            let Some(group) = s.history.group(&group_id).cloned() else {
                return;
            };
            if !verified_group_member(&s.history, &group, &sender_identity_key) {
                return;
            }
            let coordinator_ok = verified_group_coordinator(
                client,
                &s.history,
                &group,
                &coordinator_username,
                &coordinator_identity_key,
                &coordinator_device_id,
                &coordinator_reply_to_mailbox,
            );
            if !coordinator_ok
                || (sender_identity_key == coordinator_identity_key
                    && (caller_device_id != coordinator_device_id
                        || sender_username != coordinator_username))
            {
                return;
            }
            let active_match = s.group_call.as_ref().is_some_and(|call| {
                call.call_instance == call_instance
                    && call.ring_id == ring_id
                    && call.coordinator.identity_key == coordinator_identity_key
                    && call.coordinator.device_id == coordinator_device_id
            });
            if resume && !active_match {
                return;
            }
            // A group ring's registry record is keyed by `ring_id`, and so is the capsule
            // that may have announced it first — take that presentation over, exactly as
            // the 1:1 path does, or a locked phone that already showed the generic ring
            // gets a second one when the encrypted offer lands.
            let mut adopted = None;
            let retention = call_retention_secs(&s); // before `s.calls()` borrows mutably
            if !resume && !active_match {
                match s.calls().registry.receive_offer(
                    &call_instance,
                    &ring_id,
                    created_at,
                    ring_expires_at,
                    now_secs(),
                    retention,
                ) {
                    client_core::callstate::OfferDecision::Ring => {
                        adopted = adopt_capsule_ring(&mut s, &call_instance, &ring_id);
                    }
                    client_core::callstate::OfferDecision::Duplicate => {
                        adopted = adopt_capsule_ring(&mut s, &call_instance, &ring_id);
                        // A capsule made this a "duplicate": it is not one — this is the
                        // layer carrying the media capability, so it owns the ring now.
                        // Without a capsule to adopt, a real duplicate offer from a second
                        // member is still expected here (each member offers its own leg).
                    }
                    client_core::callstate::OfferDecision::Suppressed(_)
                    | client_core::callstate::OfferDecision::Expired
                    | client_core::callstate::OfferDecision::Invalid
                    | client_core::callstate::OfferDecision::Capacity => return,
                }
            }
            let username = if sender_username.is_empty() {
                s.history
                    .username_for_peer(&sender_identity_key)
                    .unwrap_or_else(|| sender_identity_key.chars().take(8).collect())
            } else {
                sender_username
            };

            // Already in this call: the offer is presence + ticket — start the leg.
            // A fresh offer also un-marks a departed member (they are rejoining) and
            // resets their re-offer budget.
            if let Some(gc) = s.group_call.as_mut().filter(|g| {
                g.call_instance == call_instance
                    && g.ring_id == ring_id
                    && g.coordinator.identity_key == coordinator_identity_key
                    && g.coordinator.device_id == coordinator_device_id
                    && (resume
                        || (g.deadline.created_at == created_at
                            && g.deadline.ring_expires_at == ring_expires_at
                            && g.deadline.expires_at == expires_at))
            }) {
                gc.departed.remove(&username);
                gc.reoffer_attempts.remove(&username);
                eng().spawn(establish_group_leg(
                    inner.clone(),
                    client.clone(),
                    call_instance,
                    sender_identity_key,
                    username,
                    Some((call_id, key_b64)),
                ));
                return;
            }
            if resume {
                return;
            }
            // Already ringing for this call: collect the ticket for the accept.
            if let Some(pending) = s.group_incoming.as_mut().filter(|o| {
                o.call_instance == call_instance
                    && o.ring_id == ring_id
                    && o.coordinator.identity_key == coordinator_identity_key
                    && o.coordinator.device_id == coordinator_device_id
                    && o.deadline.created_at == created_at
                    && o.deadline.ring_expires_at == ring_expires_at
                    && o.deadline.expires_at == expires_at
            }) {
                pending
                    .offers
                    .insert(sender_identity_key, (username, call_id, key_b64));
                return;
            }
            if let Some(pending) = s.group_claiming.as_mut().filter(|claim| {
                claim.offer.call_instance == call_instance
                    && claim.offer.ring_id == ring_id
                    && claim.offer.coordinator.identity_key == coordinator_identity_key
                    && claim.offer.coordinator.device_id == coordinator_device_id
                    && claim.offer.deadline.created_at == created_at
                    && claim.offer.deadline.ring_expires_at == ring_expires_at
                    && claim.offer.deadline.expires_at == expires_at
            }) {
                pending
                    .offer
                    .offers
                    .insert(sender_identity_key, (username, call_id, key_b64));
                return;
            }
            // Busy with anything else, or the sender is blocked: silent decline for
            // this instance only (mirrors the 1:1 auto-decline).
            if !call_slot_free(&s) || s.history.peer_blocked(&sender_identity_key) {
                let actor_device_id = s.history.self_device_id();
                let control_expires_at =
                    now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
                let envelope = {
                    let sess = &mut *s;
                    let Some(account) = sess.account.as_mut() else {
                        return;
                    };
                    let contact = contact_for(&username, &sender_identity_key);
                    client
                        .prepare_group_call_terminal_v2(
                            account,
                            &contact,
                            &group_id,
                            &call_instance,
                            &ring_id,
                            client_core::callstate::CallTerminalReason::Busy,
                            &actor_device_id,
                            &coordinator_username,
                            &coordinator_identity_key,
                            &coordinator_device_id,
                            control_expires_at,
                        )
                        .ok()
                };
                if let Some(envelope) = envelope {
                    let _ = post_call_controls(client, &mut s, &[envelope]);
                }
                return;
            }
            // Fresh ring.
            let group_name = group.name.clone();
            let ring_handle = adopted.unwrap_or_else(client_core::callstate::random_call_id);
            s.group_incoming = Some(PendingGroupOffer {
                call_instance: call_instance.clone(),
                ring_id: ring_id.clone(),
                ring_handle: ring_handle.clone(),
                group_id,
                group_name: group_name.clone(),
                rang_by_username: username.clone(),
                coordinator: GroupCoordinator {
                    username: coordinator_username,
                    identity_key: coordinator_identity_key,
                    device_id: coordinator_device_id,
                    reply_to_mailbox: coordinator_reply_to_mailbox,
                },
                deadline: GroupRingDeadline {
                    created_at,
                    ring_expires_at,
                    expires_at,
                },
                offers: std::collections::HashMap::from([(
                    sender_identity_key,
                    (username.clone(), call_id, key_b64),
                )]),
            });
            eng().emit(
                "group_call",
                serde_json::json!({ "kind": "incoming", "name": group_name, "from": username }),
            );
            // Native group ring — identical path to 1:1 with the group name as the
            // display name; skipped when the app is on screen (in-app UI rings).
            // Headset-button session starts unconditionally, same as 1:1.
            let ring_name = ring_title(&s, &group_name);
            eng().start_system_call(&ring_handle, &ring_name, false, true);
            if !eng().on_screen() {
                eng().show_ring(&ring_handle, &ring_name, true);
            }
            let inner = inner.clone();
            eng().spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(
                    ring_expires_at.saturating_sub(now_secs()),
                ))
                .await;
                let mut s = inner.lock().await;
                if let Some(o) = s
                    .group_incoming
                    .take_if(|o| o.call_instance == call_instance)
                {
                    eng().cancel_ring(&o.ring_handle, &ring_name);
                    let _ = record_call_terminal(
                        &mut s,
                        &o.call_instance,
                        &o.ring_id,
                        client_core::callstate::CallTerminalReason::Expired,
                    );
                    log_group_call_event(
                        &mut s,
                        &o.group_id,
                        &format!("📞 Missed group call from {}", o.rang_by_username),
                    );
                    eng().emit("group_call", serde_json::json!({ "kind": "missed" }));
                }
            });
        }
        _ => {}
    }
}
