use super::auth::local_group_coordinator;
use crate::*;

/// Send our leave/decline to every group member and verified device. Network-free: the
/// sealed copies go to the durable control outbox, which posts them off-lock.
pub(crate) fn send_group_call_terminal_everywhere(
    client: &Arc<Client>,
    s: &mut Session,
    group_id: &str,
    call_instance: &str,
    ring_id: &str,
    coordinator: &GroupCoordinator,
    reason: client_core::callstate::CallTerminalReason,
) {
    let Some(group) = s.history.group(group_id).cloned() else {
        return;
    };
    let multi = s.multi_device;
    let actor_device_id = s.history.self_device_id();
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let sess = &mut *s;
    let Some(account) = sess.account.as_mut() else {
        return;
    };
    let me = account.account_id().to_string();
    let mut envelopes = Vec::new();
    for member in group.members.iter().filter(|member| member.username != me) {
        // Members we have no session with yet are not addressable without a network
        // round trip; the caller's off-lock warm is what opens those sessions.
        let Some(contact) = client.member_contact_pinned(account, member) else {
            continue;
        };
        let Ok(primary) = client.prepare_group_call_terminal_v2(
            account,
            &contact,
            group_id,
            call_instance,
            ring_id,
            reason,
            &actor_device_id,
            &coordinator.username,
            &coordinator.identity_key,
            &coordinator.device_id,
            expires_at,
        ) else {
            continue;
        };
        envelopes.push(primary);
        if multi {
            if let Ok(mut extras) = client.extra_group_call_terminal_envelopes_v2(
                account,
                &sess.history,
                &contact,
                group_id,
                call_instance,
                ring_id,
                reason,
                &actor_device_id,
                &coordinator.username,
                &coordinator.identity_key,
                &coordinator.device_id,
                expires_at,
            ) {
                envelopes.append(&mut extras);
            }
        }
    }
    let _ = post_call_controls(client, s, &envelopes);
    // The same outcome on the capsule layer, exactly as the 1:1 terminal fan does it.
    // Without this a member's locked phone adopts the group ring from the offer capsule
    // (`c11aa4c`) and then never hears it end — the only terminal it gets is one it
    // cannot decrypt, so it rings out. §3.6 requires group parity for precisely this.
    //
    // But only under the condition a receiver will accept (A-25): a coordinator ending the
    // logical call. The encrypted fan above is unaffected — it carries the per-leg semantics
    // the capsule layer deliberately does not have — while a member's plain decline used to
    // mint N−1 silent high-priority wakes that every receiver then refused.
    if !group_terminal_capsule_worth_sending(s, coordinator, reason) {
        return;
    }
    let members: Vec<String> = group
        .members
        .iter()
        .map(|member| member.username.clone())
        .filter(|username| *username != me)
        .collect();
    let mut capsules = Vec::new();
    for username in &members {
        capsules.append(&mut prepare_capsules(
            s,
            client,
            username,
            &CapsuleBatch {
                kind: client_core::callcapsule::CapsuleKind::Terminal,
                call_instance_id: call_instance,
                // A group ring is keyed by its `ring_id`, not a per-member offer id —
                // the same convergence id the offer capsules carry.
                offer_id: ring_id,
                video: false,
                group: true,
                created_at: now_secs(),
                ring_expires_at: expires_at,
                expires_at,
                reason: Some(reason),
            },
        ));
    }
    spawn_capsule_posts(client, capsules);
}

/// Prepare and send one isolated pair ticket per group member.
///
/// Sealing happens under the session lock; the relay batch runs with it released, so a
/// slow member's mailbox never delays the rest of the ring or inbound signaling.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_offers_for_group(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    group_id: &str,
    call_instance: &str,
    ring_id: &str,
    coordinator: &GroupCoordinator,
    deadline: GroupRingDeadline,
    members: &[client_core::GroupMember],
) -> Result<std::collections::HashMap<String, (String, String)>, String> {
    let mut prepared = Vec::new();
    let mut plans = Vec::new();
    let mut capsules = Vec::new();
    {
        let mut s = inner.lock().await;
        if !is_current(&s, client) {
            return Err("not configured".into());
        }
        let multi = s.multi_device;
        let caller_device_id = s.history.self_device_id();
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        for member in members {
            let ticket = client_core::call::CallTicket::mint();
            let offer_id = client_core::callstate::random_call_id();
            let Some(contact) = client.member_contact_pinned(account, member) else {
                continue;
            };
            let start = prepared.len();
            let Ok(primary) = client.prepare_group_call_offer_v2(
                account,
                &contact,
                group_id,
                call_instance,
                ring_id,
                &offer_id,
                &ticket.call_id,
                &ticket.key_b64,
                deadline.created_at,
                deadline.ring_expires_at,
                deadline.expires_at,
                &caller_device_id,
                &coordinator.username,
                &coordinator.identity_key,
                &coordinator.device_id,
                &coordinator.reply_to_mailbox,
                false,
            ) else {
                continue;
            };
            prepared.push(primary);
            if multi {
                if let Ok(mut extras) = client.extra_group_call_offer_envelopes_v2(
                    account,
                    &sess.history,
                    &contact,
                    group_id,
                    call_instance,
                    ring_id,
                    &offer_id,
                    &ticket.call_id,
                    &ticket.key_b64,
                    deadline.created_at,
                    deadline.ring_expires_at,
                    deadline.expires_at,
                    &caller_device_id,
                    &coordinator.username,
                    &coordinator.identity_key,
                    &coordinator.device_id,
                    &coordinator.reply_to_mailbox,
                    false,
                ) {
                    prepared.append(&mut extras);
                }
            }
            plans.push((
                member.username.clone(),
                (ticket.call_id, ticket.key_b64),
                start,
                prepared.len(),
            ));
        }
        if prepared.is_empty() {
            return Err("no group member could be prepared".into());
        }
        // The second delivery layer, same as a 1:1 ring: one minimal capsule per member
        // device that published a call-control key. A group ring is keyed under its
        // `ring_id` (that is the id `CallRegistry` and every terminal use), so that is
        // what the capsule carries as its offer id — the two layers then converge on one
        // record instead of ringing a locked phone twice.
        for (username, _, _, _) in &plans {
            let batch = CapsuleBatch {
                kind: client_core::callcapsule::CapsuleKind::Offer,
                call_instance_id: call_instance,
                offer_id: ring_id,
                video: false,
                group: true,
                created_at: deadline.created_at,
                ring_expires_at: deadline.ring_expires_at,
                expires_at: deadline.expires_at,
                reason: None,
            };
            capsules.append(&mut prepare_capsules(&mut s, client, username, &batch));
        }
        // Persist every advanced device ratchet before the network-only concurrent launch.
        s.persist()?;
    }
    spawn_capsule_posts(client, capsules);
    let results = client.post_envelopes_concurrent(&prepared).await;
    let mut tickets = std::collections::HashMap::new();
    for (username, ticket, start, end) in plans {
        if results[start..end].iter().any(Result::is_ok) {
            tickets.insert(username, ticket);
        }
    }
    if tickets.is_empty() {
        return Err(results
            .into_iter()
            .find_map(Result::err)
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no group member could be reached".into()));
    }
    Ok(tickets)
}

/// Bound the connecting state when no group pair leg ever starts flowing.
pub(crate) fn spawn_group_no_answer_timeout(
    inner: Arc<Mutex<Session>>,
    client: Arc<Client>,
    call_instance: String,
) {
    eng().spawn(async move {
        let Some((ring_expires_at, signal_expires_at)) = ({
            let s = inner.lock().await;
            s.group_call
                .as_ref()
                .filter(|call| call.call_instance == call_instance)
                .map(|call| (call.deadline.ring_expires_at, call.deadline.expires_at))
        }) else {
            return;
        };
        tokio::time::sleep(std::time::Duration::from_secs(
            ring_expires_at.saturating_sub(now_secs()),
        ))
        .await;
        let answered_or_joining = {
            let s = inner.lock().await;
            let Some(call) = s
                .group_call
                .as_ref()
                .filter(|call| call.call_instance == call_instance)
            else {
                return;
            };
            if !call.connected.lock().unwrap().is_empty() {
                return;
            }
            !local_group_coordinator(&s, &call.coordinator) || !call.answer_arbiters.is_empty()
        };
        if answered_or_joining {
            tokio::time::sleep(std::time::Duration::from_secs(
                signal_expires_at.saturating_sub(now_secs()),
            ))
            .await;
        }
        let mut s = inner.lock().await;
        let nobody = s.group_call.as_ref().is_some_and(|call| {
            call.call_instance == call_instance && call.connected.lock().unwrap().is_empty()
        });
        if nobody {
            if let Some(call) = s.group_call.take() {
                let _ = call.stop.send(true);
                eng().end_system_call(&call.ring_handle, telecom::cause::MISSED);
                let _ = record_call_terminal(
                    &mut s,
                    &call.call_instance,
                    &call.ring_id,
                    client_core::callstate::CallTerminalReason::Expired,
                );
                send_group_call_terminal_everywhere(
                    &client,
                    &mut s,
                    &call.group_id,
                    &call.call_instance,
                    &call.ring_id,
                    &call.coordinator,
                    client_core::callstate::CallTerminalReason::Expired,
                );
                log_group_call_event(&mut s, &call.group_id, "📞 Unanswered group call");
                eng().emit("group_call", serde_json::json!({ "kind": "no_answer" }));
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) fn send_group_call_claim_to_coordinator(
    client: &Arc<Client>,
    s: &mut Session,
    coordinator: &GroupCoordinator,
    group_id: &str,
    call_instance_id: &str,
    ring_id: &str,
    claim_nonce: &str,
    answering_device_id: &str,
    reply_to_mailbox: &str,
    expires_at: u64,
) -> Result<(), String> {
    let envelope = {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .prepare_group_call_answer_claim_v2_to_mailbox(
                account,
                &coordinator.identity_key,
                &coordinator.reply_to_mailbox,
                group_id,
                call_instance_id,
                ring_id,
                claim_nonce,
                answering_device_id,
                reply_to_mailbox,
                expires_at,
            )
            .map_err(|error| error.to_string())?
    };
    post_call_controls(client, s, &[envelope])
        .into_iter()
        .next()
        .unwrap_or_else(|| Err("group answer claim was not queued".into()))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn send_group_call_winner_everywhere(
    client: &Arc<Client>,
    s: &mut Session,
    peer_username: &str,
    peer_key: &str,
    group_id: &str,
    call_instance_id: &str,
    ring_id: &str,
    claim_nonce: &str,
    winner_device_id: &str,
    winner_reply_to_mailbox: &str,
) -> Result<(), String> {
    let multi = s.multi_device;
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let contact = contact_for(peer_username, peer_key);
    let envelopes = {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        let exact = client
            .prepare_group_call_winner_v2_to_mailbox(
                account,
                peer_key,
                winner_reply_to_mailbox,
                group_id,
                call_instance_id,
                ring_id,
                claim_nonce,
                winner_device_id,
                expires_at,
            )
            .map_err(|error| error.to_string())?;
        let mut envelopes = vec![exact];
        if multi {
            if let Ok(mut extras) = client.extra_group_call_winner_envelopes_v2(
                account,
                &sess.history,
                &contact,
                group_id,
                call_instance_id,
                ring_id,
                claim_nonce,
                winner_device_id,
                expires_at,
            ) {
                envelopes.append(&mut extras);
            }
        }
        envelopes
    };
    let results = post_call_controls(client, s, &envelopes);
    if results.first().is_some_and(Result::is_ok) {
        Ok(())
    } else {
        Err("group winner acknowledgement could not be delivered".into())
    }
}
