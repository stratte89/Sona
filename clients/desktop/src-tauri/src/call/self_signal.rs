use crate::*;

/// The `handled` UI event, carrying **why** the ring ended.
///
/// Every terminal used to reach the shell as a bare `handled`, which the UI could only
/// render as "Answered on another device" — including when the call was declined
/// elsewhere, cancelled by the caller, or refused as busy (`internal/CALL_PLAN.md` §3.4). The
/// reason is authenticated and already in hand at every one of these sites; the only
/// thing missing was passing it on.
pub(crate) fn handled_event(
    reason: client_core::callstate::CallTerminalReason,
) -> serde_json::Value {
    serde_json::json!({ "kind": "handled", "reason": reason })
}

pub(super) async fn handle_self_call_terminal(inner: &Arc<Mutex<Session>>, event: InboundEvent) {
    let InboundEvent::SelfCallTerminalV2 {
        sender_identity_key,
        call_instance_id,
        offer_id,
        reason,
        expires_at,
        ..
    } = event
    else {
        return;
    };
    let mut s = inner.lock().await;
    if !s.history.is_own_device(&sender_identity_key)
        || !client_core::callstate::valid_control_expiry(expires_at, now_secs())
    {
        return;
    }
    // Through `record_call_terminal`, which reads the retention the user chose (A-9). This
    // is the **most common** terminal on a multi-device account — every "answered elsewhere"
    // this device is told about — so a literal `0` here meant the tombstone lived
    // `MIN_TOMBSTONE_SECS` whatever "Keep call records: 30 days" said, on the path it
    // happens most (A-23). The early return on a decision this device does not own stays:
    // without it a conflicting terminal could cancel a ring it has no claim to.
    if matches!(
        record_call_terminal(&mut s, &call_instance_id, &offer_id, reason),
        client_core::callstate::TerminalDecision::Conflict
            | client_core::callstate::TerminalDecision::Invalid
            | client_core::callstate::TerminalDecision::Capacity
    ) {
        return;
    }
    if let Some(offer) = s
        .incoming
        .take_if(|offer| offer.call_instance_id == call_instance_id)
    {
        eng().cancel_ring(&offer.ring_handle, "");
        eng().emit("call", handled_event(reason));
    } else if s
        .group_incoming
        .as_ref()
        .is_some_and(|offer| offer.call_instance == call_instance_id)
    {
        if let Some(offer) = s.group_incoming.take() {
            eng().cancel_ring(&offer.ring_handle, "");
        }
        eng().emit("group_call", handled_event(reason));
    } else if let Some(pending) = s
        .group_claiming
        .take_if(|pending| pending.offer.call_instance == call_instance_id)
    {
        // Answered on a sibling while this device was waiting on the coordinator: its
        // system call has to come down with the claim.
        eng().end_system_call(&pending.offer.ring_handle, disconnect_cause(reason));
        eng().emit("group_call", handled_event(reason));
    } else if let Some(pending) = s
        .claiming
        .take_if(|pending| pending.offer.call_instance_id == call_instance_id)
    {
        eng().end_system_call(&pending.offer.ring_handle, disconnect_cause(reason));
        eng().emit("call", handled_event(reason));
    }
}

/// Tell our own siblings an explicit final outcome.
pub(crate) fn ring_terminal_selfsync(
    client: &Arc<Client>,
    s: &mut Session,
    call_instance_id: &str,
    offer_id: &str,
    reason: client_core::callstate::CallTerminalReason,
) {
    if !s.multi_device {
        return;
    }
    let actor_device_id = s.history.self_device_id();
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let sess = &mut *s;
    let Some(account) = sess.account.as_mut() else {
        return;
    };
    let me = account.account_id().to_string();
    if let Ok(envelopes) = client.call_terminal_selfsync_v2(
        account,
        &sess.history,
        call_instance_id,
        offer_id,
        reason,
        &actor_device_id,
        expires_at,
    ) {
        let _ = post_call_controls(client, s, &envelopes);
    }
    // Our own siblings ring too, and one of them may be a locked phone: send them the
    // outcome on the capsule layer as well. `prepare_capsules` skips this device.
    send_terminal_capsules(
        s,
        client,
        &me,
        call_instance_id,
        offer_id,
        reason,
        expires_at,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::callstate::{
        random_call_id, CallRecordState, CallTerminalReason, CALL_SIGNAL_TTL_SECS,
        MIN_TOMBSTONE_SECS,
    };
    use client_core::history::RosterDevice;

    /// A-23: the retention the user chose has to reach **this** tombstone above all others.
    ///
    /// A-9 routed nineteen sites through `record_call_terminal` and missed this one, which is
    /// the most common terminal on a multi-device account: every "answered elsewhere" this
    /// device is told about. So "Keep call records: 30 days" described a 65-second window on
    /// the path it happens most — the exact dishonest-UI condition A-9 was raised to remove.
    #[tokio::test]
    async fn the_self_sync_terminal_is_tombstoned_for_the_retention_the_user_chose() {
        let inner: Arc<Mutex<Session>> = Arc::default();
        let (call, offer) = (random_call_id(), random_call_id());
        {
            let mut s = inner.lock().await;
            s.prefs.call_retention_secs = CALL_RETENTION_CHOICES[3]; // 30 days
                                                                     // What makes the sender one of *our* devices, which is all this path accepts.
            s.history
                .pin_roster(
                    "alice",
                    0,
                    0,
                    "primary",
                    vec![
                        RosterDevice {
                            device_id: "0".into(),
                            identity_key: "primary".into(),
                            signing_key: String::new(),
                        },
                        RosterDevice {
                            device_id: "aa".repeat(16),
                            identity_key: "sibling".into(),
                            signing_key: String::new(),
                        },
                    ],
                )
                .unwrap();
            s.history.set_self_primary_key("primary");
        }

        handle_self_call_terminal(
            &inner,
            InboundEvent::SelfCallTerminalV2 {
                sender_identity_key: "sibling".into(),
                call_instance_id: call.clone(),
                offer_id: offer.clone(),
                reason: CallTerminalReason::AnsweredElsewhere,
                actor_device_id: "aa".repeat(16),
                expires_at: now_secs() + CALL_SIGNAL_TTL_SECS,
            },
        )
        .await;

        let s = inner.lock().await;
        let kept = match &s.call_store.registry.records()[0].state {
            CallRecordState::Terminal { retain_until, .. } => {
                retain_until.saturating_sub(now_secs())
            }
            other => panic!("expected a tombstone, got {other:?}"),
        };
        assert!(
            kept >= CALL_RETENTION_CHOICES[3] - 1,
            "thirty days must mean thirty days here too, not the {MIN_TOMBSTONE_SECS}s floor"
        );
    }
}
