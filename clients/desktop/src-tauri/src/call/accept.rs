//! Answering an inbound ring, and bounding the wait that follows.
//!
//! An answer is not an acceptance: this device submits a **claim** and waits for the
//! caller to name it the winner (`internal/CALL_PLAN.md` §3.5). Media starts only then, which is
//! what stops two devices both believing they answered — and it is why the wait needs a
//! deadline of its own, kept here beside the accept that opens it.

use crate::*;

/// The accept itself, callable without a Tauri `State` — the Bluetooth/headset-button
/// answer (`notif_action`) goes through the exact same path as the UI button. The
/// call media pipeline is fully native (Kotlin bridge both directions), so an accept
/// with no webview attached is a working call; the UI resyncs from `call_status`.
pub(crate) async fn call_accept_inner(inner: &Arc<Mutex<Session>>) -> Result<(), String> {
    let mut s = inner.lock().await;
    let offer = s.incoming.take().ok_or("no incoming call")?;
    if s.call.is_some() || s.group_call.is_some() || s.claiming.is_some() || s.call_setup {
        return Err("already in a call".into());
    }
    // Accept, not cancel: the system call stays up through the claim and becomes active
    // when media connects. It ends only if the claim is lost or the call fails.
    eng().accept_ring(&offer.ring_handle, false);
    let client = s.client.clone().ok_or("not configured")?;
    let answering_device_id = s.history.self_device_id();
    let my_username = s.account.as_ref().ok_or("locked")?.account_id().to_string();
    let reply_to_mailbox = client
        .device_mailbox(&my_username, &answering_device_id)
        .map_err(|e| e.to_string())?;
    let claim_nonce = client_core::callstate::random_call_id();
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let _ = s.calls().registry.transition(
        &offer.call_instance_id,
        &offer.offer_id,
        client_core::callstate::CallPhase::Claiming,
        now_secs(),
    );
    send_call_claim_to_origin(
        &client,
        &mut s,
        &offer.peer_key,
        &offer.caller_reply_to_mailbox,
        &offer.call_instance_id,
        &offer.offer_id,
        &claim_nonce,
        &answering_device_id,
        &reply_to_mailbox,
        expires_at,
    )?;
    s.persist()?;
    let timeout = ClaimTimeout {
        claim_nonce: claim_nonce.clone(),
        call_instance_id: offer.call_instance_id.clone(),
        ring_handle: offer.ring_handle.clone(),
        offer_id: offer.offer_id.clone(),
        deadline: expires_at,
    };
    s.claiming = Some(PendingClaim {
        offer,
        claim_nonce,
        answering_device_id,
    });
    eng().emit("call", serde_json::json!({ "kind": "claiming" }));
    spawn_claim_timeout(inner.clone(), timeout);
    Ok(())
}

/// What the claim deadline needs to identify the attempt it is bounding.
struct ClaimTimeout {
    claim_nonce: String,
    call_instance_id: String,
    offer_id: String,
    ring_handle: String,
    deadline: u64,
}

/// Bound the wait for the caller's winner acknowledgement.
///
/// Without this the answer is unbounded: the ring-expiry task only takes `incoming`, and
/// by now the offer has moved into `claiming`. A caller that disappears between our claim
/// and its winner — a network drop, a crashed caller, a control that never arrived — left
/// `claiming` set forever, and with it `call_slot_free` false, so the device could neither
/// place nor receive another call. Nothing cleared it: not the ring timer, not the hangup
/// button, not Telecom's End. The group accept path has always had this timer; the 1:1 one
/// did not, which is what made it an oversight rather than a decision.
///
/// Local by construction: the claim we sent may still win right up to the deadline, so
/// nothing goes on the wire — this only stops *waiting*.
fn spawn_claim_timeout(inner: Arc<Mutex<Session>>, timeout: ClaimTimeout) {
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            timeout.deadline.saturating_sub(now_secs()),
        ))
        .await;
        let mut s = inner.lock().await;
        let Some(pending) = s.claiming.take_if(|pending| {
            pending.claim_nonce == timeout.claim_nonce
                && pending.offer.call_instance_id == timeout.call_instance_id
        }) else {
            return; // won, lost, or ended — all of which already cleared it
        };
        // This is what "stuck on establishing secure connection" *is*, seen from the device
        // that is stuck: the claim went out and the caller never named a winner. Said
        // plainly here so the callee's own log identifies it without needing the caller's
        // (E-14) — the answering side can otherwise only report that nothing happened.
        crate::diag!(
            "[call] claim TIMED OUT after {}s — the caller never sent a winner \
             acknowledgement; giving up this answer",
            client_core::callstate::CALL_SIGNAL_TTL_SECS
        );
        let _ = record_call_terminal(
            &mut s,
            &timeout.call_instance_id,
            &timeout.offer_id,
            client_core::callstate::CallTerminalReason::Expired,
        );
        eng().end_system_call(&timeout.ring_handle, telecom::cause::MISSED);
        log_call_event(&mut s, &pending.offer.peer_key, "📞 Call ended");
        eng().emit(
            "call",
            handled_event(client_core::callstate::CallTerminalReason::Expired),
        );
    });
}
