//! Ending a group call: declining the ring, and hanging up (or giving up on) a call
//! this device is in.
//!
//! Split from `group.rs` for size, but the grouping is real: these are the paths that
//! **drop** group-call state, and every one of them owes the same three things — the
//! terminal on the wire, the tombstone in the registry, and the system call taken down
//! (`internal/CALL_PLAN.md` §7.3).

use super::auth::local_group_coordinator;
use super::group_control::send_group_call_terminal_everywhere;
use crate::*;

/// Decline the pending group ring: tell everyone already in the call (they offered us
/// a leg) that we're not coming.
#[tauri::command]
pub async fn group_call_decline(state: tauri::State<'_, AppState>) -> Result<(), String> {
    group_call_decline_inner(&state.inner).await
}

/// See [`call_decline_inner`] — group flavor, shared with the system-call path.
pub(crate) async fn group_call_decline_inner(inner: &Arc<Mutex<Session>>) -> Result<(), String> {
    let mut s = inner.lock().await;
    let offer = s.group_incoming.take().ok_or("no incoming group call")?;
    eng().cancel_ring(&offer.ring_handle, "");
    let client = s.client.clone().ok_or("not configured")?;
    let actor_device_id = s.history.self_device_id();
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let envelopes = {
        let sess = &mut *s;
        let mut envelopes = Vec::new();
        if let Some(account) = sess.account.as_mut() {
            for (peer_key, (username, _, _)) in &offer.offers {
                let contact = contact_for(username, peer_key);
                if let Ok(envelope) = client.prepare_group_call_terminal_v2(
                    account,
                    &contact,
                    &offer.group_id,
                    &offer.call_instance,
                    &offer.ring_id,
                    client_core::callstate::CallTerminalReason::DeclinedHere,
                    &actor_device_id,
                    &offer.coordinator.username,
                    &offer.coordinator.identity_key,
                    &offer.coordinator.device_id,
                    expires_at,
                ) {
                    envelopes.push(envelope);
                }
            }
        }
        envelopes
    };
    let _ = post_call_controls(&client, &mut s, &envelopes);
    ring_terminal_selfsync(
        &client,
        &mut s,
        &offer.call_instance,
        &offer.ring_id,
        client_core::callstate::CallTerminalReason::DeclinedElsewhere,
    );
    let _ = record_call_terminal(
        &mut s,
        &offer.call_instance,
        &offer.ring_id,
        client_core::callstate::CallTerminalReason::DeclinedHere,
    );
    log_group_call_event(&mut s, &offer.group_id, "📞 Declined group call");
    s.persist()
}

/// Leave the live group call. The stable coordinator ends the logical call globally;
/// other participants leave only their own pair legs.
#[tauri::command]
pub async fn group_call_hangup(state: tauri::State<'_, AppState>) -> Result<(), String> {
    group_call_hangup_inner(&state.inner).await
}

/// See [`call_hangup_inner`] — group flavor, shared with the system-call path.
pub(crate) async fn group_call_hangup_inner(inner: &Arc<Mutex<Session>>) -> Result<(), String> {
    let mut s = inner.lock().await;
    let Some(gc) = s.group_call.take() else {
        // Waiting on the coordinator's winner: the same button ends it, so the state has
        // a user-visible exit and not only a timer (see `spawn_claim_timeout`).
        if let Some(pending) = s.group_claiming.take() {
            eng().end_system_call(&pending.offer.ring_handle, telecom::cause::LOCAL);
            let _ = record_call_terminal(
                &mut s,
                &pending.offer.call_instance,
                &pending.offer.ring_id,
                client_core::callstate::CallTerminalReason::DeclinedHere,
            );
            log_group_call_event(&mut s, &pending.offer.group_id, "📞 Group call ended");
            eng().emit("group_call", serde_json::json!({ "kind": "ended" }));
            return s.persist();
        }
        return Ok(());
    };
    let _ = gc.stop.send(true);
    eng().end_system_call(&gc.ring_handle, telecom::cause::LOCAL);
    let client = s.client.clone().ok_or("not configured")?;
    let coordinator_here = local_group_coordinator(&s, &gc.coordinator);
    let reason = if coordinator_here {
        client_core::callstate::CallTerminalReason::CallerCancelled
    } else {
        client_core::callstate::CallTerminalReason::DeclinedHere
    };
    send_group_call_terminal_everywhere(
        &client,
        &mut s,
        &gc.group_id,
        &gc.call_instance,
        &gc.ring_id,
        &gc.coordinator,
        reason,
    );
    // A-23: through `record_call_terminal`, so the group hangup's tombstone lives as long as
    // the user asked rather than the anti-replay floor.
    let _ = record_call_terminal(&mut s, &gc.call_instance, &gc.ring_id, reason);
    log_group_call_event(
        &mut s,
        &gc.group_id,
        &call_end_label(
            "Group call",
            true,
            gc.connected_at.load(std::sync::atomic::Ordering::Relaxed),
        ),
    );
    s.persist()?;
    Ok(())
}

/// Mute/unmute the group-call microphone (wire cadence unchanged, like 1:1).
#[tauri::command]
pub async fn group_call_set_muted(
    state: tauri::State<'_, AppState>,
    muted: bool,
) -> Result<(), String> {
    let s = state.inner.lock().await;
    let gc = s.group_call.as_ref().ok_or("no active group call")?;
    gc.muted.store(muted, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}
