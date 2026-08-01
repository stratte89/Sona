//! Attribution self-heal: inbound content from a device key we cannot attribute,
//! whose claimed username is a pinned contact or known group member, is quarantined
//! (`Session::pending_attr`) instead of silently dropped by the request gate's spoof
//! rule, then replayed after a KT-verified roster re-resolve. Split from runtime.rs; the delivery
//! loop spawns [`resolve_attr_and_replay`], and `accept_key_change` drains the same
//! quarantine after re-pinning a rotated key.

use crate::*;

/// Attribution-quarantine cap per claimed username (see `Session::pending_attr`).
pub(crate) const PENDING_ATTR_CAP: usize = 64;

/// Re-resolve `username`'s roster (KT-verified) and replay their quarantined events.
/// On success each event goes through the exact normal inbound treatment (apply →
/// visibility-gated notification → UI nudge). A device still absent from the verified
/// roster after the refresh is a real spoof: its events are dropped, loudly. A network
/// failure re-queues everything — the next message from that sender (or an
/// `accept_key_change`) retries.
pub(crate) async fn resolve_attr_and_replay(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    username: &str,
) {
    let mut plans = Vec::new();
    let mut call_signals = Vec::new();
    let mut applied = false;
    {
        let mut s = inner.lock().await;
        s.attr_inflight.remove(username);
        let events = s.pending_attr.remove(username).unwrap_or_default();
        if events.is_empty() {
            return;
        }
        // Lock across the network call matches the add_contact/open_chat precedent.
        if client
            .resolve_account_devices(&mut s.history, username)
            .await
            .is_err()
        {
            crate::diag!(
                "client: roster re-resolve for {username} failed; {} event(s) stay quarantined",
                events.len()
            );
            s.pending_attr.insert(username.to_string(), events);
            return;
        }
        let me = s
            .account
            .as_ref()
            .map(|a| a.account_id().to_string())
            .unwrap_or_default();
        let level = s.prefs.notif_level.clone();
        for event in &events {
            let key = event.sender_identity_key().to_string();
            let claimed = event
                .attribution_claim()
                .map(|(_, username)| username)
                .unwrap_or_default();
            if s.history
                .device_resolution_candidate(&key, claimed)
                .is_some()
            {
                crate::diag!(
                    "client: dropping quarantined event from {key}: not in {username}'s verified roster"
                );
                continue;
            }
            if s.history.peer_blocked(&key) {
                continue;
            }
            if event.is_call_signal() {
                call_signals.push(event.clone());
                continue;
            }
            s.history.apply(event);
            applied = true;
            let convo = s.history.attribute_device(&key);
            let plan = if s.history.request_pending_for_key(&convo) {
                s.history
                    .request_needs_notify(&convo)
                    .then(|| request_notif_plan(&s.history, &convo, &level))
            } else {
                let visible = match event {
                    InboundEvent::Message { msg_id, .. }
                    | InboundEvent::Attachment { msg_id, .. } => {
                        s.history.message(&convo, msg_id).is_some()
                    }
                    _ => true,
                };
                visible
                    .then(|| notif_for_event(&s.history, event, &level, &me))
                    .flatten()
            };
            plans.extend(plan);
        }
        let _ = s.persist();
    }
    if applied {
        eng().emit("sync", ());
    }
    for plan in &plans {
        notify_now(plan);
    }
    for event in call_signals {
        handle_call_signal(inner, client, event).await;
    }
}
