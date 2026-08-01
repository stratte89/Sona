//! Silently resuming a 1:1 call whose media leg dropped, and giving up on one that cannot
//! be resumed.
//!
//! A dropped call is not an ended call. The pair's **owner** — the lexicographically smaller
//! identity key, the same rule the group legs use — mints a fresh room and key (a call key is
//! never reused) and offers it as a `resume_of` the old one; the peer's in-call device accepts
//! it silently, so nothing rings and the user sees "reconnecting…" rather than a call that
//! vanished.
//!
//! Both halves are bounded, and that is the point of keeping them together: a resume that
//! never lands must end the call visibly instead of leaving "reconnecting…" on screen for
//! good. [`super::engine`] owns bringing a call up in the first place.

use crate::*;

/// Drive a dropped 1:1 call's silent resume. Two tasks:
///
/// * After [`RECONNECT_GRACE_MS`] (long enough for a deliberate terminal control to
///   land and cancel everything), the pair's **owner** — the lexicographically smaller
///   identity key, same rule as group legs — mints a fresh room + key (a call key is
///   never reused) and sends a v2 offer marked `resume_of: old_call_id`. The
///   peer's in-call device auto-accepts it silently; nothing ever rings.
/// * A [`RECONNECT_WINDOW_SECS`] deadline: if the resume hasn't produced a live call
///   by then, the call ends visibly instead of "reconnecting…" forever.
pub(crate) fn start_call_reconnect(
    inner: Arc<Mutex<Session>>,
    client: Arc<Client>,
    old_call_id: String,
) {
    // ── Owner re-offer, after the terminal-control grace. ──
    {
        let inner = inner.clone();
        let old = old_call_id.clone();
        eng().spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(RECONNECT_GRACE_MS)).await;
            let mut s = inner.lock().await;
            let Some(rc) = s.reconnect.as_ref().filter(|r| r.old_call_id == old) else {
                return; // the peer's terminal landed — it was a hangup, already ended
            };
            let (
                call_instance_id,
                ring_handle,
                peer_username,
                peer_key,
                peer_device_key,
                peer_reply_to_mailbox,
                peer_media2,
                prev_connected_at,
            ) = (
                rc.call_instance_id.clone(),
                // The system call never ended — a silent resume keeps its handle.
                rc.ring_handle.clone(),
                rc.peer_username.clone(),
                rc.peer_key.clone(),
                rc.peer_device_key.clone(),
                rc.peer_reply_to_mailbox.clone(),
                rc.peer_media2,
                rc.connected_at,
            );
            let Some(my_key) = s.account.as_ref().map(|a| a.ratchet_ref().identity_key()) else {
                return; // locked meanwhile
            };
            if my_key.as_str() >= peer_device_key.as_str() {
                return; // the peer owns the pair — they re-offer, we wait
            }
            let ticket = client_core::call::CallTicket::mint();
            let offer_id = client_core::callstate::random_call_id();
            let created_at = now_secs();
            let ring_expires_at =
                created_at.saturating_add(client_core::callstate::CALL_RING_TIMEOUT_SECS);
            let expires_at =
                created_at.saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
            let caller_device_id = s.history.self_device_id();
            let contact = contact_for(&peer_username, &peer_key);
            let multi = s.multi_device;
            let offers = {
                let sess = &mut *s;
                let Some(account) = sess.account.as_mut() else {
                    return;
                };
                let Ok(primary) = client.prepare_call_offer_v2(
                    account,
                    &contact,
                    &call_instance_id,
                    &offer_id,
                    &ticket.call_id,
                    &ticket.key_b64,
                    created_at,
                    ring_expires_at,
                    expires_at,
                    &caller_device_id,
                    &old,
                ) else {
                    return;
                };
                let mut offers = vec![primary];
                if multi {
                    if let Ok(mut extras) = client.extra_call_offer_envelopes_v2(
                        account,
                        &sess.history,
                        &contact,
                        &call_instance_id,
                        &offer_id,
                        &ticket.call_id,
                        &ticket.key_b64,
                        created_at,
                        ring_expires_at,
                        expires_at,
                        &caller_device_id,
                        &old,
                    ) {
                        offers.append(&mut extras);
                    }
                }
                offers
            };
            let _ = s.persist();
            // A resume is a fresh ring's worth of network: post it and join the new room
            // with the session lock released.
            drop(s);
            if !client
                .post_envelopes_concurrent(&offers)
                .await
                .iter()
                .any(Result::is_ok)
            {
                // Relay unreachable — no point holding "reconnecting" for the full window.
                give_up_reconnect(&mut *inner.lock().await, &old, telecom::cause::ERROR);
                return;
            }
            {
                let mut s = inner.lock().await;
                if s.reconnect.as_ref().is_none_or(|r| r.old_call_id != old) {
                    return; // the peer's terminal landed while the offer was in flight
                }
                let _ = s.calls().registry.receive_resume(
                    &call_instance_id,
                    &offer_id,
                    created_at,
                    expires_at,
                    now_secs(),
                );
                s.reconnect = None; // resume in flight; the fresh session takes over
            }
            // From here the resumed session owns the handle and nothing else holds it: the
            // reconnect state is gone, and `spawn_call` installs `s.call` only on success. So
            // its `Err` is itself the proof that this device gave up, and the handle it was
            // handed is the one to end.
            let giving_up = ring_handle.clone();
            if spawn_call(
                &inner,
                &client,
                call_instance_id,
                offer_id,
                ring_handle,
                ticket.call_id.clone(),
                ticket.key_b64,
                peer_username,
                peer_key.clone(),
                peer_reply_to_mailbox,
                true,
                peer_media2,
                1,
            )
            .await
            .is_err()
            {
                let mut s = inner.lock().await;
                eng().end_system_call(&giving_up, telecom::cause::ERROR);
                log_call_event(
                    &mut s,
                    &peer_key,
                    &call_end_label("Call", true, prev_connected_at),
                );
                eng().emit("call", serde_json::json!({ "kind": "ended" }));
                return;
            }
            // Carry the ORIGINAL connect time into the resumed session — the history
            // chip's duration must span the whole call, not the post-drop segment.
            if let Some(c) = inner
                .lock()
                .await
                .call
                .as_mut()
                .filter(|c| c.call_id == ticket.call_id)
            {
                // The reconnect offer still targets the exact device that owned the
                // connected leg, while `peer_key` remains the conversation key.
                c.peer_device_key = peer_device_key;
                c.connected_at
                    .store(prev_connected_at, std::sync::atomic::Ordering::Relaxed);
            }
            spawn_reconnect_window(inner, ticket.call_id);
        });
    }
    // ── Waiter deadline: the resume offer never arrived. ──
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_WINDOW_SECS)).await;
        // The peer never re-offered, so this is not a transport fault of ours: `REMOTE`.
        give_up_reconnect(
            &mut *inner.lock().await,
            &old_call_id,
            telecom::cause::REMOTE,
        );
    });
}

/// Give up on a dropped leg's silent resume: drop the state that is holding the system call
/// open, end that system call, and tell the user the call is over.
///
/// **A-17.** A *connected* call deliberately keeps its system call up across the resume —
/// the media pump's `PeerLeft | Ended` arm ends it only in the `else` branch, because a
/// resume is meant to be seamless — so every path that abandons the resume is the path that
/// owes the ending. Without it Telecom keeps a call the shell has forgotten: on Android the
/// ongoing-call chip stays, audio focus is never released, `telecomOwnsRoute` stays set so
/// the *next* call's routing is wedged, and the next `addCall` meets an occupied slot, so
/// the next call never rings. A dropped mobile leg is the ordinary way to get here.
///
/// The handle comes out of the state being removed, and that removal is also the proof that
/// this device is the one giving up: the resumed session reuses the same `ring_handle`, so
/// ending one captured before the resume would disconnect a live call. Everything is in one
/// function so a give-up path added later cannot do half of it.
pub(crate) fn give_up_reconnect(s: &mut Session, old_call_id: &str, cause: i32) -> bool {
    let Some(rc) = s.reconnect.take_if(|r| r.old_call_id == old_call_id) else {
        return false; // the peer's terminal already landed, or a resume took over
    };
    eng().end_system_call(&rc.ring_handle, cause);
    log_call_event(
        s,
        &rc.peer_key,
        &call_end_label("Call", true, rc.connected_at),
    );
    eng().emit("call", serde_json::json!({ "kind": "ended" }));
    true
}

/// End a resumed session that never actually reconnected within the window (the
/// normal 45 s no-answer timer is for rings; a resume must fail much faster).
pub(crate) fn spawn_reconnect_window(inner: Arc<Mutex<Session>>, new_call_id: String) {
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_WINDOW_SECS)).await;
        give_up_resumed_call(&mut *inner.lock().await, &new_call_id);
    });
}

/// The resumed session came up but never connected. **A-17**, and the one give-up path the
/// media pump cannot cover: `s.call` is taken here, so the pump's own `take_if` finds
/// nothing and its ending never runs. The resumed session inherited the handle the dropped
/// leg was holding, which makes this its last owner.
pub(crate) fn give_up_resumed_call(s: &mut Session, new_call_id: &str) -> bool {
    let Some(call) = s.call.take_if(|c| {
        c.call_id == new_call_id && !c.connected.load(std::sync::atomic::Ordering::Relaxed)
    }) else {
        return false;
    };
    let _ = call.stop.send(true);
    eng().end_system_call(&call.ring_handle, telecom::cause::REMOTE);
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
    true
}
