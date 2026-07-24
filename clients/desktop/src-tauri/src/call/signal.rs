use crate::*;

/// Inbound call signaling, forwarded by the delivery loop (after its lock is released).
pub(crate) async fn handle_call_signal(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    event: InboundEvent,
) {
    match event {
        InboundEvent::CallOffered {
            sender_identity_key,
            sender_username,
            call_id,
            key_b64,
            caps,
            reconnect_of,
            ..
        } => {
            let mut s = inner.lock().await;
            // A reconnect-marked offer NEVER rings and is never declined: it either
            // silently resumes the dropped call it names — same authenticated peer
            // device only — or it is silently dropped (this device wasn't in that
            // call: another of our devices was, or the call is long gone).
            if !reconnect_of.is_empty() {
                let matches = s.reconnect.as_ref().is_some_and(|r| {
                    r.old_call_id == reconnect_of && r.peer_key == sender_identity_key
                });
                if !matches {
                    return;
                }
                let rc = s.reconnect.take().expect("checked above");
                let peer_media2 = client_core::media::peer_supports_media2(&caps);
                if spawn_call(
                    inner,
                    client,
                    &mut s,
                    call_id.clone(),
                    key_b64,
                    rc.peer_username,
                    rc.peer_key.clone(),
                    false,
                    peer_media2,
                    1,
                )
                .await
                .is_err()
                {
                    log_call_event(
                        &mut s,
                        &rc.peer_key,
                        &call_end_label("Call", false, rc.connected_at),
                    );
                    eng().emit("call", serde_json::json!({ "kind": "ended" }));
                    return;
                }
                // Resumed session: keep the original connect time for the history chip.
                if let Some(c) = s.call.as_ref().filter(|c| c.call_id == call_id) {
                    c.connected_at
                        .store(rc.connected_at, std::sync::atomic::Ordering::Relaxed);
                }
                drop(s);
                spawn_reconnect_window(inner.clone(), call_id);
                return;
            }
            let username = if sender_username.is_empty() {
                s.history
                    .username_for_peer(&sender_identity_key)
                    .unwrap_or_else(|| sender_identity_key.chars().take(8).collect())
            } else {
                sender_username
            };
            // Busy (in a call, reconnecting one, or already ringing), or blocked:
            // auto-decline.
            if s.call.is_some()
                || s.incoming.is_some()
                || s.reconnect.is_some()
                || s.group_call.is_some()
                || s.group_incoming.is_some()
                || s.history.peer_blocked(&sender_identity_key)
            {
                // Busy (`true`) only for "this device is occupied" — with ring-all, the
                // caller keeps ringing our other devices. A blocked sender gets a plain
                // decline (`busy: false`), same outward behavior as today.
                let busy = !s.history.peer_blocked(&sender_identity_key);
                let _ = send_call_answer_everywhere(
                    client,
                    &mut s,
                    &username,
                    &sender_identity_key,
                    &call_id,
                    false,
                    busy,
                )
                .await;
                let _ = s.persist();
                return;
            }
            s.incoming = Some(PendingOffer {
                call_id: call_id.clone(),
                key_b64,
                username: username.clone(),
                peer_key: sender_identity_key,
                caps,
            });
            eng().emit(
                "call",
                serde_json::json!({ "kind": "incoming", "username": username }),
            );
            // Native ring — CallStyle + full-screen intent + insistent ringtone on
            // Android (RC-4 fix). Skipped only when the app is on screen: the in-app
            // ring UI (the `call` event above) handles that, avoiding double audio.
            // The headset-button MediaSession starts UNCONDITIONALLY — a tap on the
            // earbuds must answer whether the ring is native or in-app.
            let ring_name = ring_title(&s, &username);
            eng().call_buttons_start(&call_id);
            if !eng().on_screen() {
                eng().show_ring(&call_id, &ring_name, false);
            }
            // Unanswered ring expires by itself (the caller times out too).
            let inner = inner.clone();
            eng().spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(RING_TIMEOUT_SECS)).await;
                let mut s = inner.lock().await;
                if let Some(o) = s.incoming.take_if(|o| o.call_id == call_id) {
                    eng().cancel_ring(&call_id, &ring_name);
                    log_call_event(&mut s, &o.peer_key, "📞 Missed call");
                    eng().emit("call", serde_json::json!({ "kind": "missed" }));
                }
            });
        }
        InboundEvent::CallAnswered {
            call_id,
            accept,
            caps,
            busy,
            ..
        } => {
            if !accept {
                let mut s = inner.lock().await;
                use std::sync::atomic::Ordering::Relaxed;
                // A busy decline from ONE of the callee's devices must not end the ring
                // while their other devices can still answer: it only counts down. An
                // explicit decline (user pressed decline; also every old-client decline)
                // ends the ring at once. Either way, a call that already connected is
                // never torn down by a stray decline (a race with another device's
                // accept — that device's own ring is cleared by the handled self-sync).
                let end_ring = if busy {
                    match s.call.as_mut().filter(|c| c.call_id == call_id) {
                        Some(call) => {
                            call.ring_fanout = call.ring_fanout.saturating_sub(1);
                            call.ring_fanout == 0
                        }
                        None => false,
                    }
                } else {
                    true
                };
                if end_ring {
                    if let Some(call) = s
                        .call
                        .take_if(|c| c.call_id == call_id && !c.connected.load(Relaxed))
                    {
                        let _ = call.stop.send(true);
                        // Outwardly identical to a no-pickup: the callee never joined.
                        log_call_event(&mut s, &call.peer_key, &call_end_label("Call", true, 0));
                        eng().emit("call", serde_json::json!({ "kind": "declined" }));
                    }
                }
            } else {
                // The callee's caps decide whether video tracks may be enabled; the
                // engine re-evaluates the flag live (the room join usually races this
                // answer). Connected itself comes through the media session. Once
                // connected, later answers (another of the callee's devices losing the
                // accept race) must not flip the caps of the call in progress.
                let s = inner.lock().await;
                if let Some(call) = s.call.as_ref().filter(|c| {
                    c.call_id == call_id && !c.connected.load(std::sync::atomic::Ordering::Relaxed)
                }) {
                    call.peer_media2.store(
                        client_core::media::peer_supports_media2(&caps),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
        }
        InboundEvent::CallEnded { call_id, .. } => {
            let mut s = inner.lock().await;
            if let Some(call) = s.call.take_if(|c| c.call_id == call_id) {
                let _ = call.stop.send(true);
                log_call_event(
                    &mut s,
                    &call.peer_key,
                    &call_end_label(
                        "Call",
                        call.caller,
                        call.connected_at.load(std::sync::atomic::Ordering::Relaxed),
                    ),
                );
                eng().emit("call", serde_json::json!({ "kind": "ended" }));
            } else if s.incoming.as_ref().is_some_and(|o| o.call_id == call_id) {
                let (name, peer_key) = s
                    .incoming
                    .take()
                    .map(|o| (ring_title(&s, &o.username), o.peer_key))
                    .unwrap_or_default();
                eng().cancel_ring(&call_id, &name);
                // The caller gave up (or cancelled) before we picked up.
                log_call_event(&mut s, &peer_key, "📞 Missed call");
                eng().emit("call", serde_json::json!({ "kind": "missed" }));
            } else if let Some(rc) = s.reconnect.take_if(|r| r.old_call_id == call_id) {
                // The drop was actually the peer hanging up — end, don't resume.
                log_call_event(
                    &mut s,
                    &rc.peer_key,
                    &call_end_label("Call", true, rc.connected_at),
                );
                eng().emit("call", serde_json::json!({ "kind": "ended" }));
            }
        }
        // Another of OUR OWN devices answered/declined this ring — stop ringing here.
        // Honored only from a roster-verified own device; carries no key material.
        // `call_id` doubles as the group-call instance id for group rings.
        InboundEvent::SelfCallHandled {
            sender_identity_key,
            call_id,
        } => {
            let mut s = inner.lock().await;
            if !s.history.is_own_device(&sender_identity_key) {
                return;
            }
            if s.incoming.as_ref().is_some_and(|o| o.call_id == call_id) {
                s.incoming = None;
                eng().cancel_ring(&call_id, "");
                eng().emit("call", serde_json::json!({ "kind": "handled" }));
            } else if s
                .group_incoming
                .as_ref()
                .is_some_and(|o| o.call_instance == call_id)
            {
                s.group_incoming = None;
                eng().cancel_ring(&call_id, "");
                eng().emit("group_call", serde_json::json!({ "kind": "handled" }));
            }
        }
        InboundEvent::GroupCallOffered {
            sender_identity_key,
            sender_username,
            group_id,
            call_instance,
            call_id,
            key_b64,
            ..
        } => {
            let mut s = inner.lock().await;
            // Membership gate: we must know the group, and the ratchet-authenticated
            // sender (attributed device → account) must be on its roster. Anyone else's
            // "offer" is discarded unanswered — a non-member cannot ring us into a
            // group, and cannot probe whether we consider them a member.
            let Some(group) = s.history.group(&group_id).cloned() else {
                return;
            };
            let account_key = s.history.attribute_device(&sender_identity_key);
            if !group
                .members
                .iter()
                .any(|m| m.identity_key == account_key || m.identity_key == sender_identity_key)
            {
                return;
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
            if let Some(gc) = s
                .group_call
                .as_mut()
                .filter(|g| g.call_instance == call_instance)
            {
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
            // Already ringing for this call: collect the ticket for the accept.
            if let Some(pending) = s
                .group_incoming
                .as_mut()
                .filter(|o| o.call_instance == call_instance)
            {
                pending
                    .offers
                    .insert(sender_identity_key, (username, call_id, key_b64));
                return;
            }
            // Busy with anything else, or the sender is blocked: silent decline for
            // this instance only (mirrors the 1:1 auto-decline).
            if s.call.is_some()
                || s.incoming.is_some()
                || s.reconnect.is_some()
                || s.group_call.is_some()
                || s.group_incoming.is_some()
                || s.history.peer_blocked(&sender_identity_key)
            {
                let sess = &mut *s;
                if let Some(account) = sess.account.as_mut() {
                    let contact = contact_for(&username, &sender_identity_key);
                    let _ = client
                        .send_group_call_end(account, &contact, &group_id, &call_instance)
                        .await;
                }
                let _ = s.persist();
                return;
            }
            // Fresh ring.
            let group_name = group.name.clone();
            s.group_incoming = Some(PendingGroupOffer {
                call_instance: call_instance.clone(),
                group_id,
                group_name: group_name.clone(),
                rang_by: sender_identity_key.clone(),
                rang_by_username: username.clone(),
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
            eng().call_buttons_start(&call_instance);
            if !eng().on_screen() {
                eng().show_ring(&call_instance, &ring_name, true);
            }
            let inner = inner.clone();
            eng().spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(RING_TIMEOUT_SECS)).await;
                let mut s = inner.lock().await;
                if let Some(o) = s
                    .group_incoming
                    .take_if(|o| o.call_instance == call_instance)
                {
                    eng().cancel_ring(&call_instance, &ring_name);
                    log_group_call_event(
                        &mut s,
                        &o.group_id,
                        &format!("📞 Missed group call from {}", o.rang_by_username),
                    );
                    eng().emit("group_call", serde_json::json!({ "kind": "missed" }));
                }
            });
        }
        InboundEvent::GroupCallEnded {
            sender_identity_key,
            call_instance,
            ..
        } => {
            let mut s = inner.lock().await;
            let departed_name = s.history.username_for_peer(&sender_identity_key);
            if let Some(gc) = s
                .group_call
                .as_mut()
                .filter(|g| g.call_instance == call_instance)
            {
                // Their leg (if any) dies on its own when they leave the pair room;
                // this clears the pair so a rejoin can re-establish it. Marking them
                // departed cancels any pending automatic re-offer — they *meant* to go.
                gc.legs_added.remove(&sender_identity_key);
                let username = departed_name.unwrap_or_default();
                if !username.is_empty() {
                    gc.departed.insert(username.clone());
                }
                // "Declined" only for a member who never connected; a connected member
                // hanging up is a *leave*, and the engine's PeerLeft already tells the
                // UI — a "declined" toast there would be wrong.
                if !gc
                    .connected
                    .lock()
                    .unwrap()
                    .contains_key(&sender_identity_key)
                {
                    eng().emit(
                        "group_call",
                        serde_json::json!({ "kind": "peer_declined", "username": username }),
                    );
                }
            } else if let Some(pending) = s
                .group_incoming
                .as_mut()
                .filter(|o| o.call_instance == call_instance)
            {
                if pending.rang_by == sender_identity_key {
                    // The caller cancelled — stop ringing (shade ring included).
                    let gname = pending.group_name.clone();
                    let (gid, from) = (pending.group_id.clone(), pending.rang_by_username.clone());
                    s.group_incoming = None;
                    let name = ring_title(&s, &gname);
                    eng().cancel_ring(&call_instance, &name);
                    log_group_call_event(
                        &mut s,
                        &gid,
                        &format!("📞 Missed group call from {from}"),
                    );
                    eng().emit("group_call", serde_json::json!({ "kind": "missed" }));
                } else {
                    pending.offers.remove(&sender_identity_key);
                }
            }
        }
        _ => {}
    }
}
