use crate::*;

/// (Re-)apply the push half of the current delivery mode. Modes `cp`/`p` register the
/// FCM endpoint for this device's mailbox (idempotent upsert; re-run on unlock and on
/// token rotation); mode `c` unregisters. Crash-safe ordering for mode transitions is
/// the caller's job (`set_delivery_mode`): register-before-stop / start-before-
/// unregister — never a gap with neither transport live.
pub(crate) async fn do_push_registration(inner: &Arc<Mutex<Session>>) {
    let mut s = inner.lock().await;
    let mode = s.prefs.delivery_mode.clone();
    let Some(client) = s.client.clone() else {
        return;
    };
    let (mailbox, unlocked) = {
        let Some(account) = s.account.as_ref() else {
            return; // registration is challenge-signed; retried on next unlock
        };
        let mailbox = if s.history.is_primary_device() {
            account.identity_hash().as_str().to_string()
        } else {
            match client.device_mailbox(account.account_id(), &s.history.self_device_id()) {
                Ok(h) => h,
                Err(_) => return,
            }
        };
        (mailbox, true)
    };
    let _ = unlocked;
    if mode == "c" {
        // Connection-only: drop any registered endpoint (start-before-unregister — the
        // FGS was already started by the caller).
        if s.prefs.push_endpoint.is_some() {
            let ok = {
                let account = s.account.as_ref().expect("checked above");
                client.unregister_push_as(account, &mailbox).await.is_ok()
            };
            if ok {
                s.prefs.push_endpoint = None;
                let _ = s.save_prefs();
            }
        }
        return;
    }
    // cp / p need a wake transport. UnifiedPush (user-chosen distributor, §6.7) wins
    // over the system FCM token whenever both exist — the user explicitly picked a
    // Google-free broker; FCM stays as the silent fallback on stock devices with no
    // distributor installed. With neither, kick an async token fetch (it lands via
    // `nativeSetPushToken`, which re-runs this function; a distributor endpoint lands
    // via `nativeSetUpEndpoint`, same effect) and drop any stale relay registration —
    // a wake POSTed at a dead endpoint is silent loss dressed up as coverage.
    let endpoint = match eng()
        .up_endpoint()
        .or_else(|| eng().push_token().map(|t| format!("fcm:{t}")))
    {
        Some(e) => e,
        None => {
            if s.prefs.push_endpoint.is_some() {
                let ok = {
                    let account = s.account.as_ref().expect("checked above");
                    client.unregister_push_as(account, &mailbox).await.is_ok()
                };
                if ok {
                    s.prefs.push_endpoint = None;
                    let _ = s.save_prefs();
                }
            }
            notifier::request_push_token();
            return;
        }
    };
    if s.prefs.push_endpoint.as_deref() == Some(endpoint.as_str()) {
        return; // already registered with this exact endpoint
    }
    let ok = {
        let account = s.account.as_ref().expect("checked above");
        client
            .register_push_as(account, &mailbox, &endpoint)
            .await
            .is_ok()
    };
    if ok {
        s.prefs.push_endpoint = Some(endpoint);
        let _ = s.save_prefs();
    }
}

pub(crate) fn spawn_push_registration(inner: &Arc<Mutex<Session>>) {
    let inner = inner.clone();
    eng().spawn(async move {
        do_push_registration(&inner).await;
    });
}

/// Resolve the delivery-mode DEFAULT for users who never touched the setting: prefer
/// battery-friendly **push only** wherever a wake transport is actually usable (stock
/// Android: Play Services + a relay with FCM; de-Googled: the UnifiedPush distributor +
/// a relay wake path), and stay in **connection** mode everywhere else — push-only
/// without a wake path is silent message loss. Runs after every unlock and whenever a
/// push transport appears or disappears; an explicit choice in settings
/// (`delivery_mode_set`) turns this off forever. `"cp"` predates the flag and was never
/// a default, so it is treated as an explicit choice too.
pub(crate) async fn maybe_auto_delivery_mode(inner: &Arc<Mutex<Session>>) {
    let (user_set, mode, client, unlocked) = {
        let s = inner.lock().await;
        (
            s.prefs.delivery_mode_set,
            s.prefs.delivery_mode.clone(),
            s.client.clone(),
            s.account.is_some(),
        )
    };
    if user_set || mode == "cp" || !unlocked {
        return;
    }
    let Some(client) = client else { return };
    // Device-side transports (Android only — desktop has no push and keeps "c").
    let Some(h) =
        notifier::health_json().and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
    else {
        return;
    };
    let play = h["play_services"].as_bool().unwrap_or(false);
    let up_live = eng().up_endpoint().is_some()
        || !h["up_distributor"].as_str().unwrap_or_default().is_empty();
    let caps = client.server_capabilities().await.unwrap_or_default();
    let relay_fcm = caps.iter().any(|c| c == client_core::CAP_PUSH_FCM);
    let relay_webhook = caps.iter().any(|c| c == client_core::CAP_PUSH_WEBHOOK);
    // De-Googled phone, relay can wake, exactly ONE distributor installed and none
    // selected: adopt it — there is nothing to choose between, and without an endpoint
    // "push only" can never become the default. The endpoint lands async
    // (`nativeSetUpEndpoint` → on_new_up_endpoint), which re-runs this function.
    if !play && !up_live && relay_webhook {
        let dists = notifier::up_distributors()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
        if let Some([only]) = dists.as_ref().and_then(|d| d.as_array()).map(Vec::as_slice) {
            if let Some(pkg) = only["pkg"].as_str() {
                notifier::up_register(pkg);
            }
        }
        return;
    }
    let push_ok = (play && relay_fcm) || (up_live && (relay_webhook || relay_fcm));
    let target = if push_ok { "p" } else { "c" };
    if mode == target {
        return;
    }
    {
        let mut s = inner.lock().await;
        // Re-check under the lock — a settings tap may have raced the probes above.
        if s.prefs.delivery_mode_set || s.account.is_none() {
            return;
        }
        s.prefs.delivery_mode = target.into();
        let _ = s.save_prefs();
    }
    // Apply with the same crash-safe ordering as an explicit switch: the incoming
    // transport comes up before the outgoing one goes down.
    if target == "p" {
        do_push_registration(inner).await;
        delivery_service::set_background_delivery(false);
        eng().set_conn_state(notifier::ConnState::Off);
    } else {
        // Wake transport vanished (distributor uninstalled/revoked): back to the
        // always-on connection so nothing is silently lost.
        delivery_service::set_background_delivery(true);
        eng().set_conn_state(notifier::ConnState::Reconnecting);
        do_push_registration(inner).await;
    }
}

/// Kotlin delivered a (possibly rotated) FCM registration token (`onNewToken`, or the
/// fetch kicked by [`do_push_registration`]). Store it and re-run registration.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn on_new_push_token(token: String) {
    eng().set_push_token(token);
    let inner = eng().session.clone();
    eng().spawn(async move {
        do_push_registration(&inner).await;
        maybe_auto_delivery_mode(&inner).await; // a wake transport just appeared
    });
}

/// The UnifiedPush distributor delivered (or revoked — empty string) an endpoint URL.
/// Reconcile the relay registration either way: a fresh URL registers (UnifiedPush
/// outranks FCM), a revoked one falls back to the token or unregisters.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn on_new_up_endpoint(endpoint: String) {
    eng().set_up_endpoint(Some(endpoint));
    let inner = eng().session.clone();
    eng().spawn(async move {
        do_push_registration(&inner).await;
        maybe_auto_delivery_mode(&inner).await; // a wake transport appeared (or was revoked)
    });
}

/// Headless persistent start (Android): the sticky-restart shell, the boot receiver,
/// or a wake in connection mode. Tries the silent auto-unlock; on success the full
/// delivery stack comes up exactly as after an interactive unlock. Without
/// auto-unlock the FGS text says so — the one thing it must never do is lie (§4.5).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) async fn headless_start(inner: &Arc<Mutex<Session>>) {
    let mut s = inner.lock().await;
    if s.account.is_some() {
        if s.stop.is_none() {
            // Unlocked but no loops (e.g. a drain finished earlier): start them.
            spawn_subscriber(inner, &mut s);
            spawn_push_registration(inner);
        }
        return;
    }
    match attempt_auto_unlock(&mut s) {
        Some(account) => {
            if finish_unlock(inner, &mut s, account).await.is_err() {
                eng().set_conn_state(notifier::ConnState::Locked);
            }
        }
        None => {
            // PIN/password-only (or before the first device unlock after boot):
            // headless decrypt is impossible BY DESIGN. Say so truthfully.
            eng().set_conn_state(notifier::ConnState::Locked);
        }
    }
}

/// Push-wake entry (Android, modes P/C+P): drain the mailbox in a short burst, or
/// degrade honestly when the vault can't be opened headless (§7.4). `call_class` is
/// the one coarse bit the wake carried (`"t":"c"`).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) async fn headless_wake(inner: &Arc<Mutex<Session>>, call_class: bool) {
    let mut s = inner.lock().await;
    // Live subscriber already draining this mailbox (C+P with a healthy socket — the
    // relay only wakes when it saw no subscriber, so this is a rare race): done.
    if s.account.is_some() && s.stop.is_some() {
        notifier::drain_finished();
        return;
    }
    if s.account.is_none() {
        match attempt_auto_unlock(&mut s) {
            Some(account) => {
                if s.prefs.delivery_mode == "p" {
                    // Drain lifetime: install the account only; loops below.
                    if install_unlocked_account(&mut s, account).await.is_err() {
                        notifier::drain_finished();
                        return;
                    }
                    // The capability probe ran inside install; multi-device forwards
                    // work in the drain exactly as on the socket.
                } else {
                    // Mode C/C+P: a wake means the persistent stack is down — bring
                    // the whole thing back up, then release the shortService.
                    let _ = finish_unlock(inner, &mut s, account).await;
                    notifier::drain_finished();
                    return;
                }
            }
            None => {
                // Locked, no auto-unlock: content-free generic per wake class —
                // never silent loss, never a decrypt (§7.4).
                notifier::show_generic(if call_class {
                    notifier::Generic::LockedCall
                } else {
                    notifier::Generic::MaybeMessages
                });
                notifier::drain_finished();
                return;
            }
        }
    } else if s.prefs.delivery_mode != "p" {
        // Unlocked, loops dead, connection mode: full restart is the right shape.
        spawn_subscriber(inner, &mut s);
        spawn_push_registration(inner);
        notifier::drain_finished();
        return;
    }
    // ── Drain mode proper (mode P, unlocked): one bounded burst over the main
    // mailbox, plus a one-shot outbox drain. Same pipeline as the live socket —
    // decrypt, poison acks, notif decisions, ring — different lifetime. ──
    let Some(client) = s.client.clone() else {
        notifier::drain_finished();
        return;
    };
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    if let Some(old) = s.stop.replace(stop_tx) {
        let _ = old.send(true);
    }
    let main_hash = if s.history.is_primary_device() {
        None
    } else if let Some(account) = s.account.as_ref() {
        client
            .device_mailbox(account.account_id(), &s.history.self_device_id())
            .ok()
    } else {
        None
    };
    let loop_handle = spawn_delivery_loop(
        inner.clone(),
        client.clone(),
        stop_rx,
        main_hash,
        None,
        true,
    );
    {
        let inner = inner.clone();
        let client = client.clone();
        eng().spawn(async move {
            drain_outbox(&inner, &client).await;
        });
    }
    // Once the drain loop task ends, no receiver holds the watch channel any more —
    // clear the session's stop handle (unless a real unlock replaced it meanwhile,
    // whose channel has live receivers) so the next wake starts a fresh drain
    // instead of mistaking the dead handle for a live subscriber.
    let inner2 = inner.clone();
    drop(s);
    eng().spawn(async move {
        let _ = loop_handle.await;
        let mut s = inner2.lock().await;
        if s.stop.as_ref().is_some_and(|tx| tx.is_closed()) {
            s.stop = None;
        }
    });
}

/// A user-facing notification action arrived from the OS shade (Android). Validated
/// against live state in Rust — an unknown call id is a no-op, so a spoofed/stale
/// action can't decline someone else's ring.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) async fn notif_action(inner: &Arc<Mutex<Session>>, json: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return;
    };
    match v["action"].as_str() {
        Some("decline_call") => {
            let call_id = v["call_id"].as_str().unwrap_or_default();
            let mut s = inner.lock().await;
            // 1:1 ring?
            if s.incoming.as_ref().is_some_and(|o| o.call_id == call_id) {
                let offer = s.incoming.take().expect("checked");
                eng().cancel_ring(&offer.call_id, "");
                let Some(client) = s.client.clone() else {
                    return;
                };
                let _ = send_call_answer_everywhere(
                    &client,
                    &mut s,
                    &offer.username,
                    &offer.peer_key,
                    &offer.call_id,
                    false,
                    false,
                )
                .await;
                ring_handled_selfsync(&client, &mut s, &offer.call_id).await;
                log_call_event(&mut s, &offer.peer_key, "📞 Declined call");
                eng().emit("call", serde_json::json!({ "kind": "missed" }));
            } else if s
                .group_incoming
                .as_ref()
                .is_some_and(|o| o.call_instance == call_id)
            {
                let offer = s.group_incoming.take().expect("checked");
                eng().cancel_ring(&offer.call_instance, "");
                let Some(client) = s.client.clone() else {
                    return;
                };
                {
                    let sess = &mut *s;
                    if let Some(account) = sess.account.as_mut() {
                        for (peer_key, (username, _, _)) in &offer.offers {
                            let contact = contact_for(username, peer_key);
                            let _ = client
                                .send_group_call_end(
                                    account,
                                    &contact,
                                    &offer.group_id,
                                    &offer.call_instance,
                                )
                                .await;
                        }
                    }
                }
                ring_handled_selfsync(&client, &mut s, &offer.call_instance).await;
                log_group_call_event(&mut s, &offer.group_id, "📞 Declined group call");
                eng().emit("group_call", serde_json::json!({ "kind": "missed" }));
            }
        }
        // Bluetooth/headset button while ringing (MediaSession tap → accept). Same
        // validation discipline as decline: an id that doesn't match the live ring
        // is a no-op, so a stale button event can't answer a later call.
        Some("accept_call") => {
            let call_id = v["call_id"].as_str().unwrap_or_default().to_string();
            let (is_call, is_group) = {
                let s = inner.lock().await;
                (
                    s.incoming.as_ref().is_some_and(|o| o.call_id == call_id),
                    s.group_incoming
                        .as_ref()
                        .is_some_and(|o| o.call_instance == call_id),
                )
            };
            if is_call {
                if call_accept_inner(inner).await.is_ok() {
                    eng().emit("call", serde_json::json!({ "kind": "accepted" }));
                }
            } else if is_group && group_call_accept_inner(inner).await.is_ok() {
                eng().emit("group_call", serde_json::json!({ "kind": "accepted" }));
            }
        }
        // Mark-read / inline-reply exist only on REAL (decrypted) message
        // notifications — the locked-state generics never carry these actions,
        // because acting on an unknown message is meaningless. The vault can still
        // lock between posting and the tap, so both arms re-check and degrade
        // honestly instead of silently dropping the user's input.
        Some("mark_read") => {
            let chat = v["chat"].as_str().unwrap_or_default().to_string();
            if chat.is_empty() {
                return;
            }
            let mut s = inner.lock().await;
            if s.account.is_none() {
                return; // locked: can't mark anything; the notification stays honest
            }
            if s.history.group(&chat).is_some() {
                s.history.mark_group_seen(&chat);
                let _ = s.persist();
            } else {
                // 1:1: chat key is the peer identity key; the receipt path needs the
                // username too. An unknown key (contact since deleted) is a no-op.
                let Some(username) = s
                    .history
                    .contacts()
                    .into_iter()
                    .find(|(_, p)| p.identity_key == chat)
                    .map(|(u, _)| u)
                else {
                    return;
                };
                drop(s);
                if mark_seen_inner(inner, username, chat.clone())
                    .await
                    .is_err()
                {
                    return; // receipt failed: leave the notification standing
                }
            }
            eng().clear_chat_notif(&chat);
            eng().emit("sync", ());
        }
        Some("reply") => {
            let chat = v["chat"].as_str().unwrap_or_default().to_string();
            let text = v["text"].as_str().unwrap_or_default().trim().to_string();
            if chat.is_empty() || text.is_empty() {
                return;
            }
            // Every outcome MUST repost the notification — that is what clears the
            // RemoteInput spinner in the shade.
            let target = {
                let s = inner.lock().await;
                if s.account.is_none() {
                    None // locked between post and tap
                } else if s.history.group(&chat).is_some() {
                    Some((None, true))
                } else {
                    s.history
                        .contacts()
                        .into_iter()
                        .find(|(_, p)| p.identity_key == chat)
                        .map(|(u, _)| (Some(u), false))
                }
            };
            let outcome = match target {
                None => Err("Unlock Sona to send — reply not sent".to_string()),
                Some((_, true)) => send_group_inner(inner, chat.clone(), text.clone(), None)
                    .await
                    .map_err(|e| format!("Reply failed: {e}")),
                Some((Some(username), false)) => send_inner(inner, username, text.clone(), None)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("Reply failed: {e}")),
                Some((None, false)) => Err("Reply failed: unknown contact".to_string()),
            };
            match outcome {
                Ok(()) => {
                    eng().append_chat_line(&chat, "You", &text);
                    eng().emit("sync", ());
                }
                Err(msg) => eng().append_chat_line(&chat, "Sona", &msg),
            }
        }
        _ => {}
    }
}
