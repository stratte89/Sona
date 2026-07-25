use crate::*;

/// Establish the pair leg toward `peer_key`, once we know they are in the call.
///
/// Owner rule: the pair room is the one minted by the lexicographically smaller
/// identity key — both sides compute this locally and converge on one room with no
/// extra round trip; the loser's lonely room is reaped by the relay's GC.
///
/// A room key is used **once, ever** (`used_call_ids`): if we own the pair and our
/// current ticket was already consumed (their leg died and they are rejoining), we
/// mint a fresh ticket, offer it, and join the fresh room — re-deriving a consumed
/// key would restart the seal counter and reuse nonces.
pub(crate) async fn establish_group_leg(
    inner: Arc<Mutex<Session>>,
    client: Arc<Client>,
    call_instance: String,
    peer_key: String,
    username: String,
    their_ticket: Option<(String, String)>,
) {
    // ── Decide the room under the session lock; send a fresh offer if we must mint. ──
    let (call_id, key_b64, caller, leg_tx) = {
        let mut s = inner.lock().await;
        // Snapshot what the decision needs, then release the ctl borrow.
        let (i_own, group_id, current_ticket, known_member) = {
            let Some(gc) = s
                .group_call
                .as_ref()
                .filter(|g| g.call_instance == call_instance)
            else {
                return;
            };
            if gc.legs_added.contains(&peer_key) {
                return;
            }
            (
                gc.my_key.as_str() < peer_key.as_str(),
                gc.group_id.clone(),
                gc.my_tickets
                    .get(&username)
                    .filter(|(id, _)| !gc.used_call_ids.contains(id))
                    .cloned(),
                gc.my_tickets.contains_key(&username),
            )
        };
        let ticket = if i_own {
            match current_ticket {
                Some(t) => Some(t),
                // Our ticket was consumed — the peer's old leg died and they are
                // rejoining. Mint a fresh room (a key is used once, ever) and offer it
                // through the roster-resolved member (not the claimed username).
                None if known_member => {
                    let fresh = client_core::call::CallTicket::mint();
                    let member = s
                        .history
                        .group(&group_id)
                        .and_then(|g| g.members.iter().find(|m| m.username == username).cloned());
                    let Some(member) = member else { return };
                    let multi = s.multi_device;
                    {
                        let sess = &mut *s;
                        let Some(account) = sess.account.as_mut() else {
                            return;
                        };
                        let Ok(contact) = client.member_contact(account, &member).await else {
                            return;
                        };
                        if client
                            .send_group_call_offer(
                                account,
                                &contact,
                                &group_id,
                                &call_instance,
                                &fresh.call_id,
                                &fresh.key_b64,
                            )
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if multi {
                            if let Ok(extras) = client
                                .extra_group_call_offer_envelopes(
                                    account,
                                    &mut sess.history,
                                    &contact,
                                    &group_id,
                                    &call_instance,
                                    &fresh.call_id,
                                    &fresh.key_b64,
                                )
                                .await
                            {
                                for env in &extras {
                                    let _ = client.post_envelope(env).await;
                                }
                            }
                        }
                    }
                    let _ = s.persist();
                    if let Some(gc) = s
                        .group_call
                        .as_mut()
                        .filter(|g| g.call_instance == call_instance)
                    {
                        gc.my_tickets.insert(
                            username.clone(),
                            (fresh.call_id.clone(), fresh.key_b64.clone()),
                        );
                    }
                    Some((fresh.call_id, fresh.key_b64))
                }
                None => return, // not a member we rang — refuse quietly
            }
        } else {
            // They own the pair: join the room from THEIR offer (arrives with presence).
            their_ticket
        };
        let Some((call_id, key_b64)) = ticket else {
            return; // their offer hasn't arrived yet; it will
        };
        let Some(gc) = s
            .group_call
            .as_mut()
            .filter(|g| g.call_instance == call_instance)
        else {
            return;
        };
        if gc.legs_added.contains(&peer_key) || !gc.used_call_ids.insert(call_id.clone()) {
            return; // raced another establish, or the key was already used once — never re-derive
        }
        gc.legs_added.insert(peer_key.clone());
        (call_id, key_b64, i_own, gc.leg_tx.clone())
    };

    // ── Join the room off-lock and hand the leg to the engine. ──
    match client.join_call(&call_id).await {
        Ok(media) => {
            let _ = leg_tx.send(client_core::groupcall::GroupLeg {
                peer_key,
                username,
                media,
                key_b64,
                caller,
            });
        }
        Err(_) => {
            // Network blip: un-mark the pair so a later offer retries the leg. The
            // room id is released too — its key was never derived, so a retry is
            // its first (and only) use.
            let mut s = inner.lock().await;
            if let Some(gc) = s
                .group_call
                .as_mut()
                .filter(|g| g.call_instance == call_instance)
            {
                gc.legs_added.remove(&peer_key);
                gc.used_call_ids.remove(&call_id);
            }
        }
    }
}

/// Send our leave/decline for `call_instance` to every other group member (and, on a
/// multi-device relay, every device in their verified roster). Best-effort.
pub(crate) async fn send_group_call_end_everywhere(
    client: &Arc<Client>,
    s: &mut Session,
    group_id: &str,
    call_instance: &str,
) {
    let Some(group) = s.history.group(group_id).cloned() else {
        return;
    };
    let multi = s.multi_device;
    let sess = &mut *s;
    let Some(account) = sess.account.as_mut() else {
        return;
    };
    let me = account.account_id().to_string();
    for member in group.members.iter().filter(|m| m.username != me) {
        let Ok(contact) = client.member_contact(account, member).await else {
            continue;
        };
        let _ = client
            .send_group_call_end(account, &contact, group_id, call_instance)
            .await;
        if multi {
            if let Ok(extras) = client
                .extra_group_call_end_envelopes(
                    account,
                    &mut sess.history,
                    &contact,
                    group_id,
                    call_instance,
                )
                .await
            {
                for env in &extras {
                    let _ = client.post_envelope(env).await;
                }
            }
        }
    }
}

/// Start local audio + the mesh engine and install the [`GroupCallCtl`]. Legs are fed
/// in later as presence is learned (see [`start_group_leg`]).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_group_call(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    s: &mut Session,
    group_id: String,
    group_name: String,
    call_instance: String,
    my_key: String,
    my_tickets: std::collections::HashMap<String, (String, String)>,
) -> Result<(), String> {
    use std::sync::atomic::AtomicBool;

    #[cfg(target_os = "android")]
    android_media::ensure_mic_permission();
    let (audio, _aux_tx) = eng()
        .spawn_blocking(|| audio::start(None))
        .await
        .map_err(|e| e.to_string())??;

    let muted = Arc::new(AtomicBool::new(false));
    let connected: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let connected_at = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (leg_tx, leg_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel();

    {
        let muted = muted.clone();
        eng().spawn(async move {
            let _ =
                client_core::groupcall::run_group_call(leg_rx, audio, stop_rx, muted, ev_tx).await;
        });
    }

    // Event pump: engine → UI; clears the session state when the engine ends.
    {
        use client_core::groupcall::GroupCallEvent;
        let inner = inner.clone();
        let client = client.clone();
        let connected = connected.clone();
        let connected_at = connected_at.clone();
        let call_instance = call_instance.clone();
        eng().spawn(async move {
            while let Some(ev) = ev_rx.recv().await {
                match ev {
                    GroupCallEvent::PeerConnected { peer_key } => {
                        // First flowing leg = the call connected (history-chip duration).
                        let _ = connected_at.compare_exchange(
                            0,
                            now_secs(),
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        let username = {
                            let mut s = inner.lock().await;
                            let name = s
                                .history
                                .username_for_peer(&peer_key)
                                .unwrap_or_else(|| peer_key.chars().take(8).collect());
                            // A working leg resets the member's re-offer budget.
                            if let Some(gc) = s
                                .group_call
                                .as_mut()
                                .filter(|g| g.call_instance == call_instance)
                            {
                                gc.reoffer_attempts.remove(&name);
                            }
                            name
                        };
                        connected
                            .lock()
                            .unwrap()
                            .insert(peer_key.clone(), username.clone());
                        eng().emit(
                            "group_call",
                            serde_json::json!({ "kind": "peer_connected", "username": username }),
                        );
                    }
                    GroupCallEvent::PeerLeft { peer_key } => {
                        let username = connected.lock().unwrap().remove(&peer_key);
                        let mut s = inner.lock().await;
                        // Name resolution first (history), before the ctl borrow: the
                        // leg may have died before it ever connected.
                        let name_lookup = username
                            .clone()
                            .or_else(|| s.history.username_for_peer(&peer_key));
                        let mut reoffer_as: Option<String> = None;
                        if let Some(gc) = s
                            .group_call
                            .as_mut()
                            .filter(|g| g.call_instance == call_instance)
                        {
                            gc.legs_added.remove(&peer_key);
                            // A leg that died WITHOUT a GroupCallEnd is a network drop,
                            // not a leave: the pair's owner re-offers a fresh room (see
                            // establish_group_leg — a room key is never reused). The
                            // non-owner side just waits for that offer. Deliberate
                            // leavers (`departed`) are never re-rung.
                            if let Some(name) = name_lookup {
                                let i_own = gc.my_key.as_str() < peer_key.as_str();
                                let attempts = gc.reoffer_attempts.entry(name.clone()).or_insert(0);
                                if i_own
                                    && !gc.departed.contains(&name)
                                    && *attempts < MAX_LEG_REOFFERS
                                {
                                    *attempts += 1;
                                    reoffer_as = Some(name);
                                }
                            }
                        }
                        drop(s);
                        if let Some(name) = reoffer_as {
                            let inner = inner.clone();
                            let client = client.clone();
                            let call_instance = call_instance.clone();
                            let peer_key = peer_key.clone();
                            eng().spawn(async move {
                                // Grace period: if the peer meant to leave, their
                                // GroupCallEnd lands within it and marks them departed.
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    LEG_REOFFER_DELAY_MS,
                                ))
                                .await;
                                {
                                    let s = inner.lock().await;
                                    let cancelled = s
                                        .group_call
                                        .as_ref()
                                        .filter(|g| g.call_instance == call_instance)
                                        .is_none_or(|g| g.departed.contains(&name));
                                    if cancelled {
                                        return;
                                    }
                                }
                                establish_group_leg(
                                    inner,
                                    client,
                                    call_instance,
                                    peer_key,
                                    name,
                                    None, // owner path mints the fresh ticket itself
                                )
                                .await;
                            });
                        }
                        eng().emit(
                            "group_call",
                            serde_json::json!({
                                "kind": "peer_left",
                                "username": username.unwrap_or_default(),
                            }),
                        );
                    }
                    GroupCallEvent::Ended => {
                        let mut s = inner.lock().await;
                        if let Some(gc) = s.group_call.take_if(|g| g.call_instance == call_instance)
                        {
                            log_group_call_event(
                                &mut s,
                                &gc.group_id,
                                &call_end_label(
                                    "Group call",
                                    true,
                                    gc.connected_at.load(std::sync::atomic::Ordering::Relaxed),
                                ),
                            );
                            eng().emit("group_call", serde_json::json!({ "kind": "ended" }));
                        }
                        break;
                    }
                }
            }
        });
    }

    s.group_call = Some(GroupCallCtl {
        call_instance,
        group_id,
        group_name,
        my_key,
        muted,
        legs_added: std::collections::HashSet::new(),
        my_tickets,
        used_call_ids: std::collections::HashSet::new(),
        departed: std::collections::HashSet::new(),
        reoffer_attempts: std::collections::HashMap::new(),
        connected,
        connected_at,
        leg_tx,
        stop: stop_tx,
    });
    Ok(())
}

/// Ring every member of the group: one fresh pair ticket per member, sent as an offer
/// over their ratchet session plus multi-device fan copies. Shared by starting a call
/// and accepting a ring — joining a group call IS this: tell every member "I'm in,
/// here's our pair room".
pub(crate) async fn send_offers_for_group(
    client: &Arc<Client>,
    s: &mut Session,
    group_id: &str,
    call_instance: &str,
    members: &[client_core::GroupMember],
) -> Result<std::collections::HashMap<String, (String, String)>, String> {
    let multi = s.multi_device;
    let mut my_tickets = std::collections::HashMap::new();
    let sess = &mut *s;
    let account = sess.account.as_mut().ok_or("locked")?;
    for member in members {
        let ticket = client_core::call::CallTicket::mint();
        // One unreachable/unresolvable member must not kill the call for everyone —
        // skip them (their pair simply never forms this call).
        let Ok(contact) = client.member_contact(account, member).await else {
            continue;
        };
        if client
            .send_group_call_offer(
                account,
                &contact,
                group_id,
                call_instance,
                &ticket.call_id,
                &ticket.key_b64,
            )
            .await
            .is_err()
        {
            continue;
        }
        if multi {
            if let Ok(extras) = client
                .extra_group_call_offer_envelopes(
                    account,
                    &mut sess.history,
                    &contact,
                    group_id,
                    call_instance,
                    &ticket.call_id,
                    &ticket.key_b64,
                )
                .await
            {
                for env in &extras {
                    let _ = client.post_envelope(env).await;
                }
            }
        }
        my_tickets.insert(member.username.clone(), (ticket.call_id, ticket.key_b64));
    }
    if my_tickets.is_empty() {
        return Err("no group member could be reached".into());
    }
    Ok(my_tickets)
}

/// Start a group call: ring every member and wait in the (per-pair) rooms we own.
#[tauri::command]
pub async fn group_call_start(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if s.call.is_some()
        || s.incoming.is_some()
        || s.reconnect.is_some()
        || s.group_call.is_some()
        || s.group_incoming.is_some()
    {
        return Err("already in a call".into());
    }
    let client = s.client.clone().ok_or("not configured")?;
    let account = s.account.as_ref().ok_or("locked")?;
    let me = account.account_id().to_string();
    let my_key = account.ratchet_ref().identity_key();
    let group = s.history.group(&group_id).ok_or("unknown group")?;
    crate::cmd::groups::ensure_in_group(group)?;
    let group_name = group.name.clone();
    let others: Vec<client_core::GroupMember> = group
        .members
        .iter()
        .filter(|m| m.username != me)
        .cloned()
        .collect();
    if others.is_empty() {
        return Err("this group has no other members".into());
    }
    if others.len() + 1 > MAX_GROUP_CALL_MEMBERS {
        return Err(format!(
            "group calls support up to {MAX_GROUP_CALL_MEMBERS} members"
        ));
    }
    // The instance id is just 128 random bits, exactly like a room id.
    let call_instance = client_core::call::CallTicket::mint().call_id;

    let my_tickets =
        send_offers_for_group(&client, &mut s, &group_id, &call_instance, &others).await?;
    s.persist()?;
    eng().emit(
        "group_call",
        serde_json::json!({ "kind": "outgoing", "group_id": group_id, "name": group_name }),
    );
    spawn_group_call(
        &state.inner,
        &client,
        &mut s,
        group_id.clone(),
        group_name,
        call_instance.clone(),
        my_key,
        my_tickets,
    )
    .await?;

    // Ring timeout: nobody joined → tear down and tell everyone we're gone.
    spawn_group_no_answer_timeout(state.inner.clone(), client, call_instance);
    Ok(())
}

/// Tear the group call down if NOBODY's audio has connected within the ring window —
/// used by both the starter (nobody answered) and the accepter (everyone was already
/// gone by the time we joined), so neither side can sit on a spinner forever.
pub(crate) fn spawn_group_no_answer_timeout(
    inner: Arc<Mutex<Session>>,
    client: Arc<Client>,
    call_instance: String,
) {
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(RING_TIMEOUT_SECS)).await;
        let mut s = inner.lock().await;
        let nobody = s.group_call.as_ref().is_some_and(|g| {
            g.call_instance == call_instance && g.connected.lock().unwrap().is_empty()
        });
        if nobody {
            if let Some(gc) = s.group_call.take() {
                let _ = gc.stop.send(true);
                send_group_call_end_everywhere(&client, &mut s, &gc.group_id, &gc.call_instance)
                    .await;
                log_group_call_event(&mut s, &gc.group_id, "📞 Unanswered group call");
                eng().emit("group_call", serde_json::json!({ "kind": "no_answer" }));
            }
        }
    });
}

/// Accept the pending group ring: announce ourselves to every member (fresh pair
/// tickets) and join the legs of everyone already known to be in the call.
#[tauri::command]
pub async fn group_call_accept(state: tauri::State<'_, AppState>) -> Result<(), String> {
    group_call_accept_inner(&state.inner).await
}

/// See [`call_accept_inner`] — same rationale, group flavor.
pub(crate) async fn group_call_accept_inner(inner: &Arc<Mutex<Session>>) -> Result<(), String> {
    let mut s = inner.lock().await;
    let offer = s.group_incoming.take().ok_or("no incoming group call")?;
    eng().cancel_ring(&offer.call_instance, "");
    if s.call.is_some() || s.group_call.is_some() {
        return Err("already in a call".into());
    }
    let client = s.client.clone().ok_or("not configured")?;
    let account = s.account.as_ref().ok_or("locked")?;
    let me = account.account_id().to_string();
    let my_key = account.ratchet_ref().identity_key();
    let group = s.history.group(&offer.group_id).ok_or("unknown group")?;
    let others: Vec<client_core::GroupMember> = group
        .members
        .iter()
        .filter(|m| m.username != me)
        .cloned()
        .collect();

    let my_tickets = send_offers_for_group(
        &client,
        &mut s,
        &offer.group_id,
        &offer.call_instance,
        &others,
    )
    .await?;
    s.persist()?;
    spawn_group_call(
        inner,
        &client,
        &mut s,
        offer.group_id.clone(),
        offer.group_name.clone(),
        offer.call_instance.clone(),
        my_key,
        my_tickets,
    )
    .await?;
    // Join everyone whose offer arrived while we were ringing. (Spawned: each
    // establish re-locks the session after this command releases it.)
    for (peer_key, (username, call_id, key_b64)) in &offer.offers {
        eng().spawn(establish_group_leg(
            inner.clone(),
            client.clone(),
            offer.call_instance.clone(),
            peer_key.clone(),
            username.clone(),
            Some((call_id.clone(), key_b64.clone())),
        ));
    }
    // Stop our own other devices' ringing (best-effort, after the joins are underway).
    ring_handled_selfsync(&client, &mut s, &offer.call_instance).await;
    // Everyone may have left between the ring and our accept: never sit on the
    // connecting spinner past the ring window.
    spawn_group_no_answer_timeout(inner.clone(), client, offer.call_instance.clone());
    Ok(())
}

/// Decline the pending group ring: tell everyone already in the call (they offered us
/// a leg) that we're not coming.
#[tauri::command]
pub async fn group_call_decline(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let offer = s.group_incoming.take().ok_or("no incoming group call")?;
    eng().cancel_ring(&offer.call_instance, "");
    let client = s.client.clone().ok_or("not configured")?;
    {
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            for (peer_key, (username, _, _)) in &offer.offers {
                let contact = contact_for(username, peer_key);
                let _ = client
                    .send_group_call_end(account, &contact, &offer.group_id, &offer.call_instance)
                    .await;
            }
        }
    }
    ring_handled_selfsync(&client, &mut s, &offer.call_instance).await;
    log_group_call_event(&mut s, &offer.group_id, "📞 Declined group call");
    s.persist()
}

/// Leave the live group call (the others keep talking).
#[tauri::command]
pub async fn group_call_hangup(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let Some(gc) = s.group_call.take() else {
        return Ok(());
    };
    let _ = gc.stop.send(true);
    let client = s.client.clone().ok_or("not configured")?;
    send_group_call_end_everywhere(&client, &mut s, &gc.group_id, &gc.call_instance).await;
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
