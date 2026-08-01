use super::group_control::{
    send_group_call_claim_to_coordinator, send_offers_for_group, spawn_group_no_answer_timeout,
};
use crate::*;

/// Establish the pair leg toward `peer_key`, once we know they are in the call.
///
/// The lexicographically smaller identity key owns each pair room.
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
    let (i_own, group_id, ring_id, coordinator, current_ticket, known_member) = {
        let s = inner.lock().await;
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
            gc.ring_id.clone(),
            gc.coordinator.clone(),
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
                reoffer_group_leg(
                    &inner,
                    &client,
                    &call_instance,
                    &group_id,
                    &ring_id,
                    &coordinator,
                    &username,
                )
                .await
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
    let (caller, leg_tx) = {
        let mut s = inner.lock().await;
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
        (i_own, gc.leg_tx.clone())
    };

    // ── Join the room off-lock and hand the leg to the engine. ──
    match client.join_call(&call_id).await {
        Ok(media) => {
            let _ = leg_tx.send(client_core::groupcall::GroupLeg {
                peer_key,
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

/// Mint and offer a fresh pair room to one member whose leg died, with the session lock
/// released across the relay post. `None` when the member is unreachable or the call
/// ended meanwhile.
async fn reoffer_group_leg(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    call_instance: &str,
    group_id: &str,
    ring_id: &str,
    coordinator: &GroupCoordinator,
    username: &str,
) -> Option<(String, String)> {
    let fresh = client_core::call::CallTicket::mint();
    let offer_id = client_core::callstate::random_call_id();
    let created_at = now_secs();
    let ring_expires_at = created_at.saturating_add(client_core::callstate::CALL_RING_TIMEOUT_SECS);
    let expires_at = created_at.saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let offers = {
        let mut s = inner.lock().await;
        if !is_current(&s, client) {
            return None;
        }
        let member = s
            .history
            .group(group_id)
            .and_then(|g| g.members.iter().find(|m| m.username == username).cloned())?;
        let caller_device_id = s.history.self_device_id();
        let multi = s.multi_device;
        let sess = &mut *s;
        let account = sess.account.as_mut()?;
        let contact = client.member_contact_pinned(account, &member)?;
        let primary = client
            .prepare_group_call_offer_v2(
                account,
                &contact,
                group_id,
                call_instance,
                ring_id,
                &offer_id,
                &fresh.call_id,
                &fresh.key_b64,
                created_at,
                ring_expires_at,
                expires_at,
                &caller_device_id,
                &coordinator.username,
                &coordinator.identity_key,
                &coordinator.device_id,
                &coordinator.reply_to_mailbox,
                true,
            )
            .ok()?;
        let mut offers = vec![primary];
        if multi {
            if let Ok(mut extras) = client.extra_group_call_offer_envelopes_v2(
                account,
                &sess.history,
                &contact,
                group_id,
                call_instance,
                ring_id,
                &offer_id,
                &fresh.call_id,
                &fresh.key_b64,
                created_at,
                ring_expires_at,
                expires_at,
                &caller_device_id,
                &coordinator.username,
                &coordinator.identity_key,
                &coordinator.device_id,
                &coordinator.reply_to_mailbox,
                true,
            ) {
                offers.append(&mut extras);
            }
        }
        let _ = s.persist();
        offers
    };
    if !client
        .post_envelopes_concurrent(&offers)
        .await
        .iter()
        .any(Result::is_ok)
    {
        return None;
    }
    let mut s = inner.lock().await;
    let gc = s
        .group_call
        .as_mut()
        .filter(|g| g.call_instance == call_instance)?;
    gc.my_tickets.insert(
        username.to_string(),
        (fresh.call_id.clone(), fresh.key_b64.clone()),
    );
    Some((fresh.call_id, fresh.key_b64))
}

/// Start local audio + the mesh engine and install the [`GroupCallCtl`]. Legs are fed
/// in later as presence is learned (see [`start_group_leg`]).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_group_call(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    group_id: String,
    group_name: String,
    call_instance: String,
    ring_id: String,
    ring_handle: String,
    coordinator: GroupCoordinator,
    deadline: GroupRingDeadline,
    my_key: String,
    my_tickets: std::collections::HashMap<String, (String, String)>,
) -> Result<(), String> {
    use std::sync::atomic::AtomicBool;

    #[cfg(target_os = "android")]
    android_media::ensure_mic_permission();
    let (audio, _aux_tx) = eng()
        .spawn_blocking(audio::start)
        .await
        .map_err(|e| e.to_string())??;

    let muted = Arc::new(AtomicBool::new(false));
    // Per-listener volumes, shared with the mixing engine. Seeded per member as their
    // leg connects (below) — that is the first moment the peer key can be resolved to a
    // username, and it lands with the first frames.
    let gains = client_core::groupcall::PeerGains::default();
    // Mute and shared-audio level are per-call; the saved per-contact levels are not.
    crate::call::volume::reset_for_new_call();
    let connected: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let connected_at = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (leg_tx, leg_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel();

    {
        let muted = muted.clone();
        let gains = gains.clone();
        eng().spawn(async move {
            let _ =
                client_core::groupcall::run_group_call(leg_rx, audio, stop_rx, muted, gains, ev_tx)
                    .await;
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
        let ring_id = ring_id.clone();
        let gains = gains.clone();
        eng().spawn(async move {
            while let Some(ev) = ev_rx.recv().await {
                match ev {
                    GroupCallEvent::PeerConnected { peer_key } => {
                        {
                            let mut s = inner.lock().await;
                            let transition = s.calls().registry.transition(
                                &call_instance,
                                &ring_id,
                                client_core::callstate::CallPhase::Active,
                                now_secs(),
                            );
                            if !matches!(
                                transition,
                                client_core::callstate::TransitionDecision::Applied
                                    | client_core::callstate::TransitionDecision::Duplicate
                            ) {
                                if let Some(gc) =
                                    s.group_call.take_if(|g| g.call_instance == call_instance)
                                {
                                    let _ = gc.stop.send(true);
                                }
                                let _ = record_call_terminal(
                                    &mut s,
                                    &call_instance,
                                    &ring_id,
                                    client_core::callstate::CallTerminalReason::TransportError,
                                );
                                eng().emit("group_call", serde_json::json!({ "kind": "ended" }));
                                break;
                            }
                        }
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
                        // Apply this member's remembered volume now that the leg has a
                        // name to look it up by. Until this point they play as sent,
                        // which is a frame or two — the event lands with their audio.
                        {
                            let s = inner.lock().await;
                            let gain = s.history.voice_gain(&username);
                            if gain != client_core::call::GAIN_UNITY {
                                gains.set(&peer_key, gain);
                            }
                        }
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
                            // A leg that died WITHOUT a group terminal is a network drop,
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
                                // The terminal lands within it and marks them departed.
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

    let mut s = inner.lock().await;
    // The lock was released across audio start-up: a coordinator cancellation or our own
    // hangup may have ended this call in the meantime.
    if let Err(error) = call_still_live(&s, client, &call_instance) {
        let _ = stop_tx.send(true);
        return Err(error);
    }
    s.group_call = Some(GroupCallCtl {
        call_instance,
        ring_id,
        ring_handle,
        group_id,
        group_name,
        coordinator,
        deadline,
        my_key,
        muted,
        gains: gains.clone(),
        legs_added: std::collections::HashSet::new(),
        my_tickets,
        used_call_ids: std::collections::HashSet::new(),
        departed: std::collections::HashSet::new(),
        reoffer_attempts: std::collections::HashMap::new(),
        answer_arbiters: std::collections::HashMap::new(),
        connected,
        connected_at,
        leg_tx,
        stop: stop_tx,
    });
    Ok(())
}

/// Start a group call: ring every member and wait in the (per-pair) rooms we own.
///
/// Same lock discipline as [`call_start`]: member rosters are warmed, offers posted, and
/// pair rooms joined with the session mutex released.
#[tauri::command]
pub async fn group_call_start(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<(), String> {
    let inner = state.inner.clone();
    let slot = CallSlot::reserve(&inner).await?;
    let started = group_call_start_inner(&inner, &group_id).await;
    slot.release().await;
    started
}

async fn group_call_start_inner(inner: &Arc<Mutex<Session>>, group_id: &str) -> Result<(), String> {
    let (client, me, my_key, group_name, others) = {
        let s = inner.lock().await;
        let client = s.client.clone().ok_or("not configured")?;
        let account = s.account.as_ref().ok_or("locked")?;
        let me = account.account_id().to_string();
        let my_key = account.ratchet_ref().identity_key();
        let group = s.history.group(group_id).ok_or("unknown group")?;
        crate::cmd::groups::ensure_in_group(group)?;
        let others: Vec<client_core::GroupMember> = group
            .members
            .iter()
            .filter(|m| m.username != me)
            .cloned()
            .collect();
        (client, me, my_key, group.name.clone(), others)
    };
    if others.is_empty() {
        return Err("this group has no other members".into());
    }
    if others.len() + 1 > MAX_GROUP_CALL_MEMBERS {
        return Err(format!(
            "group calls support up to {MAX_GROUP_CALL_MEMBERS} members"
        ));
    }
    // Off-lock: every member's verified roster (so their linked devices are rung) and our
    // own (for the sibling terminal fan). Preparation below is then network-free.
    for member in &others {
        warm_call_routes(inner, &client, &member.username).await;
    }
    warm_call_routes(inner, &client, &me).await;

    let call_instance = client_core::call::CallTicket::mint().call_id;
    let ring_id = client_core::callstate::random_call_id();
    let created_at = now_secs();
    let deadline = GroupRingDeadline {
        created_at,
        ring_expires_at: created_at.saturating_add(client_core::callstate::CALL_RING_TIMEOUT_SECS),
        expires_at: created_at.saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS),
    };
    let coordinator = {
        let s = inner.lock().await;
        if !is_current(&s, &client) {
            return Err("not configured".into());
        }
        let coordinator_device_id = s.history.self_device_id();
        GroupCoordinator {
            username: me.clone(),
            identity_key: my_key.clone(),
            reply_to_mailbox: client
                .device_mailbox(&me, &coordinator_device_id)
                .map_err(|error| error.to_string())?,
            device_id: coordinator_device_id,
        }
    };

    let my_tickets = send_offers_for_group(
        inner,
        &client,
        group_id,
        &call_instance,
        &ring_id,
        &coordinator,
        deadline,
        &others,
    )
    .await?;
    {
        let mut s = inner.lock().await;
        call_still_live(&s, &client, &call_instance)?;
        let retention = call_retention_secs(&s); // before `s.calls()` borrows mutably
        let _ = s.calls().registry.receive_offer(
            &call_instance,
            &ring_id,
            deadline.created_at,
            deadline.ring_expires_at,
            created_at,
            retention,
        );
        let _ = s.calls().registry.transition(
            &call_instance,
            &ring_id,
            client_core::callstate::CallPhase::Winner,
            created_at,
        );
        s.persist()?;
    }
    eng().emit(
        "group_call",
        serde_json::json!({ "kind": "outgoing", "group_id": group_id, "name": group_name }),
    );
    let ring_handle = client_core::callstate::random_call_id();
    eng().start_system_call(&ring_handle, &group_name, false, false);
    spawn_group_call(
        inner,
        &client,
        group_id.to_string(),
        group_name,
        call_instance.clone(),
        ring_id,
        ring_handle,
        coordinator,
        deadline,
        my_key,
        my_tickets,
    )
    .await?;

    // Ring timeout: nobody joined → tear down and tell everyone we're gone.
    spawn_group_no_answer_timeout(inner.clone(), client, call_instance);
    Ok(())
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
    eng().accept_ring(&offer.ring_handle, false);
    if s.call.is_some()
        || s.group_call.is_some()
        || s.claiming.is_some()
        || s.group_claiming.is_some()
        || s.call_setup
    {
        return Err("already in a call".into());
    }
    let client = s.client.clone().ok_or("not configured")?;
    let answering_device_id = s.history.self_device_id();
    let my_username = s.account.as_ref().ok_or("locked")?.account_id().to_string();
    let reply_to_mailbox = client
        .device_mailbox(&my_username, &answering_device_id)
        .map_err(|error| error.to_string())?;
    let claim_nonce = client_core::callstate::random_call_id();
    let expires_at = offer
        .deadline
        .expires_at
        .min(now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS));
    if expires_at <= now_secs() {
        let _ = record_call_terminal(
            &mut s,
            &offer.call_instance,
            &offer.ring_id,
            client_core::callstate::CallTerminalReason::Expired,
        );
        return Err("group call expired".into());
    }
    let _ = s.calls().registry.transition(
        &offer.call_instance,
        &offer.ring_id,
        client_core::callstate::CallPhase::Claiming,
        now_secs(),
    );
    send_group_call_claim_to_coordinator(
        &client,
        &mut s,
        &offer.coordinator,
        &offer.group_id,
        &offer.call_instance,
        &offer.ring_id,
        &claim_nonce,
        &answering_device_id,
        &reply_to_mailbox,
        expires_at,
    )?;
    s.persist()?;
    let timeout_claim_nonce = claim_nonce.clone();
    let timeout_call_instance = offer.call_instance.clone();
    s.group_claiming = Some(PendingGroupClaim {
        offer,
        claim_nonce,
        answering_device_id,
    });
    eng().emit("group_call", serde_json::json!({ "kind": "claiming" }));
    let inner = inner.clone();
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            expires_at.saturating_sub(now_secs()),
        ))
        .await;
        let mut s = inner.lock().await;
        if let Some(pending) = s.group_claiming.take_if(|pending| {
            pending.claim_nonce == timeout_claim_nonce
                && pending.offer.call_instance == timeout_call_instance
        }) {
            let _ = record_call_terminal(
                &mut s,
                &pending.offer.call_instance,
                &pending.offer.ring_id,
                client_core::callstate::CallTerminalReason::Expired,
            );
            log_group_call_event(&mut s, &pending.offer.group_id, "📞 Group call ended");
            eng().emit("group_call", serde_json::json!({ "kind": "ended" }));
        }
    });
    Ok(())
}

/// Complete a coordinator-approved group answer. Only the exact winning device reaches
/// this path; media capabilities remain in the in-memory pending offer until now.
pub(crate) async fn finish_group_call_accept(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    offer: PendingGroupOffer,
) -> Result<(), String> {
    let (me, my_key, others) = {
        let s = inner.lock().await;
        let account = s.account.as_ref().ok_or("locked")?;
        let me = account.account_id().to_string();
        let my_key = account.ratchet_ref().identity_key();
        let group = s.history.group(&offer.group_id).ok_or("unknown group")?;
        let others: Vec<client_core::GroupMember> = group
            .members
            .iter()
            .filter(|member| member.username != me)
            .cloned()
            .collect();
        (me, my_key, others)
    };
    // Announce ourselves to every member: warm their rosters off-lock first, exactly as
    // the coordinator did when it rang.
    for member in &others {
        warm_call_routes(inner, client, &member.username).await;
    }
    warm_call_routes(inner, client, &me).await;
    let my_tickets = send_offers_for_group(
        inner,
        client,
        &offer.group_id,
        &offer.call_instance,
        &offer.ring_id,
        &offer.coordinator,
        offer.deadline,
        &others,
    )
    .await?;
    spawn_group_call(
        inner,
        client,
        offer.group_id.clone(),
        offer.group_name.clone(),
        offer.call_instance.clone(),
        offer.ring_id.clone(),
        offer.ring_handle.clone(),
        offer.coordinator.clone(),
        offer.deadline,
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
    // Redundant self-terminal survives a reordered or lost coordinator winner.
    ring_terminal_selfsync(
        client,
        &mut *inner.lock().await,
        &offer.call_instance,
        &offer.ring_id,
        client_core::callstate::CallTerminalReason::AnsweredElsewhere,
    );
    // Bound connecting if everyone left between the ring and our accept.
    spawn_group_no_answer_timeout(inner.clone(), client.clone(), offer.call_instance.clone());
    Ok(())
}
