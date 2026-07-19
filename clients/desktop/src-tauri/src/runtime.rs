use crate::*;

/// Connection-state events come only from the MAIN mailbox loop — alias (former
/// username) drains reconnect on their own and must not flap the UI indicator. Also
/// keeps the Android foreground-service status text truthful (Connected ↔
/// Reconnecting) — see `Engine::conn`.
pub(crate) fn emit_conn(alias: &Option<String>, up: bool) {
    eng().conn(alias.is_none(), up);
}

/// Post every due outbox envelope, dropping the accepted ones from the outbox. The
/// outbox holds self-sync copies (awaiting their privacy jitter) and failed forwards;
/// entries survive an app close/kill and drain here at the next opportunity — this is
/// what keeps linked devices' history convergent. Best-effort per envelope: a failed
/// post stays queued for the next pass.
pub(crate) async fn drain_outbox(inner: &Arc<Mutex<Session>>, client: &Arc<Client>) {
    let due = {
        let s = inner.lock().await;
        s.history.outbox_due(now_secs())
    };
    if due.is_empty() {
        return;
    }
    let mut posted = Vec::new();
    for env in due {
        if client.post_envelope(&env).await.is_ok() {
            posted.push(env);
        }
    }
    if !posted.is_empty() {
        let mut s = inner.lock().await;
        for env in &posted {
            s.history.outbox_ack(env);
        }
        let _ = s.persist();
    }
}

/// Spawn the disappearing-messages reaper: delete every message whose `delete_at`
/// passed, re-seal history, and nudge the UI to repaint. Runs once immediately (so
/// messages that expired while the app was closed/locked never render after unlock),
/// then every tick until the session's stop signal fires.
pub(crate) fn spawn_reaper(
    inner: Arc<Mutex<Session>>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    eng().spawn(async move {
        loop {
            let (removed, chats) = {
                let mut s = inner.lock().await;
                if s.account.is_some() {
                    let (n, chats) = s.history.reap_with_chats(now_secs());
                    if n > 0 {
                        let _ = s.persist();
                    }
                    (n, chats)
                } else {
                    (0, Vec::new())
                }
            };
            if removed > 0 {
                // Expired content must not outlive its timer in the OS shade either.
                eng().on_reaped(&chats);
                eng().emit("sync", ());
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(REAPER_TICK_SECS)) => {}
                _ = stop_rx.changed() => break,
            }
        }
    });
}

/// Spawn a one-shot outbox drain after `delay_secs` (the self-sync jitter). The durable
/// copy is already in the outbox — if this task never runs (app killed), the periodic
/// drain or the next unlock posts it instead.
pub(crate) fn spawn_outbox_drain(inner: Arc<Mutex<Session>>, client: Arc<Client>, delay_secs: u64) {
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
        drain_outbox(&inner, &client).await;
    });
}

/// Spawn the live-delivery task: keep one authenticated WebSocket open and deliver events
/// as they arrive (backlog first, then real time).
///
/// Locking discipline (this is what keeps chat snappy and loses nothing):
/// * The socket wait (`next_frame`) happens **without** the session lock — cancel-safe,
///   no timeout tricks, so a frame can never be dropped after it was decrypted.
/// * The lock is taken only to decrypt + apply + re-seal (all fast; the vault re-seal
///   uses the cached key, no KDF).
/// * The ack and the "delivered" receipt POST go out **after** the lock is released.
///
/// Emits `sync` after every applied event and `conn` (bool) on connection state changes.
/// Exits when the session's stop signal fires (lock / replaced by a new unlock).
pub(crate) fn spawn_subscriber(inner: &Arc<Mutex<Session>>, s: &mut Session) {
    // Replace any previous task's stop handle; the old tasks see `true` and exit.
    if let Some(old) = s.stop.take() {
        let _ = old.send(true);
    }
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    s.stop = Some(stop_tx);
    let Some(client) = s.client.clone() else {
        return;
    };
    // Android: keep the process (and this delivery task) alive while backgrounded via
    // the foreground service — unless the user chose push-only delivery (mode P: the
    // relay wakes the device instead). No-op on desktop (the tray keeps the process).
    if s.prefs.delivery_mode != "p" {
        delivery_service::set_background_delivery(true);
    }
    eng().set_conn_state(notifier::ConnState::Reconnecting);
    // Delivery is live from here on — make sure OS notifications may actually show
    // (Android 13+ needs a runtime grant; a no-op everywhere it's already granted).
    // Through the attached UI when there is one (the request needs an activity to
    // show its dialog); a headless start simply skips it — the grant survives.
    if let Some(app) = eng().ui_handle() {
        eng().spawn_blocking(move || {
            use tauri_plugin_notification::{NotificationExt as _, PermissionState};
            let n = app.notification();
            if !matches!(n.permission_state(), Ok(PermissionState::Granted)) {
                let _ = n.request_permission();
            }
        });
    }
    // Main mailbox. A primary/legacy device drains its account mailbox; a **linked**
    // device drains its own device mailbox (the account mailbox belongs to the primary and
    // its directory record carries the primary's key, so a linked device can't auth it).
    let main_hash = if s.history.is_primary_device() {
        None
    } else if let Some(account) = s.account.as_ref() {
        client
            .device_mailbox(account.account_id(), &s.history.self_device_id())
            .ok()
    } else {
        None
    };
    let _ = spawn_delivery_loop(
        inner.clone(),
        client.clone(),
        stop_rx.clone(),
        main_hash,
        None,
        false,
    );
    // Disappearing-messages reaper: lives and dies with this session's delivery tasks.
    spawn_reaper(inner.clone(), stop_rx.clone());
    // Durable-outbox drain: once now (post anything a previous run left behind), then
    // every 30s while unlocked — self-sync copies whose jitter elapsed, failed retries.
    {
        let inner = inner.clone();
        let client = client.clone();
        let mut stop = stop_rx.clone();
        eng().spawn(async move {
            loop {
                drain_outbox(&inner, &client).await;
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                    _ = stop.changed() => break,
                }
            }
        });
    }
    // …plus one drain loop per former username: after a rename, peers that haven't seen
    // the notice yet still deliver to the old hash — same keys, so the signed challenge
    // still authenticates, and frames decode identically.
    for former in s.history.previous_usernames() {
        let hash = identity_hash_for(former);
        let _ = spawn_delivery_loop(
            inner.clone(),
            client.clone(),
            stop_rx.clone(),
            Some(hash.clone()),
            Some(hash),
            false,
        );
    }
}

/// What to do about a relay `revoked` claim, decided by [`verify_revoked_claim`].
pub(crate) enum RevokedVerdict {
    /// KT-confirmed: really removed from the account — lock out.
    Revoked,
    /// Still in the account; this device just moved mailboxes (promotion/demotion). A
    /// fresh subscriber was spawned on the current identity — the stale loop must exit.
    Moved,
    /// Verification failed (network/rollback) — treat as transient and retry; a
    /// server-asserted frame alone must never lock the account out.
    Inconclusive,
}

/// The relay claimed this device was revoked (mid-stream `revoked` frame, or auth landing
/// on a missing directory record). The claim is unauthenticated — verify it against the KT
/// log before persisting a lockout. A device that was just promoted to primary (or demoted
/// to a fresh linked id) merely moved mailboxes: fix up state and restart delivery instead
/// of locking the user out of a healthy account.
pub(crate) async fn verify_revoked_claim(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
) -> RevokedVerdict {
    let mut s = inner.lock().await;
    let verdict = {
        let sess = &mut *s;
        let Some(account) = sess.account.as_ref() else {
            return RevokedVerdict::Inconclusive;
        };
        client
            .verify_device_revocation(account, &mut sess.history)
            .await
    };
    match verdict {
        Ok(RevocationCheck::StillActive) => {
            let _ = s.persist();
            spawn_subscriber(inner, &mut s);
            RevokedVerdict::Moved
        }
        Ok(RevocationCheck::Revoked) => {
            s.history.set_revoked(true);
            let _ = s.persist();
            RevokedVerdict::Revoked
        }
        Err(_) => RevokedVerdict::Inconclusive,
    }
}

/// Drop guard: signals the engine when a drain loop ends, on EVERY exit path — the
/// shortService must always be released, even on a panic inside the loop.
pub(crate) struct DrainGuard;

impl Drop for DrainGuard {
    fn drop(&mut self) {
        eng().drain_done();
    }
}

/// One delivery loop over one mailbox.
/// * `subscribe_hash`: `None` = the account's own mailbox (`subscribe`); `Some(hash)` = an
///   explicit mailbox — a **linked device's** device mailbox, or a former username's.
/// * `alias`: `None` = the primary/main connection (drives the UI `conn` indicator);
///   `Some` = a secondary drain (former username) that must not toggle the main indicator.
/// * `drain`: push-wake mode — flush the backlog, hang on ~15 s for stragglers, then
///   disconnect and release the shortService (docs/NOTIFICATIONS.md §6.4). Everything downstream
///   (decrypt, poison acks, notif decisions, ring) is the same code either way: one
///   pipeline, two lifetimes. A drain loop never retries a failed connect — the next
///   wake (or app open) re-drains; retrying would burn the shortService budget.
pub(crate) fn spawn_delivery_loop(
    inner: Arc<Mutex<Session>>,
    client: Arc<Client>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    subscribe_hash: Option<String>,
    alias: Option<String>,
    drain: bool,
) -> tokio::task::JoinHandle<()> {
    if drain {
        eng().drain_started();
    }
    eng().spawn(async move {
        use std::time::Duration;
        // Reconnect policy: exponential 1→60 s with ±30 % jitter, reset on success,
        // cut short by a connectivity-change nudge (see `Engine::backoff_sleep`). The
        // fixed 2 s pauses on the revoked-claim paths are deliberate and unchanged.
        let mut backoff = engine::Backoff::new();
        // Ensures drain bookkeeping runs on EVERY exit path of this task.
        let _drain_guard = drain.then(|| DrainGuard);
        'reconnect: loop {
            if *stop_rx.borrow() {
                break;
            }
            // (Re)establish the subscription. The lock is held for the auth round-trip
            // only (challenge + signed nonce), once per connection.
            let sub = {
                let s = inner.lock().await;
                let Some(account) = s.account.as_ref() else {
                    break;
                };
                match &subscribe_hash {
                    None => client.subscribe(account).await,
                    Some(hash) => client.subscribe_as(account, hash).await,
                }
            };
            let mut sub = match sub {
                Ok(sub) => sub,
                // Auth landed on a missing directory record: the relay says this mailbox
                // was revoked. Verify against the KT log (see `verify_revoked_claim`) —
                // this is also how a device that was revoked while offline discovers the
                // lockout, and how a freshly promoted/demoted device whose old mailbox
                // died finds its way onto the new one.
                Err(client_core::ClientError::DeviceRevoked)
                    if alias.is_none() && !drain && !*stop_rx.borrow() =>
                {
                    // Brief pause first: a hostile/confused relay repeating the claim
                    // must not drive KT verification in a tight loop, and during a
                    // primary transfer it gives the roster publish time to settle.
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                        _ = stop_rx.changed() => break 'reconnect,
                    }
                    match verify_revoked_claim(&inner, &client).await {
                        RevokedVerdict::Moved => break 'reconnect,
                        RevokedVerdict::Revoked => {
                            emit_conn(&alias, false);
                            eng().emit("revoked", ());
                            break 'reconnect;
                        }
                        RevokedVerdict::Inconclusive => {
                            emit_conn(&alias, false);
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(2)) => continue 'reconnect,
                                _ = stop_rx.changed() => break 'reconnect,
                            }
                        }
                    }
                }
                // The relay's access gate refused us: the operator rotated the shared
                // access token (or evicted this member). Terminal for this loop —
                // retrying with the stale token can never succeed, it would just be
                // backoff noise. The main connection tells the UI, which sends the
                // user to the "relay access changed" screen to reconnect with a fresh
                // token; secondary drains just end quietly.
                Err(client_core::ClientError::AccessDenied) => {
                    emit_conn(&alias, false);
                    if alias.is_none() && !drain {
                        eng().emit("relay_access_denied", ());
                    }
                    break 'reconnect;
                }
                Err(_) => {
                    if drain {
                        break 'reconnect; // next wake re-drains
                    }
                    emit_conn(&alias, false);
                    tokio::select! {
                        _ = eng().backoff_sleep(backoff.next_delay()) => continue 'reconnect,
                        _ = stop_rx.changed() => break 'reconnect,
                    }
                }
            };
            backoff.reset();
            emit_conn(&alias, true);

            // Drain mode: disconnect after the backlog is flushed and the socket has
            // been idle this long (the `ready` frame itself resets the timer, so the
            // window starts once the flush is done).
            let drain_idle = Duration::from_secs(15);

            loop {
                // Wait for a frame with NO lock held (cancel-safe, so select is fine —
                // and the drain-idle timeout below can only ever cancel the WAIT, never
                // a decrypted-but-unacked frame).
                let frame = tokio::select! {
                    f = sub.next_frame() => f,
                    _ = tokio::time::sleep(drain_idle), if drain => {
                        // Backlog flushed and nothing new: this wake is served.
                        sub.close().await;
                        break 'reconnect;
                    }
                    _ = stop_rx.changed() => {
                        sub.close().await;
                        break 'reconnect;
                    }
                };
                let text = match frame {
                    Ok(Some(t)) => t,
                    // Clean close or socket error: reconnect (a drain gives up — the
                    // next wake re-drains).
                    _ => {
                        if drain {
                            break 'reconnect;
                        }
                        emit_conn(&alias, false);
                        tokio::select! {
                            _ = eng().backoff_sleep(backoff.next_delay()) => continue 'reconnect,
                            _ = stop_rx.changed() => break 'reconnect,
                        }
                    }
                };

                // Short critical section: decrypt, apply, prepare the receipt, re-seal.
                let mut ack_id: Option<String> = None;
                let mut receipt = None;
                let mut got_event = false;
                let mut notif: Option<NotifPlan> = None;
                // (peer key, optional group id, typing?) — emitted to the UI after the lock.
                let mut typing_evt: Option<(String, Option<String>, bool, Option<String>)> = None;
                // Primary→linked forwarding of legacy-sender traffic (posted after unlock).
                let mut forward_out = Vec::new();
                // Call signaling is handled after the lock is released (it may need the
                // network and its own session mutations).
                let mut call_sig: Option<InboundEvent> = None;
                // A linked device's history re-export request (primary only): surface it to
                // the UI so the user can approve it with their password.
                let mut resync_req: Option<(String, String, String)> = None;
                // A primary-ownership transfer offered to this device: surface to the UI
                // for the password-gated accept.
                let mut promotion_offered = false;
                // Terminal revocation: this mailbox no longer exists on the relay.
                let mut revoked = false;
                let auth_failed = {
                    let mut s = inner.lock().await;
                    let Some(account) = s.account.as_mut() else {
                        sub.close().await;
                        break 'reconnect;
                    };
                    match client_core::decode_frame(&text, account) {
                        client_core::Decoded::Event { event, ack_msg_id } => {
                            // Blocked peer: drop silently (no record, no receipt) but ack
                            // so the relay doesn't keep redelivering it.
                            if s.history.peer_blocked(event.sender_identity_key()) {
                                let _ = s.persist(); // ratchet advanced during decrypt
                                ack_id = Some(ack_msg_id);
                                false
                            } else {
                                // Message-request gate for rings: a fresh 1:1 offer
                                // from a stranger/pending sender must never reach the
                                // call pipeline — it folds into their request instead.
                                // Reconnect offers pass (they only ever resume a call
                                // this device is already in), and answers/hangups only
                                // touch existing call state.
                                let ring_ok = match &event {
                                    InboundEvent::CallOffered {
                                        sender_identity_key,
                                        sender_username,
                                        reconnect_of,
                                        ..
                                    } if reconnect_of.is_empty() => s.history.screen_call_offer(
                                        sender_identity_key,
                                        sender_username,
                                        now_secs(),
                                    ),
                                    _ => true,
                                };
                                if ring_ok
                                    && matches!(
                                        event,
                                        InboundEvent::CallOffered { .. }
                                            | InboundEvent::CallAnswered { .. }
                                            | InboundEvent::CallEnded { .. }
                                            | InboundEvent::GroupCallOffered { .. }
                                            | InboundEvent::GroupCallEnded { .. }
                                            | InboundEvent::SelfCallHandled { .. }
                                    )
                                {
                                    call_sig = Some(event.clone());
                                }
                                if let InboundEvent::SyncRequested {
                                    sender_identity_key,
                                    provisioning_id,
                                    link_secret_b64,
                                } = &event
                                {
                                    if s.history.is_own_device(sender_identity_key) {
                                        resync_req = Some((
                                            sender_identity_key.clone(),
                                            provisioning_id.clone(),
                                            link_secret_b64.clone(),
                                        ));
                                    }
                                }
                                // A primary-transfer offer is honored only on a linked
                                // device and only from the ratchet-authenticated key we
                                // know as our account's current primary.
                                if let InboundEvent::PrimaryTransferOffered {
                                    sender_identity_key,
                                    entry,
                                    demoted,
                                } = &event
                                {
                                    if !s.history.is_primary_device()
                                        && s.history.self_primary_key()
                                            == Some(sender_identity_key.as_str())
                                    {
                                        // Persisted (sealed) with history: if the accept
                                        // later dies between publishing the rotation and
                                        // the roster, this survives the restart and the
                                        // retry completes the transfer — the old primary
                                        // can no longer re-send it.
                                        s.history
                                            .set_pending_promotion(entry.clone(), demoted.clone());
                                        promotion_offered = true;
                                    }
                                }
                                // Poison-DoS insurance: no panic is reachable in `apply`
                                // today, but a crafted event must never crash the delivery
                                // loop for good. Catch and continue — the event is still
                                // acked below, so it isn't redelivered and re-panicked.
                                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                    || s.history.apply(&event),
                                ))
                                .is_err()
                                {
                                    eprintln!(
                                        "client: history.apply panicked on an inbound event; dropping it"
                                    );
                                }
                                let me = s
                                    .account
                                    .as_ref()
                                    .map(|a| a.account_id().to_string())
                                    .unwrap_or_default();
                                // Pending sender: normal notifications stay silent —
                                // ONE "message request" notification per request
                                // lifecycle instead (the history latch is one-shot).
                                let sender_convo =
                                    s.history.attribute_device(event.sender_identity_key());
                                notif = if s.history.request_pending_for_key(&sender_convo) {
                                    s.history.request_needs_notify(&sender_convo).then(|| {
                                        request_notif_plan(
                                            &s.history,
                                            &sender_convo,
                                            &s.prefs.notif_level,
                                        )
                                    })
                                } else {
                                    notif_for_event(&s.history, &event, &s.prefs.notif_level, &me)
                                };
                                // Surface ephemeral reaction/typing to the UI so the open
                                // thread can update live (typing is never persisted).
                                match &event {
                                    InboundEvent::Typing {
                                        sender_identity_key,
                                        typing,
                                    } => {
                                        typing_evt = Some((
                                            s.history.attribute_device(sender_identity_key),
                                            None,
                                            *typing,
                                            None,
                                        ));
                                    }
                                    InboundEvent::GroupTyping {
                                        sender_identity_key,
                                        group_id,
                                        typing,
                                    } => {
                                        // Resolve the typist's roster name so the group
                                        // thread can say WHO is typing (many senders).
                                        // No roster name = not a current member: suppress
                                        // (same roster gate as group content in apply()).
                                        let key = s.history.attribute_device(sender_identity_key);
                                        let who = s.history.group(group_id).and_then(|g| {
                                            g.members
                                                .iter()
                                                .find(|m| m.identity_key == key)
                                                .map(|m| m.username.clone())
                                        });
                                        if who.is_some() {
                                            typing_evt =
                                                Some((key, Some(group_id.clone()), *typing, who));
                                        }
                                    }
                                    // The peer changed the disappearing timer — drop a local
                                    // system chip so the change is visible in the transcript.
                                    InboundEvent::TimerUpdate {
                                        sender_identity_key,
                                        disappearing_secs,
                                    } => {
                                        let peer = s.history.attribute_device(sender_identity_key);
                                        let label = timer_label(*disappearing_secs);
                                        s.history.record_system(&peer, &label, now_secs());
                                    }
                                    // WE changed the timer on another of our own devices —
                                    // same chip here (the timer itself was adopted by
                                    // History::apply, gated on a verified own device).
                                    InboundEvent::SelfTimerUpdate {
                                        sender_identity_key,
                                        peer_key,
                                        disappearing_secs,
                                    } => {
                                        if s.history.is_own_device(sender_identity_key) {
                                            let label = timer_label(*disappearing_secs);
                                            s.history.record_system(peer_key, &label, now_secs());
                                        }
                                    }
                                    // A member changed a group's timer — chip in the group
                                    // thread. Only for a group we actually belong to.
                                    InboundEvent::GroupTimerUpdate {
                                        group_id,
                                        disappearing_secs,
                                        ..
                                    } => {
                                        if s.history.group(group_id).is_some() {
                                            let label = timer_label(*disappearing_secs);
                                            s.history.record_group_system(
                                                group_id,
                                                &label,
                                                now_secs(),
                                            );
                                        }
                                    }
                                    // (Kick/re-add detection lives in History::apply — the
                                    // self primary key is seeded at unlock even for
                                    // single-device accounts, so no backstop is needed.)
                                    _ => {}
                                }
                                // "Delivered" receipt for anything with timeline presence —
                                // texts and attachments alike.
                                let deliverable = match &event {
                                    InboundEvent::Message {
                                        sender_identity_key,
                                        sender_username,
                                        msg_id,
                                        ..
                                    }
                                    | InboundEvent::Attachment {
                                        sender_identity_key,
                                        sender_username,
                                        msg_id,
                                        ..
                                    } if !sender_username.is_empty() => Some((
                                        sender_username.clone(),
                                        sender_identity_key.clone(),
                                        msg_id.clone(),
                                    )),
                                    _ => None,
                                };
                                if let Some((username, key, msg_id)) = deliverable {
                                    // Only receipt what actually landed in the timeline:
                                    // a message the request gate withheld (or that is
                                    // held behind a pending request) must not leak a
                                    // "delivered" signal back to its sender.
                                    let convo = s.history.attribute_device(&key);
                                    let recorded = s.history.message(&convo, &msg_id).is_some();
                                    let pending = s.history.request_pending_for_key(&convo);
                                    if recorded && !pending {
                                        let contact = contact_for(&username, &key);
                                        let account = s.account.as_mut().unwrap();
                                        receipt = client
                                            .prepare_receipt(account, &contact, vec![msg_id], false)
                                            .ok()
                                            .flatten();
                                    }
                                }
                                // Multi-device primary: forward a legacy sender's message
                                // to our linked devices (no-network sync path; only devices
                                // we already share a session with — see the link-time hello).
                                if s.multi_device && s.history.is_primary_device() {
                                    let sess = &mut *s;
                                    if let Some(account) = sess.account.as_mut() {
                                        forward_out = client
                                            .forward_inbound_sync(account, &sess.history, &event)
                                            .unwrap_or_default();
                                        // Durable: a crash/kill between ack and post must
                                        // not lose the linked devices' copy for good.
                                        if !forward_out.is_empty() {
                                            sess.history
                                                .outbox_push(forward_out.clone(), now_secs());
                                        }
                                    }
                                }
                                let _ = s.persist();
                                ack_id = Some(ack_msg_id);
                                got_event = true;
                                false
                            }
                        }
                        // Permanently undecryptable: ack it out of the mailbox so it
                        // cannot poison delivery; persist any ratchet state change.
                        client_core::Decoded::Ignore { ack_msg_id } => {
                            let _ = s.persist();
                            ack_id = ack_msg_id;
                            false
                        }
                        client_core::Decoded::Ready => false,
                        client_core::Decoded::AuthFailed => true,
                        client_core::Decoded::Revoked => {
                            // Server-asserted claim — verified below, after the lock is
                            // released. Never persist a lockout from the frame alone.
                            revoked = true;
                            false
                        }
                    }
                };
                if revoked {
                    sub.close().await;
                    // A former-username drain just stops (mailbox gone), a push drain
                    // gives up (the next full start verifies), and a superseded loop
                    // (stop already signaled — e.g. this device just accepted a primary
                    // transfer and respawned delivery) must not touch state.
                    if alias.is_some() || drain || *stop_rx.borrow() {
                        break 'reconnect;
                    }
                    // Same rate-limit as the auth-time path: never let repeated relay
                    // claims drive verification in a tight loop.
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                        _ = stop_rx.changed() => break 'reconnect,
                    }
                    match verify_revoked_claim(&inner, &client).await {
                        RevokedVerdict::Moved => break 'reconnect,
                        RevokedVerdict::Revoked => {
                            emit_conn(&alias, false);
                            eng().emit("revoked", ());
                            break 'reconnect;
                        }
                        RevokedVerdict::Inconclusive => {
                            emit_conn(&alias, false);
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(2)) => continue 'reconnect,
                                _ = stop_rx.changed() => break 'reconnect,
                            }
                        }
                    }
                }
                if auth_failed {
                    // A former-username drain that stops authenticating usually means
                    // the released name's grace ran out and someone else claimed it —
                    // its directory record now carries their keys. Confirm against the
                    // KT log (never on relay say-so) and drop the alias for good.
                    if let Some(alias_hash) = &alias {
                        let mut s = inner.lock().await;
                        let taken_over = match s.account.as_ref() {
                            Some(account) => {
                                let mine: Option<String> = s
                                    .history
                                    .previous_usernames()
                                    .iter()
                                    .find(|u| &identity_hash_for(u) == alias_hash)
                                    .cloned();
                                match mine {
                                    Some(name) => {
                                        match client.owns_username(account, &name).await {
                                            Ok(false) => {
                                                s.history.remove_previous_username(&name);
                                                let _ = s.persist();
                                                true
                                            }
                                            _ => false, // still ours / inconclusive: retry
                                        }
                                    }
                                    None => true, // not in our alias list — nothing to drain
                                }
                            }
                            None => false,
                        };
                        if taken_over {
                            sub.close().await;
                            break 'reconnect;
                        }
                    }
                    if drain {
                        break 'reconnect;
                    }
                    emit_conn(&alias, false);
                    tokio::select! {
                        _ = eng().backoff_sleep(backoff.next_delay()) => continue 'reconnect,
                        _ = stop_rx.changed() => break 'reconnect,
                    }
                }

                // Network I/O with the lock released: ack + delivered receipt + UI nudge.
                if let Some(id) = ack_id {
                    if sub.ack(&id).await.is_err() {
                        emit_conn(&alias, false);
                        continue 'reconnect;
                    }
                }
                if let Some(env) = receipt {
                    let _ = client.post_envelope(&env).await;
                }
                // Forwards were queued durably above; drain posts + acks them (and any
                // other due outbox traffic) — a failure leaves them for the next pass.
                if !forward_out.is_empty() {
                    drain_outbox(&inner, &client).await;
                }
                if let Some(sig) = call_sig {
                    handle_call_signal(&inner, &client, sig).await;
                }
                if let Some((sender_key, provisioning_id, link_secret_b64)) = resync_req {
                    eng().emit(
                        "resync_request",
                        serde_json::json!({
                            "sender_key": sender_key,
                            "provisioning_id": provisioning_id,
                            "link_secret_b64": link_secret_b64,
                        }),
                    );
                }
                if promotion_offered {
                    // Content stays in Rust; the UI only needs to prompt for the accept.
                    eng().emit("primary_transfer", ());
                }
                if got_event {
                    eng().emit("sync", ());
                }
                if let Some((peer, group, typing, who)) = typing_evt {
                    eng().emit(
                        "typing",
                        serde_json::json!({ "peer": peer, "group": group, "typing": typing, "who": who }),
                    );
                }
                if let Some(plan) = notif {
                    notify_now(&plan);
                }
            }
        }
        emit_conn(&alias, false);
    })
}
