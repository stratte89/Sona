use crate::*;

// ── Call history chips ─────────────────────────────────────────────────────────────
// Every call outcome leaves a local, centered chip in the conversation's timeline
// ("📞 Missed call", "📞 Call · 4:12") — a missed call must still be discoverable an
// hour later, not just as a toast that already faded. Purely local annotations
// (record_call_event never touches the wire); `sync` repaints an open thread and the
// chat-list preview. The 📞 prefix is the UI's render marker (phone icon + time).

/// Persist a call-outcome chip into a 1:1 thread.
pub(crate) fn log_call_event(s: &mut Session, peer_key: &str, label: &str) {
    if peer_key.is_empty() {
        return;
    }
    s.history.record_call_event(peer_key, label, now_secs());
    let _ = s.persist();
    eng().emit("sync", ());
}

/// Persist a call-outcome chip into a group thread.
pub(crate) fn log_group_call_event(s: &mut Session, group_id: &str, label: &str) {
    s.history
        .record_group_call_event(group_id, label, now_secs());
    let _ = s.persist();
    eng().emit("sync", ());
}

/// Outcome label for a call WE were part of when it ended: connected calls show their
/// duration; a caller-side call that never connected is "Unanswered" (no pickup or
/// declined — outwardly the same); a callee-side one that never connected (accepted
/// but the media leg never came up) is just "Call".
pub(crate) fn call_end_label(kind: &str, caller: bool, connected_at: u64) -> String {
    if connected_at > 0 {
        let secs = now_secs().saturating_sub(connected_at);
        format!("📞 {kind} · {}:{:02}", secs / 60, secs % 60)
    } else if caller {
        format!("📞 Unanswered {}", kind.to_lowercase())
    } else {
        format!("📞 {kind}")
    }
}

/// Join the room, start platform audio + lazy capture sources, and run the media
/// session; installs the [`CallCtl`] into the session. The event pump translates
/// engine events into UI events and clears the call state when the session ends.
///
/// `peer_media2`: whether the peer already advertised media v2 (known from the offer
/// when we're the callee; unknown — `false` — for the caller until the answer lands,
/// at which point [`handle_call_signal`] flips the flag live).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_call(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    s: &mut Session,
    call_id: String,
    key_b64: String,
    peer_username: String,
    peer_key: String,
    caller: bool,
    peer_media2_now: bool,
    ring_fanout: usize,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

    // Native (cpal) capture can't raise Android's runtime permission prompt itself:
    // trigger it here so a first-ever call fails once with a visible prompt instead of
    // failing forever silently. The user retries after granting.
    #[cfg(target_os = "android")]
    android_media::ensure_mic_permission();
    // Audio device init and the network join are independent — overlap them so call
    // setup takes max(mic init, join) instead of the sum.
    let peer_username_for_audio = peer_username.clone();
    let audio_task = eng().spawn_blocking(move || audio::start(Some(peer_username_for_audio)));
    let media = client
        .join_call(&call_id)
        .await
        .map_err(|e| e.to_string())?;
    let (audio, aux_tx) = audio_task.await.map_err(|e| e.to_string())??;
    let transport = media.transport();

    let media_ui = &eng().media_ui;
    let toggles = client_core::media::MediaToggles::default();
    let screen_source = Arc::new(std::sync::Mutex::new(media_shell::CaptureSource::PrimaryMonitor));
    let connected = Arc::new(AtomicBool::new(false));
    let connected_at = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let peer_media2 = Arc::new(AtomicBool::new(peer_media2_now));
    let video_ready = Arc::new(AtomicBool::new(false));
    let peer_camera = Arc::new(AtomicBool::new(false));
    let peer_screen = Arc::new(AtomicBool::new(false));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel();

    // The media session itself: voice exactly as before, plus negotiated camera /
    // screen / screen-audio tracks (see client-core's `media` module for the design).
    {
        let key_b64 = key_b64.clone();
        let toggles = toggles.clone();
        let peer_media2 = peer_media2.clone();
        let io = client_core::media::MediaIo {
            audio,
            camera: media_shell::SlotSource::camera(media_ui.clone()),
            screen: media_shell::SlotSource::screen(media_ui.clone(), screen_source.clone()),
            screen_audio: media_shell::SystemAudioSource::new(),
            sink: media_shell::ShellSink {
                ui: media_ui.clone(),
                aux: aux_tx,
            },
        };
        eng().spawn(async move {
            let _ = client_core::media::run_media_call(
                media,
                &key_b64,
                caller,
                peer_media2,
                io,
                stop_rx,
                toggles,
                ev_tx,
            )
            .await;
        });
    }

    // Event pump: engine → UI, and session-state cleanup on end.
    {
        use client_core::media::{MediaEvent, Track};
        let inner = inner.clone();
        let client = client.clone();
        let connected = connected.clone();
        let connected_at = connected_at.clone();
        let video_ready = video_ready.clone();
        let peer_camera = peer_camera.clone();
        let peer_screen = peer_screen.clone();
        let call_id = call_id.clone();
        eng().spawn(async move {
            while let Some(ev) = ev_rx.recv().await {
                match ev {
                    MediaEvent::Connected => {
                        connected.store(true, Relaxed);
                        // Keep the FIRST connect time — a resumed session (reconnect)
                        // carries the original over; the chip must span the whole call.
                        let _ = connected_at.compare_exchange(0, now_secs(), Relaxed, Relaxed);
                        eng().emit("call", serde_json::json!({ "kind": "connected" }));
                    }
                    MediaEvent::VideoReady(ready) => {
                        video_ready.store(ready, Relaxed);
                        eng().emit(
                            "call",
                            serde_json::json!({ "kind": "video_ready", "ready": ready }),
                        );
                    }
                    MediaEvent::PeerTrack { track, on } => {
                        let name = match track {
                            Track::Camera => {
                                peer_camera.store(on, Relaxed);
                                "camera"
                            }
                            Track::Screen => {
                                peer_screen.store(on, Relaxed);
                                "screen"
                            }
                            Track::ScreenAudio => "screen_audio",
                            Track::Control => continue,
                        };
                        eng().emit(
                            "call",
                            serde_json::json!({ "kind": "peer_track", "track": name, "on": on }),
                        );
                    }
                    MediaEvent::PeerLeft | MediaEvent::Ended => {
                        let mut s = inner.lock().await;
                        if let Some(call) = s.call.take_if(|c| c.call_id == call_id) {
                            // A CONNECTED call losing its media leg is a network drop
                            // until the peer's CallEnd says otherwise (a deliberate
                            // hangup closes the room first; the ratchet CallEnd lands
                            // within the grace) — hold the state for a silent resume.
                            if connected.load(Relaxed) && s.account.is_some() {
                                s.reconnect = Some(PendingReconnect {
                                    old_call_id: call.call_id.clone(),
                                    peer_username: call.peer_username.clone(),
                                    peer_key: call.peer_key.clone(),
                                    peer_media2: call.peer_media2.load(Relaxed),
                                    connected_at: call.connected_at.load(Relaxed),
                                });
                                eng().emit(
                                    "call",
                                    serde_json::json!({
                                        "kind": "reconnecting",
                                        "username": call.peer_username,
                                    }),
                                );
                                drop(s);
                                start_call_reconnect(
                                    inner.clone(),
                                    client.clone(),
                                    call.call_id.clone(),
                                );
                            } else {
                                log_call_event(
                                    &mut s,
                                    &call.peer_key.clone(),
                                    &call_end_label(
                                        "Call",
                                        call.caller,
                                        call.connected_at.load(Relaxed),
                                    ),
                                );
                                eng().emit("call", serde_json::json!({ "kind": "ended" }));
                            }
                        }
                        break;
                    }
                }
            }
        });
    }

    // Outgoing ring timeout: nobody picked up → tear down and tell the peer.
    if caller {
        let inner = inner.clone();
        let client = client.clone();
        let connected = connected.clone();
        let call_id_t = call_id.clone();
        let peer_username_t = peer_username.clone();
        let peer_key_t = peer_key.clone();
        eng().spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(RING_TIMEOUT_SECS)).await;
            if connected.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let mut s = inner.lock().await;
            if let Some(call) = s.call.take_if(|c| c.call_id == call_id_t) {
                let _ = call.stop.send(true);
                send_call_end_everywhere(
                    &client,
                    &mut s,
                    &peer_username_t,
                    &peer_key_t,
                    &call_id_t,
                )
                .await;
                log_call_event(&mut s, &peer_key_t, &call_end_label("Call", true, 0));
                eng().emit("call", serde_json::json!({ "kind": "no_answer" }));
            }
        });
    }

    s.call = Some(CallCtl {
        call_id,
        peer_username,
        peer_key,
        caller,
        toggles,
        screen_source,
        connected,
        connected_at,
        peer_media2,
        video_ready,
        peer_camera,
        peer_screen,
        transport,
        ring_fanout,
        stop: stop_tx,
    });
    Ok(())
}

/// The accept itself, callable without a Tauri `State` — the Bluetooth/headset-button
/// answer (`notif_action`) goes through the exact same path as the UI button. The
/// call media pipeline is fully native (Kotlin bridge both directions), so an accept
/// with no webview attached is a working call; the UI resyncs from `call_status`.
pub(crate) async fn call_accept_inner(inner: &Arc<Mutex<Session>>) -> Result<(), String> {
    let mut s = inner.lock().await;
    let offer = s.incoming.take().ok_or("no incoming call")?;
    if s.call.is_some() || s.group_call.is_some() {
        return Err("already in a call".into());
    }
    eng().cancel_ring(&offer.call_id, "");
    let client = s.client.clone().ok_or("not configured")?;
    send_call_answer_everywhere(
        &client,
        &mut s,
        &offer.username,
        &offer.peer_key,
        &offer.call_id,
        true,
        false,
    )
    .await?;
    s.persist()?;
    let peer_media2 = client_core::media::peer_supports_media2(&offer.caps);
    let call_id = offer.call_id.clone();
    spawn_call(
        inner,
        &client,
        &mut s,
        offer.call_id,
        offer.key_b64,
        offer.username,
        offer.peer_key,
        false,
        peer_media2,
        1,
    )
    .await?;
    // Stop our own other devices' ringing — after the media join, so answering adds no
    // latency to the connect path (siblings stop a beat later; best-effort).
    ring_handled_selfsync(&client, &mut s, &call_id).await;
    Ok(())
}

/// Send a hangup/cancel for `call_id` to the peer's directly-signaled device AND — on a
/// multi-device relay — every other device in their verified roster, so no device keeps
/// ringing for the full timeout. Best-effort; the caller persists afterward.
pub(crate) async fn send_call_end_everywhere(
    client: &Arc<Client>,
    s: &mut Session,
    peer_username: &str,
    peer_key: &str,
    call_id: &str,
) {
    let multi = s.multi_device;
    let contact = contact_for(peer_username, peer_key);
    let sess = &mut *s;
    let Some(account) = sess.account.as_mut() else {
        return;
    };
    let _ = client.send_call_end(account, &contact, call_id).await;
    if multi {
        if let Ok(extras) = client
            .extra_call_end_envelopes(account, &mut sess.history, &contact, call_id)
            .await
        {
            for env in &extras {
                let _ = client.post_envelope(env).await;
            }
        }
    }
}

/// Send an accept/decline for `call_id` to the caller's directly-signaled device AND —
/// on a multi-device relay — every other device in their verified roster. The direct
/// copy alone only works when the caller is on their primary device (the 1:1 path
/// delivers to the account mailbox); the fan copies are what reach a caller on a
/// linked device. Best-effort on the fan; the direct send's error propagates.
pub(crate) async fn send_call_answer_everywhere(
    client: &Arc<Client>,
    s: &mut Session,
    peer_username: &str,
    peer_key: &str,
    call_id: &str,
    accept: bool,
    busy: bool,
) -> Result<(), String> {
    let multi = s.multi_device;
    let contact = contact_for(peer_username, peer_key);
    let sess = &mut *s;
    let account = sess.account.as_mut().ok_or("locked")?;
    client
        .send_call_answer(account, &contact, call_id, accept, busy)
        .await
        .map_err(|e| e.to_string())?;
    if multi {
        if let Ok(extras) = client
            .extra_call_answer_envelopes(
                account,
                &mut sess.history,
                &contact,
                call_id,
                accept,
                busy,
            )
            .await
        {
            for env in &extras {
                let _ = client.post_envelope(env).await;
            }
        }
    }
    Ok(())
}

/// Tell our own other devices this ring was handled here (answered or declined), so they
/// stop ringing immediately instead of timing out. Best-effort, no-op for single-device.
pub(crate) async fn ring_handled_selfsync(client: &Arc<Client>, s: &mut Session, call_id: &str) {
    if !s.multi_device {
        return;
    }
    let sess = &mut *s;
    let Some(account) = sess.account.as_mut() else {
        return;
    };
    if let Ok(envs) = client
        .call_handled_selfsync(account, &mut sess.history, call_id)
        .await
    {
        for env in &envs {
            let _ = client.post_envelope(env).await;
        }
    }
}

/// Drive a dropped 1:1 call's silent resume. Two tasks:
///
/// * After [`RECONNECT_GRACE_MS`] (long enough for a deliberate hangup's `CallEnd` to
///   land and cancel everything), the pair's **owner** — the lexicographically smaller
///   identity key, same rule as group legs — mints a fresh room + key (a call key is
///   never reused) and sends a `CallOffer` marked `reconnect_of: old_call_id`. The
///   peer's in-call device auto-accepts it silently; nothing ever rings.
/// * A [`RECONNECT_WINDOW_SECS`] deadline: if the resume hasn't produced a live call
///   by then, the call ends visibly instead of "reconnecting…" forever.
pub(crate) fn start_call_reconnect(
    inner: Arc<Mutex<Session>>,
    client: Arc<Client>,
    old_call_id: String,
) {
    // ── Owner re-offer, after the CallEnd grace. ──
    {
        let inner = inner.clone();
        let old = old_call_id.clone();
        eng().spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(RECONNECT_GRACE_MS)).await;
            let mut s = inner.lock().await;
            let Some(rc) = s.reconnect.as_ref().filter(|r| r.old_call_id == old) else {
                return; // the peer's CallEnd landed — it was a hangup, already ended
            };
            let (peer_username, peer_key, peer_media2, prev_connected_at) = (
                rc.peer_username.clone(),
                rc.peer_key.clone(),
                rc.peer_media2,
                rc.connected_at,
            );
            let Some(my_key) = s.account.as_ref().map(|a| a.ratchet_ref().identity_key()) else {
                return; // locked meanwhile
            };
            if my_key.as_str() >= peer_key.as_str() {
                return; // the peer owns the pair — they re-offer, we wait
            }
            let ticket = client_core::call::CallTicket::mint();
            let contact = contact_for(&peer_username, &peer_key);
            let multi = s.multi_device;
            {
                let sess = &mut *s;
                let Some(account) = sess.account.as_mut() else {
                    return;
                };
                if client
                    .send_call_offer_full(account, &contact, &ticket.call_id, &ticket.key_b64, &old)
                    .await
                    .is_err()
                {
                    // Relay unreachable — no point holding "reconnecting" for the
                    // full window.
                    sess.reconnect = None;
                    log_call_event(
                        &mut s,
                        &peer_key,
                        &call_end_label("Call", true, prev_connected_at),
                    );
                    eng().emit("call", serde_json::json!({ "kind": "ended" }));
                    return;
                }
                if multi {
                    // The direct copy lands in the account mailbox (primary only);
                    // when the peer's in-call device is a linked one, the fan copy is
                    // the only route. Devices not in the dropped call ignore it.
                    if let Ok(extras) = client
                        .extra_call_offer_envelopes_full(
                            account,
                            &mut sess.history,
                            &contact,
                            &ticket.call_id,
                            &ticket.key_b64,
                            &old,
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
            s.reconnect = None; // resume in flight; the fresh session takes over
            if spawn_call(
                &inner,
                &client,
                &mut s,
                ticket.call_id.clone(),
                ticket.key_b64,
                peer_username,
                peer_key.clone(),
                true,
                peer_media2,
                1,
            )
            .await
            .is_err()
            {
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
            if let Some(c) = s.call.as_ref().filter(|c| c.call_id == ticket.call_id) {
                c.connected_at
                    .store(prev_connected_at, std::sync::atomic::Ordering::Relaxed);
            }
            drop(s);
            spawn_reconnect_window(inner, ticket.call_id);
        });
    }
    // ── Waiter deadline: the resume offer never arrived. ──
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_WINDOW_SECS)).await;
        let mut s = inner.lock().await;
        if let Some(rc) = s.reconnect.take_if(|r| r.old_call_id == old_call_id) {
            log_call_event(
                &mut s,
                &rc.peer_key,
                &call_end_label("Call", true, rc.connected_at),
            );
            eng().emit("call", serde_json::json!({ "kind": "ended" }));
        }
    });
}

/// End a resumed session that never actually reconnected within the window (the
/// normal 45 s no-answer timer is for rings; a resume must fail much faster).
pub(crate) fn spawn_reconnect_window(inner: Arc<Mutex<Session>>, new_call_id: String) {
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_WINDOW_SECS)).await;
        let mut s = inner.lock().await;
        if let Some(call) = s.call.take_if(|c| {
            c.call_id == new_call_id && !c.connected.load(std::sync::atomic::Ordering::Relaxed)
        }) {
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
        }
    });
}
