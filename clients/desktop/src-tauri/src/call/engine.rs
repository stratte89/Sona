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

/// How long call setup waits for the room join, and for the platform's audio devices,
/// before giving up on the call.
///
/// Neither wait was bounded, and both happen **before** `run_media_call` is even spawned —
/// so the media session's own give-ups, which live inside its loop, cannot see a hang here at
/// all. What the user got instead was "establishing secure connection…" until they hung up by
/// hand (measured 2026-08-01, through v0.1.47).
///
/// Generous, because a slow relay or a device that takes its time is not a failure: this is
/// the threshold for "this is not going to happen", and it is still far inside the ring
/// window, so the user learns the call failed while they are still looking at it.
const CALL_SETUP_GIVEUP: std::time::Duration = std::time::Duration::from_secs(15);

/// Join the room, start platform audio + lazy capture sources, and run the media
/// session; installs the [`CallCtl`] into the session. The event pump translates
/// engine events into UI events and clears the call state when the session ends.
///
/// `peer_media2`: whether the peer already advertised media v2 (known from the offer
/// when we're the callee; unknown — `false` — for the caller until the answer lands,
/// at which point [`handle_call_signal`] flips the flag live).
///
/// Called with the session mutex **released**: the room join is a network wait, and the
/// [`CallCtl`] is installed under a fresh lock once the media leg exists — refusing to
/// install if a terminal control landed for this call in the meantime.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_call(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    call_instance_id: String,
    offer_id: String,
    ring_handle: String,
    call_id: String,
    key_b64: String,
    peer_username: String,
    peer_key: String,
    peer_reply_to_mailbox: String,
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
    let voice_gain = inner.lock().await.history.voice_gain(&peer_username);
    // Audio device init and the network join are independent — overlap them so call
    // setup takes max(mic init, join) instead of the sum.
    let audio_task = eng().spawn_blocking(audio::start);
    // Both of these were unbounded, and both sit **upstream of every give-up the media
    // session has** — `PEER_JOIN_GIVEUP` and `VOICE_SILENCE_GIVEUP` live inside a loop that
    // `run_media_call` only reaches after this function returns. So a hang here is invisible
    // to all of them: `s.call` is never installed, the session is never spawned, and the
    // callee sits on "establishing secure connection…" for as long as the user tolerates it.
    // Measured 2026-08-01 through v0.1.47 — minutes, ended only by hand.
    //
    // Bounded and reported separately, because they fail for unrelated reasons: the join is
    // the relay and the network, the audio start is the platform's capture device.
    crate::diag!("[call] media setup: joining call room (caller={caller})");
    let media = match tokio::time::timeout(CALL_SETUP_GIVEUP, client.join_call(&call_id)).await {
        Ok(joined) => joined.map_err(|e| {
            crate::diag!("[call] media setup: call room join FAILED: {e}");
            e.to_string()
        })?,
        Err(_) => {
            crate::diag!(
                "[call] media setup: call room join TIMED OUT after {}s — giving up instead \
                 of waiting forever",
                CALL_SETUP_GIVEUP.as_secs()
            );
            return Err("could not join the call room".into());
        }
    };
    crate::diag!("[call] media setup: room joined; waiting for audio devices");
    let (audio, aux_tx) = match tokio::time::timeout(CALL_SETUP_GIVEUP, audio_task).await {
        Ok(joined) => joined
            .map_err(|e| {
                crate::diag!("[call] media setup: audio task panicked: {e}");
                e.to_string()
            })?
            .map_err(|e| {
                crate::diag!("[call] media setup: audio devices FAILED to start: {e}");
                e
            })?,
        Err(_) => {
            crate::diag!(
                "[call] media setup: audio devices did not start within {}s — giving up",
                CALL_SETUP_GIVEUP.as_secs()
            );
            return Err("the audio devices did not start".into());
        }
    };
    crate::diag!("[call] media setup: audio devices up");
    let transport = media.transport();

    let media_ui = &eng().media_ui;
    let toggles = client_core::media::MediaToggles::default();
    // This peer's remembered volume, applied from the first decoded frame rather than
    // when the UI gets round to asking. Mute and the shared-audio level are per-call and
    // reset here; the saved levels are not touched.
    crate::call::volume::reset_for_new_call();
    toggles
        .voice_gain
        .store(voice_gain, std::sync::atomic::Ordering::Relaxed);
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
            screen: media_shell::SlotSource::screen(media_ui.clone(), toggles.screen_width.clone()),
            screen_audio: media_shell::SystemAudioSource::new(),
            sink: media_shell::ShellSink {
                ui: media_ui.clone(),
                aux: aux_tx,
            },
            // Hardware H.264 where this machine has proved it works; software
            // otherwise, and software again the moment a hardware encoder misbehaves.
            // Android has no entry here: its frames are encoded by MediaCodec inside the
            // Kotlin bridge before they ever reach the engine.
            #[cfg(not(target_os = "android"))]
            encoders: Some(hwenc::factory()),
            #[cfg(target_os = "android")]
            encoders: None,
        };
        eng().spawn(async move {
            // The session's own reason for ending was discarded here. That is the half of
            // E-7 no log could see: a call that failed inside the media loop — keys that
            // never opened a frame, a relay that stopped forwarding — looked from outside
            // exactly like one that ended normally.
            // The line that separates "the session never started" from "it started and went
            // quiet". Everything inside `run_media_call`'s loop is bounded — a peer that
            // never joins, a peer that joins and sends nothing that opens — and every one of
            // those ends with the error logged below. So if this line appears and neither a
            // `VoiceFlowing` nor an error follows, the fault is inside the loop; if it never
            // appears at all, the call died in setup above.
            crate::diag!("[call] media session starting");
            if let Err(error) = client_core::media::run_media_call(
                media,
                &key_b64,
                caller,
                peer_media2,
                io,
                stop_rx,
                toggles,
                ev_tx,
            )
            .await
            {
                crate::diag!("[call] media session ended with error: {error}");
            }
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
        let call_instance_id_for_events = call_instance_id.clone();
        let offer_id_for_events = offer_id.clone();
        let ring_for_events = ring_handle.clone();
        let stop_for_events = stop_tx.clone();
        eng().spawn(async move {
            while let Some(ev) = ev_rx.recv().await {
                match ev {
                    MediaEvent::Connected => {
                        let mut session = inner.lock().await;
                        let transition = session.calls().registry.transition(
                            &call_instance_id_for_events,
                            &offer_id_for_events,
                            client_core::callstate::CallPhase::Active,
                            now_secs(),
                        );
                        if !matches!(
                            transition,
                            client_core::callstate::TransitionDecision::Applied
                                | client_core::callstate::TransitionDecision::Duplicate
                        ) {
                            // A room connection is not an answer decision. Refuse
                            // media until the authenticated caller-issued winner has
                            // advanced this exact offer to Winner.
                            let _ = stop_for_events.send(true);
                            let should_signal = !matches!(
                                transition,
                                client_core::callstate::TransitionDecision::Terminal(_)
                            );
                            if should_signal {
                                let _ = record_call_terminal(&mut session,
                                    &call_instance_id_for_events,
                                    &offer_id_for_events,
                                    client_core::callstate::CallTerminalReason::TransportError);
                            }
                            if let Some(call) = session.call.take_if(|call| call.call_id == call_id)
                            {
                                if should_signal {
                                    if call.caller {
                                        send_call_terminal_everywhere(
                                            &client,
                                            &mut session,
                                            &call.peer_username,
                                            &call.peer_key,
                                            &call.call_instance_id,
                                            &call.offer_id,
                                            client_core::callstate::CallTerminalReason::TransportError,
                                        );
                                    } else {
                                        let _ = send_call_terminal_to_device(
                                            &client,
                                            &mut session,
                                            &call.peer_device_key,
                                            &call.peer_reply_to_mailbox,
                                            &call.call_instance_id,
                                            &call.offer_id,
                                            client_core::callstate::CallTerminalReason::TransportError,
                                        );
                                    }
                                }
                                log_call_event(
                                    &mut session,
                                    &call.peer_key,
                                    &call_end_label(
                                        "Call",
                                        call.caller,
                                        call.connected_at.load(Relaxed),
                                    ),
                                );
                            }
                            drop(session);
                            eng().end_system_call(&ring_for_events, telecom::cause::ERROR);
                            eng().emit("call", serde_json::json!({ "kind": "ended" }));
                            break;
                        }
                        drop(session);
                        // The room is up and the winner check passed. `connected` keeps its
                        // existing meaning here — every gate that reads it (the capsule
                        // poll, the resume paths) is about "this call reached the room" —
                        // but nothing is claimed to the *user* yet: that waits for audio
                        // that actually opened (E-7).
                        connected.store(true, Relaxed);
                    }
                    MediaEvent::VoiceFlowing => {
                        // A frame decrypted and decoded. This is the first moment anything
                        // is entitled to say the call is up: the room, the relay and the
                        // direction-derived track keys have all just been proved to agree.
                        //
                        // `Connected` used to carry this, and it only ever meant the relay
                        // reported two peers in the room — so a call whose frames never
                        // opened at either end ran a timer over total silence, and took the
                        // system call out of CONNECTING while it did.
                        eng().system_call_active(&ring_for_events);
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
                            // until the peer's terminal says otherwise (a deliberate
                            // hangup closes the room first; the terminal control lands
                            // within the grace) — hold the state for a silent resume.
                            if connected.load(Relaxed) && s.account.is_some() {
                                s.reconnect = Some(PendingReconnect {
                                    call_instance_id: call.call_instance_id.clone(),
                                    offer_id: call.offer_id.clone(),
                                    ring_handle: call.ring_handle.clone(),
                                    old_call_id: call.call_id.clone(),
                                    peer_username: call.peer_username.clone(),
                                    peer_key: call.peer_key.clone(),
                                    peer_device_key: call.peer_device_key.clone(),
                                    peer_reply_to_mailbox: call.peer_reply_to_mailbox.clone(),
                                    caller: call.caller,
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
                                // The media leg is gone for good (never connected, or the
                                // vault closed under it): the system call goes with it.
                                eng().end_system_call(&call.ring_handle, telecom::cause::REMOTE);
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
                // Nobody picked up: the platform's log should say so.
                eng().end_system_call(&call.ring_handle, telecom::cause::MISSED);
                send_call_terminal_everywhere(
                    &client,
                    &mut s,
                    &peer_username_t,
                    &peer_key_t,
                    &call.call_instance_id,
                    &call.offer_id,
                    client_core::callstate::CallTerminalReason::Expired,
                );
                log_call_event(&mut s, &peer_key_t, &call_end_label("Call", true, 0));
                eng().emit("call", serde_json::json!({ "kind": "no_answer" }));
            }
        });
    }

    let mut s = inner.lock().await;
    // The lock was released across the join: a caller cancellation or a sibling's
    // terminal may have ended this call while the room was coming up.
    if let Err(error) = call_still_live(&s, client, &call_instance_id) {
        let _ = stop_tx.send(true);
        return Err(error);
    }
    s.call = Some(CallCtl {
        answer_arbiter: caller.then(|| {
            client_core::callstate::AnswerArbiter::new(call_instance_id.clone(), offer_id.clone())
        }),
        call_instance_id,
        offer_id,
        ring_handle,
        call_id,
        peer_username,
        peer_device_key: peer_key.clone(),
        peer_key,
        peer_reply_to_mailbox,
        caller,
        toggles,
        connected,
        connected_at,
        peer_media2,
        video_ready,
        peer_camera,
        peer_screen,
        transport,
        ring_fanout,
        busy_devices: std::collections::HashSet::new(),
        stop: stop_tx,
    });
    Ok(())
}

/// Send a final outcome to every verified peer device. Network-free: the sealed copies
/// go to the durable control outbox, which posts them off-lock.
pub(crate) fn send_call_terminal_everywhere(
    client: &Arc<Client>,
    s: &mut Session,
    peer_username: &str,
    peer_key: &str,
    call_instance_id: &str,
    offer_id: &str,
    reason: client_core::callstate::CallTerminalReason,
) {
    let multi = s.multi_device;
    let actor_device_id = s.history.self_device_id();
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let contact = contact_for(peer_username, peer_key);
    let envelopes = {
        let sess = &mut *s;
        let Some(account) = sess.account.as_mut() else {
            return;
        };
        let Ok(primary) = client.prepare_call_terminal_v2(
            account,
            &contact,
            call_instance_id,
            offer_id,
            reason,
            &actor_device_id,
            expires_at,
        ) else {
            return;
        };
        let mut envelopes = vec![primary];
        if multi {
            if let Ok(mut extras) = client.extra_call_terminal_envelopes_v2(
                account,
                &sess.history,
                &contact,
                call_instance_id,
                offer_id,
                reason,
                &actor_device_id,
                expires_at,
            ) {
                envelopes.append(&mut extras);
            }
        }
        envelopes
    };
    let _ = post_call_controls(client, s, &envelopes);
    // The same outcome on the capsule layer, so a peer device whose vault is locked (or
    // whose process slept after posting a native ring) can still stop ringing.
    send_terminal_capsules(
        s,
        client,
        peer_username,
        call_instance_id,
        offer_id,
        reason,
        expires_at,
    );
}

/// Send a final outcome to the exact authenticated peer device route.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_call_terminal_to_device(
    client: &Arc<Client>,
    s: &mut Session,
    peer_device_key: &str,
    peer_reply_to_mailbox: &str,
    call_instance_id: &str,
    offer_id: &str,
    reason: client_core::callstate::CallTerminalReason,
) -> Result<(), String> {
    let actor_device_id = s.history.self_device_id();
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let envelope = {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .prepare_call_terminal_v2_to_mailbox(
                account,
                peer_device_key,
                peer_reply_to_mailbox,
                call_instance_id,
                offer_id,
                reason,
                &actor_device_id,
                expires_at,
            )
            .map_err(|error| error.to_string())?
    };
    post_call_controls(client, s, &[envelope])
        .into_iter()
        .next()
        .unwrap_or_else(|| Err("terminal control was not queued".into()))
}

/// Send one answer claim to the exact caller device authenticated by the offer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_call_claim_to_origin(
    client: &Arc<Client>,
    s: &mut Session,
    caller_identity_key: &str,
    caller_reply_to_mailbox: &str,
    call_instance_id: &str,
    offer_id: &str,
    claim_nonce: &str,
    answering_device_id: &str,
    reply_to_mailbox: &str,
    expires_at: u64,
) -> Result<(), String> {
    let envelope = {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .prepare_call_answer_claim_v2_to_mailbox(
                account,
                caller_identity_key,
                caller_reply_to_mailbox,
                call_instance_id,
                offer_id,
                claim_nonce,
                answering_device_id,
                reply_to_mailbox,
                expires_at,
            )
            .map_err(|error| error.to_string())?
    };
    post_call_controls(client, s, &[envelope])
        .into_iter()
        .next()
        .unwrap_or_else(|| Err("answer claim was not queued".into()))
}

/// Route the caller's idempotent winner acknowledgement to the exact winner, then
/// best-effort copies to siblings so their stale rings stop immediately.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_call_winner_everywhere(
    client: &Arc<Client>,
    s: &mut Session,
    peer_username: &str,
    winner_identity_key: &str,
    call_instance_id: &str,
    offer_id: &str,
    claim_nonce: &str,
    winner_device_id: &str,
    winner_reply_to_mailbox: &str,
) -> Result<(), String> {
    let multi = s.multi_device;
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    // Using the winner identity as the fanout contact makes the helper include the
    // primary mailbox when a linked device won, while still covering every sibling.
    let contact = contact_for(peer_username, winner_identity_key);
    let envelopes = {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        let exact = client
            .prepare_call_winner_v2_to_mailbox(
                account,
                winner_identity_key,
                winner_reply_to_mailbox,
                call_instance_id,
                offer_id,
                claim_nonce,
                winner_device_id,
                expires_at,
            )
            .map_err(|error| error.to_string())?;
        let mut envelopes = vec![exact];
        if multi {
            if let Ok(mut extras) = client.extra_call_winner_envelopes_v2(
                account,
                &sess.history,
                &contact,
                call_instance_id,
                offer_id,
                claim_nonce,
                winner_device_id,
                expires_at,
            ) {
                envelopes.append(&mut extras);
            }
        }
        envelopes
    };
    let results = post_call_controls(client, s, &envelopes);
    if results.first().is_some_and(Result::is_ok) {
        Ok(())
    } else {
        Err("winner acknowledgement could not be delivered".into())
    }
}

/// Report this device busy without cancelling sibling rings.
pub(crate) fn send_call_busy_to_origin(
    client: &Arc<Client>,
    s: &mut Session,
    caller_identity_key: &str,
    caller_reply_to_mailbox: &str,
    call_instance_id: &str,
    offer_id: &str,
) -> Result<(), String> {
    let device_id = s.history.self_device_id();
    let expires_at = now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let envelope = {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .prepare_call_busy_v2_to_mailbox(
                account,
                caller_identity_key,
                caller_reply_to_mailbox,
                call_instance_id,
                offer_id,
                &device_id,
                expires_at,
            )
            .map_err(|error| error.to_string())?
    };
    post_call_controls(client, s, &[envelope])
        .into_iter()
        .next()
        .unwrap_or_else(|| Err("busy control was not queued".into()))
}
