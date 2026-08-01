use crate::*;

/// The share source the picker chose, as it comes over IPC.
#[derive(serde::Deserialize)]
pub struct ScreenSourcePick {
    /// `"screen"` or `"window"`; anything else falls back to the primary monitor.
    pub kind: String,
    pub id: u32,
}

/// The UI reports which conversation it currently has open (peer key or group id), or
/// `None` on the chat list / settings. Drives the "notify when a *different* chat is open"
/// rule. Cheap; no session lock needed.
/// Mobile: route call audio to the loudspeaker (`true`) or the earpiece (`false`).
/// The platform echo canceller keeps running either way. Desktop has no earpiece —
/// routing is the OS mixer's job — so this is Android-only.
#[tauri::command]
pub async fn call_set_speaker(state: tauri::State<'_, AppState>, on: bool) -> Result<bool, String> {
    // Same authority rule as `call_set_route`: the loudspeaker toggle is a route request.
    let system_call = {
        let s = state.inner.lock().await;
        s.call
            .as_ref()
            .map(|c| c.ring_handle.clone())
            .or_else(|| s.group_call.as_ref().map(|g| g.ring_handle.clone()))
    };
    if let Some(ring_handle) = system_call.as_deref() {
        telecom::request_route(ring_handle, if on { "speaker" } else { "earpiece" });
    }
    #[cfg(target_os = "android")]
    {
        if system_call.is_none() {
            android_media::set_speakerphone(on);
        }
        Ok(android_media::speakerphone_on())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = on;
        Err("loudspeaker routing is a mobile control".into())
    }
}

/// Mobile: the call-audio routing picture — whether a Bluetooth headset is connected
/// (its name) and which route is live. The in-call button adapts on it: headset
/// present → route chooser; none → plain loudspeaker toggle.
#[tauri::command]
pub fn call_audio_routes() -> serde_json::Value {
    #[cfg(target_os = "android")]
    {
        if let Some(j) = android_media::audio_routes() {
            if let Ok(v) = serde_json::from_str(&j) {
                return v;
            }
        }
    }
    serde_json::json!({ "bt": false, "bt_name": "", "route": "earpiece" })
}

/// Mobile: route call audio explicitly. Returns the fresh routing picture (what
/// actually happened — a refused route reports the real state, not the wish).
#[tauri::command]
pub async fn call_set_route(
    state: tauri::State<'_, AppState>,
    route: String,
) -> Result<serde_json::Value, String> {
    if !matches!(route.as_str(), "earpiece" | "speaker" | "bluetooth") {
        return Err("unknown audio route".into());
    }
    // Core-Telecom owns route selection while it owns the call: ask it, and report what
    // it actually did (the endpoint event), never the wish.
    let system_call = {
        let s = state.inner.lock().await;
        s.call
            .as_ref()
            .map(|c| c.ring_handle.clone())
            .or_else(|| s.group_call.as_ref().map(|g| g.ring_handle.clone()))
    };
    if let Some(ring_handle) = system_call.as_deref() {
        telecom::request_route(ring_handle, &route);
    }
    #[cfg(target_os = "android")]
    {
        // No Telecom call (or Telecom refused the app): the AudioManager path is still
        // the honest fallback.
        if system_call.is_none() {
            if let Some(j) = android_media::set_audio_route(&route) {
                if let Ok(v) = serde_json::from_str(&j) {
                    return Ok(v);
                }
            }
        }
        Ok(call_audio_routes())
    }
    #[cfg(not(target_os = "android"))]
    {
        Err("audio routing is a mobile control".into())
    }
}

/// Call tones ("ringback" | "ring" | "end" | "stop"). Android only: they must play
/// natively (webview audio is silent in MODE_IN_COMMUNICATION; "ring" is the system
/// ringtone). The desktop webview plays its own WebAudio tones instead.
#[tauri::command]
pub fn call_tone(kind: String) -> Result<(), String> {
    if !matches!(kind.as_str(), "ringback" | "ring" | "end" | "stop") {
        return Err("unknown tone".into());
    }
    // In-app ring only when it is the ONLY ring: with the native CallStyle ring
    // sounding (app unfocused, or it was posted before focus landed) a second
    // ringtone on top would double the audio.
    if kind == "ring" && (eng().ring_active() || !eng().is_focused()) {
        return Ok(());
    }
    #[cfg(target_os = "android")]
    android_media::call_tone(&kind);
    Ok(())
}

/// Where this call's video encoding stands: `"hardware"`, `"software"`, or `"idle"` when
/// nothing on this machine has been asked to encode yet — plus the driver's own reason
/// when there is one. Surfaced so "the share is smooth now" can be checked rather than
/// assumed, and so a backend that declined says *why* instead of hiding behind the word
/// "software".
fn hw_encode_status() -> (&'static str, Option<String>) {
    #[cfg(not(target_os = "android"))]
    {
        hwenc::status()
    }
    // Android encodes on the device's media block via MediaCodec in the Kotlin bridge;
    // there is no software path there to distinguish it from.
    #[cfg(target_os = "android")]
    {
        ("hardware", None)
    }
}

/// The display name a native ring (and its missed-call entry) may show, honoring the
/// notification privacy level: `"generic"` reveals nothing — the ring says just "Sona".
pub(crate) fn ring_title(s: &Session, name: &str) -> String {
    if s.prefs.notif_level == "generic" {
        "Sona".to_string()
    } else {
        name.to_string()
    }
}

#[tauri::command]
pub async fn call_status(state: tauri::State<'_, AppState>) -> Result<CallStatusView, String> {
    use std::sync::atomic::Ordering::Relaxed;
    let s = state.inner.lock().await;
    Ok(CallStatusView {
        active: s.call.as_ref().map(|c| {
            let (encode, encode_why) = hw_encode_status();
            serde_json::json!({
                "username": c.peer_username,
                "call_id": c.call_id,
                "outgoing": c.caller,
                "connected": c.connected.load(Relaxed),
                "muted": c.toggles.muted.load(Relaxed),
                "video_ready": c.video_ready.load(Relaxed),
                "camera_on": c.toggles.camera_on.load(Relaxed),
                "screen_on": c.toggles.screen_on.load(Relaxed),
                "screen_audio_on": c.toggles.screen_audio_on.load(Relaxed),
                "peer_camera": c.peer_camera.load(Relaxed),
                "peer_screen": c.peer_screen.load(Relaxed),
                "screen_audio_available": media_shell::screen_audio_available(),
                "video_encode": encode,
                "video_encode_why": encode_why,
                "transport": c.transport,
            })
        }),
        incoming: s
            .incoming
            .as_ref()
            .map(|o| serde_json::json!({ "username": o.username, "call_id": o.call_id })),
        claiming: s
            .claiming
            .as_ref()
            .map(|pending| serde_json::json!({ "username": pending.offer.username })),
        reconnecting: s
            .reconnect
            .as_ref()
            .map(|r| serde_json::json!({ "username": r.peer_username })),
        group_active: s.group_call.as_ref().map(|g| {
            let peers: Vec<String> = g.connected.lock().unwrap().values().cloned().collect();
            serde_json::json!({
                "group_id": g.group_id,
                "name": g.group_name,
                "muted": g.muted.load(Relaxed),
                "peers": peers,
            })
        }),
        group_incoming: s.group_incoming.as_ref().map(|o| {
            serde_json::json!({
                "group_id": o.group_id,
                "name": o.group_name,
                "from": o.rang_by_username,
            })
        }),
        group_claiming: s.group_claiming.as_ref().map(|pending| {
            serde_json::json!({
                "group_id": pending.offer.group_id,
                "name": pending.offer.group_name,
            })
        }),
        unlock_credential: s
            .pending_unlock
            .as_ref()
            .is_some_and(|p| p.wants_credential && p.expires_at > now_secs()),
    })
}

/// Ring a contact: mint the per-call capability + key, send them over the ratchet, and
/// join the room to wait.
///
/// Every network wait — roster resolution, contact discovery, the offer batch, the media
/// join — happens with the session mutex released; the lock is taken only for the local
/// steps between them (sealing, persistence, call state). The [`CallSlot`] reservation
/// holds the single call slot across those gaps.
#[tauri::command]
pub async fn call_start(state: tauri::State<'_, AppState>, username: String) -> Result<(), String> {
    let username = username.trim().to_string();
    let inner = state.inner.clone();
    let slot = CallSlot::reserve(&inner).await?;
    let started = call_start_inner(&inner, &username).await;
    slot.release().await;
    started
}

async fn call_start_inner(inner: &Arc<Mutex<Session>>, username: &str) -> Result<(), String> {
    let client = {
        let s = inner.lock().await;
        s.client.clone().ok_or("not configured")?
    };
    // Off-lock: refresh the callee's verified device roster (so every linked device is
    // rung) and our own (so the terminal self-sync reaches our siblings), then resolve the
    // contact. Preparation below is network-free because of this.
    warm_call_routes_with_self(inner, &client, username).await;
    let contact = resolve_call_contact(inner, &client, username).await?;

    let ticket = client_core::call::CallTicket::mint();
    let call_instance_id = client_core::callstate::random_call_id();
    let offer_id = client_core::callstate::random_call_id();
    let created_at = now_secs();
    let ring_expires_at = created_at.saturating_add(client_core::callstate::CALL_RING_TIMEOUT_SECS);
    let expires_at = created_at.saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
    let (offers, capsules) = {
        let mut s = inner.lock().await;
        if !is_current(&s, &client) {
            return Err("not configured".into());
        }
        let caller_device_id = s.history.self_device_id();
        let multi = s.multi_device;
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        // Seal the direct copy and every verified-device copy before launching any post,
        // so the primary and linked-device requests enter the relay together.
        let mut offers = vec![client
            .prepare_call_offer_v2(
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
                "",
            )
            .map_err(|error| error.to_string())?];
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
                "",
            ) {
                offers.append(&mut extras);
            }
        }
        // The second delivery layer for the same ring: one minimal capsule per callee
        // device that published a call-control key, naming the same logical call and
        // offer id so a device that receives both rings once.
        let capsules = prepare_capsules(
            &mut s,
            &client,
            username,
            &CapsuleBatch {
                kind: client_core::callcapsule::CapsuleKind::Offer,
                call_instance_id: &call_instance_id,
                offer_id: &offer_id,
                video: false,
                group: false,
                created_at,
                ring_expires_at,
                expires_at,
                reason: None,
            },
        );
        // E-6. Reserved BEFORE a single offer leaves this device, because the moment one
        // does a callee may answer, and its claim would otherwise arrive at a session with
        // no `s.call` yet — `spawn_call`'s mic open and room join are still ahead of us —
        // and be dropped with no retry.
        s.outgoing_setup = Some(OutgoingSetup {
            call_instance_id: call_instance_id.clone(),
            offer_id: offer_id.clone(),
            claims: Vec::new(),
        });
        // Envelope preparation advances ratchets even if every relay post fails.
        s.persist()?;
        (offers, capsules)
    };
    spawn_capsule_posts(&client, capsules);
    // A callee whose vault is locked can only answer on the capsule layer, and that
    // mailbox is not the one the delivery socket subscribes to — so read it while this
    // call is ringing out.
    spawn_ringing_capsule_poll(inner, &client, call_instance_id.clone(), expires_at);
    let results = client.post_envelopes_concurrent(&offers).await;
    let ring_fanout = results.iter().filter(|result| result.is_ok()).count();
    if ring_fanout == 0 {
        let error = results
            .into_iter()
            .find_map(Result::err)
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no call target could be reached".into());
        return Err(error);
    }
    {
        let mut s = inner.lock().await;
        call_still_live(&s, &client, &call_instance_id)?;
        // Read before the borrow: `s.calls()` takes the session mutably, which is the trap
        // A-9 documented and the reason a literal was reached for here (A-23).
        let retention = call_retention_secs(&s);
        let _ = s.calls().registry.receive_offer(
            &call_instance_id,
            &offer_id,
            created_at,
            ring_expires_at,
            created_at,
            retention,
        );
        // The last silent exit on this path. Everything else after the offers go out now
        // reports itself, and a round was already lost to an abort that wrote nothing down —
        // so this one says so too rather than being ruled out by argument next time.
        if let Err(error) = s.persist() {
            crate::diag!(
                "[call] outgoing call ABANDONED: persisting the offer failed: {error} — the \
                 devices already rung are still ringing"
            );
            return Err(error);
        }
    }
    // The offer is out — tell the UI it's ringing now, while the (slower) mic init
    // and room join below finish. A spawn failure still surfaces as this command's
    // error and the UI tears the overlay down.
    eng().emit(
        "call",
        serde_json::json!({ "kind": "outgoing", "username": contact.username }),
    );
    // A fresh opaque handle for this device's system call: the media room id must never
    // be what the platform's call log is keyed by.
    let ring_handle = client_core::callstate::random_call_id();
    // Telecom knows an outgoing call is being placed, so audio focus, routing, and
    // other-call interaction behave like any other telephony app.
    eng().start_system_call(&ring_handle, &contact.username, false, false);
    let started = spawn_call(
        inner,
        &client,
        call_instance_id,
        offer_id,
        ring_handle.clone(),
        ticket.call_id,
        ticket.key_b64,
        contact.username.clone(),
        contact.identity_key.clone(),
        String::new(),
        true,
        false, // callee caps unknown until the answer arrives
        ring_fanout,
    )
    .await;
    if let Err(error) = &started {
        // The room never came up (or a terminal landed while it was): the system call was
        // already handed over, so it has to come back rather than outlive the attempt.
        //
        // Said out loud, because this failure is **invisible from both ends**. `s.call` is
        // never installed and `CallSlot::release` clears `outgoing_setup` on the way out, so
        // a callee's claim then lands on a session holding neither and is refused with
        // "no outgoing call or setup matches it" — which reads on the caller's log like a
        // stale claim, and on the callee's screen like "establishing secure connection…"
        // until its own TTL. Measured 2026-08-01: the mic opened, the room did not, and
        // nothing between those two facts was written down.
        crate::diag!(
            "[call] outgoing call FAILED to start after the offers went out: {error} — \
             any claim for it will now be refused as matching no call"
        );
        eng().end_system_call(&ring_handle, telecom::cause::ERROR);
        return started;
    }
    // The room is up and `s.call` exists, so any claim that raced it can be applied now
    // through the ordinary path (E-6). Before `CallSlot::release`, which clears the
    // reservation this reads.
    replay_buffered_claims(inner, &client).await;
    started
}

/// Accept the pending inbound ring.
#[tauri::command]
pub async fn call_accept(state: tauri::State<'_, AppState>) -> Result<(), String> {
    call_accept_inner(&state.inner).await
}

/// Decline the pending inbound ring.
#[tauri::command]
pub async fn call_decline(state: tauri::State<'_, AppState>) -> Result<(), String> {
    call_decline_inner(&state.inner).await
}

/// The decline itself, callable without a Tauri `State`: the notification shade, a
/// headset, and Core-Telecom's Decline all reach the same path as the in-app button.
pub(crate) async fn call_decline_inner(inner: &Arc<Mutex<Session>>) -> Result<(), String> {
    let mut s = inner.lock().await;
    let offer = s.incoming.take().ok_or("no incoming call")?;
    eng().cancel_ring(&offer.ring_handle, "");
    let client = s.client.clone().ok_or("not configured")?;
    let _ = send_call_terminal_to_device(
        &client,
        &mut s,
        &offer.peer_key,
        &offer.caller_reply_to_mailbox,
        &offer.call_instance_id,
        &offer.offer_id,
        client_core::callstate::CallTerminalReason::DeclinedHere,
    );
    record_call_terminal(
        &mut s,
        &offer.call_instance_id,
        &offer.offer_id,
        client_core::callstate::CallTerminalReason::DeclinedHere,
    );
    ring_terminal_selfsync(
        &client,
        &mut s,
        &offer.call_instance_id,
        &offer.offer_id,
        client_core::callstate::CallTerminalReason::DeclinedElsewhere,
    );
    log_call_event(&mut s, &offer.peer_key, "📞 Declined call");
    s.persist()
}

/// Hang up the live call (either side, any state).
#[tauri::command]
pub async fn call_hangup(state: tauri::State<'_, AppState>) -> Result<(), String> {
    call_hangup_inner(&state.inner).await
}

/// The hangup itself, callable without a Tauri `State` (see [`call_decline_inner`]).
pub(crate) async fn call_hangup_inner(inner: &Arc<Mutex<Session>>) -> Result<(), String> {
    let mut s = inner.lock().await;
    let Some(call) = s.call.take() else {
        // Hanging up while "connecting…": we answered and are waiting to hear whether we
        // won. The user gets out of it here — before this, nothing cleared `claiming`
        // and the call slot stayed reserved until the vault locked.
        if let Some(pending) = s.claiming.take() {
            eng().end_system_call(&pending.offer.ring_handle, telecom::cause::LOCAL);
            let client = s.client.clone().ok_or("not configured")?;
            let _ = send_call_terminal_to_device(
                &client,
                &mut s,
                &pending.offer.peer_key,
                &pending.offer.caller_reply_to_mailbox,
                &pending.offer.call_instance_id,
                &pending.offer.offer_id,
                client_core::callstate::CallTerminalReason::DeclinedHere,
            );
            record_call_terminal(
                &mut s,
                &pending.offer.call_instance_id,
                &pending.offer.offer_id,
                client_core::callstate::CallTerminalReason::DeclinedHere,
            );
            log_call_event(&mut s, &pending.offer.peer_key, "📞 Call ended");
            return s.persist();
        }
        // Hanging up while "reconnecting…": tell the peer the OLD call is over so
        // their resume gives up immediately too.
        if let Some(rc) = s.reconnect.take() {
            eng().end_system_call(&rc.ring_handle, telecom::cause::LOCAL);
            let client = s.client.clone().ok_or("not configured")?;
            if rc.caller {
                send_call_terminal_everywhere(
                    &client,
                    &mut s,
                    &rc.peer_username,
                    &rc.peer_key,
                    &rc.call_instance_id,
                    &rc.offer_id,
                    client_core::callstate::CallTerminalReason::CallerCancelled,
                );
            } else {
                let _ = send_call_terminal_to_device(
                    &client,
                    &mut s,
                    &rc.peer_device_key,
                    &rc.peer_reply_to_mailbox,
                    &rc.call_instance_id,
                    &rc.offer_id,
                    client_core::callstate::CallTerminalReason::DeclinedHere,
                );
            }
            log_call_event(
                &mut s,
                &rc.peer_key,
                &call_end_label("Call", rc.caller, rc.connected_at),
            );
            s.persist()?;
        }
        return Ok(());
    };
    let _ = call.stop.send(true);
    // The platform's call ends with ours. Without this the system keeps an ongoing call
    // nothing can end, audio focus is never released, and the next `addCall` is refused.
    eng().end_system_call(&call.ring_handle, telecom::cause::LOCAL);
    let client = s.client.clone().ok_or("not configured")?;
    if call.caller {
        send_call_terminal_everywhere(
            &client,
            &mut s,
            &call.peer_username,
            &call.peer_key,
            &call.call_instance_id,
            &call.offer_id,
            client_core::callstate::CallTerminalReason::CallerCancelled,
        );
    } else {
        let _ = send_call_terminal_to_device(
            &client,
            &mut s,
            &call.peer_device_key,
            &call.peer_reply_to_mailbox,
            &call.call_instance_id,
            &call.offer_id,
            client_core::callstate::CallTerminalReason::DeclinedHere,
        );
    }
    log_call_event(
        &mut s,
        &call.peer_key,
        &call_end_label(
            "Call",
            call.caller,
            call.connected_at.load(std::sync::atomic::Ordering::Relaxed),
        ),
    );
    s.persist()?;
    Ok(())
}

/// The microphones, outputs and cameras this machine offers, plus which are pinned.
///
/// Desktop only. A phone has one microphone and one camera the front/back button
/// flips, and its output is the earpiece/loudspeaker/Bluetooth *route* chooser — a
/// device list there would be a second, contradictory way to say the same things.
#[tauri::command]
pub async fn call_media_devices() -> Result<serde_json::Value, String> {
    #[cfg(not(target_os = "android"))]
    {
        // Enumerating cameras opens each device to ask what it supports, and the sound
        // server round-trips; neither belongs on an async worker thread.
        eng()
            .spawn_blocking(|| {
                let (inputs, outputs) = audio::list_devices();
                let (pin_in, pin_out) = audio::pinned_devices();
                serde_json::json!({
                    "supported": true,
                    "inputs": inputs,
                    "outputs": outputs,
                    "cameras": media_shell::list_cameras(),
                    "input": pin_in,
                    "output": pin_out,
                    "camera": media_shell::pinned_camera(),
                })
            })
            .await
            .map_err(|e| e.to_string())
    }
    #[cfg(target_os = "android")]
    {
        Ok(serde_json::json!({
            "supported": false, "inputs": [], "outputs": [], "cameras": []
        }))
    }
}

/// Pin the microphone (`kind: "input"`), the output (`"output"`) or the camera
/// (`"camera"`). An empty/absent `id` restores the platform default, including
/// following it when the OS default changes. Applies to a call already in progress.
#[tauri::command]
pub fn call_set_media_device(kind: String, id: Option<String>) -> Result<(), String> {
    if !matches!(kind.as_str(), "input" | "output" | "camera") {
        return Err("unknown device kind".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let id = id.filter(|s| !s.is_empty());
        match kind.as_str() {
            "camera" => media_shell::set_camera(id),
            other => audio::set_device(other == "input", id),
        }
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        let _ = id;
        Err("device selection is a desktop control".into())
    }
}

/// Everything the user could share: each monitor and each ordinary application window,
/// with a still preview. Desktop only — an Android share is the whole device, granted
/// by the system's own MediaProjection consent dialog.
#[tauri::command]
pub async fn screen_sources() -> Result<serde_json::Value, String> {
    #[cfg(not(target_os = "android"))]
    {
        // Grabbing and PNG-encoding one preview per window is tens of milliseconds of
        // blocking work; keep it off the async runtime's worker threads.
        let list = eng()
            .spawn_blocking(media_shell::screen_sources)
            .await
            .map_err(|e| e.to_string())??;
        Ok(serde_json::json!({ "supported": true, "sources": list }))
    }
    #[cfg(target_os = "android")]
    {
        Ok(serde_json::json!({ "supported": false, "sources": [] }))
    }
}

/// Toggle call noise suppression (default on). Desktop: gates RNNoise in the capture
/// path; Android: the platform NoiseSuppressor effect on the voice mic. Global rather
/// than per-call — it applies to the live call immediately and to every later one.
#[tauri::command]
pub fn call_set_noise_suppression(on: bool) {
    audio::NOISE_SUPPRESSION.store(on, std::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "android")]
    android_media::set_voice_noise_suppression(on);
}

/// Mute/unmute the microphone. Wire cadence is unchanged (encoded silence goes out),
/// so mute state is invisible to the relay and the network.
#[tauri::command]
pub async fn call_set_muted(state: tauri::State<'_, AppState>, muted: bool) -> Result<(), String> {
    let s = state.inner.lock().await;
    let call = s.call.as_ref().ok_or("no active call")?;
    call.toggles
        .muted
        .store(muted, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Start/stop the camera track. Capture starts only after this is set (the engine
/// polls the source only while on, and the capture thread releases the device — and
/// the camera LED — shortly after it's turned off). Unlike mute, a track toggle is
/// visible to the relay as a bandwidth change; see the media module's threat notes.
#[tauri::command]
pub async fn call_set_camera(state: tauri::State<'_, AppState>, on: bool) -> Result<(), String> {
    let s = state.inner.lock().await;
    let call = s.call.as_ref().ok_or("no active call")?;
    call.toggles
        .camera_on
        .store(on, std::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "android")]
    android_media::set_camera_capture(on);
    Ok(())
}

/// Start/stop the screen-share track.
///
/// `source` names what to share — `{"kind": "screen"|"window", "id": <platform id>}`
/// from [`screen_sources`]. Absent (and always on Android, where the MediaProjection
/// covers the whole device) means the primary monitor. Set *before* the toggle so the
/// capture thread's first frame is already of the right thing: starting on the primary
/// monitor and switching a frame later would flash whatever is on it to the peer.
#[tauri::command]
pub async fn call_set_screen(
    state: tauri::State<'_, AppState>,
    on: bool,
    source: Option<ScreenSourcePick>,
) -> Result<(), String> {
    let s = state.inner.lock().await;
    let call = s.call.as_ref().ok_or("no active call")?;
    // One screen at a time. Two shares at once is not a feature with an audience: the
    // stage has one slot for the peer's screen, both uplinks pay a video-class bitrate,
    // and neither person can tell whose screen the other is looking at. Cameras are
    // different — several make sense at once and always have.
    //
    // Enforced here and not only in the UI because the UI can only disable a button it
    // has already been told to disable: the peer's TrackOn arrives over the network, so
    // two people pressing share within the same round trip both see an enabled button.
    // This check is the one that actually holds.
    if on && call.peer_screen.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("Only one person can share a screen at a time".into());
    }
    if on {
        media_shell::set_screen_target(match source {
            Some(p) if p.kind == "screen" => media_shell::ScreenTarget::Screen(p.id),
            Some(p) if p.kind == "window" => media_shell::ScreenTarget::Window(p.id),
            _ => media_shell::ScreenTarget::Primary,
        });
    }
    call.toggles
        .screen_on
        .store(on, std::sync::atomic::Ordering::Relaxed);
    // The UI applies its share-system-audio preference via `call_set_screen_audio`
    // right after enabling the share; here only the stop side is owned — sharing
    // system audio without a screen share is not a thing.
    if !on {
        call.toggles
            .screen_audio_on
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(target_os = "android")]
    {
        // Reset the bridge's audio intent with the projection so a stale "wanted"
        // can't attach AudioPlaybackCapture to the next share uninvited.
        if !on {
            android_media::set_screen_audio_capture(false);
        }
        android_media::set_screen_capture(on);
    }
    Ok(())
}

/// Toggle system-audio alongside an active screen share. No-ops (returns an error the
/// UI shows) when this platform has no loopback/monitor source.
#[tauri::command]
pub async fn call_set_screen_audio(
    state: tauri::State<'_, AppState>,
    on: bool,
) -> Result<(), String> {
    let s = state.inner.lock().await;
    let call = s.call.as_ref().ok_or("no active call")?;
    if on && !media_shell::screen_audio_available() {
        return Err("system audio capture is not available on this platform".into());
    }
    call.toggles
        .screen_audio_on
        .store(on, std::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "android")]
    android_media::set_screen_audio_capture(on);
    Ok(())
}

/// The UI (re)binds the channel decoded peer video frames are streamed over.
/// Message layout: `track(1) || w(2 BE) || h(2 BE) || I420` (w=h=0 ⇒ track off).
#[tauri::command]
pub async fn call_media_channel(
    channel: tauri::ipc::Channel<tauri::ipc::InvokeResponseBody>,
) -> Result<(), String> {
    *eng().media_ui.lock().map_err(|_| "poisoned")? = Some(channel);
    // A fresh channel owes nothing: whatever the previous webview had in hand is never
    // going to be acknowledged, and holding those slots would stall video for the call.
    media_shell::frames::reset();
    Ok(())
}

/// The webview has painted a peer frame and is ready for another.
///
/// This is the whole of the flow control on the frame path, and it has to exist: Tauri's
/// channel is fire-and-forget and parks large payloads in an unbounded map, so without an
/// acknowledgement there is no way to know the webview is falling behind — and at 3.1 MB
/// per 1080p frame, twenty times a second, "falling behind" stops being slow and starts
/// being a dead process.
#[tauri::command]
pub fn call_frame_ack(track: u8) {
    media_shell::frames::release(track);
}
