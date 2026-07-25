use crate::*;

/// The UI reports which conversation it currently has open (peer key or group id), or
/// `None` on the chat list / settings. Drives the "notify when a *different* chat is open"
/// rule. Cheap; no session lock needed.
/// Mobile: route call audio to the loudspeaker (`true`) or the earpiece (`false`).
/// The platform echo canceller keeps running either way. Desktop has no earpiece —
/// routing is the OS mixer's job — so this is Android-only.
#[tauri::command]
pub fn call_set_speaker(on: bool) -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        android_media::set_speakerphone(on);
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
pub fn call_set_route(route: String) -> Result<serde_json::Value, String> {
    if !matches!(route.as_str(), "earpiece" | "speaker" | "bluetooth") {
        return Err("unknown audio route".into());
    }
    #[cfg(target_os = "android")]
    {
        if let Some(j) = android_media::set_audio_route(&route) {
            if let Ok(v) = serde_json::from_str(&j) {
                return Ok(v);
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
                "transport": c.transport,
            })
        }),
        incoming: s
            .incoming
            .as_ref()
            .map(|o| serde_json::json!({ "username": o.username, "call_id": o.call_id })),
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
    })
}

/// Ring a contact: mint the per-call capability + key, send them over the ratchet, and
/// join the room to wait.
#[tauri::command]
pub async fn call_start(state: tauri::State<'_, AppState>, username: String) -> Result<(), String> {
    let username = username.trim().to_string();
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
    let contact = resolve_send_contact(&mut s, &client, &username).await?;
    let ticket = client_core::call::CallTicket::mint();
    let account = s.account.as_mut().ok_or("locked")?;
    // Ring the KT-bound (primary) device first over the existing 1:1 path — first-ring
    // latency is identical to single-device.
    client
        .send_call_offer(account, &contact, &ticket.call_id, &ticket.key_b64)
        .await
        .map_err(|e| e.to_string())?;
    // Then ring the rest of the contact's verified roster. Any roster problem (stale,
    // rollback, offline) means NO extra copies — the call key is never sealed to a
    // device outside the current verified roster; the primary keeps ringing regardless.
    let mut ring_fanout = 1usize;
    if s.multi_device {
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            if let Ok(extras) = client
                .extra_call_offer_envelopes(
                    account,
                    &mut sess.history,
                    &contact,
                    &ticket.call_id,
                    &ticket.key_b64,
                )
                .await
            {
                for env in &extras {
                    let _ = client.post_envelope(env).await;
                }
                ring_fanout += extras.len();
            }
        }
    }
    s.persist()?;
    // The offer is out — tell the UI it's ringing now, while the (slower) mic init
    // and room join below finish. A spawn failure still surfaces as this command's
    // error and the UI tears the overlay down.
    eng().emit(
        "call",
        serde_json::json!({ "kind": "outgoing", "username": contact.username }),
    );
    spawn_call(
        &state.inner,
        &client,
        &mut s,
        ticket.call_id,
        ticket.key_b64,
        contact.username.clone(),
        contact.identity_key.clone(),
        true,
        false, // callee caps unknown until the answer arrives
        ring_fanout,
    )
    .await?;
    Ok(())
}

/// Accept the pending inbound ring.
#[tauri::command]
pub async fn call_accept(state: tauri::State<'_, AppState>) -> Result<(), String> {
    call_accept_inner(&state.inner).await
}

/// Decline the pending inbound ring.
#[tauri::command]
pub async fn call_decline(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let offer = s.incoming.take().ok_or("no incoming call")?;
    eng().cancel_ring(&offer.call_id, "");
    let client = s.client.clone().ok_or("not configured")?;
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
    s.persist()
}

/// Hang up the live call (either side, any state).
#[tauri::command]
pub async fn call_hangup(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let Some(call) = s.call.take() else {
        // Hanging up while "reconnecting…": tell the peer the OLD call is over so
        // their resume gives up immediately too.
        if let Some(rc) = s.reconnect.take() {
            let client = s.client.clone().ok_or("not configured")?;
            send_call_end_everywhere(
                &client,
                &mut s,
                &rc.peer_username,
                &rc.peer_key,
                &rc.old_call_id,
            )
            .await;
            log_call_event(
                &mut s,
                &rc.peer_key,
                &call_end_label("Call", true, rc.connected_at),
            );
            s.persist()?;
        }
        return Ok(());
    };
    let _ = call.stop.send(true);
    let client = s.client.clone().ok_or("not configured")?;
    send_call_end_everywhere(
        &client,
        &mut s,
        &call.peer_username,
        &call.peer_key,
        &call.call_id,
    )
    .await;
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

/// Start/stop the screen-share track. `source` selects which monitor or window to
/// share: "monitor:0", "window:5", or None for primary monitor.
#[tauri::command]
pub async fn call_set_screen(
    state: tauri::State<'_, AppState>,
    on: bool,
    source: Option<String>,
) -> Result<(), String> {
    let s = state.inner.lock().await;
    let call = s.call.as_ref().ok_or("no active call")?;
    call.toggles
        .screen_on
        .store(on, std::sync::atomic::Ordering::Relaxed);
    if on {
        if let Some(src_str) = source {
            let src = media_shell::parse_source(&src_str);
            if let Ok(mut ss) = call.screen_source.lock() {
                *ss = src;
            }
        }
    } else {
        call.toggles
            .screen_audio_on
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(target_os = "android")]
    {
        if !on {
            android_media::set_screen_audio_capture(false);
        }
        android_media::set_screen_capture(on);
    }
    Ok(())
}

/// List available monitors and windows for the screen-share source picker.
#[tauri::command]
pub fn call_list_screens() -> serde_json::Value {
    media_shell::list_sources()
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

/// List available audio input and output devices for the settings UI.
#[tauri::command]
pub fn call_list_audio_devices() -> serde_json::Value {
    audio::list_audio_devices()
}

/// Set preferred audio input and output devices (empty string = system default).
/// Applied on the next call start; does not affect an active call.
#[tauri::command]
pub fn call_set_audio_devices(input: String, output: String) -> Result<(), String> {
    audio::set_audio_devices(&input, &output);
    Ok(())
}

/// Set per-peer volume gain (0.0 = mute, 1.0 = unity, 2.0 = 2× loud).
/// Works for both 1:1 and group calls. Applied live — no call restart needed.
#[tauri::command]
pub fn call_set_peer_volume(peer: String, gain: f32) -> Result<(), String> {
    audio::set_peer_volume(&peer, gain);
    if let Ok(mut w) = client_core::groupcall::PEER_VOLUMES.write() {
        w.insert(peer, gain);
    }
    Ok(())
}

/// Set per-peer screen-audio volume gain (0.0 = mute, 1.0 = unity, 2.0 = 2× loud).
/// Only affects the screenshare audio stream, not the voice stream. Applied live.
#[tauri::command]
pub fn call_set_screen_volume(peer: String, gain: f32) -> Result<(), String> {
    audio::set_screen_volume(&peer, gain);
    Ok(())
}

/// The UI (re)binds the channel decoded peer video frames are streamed over.
/// Message layout: `track(1) || w(2 BE) || h(2 BE) || I420` (w=h=0 ⇒ track off).
#[tauri::command]
pub async fn call_media_channel(
    channel: tauri::ipc::Channel<tauri::ipc::InvokeResponseBody>,
) -> Result<(), String> {
    *eng().media_ui.lock().map_err(|_| "poisoned")? = Some(channel);
    Ok(())
}
