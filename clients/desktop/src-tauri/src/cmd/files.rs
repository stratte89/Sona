use crate::*;

/// Resolve the contact to send to, exactly like `send` does: fast path over the live
/// session, full KT-checked discovery only when needed. Errors with `KEY_CHANGED` so the
/// UI can route to the verify flow.
pub(crate) async fn resolve_send_contact(
    s: &mut Session,
    client: &Client,
    username: &str,
) -> Result<Contact, String> {
    // A revoked device must not send: recipients would discard the messages anyway
    // (this device is off the roster), which looks like silent delivery to the user.
    if s.history.revoked() {
        return Err("this device was unlinked from the account — relink to continue".into());
    }
    let known = s.history.pinned_contact_key(username).map(str::to_string);
    let account = s.account.as_mut().ok_or("locked")?;
    ensure_not_self(account, username, known.as_deref())?;
    let my_key = account.ratchet_ref().identity_key();
    match &known {
        Some(key) if account.ratchet_ref().has_session(key) => Ok(contact_for(username, key)),
        _ => match client
            .add_contact_checked(account, username, known.as_deref())
            .await
            .map_err(|e| e.to_string())?
        {
            ContactOutcome::New(c) | ContactOutcome::Unchanged(c) => {
                if c.identity_key == my_key {
                    return Err("that's your own account — you can't message yourself".into());
                }
                Ok(c)
            }
            ContactOutcome::KeyChanged { .. } => Err("KEY_CHANGED".into()),
        },
    }
}

/// Shared body of `send_file` / `send_voice`: encrypt + upload the blob (lock released —
/// uploads can be slow), then encrypt the reference over the ratchet and relay it.
/// `voice_secs` marks the attachment as a voice message with that duration.
pub(crate) async fn send_attachment_inner(
    state: &tauri::State<'_, AppState>,
    username: &str,
    group_id: Option<String>,
    filename: &str,
    data_b64: &str,
    voice_secs: Option<u32>,
    caption: Option<String>,
    peaks: Vec<u8>,
) -> Result<MsgView, String> {
    let caption = caption
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let data = STANDARD
        .decode(data_b64.trim())
        .map_err(|_| "bad file data")?;
    if data.is_empty() {
        return Err("empty file".into());
    }
    if data.len() > MAX_ATTACHMENT_BYTES {
        return Err("file too large (max 10 MB)".into());
    }
    // Keep only the basename — no path segments inside the payload.
    let filename = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("file")
        .to_string();

    // Group target: same blob pipeline, pairwise reference fan-out instead of a
    // single contact (`group_id` wins over `username` when both are set).
    if let Some(gid) = group_id.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
        return send_group_attachment(state, gid, filename, data, voice_secs, caption, peaks).await;
    }

    // Note-to-self: record + self-sync only (no recipient, no KT resolve).
    if username == client_core::NOTE_TO_SELF_PEER {
        return crate::cmd::notes::send_note_attachment(
            state, filename, data, voice_secs, caption, peaks,
        )
        .await;
    }

    let (client, contact) = {
        let mut s = state.inner.lock().await;
        let client = s.client.clone().ok_or("not configured")?;
        let contact = resolve_send_contact(&mut s, &client, username).await?;
        (client, contact)
    };

    // Slow part (encrypt-to-blob + upload) with no lock held.
    let mut attachment = client
        .upload_attachment(&filename, &data)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(secs) = voice_secs {
        attachment.voice = true;
        attachment.duration_secs = secs;
    }
    attachment.caption = caption.clone();
    attachment.peaks = peaks;
    let view_peaks = attachment.peaks.clone();

    // Encrypt the reference under the lock, persist the advanced ratchet, then post.
    // Multi-device: fan the reference out to every recipient device AND self-sync it to
    // our own devices via the durable outbox (attachments previously skipped fan-out
    // entirely — linked devices never saw them).
    let (msg_id, sent_at) = {
        let mut s = state.inner.lock().await;
        if s.multi_device {
            let sess = &mut *s;
            let account = sess.account.as_mut().ok_or("locked")?;
            let fan = client
                .prepare_attachment_fanout(
                    account,
                    &mut sess.history,
                    &contact,
                    attachment.clone(),
                    false,
                )
                .await
                .map_err(|e| e.to_string())?;
            let jitter = if fan.deferred.is_empty() {
                None
            } else {
                let j = self_sync_jitter_secs();
                sess.history
                    .outbox_push(fan.deferred.clone(), now_secs() + j);
                Some(j)
            };
            sess.persist()?;
            drop(s);
            client
                .post_envelopes(&fan.immediate)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(j) = jitter {
                spawn_outbox_drain(state.inner.clone(), client.clone(), j + 1);
            }
            (fan.msg_id, fan.sent_at)
        } else {
            let expire = Some(s.history.timer(&contact.identity_key).unwrap_or(0));
            let account = s.account.as_mut().ok_or("locked")?;
            let prepared = client
                .prepare_attachment(account, &contact, attachment.clone(), expire, false)
                .map_err(|e| e.to_string())?;
            s.persist()?;
            drop(s);
            client
                .post_envelope(&prepared.envelope)
                .await
                .map_err(|e| e.to_string())?;
            (prepared.msg_id, prepared.sent_at)
        }
    };

    let mut s = state.inner.lock().await;
    // Sending an attachment to a pending requester is consent, same as a text. By KEY:
    // a pending row is keyed by the requester's identity key, not the name they claimed
    // (SP-02), so the username would not find it.
    s.history.accept_request_for_key(&contact.identity_key);
    let verified = s.history.contact_verified(&contact.username);
    s.history
        .pin_contact(&contact.username, &contact.identity_key, verified);
    s.history.record_attachment(
        &contact.identity_key,
        Direction::Outgoing,
        &msg_id,
        attachment,
        sent_at,
        None,
    );
    let delete_at = s
        .history
        .message(&contact.identity_key, &msg_id)
        .and_then(|m| m.delete_at);
    let view = MsgView {
        msg_id,
        direction: "outgoing",
        body: filename,
        sent_at,
        delete_at,
        attachment: true,
        voice: voice_secs.is_some(),
        duration_secs: voice_secs.unwrap_or(0),
        status: "sent",
        edited: false,
        reply_to_id: None,
        reply_preview: None,
        reactions: Vec::new(),
        caption,
        peaks: view_peaks,
        system: false,
        unread: false,
        pinned: false,
        forwarded: false,
    };
    s.persist()?;
    drop(s);
    // Same as a text send: the session provably exists — reconcile our profile picture.
    cmd::contacts::spawn_profile_reconcile(state.inner.clone(), contact.username.clone());
    Ok(view)
}

#[tauri::command]
pub async fn send_file(
    state: tauri::State<'_, AppState>,
    username: String,
    group_id: Option<String>,
    filename: String,
    data_b64: String,
    caption: Option<String>,
) -> Result<MsgView, String> {
    send_attachment_inner(
        &state,
        username.trim(),
        group_id,
        &filename,
        &data_b64,
        None,
        caption,
        Vec::new(),
    )
    .await
}

/// Whether the configured relay proxies GIF search (`CAP_GIF_SEARCH`).
#[tauri::command]
pub async fn gif_available(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let client = {
        let s = state.inner.lock().await;
        s.client.clone().ok_or("not configured")?
    };
    Ok(client
        .server_capabilities()
        .await
        .map(|caps| caps.iter().any(|c| c == multidevice::CAP_GIF_SEARCH))
        .unwrap_or(false))
}

/// Search GIFs via the relay proxy. Returns the relay's slimmed JSON
/// (`{results: [{url, preview, width, height}], next}`) — the provider never sees us.
#[tauri::command]
pub async fn gif_search(
    state: tauri::State<'_, AppState>,
    query: String,
    pos: Option<String>,
) -> Result<serde_json::Value, String> {
    let client = {
        let s = state.inner.lock().await;
        s.client.clone().ok_or("not configured")?
    };
    client
        .gif_search(query.trim(), pos.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// Trending GIFs from the relay's pre-loaded cache — the GIF tab's default suggestions.
#[tauri::command]
pub async fn gif_trending(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let client = {
        let s = state.inner.lock().await;
        s.client.clone().ok_or("not configured")?
    };
    client.gif_trending().await.map_err(|e| e.to_string())
}

/// Fetch a GIF preview through the relay proxy and hand it to the UI as a data URL
/// (the strict CSP forbids remote images, and the provider must never see the client).
#[tauri::command]
pub async fn gif_preview(state: tauri::State<'_, AppState>, url: String) -> Result<String, String> {
    let client = {
        let s = state.inner.lock().await;
        s.client.clone().ok_or("not configured")?
    };
    let bytes = client.gif_fetch(&url).await.map_err(|e| e.to_string())?;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    Ok(format!("data:image/gif;base64,{}", STANDARD.encode(bytes)))
}

/// Send a picked GIF: fetch the full media through the relay proxy, then ship it as an
/// ordinary end-to-end-encrypted attachment (the recipient never contacts the provider).
#[tauri::command]
pub async fn send_gif(
    state: tauri::State<'_, AppState>,
    username: String,
    group_id: Option<String>,
    url: String,
) -> Result<MsgView, String> {
    let client = {
        let s = state.inner.lock().await;
        s.client.clone().ok_or("not configured")?
    };
    let bytes = client.gif_fetch(&url).await.map_err(|e| e.to_string())?;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let data_b64 = STANDARD.encode(bytes);
    send_attachment_inner(
        &state,
        username.trim(),
        group_id,
        "gif.gif",
        &data_b64,
        None,
        None,
        Vec::new(),
    )
    .await
}

/// Send a recorded voice message: same E2E attachment pipeline (client-side encryption,
/// padded blob, key inside the ratchet — the server sees a voice note and a PDF as the
/// same opaque blob), plus the voice flag + duration for the recipient's player.
#[tauri::command]
pub async fn send_voice(
    state: tauri::State<'_, AppState>,
    username: String,
    group_id: Option<String>,
    data_b64: String,
    mime: String,
    duration_secs: u32,
    peaks: Option<Vec<u8>>,
) -> Result<MsgView, String> {
    if duration_secs == 0 {
        return Err("recording too short".into());
    }
    // Extension only affects the fallback save-as filename; playback keys off `voice`.
    let ext = match mime.as_str() {
        m if m.contains("ogg") => "ogg",
        m if m.contains("wav") => "wav",
        m if m.contains("mp4") || m.contains("aac") => "m4a",
        _ => "webm",
    };
    let filename = format!("voice-{}.{ext}", now_secs());
    // Clamp waveform peaks to a sane bucket count (belt-and-suspenders; the UI sends ~60).
    let mut peaks = peaks.unwrap_or_default();
    peaks.truncate(128);
    send_attachment_inner(
        &state,
        username.trim(),
        group_id,
        &filename,
        &data_b64,
        Some(duration_secs),
        None,
        peaks,
    )
    .await
}

/// Download + verify + decrypt an attachment and return it as base64 (for inline
/// image previews). The download runs with no lock held.
#[tauri::command]
pub async fn fetch_attachment(
    state: tauri::State<'_, AppState>,
    peer: String,
    msg_id: String,
) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (client, att) = attachment_ref(&state, peer.trim(), msg_id.trim()).await?;
    let bytes = client
        .download_attachment(&att)
        .await
        .map_err(|e| e.to_string())?;
    Ok(STANDARD.encode(bytes))
}

/// Download + decrypt an attachment and let the user pick where to save it (native
/// "Save as" dialog, pre-filled with the original filename). `Ok(None)` = user cancelled.
#[tauri::command]
pub async fn save_attachment(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    peer: String,
    msg_id: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (client, att) = attachment_ref(&state, peer.trim(), msg_id.trim()).await?;
    let bytes = client
        .download_attachment(&att)
        .await
        .map_err(|e| e.to_string())?;

    // Basename only — the sender must not steer the path.
    let safe = att
        .filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("attachment")
        .to_string();

    // Native async save dialog; resolve through a oneshot so this command stays async.
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(&safe)
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.map_err(|_| "dialog closed")? else {
        return Ok(None); // user cancelled — not an error
    };
    let path = path.into_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
    Ok(Some(path.to_string_lossy().to_string()))
}

/// The system clipboard's image as `{"name","mime","b64"}` — the Android paste
/// fallback (WebView never exposes clipboard images to JS in a textarea). `null`
/// when the clipboard holds no readable image, and on desktop (whose webviews
/// deliver clipboard files to JS directly).
#[tauri::command]
pub fn clipboard_image() -> Option<serde_json::Value> {
    notifier::clipboard_image().and_then(|s| serde_json::from_str(&s).ok())
}
