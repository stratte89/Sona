//! Note-to-self: notes are ordinary history entries under the reserved
//! [`NOTE_TO_SELF_PEER`] key, synced ONLY to the account's own other devices
//! (SelfText/SelfFile with that peer key). No recipient ever exists, so there is no KT
//! resolve, no session, no receipt, no typing — just the sealed history and the durable
//! self-sync outbox.

use crate::*;
use client_core::NOTE_TO_SELF_PEER;

/// A locally minted id for a note (no envelope exists to donate one). Same shape as the
/// legacy single-device group path's ids.
fn note_msg_id() -> String {
    format!(
        "n{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

/// Send a note-to-self text: record locally, then self-sync to our own other devices.
/// The local record always succeeds — a network failure only delays the other devices'
/// copies (durable outbox retries them).
#[tauri::command]
pub async fn send_note(
    state: tauri::State<'_, AppState>,
    text: String,
    reply_to: Option<String>,
) -> Result<(), String> {
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err("empty message".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let reply = reply_to.as_deref().and_then(|id| {
        s.history.message(NOTE_TO_SELF_PEER, id).map(|m| {
            let mut preview: String = m.body.chars().take(80).collect();
            if m.body.chars().count() > 80 {
                preview.push('…');
            }
            client_core::ReplyRef {
                msg_id: id.to_string(),
                preview,
            }
        })
    });
    let msg_id = note_msg_id();
    let sent_at = now_secs();
    s.history.record_full(
        NOTE_TO_SELF_PEER,
        Direction::Outgoing,
        &msg_id,
        &text,
        sent_at,
        reply.clone(),
        None,
    );
    // Multi-device: mirror to our own other devices (durable — survives kill/restart).
    if s.multi_device {
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            if let Ok(envs) = client
                .prepare_note_text_selfsync(
                    account,
                    &mut sess.history,
                    &msg_id,
                    &text,
                    sent_at,
                    reply,
                    false,
                )
                .await
            {
                if !envs.is_empty() {
                    sess.history.outbox_push(envs, now_secs());
                }
            }
        }
    }
    s.persist()?;
    drop(s);
    spawn_outbox_drain(state.inner.clone(), client, 0);
    Ok(())
}

/// Set (or clear, with `None`) the disappearing-messages timer for note-to-self. Notes
/// have no peer — the timer is pure local state, self-synced (`SelfTimer`) to our own
/// other devices so every device stamps the same deadlines on the copies it records.
#[tauri::command]
pub async fn set_note_disappearing(
    state: tauri::State<'_, AppState>,
    secs: Option<u64>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    s.history.set_timer(NOTE_TO_SELF_PEER, secs);
    let label = timer_label(secs);
    s.history
        .record_system(NOTE_TO_SELF_PEER, &label, now_secs());
    if s.multi_device {
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            if let Ok(envs) = client
                .prepare_note_timer_selfsync(account, &mut sess.history, secs)
                .await
            {
                if !envs.is_empty() {
                    sess.history.outbox_push(envs, now_secs());
                }
            }
        }
    }
    s.persist()?;
    drop(s);
    spawn_outbox_drain(state.inner.clone(), client, 0);
    Ok(())
}

/// Note-to-self attachment: upload the (padded, encrypted) blob once so our other
/// devices can fetch it, record locally, self-sync the reference. Single-device
/// accounts still upload — the blob is the storage the fetch path expects.
pub(crate) async fn send_note_attachment(
    state: &tauri::State<'_, AppState>,
    filename: String,
    data: Vec<u8>,
    voice_secs: Option<u32>,
    caption: Option<String>,
    peaks: Vec<u8>,
) -> Result<MsgView, String> {
    let client = {
        let s = state.inner.lock().await;
        s.client.clone().ok_or("not configured")?
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

    let mut s = state.inner.lock().await;
    let msg_id = note_msg_id();
    let sent_at = attachment.ts;
    s.history.record_attachment(
        NOTE_TO_SELF_PEER,
        Direction::Outgoing,
        &msg_id,
        attachment.clone(),
        sent_at,
        None,
    );
    if s.multi_device {
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            if let Ok(envs) = client
                .prepare_note_file_selfsync(account, &mut sess.history, &msg_id, attachment, false)
                .await
            {
                if !envs.is_empty() {
                    sess.history.outbox_push(envs, now_secs());
                }
            }
        }
    }
    let delete_at = s
        .history
        .message(NOTE_TO_SELF_PEER, &msg_id)
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
    spawn_outbox_drain(state.inner.clone(), client, 0);
    Ok(view)
}
