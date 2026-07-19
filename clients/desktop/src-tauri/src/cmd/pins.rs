//! Message pinning. A pin is shared conversation metadata (both sides / all members
//! already hold the plaintext), so either side of a 1:1 and any group member may pin.
//! 1:1 pins fan out to the peer's devices + self-sync to our own (reaction-shaped);
//! group pins ride the standard group fan-out. Note-to-self pins are purely local.

use crate::*;
use client_core::NOTE_TO_SELF_PEER;

/// Pin (or unpin) a 1:1 message: flip it locally, then sync the peer (and our own
/// other devices) so every timeline shows the same pinned set.
#[tauri::command]
pub async fn set_msg_pinned(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
    msg_id: String,
    pin: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.history.set_msg_pinned(peer.trim(), msg_id.trim(), pin) {
        return Err("no such message".into());
    }
    // Note-to-self: no peer exists — the local flip is the whole operation. (Multi-device
    // note pins stay per-device; a note pin is a bookmark, not shared state.)
    if peer.trim() == NOTE_TO_SELF_PEER {
        return s.persist();
    }
    let client = s.client.clone().ok_or("not configured")?;
    let contact = contact_for(username.trim(), peer.trim());
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        let fan = client
            .prepare_pin_fanout(
                account,
                &mut sess.history,
                &contact,
                msg_id.trim().to_string(),
                pin,
            )
            .await
            .map_err(|e| e.to_string())?;
        // Same durability shape as reactions: self-sync copies ride the outbox (due
        // immediately), recipient copies post now.
        let deferred = !fan.deferred.is_empty();
        if deferred {
            sess.history.outbox_push(fan.deferred.clone(), now_secs());
        }
        sess.persist()?;
        drop(s);
        client
            .post_envelopes(&fan.immediate)
            .await
            .map_err(|e| e.to_string())?;
        if deferred {
            spawn_outbox_drain(state.inner.clone(), client.clone(), 0);
        }
    } else {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_pin_msg(account, &contact, msg_id.trim(), pin)
            .await
            .map_err(|e| e.to_string())?;
        s.persist()?;
    }
    Ok(())
}

/// Pin (or unpin) a group message for every member (any member may — roster model).
#[tauri::command]
pub async fn set_group_msg_pinned(
    state: tauri::State<'_, AppState>,
    group_id: String,
    msg_id: String,
    pin: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?;
    crate::cmd::groups::ensure_in_group(g)?;
    let group = group_from_record(&group_id, g);
    if !s
        .history
        .set_group_msg_pinned(&group_id, msg_id.trim(), pin)
    {
        return Err("no such message".into());
    }
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_pin_multi(account, &mut sess.history, &group, msg_id.trim(), pin)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_group_pin(account, &group, msg_id.trim(), pin)
            .await
            .map_err(|e| e.to_string())?;
    }
    s.persist()
}
