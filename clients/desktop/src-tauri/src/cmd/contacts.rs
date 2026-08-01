use crate::*;

pub(crate) async fn edit_contact(
    state: &tauri::State<'_, AppState>,
    username: &str,
    f: impl FnOnce(&mut client_core::ContactPin),
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.history.with_contact_mut(username.trim(), f) {
        return Err("no such contact".into());
    }
    s.persist()
}

#[tauri::command]
pub async fn set_pinned(
    state: tauri::State<'_, AppState>,
    username: String,
    pinned: bool,
) -> Result<(), String> {
    edit_contact(&state, &username, |c| c.pinned = pinned).await
}

/// Archive/unarchive a chat (local-only). Archiving also clears any manual-unread mark.
#[tauri::command]
pub async fn set_archived(
    state: tauri::State<'_, AppState>,
    username: String,
    archived: bool,
) -> Result<(), String> {
    edit_contact(&state, &username, |c| {
        c.archived = archived;
        if archived {
            c.unread = false;
        }
    })
    .await
}

/// Manually mark a chat unread (or clear it). Local-only; the badge shows until opened.
#[tauri::command]
pub async fn set_unread(
    state: tauri::State<'_, AppState>,
    username: String,
    unread: bool,
) -> Result<(), String> {
    edit_contact(&state, &username, |c| {
        c.unread = unread;
        // Marking unread also un-archives, so the chat is visible with its badge.
        if unread {
            c.archived = false;
        }
    })
    .await
}

/// Clear a chat's manual-unread and archived flags when it's opened. Idempotent; no-op for
/// an unknown contact.
#[tauri::command]
pub async fn clear_unread_on_open(
    state: tauri::State<'_, AppState>,
    username: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let changed = s.history.with_contact_mut(username.trim(), |c| {
        c.unread = false;
        c.archived = false;
    });
    if changed {
        s.persist()
    } else {
        Ok(())
    }
}

/// `until` = unix seconds (u64::MAX-ish for "forever"); `None` unmutes.
#[tauri::command]
pub async fn set_muted(
    state: tauri::State<'_, AppState>,
    username: String,
    until: Option<u64>,
) -> Result<(), String> {
    edit_contact(&state, &username, |c| c.muted_until = until).await
}

#[tauri::command]
pub async fn set_nickname(
    state: tauri::State<'_, AppState>,
    username: String,
    nickname: Option<String>,
) -> Result<(), String> {
    let nickname = nickname
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    edit_contact(&state, &username, |c| c.nickname = nickname).await
}

/// Our own profile picture as a `data:` image URI, or `None` if unset. Drives the settings
/// preview + our own avatar in the UI.
#[tauri::command]
pub async fn my_avatar(state: tauri::State<'_, AppState>) -> Result<Option<String>, String> {
    let s = state.inner.lock().await;
    Ok(s.history.my_avatar().map(str::to_string))
}

/// Set (or clear with `None`) our own profile picture, then broadcast it to every (non-blocked)
/// contact we share a session with so their client shows it, and durably self-sync it to our
/// own other devices so all of them show the same picture. Stored (sanitized) locally first, so
/// the picture sticks even if some sends fail — those recipients learn it whenever we next
/// reach them. The value is bounded + format-checked in `History::set_my_avatar`.
#[tauri::command]
pub async fn set_my_avatar(
    state: tauri::State<'_, AppState>,
    avatar: Option<String>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    s.history.set_my_avatar(avatar);
    // Re-read the sanitized value so recipients get exactly what we stored (never raw input).
    let stored = s.history.my_avatar().map(str::to_string);
    // Skip blocked contacts — we drop their traffic and refuse sends, so they get no picture.
    let notify: Vec<(String, String)> = s
        .history
        .contacts()
        .into_iter()
        .filter(|(_, p)| !p.blocked)
        .map(|(u, p)| (u, p.identity_key))
        .collect();
    let multi = s.multi_device;
    if multi {
        // Durable self-sync to our own other devices (retried across restarts via the outbox).
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            match client
                .prepare_profile_selfsync(account, &mut sess.history, stored.clone())
                .await
            {
                Ok(envs) if !envs.is_empty() => sess.history.outbox_push(envs, now_secs()),
                _ => {}
            }
        }
    }
    {
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            for (username, key) in &notify {
                if !account.ratchet_ref().has_session(key) {
                    continue; // no session yet — reconciled on the next send to them
                }
                let contact = contact_for(username, key);
                if client
                    .send_profile(account, &contact, stored.clone())
                    .await
                    .is_ok()
                {
                    // Bookkeeping for the reconcile pass: contacts we could NOT reach
                    // here keep their stale fingerprint and get the picture with the
                    // next message we send them (see `spawn_profile_reconcile`).
                    sess.history.mark_profile_sent(username);
                }
            }
        }
    }
    s.persist()?;
    drop(s);
    if multi {
        spawn_outbox_drain(state.inner.clone(), client, 0);
    }
    Ok(())
}

#[tauri::command]
pub async fn set_blocked(
    state: tauri::State<'_, AppState>,
    username: String,
    blocked: bool,
) -> Result<(), String> {
    edit_contact(&state, &username, |c| c.blocked = blocked).await?;
    // A blocked caller must not be able to ring this device while it is locked either.
    refresh_call_screen(&mut *state.inner.lock().await);
    Ok(())
}

/// Delete a conversation. `for_both` additionally sends an end-to-end delete request the
/// peer's client honors (both sides already hold the plaintext — cooperative hygiene,
/// not a security boundary). Local deletion always succeeds even if the send fails.
#[tauri::command]
pub async fn delete_chat(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
    for_both: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if for_both {
        let client = s.client.clone().ok_or("not configured")?;
        if let Some(account) = s.account.as_mut() {
            let contact = contact_for(username.trim(), peer.trim());
            let _ = client.send_delete_chat(account, &contact).await;
        }
    }
    s.history.delete_conversation(peer.trim());
    s.history.remove_contact(username.trim());
    s.persist()
}

/// Best-effort profile reconcile: if this contact has never been sent our **current**
/// profile picture (new contact, or a broadcast that failed or skipped them for lack of
/// a session), send it now. Called after the moments a session provably exists — an
/// outgoing 1:1 send, or accepting their message request. Idempotent and cheap when
/// nothing is owed (one lock + a fingerprint compare, no network).
pub(crate) fn spawn_profile_reconcile(inner: Arc<Mutex<Session>>, username: String) {
    eng().spawn(async move {
        let mut s = inner.lock().await;
        if !s.history.profile_send_needed(&username) {
            return;
        }
        let Some(client) = s.client.clone() else {
            return;
        };
        let Some(key) = s.history.pinned_contact_key(&username).map(str::to_string) else {
            return;
        };
        let stored = s.history.my_avatar().map(str::to_string);
        let sess = &mut *s;
        let Some(account) = sess.account.as_mut() else {
            return;
        };
        if !account.ratchet_ref().has_session(&key) {
            return; // still no session — a later send retries
        }
        let contact = contact_for(&username, &key);
        if client.send_profile(account, &contact, stored).await.is_ok() {
            sess.history.mark_profile_sent(&username);
            let _ = sess.persist();
        }
    });
}
