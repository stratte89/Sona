//! Message requests: the recipient-side gate UI surface. All enforcement lives in
//! `client-core::History` (the single inbound choke point — sealed sender means only
//! the recipient's client can tell a stranger from a contact); these commands only
//! read/flip that state for the webview.

use crate::*;

/// One row in the requests list.
#[derive(Serialize)]
pub(crate) struct RequestView {
    /// The contacts-map key to pass back to accept/decline — the requester's identity
    /// key, NOT their claimed name. A stranger must not be addressable by a name they
    /// merely claimed (SP-02).
    pub(crate) key: String,
    /// The name the requester claimed, for display only. Unverified until accepted.
    pub(crate) username: String,
    /// The requester's (attributed) conversation key — used to open the held thread
    /// after accepting.
    pub(crate) peer: String,
    /// Unix time of first / latest activity.
    pub(crate) since: u64,
    pub(crate) last: u64,
    /// Texts/attachments withheld entirely (request-only mode).
    pub(crate) withheld: u32,
    /// Suppressed call attempts.
    pub(crate) calls: u32,
    /// Names of group invites held for replay on accept.
    pub(crate) invites: Vec<String>,
    /// Held messages already recorded in the hidden conversation (text-allowed mode).
    pub(crate) held_msgs: usize,
    /// Preview of the newest held message ("" when nothing is held).
    pub(crate) preview: String,
    /// The requester's profile picture, if their broadcast reached us (sanitized).
    pub(crate) avatar: Option<String>,
    /// The user has not viewed this request since its last activity (red dot).
    pub(crate) unseen: bool,
}

/// Badge for the chat-list entry point: how many requests wait, and whether any are new.
#[derive(Serialize)]
pub(crate) struct RequestBadge {
    pub(crate) count: usize,
    pub(crate) unseen: usize,
    /// Requests are enabled at all (gate off ⇒ the entry point disappears).
    pub(crate) enabled: bool,
}

/// The message-request settings the privacy screen renders.
#[derive(Serialize)]
pub(crate) struct RequestPrefsView {
    /// Requests on (default) vs open messaging (anyone can message directly).
    pub(crate) enabled: bool,
    /// A requester's text rides along with the request vs request-only (default).
    pub(crate) allow_text: bool,
}

#[tauri::command]
pub async fn message_requests(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RequestView>, String> {
    let s = state.inner.lock().await;
    // Held content exists in BOTH modes now (so an accept surfaces the first message),
    // but request-only mode must never SHOW it before the accept — no preview there.
    let (_, allow_text) = s.history.request_prefs();
    let out = s
        .history
        .pending_requests()
        .into_iter()
        .map(|(key, pin)| {
            let req = pin.request.clone().unwrap_or_default();
            let username = History::display_name(&key, &pin);
            let held = s.history.messages(&pin.identity_key);
            let preview = if allow_text {
                held.iter()
                    .rev()
                    .find(|m| !m.system)
                    .map(|m| {
                        let mut p: String = m.body.chars().take(90).collect();
                        if m.body.chars().count() > 90 {
                            p.push('…');
                        }
                        p
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };
            RequestView {
                peer: pin.identity_key.clone(),
                since: req.since,
                last: req.last,
                withheld: req.withheld,
                calls: req.calls,
                invites: req.invites.iter().map(|i| i.name.clone()).collect(),
                held_msgs: held.iter().filter(|m| !m.system).count(),
                preview,
                avatar: pin.avatar,
                unseen: !req.seen,
                username,
                key,
            }
        })
        .collect();
    Ok(out)
}

/// The requests badge (entry-point row + red dot). Cheap; called with every chat-list
/// repaint.
#[tauri::command]
pub async fn request_badge(state: tauri::State<'_, AppState>) -> Result<RequestBadge, String> {
    let s = state.inner.lock().await;
    let (enabled, _) = s.history.request_prefs();
    Ok(RequestBadge {
        count: s.history.request_count(),
        unseen: s.history.requests_unseen(),
        enabled,
    })
}

/// Accept a request: the chat surfaces, held invites replay. Returns the peer key so
/// the UI can open the thread directly.
#[tauri::command]
pub async fn accept_msg_request(
    state: tauri::State<'_, AppState>,
    key: String,
) -> Result<String, String> {
    let mut s = state.inner.lock().await;
    let key = key.trim();
    // The name the row will be filed under once accepted — read before the accept,
    // since the row moves from its identity-key slot to that name (SP-02).
    let username = s
        .history
        .pending_requests()
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(k, pin)| History::display_name(&k, &pin))
        .ok_or("no such request")?;
    if !s.history.accept_request(key) {
        return Err(format!(
            "can't accept: “{username}” is already another contact — rename or remove them first"
        ));
    }
    let peer = s
        .history
        .pinned_contact_key(&username)
        .map(str::to_string)
        .unwrap_or_default();
    s.persist()?;
    // An accepted requester may now ring this device while it is locked.
    refresh_call_screen(&mut s);
    drop(s);
    // Accepting made them a full contact — they messaged us, so a session exists: send
    // them our profile picture right away (they never saw our pre-existing one).
    cmd::contacts::spawn_profile_reconcile(state.inner.clone(), username);
    Ok(peer)
}

/// Decline a request. `block` additionally keeps the sender blocked, so their future
/// traffic is dropped silently; otherwise they may request again.
#[tauri::command]
pub async fn decline_msg_request(
    state: tauri::State<'_, AppState>,
    key: String,
    block: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.history.decline_request(key.trim(), block) {
        return Err("no such request".into());
    }
    s.persist()?;
    refresh_call_screen(&mut s);
    Ok(())
}

/// The user opened the requests list — clear the red dot (rows stay pending).
#[tauri::command]
pub async fn mark_requests_seen(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if s.history.requests_unseen() == 0 {
        return Ok(());
    }
    s.history.mark_requests_seen();
    s.persist()
}

#[tauri::command]
pub async fn msg_request_prefs(
    state: tauri::State<'_, AppState>,
) -> Result<RequestPrefsView, String> {
    let s = state.inner.lock().await;
    let (enabled, allow_text) = s.history.request_prefs();
    Ok(RequestPrefsView {
        enabled,
        allow_text,
    })
}

/// Change the message-request settings. Disabling requests accepts everything pending
/// in the same breath (client-core enforces that invariant).
#[tauri::command]
pub async fn set_msg_request_prefs(
    state: tauri::State<'_, AppState>,
    enabled: bool,
    allow_text: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.history.set_request_prefs(enabled, allow_text);
    s.persist()
}

/// Send an explicit chat request ("knock") to `username`: their request gate surfaces a
/// pending-request row with no message content — the "Request to chat" button. A local
/// system chip marks it sent so the thread isn't empty on our side.
#[tauri::command]
pub async fn send_chat_request(
    state: tauri::State<'_, AppState>,
    username: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let contact = resolve_send_contact(&mut s, &client, username.trim()).await?;
    let multi = s.multi_device;
    if multi {
        // Every recipient device shows the request row, not just their primary.
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        let fan = client
            .prepare_knock_fanout(account, &mut sess.history, &contact)
            .await
            .map_err(|e| e.to_string())?;
        let mut all = fan.immediate;
        all.extend(fan.deferred);
        sess.history.outbox_push(all, now_secs());
    } else {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_knock(account, &contact)
            .await
            .map_err(|e| e.to_string())?;
    }
    let verified = s.history.contact_verified(&contact.username);
    s.history
        .pin_contact(&contact.username, &contact.identity_key, verified);
    s.history
        .record_system(&contact.identity_key, "You sent a chat request", now_secs());
    s.persist()?;
    drop(s);
    if multi {
        spawn_outbox_drain(state.inner.clone(), client, 0);
    }
    Ok(())
}
