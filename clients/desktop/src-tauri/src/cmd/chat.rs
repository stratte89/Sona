use crate::*;

/// The chat list: one row per pinned contact (address book), newest activity first.
#[tauri::command]
pub async fn conversations(state: tauri::State<'_, AppState>) -> Result<Vec<ConvView>, String> {
    let mut s = state.inner.lock().await;
    // Reap first so an expired message can never surface as a chat-list preview (the
    // periodic reaper may not have ticked yet right after unlock).
    if s.account.is_some() && s.history.reap(now_secs()) > 0 {
        s.persist()?;
    }
    let s = &*s;
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    let my_primary = s.history.self_primary_key().map(str::to_string);
    let group_mine = |sender: Option<&str>| {
        sender == Some(my_key.as_str()) || (sender.is_some() && sender == my_primary.as_deref())
    };
    let mut out: Vec<ConvView> = s
        .history
        .contacts()
        .into_iter()
        // Pending message requests live in the requests list, never in the chat list.
        .filter(|(_, pin)| pin.request.is_none())
        .map(|(username, pin)| {
            let peer = pin.identity_key;
            let last = s.history.last_message(&peer);
            ConvView {
                kind: "chat",
                username,
                last_body: last.map(|m| m.body.clone()).unwrap_or_default(),
                last_ts: last.map(|m| m.sent_at).unwrap_or(0),
                last_outgoing: matches!(last.map(|m| m.direction), Some(Direction::Outgoing)),
                verified: pin.verified,
                timer_secs: s.history.timer(&peer),
                has_messages: last.is_some(),
                unread: s.history.unread_count(&peer),
                last_attachment: last.is_some_and(|m| m.attachment.is_some()),
                last_voice: last.is_some_and(|m| m.attachment.as_ref().is_some_and(|a| a.voice)),
                pinned: pin.pinned,
                muted_until: pin.muted_until,
                nickname: pin.nickname,
                blocked: pin.blocked,
                avatar: pin.avatar,
                members: 0,
                archived: pin.archived,
                manual_unread: pin.unread,
                note: false,
                peer,
            }
        })
        .collect();
    for (group_id, g) in s.history.groups() {
        let last = g.messages.last();
        out.push(ConvView {
            kind: "group",
            peer: group_id.clone(),
            username: g.name.clone(),
            last_body: last.map(|m| m.body.clone()).unwrap_or_default(),
            last_ts: last.map(|m| m.sent_at).unwrap_or(0),
            last_outgoing: last.is_some_and(|m| group_mine(m.sender.as_deref())),
            verified: false,
            timer_secs: g.disappearing_secs,
            has_messages: last.is_some(),
            unread: s.history.group_unread(&group_id),
            last_attachment: last.is_some_and(|m| m.attachment.is_some()),
            last_voice: last.is_some_and(|m| m.attachment.as_ref().is_some_and(|a| a.voice)),
            pinned: g.pinned,
            muted_until: g.muted_until,
            nickname: None,
            blocked: false,
            avatar: g.avatar.clone(),
            members: g.members.len(),
            archived: g.archived,
            manual_unread: g.unread,
            note: false,
        });
    }
    // Note-to-self: a synthetic row (there is no ContactPin for it). Shown once it has
    // content; the UI can also open it any time from the "+" menu.
    {
        use client_core::NOTE_TO_SELF_PEER;
        let last = s.history.last_message(NOTE_TO_SELF_PEER);
        if last.is_some() {
            out.push(ConvView {
                kind: "chat",
                peer: NOTE_TO_SELF_PEER.to_string(),
                username: NOTE_TO_SELF_PEER.to_string(),
                last_body: last.map(|m| m.body.clone()).unwrap_or_default(),
                last_ts: last.map(|m| m.sent_at).unwrap_or(0),
                last_outgoing: true,
                verified: false,
                timer_secs: None,
                has_messages: true,
                unread: 0,
                last_attachment: last.is_some_and(|m| m.attachment.is_some()),
                last_voice: last.is_some_and(|m| m.attachment.as_ref().is_some_and(|a| a.voice)),
                pinned: false,
                muted_until: None,
                nickname: Some("Note to self".to_string()),
                blocked: false,
                avatar: None,
                members: 0,
                archived: false,
                manual_unread: false,
                note: true,
            });
        }
    }
    // Pinned chats float; everything else by recency.
    out.sort_by(|a, b| b.pinned.cmp(&a.pinned).then(b.last_ts.cmp(&a.last_ts)));
    Ok(out)
}

/// `limit` = window size (newest N; `None` = everything). The window auto-extends to
/// the first unread message and to `anchor` (a msg_id the UI must be able to scroll
/// to), so the divider and jump-to-quote/pin always work.
#[tauri::command]
pub async fn thread(
    state: tauri::State<'_, AppState>,
    peer: String,
    limit: Option<usize>,
    anchor: Option<String>,
) -> Result<ThreadView, String> {
    let mut s = state.inner.lock().await;
    // Reap first: an expired message must never render, even if the periodic reaper
    // hasn't ticked yet (e.g. the first paint right after unlock).
    if s.account.is_some() && s.history.reap(now_secs()) > 0 {
        s.persist()?;
    }
    // 1:1: every non-local reactor is the peer — resolve to their username.
    let peer_name = s
        .history
        .username_for_peer(&peer)
        .unwrap_or_else(|| "Them".to_string());
    let all = s.history.messages(&peer);
    let total = all.len();
    let unread = |m: &StoredMessage| {
        matches!(m.direction, Direction::Incoming) && !m.seen_receipted && !m.system
    };
    let start = window_start(
        total,
        limit,
        all.iter().position(unread),
        anchor
            .as_ref()
            .and_then(|a| all.iter().position(|m| &m.msg_id == a)),
    );
    let mut messages: Vec<MsgView> = all[start..].iter().map(Into::into).collect();
    for m in &mut messages {
        resolve_reactors(&mut m.reactions, |_| peer_name.clone());
    }
    let mut pinned: Vec<MsgView> = all
        .iter()
        .filter(|m| m.pinned && !m.system)
        .map(Into::into)
        .collect();
    // Note-to-self: there is no recipient — you always "received and read" your own
    // note, so every message renders with the seen double-tick instead of a lying
    // single "sent".
    if peer == client_core::NOTE_TO_SELF_PEER {
        for m in messages.iter_mut().chain(pinned.iter_mut()) {
            if m.direction == "outgoing" {
                m.status = "seen";
            }
        }
    }
    Ok(ThreadView {
        messages,
        timer_secs: s.history.timer(&peer),
        total,
        more: start > 0,
        pinned,
    })
}

/// Resolve a contact by username, KT-verified and key-change-aware. On first contact or an
/// unchanged key a session is started and the contact pinned; on a key change nothing is
/// started and the UI is told to warn.
#[tauri::command]
pub async fn open_chat(
    state: tauri::State<'_, AppState>,
    username: String,
) -> Result<OpenChatView, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("enter a username".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let known = s.history.pinned_contact_key(&username).map(str::to_string);
    let account = s.account.as_mut().ok_or("locked")?;
    ensure_not_self(account, &username, known.as_deref())?;
    let my_key = account.ratchet_ref().identity_key();
    let outcome = client
        .add_contact_checked(account, &username, known.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    if let ContactOutcome::New(c) | ContactOutcome::Unchanged(c) = &outcome {
        if c.identity_key == my_key {
            return Err("that's your own account — you can't message yourself".into());
        }
    }
    let view = match outcome {
        ContactOutcome::New(c) => {
            s.history.pin_contact(&c.username, &c.identity_key, false);
            OpenChatView {
                status: "new",
                peer: c.identity_key,
                username: c.username,
                safety_number: c.safety_number,
                verified: false,
                previous_key: None,
            }
        }
        ContactOutcome::Unchanged(c) => {
            let verified = s.history.contact_verified(&c.username);
            OpenChatView {
                status: "unchanged",
                peer: c.identity_key,
                username: c.username,
                safety_number: c.safety_number,
                verified,
                previous_key: None,
            }
        }
        ContactOutcome::KeyChanged {
            username,
            previous_identity_key,
            new_identity_key,
            new_safety_number,
        } => OpenChatView {
            status: "key_changed",
            peer: new_identity_key,
            username,
            safety_number: new_safety_number,
            verified: false,
            previous_key: Some(previous_identity_key),
        },
    };
    s.persist()?;
    Ok(view)
}

/// Accept a contact's changed key: re-pin it (unverified) and establish the session. Only
/// call after the user has compared the new safety number out-of-band.
#[tauri::command]
pub async fn accept_key_change(
    state: tauri::State<'_, AppState>,
    username: String,
) -> Result<OpenChatView, String> {
    let username = username.trim().to_string();
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let account = s.account.as_mut().ok_or("locked")?;
    let c = client
        .add_contact(account, &username)
        .await
        .map_err(|e| e.to_string())?;
    s.history.pin_contact(&c.username, &c.identity_key, false);
    s.history.record_system(
        &c.identity_key,
        &format!("{}'s security code changed", c.username),
        now_secs(),
    );
    let view = OpenChatView {
        status: "unchanged",
        peer: c.identity_key,
        username: c.username,
        safety_number: c.safety_number,
        verified: false,
        previous_key: None,
    };
    s.persist()?;
    Ok(view)
}

/// Mark a contact verified (the user compared safety numbers out-of-band).
#[tauri::command]
pub async fn mark_verified(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.history.pin_contact(username.trim(), peer.trim(), true);
    s.history.record_system(
        peer.trim(),
        &format!("You verified {}", username.trim()),
        now_secs(),
    );
    s.persist()
}

/// Send a text message to a contact. Re-resolves the contact by username + KT on every
/// send (so a rotated/forged key is caught before sending), records the sent message in
/// local history, and re-seals. A key change aborts the send and asks the UI to warn.
#[tauri::command]
pub async fn send(
    state: tauri::State<'_, AppState>,
    username: String,
    text: String,
    reply_to: Option<String>,
) -> Result<MsgView, String> {
    send_inner(&state.inner, username, text, reply_to).await
}

/// The send itself, callable without a Tauri `State` — the inline-reply notification
/// action (`notif_action`) sends through the exact same path as the UI.
pub(crate) async fn send_inner(
    inner: &Arc<Mutex<Session>>,
    username: String,
    text: String,
    reply_to: Option<String>,
) -> Result<MsgView, String> {
    let username = username.trim().to_string();
    if text.trim().is_empty() {
        return Err("empty message".into());
    }
    let mut s = inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    if s.history
        .contacts()
        .iter()
        .any(|(u, p)| u == &username && p.blocked)
    {
        return Err("contact is blocked — unblock them in chat settings first".into());
    }
    // Fast path inside: a live ratchet session skips the network; otherwise a full
    // KT-verified discovery runs. Also rejects sending to ourselves.
    let contact: Contact = resolve_send_contact(&mut s, &client, &username).await?;
    // Quoting? Build the reply ref (id + short snippet) from our own copy.
    let reply = reply_to.as_deref().and_then(|id| {
        s.history.message(&contact.identity_key, id).map(|m| {
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
    let peer = contact.identity_key.clone();
    let contact_username = contact.username.clone();

    // Multi-device: fan the message out to every recipient device AND our own other
    // devices (self-sync, jittered). Single-device (or an old relay): the 1:1 path.
    let (msg_id, sent_at) = if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        let fan = client
            .prepare_text_fanout(
                account,
                &mut sess.history,
                &contact,
                &text,
                reply.clone(),
                false,
            )
            .await
            .map_err(|e| e.to_string())?;
        // Own-device self-sync copies go through the DURABLE outbox with their privacy
        // jitter (so the relay can't correlate the burst back to who is talking to
        // whom). Persisted before anything hits the network: an app close/kill between
        // send and jitter no longer silently desyncs the other devices' history.
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
        // Recipient copies go now.
        client
            .post_envelopes(&fan.immediate)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(j) = jitter {
            spawn_outbox_drain(inner.clone(), client.clone(), j + 1);
        }
        (fan.msg_id, fan.sent_at)
    } else {
        // Carry the timer inside the message (Some(0) = off) — anti-race, see core docs.
        let expire = Some(s.history.timer(&peer).unwrap_or(0));
        let account = s.account.as_mut().ok_or("locked")?;
        let prepared = client
            .prepare_message_replying(account, &contact, &text, reply.clone(), expire, false)
            .map_err(|e| e.to_string())?;
        s.persist()?;
        drop(s);
        client
            .post_envelope(&prepared.envelope)
            .await
            .map_err(|e| e.to_string())?;
        (prepared.msg_id, prepared.sent_at)
    };

    // Delivered to the relay: record it in history. Sending to a pending requester is
    // consent — their request clears and the chat surfaces on every device (the
    // self-sync copy applies the same rule on our other devices).
    let mut s = inner.lock().await;
    s.history.accept_request(&contact_username);
    let verified = s.history.contact_verified(&contact_username);
    s.history.pin_contact(&contact_username, &peer, verified);
    s.history.record_full(
        &peer,
        Direction::Outgoing,
        &msg_id,
        &text,
        sent_at,
        reply.clone(),
        None,
    );
    // The recorded copy carries the authoritative delete_at (derived from the timer).
    let delete_at = s.history.message(&peer, &msg_id).and_then(|m| m.delete_at);
    let view = MsgView {
        msg_id,
        direction: "outgoing",
        body: text,
        sent_at,
        delete_at,
        attachment: false,
        voice: false,
        duration_secs: 0,
        status: "sent",
        edited: false,
        reply_to_id: reply.as_ref().map(|r| r.msg_id.clone()),
        reply_preview: reply.map(|r| r.preview),
        reactions: Vec::new(),
        caption: None,
        peaks: Vec::new(),
        system: false,
        unread: false,
        pinned: false,
        forwarded: false,
    };
    s.persist()?;
    drop(s);
    // A session with them provably exists now — make sure they have our profile picture
    // (covers the contact we added and messaged first, and the accepted requester).
    cmd::contacts::spawn_profile_reconcile(inner.clone(), contact_username);
    Ok(view)
}

/// Mark the peer's messages in a conversation as seen: send a "seen" receipt over the
/// existing session so the sender's UI shows the read state. Called when the user opens a
/// thread. Covers only messages not already receipted (each receipt goes out exactly
/// once), and the network POST happens with the session lock released.
#[tauri::command]
pub async fn mark_seen(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
) -> Result<(), String> {
    mark_seen_inner(&state.inner, username, peer).await
}

/// The receipt logic itself, callable without a Tauri `State` — the mark-read
/// notification action (`notif_action`) goes through the exact same path as the UI.
pub(crate) async fn mark_seen_inner(
    inner: &Arc<Mutex<Session>>,
    username: String,
    peer: String,
) -> Result<(), String> {
    let (client, envelopes) = {
        let mut s = inner.lock().await;
        let client = s.client.clone().ok_or("not configured")?;
        let ids = s.history.unseen_incoming_ids(peer.trim());
        if ids.is_empty() {
            return Ok(());
        }
        // Privacy: read receipts off ⇒ send NOTHING over the wire (no send-then-hide). Still
        // clear the *local* unread state so this device's own badge updates.
        if !s.prefs.send_receipts {
            s.history.mark_seen_receipted(peer.trim(), &ids);
            return s.persist();
        }
        let contact = contact_for(username.trim(), peer.trim());
        // Multi-device: fan the read receipt out to the contact's devices AND self-sync it
        // to our own devices so every device clears the unread badge. Single-device: one
        // receipt over the existing session.
        let envelopes = if s.multi_device {
            let sess = &mut *s;
            let account = sess.account.as_mut().ok_or("locked")?;
            match client
                .prepare_receipt_fanout(account, &mut sess.history, &contact, ids.clone())
                .await
                .map_err(|e| e.to_string())?
            {
                Some(fan) => {
                    let mut all = fan.immediate;
                    all.extend(fan.deferred);
                    all
                }
                None => Vec::new(),
            }
        } else {
            let account = s.account.as_mut().ok_or("locked")?;
            client
                .prepare_receipt(account, &contact, ids.clone(), true)
                .map_err(|e| e.to_string())?
                .into_iter()
                .collect()
        };
        // The ratchet advanced while encrypting — persist before hitting the network.
        s.history.mark_seen_receipted(peer.trim(), &ids);
        s.persist()?;
        (client, envelopes)
    };
    client
        .post_envelopes(&envelopes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Toggle an emoji reaction on a 1:1 message: update our own copy and send the E2E
/// reaction so the peer's copy updates too. `add` sets it, `!add` removes it.
#[tauri::command]
pub async fn react(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
    msg_id: String,
    emoji: String,
    add: bool,
) -> Result<(), String> {
    let emoji = emoji.trim().to_string();
    if emoji.is_empty() || emoji.chars().count() > 8 {
        return Err("bad emoji".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    if !s.history.react(peer.trim(), msg_id.trim(), "", &emoji, add) {
        return Err("no such message".into());
    }
    // Note-to-self: reactions are local bookmarks — nothing to send anywhere.
    if peer.trim() == client_core::NOTE_TO_SELF_PEER {
        return s.persist();
    }
    let contact = contact_for(username.trim(), peer.trim());
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        let fan = client
            .prepare_reaction_fanout(
                account,
                &mut sess.history,
                &contact,
                msg_id.trim().to_string(),
                emoji.clone(),
                add,
            )
            .await
            .map_err(|e| e.to_string())?;
        // Self-sync copies ride the durable outbox (due immediately — reactions carry
        // no burst-correlation jitter) so other devices converge even if we die here.
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
            .send_reaction(account, &contact, msg_id.trim(), &emoji, add)
            .await
            .map_err(|e| e.to_string())?;
        s.persist()?;
    }
    Ok(())
}

/// Toggle an emoji reaction on a group message (pairwise fan-out to each other member).
#[tauri::command]
pub async fn react_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
    msg_id: String,
    emoji: String,
    add: bool,
) -> Result<(), String> {
    let emoji = emoji.trim().to_string();
    if emoji.is_empty() || emoji.chars().count() > 8 {
        return Err("bad emoji".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    {
        let g = s.history.group(&group_id).ok_or("no such group")?;
        crate::cmd::groups::ensure_in_group(g)?;
    }
    s.history
        .react_group(&group_id, msg_id.trim(), "", &emoji, add);
    let g = s.history.group(&group_id).ok_or("no such group")?;
    let group = group_from_record(&group_id, g);
    let account = s.account.as_mut().ok_or("locked")?;
    client
        .send_group_reaction(account, &group, msg_id.trim(), &emoji, add)
        .await
        .map_err(|e| e.to_string())?;
    s.persist()
}

/// Send an ephemeral typing signal to a 1:1 peer (or an explicit stop). Best-effort and
/// gated by the "send typing indicators" privacy setting — off ⇒ nothing goes out.
#[tauri::command]
pub async fn set_typing(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
    typing: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.prefs.send_typing {
        return Ok(());
    }
    let client = s.client.clone().ok_or("not configured")?;
    // Only signal to a peer we already have live sessions with — never burn a one-time
    // key or run KT discovery just to say "typing". Multi-device: seal one copy per
    // recipient DEVICE with an existing session (the pinned roster), otherwise a linked
    // device (e.g. the peer's desktop) never sees the indicator.
    let contact = contact_for(username.trim(), peer.trim());
    let sess = &mut *s;
    let Some(account) = sess.account.as_mut() else {
        return Ok(());
    };
    let envelopes = client
        .prepare_typing_fanout(account, &sess.history, &contact, typing)
        .unwrap_or_default();
    if envelopes.is_empty() {
        return Ok(());
    }
    // Typing frames advance the ratchet; persist before hitting the network.
    s.persist()?;
    drop(s);
    let _ = client.post_envelopes(&envelopes).await;
    Ok(())
}

/// Ephemeral group typing signal (or stop), gated by the same privacy setting.
#[tauri::command]
pub async fn set_group_typing(
    state: tauri::State<'_, AppState>,
    group_id: String,
    typing: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.prefs.send_typing {
        return Ok(());
    }
    let client = s.client.clone().ok_or("not configured")?;
    let Some(g) = s.history.group(&group_id) else {
        return Ok(());
    };
    let group = group_from_record(&group_id, g);
    let sess = &mut *s;
    let Some(account) = sess.account.as_mut() else {
        return Ok(());
    };
    // Session-gated device fan-out per member (like 1:1 typing): every device of every
    // member we already have a session with sees the indicator; nobody costs network.
    let envelopes = client
        .prepare_group_typing_fanout(account, &sess.history, &group, typing)
        .unwrap_or_default();
    if envelopes.is_empty() {
        return Ok(());
    }
    s.persist()?;
    drop(s);
    let _ = client.post_envelopes(&envelopes).await;
    Ok(())
}

/// Edit one of our own sent messages (within the 5-minute window): update locally and
/// send the E2E edit so the peer's copy updates too.
#[tauri::command]
pub async fn edit_message(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
    msg_id: String,
    text: String,
) -> Result<(), String> {
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err("empty message".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    {
        let m = s
            .history
            .message(peer.trim(), msg_id.trim())
            .ok_or("no such message")?;
        if !matches!(m.direction, Direction::Outgoing) {
            return Err("not your message".into());
        }
        if now.saturating_sub(m.sent_at) > EDIT_WINDOW_SECS {
            return Err("edit window (5 min) has passed".into());
        }
    }
    // Note-to-self: no peer exists — the local edit is the whole operation.
    if peer.trim() != client_core::NOTE_TO_SELF_PEER {
        let account = s.account.as_mut().ok_or("locked")?;
        let contact = contact_for(username.trim(), peer.trim());
        client
            .send_edit(account, &contact, msg_id.trim(), &text)
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.edit_local(peer.trim(), msg_id.trim(), &text);
    s.persist()
}

/// Delete one message locally ("delete for me").
#[tauri::command]
pub async fn delete_message(
    state: tauri::State<'_, AppState>,
    peer: String,
    msg_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.history.delete_message(peer.trim(), msg_id.trim());
    s.persist()
}

/// Delete one of our own messages for everyone: E2E delete request + local removal.
#[tauri::command]
pub async fn delete_message_everyone(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
    msg_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    {
        let m = s
            .history
            .message(peer.trim(), msg_id.trim())
            .ok_or("no such message")?;
        if !matches!(m.direction, Direction::Outgoing) {
            return Err("not your message".into());
        }
    }
    if peer.trim() != client_core::NOTE_TO_SELF_PEER {
        let account = s.account.as_mut().ok_or("locked")?;
        let contact = contact_for(username.trim(), peer.trim());
        client
            .send_delete_msg(account, &contact, msg_id.trim())
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.delete_message(peer.trim(), msg_id.trim());
    s.persist()
}

/// Mute (or unmute with `None`) a group — local preference, encrypted at rest.
#[tauri::command]
pub async fn set_group_muted(
    state: tauri::State<'_, AppState>,
    group_id: String,
    until: Option<u64>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.history.set_group_muted(&group_id, until) {
        return Err("no such group".into());
    }
    s.persist()
}

/// Set (or clear, with `None`) the disappearing-messages timer for a conversation. Syncs
/// the timer to EVERY device of the peer and self-syncs it to our own other devices
/// (multi-device), applies it locally, and drops a system chip. The sealed copies ride
/// the durable outbox, so a network blip or app kill can't leave devices with different
/// timers — they retry until the relay accepts them.
#[tauri::command]
pub async fn set_disappearing(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
    secs: Option<u64>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let contact = contact_for(username.trim(), peer.trim());
    let multi = s.multi_device;
    if multi {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        let fan = client
            .prepare_timer_fanout(account, &mut sess.history, &contact, secs)
            .await
            .map_err(|e| e.to_string())?;
        // All copies due immediately: a timer flip is a rare, single control message,
        // so the self-sync burst-correlation jitter buys nothing here.
        let mut all = fan.immediate;
        all.extend(fan.deferred);
        sess.history.outbox_push(all, now_secs());
    } else {
        // Single-device: one control message over the existing session — no discovery
        // round-trip (and no one-time-key burn) just to flip a timer.
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .set_disappearing(account, &contact, secs)
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.set_timer(peer.trim(), secs);
    let label = timer_label(secs);
    s.history.record_system(peer.trim(), &label, now_secs());
    s.persist()?;
    drop(s);
    if multi {
        spawn_outbox_drain(state.inner.clone(), client, 0);
    }
    Ok(())
}

/// Set (or clear, with `None`) the disappearing-messages timer for a GROUP. Fans the
/// control message out to every device of every member (and our own other devices),
/// applies it locally, and drops a system chip in the group thread.
#[tauri::command]
pub async fn set_group_disappearing(
    state: tauri::State<'_, AppState>,
    group_id: String,
    secs: Option<u64>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?;
    crate::cmd::groups::ensure_in_group(g)?;
    let group = group_from_record(&group_id, g);
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_timer_multi(account, &mut sess.history, &group, secs)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_group_timer(account, &group, secs)
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.set_group_timer(&group_id, secs);
    let label = timer_label(secs);
    s.history.record_group_system(&group_id, &label, now_secs());
    s.persist()
}

#[tauri::command]
pub fn set_open_chat(peer: Option<String>) {
    if let Some(p) = &peer {
        // Opening a chat consumes its shade notification.
        eng().clear_chat_notif(p);
    }
    if let Ok(mut g) = eng().open_chat.lock() {
        *g = peer;
    }
}
