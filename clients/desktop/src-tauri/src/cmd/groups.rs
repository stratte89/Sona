use crate::*;

/// Create a group with the given contacts (all KT-resolved) and invite them.
/// Returns the group id.
#[tauri::command]
pub async fn create_group(
    state: tauri::State<'_, AppState>,
    name: String,
    members: Vec<String>,
) -> Result<String, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("group needs a name".into());
    }
    if members.is_empty() {
        return Err("pick at least one member".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let mut contacts = Vec::new();
    for m in &members {
        contacts.push(resolve_send_contact(&mut s, &client, m.trim()).await?);
    }
    let account = s.account.as_mut().ok_or("locked")?;
    // Create an admin-model group: `create_group` mints the genesis membership epoch (we are
    // the admin) and fans it out. We adopt it locally so our own roster is pinned to the same
    // signed epoch every member validates, then set the (egalitarian) name.
    let (group, epoch) = client
        .create_group(account, &name, &contacts)
        .await
        .map_err(|e| e.to_string())?;
    s.history.adopt_group_epoch(&epoch);
    s.history.set_group_name(&group.id, &group.name);
    // Multi-device: the pairwise fan above only reaches each member's primary — re-fan the
    // epoch to every device of every member (and our own linked devices) so no device is
    // left with a stale roster.
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_roster_multi(
                account,
                &mut sess.history,
                &group,
                &epoch,
                &name,
                Some(0),
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
    }
    s.persist()?;
    Ok(group.id)
}

/// Refuse group actions after we left / were removed (the thread stays readable, but
/// nothing may be sent or changed anymore).
pub(crate) fn ensure_in_group(g: &client_core::GroupRecord) -> Result<(), String> {
    if g.left {
        return Err("you're no longer in this group".into());
    }
    Ok(())
}

/// Add a member to an existing group and re-send the updated roster to everyone.
#[tauri::command]
pub async fn add_to_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
    username: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?.clone();
    ensure_in_group(&g)?;
    let contact = resolve_send_contact(&mut s, &client, username.trim()).await?;
    let mut members = g.members.clone();
    if members
        .iter()
        .any(|m| m.identity_key == contact.identity_key)
    {
        return Err("already a member".into());
    }
    members.push(GroupMember {
        username: contact.username.clone(),
        identity_key: contact.identity_key.clone(),
    });
    // The roster carries the group's current timer + picture so the newcomer adopts both.
    let timer = g.disappearing_secs;
    let avatar = g.avatar.clone();
    // Adding a member is admin-only: mint a signed successor epoch and fan it (as a
    // GroupRoster) to every member including the newcomer, then adopt it locally.
    let admin = g.admin.as_ref().ok_or("group has no admin")?;
    require_admin(&s, admin)?;
    let account = s.account.as_mut().ok_or("locked")?;
    let epoch = client
        .group_membership_epoch(account, admin, &group_id, &members)
        .map_err(|e| e.to_string())?;
    client
        .send_group_roster(account, &members, &epoch, &g.name, timer, avatar.clone())
        .await
        .map_err(|e| e.to_string())?;
    s.history.adopt_group_epoch(&epoch);
    // Multi-device: re-fan the epoch to every device of every member (the pairwise fan
    // above only reaches primaries); duplicate copies are refused as a seq rollback.
    if s.multi_device {
        let group = Group {
            id: group_id.clone(),
            name: g.name.clone(),
            members: members.clone(),
        };
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_roster_multi(
                account,
                &mut sess.history,
                &group,
                &epoch,
                &g.name,
                timer,
                avatar,
            )
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.record_group_system(
        &group_id,
        &format!("You added {}", contact.username),
        now_secs(),
    );
    s.persist()
}

/// Gate an admin-only action: THIS device must be the group's current admin. Compares the
/// pinned `admin_identity_key` against our account identity key (and our multi-device
/// primary key). Admin actions are primary-device-only — the admin key is the KT-bound
/// account signing key, held by the primary (mirrors username-rename being primary-only).
pub(crate) fn require_admin(s: &Session, admin: &client_core::GroupAdmin) -> Result<(), String> {
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    let is_admin = admin.admin_identity_key == my_key
        || s.history.self_primary_key() == Some(admin.admin_identity_key.as_str());
    if !is_admin {
        return Err("only the group admin can do that".into());
    }
    Ok(())
}

/// Set (or clear with `None`) a group's picture, then fan the change out to every member.
/// Stored locally first so it sticks even if the network send fails; recipients bound +
/// format-check the value. Any member may set it (same trust model as the name/roster).
#[tauri::command]
pub async fn set_group_avatar(
    state: tauri::State<'_, AppState>,
    group_id: String,
    avatar: Option<String>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    {
        let g = s.history.group(&group_id).ok_or("no such group")?;
        ensure_in_group(g)?;
    }
    if !s.history.set_group_avatar(&group_id, avatar) {
        return Err("no such group".into());
    }
    // Re-read the sanitized value + roster to broadcast exactly what we stored.
    let g = s.history.group(&group_id).ok_or("no such group")?.clone();
    let group = group_from_record(&group_id, &g);
    let stored = g.avatar.clone();
    let account = s.account.as_mut().ok_or("locked")?;
    let sent = client.send_group_avatar(account, &group, stored).await;
    s.persist()?;
    sent.map_err(|e| e.to_string())
}

/// A group's thread: roster display names + messages, oldest first. `limit`/`anchor`
/// window the messages exactly like the 1:1 `thread` command (newest N, extended to
/// the first unread and the anchor); pins are returned window-independently.
#[tauri::command]
pub async fn group_thread(
    state: tauri::State<'_, AppState>,
    group_id: String,
    limit: Option<usize>,
    anchor: Option<String>,
) -> Result<GroupThreadView, String> {
    let mut s = state.inner.lock().await;
    // Reap first — an expired group message must never render (same rule as `thread`).
    if s.account.is_some() && s.history.reap(now_secs()) > 0 {
        s.persist()?;
    }
    let s = &*s;
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    // A group message is "ours" if its sender is this device's key OR our account's primary
    // key (a message we sent from another of our own devices, attributed to the primary).
    let my_primary = s.history.self_primary_key().map(str::to_string);
    let is_mine = |sender: &str| sender == my_key || my_primary.as_deref() == Some(sender);
    let g = s.history.group(&group_id).ok_or("no such group")?;
    let name_of = |key: &str| -> String {
        g.members
            .iter()
            .find(|m| m.identity_key == key)
            .map(|m| m.username.clone())
            .unwrap_or_else(|| format!("{}…", &key[..key.len().min(8)]))
    };
    let to_view = |m: &StoredMessage| {
        let sender = m.sender.clone().unwrap_or_default();
        let mut reactions = group_reactions(&m.reactions);
        resolve_reactors(&mut reactions, &name_of);
        let mine = is_mine(&sender);
        GroupMsgView {
            msg_id: m.msg_id.clone(),
            body: m.body.clone(),
            sent_at: m.sent_at,
            delete_at: m.delete_at,
            sender_name: name_of(&sender),
            mine,
            reactions,
            system: m.system,
            attachment: m.attachment.is_some(),
            voice: m.attachment.as_ref().is_some_and(|a| a.voice),
            duration_secs: m.attachment.as_ref().map(|a| a.duration_secs).unwrap_or(0),
            caption: m.attachment.as_ref().and_then(|a| a.caption.clone()),
            peaks: m
                .attachment
                .as_ref()
                .map(|a| a.peaks.clone())
                .unwrap_or_default(),
            edited: m.edited,
            reply_to_id: m.reply.as_ref().map(|r| r.msg_id.clone()),
            reply_preview: m.reply.as_ref().map(|r| r.preview.clone()),
            unread: !mine && !m.seen_receipted && !m.system,
            pinned: m.pinned,
            forwarded: m.forwarded,
        }
    };
    let total = g.messages.len();
    let start = window_start(
        total,
        limit,
        g.messages.iter().position(|m| {
            !is_mine(m.sender.as_deref().unwrap_or_default()) && !m.seen_receipted && !m.system
        }),
        anchor
            .as_ref()
            .and_then(|a| g.messages.iter().position(|m| &m.msg_id == a)),
    );
    // Admin-model groups: resolve the admin's display name and whether THIS device is it.
    let admin = g.admin.as_ref().and_then(|a| {
        g.members
            .iter()
            .find(|m| m.identity_key == a.admin_identity_key)
            .map(|m| m.username.clone())
    });
    let is_admin = g.admin.as_ref().is_some_and(|a| {
        a.admin_identity_key == my_key
            || my_primary.as_deref() == Some(a.admin_identity_key.as_str())
    });
    Ok(GroupThreadView {
        name: g.name.clone(),
        members: g.members.iter().map(|m| m.username.clone()).collect(),
        messages: g.messages[start..].iter().map(to_view).collect(),
        timer_secs: g.disappearing_secs,
        avatar: g.avatar.clone(),
        left: g.left,
        admin,
        is_admin,
        total,
        more: start > 0,
        pinned: g
            .messages
            .iter()
            .filter(|m| m.pinned && !m.system)
            .map(to_view)
            .collect(),
    })
}

/// Send a message to a group (pairwise fan-out over existing sessions). `reply_to`
/// quotes an earlier message in the same thread.
#[tauri::command]
pub async fn send_group_msg(
    state: tauri::State<'_, AppState>,
    group_id: String,
    text: String,
    reply_to: Option<String>,
) -> Result<(), String> {
    send_group_inner(&state.inner, group_id, text, reply_to).await
}

/// The group send itself, callable without a Tauri `State` — the inline-reply
/// notification action (`notif_action`) sends through the exact same path as the UI.
pub(crate) async fn send_group_inner(
    inner: &Arc<Mutex<Session>>,
    group_id: String,
    text: String,
    reply_to: Option<String>,
) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("empty message".into());
    }
    let mut s = inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?;
    ensure_in_group(g)?;
    let group = group_from_record(&group_id, g);
    // Quoting? Build the reply ref (id + short snippet) from our stored copy.
    let reply = reply_to.as_deref().and_then(|id| {
        s.history.group_message(&group_id, id).map(|m| {
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
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    // File our own copy under the account PRIMARY key so it renders as ours on every one of
    // our devices (attribution maps device→primary). Single-device: primary == my_key.
    let sender_key = s
        .history
        .self_primary_key()
        .map(str::to_string)
        .unwrap_or_else(|| my_key.clone());

    // Multi-device: fan the group message out to every member's devices AND our own other
    // devices, sharing one id so copies dedup. Single-device relay: the pairwise path.
    // Record the local copy with the SAME `sent_at` the wire copies carry, so the
    // disappearing deadline is identical on every member's device.
    let (msg_id, sent_at) = if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_multi(
                account,
                &mut sess.history,
                &group,
                &text,
                reply.clone(),
                false,
            )
            .await
            .map_err(|e| e.to_string())?
    } else {
        let expire = Some(s.history.group_timer(&group_id).unwrap_or(0));
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_group_timed(account, &group, &text, expire, reply.clone(), false)
            .await
            .map_err(|e| e.to_string())?;
        (
            format!(
                "g{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ),
            now_secs(),
        )
    };
    s.history
        .record_group_message(&group_id, &sender_key, &msg_id, &text, sent_at, None, reply);
    s.history.mark_group_seen(&group_id);
    s.persist()
}

/// Edit one of our own group messages (5-minute window): update locally and fan the E2E
/// edit to every member (and our own other devices) so every copy updates.
#[tauri::command]
pub async fn edit_group_message(
    state: tauri::State<'_, AppState>,
    group_id: String,
    msg_id: String,
    text: String,
) -> Result<(), String> {
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err("empty message".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?;
    ensure_in_group(g)?;
    let group = group_from_record(&group_id, g);
    ensure_own_group_msg(&s, &group_id, msg_id.trim())?;
    {
        let m = s
            .history
            .group_message(&group_id, msg_id.trim())
            .ok_or("no such message")?;
        if now_secs().saturating_sub(m.sent_at) > EDIT_WINDOW_SECS {
            return Err("edit window (5 min) has passed".into());
        }
    }
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_edit_multi(account, &mut sess.history, &group, msg_id.trim(), &text)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_group_edit(account, &group, msg_id.trim(), &text)
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.edit_group_local(&group_id, msg_id.trim(), &text);
    s.persist()
}

/// Delete one group message locally ("delete for me" — any sender's message).
#[tauri::command]
pub async fn delete_group_message(
    state: tauri::State<'_, AppState>,
    group_id: String,
    msg_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.history.delete_group_message(&group_id, msg_id.trim());
    s.persist()
}

/// Delete one of our own group messages for everyone: E2E delete fan-out + local removal.
#[tauri::command]
pub async fn delete_group_message_everyone(
    state: tauri::State<'_, AppState>,
    group_id: String,
    msg_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?;
    ensure_in_group(g)?;
    let group = group_from_record(&group_id, g);
    ensure_own_group_msg(&s, &group_id, msg_id.trim())?;
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_delete_msg_multi(account, &mut sess.history, &group, msg_id.trim())
            .await
            .map_err(|e| e.to_string())?;
    } else {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_group_delete_msg(account, &group, msg_id.trim())
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.delete_group_message(&group_id, msg_id.trim());
    s.persist()
}

/// The stored message must be OURS (sent from this device or attributed to our account's
/// primary) — the ownership gate for group edit / delete-for-everyone.
fn ensure_own_group_msg(s: &Session, group_id: &str, msg_id: &str) -> Result<(), String> {
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    let my_primary = s.history.self_primary_key().map(str::to_string);
    let m = s
        .history
        .group_message(group_id, msg_id)
        .ok_or("no such message")?;
    let mine = m.sender.as_deref() == Some(my_key.as_str())
        || (m.sender.is_some() && m.sender.as_deref() == my_primary.as_deref());
    if !mine {
        return Err("not your message".into());
    }
    Ok(())
}

/// Rename a group for everyone (any member may — same trust model as the roster).
#[tauri::command]
pub async fn rename_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
    name: String,
) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("group needs a name".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?;
    ensure_in_group(g)?;
    let group = group_from_record(&group_id, g);
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_rename_multi(account, &mut sess.history, &group, &name)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_group_rename(account, &group, &name)
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.rename_group(&group_id, &name);
    s.history.record_group_system(
        &group_id,
        &format!("You renamed the group to \"{name}\""),
        now_secs(),
    );
    s.persist()
}

/// Remove a member from a group for everyone. The removal is fanned out over the FULL
/// roster (including the removed member, whose client marks the group left), then the
/// member is dropped locally.
#[tauri::command]
pub async fn remove_group_member(
    state: tauri::State<'_, AppState>,
    group_id: String,
    username: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?.clone();
    ensure_in_group(&g)?;
    let member = g
        .members
        .iter()
        .find(|m| m.username == username.trim())
        .cloned()
        .ok_or("not a member of this group")?;
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    if member.identity_key == my_key
        || s.history.self_primary_key() == Some(member.identity_key.as_str())
    {
        return Err("use Leave group to remove yourself".into());
    }
    // Removing a member is admin-only: mint a signed successor epoch WITHOUT the member and
    // fan it to the full old roster (so the kicked member learns too), then adopt locally —
    // which drops the member from our own view.
    let admin = g.admin.as_ref().ok_or("group has no admin")?;
    require_admin(&s, admin)?;
    let new_members: Vec<GroupMember> = g
        .members
        .iter()
        .filter(|m| m.identity_key != member.identity_key)
        .cloned()
        .collect();
    let account = s.account.as_mut().ok_or("locked")?;
    let epoch = client
        .group_membership_epoch(account, admin, &group_id, &new_members)
        .map_err(|e| e.to_string())?;
    client
        .send_group_roster(
            account,
            &g.members, // full roster incl. the kicked member
            &epoch,
            &g.name,
            g.disappearing_secs,
            g.avatar.clone(),
        )
        .await
        .map_err(|e| e.to_string())?;
    s.history.adopt_group_epoch(&epoch);
    // Multi-device: re-fan over the FULL old roster so the kicked member's linked
    // devices (and everyone else's) also see the epoch; primaries dedup by refusal.
    if s.multi_device {
        let group = group_from_record(&group_id, &g);
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_roster_multi(
                account,
                &mut sess.history,
                &group,
                &epoch,
                &g.name,
                g.disappearing_secs,
                g.avatar.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.record_group_system(
        &group_id,
        &format!("You removed {}", member.username),
        now_secs(),
    );
    s.persist()
}

/// Transfer the admin role of an admin-model group to a current member (admin-only). Mints
/// an admin-transfer epoch (signed by us, the outgoing admin; the new admin's account key is
/// KT-verified) and fans it to every member. After this, only the new admin can change
/// membership.
#[tauri::command]
pub async fn transfer_group_admin(
    state: tauri::State<'_, AppState>,
    group_id: String,
    username: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?.clone();
    ensure_in_group(&g)?;
    let admin = g
        .admin
        .clone()
        .ok_or("this is a legacy group without an admin")?;
    require_admin(&s, &admin)?;
    let new_admin = g
        .members
        .iter()
        .find(|m| m.username == username.trim())
        .cloned()
        .ok_or("not a member of this group")?;
    let account = s.account.as_mut().ok_or("locked")?;
    let epoch = client
        .group_transfer_epoch(account, &admin, &group_id, &g.members, &new_admin)
        .await
        .map_err(|e| e.to_string())?;
    client
        .send_group_roster(
            account,
            &g.members,
            &epoch,
            &g.name,
            g.disappearing_secs,
            g.avatar.clone(),
        )
        .await
        .map_err(|e| e.to_string())?;
    s.history.adopt_group_epoch(&epoch);
    // Multi-device: re-fan so every member's linked devices pin the new admin too.
    if s.multi_device {
        let group = group_from_record(&group_id, &g);
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_roster_multi(
                account,
                &mut sess.history,
                &group,
                &epoch,
                &g.name,
                g.disappearing_secs,
                g.avatar.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;
    }
    s.history.record_group_system(
        &group_id,
        &format!("You made {} the admin", new_admin.username),
        now_secs(),
    );
    s.persist()
}

/// Leave a group: tell every member (their clients drop us from the roster), then delete
/// the group locally. The wire notice is best-effort per member — leaving always succeeds
/// locally even if some sends fail.
#[tauri::command]
pub async fn leave_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let g = s.history.group(&group_id).ok_or("no such group")?;
    if !g.left {
        let group = group_from_record(&group_id, g);
        if s.multi_device {
            let sess = &mut *s;
            if let Some(account) = sess.account.as_mut() {
                let _ = client
                    .send_group_leave_multi(account, &mut sess.history, &group)
                    .await;
            }
        } else if let Some(account) = s.account.as_mut() {
            let _ = client.send_group_leave(account, &group).await;
        }
    }
    s.history.delete_group(&group_id);
    s.persist()
}

/// Pin/unpin a group in the chat list (local-only).
#[tauri::command]
pub async fn set_group_pinned(
    state: tauri::State<'_, AppState>,
    group_id: String,
    pinned: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.history.set_group_pinned(&group_id, pinned) {
        return Err("no such group".into());
    }
    s.persist()
}

/// Archive/unarchive a group (local-only).
#[tauri::command]
pub async fn set_group_archived(
    state: tauri::State<'_, AppState>,
    group_id: String,
    archived: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.history.set_group_archived(&group_id, archived) {
        return Err("no such group".into());
    }
    s.persist()
}

/// Manually mark a group unread (or clear it) — local-only, like the 1:1 flag.
#[tauri::command]
pub async fn set_group_unread(
    state: tauri::State<'_, AppState>,
    group_id: String,
    unread: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if !s.history.set_group_manual_unread(&group_id, unread) {
        return Err("no such group".into());
    }
    s.persist()
}

/// Clear a group's manual-unread and archived flags when it's opened (1:1 parity).
#[tauri::command]
pub async fn clear_group_unread_on_open(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let a = s.history.set_group_manual_unread(&group_id, false);
    let b = s.history.set_group_archived(&group_id, false);
    if a || b {
        s.persist()
    } else {
        Ok(())
    }
}

/// Mark a group's messages as read locally (no receipts for groups).
#[tauri::command]
pub async fn mark_group_seen(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.history.mark_group_seen(&group_id);
    s.persist()
}

/// Leave/delete a group locally (no wire message; others keep their copies).
#[tauri::command]
pub async fn delete_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.history.delete_group(&group_id);
    s.persist()
}

#[tauri::command]
pub async fn my_groups(state: tauri::State<'_, AppState>) -> Result<Vec<GroupListItem>, String> {
    let s = state.inner.lock().await;
    Ok(s.history
        .groups()
        .into_iter()
        .map(|(group_id, g)| GroupListItem {
            group_id,
            name: g.name,
            members: g.members.len(),
        })
        .collect())
}
