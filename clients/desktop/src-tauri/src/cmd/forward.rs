//! Forwarding: re-send an existing message — text OR attachment — into another
//! conversation (1:1, group, or note-to-self). An attachment forward reuses the original
//! [`AttachmentRef`] (one relay blob, its key re-sealed under the new ratchet), so
//! nothing is re-uploaded. Every copy carries the wire `fwd` flag, so recipients render
//! the "Forwarded" tag.

use crate::*;
use client_core::NOTE_TO_SELF_PEER;

/// The source message to forward, snapshotted out of history.
struct ForwardSrc {
    body: String,
    attachment: Option<client_core::AttachmentRef>,
}

fn snapshot_src(
    s: &Session,
    src_group: Option<&str>,
    src_peer: Option<&str>,
    msg_id: &str,
) -> Result<ForwardSrc, String> {
    let m = if let Some(gid) = src_group {
        s.history.group_message(gid, msg_id)
    } else {
        s.history.message(src_peer.unwrap_or_default(), msg_id)
    }
    .ok_or("no such message")?;
    if m.system {
        return Err("can't forward that".into());
    }
    Ok(ForwardSrc {
        body: m.body.clone(),
        attachment: m.attachment.clone(),
    })
}

/// Forward `msg_id` (from a 1:1 `src_peer` or a group `src_group`) to `dst`:
/// `dst_group` = a group id, `dst_username` = a 1:1 contact, neither = note-to-self.
#[tauri::command]
pub async fn forward_message(
    state: tauri::State<'_, AppState>,
    src_peer: Option<String>,
    src_group: Option<String>,
    msg_id: String,
    dst_username: Option<String>,
    dst_group: Option<String>,
) -> Result<(), String> {
    let src = {
        let s = state.inner.lock().await;
        snapshot_src(&s, src_group.as_deref(), src_peer.as_deref(), msg_id.trim())?
    };
    // A forwarded attachment keeps its content (voice flag, waveform, caption) but is a
    // NEW message: fresh timestamp so it sorts at the destination's now.
    let attachment = src.attachment.map(|mut a| {
        a.ts = now_secs();
        a
    });

    match (dst_group, dst_username) {
        // ── Into a group ─────────────────────────────────────────────────────────
        (Some(gid), _) => {
            let mut s = state.inner.lock().await;
            let client = s.client.clone().ok_or("not configured")?;
            let g = s.history.group(&gid).ok_or("no such group")?;
            crate::cmd::groups::ensure_in_group(g)?;
            let group = group_from_record(&gid, g);
            let sender_key = s
                .history
                .self_primary_key()
                .map(str::to_string)
                .unwrap_or_else(|| {
                    s.account
                        .as_ref()
                        .map(|a| a.ratchet_ref().identity_key())
                        .unwrap_or_default()
                });
            let multi = s.multi_device;
            let (new_id, sent_at) = match &attachment {
                Some(att) => {
                    let sess = &mut *s;
                    let account = sess.account.as_mut().ok_or("locked")?;
                    if multi {
                        client
                            .send_group_file_multi(
                                account,
                                &mut sess.history,
                                &group,
                                att.clone(),
                                true,
                            )
                            .await
                            .map_err(|e| e.to_string())?
                    } else {
                        let expire = Some(sess.history.group_timer(&gid).unwrap_or(0));
                        client
                            .send_group_file(account, &group, att.clone(), expire, true)
                            .await
                            .map_err(|e| e.to_string())?;
                        (local_msg_id(), att.ts)
                    }
                }
                None => {
                    let sess = &mut *s;
                    let account = sess.account.as_mut().ok_or("locked")?;
                    if multi {
                        client
                            .send_group_multi(
                                account,
                                &mut sess.history,
                                &group,
                                &src.body,
                                None,
                                true,
                            )
                            .await
                            .map_err(|e| e.to_string())?
                    } else {
                        let expire = Some(sess.history.group_timer(&gid).unwrap_or(0));
                        client
                            .send_group_timed(account, &group, &src.body, expire, None, true)
                            .await
                            .map_err(|e| e.to_string())?;
                        (local_msg_id(), now_secs())
                    }
                }
            };
            match attachment {
                Some(att) => s.history.record_group_attachment(
                    &gid,
                    &sender_key,
                    &new_id,
                    att,
                    sent_at,
                    None,
                ),
                None => s.history.record_group_message(
                    &gid,
                    &sender_key,
                    &new_id,
                    &src.body,
                    sent_at,
                    None,
                    None,
                ),
            }
            s.history.set_group_forwarded(&gid, &new_id);
            s.history.mark_group_seen(&gid);
            s.persist()
        }
        // ── Into a 1:1 chat ──────────────────────────────────────────────────────
        (None, Some(username)) => {
            let mut s = state.inner.lock().await;
            let client = s.client.clone().ok_or("not configured")?;
            if s.history
                .contacts()
                .iter()
                .any(|(u, p)| u == &username && p.blocked)
            {
                return Err("contact is blocked — unblock them first".into());
            }
            let contact = resolve_send_contact(&mut s, &client, username.trim()).await?;
            let peer = contact.identity_key.clone();
            let multi = s.multi_device;
            let (new_id, sent_at) = {
                let sess = &mut *s;
                let account = sess.account.as_mut().ok_or("locked")?;
                if multi {
                    let fan = match &attachment {
                        Some(att) => {
                            client
                                .prepare_attachment_fanout(
                                    account,
                                    &mut sess.history,
                                    &contact,
                                    att.clone(),
                                    true,
                                )
                                .await
                        }
                        None => {
                            client
                                .prepare_text_fanout(
                                    account,
                                    &mut sess.history,
                                    &contact,
                                    &src.body,
                                    None,
                                    true,
                                )
                                .await
                        }
                    }
                    .map_err(|e| e.to_string())?;
                    if !fan.deferred.is_empty() {
                        sess.history.outbox_push(fan.deferred.clone(), now_secs());
                    }
                    sess.persist()?;
                    let ids = (fan.msg_id.clone(), fan.sent_at);
                    drop(s);
                    client
                        .post_envelopes(&fan.immediate)
                        .await
                        .map_err(|e| e.to_string())?;
                    spawn_outbox_drain(state.inner.clone(), client.clone(), 0);
                    s = state.inner.lock().await;
                    ids
                } else {
                    let expire = Some(sess.history.timer(&peer).unwrap_or(0));
                    let prepared = match &attachment {
                        Some(att) => {
                            client.prepare_attachment(account, &contact, att.clone(), expire, true)
                        }
                        None => client.prepare_message_replying(
                            account, &contact, &src.body, None, expire, true,
                        ),
                    }
                    .map_err(|e| e.to_string())?;
                    sess.persist()?;
                    let ids = (prepared.msg_id.clone(), prepared.sent_at);
                    drop(s);
                    client
                        .post_envelope(&prepared.envelope)
                        .await
                        .map_err(|e| e.to_string())?;
                    s = state.inner.lock().await;
                    ids
                }
            };
            match attachment {
                Some(att) => s.history.record_attachment(
                    &peer,
                    Direction::Outgoing,
                    &new_id,
                    att,
                    sent_at,
                    None,
                ),
                None => s.history.record_full(
                    &peer,
                    Direction::Outgoing,
                    &new_id,
                    &src.body,
                    sent_at,
                    None,
                    None,
                ),
            }
            s.history.set_forwarded(&peer, &new_id);
            s.persist()
        }
        // ── Into note-to-self ────────────────────────────────────────────────────
        (None, None) => {
            let mut s = state.inner.lock().await;
            let client = s.client.clone().ok_or("not configured")?;
            let new_id = local_msg_id();
            let sent_at = now_secs();
            match &attachment {
                Some(att) => s.history.record_attachment(
                    NOTE_TO_SELF_PEER,
                    Direction::Outgoing,
                    &new_id,
                    att.clone(),
                    sent_at,
                    None,
                ),
                None => s.history.record_full(
                    NOTE_TO_SELF_PEER,
                    Direction::Outgoing,
                    &new_id,
                    &src.body,
                    sent_at,
                    None,
                    None,
                ),
            }
            s.history.set_forwarded(NOTE_TO_SELF_PEER, &new_id);
            if s.multi_device {
                let sess = &mut *s;
                if let Some(account) = sess.account.as_mut() {
                    let envs = match &attachment {
                        Some(att) => {
                            client
                                .prepare_note_file_selfsync(
                                    account,
                                    &mut sess.history,
                                    &new_id,
                                    att.clone(),
                                    true,
                                )
                                .await
                        }
                        None => {
                            client
                                .prepare_note_text_selfsync(
                                    account,
                                    &mut sess.history,
                                    &new_id,
                                    &src.body,
                                    sent_at,
                                    None,
                                    true,
                                )
                                .await
                        }
                    };
                    if let Ok(envs) = envs {
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
    }
}

/// A locally minted message id for paths that have no envelope to donate one.
fn local_msg_id() -> String {
    format!(
        "f{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}
