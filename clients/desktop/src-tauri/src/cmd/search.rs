use crate::*;

/// One global-search hit: enough to render a result row (conversation, snippet, time)
/// and to jump straight to the message (`peer` + `msg_id` — the thread command's
/// `anchor` extends the render window back to it).
#[derive(Serialize)]
pub(crate) struct SearchHit {
    /// "chat" | "group" | "note" — picks the open path in the UI.
    pub(crate) kind: &'static str,
    /// Conversation id: peer identity key / group id / the reserved note key.
    pub(crate) peer: String,
    /// Chats only: the username `open_chat` resolves (title may be a nickname).
    pub(crate) username: String,
    /// Display name for the row (nickname/username, group name, "Note to self").
    pub(crate) title: String,
    pub(crate) msg_id: String,
    /// The matched text, trimmed to a window around the first match.
    pub(crate) snippet: String,
    pub(crate) sent_at: u64,
    pub(crate) mine: bool,
    /// Groups: who wrote it (drives the "Anna:" prefix).
    pub(crate) sender: Option<String>,
    pub(crate) attachment: bool,
    pub(crate) voice: bool,
}

/// A readable window around the first case-insensitive match: `…context MATCH context…`.
/// Byte positions are mapped defensively (lowercasing can shift offsets for a few
/// scripts) — every slice point is snapped to a char boundary, so this can trim
/// slightly off but can never panic.
fn snippet_around(body: &str, needle_lc: &str) -> String {
    const BEFORE: usize = 32;
    const AFTER: usize = 56;
    let lc = body.to_lowercase();
    let pos = lc.find(needle_lc).unwrap_or(0).min(body.len());
    let mut start = pos.saturating_sub(BEFORE);
    while start > 0 && !body.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (pos + needle_lc.len() + AFTER).min(body.len());
    while end < body.len() && !body.is_char_boundary(end) {
        end += 1;
    }
    format!(
        "{}{}{}",
        if start > 0 { "…" } else { "" },
        &body[start..end],
        if end < body.len() { "…" } else { "" }
    )
}

/// First matching text of a message (body, caption, attachment filename), as a snippet.
/// System chips are skipped — "call" must not surface every call-history chip.
fn message_match(m: &StoredMessage, needle_lc: &str) -> Option<String> {
    if m.system {
        return None;
    }
    if m.body.to_lowercase().contains(needle_lc) {
        return Some(snippet_around(&m.body, needle_lc));
    }
    if let Some(cap) = m.attachment.as_ref().and_then(|a| a.caption.as_ref()) {
        if cap.to_lowercase().contains(needle_lc) {
            return Some(snippet_around(cap, needle_lc));
        }
    }
    None
}

/// Global message search: case-insensitive substring over EVERY conversation's
/// decrypted in-memory history — 1:1 chats, groups, and note-to-self. Newest hits
/// first, capped at `limit`. Purely local (nothing is sent anywhere: the relay never
/// sees plaintext, so search can only ever be client-side).
#[tauri::command]
pub async fn search_messages(
    state: tauri::State<'_, AppState>,
    query: String,
    limit: Option<usize>,
) -> Result<Vec<SearchHit>, String> {
    let mut s = state.inner.lock().await;
    // Reap first — an expired message must never resurface through search.
    if s.account.is_some() && s.history.reap(now_secs()) > 0 {
        s.persist()?;
    }
    let s = &*s;
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    let limit = limit.unwrap_or(60).clamp(1, 200);
    let mut hits: Vec<SearchHit> = Vec::new();

    // 1:1 chats (address book). Pending requests are excluded — content held behind a
    // request must not surface through search before the user accepts.
    for (username, pin) in s.history.contacts() {
        if pin.request.is_some() {
            continue;
        }
        let title = pin.nickname.clone().unwrap_or_else(|| username.clone());
        for m in s.history.messages(&pin.identity_key) {
            if let Some(snippet) = message_match(m, &needle) {
                hits.push(SearchHit {
                    kind: "chat",
                    peer: pin.identity_key.clone(),
                    username: username.clone(),
                    title: title.clone(),
                    msg_id: m.msg_id.clone(),
                    snippet,
                    sent_at: m.sent_at,
                    mine: matches!(m.direction, Direction::Outgoing),
                    sender: None,
                    attachment: m.attachment.is_some(),
                    voice: m.attachment.as_ref().is_some_and(|a| a.voice),
                });
            }
        }
    }

    // Note-to-self.
    for m in s.history.messages(client_core::NOTE_TO_SELF_PEER) {
        if let Some(snippet) = message_match(m, &needle) {
            hits.push(SearchHit {
                kind: "note",
                peer: client_core::NOTE_TO_SELF_PEER.to_string(),
                username: String::new(),
                title: "Note to self".to_string(),
                msg_id: m.msg_id.clone(),
                snippet,
                sent_at: m.sent_at,
                mine: true,
                sender: None,
                attachment: m.attachment.is_some(),
                voice: m.attachment.as_ref().is_some_and(|a| a.voice),
            });
        }
    }

    // Groups: attribute the sender for the row prefix, same rules as group_thread.
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    let my_primary = s.history.self_primary_key().map(str::to_string);
    for (group_id, g) in s.history.groups() {
        for m in &g.messages {
            if let Some(snippet) = message_match(m, &needle) {
                let sender = m.sender.as_deref().unwrap_or_default();
                let mine = sender == my_key || my_primary.as_deref() == Some(sender);
                hits.push(SearchHit {
                    kind: "group",
                    peer: group_id.clone(),
                    username: String::new(),
                    title: g.name.clone(),
                    msg_id: m.msg_id.clone(),
                    snippet,
                    sent_at: m.sent_at,
                    mine,
                    sender: (!mine)
                        .then(|| {
                            g.members
                                .iter()
                                .find(|mem| mem.identity_key == sender)
                                .map(|mem| mem.username.clone())
                        })
                        .flatten(),
                    attachment: m.attachment.is_some(),
                    voice: m.attachment.as_ref().is_some_and(|a| a.voice),
                });
            }
        }
    }

    hits.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));
    hits.truncate(limit);
    Ok(hits)
}
