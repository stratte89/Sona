// ═══════════════════════════════════════════════════════════════════════════════
// Chats list
// ═══════════════════════════════════════════════════════════════════════════════
async function openChats() { show('chats'); invoke('set_open_chat', { peer: null }).catch(() => {}); stopTyping(); await loadChats(); }
$('#ch-new').onclick = () => {
  const card = openModal(
    `<button class="modal-x" id="mo-x" aria-label="Close">${icon('x')}</button>
     <h3>Start something</h3>
     <div class="modal-list">
       <button id="mo-chat">${icon('chat')}New chat<em>message a username</em></button>
       <button id="mo-group">${icon('users')}New group<em>you + your contacts</em></button>
       <button id="mo-note">${icon('bookmark')}Note to self<em>your private scratchpad, synced to your devices</em></button>
     </div>`);
  card.querySelector('#mo-x').onclick = closeModal;
  card.querySelector('#mo-chat').onclick = () => { closeModal(); $('#nc-user').value = ''; show('newchat'); setTimeout(() => $('#nc-user').focus(), 250); };
  card.querySelector('#mo-group').onclick = () => { closeModal(); openNewGroup(); };
  card.querySelector('#mo-note').onclick = () => { closeModal(); openNote(); };
};

const isMuted = (c) => c.muted_until && c.muted_until > Math.floor(Date.now() / 1000);

const BASE_TITLE = 'Sona';
function updateTitleBadge(convs) {
  const total = convs.reduce((n, c) => n + (c.unread || 0), 0);
  document.title = total > 0 ? `(${total > 99 ? '99+' : total}) ${BASE_TITLE}` : BASE_TITLE;
}

// ── Incoming typing indicators (B): each entry expires ~6s after the last refresh.
// Value carries WHO types (groups have many senders); 1:1 leaves `name` unset.
const typingState = new Map(); // conversation id (peer key or group id) -> { exp, name }
function isTyping(id) {
  const e = typingState.get(id);
  if (!e) return false;
  if (e.exp < Date.now()) { typingState.delete(id); return false; }
  return true;
}
function typingName(id) {
  const e = typingState.get(id);
  return (isTyping(id) && e.name) || '';
}
function applyTyping(peer, group, on, who) {
  const id = group || peer;
  if (!id) return;
  if (on) typingState.set(id, { exp: Date.now() + 6000, name: group ? who || '' : '' });
  else typingState.delete(id);
  refreshTypingUi(id);
}
// Update the in-thread "..." bubble and the chat-list row for a conversation's typing
// state. The bubble sits at the bottom-left of the message list (modern-messenger
// style) and vanishes when the peer stops.
function refreshTypingUi(id) {
  if (cur.peer === id) updateTypingBubble();
  const row = $(`#ch-list .conv[data-peer="${CSS.escape(id)}"]`);
  if (row) {
    const last = row.querySelector('.conv-last');
    const c = lastConvs.find((x) => x.peer === id);
    if (last) {
      if (isTyping(id)) {
        const who = typingName(id);
        last.innerHTML = `<span class="typing-preview">${who ? escapeHtml(who) + ' is ' : ''}typing…</span>`;
      } else if (c) { const bt = c.last_voice ? 'Voice message' : c.last_attachment ? 'Attachment' : stripMarkers(c.last_body || ''); last.innerHTML = (c.last_outgoing ? '<span class="me">You: </span>' : '') + escapeHtml(bt); }
    }
  }
}
// The "peer is typing" bubble: always the LAST element of the thread, so repaints must
// re-call this (renderThread/renderGroupThread do). Follows the scroll rule of new
// messages: only auto-scrolls when the user is already at the bottom. In a group it
// carries the typist's name — dots alone can't say who, there are many senders.
function updateTypingBubble() {
  const box = $('#th-thread');
  const existing = $('#th-typing');
  if (!cur.peer || !isTyping(cur.peer)) { if (existing) existing.remove(); return; }
  const who = typingName(cur.peer);
  if (existing) {
    const label = existing.querySelector('.sender');
    if (who && label) label.textContent = who;
    else if (who && !label) {
      const s = document.createElement('span');
      s.className = 'sender'; s.textContent = who;
      existing.prepend(s);
    } else if (!who && label) label.remove();
    box.appendChild(existing);
    return;
  }
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const el = document.createElement('div');
  el.id = 'th-typing';
  el.className = 'bubble in typing-bubble';
  el.innerHTML = '<span class="typing-dots"><i></i><i></i><i></i></span>';
  if (who) {
    const s = document.createElement('span');
    s.className = 'sender'; s.textContent = who;
    el.prepend(s);
  }
  box.appendChild(el);
  if (nearBottom) box.scrollTop = box.scrollHeight;
}
// Re-check expiries periodically so a stale "typing…" clears even without a stop frame.
setInterval(() => { for (const [id, e] of typingState) if (e.exp < Date.now()) { typingState.delete(id); refreshTypingUi(id); } }, 2000);

let archivedOpen = false;
function convRow(c) {
  const display = c.nickname || c.username;
  const row = document.createElement('div');
  const unreadBadge = c.unread || (c.manual_unread ? 1 : 0);
  row.className = 'conv' + ((unreadBadge || c.manual_unread) ? ' unread' : '');
  row.dataset.peer = c.peer;
  const attText = IMG_EXT.test(c.last_body || '') ? 'Sent an image' : 'Sent a file';
  const bodyText = c.last_voice ? 'Voice message' : c.last_attachment ? attText : stripMarkers(c.last_body || '');
  const typing = isTyping(c.peer);
  const typist = typingName(c.peer);
  const preview = typing
    ? `<span class="typing-preview">${typist ? escapeHtml(typist) + ' is ' : ''}typing…</span>`
    : c.has_messages
      ? (c.last_outgoing ? '<span class="me">You: </span>' : '') + escapeHtml(bodyText)
      : '<span class="me">No messages yet</span>';
  const badge = unreadBadge
    ? `<span class="unread-badge${isMuted(c) ? ' muted' : ''}">${c.unread > 99 ? '99+' : (c.unread || '')}</span>` : '';
  const tchip = c.timer_secs ? `<span class="av-timer">${icon('clock')}${tlabel(c.timer_secs)}</span>` : '';
  const flags =
    (c.pinned ? `<span class="conv-flags">${icon('pin')}</span>` : '') +
    (isMuted(c) ? `<span class="conv-flags">${icon('belloff')}</span>` : '') +
    (c.blocked ? `<span class="conv-flags">${icon('block')}</span>` : '');
  const avInner = c.note ? icon('bookmark') : avatarInner(c.avatar, display, c.kind === 'group');
  row.innerHTML =
    `<div class="avatar" style="--av-h:${hue(c.kind === 'group' ? c.peer : c.username)}">${avInner}${tchip}</div>
     <div class="conv-body">
       <div class="conv-top">
         <span class="conv-name">${escapeHtml(display)}${c.verified ? `<span class="verify-mini">${icon('shield')}</span>` : ''}${flags}</span>
         <span class="conv-time">${c.last_ts ? hhmm(c.last_ts) : ''}</span>
       </div>
       <div class="conv-bottom">
         <span class="conv-last">${preview}</span>${badge}
       </div>
     </div>`;
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  row.onclick = () => (c.note ? openNote() : c.kind === 'group' ? openGroup(c.peer, c.username) : openThread(c.username, c.peer, display));
  row.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); } };
  const menu = (x, y) => showCtx(x, y, rowMenu(c));
  row.oncontextmenu = (e) => { e.preventDefault(); menu(e.clientX, e.clientY); };
  onHold(row, menu);
  return row;
}

async function loadChats() {
  let convs = [];
  try { convs = await invoke('conversations'); } catch (e) { toast(say(e), 'err'); }
  await refreshReqBadge();
  lastConvs = convs;
  const list = $('#ch-list');
  $('#ch-empty').hidden = convs.length > 0 || reqBadge.count > 0;
  const q = ($('#ch-search').value || '').trim().toLowerCase();
  const match = (c) => !q || (c.nickname || c.username).toLowerCase().includes(q) || c.username.toLowerCase().includes(q);
  const active = convs.filter((c) => !c.archived && match(c));
  const archived = convs.filter((c) => c.archived && match(c));
  // Reconciled like the thread (see 30-thread.js): every sync repaints this list,
  // and wiping it re-decoded every avatar — a visible blink in the desktop sidebar.
  // The signature folds in state that lives OUTSIDE the conversation view but
  // changes a row's rendering: mute, and the typing preview read at build time.
  const rowItem = (c) => ({
    key: 'c:' + c.kind + ':' + (c.peer || c.username),
    sig: JSON.stringify(c) + '|' + isMuted(c) + '|' + isTyping(c.peer) + ':' + typingName(c.peer),
    build: () => convRow(c),
  });
  const items = [];
  // Requests entry point: pinned above the chats whenever something waits. Hidden
  // while searching (the search filters chats), and gone entirely in open mode.
  if (!q && reqBadge.enabled && reqBadge.count > 0) {
    items.push({ key: 'req', sig: JSON.stringify(reqBadge), build: requestsEntryRow });
  }
  for (const c of active) items.push(rowItem(c));
  if (archived.length) {
    items.push({
      key: 'ahead', sig: archivedOpen + ':' + archived.length,
      build: () => {
        const head = document.createElement('button');
        head.className = 'archived-head';
        head.innerHTML = `${icon(archivedOpen ? 'downchev' : 'up')}<span>Archived (${archived.length})</span>`;
        head.onclick = () => { archivedOpen = !archivedOpen; loadChats(); };
        return head;
      },
    });
    if (archivedOpen) for (const c of archived) items.push(rowItem(c));
  }
  reconcileThread(list, items);
  scheduleGlobalHits(q); // content hits render below the name matches
  updateTitleBadge(convs);
}
let lastConvs = [];
$('#ch-search').addEventListener('input', loadChats);

// ── Global message search ─────────────────────────────────────────────────────────
// The chat-list search field filters conversation NAMES instantly; from 2 characters
// it also searches every conversation's message CONTENT (backend scan over the
// decrypted in-memory history — the relay never sees plaintext, so search can only
// be local). Hits render as a "Messages" section under the name matches; tapping one
// opens the thread anchored on that message.
let ghSeq = 0;
let ghTimer = null;
function scheduleGlobalHits(q) {
  clearTimeout(ghTimer);
  ghSeq++; // invalidate any in-flight query
  if (q.length < 2) return; // the list repaint already dropped the old section
  ghTimer = setTimeout(() => renderGlobalHits(q), 220);
}
async function renderGlobalHits(q) {
  const my = ++ghSeq;
  let hits = [];
  try { hits = await invoke('search_messages', { query: q, limit: 60 }); } catch (_) {}
  // Stale (newer keystroke or a cleared/changed field): drop silently. No screen
  // check — on wide layouts the chat list is a sidebar while a thread is open.
  if (my !== ghSeq) return;
  if (($('#ch-search').value || '').trim().toLowerCase() !== q) return;
  $('#ch-ghits')?.remove();
  if (!hits.length) return;
  const wrap = document.createElement('div');
  wrap.id = 'ch-ghits';
  const head = document.createElement('div');
  head.className = 'ghits-head';
  head.innerHTML = `${icon('search')}<span>Messages</span><em>${hits.length}${hits.length >= 60 ? '+' : ''}</em>`;
  wrap.appendChild(head);
  for (const h of hits) wrap.appendChild(hitRow(h, q));
  $('#ch-list').appendChild(wrap);
}
// Snippet with the matched substring highlighted (built as DOM — never innerHTML of
// message text).
function snippetNode(sn, q) {
  const span = document.createElement('span');
  span.className = 'ghit-snippet';
  const i = sn.toLowerCase().indexOf(q);
  if (i < 0) { span.textContent = sn; return span; }
  span.append(sn.slice(0, i));
  const mk = document.createElement('mark');
  mk.textContent = sn.slice(i, i + q.length);
  span.append(mk, sn.slice(i + q.length));
  return span;
}
function hitRow(h, q) {
  const row = document.createElement('div');
  row.className = 'ghit';
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  const conv = lastConvs.find((c) => c.peer === h.peer);
  const av = document.createElement('div');
  av.className = 'avatar';
  av.style.setProperty('--av-h', hue(h.kind === 'group' ? h.peer : (h.username || h.peer)));
  av.innerHTML = h.kind === 'note' ? icon('bookmark') : avatarInner(conv && conv.avatar, h.title, h.kind === 'group');
  const body = document.createElement('div');
  body.className = 'ghit-body';
  const top = document.createElement('div');
  top.className = 'ghit-top';
  const name = document.createElement('span');
  name.className = 'ghit-name';
  name.textContent = h.title;
  const time = document.createElement('span');
  time.className = 'ghit-time';
  time.textContent = relday(h.sent_at) + ' · ' + hhmm(h.sent_at);
  top.append(name, time);
  const line = document.createElement('div');
  line.className = 'ghit-line';
  const who = h.mine ? 'You: ' : h.sender ? h.sender + ': ' : '';
  if (who) {
    const w = document.createElement('span');
    w.className = 'ghit-who';
    w.textContent = who;
    line.appendChild(w);
  }
  if (h.voice || h.attachment) {
    const a = document.createElement('span');
    a.className = 'ghit-att';
    a.textContent = h.voice ? '🎤 ' : '📎 ';
    line.appendChild(a);
  }
  line.appendChild(snippetNode(h.snippet, q));
  body.append(top, line);
  row.append(av, body);
  row.onclick = async () => {
    if (h.kind === 'note') await openNote();
    else if (h.kind === 'group') await openGroup(h.peer, h.title);
    else await openThread(h.username, h.peer, h.title);
    jumpToMsg(h.msg_id); // anchors the render window back to the hit if needed
  };
  row.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); } };
  return row;
}

// ── Message requests ──────────────────────────────────────────────────────────────
// Strangers knock here first (the Rust gate holds everything back until an accept).
// The entry row lives at the top of the chat list; a pulsing red dot marks unseen
// activity. Accept opens the chat; Delete forgets quietly; Block keeps dropping.
let reqBadge = { count: 0, unseen: 0, enabled: true };
async function refreshReqBadge() {
  try { reqBadge = await invoke('request_badge'); }
  catch (_) { reqBadge = { count: 0, unseen: 0, enabled: true }; }
}
function requestsEntryRow() {
  const row = document.createElement('button');
  row.type = 'button';
  row.className = 'req-entry' + (reqBadge.unseen ? ' hot' : '');
  row.innerHTML =
    `<span class="req-ico">${icon('users')}${reqBadge.unseen ? '<i class="reqdot"></i>' : ''}</span>
     <span class="req-body">
       <b>Message requests</b>
       <em>${reqBadge.count === 1 ? '1 person wants' : reqBadge.count + ' people want'} to chat with you</em>
     </span>
     <span class="req-count">${reqBadge.count}</span>`;
  row.onclick = openRequests;
  return row;
}

async function openRequests() {
  show('requests');
  await loadRequests();
  // Mark viewed AFTER the render, so this visit still shows what was new.
  invoke('mark_requests_seen').catch(() => {});
}

async function loadRequests() {
  let reqs = [];
  try { reqs = await invoke('message_requests'); } catch (e) { toast(say(e), 'err'); }
  const list = $('#rq-list');
  list.innerHTML = '';
  $('#rq-empty').hidden = reqs.length > 0;
  for (const r of reqs) list.appendChild(rqRow(r));
}

// Meta line: what the requester tried, without ever showing withheld content.
function rqMeta(r) {
  const bits = [];
  if (r.withheld) bits.push(`${r.withheld} message${r.withheld > 1 ? 's' : ''} waiting`);
  if (r.calls) bits.push(`tried to call${r.calls > 1 ? ' ×' + r.calls : ''}`);
  if (r.invites.length) bits.push(r.invites.length === 1 ? `invited you to “${r.invites[0]}”` : `${r.invites.length} group invites`);
  return bits.join(' · ') || 'wants to chat with you';
}

function rqRow(r) {
  const row = document.createElement('div');
  row.className = 'req-row' + (r.unseen ? ' fresh' : '');
  const av = document.createElement('div');
  av.className = 'avatar';
  av.style.setProperty('--av-h', hue(r.username));
  av.innerHTML = avatarInner(r.avatar, r.username, false);
  const body = document.createElement('div');
  body.className = 'req-rowbody';
  const top = document.createElement('div');
  top.className = 'conv-top';
  const name = document.createElement('span');
  name.className = 'conv-name';
  name.textContent = r.username;
  if (r.unseen) { const d = document.createElement('i'); d.className = 'reqdot inline'; name.appendChild(d); }
  const time = document.createElement('span');
  time.className = 'conv-time';
  time.textContent = r.last ? `${relday(r.last)} · ${hhmm(r.last)}` : '';
  top.append(name, time);
  const line = document.createElement('div');
  line.className = 'req-line';
  // The preview only exists in "message travels along" mode; withheld content shows
  // as a count, never as text. Built as DOM — never innerHTML of message text.
  if (r.preview) line.textContent = r.preview;
  else { line.textContent = rqMeta(r); line.classList.add('muted'); }
  // Compact actions that always fit inside the card: an Approve pill on its own
  // line, then small red icon buttons (delete / block) — labels live in tooltips
  // and aria, so nothing can overflow the bubble on narrow screens.
  const acts = document.createElement('div');
  acts.className = 'req-actions';
  const mkBtn = (html, cls, label, fn) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = cls;
    b.innerHTML = html;
    b.title = label;
    b.setAttribute('aria-label', label);
    b.onclick = (e) => { e.stopPropagation(); fn(b); };
    return b;
  };
  acts.append(
    mkBtn(`${icon('check')}<span>Approve</span>`, 'btn btn-sm req-accept', 'Approve request', async (b) => {
      busy(b, true, 'Accepting…');
      try {
        const peer = await invoke('accept_msg_request', { username: r.username });
        toast(`${r.username} can now message you`, 'ok');
        openThread(r.username, peer, r.username);
      } catch (e) { busy(b, false); toast(say(e), 'err'); loadRequests(); }
    }),
    mkBtn(icon('trash'), 'req-iconbtn', 'Delete request', async () => {
      try {
        await invoke('decline_msg_request', { username: r.username, block: false });
        toast('Request deleted — they aren’t told', 'ok');
        loadRequests();
      } catch (e) { toast(say(e), 'err'); }
    }),
    mkBtn(icon('block'), 'req-iconbtn', 'Block', async () => {
      if (!(await confirmModal(`Block ${r.username}?`,
        'The request disappears and everything they send is dropped silently. They aren’t told.',
        'Block'))) return;
      try {
        await invoke('decline_msg_request', { username: r.username, block: true });
        toast(`${r.username} blocked`, 'ok');
        loadRequests();
      } catch (e) { toast(say(e), 'err'); }
    }),
  );
  body.append(top, line, acts);
  row.append(av, body);
  return row;
}
$('#rq-back').onclick = () => navBack('chats');

// Right-click / long-press menu for a chat-list row.
function rowMenu(c) {
  if (c.note) {
    // Note-to-self: no mute/block/nickname surface — just wipe.
    return [{
      label: 'Delete notes…', icon: 'trash', danger: true,
      fn: async () => {
        if (!(await confirmModal('Delete your notes?', 'Every note on this device is wiped. Other devices keep their copies.', 'Delete'))) return;
        try { await invoke('delete_chat', { username: NOTE_PEER, peer: NOTE_PEER, forBoth: false }); clearMediaCaches(); loadChats(); }
        catch (e) { toast(say(e), 'err'); }
      },
    }];
  }
  if (c.kind === 'group') {
    const gflip = async (cmd, args) => { try { await invoke(cmd, args); loadChats(); } catch (e) { toast(say(e), 'err'); } };
    return [{
      label: c.pinned ? 'Unpin' : 'Pin', icon: 'pin',
      fn: () => gflip('set_group_pinned', { groupId: c.peer, pinned: !c.pinned }),
    }, {
      label: (c.unread || c.manual_unread) ? 'Mark read' : 'Mark unread', icon: 'check',
      fn: async () => {
        try {
          if (c.unread || c.manual_unread) {
            await invoke('mark_group_seen', { groupId: c.peer });
            await invoke('set_group_unread', { groupId: c.peer, unread: false });
          } else {
            await invoke('set_group_unread', { groupId: c.peer, unread: true });
          }
          loadChats();
        } catch (e) { toast(say(e), 'err'); }
      },
    }, {
      label: c.archived ? 'Unarchive' : 'Archive', icon: 'down',
      fn: () => gflip('set_group_archived', { groupId: c.peer, archived: !c.archived }),
    }, {
      label: isMuted(c) ? 'Unmute' : 'Mute…', icon: isMuted(c) ? 'bell' : 'belloff',
      fn: () => (isMuted(c) ? unmute({ kind: 'group', id: c.peer }) : muteModal({ kind: 'group', id: c.peer, name: c.username })),
    }, {
      label: 'Leave group…', icon: 'block', danger: true,
      fn: async () => {
        if (!(await confirmModal('Leave group?', `The other members of "${c.username}" are told you left, and the group is removed from this device.`, 'Leave group'))) return;
        try { await invoke('leave_group', { groupId: c.peer }); loadChats(); } catch (e) { toast(say(e), 'err'); }
      },
    }, {
      label: 'Delete for me', icon: 'trash', danger: true,
      fn: async () => {
        if (!(await confirmModal('Delete group?', `"${c.username}" and its messages are removed from this device only — nobody is told, and other members keep their copies.`, 'Delete group'))) return;
        try { await invoke('delete_group', { groupId: c.peer }); loadChats(); } catch (e) { toast(say(e), 'err'); }
      },
    }];
  }
  const flip = async (cmd, args, ok) => { try { await invoke(cmd, args); if (ok) toast(ok, 'ok'); loadChats(); } catch (e) { toast(say(e), 'err'); } };
  return [
    {
      label: c.pinned ? 'Unpin' : 'Pin', icon: 'pin',
      fn: () => flip('set_pinned', { username: c.username, pinned: !c.pinned }),
    },
    {
      label: (c.unread || c.manual_unread) ? 'Mark read' : 'Mark unread', icon: 'check',
      fn: async () => {
        try {
          if (c.unread || c.manual_unread) {
            // The badge is the real unseen-message count plus the manual flag —
            // clear BOTH (set_unread alone left the count, so "Mark read" looked
            // dead). mark_seen also sends the receipts, honoring the privacy pref.
            await invoke('mark_seen', { username: c.username, peer: c.peer });
            await invoke('set_unread', { username: c.username, unread: false });
          } else {
            await invoke('set_unread', { username: c.username, unread: true });
          }
          loadChats();
        } catch (e) { toast(say(e), 'err'); }
      },
    },
    {
      label: c.archived ? 'Unarchive' : 'Archive', icon: 'down',
      fn: () => flip('set_archived', { username: c.username, archived: !c.archived }),
    },
    {
      label: isMuted(c) ? 'Unmute' : 'Mute…', icon: isMuted(c) ? 'bell' : 'belloff',
      fn: () => (isMuted(c) ? unmute({ kind: 'chat', id: c.username }) : muteModal({ kind: 'chat', id: c.username, name: c.nickname || c.username })),
    },
    {
      label: 'Delete chat…', icon: 'trash', danger: true,
      fn: () => deleteChatModal(c.username, c.peer),
    },
  ];
}

async function unmute(target) {
  try {
    if (target.kind === 'group') await invoke('set_group_muted', { groupId: target.id, until: null });
    else await invoke('set_muted', { username: target.id, until: null });
    loadChats();
  } catch (e) { toast(say(e), 'err'); }
}

// Mute: explicit duration choice. `target` = {kind:'chat'|'group', id, name}.
function muteModal(target, after) {
  const username = target.name;
  const opts = [['1 hour', 3600], ['8 hours', 8 * 3600], ['1 day', 86400], ['1 week', 7 * 86400], ['Forever', null]];
  const card = openModal(
    `<h3>Mute ${escapeHtml(username)}</h3><p>No unread highlights from this chat until then.</p>
     <div class="modal-list">${opts.map(([l], i) => `<button data-i="${i}">${icon('belloff')}${l}</button>`).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-i]').forEach((b) => {
    b.onclick = async () => {
      const secs = opts[Number(b.dataset.i)][1];
      const until = secs === null ? 253370764800 : Math.floor(Date.now() / 1000) + secs; // null = year 9999
      closeModal();
      try {
        if (target.kind === 'group') await invoke('set_group_muted', { groupId: target.id, until });
        else await invoke('set_muted', { username: target.id, until });
        loadChats(); if (after) after();
      } catch (e) { toast(say(e), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
}

// Delete: explicit, and "for both" is a separate explicit choice.
function deleteChatModal(username, peer, after) {
  const card = openModal(
    `<h3>Delete chat with ${escapeHtml(username)}?</h3>
     <p>This wipes the conversation from this device. "Delete for both" also asks their
        device to wipe it — it already holds the messages, so this is cooperation, not a guarantee.</p>
     <button class="btn btn-danger" id="mo-me">Delete for me</button>
     <button class="btn btn-danger" id="mo-both">Delete for both</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  const doDelete = async (forBoth) => {
    closeModal();
    try {
      await invoke('delete_chat', { username, peer, forBoth });
      clearMediaCaches(); // the deleted thread's decrypted media must not linger in RAM
      toast('Chat deleted', 'ok');
      show('chats'); loadChats();
      if (after) after();
    } catch (e) { toast(say(e), 'err'); }
  };
  card.querySelector('#mo-me').onclick = () => doDelete(false);
  card.querySelector('#mo-both').onclick = () => doDelete(true);
  card.querySelector('#mo-no').onclick = closeModal;
}

