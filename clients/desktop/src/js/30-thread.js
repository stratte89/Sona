// ═══════════════════════════════════════════════════════════════════════════════
// Thread
// ═══════════════════════════════════════════════════════════════════════════════
let cur = { kind: 'chat', peer: null, username: null, verified: false, safety: '', keyChanged: false, timer: null, blocked: false };

// ── Per-chat drafts ────────────────────────────────────────────────────────────
// Composer text, reply state and queued attachments are saved per conversation and
// restored on reopen — switching chats can never send chat A's draft into chat B.
// In-memory only (a draft never touches disk unencrypted; lock drops it with the rest).
const drafts = new Map(); // draft key -> { text, replyTo, replyText, queue }
function draftKey() {
  if (!cur.username && !cur.peer) return null;
  return cur.kind === 'group' ? 'group:' + cur.peer : 'chat:' + cur.username;
}
function saveDraft() {
  const key = draftKey();
  if (!key) return;
  const text = $('#th-input').value;
  const queue = attachQueue.slice();
  attachQueue = [];
  renderQueue();
  if (text.trim() || replyTo || queue.length) {
    drafts.set(key, { text, replyTo, replyText: $('#th-replytext').textContent, queue });
  } else {
    drafts.delete(key);
  }
  $('#th-input').value = '';
  $('#th-input').style.height = 'auto';
  updateCmp(); // the queue emptied above ran it too early — the input just cleared
}
function restoreDraft() {
  closeCmpPanel(); // a chat switch never inherits the previous chat's emoji/GIF panel
  const d = drafts.get(draftKey());
  const inp = $('#th-input');
  inp.value = d ? d.text : '';
  inp.style.height = 'auto';
  if (inp.value) inp.style.height = Math.min(inp.scrollHeight, 120) + 'px';
  attachQueue = d && d.queue ? d.queue.slice() : [];
  renderQueue();
  if (d && d.replyTo) {
    replyTo = d.replyTo;
    $('#th-replytext').textContent = d.replyText || '';
    $('#th-replybar').hidden = false;
  } else {
    clearReply();
  }
}

// ── Pinned-messages banner ──────────────────────────────────────────────────────
// `curPins` = the open thread's pinned messages, oldest→newest. The banner shows one;
// tapping jumps to it and cycles to the next (Telegram-style), the chevron opens the
// full list. Re-fed on every render (renderThread / renderGroupThread).
let curPins = [];
let pinCursor = 0;
function updatePinBar(pins) {
  curPins = pins;
  if (pinCursor >= pins.length) pinCursor = Math.max(0, pins.length - 1);
  const bar = $('#th-pinbar');
  bar.hidden = !pins.length;
  if (!pins.length) return;
  const m = pins[pinCursor];
  $('#th-pinlabel').textContent = pins.length > 1 ? `Pinned ${pinCursor + 1}/${pins.length}` : 'Pinned';
  $('#th-pintext').textContent = m.voice ? '🎤 Voice message' : m.attachment ? '📎 ' + m.body : stripMarkers(m.body);
}
$('#th-pinbar').onclick = (e) => {
  if (e.target.closest('#th-pinlist')) { e.stopPropagation(); pinnedListModal(); return; }
  if (!curPins.length) return;
  jumpToMsg(curPins[pinCursor].msg_id);
  pinCursor = (pinCursor + 1) % curPins.length; // next tap surfaces the next pin
  updatePinBar(curPins);
};

// ── Note-to-self ────────────────────────────────────────────────────────────────
// A local conversation under the reserved NOTE_PEER key: no contact, no KT resolve, no
// receipts/typing/calls — notes self-sync to your own other devices and nothing else.
async function openNote() {
  saveDraft();
  threadWin.delete(NOTE_PEER); // fresh open: back to the default window
  cur = { kind: 'chat', peer: NOTE_PEER, username: NOTE_PEER, display: 'Note to self', verified: false, safety: '', keyChanged: false, timer: null, blocked: false, note: true };
  cur.avatar = null;
  const av = $('#th-avatar');
  av.innerHTML = icon('bookmark');
  av.style.setProperty('--av-h', hue(NOTE_PEER));
  show('thread');
  $('#th-name').textContent = 'Note to self';
  $('#th-sub').hidden = false;
  $('#th-sub').textContent = 'only you can see this';
  cur.subBase = 'only you can see this';
  $('#th-keychange').hidden = true;
  $('#th-searchbar').hidden = true;
  $('#th-timerchip').hidden = true;
  $('#th-blocked').hidden = true;
  $('#th-left').hidden = true;
  $('#th-knock').hidden = true;
  $('#th-form').style.display = '';
  $('#th-mic').hidden = false;
  $('#th-call').hidden = true; // you can't ring yourself
  cancelVoice();
  stopNowPlaying();
  restoreDraft();
  await renderThread(NOTE_PEER); // callers may jump to a message right after
  invoke('set_open_chat', { peer: NOTE_PEER }).catch(() => {});
  if (!IS_ANDROID) $('#th-input').focus();
}

// ── Failed sends ───────────────────────────────────────────────────────────────
// A send that errored is kept (in memory) and re-rendered as a red bubble with
// Retry/Discard at the end of the thread — a repaint must never eat an unsent message.
let failedSeq = 0;
const failedSends = new Map(); // draft key -> [{ fid, kind, ... }]
function noteFailedSend(entry, key) {
  key = key || draftKey(); // callers pass the key captured at send time (async races)
  if (!key) return;
  entry.fid = ++failedSeq;
  entry.key = key;
  const list = failedSends.get(key) || [];
  list.push(entry);
  failedSends.set(key, list);
}
function dropFailedSend(entry) {
  const list = failedSends.get(entry.key) || [];
  const i = list.findIndex((e) => e.fid === entry.fid);
  if (i >= 0) list.splice(i, 1);
  if (!list.length) failedSends.delete(entry.key);
}
function failedLabel(e) {
  if (e.kind === 'voice') return '🎤 Voice message';
  if (e.kind === 'file') return '📎 ' + e.name;
  return e.text;
}
async function retryFailedSend(entry) {
  dropFailedSend(entry);
  if (entry.kind === 'text') return sendTextMessage(entry.text, entry.replyTo);
  if (entry.kind === 'file') {
    const r = await sendOneFile({ file: entry.file, bytes: entry.bytes, name: entry.name }, entry.caption || null);
    if (r !== 'key_changed' && cur.peer) {
      await (cur.kind === 'group' ? renderGroupThread(cur.peer) : renderThread(cur.peer));
      loadChats();
    }
    return;
  }
  if (entry.kind === 'voice') return sendVoiceBlob(entry);
}
// Append the red failed bubbles for the open conversation (called after every repaint).
function renderFailedSends(box) {
  const list = failedSends.get(draftKey());
  if (!list || !list.length) return;
  for (const e of list) {
    const el = document.createElement('div');
    el.className = 'bubble out failed';
    const tx = document.createElement('span');
    tx.className = 'msg-text';
    tx.textContent = failedLabel(e);
    el.appendChild(tx);
    const row = document.createElement('div');
    row.className = 'failed-row';
    const note = document.createElement('span');
    note.className = 'failed-note';
    note.textContent = 'Not sent';
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'failed-btn';
    retry.textContent = 'Retry';
    retry.onclick = (ev) => { ev.stopPropagation(); el.remove(); retryFailedSend(e); };
    const drop = document.createElement('button');
    drop.type = 'button';
    drop.className = 'failed-btn';
    drop.textContent = 'Discard';
    drop.onclick = (ev) => { ev.stopPropagation(); dropFailedSend(e); el.remove(); };
    row.append(note, retry, drop);
    el.appendChild(row);
    box.appendChild(el);
  }
}

// "Request to chat": an explicit knock — the recipient's request screen shows a row
// without the sender having to compose a first message.
$('#th-knockbtn').onclick = async () => {
  const btn = $('#th-knockbtn');
  const username = cur.username;
  busy(btn, true, 'Sending…');
  try {
    await invoke('send_chat_request', { username });
    busy(btn, false);
    toast('Chat request sent', 'ok');
    $('#th-knock').hidden = true;
    if (cur.username === username && cur.peer) await renderThread(cur.peer); // system chip
    loadChats();
  } catch (e) { busy(btn, false); toast(say(e), 'err'); }
};

// In-app back buttons pop history so the state stack stays aligned with the UI
// (the popstate handler does the actual navigation).
$('#th-back').onclick = () => history.back();
$('#nc-back').onclick = () => history.back();
$('#se-back').onclick = () => history.back();

$('#nc-start').onclick = async () => {
  const u = $('#nc-user').value.trim();
  if (!u) return toast('Enter a username', 'err');
  openThread(u, null); // thread header shows its own verifying spinner
};
$('#nc-user').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#nc-start').click(); });

// A group thread reuses the thread screen; chat-only chrome hides itself.
async function openGroup(groupId, name) {
  saveDraft(); // park the previous chat's composer state before switching
  threadWin.delete(groupId); // fresh open: back to the default window
  cur = { kind: 'group', peer: groupId, username: name, verified: false, safety: '', keyChanged: false, timer: null, blocked: false, left: false };
  cur.avatar = (lastConvs.find((x) => x.kind === 'group' && x.peer === groupId) || {}).avatar || null;
  setAvatarEl($('#th-avatar'), cur.avatar, name, true, groupId);
  show('thread');
  // Group header shows the name alone — no roster line; the timer badge rides the
  // avatar (chat-list style) instead of a chip eating header width.
  $('#th-name').textContent = ell25(name);
  $('#th-sub').hidden = true;
  $('#th-keychange').hidden = true;
  $('#th-timerchip').hidden = true;
  $('#th-blocked').hidden = true;
  $('#th-left').hidden = true;
  $('#th-knock').hidden = true;
  $('#th-pinbar').hidden = true;
  if (!gifOk) probeGif(); // unlock-time probe may have raced the network — retry
  $('#th-mic').hidden = false;
  $('#th-call').hidden = false; // group voice call (mesh; voice-only)
  cancelVoice();
  stopNowPlaying();
  restoreDraft();
  await renderGroupThread(groupId);
  invoke('set_open_chat', { peer: groupId }).catch(() => {});
  try { await invoke('mark_group_seen', { groupId }); } catch (_) {}
  invoke('clear_group_unread_on_open', { groupId }).then(loadChats).catch(() => {});
  // Mobile: never autofocus on open — it pops the keyboard over the thread the user
  // came to read. Tapping the composer is the "I want to type" signal.
  if (!IS_ANDROID) $('#th-input').focus();
}

async function renderGroupThread(groupId, anchor) {
  let t;
  try {
    t = await invoke('group_thread', { groupId, limit: winFor(groupId), anchor: anchor || null });
  } catch (e) { return; }
  curMore = t.more;
  threadWin.set(groupId, Math.max(winFor(groupId), t.messages.length));
  cur.avatar = t.avatar || null;
  setAvatarEl($('#th-avatar'), cur.avatar, t.name, true, groupId);
  cur.username = t.name;
  // Name only in the group header (clamped) — the roster lives in group settings now.
  $('#th-name').textContent = ell25(t.name);
  $('#th-sub').hidden = true;
  cur.members = t.members; // roster for @mention autocomplete + highlighting
  cur.isAdmin = !!t.is_admin;
  cur.admin = t.admin || null;
  const mset = new Set(t.members.map((u) => u.toLowerCase()));
  // Left (or removed): the thread stays readable, everything that sends is hidden.
  cur.left = !!t.left;
  $('#th-left').hidden = !cur.left;
  $('#th-form').style.display = cur.left ? 'none' : '';
  $('#th-mic').hidden = cur.left;
  $('#th-call').hidden = cur.left;
  // Group disappearing timer: badge over the avatar, chat-list style (no header chip).
  cur.timer = t.timer_secs ?? null;
  $('#th-timerchip').hidden = true;
  paintGroupAvatarTimer();
  const box = $('#th-thread');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80 || !box.childElementCount;
  const keep = box.scrollTop;
  const rows = t.messages.map((m) => ({ ...m, direction: m.mine ? 'outgoing' : 'incoming' }));
  // Roster in the signature: a membership change re-renders bubbles because it can
  // re-color @mention chips, even though the messages themselves didn't change.
  reconcileThread(box, threadItems(rows, (m, grp) => groupBubble(m, grp, mset), '|' + t.members.join(',')));
  const dividerEl = box.querySelector('.unread-div');
  renderFailedSends(box);
  if (dividerEl && nearBottom) {
    dividerEl.scrollIntoView({ block: 'center' });
    newSinceScroll = 0;
  } else {
    box.scrollTop = nearBottom ? box.scrollHeight : keep;
  }
  updateTypingBubble(); // repaint wiped it; the bubble is always the last element
  updateJumpFab();
  updatePinBar(t.pinned); // window-independent — a pin renders in the banner however old
}

// Timer badge over the header avatar for groups — same look as the chat list's.
function paintGroupAvatarTimer() {
  const av = $('#th-avatar');
  av.querySelectorAll('.av-timer').forEach((n) => n.remove());
  if (cur.kind === 'group' && cur.timer) {
    av.insertAdjacentHTML('beforeend', `<span class="av-timer">${icon('clock')}${tlabel(cur.timer)}</span>`);
  }
}

// One group-chat bubble (the 1:1 equivalent is `bubble()` below). `mset` is the
// lowercase roster set for @mention highlighting.
function groupBubble(m, grp, mset) {
  const el = document.createElement('div');
  el.className = 'bubble ' + (m.mine ? 'out' : 'in') + (grp ? ' ' + grp : '');
  el.dataset.msgId = m.msg_id || '';
  // Sender name only on the first bubble of a cluster (not for our own).
  const senderSpan = (!m.mine && (grp === '' || grp === 'grp-top')) ? (() => {
    const who = document.createElement('span');
    who.className = 'sender'; who.textContent = m.sender_name;
    return who;
  })() : null;
  // Groups have no receipts, so "mine" tops out at a single sent tick — honest, and
  // it still separates "handed to the relay" from the optimistic spinner.
  const edited = m.edited ? '<span class="edited-tag">edited</span>' : '';
  const meta = m.mine ? statusIcon('sent') : '';
  const pinMark = m.pinned ? `<span class="pin-mark">${icon('pin')}</span>` : '';
  const timeHtml = (grp === '' || grp === 'grp-bot') ? `<span class="t">${pinMark}${edited}${hhmm(m.sent_at)}${meta}</span>` : (pinMark ? `<span class="t">${pinMark}</span>` : '');
  if (m.forwarded) el.insertAdjacentHTML('afterbegin', `<span class="fwd-tag">${icon('send')}Forwarded</span>`);
  if (m.attachment) {
    // Same renderers as 1:1 (image preview / file chip / voice player); they fetch
    // through cur.peer, which is the group id here — attachment_ref resolves both.
    // They own el.innerHTML, so the sender label is prepended after.
    (m.voice ? renderVoice : renderAttachment)(el, m, timeHtml, false);
    if (senderSpan) el.prepend(senderSpan);
    if (m.caption) {
      const cap = document.createElement('div');
      cap.className = 'caption';
      cap.appendChild(formatText(m.caption, mset));
      el.appendChild(cap);
    }
  } else {
    if (senderSpan) el.appendChild(senderSpan);
    if (m.reply_to_id) {
      const q = document.createElement('span');
      q.className = 'quote'; q.dataset.jump = m.reply_to_id;
      q.textContent = m.reply_preview || '';
      q.onclick = (e) => { e.stopPropagation(); jumpToMsg(q.dataset.jump); };
      el.appendChild(q);
    }
    const tx = document.createElement('span');
    tx.className = 'msg-text';
    tx.appendChild(formatText(m.body, mset));
    el.appendChild(tx);
    if (timeHtml) el.insertAdjacentHTML('beforeend', timeHtml);
  }
  if (m.delete_at) el.appendChild(expiryBadge(m.delete_at));
  renderReactions(el, m);
  // Full message actions in groups — the same hover icons / long-press sheet /
  // context menu as 1:1 (msgMenu routes each action to the group backend).
  if (m.msg_id) wireMsgActions(el, m);
  return el;
}

async function openThread(username, knownPeer, display) {
  saveDraft(); // park the previous chat's composer state before switching
  if (knownPeer) threadWin.delete(knownPeer); // fresh open: back to the default window
  cur = { kind: 'chat', peer: knownPeer, username, display: display || username, verified: false, safety: '', keyChanged: false, timer: null, blocked: false };
  cur.avatar = (lastConvs.find((x) => x.kind === 'chat' && x.username === username) || {}).avatar || null;
  setAvatarEl($('#th-avatar'), cur.avatar, cur.display, false, username);
  show('thread');
  $('#th-left').hidden = true;
  $('#th-knock').hidden = true;
  $('#th-pinbar').hidden = true;
  $('#th-form').style.display = '';
  if (!gifOk) probeGif(); // unlock-time probe may have raced the network — retry
  $('#th-mic').hidden = false;
  $('#th-call').hidden = false;
  cancelVoice();
  stopNowPlaying();
  restoreDraft();
  $('#th-name').textContent = ell25(cur.display);
  $('#th-sub').hidden = false;
  $('#th-sub').innerHTML = '<span class="spinner-sm"></span> verifying key…';
  $('#th-keychange').hidden = true;
  $('#th-searchbar').hidden = true;
  $('#th-timerchip').hidden = true;
  if (knownPeer) await renderThread(knownPeer); else $('#th-thread').innerHTML = '';
  // Re-resolve the contact (KT-verified) — establishes/refreshes the session, and detects
  // a key change before we ever show a composer the user trusts.
  try {
    const r = await invoke('open_chat', { username });
    cur.peer = r.peer;
    cur.safety = r.safety_number;
    cur.verified = r.verified;
    if (r.status === 'key_changed') {
      cur.keyChanged = true;
      $('#th-kc-num').textContent = spaced(r.safety_number);
      $('#th-keychange').hidden = false;
      $('#th-sub').textContent = 'key changed — verify';
    } else {
      updateBadge();
      await renderThread(r.peer);
      markSeen(); // tell the sender we opened it
      invoke('set_open_chat', { peer: r.peer }).catch(() => {});
      invoke('clear_unread_on_open', { username: cur.username }).catch(() => {});
      loadChats(); // clear the unread badge in the list behind this screen
      // Mobile: no autofocus (keyboard would pop over the thread); tap to type.
      if (!IS_ANDROID) $('#th-input').focus();
      // Blocked contact? Show the banner (their traffic is being dropped).
      try {
        const c = (await invoke('conversations')).find((x) => x.kind === 'chat' && x.username === cur.username);
        cur.blocked = !!(c && c.blocked);
        $('#th-blocked').hidden = !cur.blocked;
      } catch (_) {}
    }
  } catch (e) {
    // No such account: for a brand-new chat (typed in "new chat") don't leave a dead
    // thread open — go back to the form so a typo is a two-second fix. For an
    // existing chat (deleted/released account) keep the history visible with a note.
    if (/doesn't exist/.test(say(e))) {
      if (!knownPeer) {
        show('newchat');
        toast(`No user named “${username}”`, 'err');
        const inp = $('#nc-user');
        inp.focus(); inp.select();
        return;
      }
      $('#th-sub').textContent = 'account no longer exists';
      return;
    }
    $('#th-sub').textContent = 'offline';
    toast(say(e), 'err');
  }
}

function updateBadge() {
  cur.subBase = cur.verified ? 'verified · tap for settings' : 'tap for chat settings';
  $('#th-sub').textContent = cur.subBase;
  const b = $('#th-badge');
  b.className = 'badge ' + (cur.verified ? 'verified' : 'unverified');
  b.innerHTML = cur.verified ? icon('shield') + ' Verified' : 'Not yet verified';
}

function syncTimerUi() {
  const chip = $('#th-timerchip');
  chip.hidden = !cur.timer;
  if (cur.timer) $('#th-timerchip-label').textContent = tlabel(cur.timer);
  $$('#th-timeropts .topt').forEach((b) => {
    const secs = b.dataset.secs ? Number(b.dataset.secs) : null;
    b.classList.toggle('on', secs === (cur.timer ?? null));
  });
}

// Consecutive same-sender bubbles within this window cluster together (G).
const GROUP_WINDOW = 300;
function sameCluster(a, b) {
  if (!a || !b || a.system || b.system) return false;
  if (a.direction !== b.direction) return false;
  if (relday(a.sent_at) !== relday(b.sent_at)) return false;
  return Math.abs((a.sent_at || 0) - (b.sent_at || 0)) <= GROUP_WINDOW;
}
// ── Flicker-free repaint ────────────────────────────────────────────────────────
// Every sync event repaints the open thread. Wiping innerHTML re-created every node:
// animated GIFs restarted, images re-decoded, players reset — the pane visibly
// blinked on each receipt/reaction/arrival. Instead the thread is RECONCILED: each
// row carries a key (message id) and a content signature (serialized message view +
// cluster position); rows whose signature is unchanged keep their live DOM node,
// changed ones are rebuilt in place, and ordering is fixed with minimal moves. The
// common case during active chatting — one appended bubble, one tick flip — is two
// DOM ops and zero flicker.
//
// Unkeyed strays (optimistic bubbles, failed-send rows — both re-added by their
// owners right after every repaint) are dropped; the typing bubble survives because
// updateTypingBubble re-anchors the SAME node to the end afterwards.
function reconcileThread(box, items) {
  const want = new Set(items.map((it) => it.key));
  for (const el of [...box.children]) {
    if (el.id === 'th-typing') continue;
    if (!el.dataset.rkey || !want.has(el.dataset.rkey)) el.remove();
  }
  const have = new Map();
  for (const el of box.children) if (el.dataset.rkey) have.set(el.dataset.rkey, el);
  const nodes = items.map((it) => {
    const old = have.get(it.key);
    if (old && old.dataset.rsig === it.sig) return old;
    const el = it.build();
    el.dataset.rkey = it.key;
    el.dataset.rsig = it.sig;
    if (old) {
      // In-place rebuild (a tick flip, a reaction): no entrance animation — only
      // genuinely NEW rows get the pop, or the whole pane appears to blink.
      el.style.animation = 'none';
      old.replaceWith(el);
    }
    return el;
  });
  // Order pass: walk expected vs actual; an append-mostly repaint takes the fast
  // path (zero moves). insertBefore with a null ref appends.
  let ptr = box.firstElementChild;
  for (const el of nodes) {
    while (ptr && ptr.id === 'th-typing') ptr = ptr.nextElementSibling;
    if (el === ptr) { ptr = ptr.nextElementSibling; continue; }
    box.insertBefore(el, ptr);
  }
}
// Build the reconciler's item list from a message window: day separators, the
// unread divider, system chips, and bubbles — `mkBubble(m, grp)` supplies the
// chat-flavor-specific bubble builder, `extraSig` folds surrounding state that
// changes a bubble's rendering without appearing in the message itself (the group
// roster, for mention highlighting).
function threadItems(msgs, mkBubble, extraSig) {
  const items = [];
  let lastDay = '';
  const firstUnread = msgs.findIndex((m) => m.unread);
  for (let i = 0; i < msgs.length; i++) {
    const m = msgs[i];
    const day = relday(m.sent_at);
    if (day !== lastDay) {
      items.push({
        key: 'd:' + day, sig: day,
        build: () => {
          const sep = document.createElement('div');
          sep.className = 'daysep'; sep.dataset.day = day; sep.textContent = day;
          return sep;
        },
      });
      lastDay = day;
    }
    if (i === firstUnread && firstUnread > 0) {
      items.push({
        key: 'unread', sig: String(m.msg_id || m.sent_at),
        build: () => {
          const div = document.createElement('div');
          div.className = 'unread-div'; div.textContent = 'new messages';
          return div;
        },
      });
    }
    const key = m.msg_id ? 'm:' + m.msg_id : 'x:' + m.sent_at + ':' + i;
    const grp = m.system ? '' : groupPos(m, msgs[i - 1], msgs[i + 1]);
    const sig = JSON.stringify(m) + '|' + grp + (extraSig || '');
    items.push({ key, sig, build: m.system ? () => sysChip(m) : () => mkBubble(m, grp) });
  }
  return items;
}

function groupPos(m, prev, next) {
  const withPrev = sameCluster(m, prev), withNext = sameCluster(m, next);
  if (withPrev && withNext) return 'grp-mid';
  if (!withPrev && withNext) return 'grp-top';
  if (withPrev && !withNext) return 'grp-bot';
  return '';
}
function sysChip(m) {
  const el = document.createElement('div');
  // Call-history chips (body carries the 📞 marker) get their own look: phone icon,
  // outcome text, and the time-of-day — a missed call stays discoverable in the
  // timeline long after its toast/notification is gone.
  if (m.body.startsWith('📞')) {
    el.className = 'sysmsg callchip' + (/Missed|Declined|Unanswered/.test(m.body) ? ' bad' : '');
    el.innerHTML = `<span class="cc-ico">${icon('phone')}</span>`;
    const tx = document.createElement('span');
    tx.textContent = m.body.replace(/^📞\s*/, '');
    const time = document.createElement('span');
    time.className = 'cc-time';
    time.textContent = hhmm(m.sent_at);
    el.append(tx, time);
    return el;
  }
  el.className = 'sysmsg';
  el.textContent = m.body;
  return el;
}

async function renderThread(peer, anchor) {
  let msgs = [], total = 0, pins = [];
  try {
    const t = await invoke('thread', { peer, limit: winFor(peer), anchor: anchor || null });
    msgs = t.messages;
    total = t.total;
    pins = t.pinned;
    curMore = t.more;
    // An anchor/unread extension is a real window growth — keep it across repaints.
    threadWin.set(peer, Math.max(winFor(peer), msgs.length));
    cur.timer = t.timer_secs ?? null;
    syncTimerUi();
  } catch (e) { return; }
  // Brand-new 1:1 chat (nothing ever sent): offer an explicit "Request to chat" so a
  // knock reaches their request screen without the sender having to compose anything.
  $('#th-knock').hidden = !(cur.kind === 'chat' && !cur.note && !cur.keyChanged && total === 0);
  const box = $('#th-thread');
  // Keep the reading position unless the user is already near the bottom (or it's a
  // fresh open) — a repaint must never yank them away from what they're reading.
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80 || !box.childElementCount;
  const keep = box.scrollTop;
  reconcileThread(box, threadItems(msgs, (m, grp) => bubble(m, false, grp)));
  const dividerEl = box.querySelector('.unread-div');
  renderFailedSends(box);
  // Track new arrivals while scrolled up to drive the jump-FAB counter. Uses the
  // conversation TOTAL, not the window length — paging older history in isn't "new".
  if (!nearBottom && cur.lastCount != null && total > cur.lastCount) {
    newSinceScroll += total - cur.lastCount;
  }
  cur.lastCount = total;
  // On open with unread present, land on the divider, not the very bottom.
  if (dividerEl && nearBottom) {
    dividerEl.scrollIntoView({ block: 'center' });
    newSinceScroll = 0;
  } else if (nearBottom) {
    box.scrollTop = box.scrollHeight;
    newSinceScroll = 0;
  } else {
    box.scrollTop = keep;
  }
  updateTypingBubble(); // repaint wiped it; the bubble is always the last element
  updateJumpFab();
  updateStickyDate();
  updatePinBar(pins); // window-independent — a pin renders in the banner however old
}
const IMG_EXT = /\.(png|jpe?g|gif|webp|avif|bmp)$/i;
const VIDEO_EXT = /\.(mp4|webm|mov|m4v|3gpp?|ogv)$/i;
// Decrypted previews, this session only — LRU-bounded so a heavy image/video chat
// can't grow memory until the next lock (an evicted entry just re-fetches).
const imgCache = new LruCache({ max: 200, budget: 48 * 1024 * 1024, cost: (v) => v.length }); // msg_id -> data URL
const vidCache = new LruCache({ max: 6, onEvict: (url) => URL.revokeObjectURL(url) });        // msg_id -> blob URL
function mimeFor(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
           webp: 'image/webp', avif: 'image/avif', bmp: 'image/bmp' }[ext] || 'application/octet-stream';
}
function videoMime(name) {
  const ext = (String(name).split('.').pop() || '').toLowerCase();
  return { mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime', m4v: 'video/x-m4v',
           '3gp': 'video/3gpp', '3gpp': 'video/3gpp', ogv: 'video/ogg' }[ext] || 'video/mp4';
}
// Decrypt a video attachment to a session-lifetime blob URL (cached — a replay or a
// gallery open never re-downloads).
async function loadVideoUrl(peer, m) {
  let url = vidCache.get(m.msg_id);
  if (url) return url;
  const b64 = await invoke('fetch_attachment', { peer, msgId: m.msg_id });
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  url = URL.createObjectURL(new Blob([bytes], { type: videoMime(m.body) }));
  vidCache.set(m.msg_id, url);
  return url;
}

// Parse inline markers (*bold* _italic_ `mono` ~strike~ ||spoiler||) into DOM nodes.
// No innerHTML of user text — everything is textContent, so it's escaped by construction.
// Single-level only (no nesting), which is enough and keeps the tokenizer tiny.
const FMT_PATTERNS = [
  { re: /\|\|([\s\S]+?)\|\|/, kind: 'spoiler' },
  { re: /\*([^*\n]+?)\*/, kind: 'b' },
  { re: /_([^_\n]+?)_/, kind: 'i' },
  { re: /~([^~\n]+?)~/, kind: 's' },
  { re: /`([^`\n]+?)`/, kind: 'code' },
];
function fmtNode(kind, inner) {
  if (kind === 'spoiler') {
    const sp = document.createElement('span');
    sp.className = 'spoiler';
    const t = document.createElement('span');
    t.textContent = inner;
    sp.appendChild(t);
    sp.onclick = (e) => { e.stopPropagation(); sp.classList.add('revealed'); };
    return sp;
  }
  const tag = kind === 'b' ? 'strong' : kind === 'i' ? 'em' : kind === 's' ? 's' : 'code';
  const el = document.createElement(tag);
  if (kind === 'code') el.className = 'mono-inline';
  el.textContent = inner;
  return el;
}
// Append `text` as text nodes, upgrading @username tokens that name a real roster
// member (`mentions` = lowercase username set) into highlighted mention chips — our own
// name gets the louder `.me` style. Everything stays textContent (escaped by construction).
function appendTextWithMentions(frag, text, mentions) {
  if (!mentions || !mentions.size || !text.includes('@')) {
    frag.appendChild(document.createTextNode(text));
    return;
  }
  const re = /@([A-Za-z0-9_.-]+)/g;
  let last = 0, mm;
  while ((mm = re.exec(text))) {
    const name = mm[1].toLowerCase();
    // Only real members highlight, and only at a token boundary (not mid-word/email).
    const before = text[mm.index - 1];
    if (!mentions.has(name) || (before && /[A-Za-z0-9_.@-]/.test(before))) continue;
    if (mm.index > last) frag.appendChild(document.createTextNode(text.slice(last, mm.index)));
    const sp = document.createElement('span');
    sp.className = 'mention' + (name === (myName || '').toLowerCase() ? ' me' : '');
    sp.textContent = mm[0];
    frag.appendChild(sp);
    last = mm.index + mm[0].length;
  }
  if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
}
function formatText(text, mentions) {
  const frag = document.createDocumentFragment();
  let rest = String(text);
  let guard = 0;
  while (rest && guard++ < 5000) {
    let best = null;
    for (const p of FMT_PATTERNS) {
      const m = p.re.exec(rest);
      if (m && (!best || m.index < best.m.index)) best = { p, m };
    }
    if (!best) { appendTextWithMentions(frag, rest, mentions); break; }
    if (best.m.index > 0) appendTextWithMentions(frag, rest.slice(0, best.m.index), mentions);
    frag.appendChild(fmtNode(best.p.kind, best.m[1]));
    rest = rest.slice(best.m.index + best.m[0].length);
  }
  return frag;
}
// Strip markers for previews (chat-list last-message line).
function stripMarkers(text) {
  return String(text).replace(/\|\|([\s\S]+?)\|\||[*_~`]([^*_~`\n]+?)[*_~`]/g, (_, a, b) => a || b);
}

function bubble(m, optimistic, grpPos = '') {
  const el = document.createElement('div');
  el.className = 'bubble ' + (m.direction === 'outgoing' ? 'out' : 'in') + (grpPos ? ' ' + grpPos : '');
  el.dataset.msgId = m.msg_id || '';
  el.dataset.ts = m.sent_at || 0;
  const edited = m.edited ? '<span class="edited-tag">edited</span>' : '';
  const meta = m.direction === 'outgoing' ? statusIcon(optimistic ? 'sending' : m.status) : '';
  const pinMark = m.pinned ? `<span class="pin-mark">${icon('pin')}</span>` : '';
  // Timestamp only on the last bubble of a cluster (or a standalone one).
  const showTime = optimistic || grpPos === '' || grpPos === 'grp-bot';
  const time = showTime ? `<span class="t">${pinMark}${edited}${hhmm(m.sent_at)}${meta}</span>` : (pinMark ? `<span class="t">${pinMark}</span>` : '');
  if (m.forwarded) el.insertAdjacentHTML('afterbegin', `<span class="fwd-tag">${icon('send')}Forwarded</span>`);
  if (m.attachment && m.voice) {
    renderVoice(el, m, time, optimistic);
  } else if (m.attachment) {
    renderAttachment(el, m, time, optimistic);
  } else {
    if (m.reply_to_id) {
      const q = document.createElement('span');
      q.className = 'quote'; q.dataset.jump = m.reply_to_id;
      q.textContent = m.reply_preview || '';
      el.appendChild(q);
    }
    const tx = document.createElement('span');
    tx.className = 'msg-text';
    tx.appendChild(formatText(m.body));
    el.appendChild(tx);
    if (time) el.insertAdjacentHTML('beforeend', time);
  }
  // Caption under an attachment, in the same bubble.
  if (m.caption) {
    const cap = document.createElement('div');
    cap.className = 'caption';
    cap.appendChild(formatText(m.caption));
    el.appendChild(cap);
  }
  // Disappearing message: per-message countdown badge (removed live at expiry).
  if (m.delete_at) el.appendChild(expiryBadge(m.delete_at));
  if (!optimistic) renderReactions(el, m);
  const q = el.querySelector('.quote');
  if (q) q.onclick = (e) => { e.stopPropagation(); jumpToMsg(q.dataset.jump); };
  if (!optimistic && m.msg_id && cur.kind === 'chat') wireMsgActions(el, m);
  return el;
}

// ── Disappearing-message countdown ────────────────────────────────────────────────
// Remaining time, short form ("3d" / "5h" / "12m"), rounded up. Minute granularity
// minimum — no seconds ticking away in the badge; the bubble still vanishes at the
// exact expiry second.
function fmtLeft(s) {
  if (s >= 86400) return Math.ceil(s / 86400) + 'd';
  if (s >= 3600) return Math.ceil(s / 3600) + 'h';
  return Math.max(1, Math.ceil(s / 60)) + 'm';
}
// Per-message countdown badge (ticked by the global 1s timer below).
function expiryBadge(deleteAt) {
  const ex = document.createElement('span');
  ex.className = 'expiry';
  ex.dataset.deleteAt = deleteAt;
  ex.title = 'Disappearing message';
  ex.innerHTML = icon('clock') + '<span class="expiry-left"></span>';
  ex.querySelector('.expiry-left').textContent = fmtLeft(deleteAt - Math.floor(Date.now() / 1000));
  return ex;
}
// One global 1s ticker: refresh every badge and drop bubbles the moment they expire.
// The backend reaper deletes them from the sealed history on its own tick; this only
// makes the vanish instant on screen.
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  $$('#th-thread .expiry').forEach((ex) => {
    const left = Number(ex.dataset.deleteAt || 0) - now;
    if (left <= 0) {
      const b = ex.closest('.bubble');
      if (b) b.remove();
      return;
    }
    const t = ex.querySelector('.expiry-left');
    if (t) t.textContent = fmtLeft(left);
  });
}, 1000);

async function jumpToMsg(msgId) {
  const find = () => $(`#th-thread .bubble[data-msg-id="${CSS.escape(msgId)}"]`);
  let t = find();
  // Not rendered but older history exists: re-render anchored on the target (the
  // backend extends the window back to it), then jump.
  if (!t && curMore && cur.peer) {
    await (cur.kind === 'group' ? renderGroupThread(cur.peer, msgId) : renderThread(cur.peer, msgId));
    t = find();
  }
  if (!t) return toast('Original message is gone', 'err');
  t.scrollIntoView({ block: 'center', behavior: 'smooth' });
  t.classList.add('hl');
  setTimeout(() => t.classList.remove('hl'), 1200);
}

// An attachment bubble: images decrypt + preview inline; videos get an inline player
// behind a tap-to-play tile (decrypting every video on render would hammer the relay);
// anything else is a file chip. Clicking a chip saves the decrypted file to Downloads.
function renderAttachment(el, m, time, uploading) {
  const name = m.body || 'file';
  if (VIDEO_EXT.test(name) && !uploading) {
    el.innerHTML =
      `<button type="button" class="att-vid" title="${escapeHtml(name)}">
         <span class="att-vid-play">${icon('play')}</span>
         <span class="att-vid-name">${escapeHtml(name)}</span>
       </button>${time}`;
    const peer = cur.peer;
    const tile = el.querySelector('.att-vid');
    tile.onclick = async (e) => {
      e.stopPropagation();
      tile.disabled = true;
      tile.querySelector('.att-vid-play').innerHTML = '<span class="spinner-sm"></span>';
      try {
        const url = await loadVideoUrl(peer, m);
        stopNowPlaying(); // a voice note must not talk over the video
        const wrap = document.createElement('div');
        wrap.className = 'att-vidwrap';
        const v = document.createElement('video');
        v.className = 'att-video';
        v.controls = true;
        v.playsInline = true;
        v.autoplay = true;
        v.src = url;
        wrap.appendChild(v);
        // The webview's native fullscreen control is dead on some platforms (no
        // fullscreen plumbing in the shell), so ship our own: expand into the
        // full-viewport video overlay, continuing from the inline position.
        const fs = document.createElement('button');
        fs.type = 'button'; fs.className = 'icon-btn att-vid-fs'; fs.title = 'Fullscreen';
        fs.innerHTML = icon('expand');
        fs.onclick = (e) => {
          e.stopPropagation();
          const at = v.currentTime;
          const paused = v.paused;
          v.pause();
          openVidbox(url, peer, m.msg_id);
          const bv = $('#vb2-video');
          const seek = () => { bv.currentTime = at; if (paused) bv.pause(); };
          if (bv.readyState >= 1) seek();
          else bv.addEventListener('loadedmetadata', seek, { once: true });
        };
        wrap.appendChild(fs);
        tile.replaceWith(wrap);
      } catch (err) {
        tile.disabled = false;
        tile.querySelector('.att-vid-play').innerHTML = icon('play');
        toast('Video failed: ' + say(err), 'err');
      }
    };
    return;
  }
  if (IMG_EXT.test(name) && !uploading) {
    el.innerHTML = `<div class="att-loading"><span class="spinner-sm"></span></div>${time}`;
    const peer = cur.peer;
    (async () => {
      try {
        const b64 = imgCache.get(m.msg_id) ||
          `data:${mimeFor(name)};base64,` + await invoke('fetch_attachment', { peer, msgId: m.msg_id });
        imgCache.set(m.msg_id, b64);
        const holder = el.querySelector('.att-loading');
        if (!holder) return;
        const img = document.createElement('img');
        img.className = 'att-img';
        img.src = b64;
        img.title = name + ' — click to view';
        img.onclick = () => openLightbox(b64, peer, m.msg_id);
        holder.replaceWith(img);
      } catch (e) {
        const holder = el.querySelector('.att-loading');
        if (holder) holder.outerHTML = fileChipHtml(name, 'download failed — tap to retry');
        wireChip(el, m);
      }
    })();
  } else {
    el.innerHTML = `${fileChipHtml(name, uploading ? 'encrypting & uploading…' : 'tap to save as…')}${time}`;
    if (!uploading) wireChip(el, m);
  }
}
function fileChipHtml(name, sub) {
  return `<span class="att-chip"><span class="att-ico">${icon('file')}</span><span><span class="att-name">${escapeHtml(name)}</span><span class="att-sub">${escapeHtml(sub)}</span></span></span>`;
}
function wireChip(el, m) {
  const chip = el.querySelector('.att-chip');
  if (chip) chip.onclick = () => saveAtt(cur.peer, m.msg_id);
}
async function saveAtt(peer, msgId) {
  try {
    const path = await invoke('save_attachment', { peer, msgId }); // native Save-As dialog
    if (path) toast('Saved to ' + path, 'ok'); // null = user cancelled
  } catch (e) { toast('Save failed: ' + say(e), 'err'); }
}

