// ═══════════════════════════════════════════════════════════════════════════════
// Message actions: reactions, long-press sheet, context menu, reply/edit/delete/
// forward. Split from 30-thread.js (no-monolith ratchet); everything here is
// conversation-agnostic — msgMenu routes each action to the 1:1 or group backend.
// ═══════════════════════════════════════════════════════════════════════════════

// Render reaction chips under a bubble; clicking a chip toggles our own reaction.
// Only the first two emoji groups show as chips — the rest collapse into a "+N"
// chip (N = hidden reaction count) so a well-reacted message can't stretch its
// bubble. "+N" (or long-press/right-click on any chip) opens the details sheet.
const MAX_REACTION_CHIPS = 2;
function renderReactions(el, m) {
  if (!m.reactions || !m.reactions.length) return;
  const wrap = document.createElement('div');
  wrap.className = 'reactions';
  const details = (e) => { e.preventDefault(); e.stopPropagation(); reactionDetails(m); };
  for (const r of m.reactions.slice(0, MAX_REACTION_CHIPS)) {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'react-chip' + (r.mine ? ' mine' : '');
    chip.innerHTML = `<span>${escapeHtml(r.emoji)}</span>` + (r.count > 1 ? `<span class="rc-count">${r.count}</span>` : '');
    chip.onclick = (e) => { e.stopPropagation(); toggleReaction(m, r.emoji, !r.mine); };
    chip.oncontextmenu = details;
    // Keep the bubble's own long-press (message sheet) out of chip holds.
    chip.addEventListener('touchstart', (e) => e.stopPropagation(), { passive: true });
    onHold(chip, () => reactionDetails(m));
    wrap.appendChild(chip);
  }
  const rest = m.reactions.slice(MAX_REACTION_CHIPS);
  if (rest.length) {
    const more = document.createElement('button');
    more.type = 'button';
    more.className = 'react-chip rc-more';
    more.textContent = `+${rest.reduce((n, r) => n + r.count, 0)}`;
    more.onclick = details;
    more.addEventListener('touchstart', (e) => e.stopPropagation(), { passive: true });
    wrap.appendChild(more);
  }
  el.appendChild(wrap);
}

// Who reacted with what: one row per emoji, names + count. Tapping a row toggles our
// own reaction with that emoji (same as tapping its chip).
function reactionDetails(m) {
  const rows = m.reactions.map((r, i) =>
    `<button type="button" class="rd-row" data-i="${i}">
       <span class="rd-emoji">${escapeHtml(r.emoji)}</span>
       <span class="rd-who">${escapeHtml((r.reactors || []).join(', '))}</span>
       <span class="rd-count">${r.count}</span>
     </button>`).join('');
  const card = openModal(`<h3>Reactions</h3><div class="rd-list">${rows}</div>`);
  $$('.rd-row', card).forEach((row) => {
    row.onclick = () => {
      const r = m.reactions[Number(row.dataset.i)];
      closeModal();
      if (r) toggleReaction(m, r.emoji, !r.mine);
    };
  });
}

// The DEFAULT quick-react set. What actually renders is `quickReactionEmoji()`
// (38-emoji.js): the user's most-used reactions first, these filling the rest.
const QUICK_EMOJI = ['👍', '❤️', '😂', '😮', '😢', '🔥', '✅'];

// The "+" at the end of every quick-react row: the FULL picker (any emoji, search,
// skin tones), reacting through the exact same toggle path. `closer` dismisses
// whatever surface hosted the row before the picker opens.
function reactMoreButton(m, closer) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'react-more';
  b.innerHTML = icon('plus');
  b.title = 'More reactions';
  b.onclick = (ev) => {
    ev.stopPropagation();
    const at = b.getBoundingClientRect();
    closer();
    openEmojiPicker({
      x: at.left,
      y: at.top,
      onPick: (em) => {
        const mine = (m.reactions || []).some((r) => r.emoji === em && r.mine);
        toggleReaction(m, em, !mine);
      },
    });
  };
  return b;
}
async function toggleReaction(m, emoji, add) {
  try {
    if (cur.kind === 'group') {
      await invoke('react_group', { groupId: cur.peer, msgId: m.msg_id, emoji, add });
      await renderGroupThread(cur.peer);
    } else {
      await invoke('react', { username: cur.username, peer: cur.peer, msgId: m.msg_id, emoji, add });
      await renderThread(cur.peer);
    }
    // Teach the adaptive quick row (adds only — removing isn't preference).
    if (add) noteReactionUsed(emoji);
  } catch (e) { toast('Reaction failed: ' + say(e), 'err'); }
}
// A small emoji picker anchored directly above the message (falls back to the pointer
// when no anchor is known). Clamped to the viewport on every side.
function openReactionPicker(x, y, m, anchor) {
  hideCtx();
  const p = $('#ctxmenu');
  p.innerHTML = '';
  p.className = 'react-picker';
  for (const e of quickReactionEmoji()) {
    const b = document.createElement('button');
    b.type = 'button'; b.textContent = e;
    const mine = (m.reactions || []).some((r) => r.emoji === e && r.mine);
    b.onclick = () => { hideCtx(); toggleReaction(m, e, !mine); };
    p.appendChild(b);
  }
  p.appendChild(reactMoreButton(m, hideCtx));
  p.hidden = false;
  const r = p.getBoundingClientRect();
  let left = x, top = y - r.height - 8;
  if (anchor) {
    const a = anchor.getBoundingClientRect();
    left = anchor.classList.contains('out') ? a.right - r.width : a.left;
    top = a.top - r.height - 8;
    // No room above (once the status bar is accounted for) → flip below the message.
    if (top < safeInsets().top + SAFE_GAP) top = a.bottom + 8;
  }
  const at = clampSafe(left, top, r.width, r.height);
  p.style.left = at.left + 'px';
  p.style.top = at.top + 'px';
}

// ── Mobile long-press sheet: dim everything, keep the pressed message in focus, show
//    the emoji row directly above it and the actions directly below (modern-messenger
//    pattern). Touch replaces both the hover icons and the plain context menu. ──────
let msheetEl = null;
function openMsgSheet(m, el, items) {
  hideCtx();
  const ov = $('#msheet');
  ov.innerHTML = '';
  const row = document.createElement('div');
  row.className = 'react-picker msheet-emoji';
  for (const e of quickReactionEmoji()) {
    const b = document.createElement('button');
    b.type = 'button'; b.textContent = e;
    const mine = (m.reactions || []).some((r) => r.emoji === e && r.mine);
    b.onclick = (ev) => { ev.stopPropagation(); closeMsgSheet(); toggleReaction(m, e, !mine); };
    row.appendChild(b);
  }
  row.appendChild(reactMoreButton(m, closeMsgSheet));
  ov.appendChild(row);
  let menu = null;
  if (items && items.length) {
    menu = document.createElement('div');
    menu.className = 'ctxmenu msheet-menu';
    for (const it of items) {
      const b = document.createElement('button');
      if (it.danger) b.className = 'danger';
      b.innerHTML = `${icon(it.icon || '')}${escapeHtml(it.label)}`;
      b.onclick = (ev) => { ev.stopPropagation(); closeMsgSheet(); it.fn(); };
      menu.appendChild(b);
    }
    ov.appendChild(menu);
  }
  ov.hidden = false;
  el.classList.add('msg-focus');
  msheetEl = el;
  // Anchor around the pressed bubble, clamped so nothing ever leaves the *usable* viewport
  // (status bar and gesture bar excluded — see `clampSafe`).
  const a = el.getBoundingClientRect();
  const out = el.classList.contains('out');
  const rw = row.getBoundingClientRect();
  const place = (node, w, h, top) => {
    const at = clampSafe(out ? a.right - w : a.left, top, w, h);
    node.style.left = at.left + 'px';
    node.style.top = at.top + 'px';
  };
  place(row, rw.width, rw.height, a.top - rw.height - 10);
  if (menu) {
    const mw = menu.getBoundingClientRect();
    place(menu, mw.width, mw.height, a.bottom + 10);
  }
  ov.onclick = closeMsgSheet;
}
function closeMsgSheet() {
  const ov = $('#msheet');
  ov.hidden = true; ov.innerHTML = '';
  if (msheetEl) { msheetEl.classList.remove('msg-focus'); msheetEl = null; }
}

// Touch-first UI (no hover): long-press opens the focused message sheet; the hover
// action icons are hidden entirely in CSS via (hover: none).
const TOUCH_UI = IS_ANDROID || window.matchMedia('(hover: none), (pointer: coarse)').matches;

// Hover (desktop): react + reply + ⋮ buttons. Hold/right-click (touch): the focused
// message sheet — emoji row above, actions below. Swipe right (touch): reply.
function wireMsgActions(el, m) {
  const acts = document.createElement('span');
  acts.className = 'msg-act';
  const eb = document.createElement('button');
  eb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M9 10h.01M15 10h.01"/><path d="M8.5 14.5a4 4 0 0 0 7 0"/></svg>';
  eb.title = 'React';
  eb.onclick = (e) => { e.stopPropagation(); openReactionPicker(e.clientX, e.clientY, m, el); };
  const rb = document.createElement('button');
  rb.innerHTML = icon('back'); rb.title = 'Reply';
  rb.onclick = (e) => { e.stopPropagation(); startReply(m); };
  const db = document.createElement('button');
  db.innerHTML = icon('gear') && '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="12" cy="19" r="1.8"/></svg>';
  db.title = 'Options';
  db.onclick = (e) => { e.stopPropagation(); showCtx(e.clientX, e.clientY, msgMenu(m, el)); };
  acts.append(eb, rb, db);
  el.appendChild(acts);
  const openMenu = (x, y) => TOUCH_UI
    ? openMsgSheet(m, el, msgMenu(m, el, true))
    : showCtx(x, y, msgMenu(m, el));
  el.oncontextmenu = (e) => { e.preventDefault(); e.stopPropagation(); openMenu(e.clientX, e.clientY); };
  onHold(el, openMenu);
  wireSwipeReply(el, m);
}

// ── Swipe right → reply (touch only) ─────────────────────────────────────────────
// The bubble tracks the finger: it slides right with a rubber-band past the arm point
// while a reply glyph fades in beside it and pops (plus a haptic tick) the moment the
// gesture arms — release then springs everything back and starts the reply. A mostly
// vertical move stays a scroll; a left move is ignored.
const SWIPE_ARM = 56;   // px of drag that arms the reply
const SWIPE_MAX = 84;   // hard cap on bubble travel
function wireSwipeReply(el, m) {
  let sx = null, sy = null, swiping = false, armed = false, glyph = null;
  const reset = () => {
    if (swiping) {
      el.classList.remove('swiping');
      el.classList.add('swipe-return'); // spring back (overshoot curve in CSS)
      el.style.transform = '';
      const g = glyph;
      setTimeout(() => { el.classList.remove('swipe-return'); if (g) g.remove(); }, 300);
    }
    sx = null; sy = null; swiping = false; armed = false; glyph = null;
  };
  el.addEventListener('touchstart', (e) => {
    // Not ours: multi-touch, the focused-message sheet, or a drag that starts on a
    // control with its own horizontal gesture (voice scrub bar, inline video).
    if (e.touches.length !== 1 || !$('#msheet').hidden ||
        (cur.kind === 'group' && cur.left) || // read-only thread: nothing to reply with
        e.target.closest('.vc-wave, .vc-btn, .vc-speed, .att-video')) { sx = null; return; }
    sx = e.touches[0].clientX; sy = e.touches[0].clientY;
  }, { passive: true });
  el.addEventListener('touchmove', (e) => {
    if (sx === null) return;
    const t = e.touches[0];
    const mx = t.clientX - sx, my = t.clientY - sy;
    if (!swiping) {
      if (Math.abs(mx) < 14) return;                 // undecided yet
      if (mx < 0 || Math.abs(my) > Math.abs(mx) * 0.8) { sx = null; return; } // scroll/left: not ours
      swiping = true;
      el.classList.add('swiping');
      glyph = document.createElement('span');
      glyph.className = 'swipe-reply-ico';
      glyph.innerHTML = icon('back');
      el.appendChild(glyph);
    }
    if (e.cancelable) e.preventDefault(); // gesture claimed: the thread must not scroll under it
    // Linear to the arm point, heavy rubber-band past it, hard-capped.
    const dx = Math.min(mx <= SWIPE_ARM ? mx : SWIPE_ARM + (mx - SWIPE_ARM) * 0.22, SWIPE_MAX);
    el.style.transform = `translateX(${dx}px)`;
    const p = Math.min(1, dx / SWIPE_ARM);
    glyph.style.opacity = p * p; // ease-in: barely there until the pull means it
    if (p >= 1 && !armed) {
      armed = true;
      el.classList.add('swipe-armed');
      if (navigator.vibrate) try { navigator.vibrate(10); } catch (_) {}
    } else if (p < 1 && armed) {
      armed = false;
      el.classList.remove('swipe-armed');
    }
  }, { passive: false });
  el.addEventListener('touchend', () => {
    const go = armed;
    el.classList.remove('swipe-armed');
    reset();
    if (go) startReply(m);
  });
  el.addEventListener('touchcancel', () => { el.classList.remove('swipe-armed'); reset(); });
}

// `skipReact`: the message sheet already shows the emoji row — no need for a menu row.
function msgMenu(m, anchorEl, skipReact) {
  const mine = m.direction === 'outgoing';
  // Left/removed group: everything that would SEND is off the table; local actions stay.
  const canSend = !(cur.kind === 'group' && cur.left);
  const items = [];
  if (!skipReact && canSend) {
    items.push({ label: 'React…', icon: 'check', fn: () => openReactionPicker(window.innerWidth / 2, window.innerHeight / 2, m, anchorEl) });
  }
  if (canSend) items.push({ label: 'Reply', icon: 'back', fn: () => startReply(m) });
  if (!m.attachment) {
    items.push({
      label: 'Copy', icon: 'file',
      fn: async () => {
        try { await navigator.clipboard.writeText(m.body); toast('Copied', 'ok'); }
        catch (_) { toast('Copy failed', 'err'); }
      },
    });
  }
  // Forward works for text AND attachments (the original blob is re-referenced —
  // nothing re-uploads); targets are chats, groups and note-to-self.
  items.push({ label: 'Forward…', icon: 'send', fn: () => forwardModal(m) });
  // Pin: shared conversation metadata — synced to the peer / every member. In the
  // note thread it's a private bookmark (local only). Left groups: read-only.
  if (canSend) items.push({
    label: m.pinned ? 'Unpin' : 'Pin', icon: 'pin',
    fn: async () => {
      try {
        if (cur.kind === 'group') {
          await invoke('set_group_msg_pinned', { groupId: cur.peer, msgId: m.msg_id, pin: !m.pinned });
          await renderGroupThread(cur.peer);
        } else {
          await invoke('set_msg_pinned', { username: cur.username, peer: cur.peer, msgId: m.msg_id, pin: !m.pinned });
          await renderThread(cur.peer);
        }
      } catch (e) { toast(say(e), 'err'); }
    },
  });
  if (m.attachment) {
    items.push({ label: 'Save as…', icon: 'down', fn: () => saveAtt(cur.peer, m.msg_id) });
  }
  if (mine && canSend && !m.attachment && Math.floor(Date.now() / 1000) - m.sent_at <= 300) {
    items.push({ label: 'Edit', icon: 'edit', fn: () => editModal(m) });
  }
  items.push({
    label: mine && canSend ? 'Delete…' : 'Delete for me…', icon: 'trash', danger: true,
    fn: () => deleteMsgModal(m),
  });
  return items;
}

// ── Reply state ─────────────────────────────────────────────────────────────────
let replyTo = null;
function startReply(m) {
  replyTo = m.msg_id;
  $('#th-replytext').textContent = m.attachment ? '📎 ' + m.body : m.body;
  $('#th-replybar').hidden = false;
  $('#th-input').focus();
}
function clearReply() { replyTo = null; $('#th-replybar').hidden = true; }
$('#th-replycancel').onclick = clearReply;

function editModal(m) {
  const isGroup = cur.kind === 'group';
  const card = openModal(
    `<h3>Edit message</h3>
     <p>${cur.note ? 'Edits stay on this device.' : isGroup ? 'Every member sees the edit.' : 'Both sides see the edit.'} Possible for 5 minutes after sending.</p>
     <input id="mo-edit" type="text" autocomplete="off" />
     <button class="btn" id="mo-save">Save</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  const inputEl = card.querySelector('#mo-edit');
  inputEl.value = m.body;
  inputEl.focus();
  card.querySelector('#mo-save').onclick = async () => {
    const text = inputEl.value.trim();
    closeModal();
    if (!text || text === m.body) return;
    try {
      if (isGroup) {
        await invoke('edit_group_message', { groupId: cur.peer, msgId: m.msg_id, text });
        renderGroupThread(cur.peer);
      } else {
        await invoke('edit_message', { username: cur.username, peer: cur.peer, msgId: m.msg_id, text });
        renderThread(cur.peer);
      }
    } catch (e) { toast(say(e), 'err'); }
  };
  card.querySelector('#mo-no').onclick = closeModal;
}

function deleteMsgModal(m) {
  // Note thread: there is no "everyone" — only this device's copy.
  const mine = m.direction === 'outgoing' && !(cur.kind === 'group' && cur.left) && !cur.note;
  const isGroup = cur.kind === 'group';
  const repaint = () => { (isGroup ? renderGroupThread : renderThread)(cur.peer); loadChats(); };
  const card = openModal(
    `<h3>Delete message?</h3>
     <p>${mine ? `For everyone also removes it from ${isGroup ? "every member's device (their clients cooperate — they already hold the text)" : 'their device (their client cooperates — it already holds the text)'}.` : 'Removed from this device only.'}</p>
     <button class="btn btn-danger" id="mo-me">Delete for me</button>
     ${mine ? '<button class="btn btn-danger" id="mo-all">Delete for everyone</button>' : ''}
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelector('#mo-me').onclick = async () => {
    closeModal();
    try {
      if (isGroup) await invoke('delete_group_message', { groupId: cur.peer, msgId: m.msg_id });
      else await invoke('delete_message', { peer: cur.peer, msgId: m.msg_id });
      repaint();
    } catch (e) { toast(say(e), 'err'); }
  };
  const all = card.querySelector('#mo-all');
  if (all) all.onclick = async () => {
    closeModal();
    try {
      if (isGroup) await invoke('delete_group_message_everyone', { groupId: cur.peer, msgId: m.msg_id });
      else await invoke('delete_message_everyone', { username: cur.username, peer: cur.peer, msgId: m.msg_id });
      repaint();
    } catch (e) { toast(say(e), 'err'); }
  };
  card.querySelector('#mo-no').onclick = closeModal;
}

// Forward anything (text, file, image, voice) to any chat, group, or note-to-self.
// The backend re-references the original encrypted blob and stamps the wire `fwd`
// flag, so recipients see the "Forwarded" tag and nothing re-uploads.
function forwardModal(m) {
  invoke('conversations').then((convs) => {
    const targets = convs.filter((c) => !c.note && ((c.kind === 'chat' && !c.blocked) || c.kind === 'group'));
    const rows = [
      `<button data-note="1"><div class="avatar" style="--av-h:${hue(NOTE_PEER)};width:26px;height:26px;font-size:12px">${icon('bookmark')}</div>Note to self</button>`,
      ...targets.map((c, i) => {
        const display = c.kind === 'group' ? c.username : (c.nickname || c.username);
        const av = c.kind === 'group' ? icon('users') : escapeHtml(initial(display));
        return `<button data-i="${i}"><div class="avatar" style="--av-h:${hue(c.kind === 'group' ? c.peer : c.username)};width:26px;height:26px;font-size:12px">${av}</div>${escapeHtml(display)}</button>`;
      }),
    ];
    const card = openModal(
      `<h3>Forward to…</h3>
       <div class="modal-list">${rows.join('')}</div>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    const src = {
      srcPeer: cur.kind === 'chat' ? cur.peer : null,
      srcGroup: cur.kind === 'group' ? cur.peer : null,
      msgId: m.msg_id,
    };
    const go = async (dst, display) => {
      closeModal();
      try {
        await invoke('forward_message', { ...src, ...dst });
        toast('Forwarded to ' + display, 'ok');
        loadChats();
        if (cur.peer) await (cur.kind === 'group' ? renderGroupThread(cur.peer) : renderThread(cur.peer));
      } catch (e) { toast(say(e), 'err'); }
    };
    card.querySelector('[data-note]').onclick = () => go({ dstUsername: null, dstGroup: null }, 'Note to self');
    card.querySelectorAll('[data-i]').forEach((b) => {
      b.onclick = () => {
        const t = targets[Number(b.dataset.i)];
        const display = t.kind === 'group' ? t.username : (t.nickname || t.username);
        go(t.kind === 'group' ? { dstUsername: null, dstGroup: t.peer } : { dstUsername: t.username, dstGroup: null }, display);
      };
    });
    card.querySelector('#mo-no').onclick = closeModal;
  }).catch((e) => toast(say(e), 'err'));
}

// Every pinned message of the open thread: tap a row to jump, ✕ to unpin.
function pinnedListModal() {
  if (!curPins.length) return;
  const card = openModal(
    `<h3>Pinned messages</h3>
     <div class="mg-list">${curPins.map((m, i) => {
       const label = m.voice ? '🎤 Voice message' : m.attachment ? '📎 ' + m.body : stripMarkers(m.body);
       return `<div class="mg-row pin-row" data-i="${i}">
         <span class="mg-rowico">${icon('pin')}</span>
         <span class="mg-rowbody"><b>${escapeHtml(label)}</b><em>${relday(m.sent_at)} · ${hhmm(m.sent_at)}</em></span>
         <button type="button" class="icon-btn pin-un" data-un="${i}" aria-label="Unpin">${icon('x')}</button>
       </div>`;
     }).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('.pin-row').forEach((row) => {
    row.onclick = () => {
      const m = curPins[Number(row.dataset.i)];
      closeModal();
      if (m) jumpToMsg(m.msg_id);
    };
  });
  card.querySelectorAll('.pin-un').forEach((b) => {
    b.onclick = async (e) => {
      e.stopPropagation();
      const m = curPins[Number(b.dataset.un)];
      closeModal();
      if (!m) return;
      try {
        if (cur.kind === 'group') {
          await invoke('set_group_msg_pinned', { groupId: cur.peer, msgId: m.msg_id, pin: false });
          await renderGroupThread(cur.peer);
        } else {
          await invoke('set_msg_pinned', { username: cur.username, peer: cur.peer, msgId: m.msg_id, pin: false });
          await renderThread(cur.peer);
        }
      } catch (err) { toast(say(err), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
}

