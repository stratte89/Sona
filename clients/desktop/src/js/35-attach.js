// ── Image lightbox: view full-size; save is an explicit button ─────────────────
// Zoom lives HERE and nowhere else. Browser zoom is off document-wide (viewport
// user-scalable=no + `touch-action: pan-x pan-y` on <html>) because a pinch in the chat
// list or thread only ever wrecks the layout; previewed media is the one place the gesture
// means something, so the image carries its own pinch / drag / double-tap transform.
//
// Geometry: `#lb-img` has `transform-origin: 0 0`, so with `base` = its untransformed
// top-left (measured on load, transform cleared) the mapping is
//   screen = base + t + scale * local
// and zooming about a focal screen point f keeps `local` fixed:
//   t' = f - base - (s'/s) * (f - base - t)
const lb = { peer: null, msgId: null, s: 1, tx: 0, ty: 0, base: null };
const LB_MAX_SCALE = 6;
const lbPtrs = new Map(); // active pointers on the image (2 = pinch)
let lbPinch = null;       // last pinch sample: { dist, mx, my }
let lbMoved = 0;          // px travelled in the current gesture (tap vs drag)
let lbLastTap = 0;

function lbApply() {
  const img = $('#lb-img');
  img.style.transform = `translate(${lb.tx}px, ${lb.ty}px) scale(${lb.s})`;
  img.classList.toggle('zoomed', lb.s > 1.01);
}
// Measure the image where CSS puts it at 1×, so the transform maths has a fixed origin.
function lbMeasure() {
  const img = $('#lb-img');
  const keep = img.style.transform;
  img.style.transform = 'none';
  const r = img.getBoundingClientRect();
  lb.base = { x: r.left, y: r.top, w: r.width, h: r.height };
  img.style.transform = keep;
}
function lbReset() { lb.s = 1; lb.tx = 0; lb.ty = 0; lbApply(); }
// Keep the image on screen: an axis that fits stays centred; an axis that overflows may be
// panned, but never past its own edge (no flinging the photo into the void).
function lbClamp() {
  if (!lb.base) return;
  const axis = (t, base, size, view) => {
    const scaled = size * lb.s;
    if (scaled <= view) return (view - scaled) / 2 - base;
    return Math.min(-base, Math.max(view - scaled - base, t));
  };
  lb.tx = axis(lb.tx, lb.base.x, lb.base.w, window.innerWidth);
  lb.ty = axis(lb.ty, lb.base.y, lb.base.h, window.innerHeight);
}
function lbZoomTo(scale, fx, fy) {
  if (!lb.base) lbMeasure();
  const s2 = Math.min(LB_MAX_SCALE, Math.max(1, scale));
  const k = s2 / lb.s;
  lb.tx = fx - lb.base.x - k * (fx - lb.base.x - lb.tx);
  lb.ty = fy - lb.base.y - k * (fy - lb.base.y - lb.ty);
  lb.s = s2;
  lbClamp(); lbApply();
}

function openLightbox(src, peer, msgId) {
  lb.peer = peer; lb.msgId = msgId; lb.base = null;
  const img = $('#lb-img');
  lbReset();
  img.onload = () => { lbMeasure(); lbClamp(); lbApply(); };
  img.src = src;
  $('#lightbox').hidden = false;
}
function closeLightbox() {
  $('#lightbox').hidden = true;
  $('#lb-img').src = '';
  lbPtrs.clear(); lbPinch = null;
  lbReset();
}
$('#lb-close').onclick = closeLightbox;
// Tap the backdrop to close — but not when the tap is the tail of a pan/pinch.
$('#lightbox').onclick = (e) => { if (e.target === $('#lightbox') && lbMoved <= 10) closeLightbox(); };
$('#lb-save').onclick = () => { if (lb.peer) saveAtt(lb.peer, lb.msgId); };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('#lightbox').hidden) closeLightbox(); });
// A layout change invalidates `base` (the image is re-laid-out against the new viewport).
window.addEventListener('resize', () => { if (!$('#lightbox').hidden) { lbReset(); lbMeasure(); } });

{
  const img = $('#lb-img');
  const sample = () => {
    const [a, b] = [...lbPtrs.values()];
    return { dist: Math.hypot(a.x - b.x, a.y - b.y), mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2 };
  };
  img.addEventListener('pointerdown', (e) => {
    img.setPointerCapture(e.pointerId);
    lbPtrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
    lbMoved = 0;
    lbPinch = lbPtrs.size === 2 ? sample() : null;
  });
  img.addEventListener('pointermove', (e) => {
    const p = lbPtrs.get(e.pointerId);
    if (!p) return;
    const dx = e.clientX - p.x, dy = e.clientY - p.y;
    p.x = e.clientX; p.y = e.clientY;
    lbMoved += Math.abs(dx) + Math.abs(dy);
    if (lbPtrs.size >= 2) {
      const now = sample();
      if (lbPinch && lbPinch.dist > 0) {
        // Pinch = scale about the midpoint, plus whatever the midpoint itself travelled.
        lb.tx += now.mx - lbPinch.mx;
        lb.ty += now.my - lbPinch.my;
        lbZoomTo(lb.s * (now.dist / lbPinch.dist), now.mx, now.my);
      }
      lbPinch = now;
    } else if (lb.s > 1.01) {
      lb.tx += dx; lb.ty += dy;
      lbClamp(); lbApply();
    }
  });
  const release = (e) => {
    lbPtrs.delete(e.pointerId);
    if (lbPtrs.size < 2) lbPinch = null;
  };
  img.addEventListener('pointerup', (e) => {
    release(e);
    if (lbMoved > 10 || lbPtrs.size) return;
    const now = performance.now();
    if (now - lbLastTap < 300) { // double-tap: toggle 2.5× at the tapped point
      lbLastTap = 0;
      if (lb.s > 1.01) lbReset(); else lbZoomTo(2.5, e.clientX, e.clientY);
    } else {
      lbLastTap = now;
    }
  });
  img.addEventListener('pointercancel', release);
  // Desktop: wheel zooms about the cursor.
  $('#lightbox').addEventListener('wheel', (e) => {
    e.preventDefault();
    lbZoomTo(lb.s * (e.deltaY < 0 ? 1.15 : 1 / 1.15), e.clientX, e.clientY);
  }, { passive: false });
}
// Outgoing delivery indicator: sending → sent (✓) → delivered (✓✓) → seen (✓✓ accent).
function statusIcon(status) {
  if (status === 'sending') return '<i class="tick spin"></i>';
  if (status === 'seen') return `<i class="tick seen">${icon('checks')}</i>`;
  if (status === 'delivered') return `<i class="tick">${icon('checks')}</i>`;
  return `<i class="tick">${icon('check')}</i>`; // sent
}
async function markSeen() {
  if (!cur.username || !cur.peer || cur.keyChanged) return;
  try { await invoke('mark_seen', { username: cur.username, peer: cur.peer }); } catch (_) { /* offline */ }
}

// ── Group settings page ─────────────────────────────────────────────────────────
// Mirrors the 1:1 chat-settings page (same header/back/cards) instead of the old
// modal. Admin-model UI: only the admin sees add/remove/make-admin — everyone else
// gets a plain roster, so nobody can even tap into a "not allowed" error. Removing
// yourself is never offered; that's what "Leave group" is for.
async function openGroupSettings() {
  const gid = cur.peer;
  let t;
  try {
    t = await invoke('group_thread', { groupId: gid, limit: 1 }); // roster/meta only
  } catch (e) { return toast(say(e), 'err'); }
  cur.username = t.name;
  cur.timer = t.timer_secs ?? null;
  cur.avatar = t.avatar || null;
  cur.left = !!t.left;
  cur.members = t.members;
  cur.isAdmin = !!t.is_admin;
  cur.admin = t.admin || null;
  renderGroupSettings(gid, t);
  show('groupsettings');
}

function renderGroupSettings(gid, t) {
  const readOnly = !!t.left;
  $('#gs-name').textContent = ell25(t.name);
  $('#gs-count').textContent = t.members.length + (t.members.length === 1 ? ' member' : ' members');
  $('#gs-left-note').hidden = !readOnly;
  $('#gs-rename').hidden = readOnly;
  $('#gs-timer-h').hidden = readOnly;
  $('#gs-timer-card').hidden = readOnly;
  $('#gs-add-card').hidden = readOnly || !t.is_admin;
  $('#gs-leave').hidden = readOnly;

  // Group photo: any member may set it (egalitarian, like the name).
  const avEl = $('#gs-avatar');
  const paintAvatar = () => {
    avEl.innerHTML = avatarInner(cur.avatar, t.name, true) + (readOnly ? '' : `<span class="av-cam">${icon('cam')}</span>`);
    avEl.style.setProperty('--av-h', hue(gid));
    avEl.classList.toggle('editable', !readOnly);
    $('#gs-avatar-rm').hidden = readOnly || !isAvatar(cur.avatar);
  };
  paintAvatar();
  const saveAvatar = async (avatar) => {
    try {
      await invoke('set_group_avatar', { groupId: gid, avatar });
      cur.avatar = avatar;
      paintAvatar();
      setAvatarEl($('#th-avatar'), cur.avatar, cur.username, true, gid);
      paintGroupAvatarTimer();
      loadChats();
    } catch (e) { toast(say(e), 'err'); }
  };
  avEl.onclick = async () => { if (readOnly) return; const a = await pickAvatar(); if (a) saveAvatar(a); };
  $('#gs-avatar-rm').onclick = () => saveAvatar(null);

  // Timer state.
  $$('#gs-timeropts .topt').forEach((b) => {
    const secs = b.dataset.secs ? Number(b.dataset.secs) : null;
    b.classList.toggle('on', secs === (cur.timer ?? null));
  });

  // Roster. The admin gets per-row actions on everyone BUT themselves; nobody ever
  // gets a remove button on their own row.
  const box = $('#gs-members');
  box.innerHTML = '';
  const me = (myName || '').toLowerCase();
  for (const u of t.members) {
    const row = document.createElement('div');
    row.className = 'member-row';
    row.innerHTML =
      `<div class="avatar" style="--av-h:${hue(u)}">${escapeHtml(initial(u))}</div>
       <span class="gs-mname">${escapeHtml(u)}${u.toLowerCase() === me ? ' (you)' : ''}</span>` +
      (t.admin && u === t.admin ? '<span class="gs-admin-tag">Admin</span>' : '');
    if (t.is_admin && !readOnly && u.toLowerCase() !== me) {
      const act = document.createElement('span');
      act.className = 'gs-act';
      const mk = document.createElement('button');
      mk.type = 'button';
      mk.className = 'icon-btn gs-mkadmin';
      mk.title = 'Make admin';
      mk.setAttribute('aria-label', 'Make ' + u + ' the admin');
      mk.innerHTML = icon('shield');
      mk.onclick = async () => {
        if (!(await confirmModal(`Make ${u} the admin?`,
          'A group has one admin. They take over adding and removing members — you stay in the group as a regular member.', 'Make admin'))) return;
        try {
          await invoke('transfer_group_admin', { groupId: gid, username: u });
          toast(u + ' is now the admin', 'ok');
          openGroupSettings();
          loadChats();
        } catch (e) { toast(say(e), 'err'); }
      };
      const rm = document.createElement('button');
      rm.type = 'button';
      rm.className = 'icon-btn gi-kick';
      rm.title = 'Remove from group';
      rm.setAttribute('aria-label', 'Remove ' + u);
      rm.innerHTML = icon('x');
      rm.onclick = async () => {
        if (!(await confirmModal(`Remove ${u}?`,
          'They are removed for every member and can no longer read or send new messages. Their device keeps the old history.', 'Remove'))) return;
        try {
          await invoke('remove_group_member', { groupId: gid, username: u });
          toast('Removed ' + u, 'ok');
          openGroupSettings();
          renderGroupThread(gid);
          loadChats();
        } catch (e) { toast(say(e), 'err'); }
      };
      act.append(mk, rm);
      row.appendChild(act);
    }
    box.appendChild(row);
  }
}

// Add members (admin only): pick from your contacts, Signal-style — no typing.
$('#gs-add').onclick = async () => {
  const gid = cur.peer;
  let convs = [];
  try { convs = await invoke('conversations'); } catch (_) {}
  const inGroup = new Set((cur.members || []).map((u) => u.toLowerCase()));
  const contacts = convs.filter((c) => c.kind === 'chat' && !c.blocked && !c.note && !inGroup.has(c.username.toLowerCase()));
  const sel = new Set();
  const card = openModal(
    `<h3>Add members</h3>` +
    (contacts.length
      ? `<div class="modal-list gs-pick" id="gsa-list"></div>
         <button class="btn" id="gsa-add" disabled>Add</button>`
      : '<p class="hint">Everyone you chat with is already in this group.</p>') +
    `<button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelector('#mo-no').onclick = closeModal;
  const list = card.querySelector('#gsa-list');
  const addBtn = card.querySelector('#gsa-add');
  const syncBtn = () => {
    if (!addBtn) return;
    addBtn.disabled = !sel.size;
    addBtn.textContent = sel.size ? `Add ${sel.size}` : 'Add';
  };
  for (const c of contacts) {
    const display = c.nickname || c.username;
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'member-row';
    b.innerHTML =
      `<div class="avatar" style="--av-h:${hue(c.username)}">${escapeHtml(initial(display))}</div>
       <span>${escapeHtml(display)}</span><span class="check">${icon('check')}</span>`;
    b.onclick = () => {
      if (sel.has(c.username)) { sel.delete(c.username); b.classList.remove('sel'); }
      else { sel.add(c.username); b.classList.add('sel'); }
      syncBtn();
    };
    list.appendChild(b);
  }
  if (addBtn) addBtn.onclick = async () => {
    addBtn.disabled = true;
    closeModal();
    for (const u of sel) {
      try { await invoke('add_to_group', { groupId: gid, username: u }); toast('Added ' + u, 'ok'); }
      catch (e) { toast(`Couldn't add ${u}: ` + say(e), 'err'); }
    }
    openGroupSettings();
    renderGroupThread(gid);
    loadChats();
  };
};

// Rename: any member may; every member sees the change + a system chip.
$('#gs-rename').onclick = () => {
  const gid = cur.peer;
  const c2 = openModal(
    `<h3>Rename group</h3>
     <p>Every member sees the new name.</p>
     <input id="mo-gname" type="text" autocomplete="off" />
     <button class="btn" id="mo-save">Rename</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  const inp = c2.querySelector('#mo-gname');
  inp.value = cur.username;
  inp.focus(); inp.select();
  c2.querySelector('#mo-no').onclick = closeModal;
  c2.querySelector('#mo-save').onclick = async () => {
    const name = inp.value.trim();
    closeModal();
    if (!name || name === cur.username) return;
    try {
      await invoke('rename_group', { groupId: gid, name });
      cur.username = name;
      $('#th-name').textContent = ell25(name);
      $('#gs-name').textContent = ell25(name);
      renderGroupThread(gid);
      loadChats();
    } catch (e) { toast(say(e), 'err'); }
  };
};

// Group disappearing timer (any member may — synced to everyone).
$$('#gs-timeropts .topt').forEach((b) => {
  b.onclick = async () => {
    const gid = cur.peer;
    const secs = b.dataset.secs ? Number(b.dataset.secs) : null;
    const all = $$('#gs-timeropts .topt');
    all.forEach((x) => (x.disabled = true));
    try {
      await invoke('set_group_disappearing', { groupId: gid, secs });
      cur.timer = secs;
      all.forEach((x) => {
        const s = x.dataset.secs ? Number(x.dataset.secs) : null;
        x.classList.toggle('on', s === (secs ?? null));
      });
      paintGroupAvatarTimer();
      renderGroupThread(gid); // show the system chip
      loadChats();
    } catch (e) { toast(say(e), 'err'); }
    finally { all.forEach((x) => (x.disabled = false)); }
  };
});

$('#gs-back').onclick = () => history.back();
$('#gs-search').onclick = () => { show('thread'); openChatSearch(); };
$('#gs-media').onclick = () => mediaGalleryModal();
$('#gs-leave').onclick = async () => {
  const gid = cur.peer;
  if (!(await confirmModal('Leave group?', 'The other members are told you left, and the group is removed from this device.', 'Leave group'))) return;
  try { await invoke('leave_group', { groupId: gid }); show('chats'); loadChats(); } catch (e) { toast(say(e), 'err'); }
};
$('#gs-delete').onclick = async () => {
  const gid = cur.peer;
  if (!(await confirmModal('Delete group?', 'Removed from this device only — nobody is told, and other members keep their copies.', 'Delete group'))) return;
  try { await invoke('delete_group', { groupId: gid }); show('chats'); loadChats(); } catch (e) { toast(say(e), 'err'); }
};

// ── Safety-number QR verify ───────────────────────────────────────────────────────
// The safety number is symmetric per pair, so both sides render the SAME code — scan
// either direction and compare against our own. The digits stay visible for the
// read-them-aloud ceremony; the QR is the in-person fast path.
function renderVerifyQr() {
  const box = $('#cs-qr');
  box.innerHTML = '';
  const sn = (cur.safety || '').replace(/\s+/g, '');
  box.hidden = !sn;
  if (!sn) return;
  try {
    const qr = qrcode(0, 'M');
    qr.addData(JSON.stringify({ sona: 'verify', v: 1, sn }), 'Byte');
    qr.make();
    box.innerHTML = qr.createSvgTag({ cellSize: 3, margin: 0, scalable: true, alt: { text: 'safety number QR' } });
  } catch (_) { box.hidden = true; }
}
// Strict shape check for a scanned verify code — scanner input is data, never anything else.
function looksLikeVerifyCode(text) {
  if (typeof text !== 'string' || text.length > 512) return false;
  try {
    const o = JSON.parse(text);
    return !!(o && o.sona === 'verify' && o.v === 1
      && typeof o.sn === 'string' && /^[0-9]{10,120}$/.test(o.sn));
  } catch (_) { return false; }
}
$('#cs-scanverify').onclick = async () => {
  const btn = $('#cs-scanverify');
  busy(btn, true, 'Opening camera…');
  try {
    const text = await scanQr(looksLikeVerifyCode);
    busy(btn, false);
    if (!text) return;
    const theirs = JSON.parse(text).sn;
    const mine = (cur.safety || '').replace(/\s+/g, '');
    if (mine && theirs === mine) {
      await invoke('mark_verified', { username: cur.username, peer: cur.peer });
      cur.verified = true;
      updateBadge();
      loadChats();
      toast('Codes match — contact verified ✓', 'ok');
    } else {
      openModal(
        `<h3>⚠ Codes do NOT match</h3>
         <p>The scanned safety number is different from this conversation's. Someone may be
            sitting between you — <strong>do not verify</strong>, and stop sharing anything
            sensitive until you've compared numbers over another channel you trust.</p>
         <button class="btn" id="mo-ok">Understood</button>`)
        .querySelector('#mo-ok').onclick = closeModal;
    }
  } catch (e) { busy(btn, false); toast(say(e), 'err'); }
};

// Note-to-self header tap: disappearing timer + media. No safety surface — the peer
// is you; the timer self-syncs so every one of your devices reaps on the same clock.
function noteInfoModal() {
  const card = openModal(
    `<button class="modal-x" id="mo-x" aria-label="Close">${icon('x')}</button>
     <h3>Note to self</h3>
     <p class="gi-timer-h">Disappearing notes <span class="safety-desc">— notes delete themselves on all your devices after this long.</span></p>
     <div class="timer-opts" id="ni-timeropts">
       <button data-secs="" class="topt">Off</button>
       <button data-secs="300" class="topt">5m</button>
       <button data-secs="3600" class="topt">1h</button>
       <button data-secs="86400" class="topt">1d</button>
       <button data-secs="604800" class="topt">7d</button>
     </div>
     <button class="btn btn-sm btn-ghost" id="ni-media">Media, files &amp; voice</button>`);
  card.querySelector('#mo-x').onclick = closeModal;
  const paint = () => card.querySelectorAll('#ni-timeropts .topt').forEach((b) => {
    const secs = b.dataset.secs ? Number(b.dataset.secs) : null;
    b.classList.toggle('on', secs === (cur.timer ?? null));
  });
  paint();
  card.querySelectorAll('#ni-timeropts .topt').forEach((b) => {
    b.onclick = async () => {
      const secs = b.dataset.secs ? Number(b.dataset.secs) : null;
      const all = card.querySelectorAll('#ni-timeropts .topt');
      all.forEach((x) => (x.disabled = true));
      try {
        await invoke('set_note_disappearing', { secs });
        cur.timer = secs;
        paint();
        syncTimerUi();
        renderThread(NOTE_PEER); // show the system chip
        loadChats();
      } catch (e) { toast(say(e), 'err'); }
      finally { all.forEach((x) => (x.disabled = false)); }
    };
  });
  card.querySelector('#ni-media').onclick = () => mediaGalleryModal(); // replaces this modal
}

// Chat settings is its own page (safety number + disappearing timer live there).
$('#th-peer').onclick = () => {
  if (cur.note) return noteInfoModal();
  if (cur.kind === 'group') return openGroupSettings();
  if (cur.keyChanged || !cur.peer) return;
  $('#cs-name').textContent = cur.display || cur.username;
  $('#cs-username').textContent = '@' + cur.username;
  setAvatarEl($('#cs-avatar'), cur.avatar, cur.display || cur.username, false, cur.username);
  $('#th-safetynum').textContent = spaced(cur.safety);
  renderVerifyQr();
  $('#cs-scanverify').hidden = !(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  updateBadge();
  syncTimerUi();
  refreshSettingsMeta();
  show('chatsettings');
};

// Pull this contact's local prefs (mute/nickname/block) into the settings page.
async function refreshSettingsMeta() {
  let c = null;
  try { c = (await invoke('conversations')).find((x) => x.kind === 'chat' && x.username === cur.username); } catch (_) {}
  if (!c) return;
  cur.blocked = c.blocked;
  $('#cs-mute-state').textContent = isMuted(c)
    ? (c.muted_until > 4102444800 ? 'muted forever' : 'until ' + hhmm(c.muted_until)) : 'off';
  $('#cs-nick-state').textContent = c.nickname || '—';
  $('#cs-block-label').textContent = c.blocked ? 'Unblock' : 'Block';
}

$('#cs-search').onclick = () => { show('thread'); openChatSearch(); };
$('#cs-mute').onclick = async () => {
  const convs = await invoke('conversations').catch(() => []);
  const c = convs.find((x) => x.kind === 'chat' && x.username === cur.username);
  if (c && isMuted(c)) { await unmute({ kind: 'chat', id: cur.username }); refreshSettingsMeta(); }
  else muteModal({ kind: 'chat', id: cur.username, name: cur.display || cur.username }, refreshSettingsMeta);
};
$('#cs-nick').onclick = () => {
  const card = openModal(
    `<h3>Nickname for ${escapeHtml(cur.username)}</h3>
     <p>Only you see this. Leave empty to clear.</p>
     <input id="mo-nick" type="text" autocomplete="off" placeholder="nickname" />
     <button class="btn" id="mo-save">Save</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  const inputEl = card.querySelector('#mo-nick');
  inputEl.focus();
  card.querySelector('#mo-save').onclick = async () => {
    const nickname = inputEl.value.trim() || null;
    closeModal();
    try {
      await invoke('set_nickname', { username: cur.username, nickname });
      cur.display = nickname || cur.username;
      $('#th-name').textContent = ell25(cur.display);
      $('#cs-name').textContent = cur.display;
      refreshSettingsMeta(); loadChats();
    } catch (e) { toast(say(e), 'err'); }
  };
  card.querySelector('#mo-no').onclick = closeModal;
};
$('#cs-addgroup').onclick = async () => {
  let groups = [];
  try { groups = await invoke('my_groups'); } catch (_) {}
  if (!groups.length) return toast('No groups yet — create one from the + button', 'err');
  const card = openModal(
    `<h3>Add ${escapeHtml(cur.username)} to…</h3>
     <div class="modal-list">${groups.map((g, i) => `<button data-i="${i}">${icon('users')}${escapeHtml(g.name)}<em>${g.members} members</em></button>`).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-i]').forEach((b) => {
    b.onclick = async () => {
      const g = groups[Number(b.dataset.i)];
      closeModal();
      try { await invoke('add_to_group', { groupId: g.group_id, username: cur.username }); toast(`Added to ${g.name}`, 'ok'); }
      catch (e) { toast(say(e), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
};
$('#cs-block').onclick = async () => {
  const blocking = $('#cs-block-label').textContent === 'Block';
  if (blocking && !(await confirmModal(`Block ${cur.username}?`,
    'Everything they send is dropped silently — no messages, no receipts. They are not told. You can unblock any time.', 'Block'))) return;
  try {
    await invoke('set_blocked', { username: cur.username, blocked: blocking });
    toast(blocking ? 'Blocked' : 'Unblocked', 'ok');
    refreshSettingsMeta(); loadChats();
  } catch (e) { toast(say(e), 'err'); }
};
$('#cs-delete').onclick = () => deleteChatModal(cur.username, cur.peer);
$('#th-unblock').onclick = async () => {
  try {
    await invoke('set_blocked', { username: cur.username, blocked: false });
    $('#th-blocked').hidden = true; cur.blocked = false;
    toast('Unblocked', 'ok'); loadChats();
  } catch (e) { toast(say(e), 'err'); }
};
$('#cs-back').onclick = () => history.back();
// ── In-chat search: filter over rendered bubbles, jump between matches ──────────
// Search works over the DOM, so the windowed render would hide old matches: opening
// the bar grows the window to the full history for the search's lifetime, closing it
// restores the previous window (the next repaint shrinks the DOM back).
let hits = [], hitIdx = -1;
let searchPrevWin = null;
async function openChatSearch() {
  $('#th-searchbar').hidden = false;
  $('#th-searchinput').value = '';
  $('#th-searchcount').textContent = '';
  if (cur.peer && curMore && searchPrevWin === null) {
    searchPrevWin = winFor(cur.peer);
    threadWin.set(cur.peer, 1e9);
    await (cur.kind === 'group' ? renderGroupThread(cur.peer) : renderThread(cur.peer));
  }
  setTimeout(() => $('#th-searchinput').focus(), 100);
}
$('#th-search').onclick = openChatSearch;
$('#th-searchclose').onclick = () => {
  $('#th-searchbar').hidden = true;
  hits.forEach((h) => h.classList.remove('hl'));
  hits = []; hitIdx = -1;
  // Restore the window only when the user is back at the bottom — if they're up
  // reading a match, a shrunken repaint would rip it out from under them (the window
  // resets anyway on the next thread open).
  if (searchPrevWin !== null && cur.peer && !threadScrolledUp()) threadWin.set(cur.peer, searchPrevWin);
  searchPrevWin = null;
};
function runChatSearch() {
  hits.forEach((h) => h.classList.remove('hl'));
  hits = []; hitIdx = -1;
  const q = $('#th-searchinput').value.trim().toLowerCase();
  $('#th-searchcount').textContent = '';
  if (!q) return;
  // Match message CONTENT only (text, caption, attachment name) — never the timestamp
  // or "edited" tag, or searching "10" would hit every 10:xx message.
  const contentOf = (b) =>
    $$('.msg-text, .caption, .att-name, .quote', b).map((n) => n.textContent).join(' ');
  hits = $$('#th-thread .bubble').filter((b) => contentOf(b).toLowerCase().includes(q));
  if (!hits.length) { $('#th-searchcount').textContent = '0'; return; }
  hitIdx = hits.length - 1; // start at the newest match
  focusHit();
}
function focusHit() {
  hits.forEach((h) => h.classList.remove('hl'));
  const h = hits[hitIdx];
  if (!h) return;
  h.classList.add('hl');
  h.scrollIntoView({ block: 'center', behavior: 'smooth' });
  $('#th-searchcount').textContent = `${hitIdx + 1}/${hits.length}`;
}
$('#th-searchinput').addEventListener('input', runChatSearch);
$('#th-searchinput').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); $('#th-searchprev').click(); } });
$('#th-searchprev').onclick = () => { if (hits.length) { hitIdx = (hitIdx - 1 + hits.length) % hits.length; focusHit(); } };
$('#th-searchnext').onclick = () => { if (hits.length) { hitIdx = (hitIdx + 1) % hits.length; focusHit(); } };

$('#th-verify').onclick = async () => {
  try {
    await invoke('mark_verified', { username: cur.username, peer: cur.peer });
    cur.verified = true; updateBadge();
    toast('Marked verified', 'ok');
    loadChats();
  } catch (e) { toast(say(e), 'err'); }
};
$('#th-kc-accept').onclick = async () => {
  try {
    const r = await invoke('accept_key_change', { username: cur.username });
    cur.peer = r.peer; cur.safety = r.safety_number; cur.verified = false; cur.keyChanged = false;
    $('#th-keychange').hidden = true;
    updateBadge();
    await renderThread(r.peer);
    toast('New key accepted', 'ok');
  } catch (e) { toast(say(e), 'err'); }
};

// Disappearing-messages picker: explicit choice, shown selected, synced to the peer.
$$('#th-timeropts .topt').forEach((b) => {
  b.onclick = async () => {
    if (!cur.peer) return;
    const secs = b.dataset.secs ? Number(b.dataset.secs) : null;
    const all = $$('#th-timeropts .topt');
    all.forEach((x) => (x.disabled = true));
    try {
      await invoke('set_disappearing', { username: cur.username, peer: cur.peer, secs });
      cur.timer = secs;
      syncTimerUi();
      loadChats(); // avatar badge in the list
    } catch (e) { toast(say(e), 'err'); }
    finally { all.forEach((x) => (x.disabled = false)); }
  };
});

// ── New group ───────────────────────────────────────────────────────────────────
let ngSel = new Set();
async function openNewGroup() {
  ngSel = new Set();
  $('#ng-name').value = '';
  show('newgroup');
  let convs = [];
  try { convs = await invoke('conversations'); } catch (_) {}
  // Real contacts only: Note to self is you — it can never be a group member.
  const contacts = convs.filter((c) => c.kind === 'chat' && !c.blocked && !c.note);
  const box = $('#ng-members');
  box.innerHTML = '';
  $('#ng-hint').hidden = contacts.length > 0;
  for (const c of contacts) {
    const display = c.nickname || c.username;
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'member-row';
    b.innerHTML =
      `<div class="avatar" style="--av-h:${hue(c.username)}">${escapeHtml(initial(display))}</div>
       <span>${escapeHtml(display)}</span><span class="check">${icon('check')}</span>`;
    b.onclick = () => {
      if (ngSel.has(c.username)) { ngSel.delete(c.username); b.classList.remove('sel'); }
      else { ngSel.add(c.username); b.classList.add('sel'); }
    };
    box.appendChild(b);
  }
}
$('#ng-back').onclick = () => history.back();
$('#ng-create').onclick = async () => {
  const name = $('#ng-name').value.trim();
  if (!name) return toast('Give the group a name', 'err');
  if (!ngSel.size) return toast('Pick at least one member', 'err');
  const btn = $('#ng-create');
  busy(btn, true, 'Creating & inviting…');
  try {
    const gid = await invoke('create_group', { name, members: [...ngSel] });
    busy(btn, false);
    toast('Group created', 'ok');
    openGroup(gid, name);
    loadChats();
  } catch (e) { busy(btn, false); toast(say(e), 'err'); }
};

// Chunked base64 of raw bytes (String.fromCharCode chokes on big arrays in one call).
function toB64(buf) {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < buf.length; i += CHUNK) bin += String.fromCharCode(...buf.subarray(i, i + CHUNK));
  return btoa(bin);
}

