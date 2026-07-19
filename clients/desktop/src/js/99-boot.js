// ── Helpers ──────────────────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function initial(u) { return (u || '?').trim().charAt(0).toUpperCase() || '?'; }
function spaced(sn) { return sn || ''; }

// ── Keyboard shortcuts (I) ────────────────────────────────────────────────────────
// Ctrl/Cmd+K quick switcher: a modal with a fuzzy chat filter; Enter opens the top hit.
function openQuickSwitcher() {
  if (!$('#modal').hidden) return;
  const card = openModal(
    `<h3>Jump to chat</h3>
     <input class="qs-input" id="qs-in" type="text" placeholder="Type a name…" autocomplete="off" />
     <div class="qs-list" id="qs-list"></div>`);
  const inp = card.querySelector('#qs-in');
  const list = card.querySelector('#qs-list');
  let active = 0, hits = [];
  const render = () => {
    const q = inp.value.trim().toLowerCase();
    hits = lastConvs.filter((c) => !q || (c.nickname || c.username).toLowerCase().includes(q) || c.username.toLowerCase().includes(q)).slice(0, 8);
    active = 0;
    list.innerHTML = '';
    hits.forEach((c, i) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'qs-item' + (i === 0 ? ' active' : '');
      const display = c.nickname || c.username;
      b.innerHTML = `<div class="avatar" style="--av-h:${hue(c.kind === 'group' ? c.peer : c.username)};width:26px;height:26px;font-size:12px">${c.kind === 'group' ? icon('users') : escapeHtml(initial(display))}</div><span>${escapeHtml(display)}</span>`;
      b.onclick = () => { closeModal(); openConv(c); };
      list.appendChild(b);
    });
  };
  const openConv = (c) => (c.note ? openNote() : c.kind === 'group' ? openGroup(c.peer, c.username) : openThread(c.username, c.peer, c.nickname || c.username));
  inp.addEventListener('input', render);
  inp.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(active + 1, hits.length - 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(active - 1, 0); }
    else if (e.key === 'Enter') { e.preventDefault(); if (hits[active]) { closeModal(); openConv(hits[active]); } return; }
    else return;
    $$('.qs-item', list).forEach((el, i) => el.classList.toggle('active', i === active));
  });
  render();
}

// Edit our last own text message when ArrowUp is pressed in an empty composer.
async function editLastOwnMessage() {
  if (cur.kind !== 'chat' || !cur.peer) return;
  try {
    // Editable = own message ≤5 min old — the newest few dozen more than cover it.
    const t = await invoke('thread', { peer: cur.peer, limit: 50 });
    const now = Math.floor(Date.now() / 1000);
    const m = [...t.messages].reverse().find((x) => x.direction === 'outgoing' && !x.attachment && !x.system && now - x.sent_at <= 300);
    if (m) editModal(m);
  } catch (_) {}
}

// Alt+ArrowUp/Down — previous/next chat in the (non-archived) list.
function stepChat(dir) {
  const rows = lastConvs.filter((c) => !c.archived);
  if (!rows.length) return;
  let i = rows.findIndex((c) => c.peer === cur.peer);
  i = i < 0 ? 0 : Math.min(Math.max(i + dir, 0), rows.length - 1);
  const c = rows[i];
  if (c) (c.note ? openNote() : c.kind === 'group' ? openGroup(c.peer, c.username) : openThread(c.username, c.peer, c.nickname || c.username));
}

document.addEventListener('keydown', (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); openQuickSwitcher(); return; }
  if (e.altKey && e.key === 'ArrowUp') { e.preventDefault(); stepChat(-1); return; }
  if (e.altKey && e.key === 'ArrowDown') { e.preventDefault(); stepChat(1); return; }
  // Esc: close whatever overlay is on top, else step back — reuse the popstate router.
  if (e.key === 'Escape') {
    const epk = $('#emojipk');
    if (!$('#modal').hidden || !$('#ctxmenu').hidden || !$('#lightbox').hidden ||
        !$('#vidbox').hidden || (epk && !epk.hidden) ||
        !$('#camui').hidden || !$('#msel').hidden || cmpPanelOpen() ||
        (current === 'thread' && !$('#th-searchbar').hidden) || MAIN_SCREENS.has(current)) {
      history.back();
    }
    return;
  }
  // ArrowUp in an empty composer edits our last message.
  if (e.key === 'ArrowUp' && e.target === $('#th-input') && !$('#th-input').value.trim() && !attachQueue.length) {
    e.preventDefault(); editLastOwnMessage();
  }
});

// Deferred cross-file handler wiring (defined in later scripts; bound after load).
$('#ch-settings').onclick = openSettings;

boot();
