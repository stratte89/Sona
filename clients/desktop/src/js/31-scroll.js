// ═══════════════════════════════════════════════════════════════════════════════
// Thread scrolling: the windowed-history pager, jump-to-bottom FAB and sticky date.
// Split out of 30-thread.js (no-monolith ratchet); shares its `cur`/render globals.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Windowed history ───────────────────────────────────────────────────────────
// Only the newest N messages render (the backend extends the window to the first
// unread and any jump anchor). Scrolling to the top pages older history in; the
// window resets on every fresh open, so a years-long thread never repaints whole
// on a sync. In-chat search grows the window to everything for its lifetime.
const THREAD_PAGE = 60;
const threadWin = new Map(); // conversation id (peer/group) -> current window size
let curMore = false;         // older messages exist above the rendered window
let loadingEarlier = false;
function winFor(id) { return threadWin.get(id) || THREAD_PAGE; }
// Page older history in, keeping the viewport anchored on what the user is reading.
async function loadEarlier() {
  const peer = cur.peer;
  if (!peer || loadingEarlier || !curMore) return;
  loadingEarlier = true;
  try {
    threadWin.set(peer, winFor(peer) + THREAD_PAGE);
    const box = $('#th-thread');
    const prevH = box.scrollHeight, prevTop = box.scrollTop;
    await (cur.kind === 'group' ? renderGroupThread(peer) : renderThread(peer));
    box.scrollTop = box.scrollHeight - prevH + prevTop; // no jump: same message stays put
  } finally {
    loadingEarlier = false;
  }
}

// Jump-to-bottom FAB + count of messages that arrived while scrolled up (G).
let newSinceScroll = 0;
function threadScrolledUp() {
  const box = $('#th-thread');
  return box.scrollHeight - box.scrollTop - box.clientHeight > 120;
}
function updateJumpFab() {
  const fab = $('#th-jump');
  if (!fab) return;
  const up = threadScrolledUp();
  fab.hidden = !up;
  if (!up) newSinceScroll = 0;
  const badge = $('#th-jumpcount');
  if (badge) { badge.hidden = newSinceScroll === 0; badge.textContent = newSinceScroll > 99 ? '99+' : String(newSinceScroll); }
}
// Sticky date header reflecting the topmost visible day separator (G).
function updateStickyDate() {
  const box = $('#th-thread');
  const sticky = $('#th-stickydate');
  if (!sticky) return;
  const seps = $$('.daysep', box);
  let label = '';
  const top = box.getBoundingClientRect().top;
  for (const s of seps) {
    if (s.getBoundingClientRect().top - top < 24) label = s.dataset.day || s.textContent;
    else break;
  }
  if (label) { sticky.textContent = label; sticky.classList.add('show'); }
  else sticky.classList.remove('show');
}
let stickyHideTimer;
function onThreadScroll() {
  updateJumpFab();
  updateStickyDate();
  if ($('#th-thread').scrollTop < 300) loadEarlier(); // near the top: page older history in
  clearTimeout(stickyHideTimer);
  stickyHideTimer = setTimeout(() => { const s = $('#th-stickydate'); if (s) s.classList.remove('show'); }, 1400);
}
$('#th-thread').addEventListener('scroll', onThreadScroll, { passive: true });
$('#th-jump').onclick = () => {
  const box = $('#th-thread');
  box.scrollTo({ top: box.scrollHeight, behavior: 'smooth' });
  newSinceScroll = 0; updateJumpFab();
};
