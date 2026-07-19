// ═══════════════════════════════════════════════════════════════════════════════
// Full emoji picker — composer insertion + "more reactions".
//
// The dataset (vendor/emoji.js, generated from Unicode's emoji-test.txt, capped at
// E15.1 so nothing renders as tofu on common system fonts) is ~50 KB and lazy-loaded
// the first time the picker opens, exactly like the QR decoder (strict CSP: no remote
// assets, ever). Skin tones are applied at render time: an emoji is only marked
// tonable when the generator proved the simple modifier insertion yields the exact
// RGI sequence, so the picker can never produce a broken sequence. Toned emoji stay
// within the 8-char reaction cap the Rust side enforces (verified at generation).
// ═══════════════════════════════════════════════════════════════════════════════

let emojiLoading = null;
function loadEmojiData() {
  if (window.EMOJI_DATA) return Promise.resolve();
  if (!emojiLoading) {
    emojiLoading = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'vendor/emoji.js';
      s.onload = resolve;
      s.onerror = () => { emojiLoading = null; reject(new Error('emoji data failed to load')); };
      document.head.appendChild(s);
    });
  }
  return emojiLoading;
}

// Recents + skin-tone preference. Plain emoji strings only — no message content, no
// identities — so webview localStorage is the right tier (same as UI theme state).
const EMOJI_RECENT_KEY = 'sona-emoji-recent';
const EMOJI_TONE_KEY = 'sona-emoji-tone';
const EMOJI_TONES = ['', '\u{1F3FB}', '\u{1F3FC}', '\u{1F3FD}', '\u{1F3FE}', '\u{1F3FF}'];
function emojiRecents() {
  try {
    const v = JSON.parse(localStorage.getItem(EMOJI_RECENT_KEY) || '[]');
    return Array.isArray(v) ? v.filter((e) => typeof e === 'string' && e.length <= 32) : [];
  } catch (_) { return []; }
}
function noteEmojiUsed(e) {
  const r = [e, ...emojiRecents().filter((x) => x !== e)].slice(0, 32);
  try { localStorage.setItem(EMOJI_RECENT_KEY, JSON.stringify(r)); } catch (_) {}
}
function emojiTone() {
  const t = Number(localStorage.getItem(EMOJI_TONE_KEY) || 0);
  return t >= 0 && t < EMOJI_TONES.length ? t : 0;
}

// ── Adaptive quick reactions ─────────────────────────────────────────────────────
// The quick-react row starts as the classic default set, then reshapes itself around
// what this user actually reacts with: every reaction bumps a per-emoji counter, and
// the row shows the top scorers first, defaults filling whatever is left. Counters
// live in localStorage (emoji + a number — no content, no identities) and are bounded.
const EMOJI_FREQ_KEY = 'sona-emoji-freq';
function emojiFreq() {
  try {
    const v = JSON.parse(localStorage.getItem(EMOJI_FREQ_KEY) || '{}');
    return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  } catch (_) { return {}; }
}
function noteReactionUsed(e) {
  if (typeof e !== 'string' || !e || e.length > 32) return;
  const f = emojiFreq();
  f[e] = Math.min((f[e] || 0) + 1, 9999);
  // Bounded: keep the 64 hottest, so the map can't grow forever.
  const entries = Object.entries(f).sort((a, b) => b[1] - a[1]).slice(0, 64);
  try { localStorage.setItem(EMOJI_FREQ_KEY, JSON.stringify(Object.fromEntries(entries))); } catch (_) {}
}
// The quick row: most-used first (ties break by earliest use), defaults topping it
// up — a fresh install shows exactly the classic seven.
function quickReactionEmoji() {
  const f = emojiFreq();
  const top = Object.entries(f)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([e]) => e)
    .slice(0, QUICK_EMOJI.length);
  for (const e of QUICK_EMOJI) {
    if (top.length >= QUICK_EMOJI.length) break;
    if (!top.includes(e)) top.push(e);
  }
  return top;
}

// Apply the stored tone to a tonable emoji: modifier goes after the first code point,
// replacing a variation selector that followed it (the generator proved this exact
// construction against the RGI list for every emoji it flags).
function applyTone(emoji, tonable, toneIdx) {
  const tone = EMOJI_TONES[toneIdx];
  if (!tonable || !tone) return emoji;
  const cps = [...emoji];
  let rest = cps.slice(1);
  if (rest[0] === '\uFE0F') rest = rest.slice(1); // drop the variation selector
  return cps[0] + tone + rest.join('');
}

// ── The picker ──────────────────────────────────────────────────────────────────
// One instance, created on demand. Touch: bottom sheet. Desktop: floating panel near
// the anchor, clamped to the usable viewport. `onPick(emoji)` fires per pick;
// `sticky: true` keeps the panel open for multi-insert (composer), else it closes.
let epState = null; // { onPick, sticky, tab, query }

function ensureEmojiDom() {
  if ($('#emojipk')) return;
  const wrap = document.createElement('div');
  wrap.id = 'emojipk';
  wrap.hidden = true;
  wrap.innerHTML =
    `<div class="ep-backdrop"></div>
     <div class="ep-panel" role="dialog" aria-label="Emoji picker">
       <div class="ep-head">
         <span class="ep-search-ico">${icon('search')}</span>
         <input id="ep-search" type="search" placeholder="Search emoji" autocomplete="off" spellcheck="false" />
         <div class="ep-tones" id="ep-tones" title="Skin tone"></div>
       </div>
       <div class="ep-tabs" id="ep-tabs"></div>
       <div class="ep-grid" id="ep-grid"></div>
     </div>`;
  document.body.appendChild(wrap);
  wrap.querySelector('.ep-backdrop').onclick = closeEmojiPicker;
  $('#ep-search').addEventListener('input', () => {
    if (!epState) return;
    epState.query = $('#ep-search').value.trim().toLowerCase();
    renderEmojiGrid();
  });
  $('#ep-search').addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeEmojiPicker(); }
  });
}

function renderEmojiTones() {
  const box = $('#ep-tones');
  box.innerHTML = '';
  const current = emojiTone();
  EMOJI_TONES.forEach((t, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ep-tone' + (i === current ? ' sel' : '');
    b.textContent = applyTone('✋', true, i); // ✋ in every tone
    b.onclick = () => {
      try { localStorage.setItem(EMOJI_TONE_KEY, String(i)); } catch (_) {}
      renderEmojiTones();
      renderEmojiGrid();
    };
    box.appendChild(b);
  });
}

function renderEmojiTabs() {
  const tabs = $('#ep-tabs');
  tabs.innerHTML = '';
  const mk = (label, key, glyph) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ep-tab' + (epState.tab === key ? ' sel' : '');
    b.title = label;
    b.textContent = glyph;
    b.onclick = () => {
      epState.tab = key;
      epState.query = '';
      $('#ep-search').value = '';
      renderEmojiTabs();
      renderEmojiGrid();
    };
    tabs.appendChild(b);
  };
  if (emojiRecents().length) mk('Recent', 'recent', '🕘');
  window.EMOJI_DATA.forEach((g, i) => mk(g.n, String(i), g.e[0][0]));
}

function renderEmojiGrid() {
  const grid = $('#ep-grid');
  grid.innerHTML = '';
  const tone = emojiTone();
  const add = (emoji, name, tonable) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ep-cell';
    b.title = name;
    b.textContent = applyTone(emoji, tonable, tone);
    b.onclick = () => {
      const picked = b.textContent;
      noteEmojiUsed(picked);
      const done = epState && !epState.sticky;
      const cb = epState && epState.onPick;
      if (done) closeEmojiPicker();
      if (cb) cb(picked);
    };
    grid.appendChild(b);
  };
  const q = epState.query;
  if (q) {
    let shown = 0;
    for (const g of window.EMOJI_DATA) {
      for (const [e, name, t] of g.e) {
        if (shown >= 150) break;
        if (name.toLowerCase().includes(q)) { add(e, name, t); shown++; }
      }
    }
    if (!shown) grid.innerHTML = '<p class="ep-empty">No emoji match.</p>';
    return;
  }
  if (epState.tab === 'recent') {
    // Recents were stored exactly as picked (tone already baked in).
    for (const e of emojiRecents()) add(e, '', 0);
    return;
  }
  const g = window.EMOJI_DATA[Number(epState.tab)] || window.EMOJI_DATA[0];
  for (const [e, name, t] of g.e) add(e, name, t);
}

/// Open the picker. opts: { onPick(emoji), sticky?, x?, y?, mount? } — x/y anchor the
/// desktop popover (bottom sheet on touch ignores them). `mount` inlines the panel
/// into that element instead (the composer's emoji/GIF panel) — no backdrop, no
/// positioning, the host owns the geometry.
async function openEmojiPicker(opts) {
  try { await loadEmojiData(); } catch (e) { return toast(say(e), 'err'); }
  ensureEmojiDom();
  // Opening as an overlay while the composer panel hosts the picker inline would
  // steal the panel node from under it — close the composer panel first.
  if (!opts.mount && typeof closeCmpPanel === 'function') closeCmpPanel();
  epState = {
    onPick: opts.onPick,
    sticky: !!opts.sticky,
    tab: emojiRecents().length ? 'recent' : '0',
    query: '',
  };
  $('#ep-search').value = '';
  renderEmojiTones();
  renderEmojiTabs();
  renderEmojiGrid();
  const wrap = $('#emojipk');
  const panel = wrap.querySelector('.ep-panel');
  if (opts.mount) {
    wrap.hidden = true;
    panel.classList.add('inline');
    panel.style.left = '';
    panel.style.top = '';
    if (panel.parentElement !== opts.mount) opts.mount.appendChild(panel);
    if (!TOUCH_UI) setTimeout(() => $('#ep-search').focus(), 0);
    return;
  }
  panel.classList.remove('inline');
  if (panel.parentElement !== wrap) wrap.appendChild(panel);
  wrap.classList.toggle('sheet', TOUCH_UI);
  wrap.hidden = false;
  if (!TOUCH_UI) {
    // Float near the anchor point, above it when there is room, clamped like every
    // other screen-anchored box.
    const r = panel.getBoundingClientRect();
    const x = opts.x != null ? opts.x : (window.innerWidth - r.width) / 2;
    const y = opts.y != null ? opts.y - r.height - 10 : (window.innerHeight - r.height) / 2;
    const at = clampSafe(x, y, r.width, r.height);
    panel.style.left = at.left + 'px';
    panel.style.top = at.top + 'px';
    setTimeout(() => $('#ep-search').focus(), 0);
  } else {
    panel.style.left = '';
    panel.style.top = '';
  }
}

function closeEmojiPicker() {
  const wrap = $('#emojipk');
  if (!wrap) return;
  // Inline-mounted (composer panel): hand the panel node back to the overlay wrap.
  const panel = wrap.querySelector('.ep-panel') || document.querySelector('.ep-panel');
  if (panel && panel.parentElement !== wrap) {
    panel.classList.remove('inline');
    wrap.appendChild(panel);
  }
  wrap.hidden = true;
  epState = null;
}

// ── Caret insertion (composer + anywhere else that needs it) ─────────────────────
// The composer's emoji button itself lives in 34-composer.js — it opens the docked
// emoji/GIF panel, which mounts this picker inline.
function insertAtCaret(inp, text) {
  const s = inp.selectionStart != null ? inp.selectionStart : inp.value.length;
  const e = inp.selectionEnd != null ? inp.selectionEnd : s;
  inp.value = inp.value.slice(0, s) + text + inp.value.slice(e);
  inp.selectionStart = inp.selectionEnd = s + text.length;
  // Fire the composer's own hooks (autosize, draft, typing signal, mentions).
  inp.dispatchEvent(new Event('input', { bubbles: true }));
}
