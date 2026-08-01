// ═══════════════════════════════════════════════════════════════════════════════
// Per-stream call controls: the three-dot menus on the shared screen and on the
// peer's avatar, the volume sliders behind them, and fullscreen.
//
// Everything here is a *listener-side* control — how loud this device plays somebody,
// whether their share is muted for us, how big the picture is. None of it is sent, so
// the other end never learns they were turned down. The backend owns the levels
// (`call::volume`); this file only draws them and pushes changes.
// ═══════════════════════════════════════════════════════════════════════════════

// Which stream a menu belongs to. `share` = the screen we are watching, `self` = our
// own share, `voice` = the person we are talking to.
//
// `fullscreen` names *which* tile is expanded, not merely that one is: the peer's stage
// and our own share preview are different elements, and the sharer's menu has to expand
// the thing they are looking at. Fullscreening the peer's stage from the self menu put a
// black rectangle over the app whenever the peer had no video, which is most shares.
const volState = { open: null, fullscreen: null };

// ── The popover ───────────────────────────────────────────────────────────────────
// One node, rebuilt per open. `items` is a small spec rather than markup so the three
// menus cannot drift apart in styling or keyboard behaviour.
function closeVolMenu() {
  const m = $('#volmenu');
  m.hidden = true;
  m.innerHTML = '';
  volState.open = null;
  for (const id of ['#cv-menu', '#selfscr-menu', '#call-voicemenu', '#call-barav']) {
    const b = $(id);
    if (b) b.setAttribute('aria-expanded', 'false');
  }
  $('#cv-ctls').classList.remove('open');
  $('#selfscr-menu')?.classList.remove('open');
}

// Must match the thumb size in `.volslider input[type="range"]::-*-slider-thumb`.
const SLIDER_THUMB = 15;

// `y` is the menu's top edge, unless `above` is set — then it is the line the menu's
// *bottom* should sit on. The bar avatar lives at the bottom of the window, and a menu
// dropped below it would be clipped; guessing its height to compensate would go stale
// the moment a row is added, so it is measured instead.
function openVolMenu(x, y, kind, items, anchor, above) {
  const m = $('#volmenu');
  m.innerHTML = '';
  volState.open = kind;
  // Fills that can only be computed once the menu has a width.
  const paints = [];
  for (const it of items) {
    if (it.kind === 'title') {
      const h = document.createElement('h5');
      h.textContent = it.label;
      m.appendChild(h);
    } else if (it.kind === 'sep') {
      m.appendChild(document.createElement('hr'));
    } else if (it.kind === 'check') {
      const b = document.createElement('button');
      b.className = 'volrow';
      b.type = 'button';
      b.setAttribute('role', 'menuitemcheckbox');
      b.setAttribute('aria-checked', it.on ? 'true' : 'false');
      b.innerHTML = `${icon(it.icon || '')}<span>${escapeHtml(it.label)}</span><span class="volcheck" aria-hidden="true"></span>`;
      b.onclick = () => {
        const next = b.getAttribute('aria-checked') !== 'true';
        b.setAttribute('aria-checked', next ? 'true' : 'false');
        // The label flips with the state ("Mute"/"Unmute"), so re-render it in place
        // rather than closing — people nudge these controls repeatedly.
        const lbl = b.querySelector('span');
        if (it.labelFor) lbl.textContent = it.labelFor(next);
        it.fn(next);
      };
      m.appendChild(b);
    } else if (it.kind === 'slider') {
      const wrap = document.createElement('div');
      wrap.className = 'volslider' + (it.disabled ? ' off' : '');
      wrap.innerHTML =
        `<label>${escapeHtml(it.label)}<em>${it.value}%</em></label>` +
        '<div class="volrail"><span class="volrail-fill"></span><span class="volrail-knob"></span>' +
        `<input type="range" min="0" max="${it.max}" step="5" value="${it.value}" aria-label="${escapeHtml(it.label)}"></div>`;
      const out = wrap.querySelector('em');
      const input = wrap.querySelector('input');
      const rail = wrap.querySelector('.volrail');
      const fill = wrap.querySelector('.volrail-fill');
      const knob = wrap.querySelector('.volrail-knob');
      // The thumb's *centre* travels from half a thumb in to half a thumb from the end,
      // not from 0 % to 100 % — so a fill computed straight from the value runs ahead of
      // it in the middle and sits well short of it at the top. Measure the same path the
      // thumb takes. `clientWidth` is only real once the menu is in the document, so the
      // first paint is deferred to `paints` below.
      const paint = () => {
        const span = (input.max - input.min) || 1;
        const frac = (input.value - input.min) / span;
        const w = rail.clientWidth || 1;
        const centre = SLIDER_THUMB / 2 + frac * (w - SLIDER_THUMB);
        fill.style.width = `${centre}px`;
        knob.style.left = `${centre}px`;
      };
      paints.push(paint);
      // `input` fires continuously while dragging: the level has to follow the thumb,
      // because the only way to set a volume is to hear it move.
      input.oninput = () => {
        out.textContent = `${input.value}%`;
        paint();
        it.fn(Number(input.value));
      };
      m.appendChild(wrap);
    } else {
      const b = document.createElement('button');
      b.className = 'volrow' + (it.danger ? ' danger' : '');
      b.type = 'button';
      b.setAttribute('role', 'menuitem');
      b.innerHTML = `${icon(it.icon || '')}<span>${escapeHtml(it.label)}</span>`;
      b.onclick = () => { closeVolMenu(); it.fn(); };
      m.appendChild(b);
    }
  }
  m.hidden = false;
  for (const p of paints) p();
  const r = m.getBoundingClientRect();
  const at = clampSafe(x, above ? y - r.height : y, r.width, r.height);
  m.style.left = `${at.left}px`;
  m.style.top = `${at.top}px`;
  if (anchor) anchor.setAttribute('aria-expanded', 'true');
  // Keep the overlay buttons visible while their menu is open, or the controls fade
  // out from under the pointer the moment it moves onto the menu.
  $('#cv-ctls').classList.toggle('open', kind === 'share');
  $('#selfscr-menu')?.classList.toggle('open', kind === 'self');
  const first = m.querySelector('button, input');
  if (first) setTimeout(() => first.focus(), 0);
}

// Dismissal: anywhere outside, Escape, or the call going away.
document.addEventListener('pointerdown', (e) => {
  if (!volState.open) return;
  if (e.target.closest('#volmenu')) return;
  if (e.target.closest('#cv-menu, #selfscr-menu, #call-voicemenu, #call-barav')) return;
  closeVolMenu();
}, true);
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (volState.open) { e.stopPropagation(); closeVolMenu(); return; }
  // Escape leaves fullscreen before it does anything else with the call.
  if (volState.fullscreen) { e.stopPropagation(); setFullscreen(null); }
}, true);

// ── Fullscreen ────────────────────────────────────────────────────────────────────
// A class, not the Fullscreen API: this has to behave identically inside a WebKitGTK
// webview, a WebView2 one and an Android WebView, and `requestFullscreen` is refused or
// silently ignored in enough of those that a control which sometimes does nothing would
// be worse than one that always covers the window.
const FULL_TARGETS = { peer: '#call-video', self: '#self-scr' };

// `which` is 'peer', 'self', or null for "nothing expanded". Only one at a time.
function setFullscreen(which) {
  volState.fullscreen = which;
  for (const [name, sel] of Object.entries(FULL_TARGETS)) {
    $(sel).classList.toggle('full', which === name);
  }
  // The self preview's wrapper is what actually expands — see `.call-self.selffull`.
  $('#call-self').classList.toggle('selffull', which === 'self');
  const b = $('#cv-full');
  const on = which === 'peer';
  b.innerHTML = icon(on ? 'unfull' : 'full');
  b.setAttribute('aria-label', on ? 'Exit fullscreen' : 'Fullscreen');
  b.title = b.getAttribute('aria-label');
}
function toggleFullscreen(which) {
  setFullscreen(volState.fullscreen === which ? null : which);
}

// ── Menu contents ─────────────────────────────────────────────────────────────────
async function shareMenuItems() {
  let v = { gain: 50, muted: false, max: 100 };
  try { v = await invoke('call_share_volume'); } catch { /* defaults are fine */ }
  const who = callUi.username || 'This stream';
  return [
    { kind: 'title', label: `${who}'s screen` },
    {
      kind: 'check',
      label: v.muted ? 'Unmute stream' : 'Mute stream',
      labelFor: (on) => (on ? 'Unmute stream' : 'Mute stream'),
      icon: 'voloff',
      on: v.muted,
      fn: (on) => {
        invoke('call_set_share_muted', { muted: on }).catch((e) => toast(say(e), 'err'));
        const sl = $('#volmenu .volslider');
        if (sl) sl.classList.toggle('off', on);
      },
    },
    {
      kind: 'slider',
      label: 'Stream volume',
      value: v.gain,
      max: v.max,
      disabled: v.muted,
      fn: (n) => invoke('call_set_share_gain', { percent: n }).catch(() => {}),
    },
    { kind: 'sep' },
    {
      kind: 'item',
      label: volState.fullscreen === 'peer' ? 'Minimise' : 'Fullscreen',
      icon: volState.fullscreen === 'peer' ? 'unfull' : 'full',
      fn: () => toggleFullscreen('peer'),
    },
  ];
}

// Our own share: there is nothing to turn down (it is never played back to us), so the
// menu is the two things that *are* ours to do with it.
function selfShareMenuItems() {
  return [
    { kind: 'title', label: 'Your screen' },
    {
      kind: 'item',
      label: volState.fullscreen === 'self' ? 'Minimise' : 'Fullscreen',
      icon: volState.fullscreen === 'self' ? 'unfull' : 'full',
      fn: () => toggleFullscreen('self'),
    },
    { kind: 'sep' },
    {
      kind: 'item',
      label: 'Stop screen share',
      icon: 'stopsq',
      danger: true,
      fn: () => setScreenShare(false),
    },
  ];
}

async function voiceMenuItems() {
  const who = callUi.username;
  if (!who) return null;
  let v = { gain: 100, muted: false, max: 200 };
  try { v = await invoke('call_voice_volume', { username: who }); } catch { /* defaults */ }
  return [
    { kind: 'title', label: who },
    {
      kind: 'check',
      label: v.muted ? 'Unmute voice audio' : 'Mute voice audio',
      labelFor: (on) => (on ? 'Unmute voice audio' : 'Mute voice audio'),
      icon: 'voloff',
      on: v.muted,
      fn: (on) => {
        invoke('call_set_voice_muted', { username: who, muted: on })
          .catch((e) => toast(say(e), 'err'));
        const sl = $('#volmenu .volslider');
        if (sl) sl.classList.toggle('off', on);
      },
    },
    {
      kind: 'slider',
      label: 'Voice volume',
      value: v.gain,
      max: v.max,
      disabled: v.muted,
      // Saved against the contact, so it is still there next time you call them.
      fn: (n) => invoke('call_set_voice_gain', { username: who, percent: n }).catch(() => {}),
    },
  ];
}

// ── Openers ───────────────────────────────────────────────────────────────────────
async function openShareMenu(x, y) {
  if (volState.open === 'share') return closeVolMenu();
  openVolMenu(x, y, 'share', await shareMenuItems(), $('#cv-menu'));
}
function openSelfShareMenu(x, y) {
  if (volState.open === 'self') return closeVolMenu();
  openVolMenu(x, y, 'self', selfShareMenuItems(), $('#selfscr-menu'));
}
async function openVoiceMenu(x, y, opts = {}) {
  if (volState.open === 'voice') return closeVolMenu();
  const items = await voiceMenuItems();
  if (!items) return; // group call: no single person to attach a level to
  openVolMenu(x, y, 'voice', items, opts.anchor || $('#call-voicemenu'), opts.above);
}

// Anchor a menu under a button rather than at the pointer, so the keyboard path and
// the touch path both land somewhere sensible.
function underButton(btn) {
  const r = btn.getBoundingClientRect();
  return [r.left, r.bottom + 6];
}

// ── Wiring ────────────────────────────────────────────────────────────────────────
$('#cv-menu').onclick = (e) => { e.stopPropagation(); openShareMenu(...underButton(e.currentTarget)); };
$('#cv-full').onclick = (e) => { e.stopPropagation(); toggleFullscreen('peer'); };
$('#selfscr-menu').onclick = (e) => { e.stopPropagation(); openSelfShareMenu(...underButton(e.currentTarget)); };
$('#call-voicemenu').onclick = (e) => { e.stopPropagation(); openVoiceMenu(...underButton(e.currentTarget)); };
// The bar avatar opens the same menu — anchored *above* it, since the bar is at the
// bottom of the screen and a menu dropped below it would be clipped off.
$('#call-barav').onclick = (e) => {
  e.stopPropagation();
  const r = e.currentTarget.getBoundingClientRect();
  openVoiceMenu(r.left, r.top - 8, { above: true, anchor: e.currentTarget });
};

// Right-click anywhere on the stream you are watching. The whole picture is the target
// — hunting for a 34-pixel button is not how anyone reaches for this.
$('#call-video').oncontextmenu = (e) => {
  if ($('#cv-ctls').hidden) return; // nothing being watched
  e.preventDefault();
  e.stopPropagation();
  openShareMenu(e.clientX, e.clientY);
};
// …and on your own share tile, which gets the other menu.
$('#self-scr').oncontextmenu = (e) => {
  e.preventDefault();
  e.stopPropagation();
  openSelfShareMenu(e.clientX, e.clientY);
};
// The avatar is the peer, so right-clicking it is the voice menu. The name in the top
// bar too: during a video call the avatar is hidden behind the picture, and the control
// has to stay reachable.
for (const sel of ['#call-avatar', '#call-barav', '#call-topname', '#call-barname']) {
  const el = $(sel);
  if (!el) continue;
  el.oncontextmenu = (e) => {
    if (!callUi.username || callUi.group) return;
    e.preventDefault();
    e.stopPropagation();
    openVoiceMenu(e.clientX, e.clientY);
  };
}
// Touch has no right-click: long-press opens the same menus.
if (typeof onHold === 'function') {
  onHold($('#call-video'), (x, y) => { if (!$('#cv-ctls').hidden) openShareMenu(x, y); });
  onHold($('#call-avatar'), (x, y) => openVoiceMenu(x, y));
}

// ── Anchoring the controls to the picture, not the box ────────────────────────────
// `#call-video` fills the stage; the canvas inside it is letterboxed to the stream's
// aspect ratio, so a stream that is wider than it is tall leaves a lot of empty box
// above it. Pinning the buttons to the box's corner put them floating in that gap,
// nowhere near the video. Measure the tile and sit on *its* corner instead.
//
// Fullscreen is left to CSS: there the picture fills the window and the corner is the
// corner.
function positionStreamControls() {
  const ctls = $('#cv-ctls');
  const vid = $('#call-video');
  if (ctls.hidden) return;
  if (vid.classList.contains('full')) {
    ctls.style.left = ctls.style.top = ctls.style.right = '';
    return;
  }
  // The screen share is the tile these controls are about; fall back to the camera so
  // they still land on a picture during a camera-only call.
  const scr = $('#cv-screen');
  const tile = !scr.hidden ? scr : $('#cv-camera');
  if (tile.hidden) return;
  const t = tile.getBoundingClientRect();
  const p = vid.getBoundingClientRect();
  if (!t.width || !t.height) return; // no frame painted yet
  const w = ctls.offsetWidth || 74;
  ctls.style.right = 'auto';
  ctls.style.left = `${Math.round(t.right - p.left - w - 10)}px`;
  ctls.style.top = `${Math.round(t.top - p.top + 10)}px`;
}
// The tile resizes on a window resize and whenever the stream's dimensions change.
window.addEventListener('resize', positionStreamControls);

// ── State ─────────────────────────────────────────────────────────────────────────
// Called from the call UI whenever the peer's tracks or the call itself change.
function syncCallMenus() {
  // The video stage is *moved* into the corner bubble when the call is collapsed (see
  // 81-callmini): overlay buttons and a per-stream menu make no sense at that size, and
  // the bubble has its own controls.
  const watching = !$('#call-video').hidden && !callUi.collapsed;
  $('#cv-ctls').hidden = !watching;
  positionStreamControls();
  // The voice menu needs exactly one person to point at: a group call has no avatar
  // per participant to hang it off, so it stays hidden there.
  const oneToOne = callUi.mode === 'connected' && !!callUi.username && !callUi.group;
  $('#call-voicemenu').hidden = !oneToOne;
  // In the bar only while something is covering the idle card's avatar — otherwise the
  // same control would be offered twice, a foot apart.
  $('#call-barav').hidden = !(oneToOne && watching);
  // A stream that stopped cannot stay fullscreen, and a menu about it cannot stay open.
  if (!watching) {
    if (volState.fullscreen === 'peer') setFullscreen(null);
    if (volState.open === 'share') closeVolMenu();
  }
  // Our share stopped: its preview is gone, so it cannot stay expanded either.
  if (!callUi.screenOn) {
    if (volState.fullscreen === 'self') setFullscreen(null);
    if (volState.open === 'self') closeVolMenu();
  }
}

// Ending a call drops every per-call control back to its resting state. The backend
// resets its own levels when the next call starts; this is the view side of that.
function resetCallMenus() {
  closeVolMenu();
  setFullscreen(null);
}
