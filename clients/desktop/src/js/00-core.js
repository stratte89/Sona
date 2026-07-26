// Sona desktop/mobile UI. All security logic is in the Rust `client-core` SDK; this file
// only invokes Tauri commands, routes between screens, and renders results.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// Android build of the same app (Tauri webview UA carries "Android"). Gates the
// mobile-only controls (loudspeaker route) and touch-first UX branches.
const IS_ANDROID = /android/i.test(navigator.userAgent);

// This account's username (set on unlock) — drives "your own mention" highlighting
// and keeps the @mention picker from offering yourself.
let myName = '';

// Reserved peer key of the local note-to-self thread (mirrors client-core's
// NOTE_TO_SELF_PEER — can never collide with a real identity key).
const NOTE_PEER = 'note:self';

// ── Bounded session cache (LRU) ──────────────────────────────────────────────
// Decrypted media (image data-URLs, voice/video blob URLs) is cached for the session so
// nothing re-downloads on repaint — but an image-heavy chat must not grow memory until
// the next lock. Map insertion order gives the LRU: get() re-inserts, eviction pops the
// oldest until both the entry cap and the byte budget hold. `onEvict` releases whatever
// the value holds (revoke blob URLs, pause audio); an evicted entry just re-fetches.
class LruCache {
  constructor({ max = Infinity, budget = Infinity, cost = () => 0, onEvict = null } = {}) {
    this.max = max; this.budget = budget; this.costOf = cost; this.onEvict = onEvict;
    this.map = new Map(); this.spent = 0;
  }
  get(k) {
    if (!this.map.has(k)) return undefined;
    const v = this.map.get(k);
    this.map.delete(k); this.map.set(k, v); // refresh recency
    return v;
  }
  set(k, v) {
    if (this.map.has(k)) { this.spent -= this.costOf(this.map.get(k)); this.map.delete(k); }
    this.map.set(k, v);
    this.spent += this.costOf(v);
    while (this.map.size > 1 && (this.map.size > this.max || this.spent > this.budget)) {
      const [ek, ev] = this.map.entries().next().value;
      this.map.delete(ek);
      this.spent -= this.costOf(ev);
      if (this.onEvict) try { this.onEvict(ev, ek); } catch (_) {}
    }
  }
  forEach(fn) { this.map.forEach(fn); }
  delete(k) {
    if (!this.map.has(k)) return;
    const v = this.map.get(k);
    this.map.delete(k);
    this.spent -= this.costOf(v);
    if (this.onEvict) try { this.onEvict(v, k); } catch (_) {}
  }
  clear() {
    if (this.onEvict) this.map.forEach((v, k) => { try { this.onEvict(v, k); } catch (_) {} });
    this.map.clear(); this.spent = 0;
  }
}

// ── Inline icons (no external assets, CSP-safe) ──────────────────────────────
const ICONS = {
  lock:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10.5" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/><circle cx="12" cy="15.5" r="1.4" fill="currentColor" stroke="none"/></svg>',
  gear:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 7 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H1a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 2.6 7a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H7a1.6 1.6 0 0 0 1-1.5V1a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 2.7 1.1 1.6 1.6 0 0 0 .3-1.8"/></svg>',
  plus:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  back:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>',
  send:  '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3.4 20.4l17.6-8.4a.7.7 0 0 0 0-1.3L3.4 2.3a.7.7 0 0 0-1 .8L4.7 11l12 1-12 1L2.4 19.6a.7.7 0 0 0 1 .8z"/></svg>',
  clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
  chat:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.5 8.5 0 0 1-12.3 7.6L3 21l1.9-5.7A8.5 8.5 0 1 1 21 11.5z"/></svg>',
  shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.3-7 9.5C8 22.3 5 18.5 5 14V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4L19 6"/></svg>',
  checks:'<svg viewBox="0 0 28 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M2 13l4 4L16 6"/><path d="M11 17L21 6"/></svg>',
  clip:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.4 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 1 1 5.66 5.66L9.4 17.4a2 2 0 0 1-2.83-2.83l8.49-8.49"/></svg>',
  file:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7z"/><path d="M14 2v5h5"/></svg>',
  down:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v12m0 0l-5-5m5 5l5-5"/><path d="M4 20h16"/></svg>',
  x:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  search:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>',
  up:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 15l-6-6-6 6"/></svg>',
  downchev:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
  bell:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg>',
  belloff:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13.7 21a2 2 0 0 1-3.4 0"/><path d="M18.6 13c-.4-1.4-.6-3-.6-5a6 6 0 0 0-9.3-5M6.3 6.3C6.1 6.8 6 7.4 6 8c0 7-3 9-3 9h14"/><path d="M2 2l20 20"/></svg>',
  edit:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/></svg>',
  users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
  block: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M5.5 5.5l13 13"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6M14 11v6"/></svg>',
  pin:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5M9 3h6l1 7 3 2v2H5v-2l3-2z"/></svg>',
  mic:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2.5" width="6" height="11.5" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3.5"/></svg>',
  play:  '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 4.8v14.4a.8.8 0 0 0 1.2.7l11.5-7.2a.8.8 0 0 0 0-1.4L8.2 4.1A.8.8 0 0 0 7 4.8z"/></svg>',
  pause: '<svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4.4" height="16" rx="1.4"/><rect x="13.6" y="4" width="4.4" height="16" rx="1.4"/></svg>',
  stopsq:'<svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2.5"/></svg>',
  phone: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.3 1.9.6 2.8a2 2 0 0 1-.5 2.1L8 9.9a16 16 0 0 0 6 6l1.3-1.2a2 2 0 0 1 2.1-.5c.9.3 1.9.5 2.8.6a2 2 0 0 1 1.8 2.1z"/></svg>',
  phonedown:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><g transform="rotate(135 12 12)"><path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.3 1.9.6 2.8a2 2 0 0 1-.5 2.1L8 9.9a16 16 0 0 0 6 6l1.3-1.2a2 2 0 0 1 2.1-.5c.9.3 1.9.5 2.8.6a2 2 0 0 1 1.8 2.1z"/></g></svg>',
  micoff:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2.5" width="6" height="11.5" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3.5"/><path d="M3 3l18 18"/></svg>',
  noise: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h2l2.5-7 3.5 14 3.5-14 2.5 7h2"/><path d="M20 9.5v5"/><path d="M22.5 11v2"/></svg>',
  gear:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.11-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1.11 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.08A1.7 1.7 0 0 0 10 3.09V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.08A1.7 1.7 0 0 0 20.91 10H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1z"/></svg>',
  cam:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="6" width="13" height="12" rx="2.5"/><path d="M15.5 10.5l5-3v9l-5-3"/></svg>',
  camoff:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="6" width="13" height="12" rx="2.5"/><path d="M15.5 10.5l5-3v9l-5-3"/><path d="M3 3l18 18"/></svg>',
  screen:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
  vol:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5L6.5 9H3v6h3.5L11 19V5z"/><path d="M15.5 8.5a5 5 0 0 1 0 7M18.5 5.5a9 9 0 0 1 0 13"/></svg>',
  bt:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6.5 7l11 10-5.5 4.5v-19L17.5 7l-11 10"/></svg>',
  copy:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  qr:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM21 14v.01M14 21h.01M18 18h3v3h-3z"/></svg>',
  info:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.5" r="0.5" fill="currentColor"/></svg>',
  bookmark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6.5 3.5h11a1 1 0 0 1 1 1V21l-6.5-4-6.5 4V4.5a1 1 0 0 1 1-1z"/></svg>',
  smile: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M9 10h.01M15 10h.01"/><path d="M8.5 14.5a4 4 0 0 0 7 0"/></svg>',
  camera:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>',
  keyboard:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M6 14h.01M18 14h.01M9 14h6"/></svg>',
  image: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5" fill="currentColor" stroke="none"/><path d="M21 15l-5-5L5 21"/></svg>',
  flip:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/></svg>',
  expand:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>',
  // Collapse-the-call-into-a-bubble: a screen with a picture-in-picture tile.
  pip:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4.5" width="19" height="15" rx="2.5"/><rect x="11.5" y="11" width="8" height="6" rx="1.5" fill="currentColor" stroke="none"/></svg>',
};
const icon = (name) => ICONS[name] || '';
$$('[data-icon]').forEach((el) => (el.innerHTML = icon(el.dataset.icon)));

// ── Mobile safe areas ────────────────────────────────────────────────────────
// The Android build is edge-to-edge (viewport-fit=cover), so the top/bottom strips of the
// screen belong to the status bar and the gesture bar. CSS keeps clear of them with
// env(safe-area-inset-*); anything positioned from JS has to ask for the same numbers, or
// it lands under the system UI (this is exactly how the chat-list header and the lightbox
// buttons broke). Measured off a probe element because custom properties don't reliably
// resolve env() when read back. Cached; the insets only change on rotation/resize.
let safeCache = null;
function safeInsets() {
  if (safeCache) return safeCache;
  const probe = document.createElement('div');
  probe.style.cssText =
    'position:fixed;top:0;left:0;visibility:hidden;pointer-events:none;' +
    'padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);' +
    'padding-left:env(safe-area-inset-left,0px);padding-right:env(safe-area-inset-right,0px);';
  document.body.appendChild(probe);
  const cs = getComputedStyle(probe);
  safeCache = {
    top: parseFloat(cs.paddingTop) || 0,
    bottom: parseFloat(cs.paddingBottom) || 0,
    left: parseFloat(cs.paddingLeft) || 0,
    right: parseFloat(cs.paddingRight) || 0,
  };
  probe.remove();
  return safeCache;
}
window.addEventListener('resize', () => { safeCache = null; });
// Clamp a screen-anchored box (menus, sheets, pickers) into the *usable* viewport.
const SAFE_GAP = 8;
function clampSafe(left, top, w, h) {
  const s = safeInsets();
  return {
    left: Math.max(s.left + SAFE_GAP, Math.min(left, window.innerWidth - s.right - w - SAFE_GAP)),
    top: Math.max(s.top + SAFE_GAP, Math.min(top, window.innerHeight - s.bottom - h - SAFE_GAP)),
  };
}

// ── Toast ────────────────────────────────────────────────────────────────────
let toastTimer;
function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = 'toast ' + kind), 2600);
}
// Turn a backend error into something a human can read.
function say(e) { return typeof e === 'string' ? e : (e && e.message) || String(e); }

// Busy state for a button: disable + spinner + optional label swap, restore after.
function busy(btn, on, labelWhile) {
  if (on) {
    btn.dataset.label = btn.innerHTML;
    btn.disabled = true; btn.classList.add('loading');
    btn.innerHTML = `<span class="spinner-sm"></span>${labelWhile || btn.textContent}`;
  } else {
    btn.disabled = false; btn.classList.remove('loading');
    if (btn.dataset.label) { btn.innerHTML = btn.dataset.label; delete btn.dataset.label; }
  }
}

// ── Modal / action sheet ────────────────────────────────────────────────────────
let modalOpener = null;
// `onCall: true` lifts the modal above the call overlay (z 60) — used by dialogs opened
// FROM the call UI (audio-route chooser). Ordinary modals stay below it on purpose: an
// incoming call must cover whatever dialog was open.
function openModal(html, { onCall = false } = {}) {
  modalOpener = document.activeElement;
  const card = $('#modal-card');
  card.innerHTML = html;
  $('#modal').classList.toggle('oncall', onCall);
  $('#modal').hidden = false;
  // Move focus inside so the trap and Esc work and screen readers land in the dialog.
  const first = card.querySelector('input, textarea, select, button');
  if (first) setTimeout(() => first.focus(), 0);
  return card;
}
function closeModal() {
  $('#modal').hidden = true;
  $('#modal').classList.remove('oncall');
  $('#modal-card').innerHTML = '';
  // Return focus to whatever opened the modal (accessibility).
  if (modalOpener && modalOpener.isConnected) { try { modalOpener.focus(); } catch (_) {} }
  modalOpener = null;
}
$('#modal').addEventListener('click', (e) => { if (e.target === $('#modal')) closeModal(); });
// Focus trap: Tab cycles within the modal card; Esc closes it.
$('#modal').addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { e.preventDefault(); closeModal(); return; }
  if (e.key !== 'Tab') return;
  const items = $$('#modal-card').flatMap((c) => $$('a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])', c));
  if (!items.length) return;
  const first = items[0], last = items[items.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});

// "Are you sure" — resolves true only on explicit confirm.
function confirmModal(title, desc, confirmLabel) {
  return new Promise((resolve) => {
    const card = openModal(
      `<h3>${escapeHtml(title)}</h3><p>${escapeHtml(desc)}</p>
       <button class="btn btn-danger" id="mo-yes">${escapeHtml(confirmLabel)}</button>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    card.querySelector('#mo-yes').onclick = () => { closeModal(); resolve(true); };
    card.querySelector('#mo-no').onclick = () => { closeModal(); resolve(false); };
  });
}

// ── Context menu (right-click / long-press) ─────────────────────────────────────
function showCtx(x, y, items) {
  const m = $('#ctxmenu');
  m.className = 'ctxmenu';
  m.innerHTML = '';
  for (const it of items) {
    const b = document.createElement('button');
    if (it.danger) b.className = 'danger';
    b.innerHTML = `${icon(it.icon || '')}${escapeHtml(it.label)}`;
    b.onclick = () => { hideCtx(); it.fn(); };
    m.appendChild(b);
  }
  m.hidden = false;
  const r = m.getBoundingClientRect();
  const at = clampSafe(x, y, r.width, r.height);
  m.style.left = at.left + 'px';
  m.style.top = at.top + 'px';
  const firstBtn = m.querySelector('button');
  if (firstBtn) setTimeout(() => firstBtn.focus(), 0);
  // Keyboard navigation: arrows move, Enter activates, Esc closes (I).
  m.onkeydown = (e) => {
    const btns = $$('button', m);
    if (!btns.length) return;
    let i = btns.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); btns[(i + 1 + btns.length) % btns.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); btns[(i - 1 + btns.length) % btns.length].focus(); }
    else if (e.key === 'Escape') { e.preventDefault(); hideCtx(); }
  };
}
function hideCtx() { const m = $('#ctxmenu'); m.hidden = true; m.className = 'ctxmenu'; }
document.addEventListener('click', hideCtx);
document.addEventListener('contextmenu', (e) => { if (!e.target.closest('.conv')) hideCtx(); });

// Long-press support (Android / touch): fire the same menu as right-click.
function onHold(el, fn) {
  let t;
  el.addEventListener('touchstart', (e) => { t = setTimeout(() => fn(e.touches[0].clientX, e.touches[0].clientY), 550); }, { passive: true });
  el.addEventListener('touchend', () => clearTimeout(t));
  el.addEventListener('touchmove', () => clearTimeout(t));
}

// Stable per-user hue so every contact gets their own avatar color.
function hue(name) {
  let h = 0;
  for (const c of String(name)) h = (h * 31 + c.codePointAt(0)) % 360;
  return h;
}

// ── Profile pictures ───────────────────────────────────────────────────────────
// A picture is only ever a bounded, base64 `data:` image URI. This is the same gate the
// Rust side enforces (client-core `valid_avatar`), applied again here so a value coming
// out of history can only ever land in an <img src> — never markup, never a remote URL
// (no injected script, no external fetch). Keep the limit in sync with `MAX_AVATAR_BYTES`.
const MAX_AVATAR_BYTES = 262144;
function isAvatar(s) {
  return typeof s === 'string' && s.length <= MAX_AVATAR_BYTES &&
    /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(s);
}
// Inner HTML for a `.avatar` element: the picture if we have a valid one, else the
// generated fallback (a group glyph for groups, otherwise the name's first letter).
function avatarInner(av, label, isGroup) {
  if (isAvatar(av)) return `<img class="av-img" alt="" src="${av}">`;
  return isGroup ? icon('users') : escapeHtml(initial(label));
}
// Downscale + center-crop an image File to a small square JPEG `data:` URI. Kept tiny so a
// picture rides a single ratchet message — fast to send, cheap to store. Steps quality down
// until it fits the cap; rejects if it still won't.
function fileToAvatar(file) {
  return new Promise((resolve, reject) => {
    if (!file || !/^image\//.test(file.type || '')) return reject(new Error('not an image'));
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      const S = 256;
      const canvas = document.createElement('canvas');
      canvas.width = S; canvas.height = S;
      const ctx = canvas.getContext('2d');
      const side = Math.min(img.width, img.height);
      if (!side) return reject(new Error('empty image'));
      ctx.drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, S, S);
      let q = 0.85, out = canvas.toDataURL('image/jpeg', q);
      while (out.length > MAX_AVATAR_BYTES && q > 0.4) { q -= 0.15; out = canvas.toDataURL('image/jpeg', q); }
      if (out.length > MAX_AVATAR_BYTES) return reject(new Error('image too large'));
      resolve(out);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('could not read image')); };
    img.src = url;
  });
}
// Paint an existing `.avatar` DOM node: the picture if valid, else the generated fallback,
// with a stable per-identity hue for the fallback gradient.
function setAvatarEl(el, av, label, isGroup, hueSeed) {
  if (!el) return;
  el.innerHTML = avatarInner(av, label, isGroup);
  el.style.setProperty('--av-h', hue(hueSeed != null ? hueSeed : label));
}

// Open the OS image picker and resolve to a processed avatar data URI (or null if the user
// cancelled / the file was unusable — a toast already explained why).
function pickAvatar() {
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = 'image/*';
    inp.onchange = () => {
      const f = inp.files && inp.files[0];
      if (!f) return resolve(null);
      fileToAvatar(f).then(resolve).catch((e) => { toast(say(e), 'err'); resolve(null); });
    };
    inp.click();
  });
}

// Display-only name clamp: anything past 25 chars ellipsizes so a long name can never
// blow up a header (CSS text-overflow stays as the pixel-level safety net).
function ell25(n) {
  n = String(n || '');
  return n.length > 25 ? n.slice(0, 25).trimEnd() + '…' : n;
}

// Short human label for a disappearing timer.
function tlabel(secs) {
  if (!secs) return '';
  if (secs < 3600) return (secs / 60) + 'm';
  if (secs < 86400) return (secs / 3600) + 'h';
  return (secs / 86400) + 'd';
}

// ── Screen router ─────────────────────────────────────────────────────────────
let current = 'loading';
const ORDER = ['loading', 'connect', 'create', 'unlock', 'link', 'revoked', 'accessdenied', 'chats', 'requests', 'thread', 'chatsettings', 'groupsettings', 'newchat', 'newgroup', 'settings'];
// Screens that live in the main pane on wide (desktop) layouts — the chats list
// stays visible next to them as a sidebar.
const MAIN_SCREENS = new Set(['requests', 'thread', 'chatsettings', 'groupsettings', 'newchat', 'newgroup', 'settings']);
// Where the system back button/gesture goes from each screen. Screens not listed
// are roots: back leaves the app (Android) / does nothing (desktop).
const BACK_TO = { requests: 'chats', thread: 'chats', chatsettings: 'thread', groupsettings: 'thread', newchat: 'chats', newgroup: 'chats', settings: 'chats' };

const wideMq = window.matchMedia('(min-width: 900px)');
wideMq.addEventListener('change', () => show(current, true));

function show(name, fromPop) {
  const wide = wideMq.matches;
  const back = ORDER.indexOf(name) < ORDER.indexOf(current);
  $$('.screen').forEach((s) => {
    const n = s.dataset.screen;
    const active = n === name || (wide && n === 'chats' && MAIN_SCREENS.has(name));
    s.classList.toggle('is-active', active);
    s.classList.toggle('is-back', !active && back);
  });
  $('#main-empty').hidden = !(wide && name === 'chats');
  // Every forward navigation into a non-root screen leaves a history entry, so the
  // Android back button/gesture walks the app instead of closing it. The chat list
  // (root) gets one guard entry too — that is what routes its back press into the
  // double-back-to-exit handler instead of straight out of the app.
  if (!fromPop && name !== current && (BACK_TO[name] || name === 'chats')) {
    history.pushState({ s: name }, '');
  }
  current = name;
  // Invite-gated relays: reveal the create screen's code field (async fill-in; the
  // server enforces regardless, this only saves a doomed submit).
  if (name === 'create') probeInviteField();
  // Re-entering the connect screen on an already-configured app (Change relay, or the
  // access-denied recovery path): prefill the address + pinned key so the user only
  // types what actually changed. The token is deliberately NOT prefilled — on the
  // rotation path the old one is dead, and pasting a fresh invite fills it anyway.
  if (name === 'connect') prefillConnect();
}

async function probeInviteField() {
  try {
    $('#cr-invite-wrap').hidden = !(await invoke('registration_needs_invite'));
  } catch (_) { /* leave hidden — enforcement is server-side */ }
}

async function prefillConnect() {
  const el = $('#cx-server');
  // Never clobber something the user already typed this session.
  if (el.value.trim() && el.value.trim() !== '127.0.0.1:5002') return;
  try {
    const inv = parseInvite(await invoke('relay_invite'));
    if (!inv) return;
    const m = /^(https?:\/\/)(.*)$/i.exec(inv.url);
    $('#cx-scheme').value = m[1].toLowerCase();
    el.value = m[2];
    if (!$('#cx-pin').value.trim()) $('#cx-pin').value = inv.kt;
  } catch (_) { /* not configured yet — leave the defaults */ }
}
$$('[data-goto]').forEach((el) => (el.onclick = () => show(el.dataset.goto)));

// Back-press router: close whatever is on top, else step to the parent screen.
// Returns true when the press was consumed (an overlay closed or a screen navigated),
// false when we're at a root and the press means "leave".
function routeBack() {
  const epk = $('#emojipk');
  if (epk && !epk.hidden) { closeEmojiPicker(); return true; }
  if (!$('#camui').hidden) { closeCamera(); return true; }
  if (!$('#msel').hidden) { closeMsel(); return true; }
  if (cmpPanelOpen()) { closeCmpPanel(); return true; }
  if (!$('#scanui').hidden) { $('#scan-cancel').click(); return true; }
  if (!$('#vidbox').hidden) { closeVidbox(); return true; }
  if (!$('#lightbox').hidden) { closeLightbox(); return true; }
  if (!$('#modal').hidden) { closeModal(); return true; }
  if (!$('#msheet').hidden) { closeMsgSheet(); return true; }
  if (!$('#ctxmenu').hidden) { hideCtx(); return true; }
  // Back on a live call screen minimises it into the bubble (the call keeps running)
  // rather than navigating the app underneath it. An incoming ring has no bubble to
  // fall back to, so it keeps the screen until it is answered or declined.
  if (!$('#callui').hidden && callUi.mode && callUi.mode !== 'incoming') {
    setCollapsed(true);
    return true;
  }
  if (current === 'thread' && !$('#th-searchbar').hidden) { $('#th-searchclose').click(); return true; }
  const to = BACK_TO[current];
  if (to) { navBack(to); return true; }
  return false;
}
// At the chat-list root, leaving is a deliberate double-back — and it backgrounds the
// app via the OS task stack instead of killing the process, which keeps delivery running.
let exitArmedAt = 0;
function rootBack() {
  if (Date.now() - exitArmedAt < 1800) {
    invoke('app_background').catch(() => {});
  } else {
    exitArmedAt = Date.now();
    toast('Press back again to exit', '');
  }
}
// In-app history pops (header back buttons, Esc — they call history.back()). EVERY
// handled pop re-arms a guard entry so the webview history stack never drains.
window.addEventListener('popstate', () => {
  const rearm = () => history.pushState({ s: current }, '');
  if (routeBack()) { rearm(); return; }
  if (current === 'chats' && IS_ANDROID) { rootBack(); rearm(); }
  // Auth/loading screens: nothing to re-arm.
});
// The Android SYSTEM back button/gesture. Dispatched straight from Kotlin
// (MainActivity's OnBackPressedCallback → evaluateJavascript), NEVER through webview
// history: the old canGoBack()/goBack() route raced the popstate re-arm above — a
// fast back press could observe a drained stack and close the whole activity from
// inside a chat. Here the router decides synchronously; at a root we background the
// app ourselves (task stack, process alive, delivery running).
window.__sonaBack = () => {
  if (routeBack()) return 'ok';
  if (current === 'chats') { rootBack(); return 'ok'; }
  // Auth/loading roots: back means leave — background, never kill.
  invoke('app_background').catch(() => {});
  return 'ok';
};

function navBack(to) {
  if (to === 'chats') {
    cancelVoice(); stopNowPlaying();
    saveDraft(); // leaving the thread parks its composer state (text/reply/queue)
    show('chats', true); loadChats();
  } else if (to === 'thread') {
    show('thread', true);
    if (cur.peer) (cur.kind === 'group' ? renderGroupThread(cur.peer) : renderThread(cur.peer));
  } else {
    show(to, true);
  }
}

// ── Time formatting ────────────────────────────────────────────────────────────
function hhmm(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function relday(ts) {
  const d = new Date(ts * 1000), now = new Date();
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = (day(now) - day(d)) / 86400000;
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

