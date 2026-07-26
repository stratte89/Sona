// ═══════════════════════════════════════════════════════════════════════════════
// The minimised call: collapse the call screen into a draggable corner bubble so the
// chat list and every conversation stay usable while the call runs. Loaded after
// 80-calls.js — it drives that file's `callUi` state and is driven by its showCall/
// hideCall (and by the Android back button, via routeBack in 00-core.js).
//
// The peer-video element is MOVED between the stage and the bubble rather than
// duplicated — the WebGL contexts that paint it belong to those canvases and survive a
// reparent, while a second set of canvases would never receive a frame.
// ═══════════════════════════════════════════════════════════════════════════════
function setCollapsed(on) {
  if (!callUi.mode) on = false;
  callUi.collapsed = on;
  const video = $('#call-video');
  const home = on ? $('#cm-stage') : $('#call-stage');
  if (video.parentElement !== home) home.insertBefore(video, home.firstChild);
  $('#callui').hidden = on;
  $('#callmini').hidden = !on;
  updateVideoStage(); // avatar vs. video, in whichever container now holds it
  if (on) {
    $('#call-settings').hidden = true; // the gear modal belongs to the full screen
    placeMini(false);
  } else {
    placePip(false); // self-view PiP re-anchors to the restored stage
  }
  paintCallState();
}

// Same transform-from-top-left mechanism as the self-view PiP, and the same
// snap-to-corner on release; the corner persists across calls.
const callMini = { corner: localStorage.getItem('sona-callmini-corner') || 'br', drag: null, moved: false };
function placeMini(animate) {
  const el = $('#callmini');
  if (el.hidden) return;
  const m = 14;
  // The bubble is placed by transform, so it cannot inherit the CSS safe-area insets
  // the rest of the edge-to-edge UI uses; --cm-sa* carry them here (0 where the engine
  // does not substitute env() into a custom property — desktop has no insets anyway).
  const cs = getComputedStyle(el);
  const inset = (n) => parseFloat(cs.getPropertyValue(n)) || 0;
  const x = callMini.corner.includes('l') ? m + inset('--cm-sal')
    : window.innerWidth - el.offsetWidth - m - inset('--cm-sar');
  const y = callMini.corner.includes('t') ? m + inset('--cm-sat')
    : window.innerHeight - el.offsetHeight - m - 8 - inset('--cm-sab');
  el.classList.toggle('snap', !!animate);
  el.style.transform = `translate(${Math.max(0, x)}px, ${Math.max(0, y)}px)`;
}
(() => {
  const el = $('#callmini');
  el.addEventListener('pointerdown', (e) => {
    if (el.hidden || e.target.closest('button')) return;
    const r = el.getBoundingClientRect();
    callMini.drag = { id: e.pointerId, dx: e.clientX - r.left, dy: e.clientY - r.top };
    callMini.moved = false;
    el.setPointerCapture(e.pointerId);
    el.classList.remove('snap');
  });
  el.addEventListener('pointermove', (e) => {
    const d = callMini.drag;
    if (!d || e.pointerId !== d.id) return;
    callMini.moved = true;
    el.style.transform = `translate(${e.clientX - d.dx}px, ${e.clientY - d.dy}px)`;
  });
  const drop = (e) => {
    const d = callMini.drag;
    if (!d || e.pointerId !== d.id) return;
    callMini.drag = null;
    const r = el.getBoundingClientRect();
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    callMini.corner = (cy < window.innerHeight / 2 ? 't' : 'b') + (cx < window.innerWidth / 2 ? 'l' : 'r');
    try { localStorage.setItem('sona-callmini-corner', callMini.corner); } catch (_) {}
    placeMini(true);
    // A tap (no drag) on the bubble body is "take me back to the call".
    if (!callMini.moved) setCollapsed(false);
  };
  el.addEventListener('pointerup', drop);
  el.addEventListener('pointercancel', drop);
  new ResizeObserver(() => { if (!callMini.drag) placeMini(false); }).observe(el);
  window.addEventListener('resize', () => { if (!callMini.drag) placeMini(false); });
})();
$('#call-collapse').onclick = () => setCollapsed(true);
$('#cm-expand').onclick = () => setCollapsed(false);
$('#cm-hangup').onclick = () => $('#call-hangup').click();
$('#cm-mute').onclick = () => $('#call-mute').click();
