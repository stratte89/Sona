// ═══════════════════════════════════════════════════════════════════════════════
// Voice calls: overlay UI over backend call events. All media/crypto is native —
// this file only shows state and pushes buttons.
// ═══════════════════════════════════════════════════════════════════════════════
const callUi = {
  mode: null, username: null, startedAt: 0, timer: null, muted: false,
  // media v2 state
  videoReady: false, cameraOn: false, screenOn: false, screenAudioOn: false,
  screenAudioAvail: false, peerCam: false, peerScr: false, channel: null,
  // Desktop diagnostics from the backend: where video encoding ended up
  // ('hardware' | 'software' | 'idle'), why if it declined, and which media transport
  // the call negotiated ('quic' | 'ws').
  videoEncode: 'idle', videoEncodeWhy: null, transport: null,
  // user hung up while setup was still in flight → kill the call when it lands
  cancelled: false,
  // group call: same overlay, voice-only; `peers` = usernames with audio flowing
  group: false, peers: new Set(),
  // 1:1 media leg dropped, backend resuming silently — freezes the timer text
  reconnecting: false,
  // Android: call audio routed to the loudspeaker (earpiece is the default).
  speakerOn: false,
  // Minimised into the corner bubble (the rest of the app is in use).
  collapsed: false,
  // Android audio routes: {bt, bt_name, route} from the backend; null off-call.
  // pendingRoute = user's pick made before 'connected' (applied when audio starts).
  routes: null, pendingRoute: null,
};

// The speaker/route button: with a Bluetooth headset connected it becomes a
// Bluetooth-marked route chooser; without one it stays the plain loudspeaker toggle.
function updateRouteBtn() {
  const b = $('#call-speaker');
  const r = callUi.routes;
  if (r && r.bt) {
    b.innerHTML = icon('bt');
    b.setAttribute('aria-label', 'Audio output');
    b.classList.toggle('on', r.route === 'bluetooth' || r.route === 'speaker');
  } else {
    if (r) callUi.speakerOn = r.route === 'speaker';
    b.innerHTML = icon('vol');
    b.setAttribute('aria-label', 'Loudspeaker');
    b.classList.toggle('on', callUi.speakerOn);
  }
}

async function refreshRoutes() {
  if (!IS_ANDROID || !callUi.mode) return;
  try { callUi.routes = await invoke('call_audio_routes'); } catch (_) { return; }
  updateRouteBtn();
}

// ── Call progress tones: outgoing ringback + end-of-call beep ────────────────────
// Android plays them natively on the voice-call stream (webview audio is silent in
// MODE_IN_COMMUNICATION); the desktop webview synthesizes the same tones with WebAudio.
let ringbackOn = false;
let toneCtx = null, ringbackTimer = null, ringNodes = null;
function toneBeep(freq, at, dur, gain = 0.12) {
  const o = toneCtx.createOscillator(), g = toneCtx.createGain();
  o.frequency.value = freq;
  g.gain.setValueAtTime(0, at);
  g.gain.linearRampToValueAtTime(gain, at + 0.02);
  g.gain.setValueAtTime(gain, at + dur - 0.03);
  g.gain.linearRampToValueAtTime(0, at + dur);
  o.connect(g).connect(toneCtx.destination);
  o.start(at); o.stop(at + dur + 0.01);
  return g;
}
function startRingback() {
  if (ringbackOn) return;
  ringbackOn = true;
  if (IS_ANDROID) { invoke('call_tone', { kind: 'ringback' }).catch(() => {}); return; }
  try {
    toneCtx = toneCtx || new AudioContext();
    // ETSI ringback: 425 Hz, 1 s on / 4 s off.
    const cycle = () => { ringNodes = toneBeep(425, toneCtx.currentTime + 0.05, 1.0); };
    cycle();
    ringbackTimer = setInterval(cycle, 5000);
  } catch (_) {}
}
function stopRingback() {
  if (!ringbackOn) return;
  ringbackOn = false;
  if (IS_ANDROID) { invoke('call_tone', { kind: 'stop' }).catch(() => {}); return; }
  clearInterval(ringbackTimer); ringbackTimer = null;
  if (ringNodes) { try { ringNodes.disconnect(); } catch (_) {} ringNodes = null; }
}
function endBeep() {
  stopRingback();
  stopIncomingRing();
  if (IS_ANDROID) { invoke('call_tone', { kind: 'end' }).catch(() => {}); return; }
  try {
    toneCtx = toneCtx || new AudioContext();
    const t = toneCtx.currentTime + 0.02;
    toneBeep(425, t, 0.14); toneBeep(425, t + 0.22, 0.14);
  } catch (_) {}
}
// Incoming ring for the IN-APP overlay: the native ring (notification + system
// ringtone) is skipped while the app is on screen, so the overlay must sound itself.
// Android asks the backend, which plays the system ringtone — and refuses when a
// native ring is already sounding (opened from the ring notification), so the two
// never overlap. Desktop synthesizes a classic dual-tone ring.
let inRingOn = false, inRingTimer = null, inRingNodes = null;
function startIncomingRing() {
  if (inRingOn) return;
  inRingOn = true;
  if (IS_ANDROID) { invoke('call_tone', { kind: 'ring' }).catch(() => {}); return; }
  if (!document.hasFocus()) return; // desktop: unfocused = the native notification rings
  try {
    toneCtx = toneCtx || new AudioContext();
    const cycle = () => { // 440+480 Hz, 2 s on / 4 s off
      const t = toneCtx.currentTime + 0.05;
      inRingNodes = [toneBeep(440, t, 2.0, 0.09), toneBeep(480, t, 2.0, 0.09)];
    };
    cycle();
    inRingTimer = setInterval(cycle, 6000);
  } catch (_) {}
}
function stopIncomingRing() {
  if (!inRingOn) return;
  inRingOn = false;
  if (IS_ANDROID) { invoke('call_tone', { kind: 'stop' }).catch(() => {}); return; }
  clearInterval(inRingTimer); inRingTimer = null;
  (inRingNodes || []).forEach((g) => { try { g.disconnect(); } catch (_) {} });
  inRingNodes = null;
}

// One frame from the backend: track(1) || w(2 BE) || h(2 BE) || I420. w=h=0 → off.
// Tracks 1/2 are the peer; 101/102 are the local self-view preview.
function onMediaFrame(msg) {
  let bytes;
  if (msg instanceof ArrayBuffer) bytes = new Uint8Array(msg);
  else if (ArrayBuffer.isView(msg)) bytes = new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength);
  else bytes = Uint8Array.from(msg); // JSON array fallback
  if (bytes.length < 5) return;
  const track = bytes[0];
  const w = (bytes[1] << 8) | bytes[2], h = (bytes[3] << 8) | bytes[4];

  // Self-view frames are throttled and shrunk at the source and reserve nothing, so they
  // must never be acknowledged — an ack the backend did not hand out a slot for would
  // release somebody else's, and the flow control would let a backlog through after all.
  if (track === 101 || track === 102) {
    if (!w || !h || bytes.length < 5 + (w * h * 3) / 2) return;
    if (callUi.mode !== 'connected') return;
    const wrap = track === 101 ? $('#self-cam') : $('#self-scr');
    wrap.querySelector('.self-note').hidden = true; // first frame — capture is live
    tileFor(track).painter.paint(w, h, bytes.subarray(5));
    return;
  }
  if (track !== 1 && track !== 2) return;

  // Peer frames: the backend is holding a slot for this one and sends no more until it
  // hears back, so every path out of here from this point acknowledges — including the
  // ones that discard the frame. A missed ack costs a stall until it times out.
  const ack = () => { invoke('call_frame_ack', { track }).catch(() => {}); };
  // The track-off marker (w = h = 0) is NOT acknowledged: the backend sends it without
  // reserving, precisely because it must never be dropped, so acking it would release a
  // credit that a real frame is still holding and let the backlog through anyway.
  if (!w || !h) { trackWentOff(track); return; }
  // Frames that were already in flight when the track stopped must not resurrect the tile.
  //
  // The off marker is five bytes and a 1080p frame is three megabytes, and Tauri splits
  // its channel at one kilobyte: small payloads are handed to the webview directly, large
  // ones through an asynchronous fetch. Two delivery paths, two latencies, and the tiny
  // marker overtakes the frames still crossing the big one. The tile hid and the next
  // straggler unhid it, which is why a stopped share left its last frame on screen for the
  // rest of the call. Ordering cannot be relied on here, so the off is treated as a fact
  // about the track rather than a position in a queue.
  if (offGuardActive(track)) { ack(); return; }
  // Only a connected call has media. Anything arriving outside one is a straggler from
  // the call that just ended: the frame channel is process-wide and outlives any single
  // call, and a frame already queued on it can be delivered after the end-of-call event
  // has been handled. Painting it would re-show the video stage over the avatar card,
  // and it would stay that way until the next call tore it down.
  if (callUi.mode !== 'connected') { ack(); return; }
  const { el, painter } = tileFor(track);
  if (bytes.length < 5 + (w * h * 3) / 2) { ack(); return; }
  el.hidden = false;
  lastFrameAt[track] = Date.now();
  updateVideoStage();
  painter.paint(w, h, bytes.subarray(5));
  // After the paint call, not before: the point of the acknowledgement is that the
  // webview has done the work, and asking for the next frame first would defeat it.
  ack();
}

// (Re)bind the frame channel — called when a call starts and after webview reloads.
async function bindMediaChannel() {
  try {
    const { Channel } = window.__TAURI__.core;
    const ch = new Channel();
    ch.onmessage = onMediaFrame;
    await invoke('call_media_channel', { channel: ch });
    callUi.channel = ch; // keep alive
  } catch (e) { console.error('media channel bind failed:', e); }
}

function setCallButtons() {
  const inCall = callUi.mode === 'connected';
  const vid = inCall && callUi.videoReady;
  $('#call-cam').hidden = !vid;
  $('#call-share').hidden = !vid;
  $('#call-cam').innerHTML = icon(callUi.cameraOn ? 'cam' : 'camoff');
  $('#call-cam').classList.toggle('on', callUi.cameraOn);
  $('#call-share').classList.toggle('on', callUi.screenOn);
  // One screen at a time: while the peer is sharing, ours is not on offer. Greyed with
  // a reason rather than hidden — a button that vanishes reads as a bug, and the backend
  // refuses this case anyway (see `call_set_screen`), so the disable is there to explain
  // the rule rather than to enforce it. Cameras are unaffected; several at once is fine.
  const blocked = callUi.peerScr && !callUi.screenOn;
  $('#call-share').disabled = blocked;
  $('#call-share').setAttribute('aria-disabled', blocked ? 'true' : 'false');
  $('#call-share').title = blocked
    ? `${callUi.username || 'The other person'} is sharing — only one screen at a time`
    : 'Share your screen';
  // The per-person voice menu only exists where there is one person to point at.
  if (typeof syncCallMenus === 'function') syncCallMenus();
}

// Self-view PiP: visible whenever *we* are sending video. The per-tile spinner note
// covers the device-warmup gap (shown until the first captured frame arrives).
function updateSelfStage() {
  $('#self-cam').hidden = !callUi.cameraOn;
  $('#self-scr').hidden = !callUi.screenOn;
  const wasHidden = $('#call-self').hidden;
  $('#call-self').hidden = !(callUi.cameraOn || callUi.screenOn);
  // Just became visible: park it in its corner before the first paint settles.
  if (wasHidden && !$('#call-self').hidden) placePip(false);
}

// ── Self-view PiP drag: grab it anywhere, release → snaps to the nearest corner
// (with margins clearing the header and the control row). The corner persists
// across calls. Drag and snap share one mechanism: a transform from the top-left,
// so the snap is just the same transform with a transition on.
const pip = { corner: localStorage.getItem('sona-pip-corner') || 'br', drag: null };
function pipMargins() {
  const wide = window.innerWidth >= 900;
  return { side: wide ? 22 : 14, top: wide ? 84 : 76, bottom: wide ? 130 : 118 };
}
function placePip(animate) {
  const el = $('#call-self');
  if (el.hidden) return;
  const parent = el.offsetParent || $('#callui');
  const m = pipMargins();
  const x = pip.corner.includes('l') ? m.side : parent.clientWidth - el.offsetWidth - m.side;
  const y = pip.corner.includes('t') ? m.top : parent.clientHeight - el.offsetHeight - m.bottom;
  el.classList.toggle('snap', !!animate);
  el.classList.toggle('side-l', pip.corner.includes('l'));
  el.style.transform = `translate(${x}px, ${y}px)`;
}
(() => {
  const el = $('#call-self');
  el.addEventListener('pointerdown', (e) => {
    if (el.hidden) return;
    // Fullscreen is not a picture-in-picture tile any more; dragging it would fling a
    // full-window canvas across the screen and leave a transform behind on exit.
    if (el.classList.contains('selffull')) return;
    const r = el.getBoundingClientRect();
    pip.drag = { id: e.pointerId, dx: e.clientX - r.left, dy: e.clientY - r.top };
    el.setPointerCapture(e.pointerId);
    el.classList.remove('snap');
  });
  el.addEventListener('pointermove', (e) => {
    const d = pip.drag;
    if (!d || e.pointerId !== d.id) return;
    const p = (el.offsetParent || $('#callui')).getBoundingClientRect();
    el.style.transform = `translate(${e.clientX - p.left - d.dx}px, ${e.clientY - p.top - d.dy}px)`;
  });
  const drop = (e) => {
    const d = pip.drag;
    if (!d || e.pointerId !== d.id) return;
    pip.drag = null;
    const p = (el.offsetParent || $('#callui')).getBoundingClientRect();
    const r = el.getBoundingClientRect();
    const cx = r.left + r.width / 2 - p.left;
    const cy = r.top + r.height / 2 - p.top;
    pip.corner = (cy < p.height / 2 ? 't' : 'b') + (cx < p.width / 2 ? 'l' : 'r');
    try { localStorage.setItem('sona-pip-corner', pip.corner); } catch (_) {}
    placePip(true);
  };
  el.addEventListener('pointerup', drop);
  el.addEventListener('pointercancel', drop);
  // Tiles appear/disappear and resize with the video aspect — keep the corner
  // anchored through all of it (and through rotations/window resizes).
  new ResizeObserver(() => { if (!pip.drag) placePip(false); }).observe(el);
  window.addEventListener('resize', () => { if (!pip.drag) placePip(false); });
})();

// Mute is shown in two places (control bar + bubble); one writer keeps them in step.
function paintMuted(on) {
  callUi.muted = on;
  for (const id of ['#call-mute', '#cm-mute']) {
    $(id).innerHTML = icon(on ? 'micoff' : 'mic');
    $(id).classList.toggle('on', on);
  }
}

// Identity and status live in two slots at once (top bar on a phone, control pill on
// a desktop window — see the CSS), plus the bubble; every writer goes through these.
function paintCallId() {
  const name = callUi.username || '—';
  $('#call-topname').textContent = name;
  $('#call-barname').textContent = name;
  for (const id of ['#call-avatar', '#cm-avatar', '#call-baravatar']) {
    const av = $(id);
    av.textContent = initial(name);
    av.style.setProperty('--av-h', hue(name));
  }
}
// `html` sticks until the next call; omit it to just repaint the current text (used
// when the layout changes, e.g. on collapse/expand).
let callStateHtml = '';
function paintCallState(html) {
  if (html !== undefined) callStateHtml = html;
  $('#call-topstate').innerHTML = callStateHtml;
  $('#call-barstate').innerHTML = callStateHtml;
}

function showCall(mode, username) {
  const wasMode = callUi.mode;
  callUi.mode = mode;
  if (username) callUi.username = username;
  // Collapse is for a call in progress; an incoming ring always takes the screen.
  if (mode === 'incoming' && callUi.collapsed) setCollapsed(false);
  paintCallId();
  // The collapse control reads as "minimise" on a desktop window and as "back" on a
  // phone, matching where the identity sits in each layout.
  $('#call-collapse').innerHTML = icon(window.innerWidth <= 700 ? 'back' : 'pip');
  $('#call-accept').hidden = mode !== 'incoming';
  $('#call-mute').hidden = mode !== 'connected';
  $('#cm-mute').hidden = mode !== 'connected';
  // Nothing to minimise into while a call is only ringing at us.
  $('#call-collapse').hidden = mode === 'incoming';
  // Loudspeaker toggle: phones only (earpiece↔speaker routing; desktop has no
  // earpiece). Available from the first ring — before 'connected' it arms the
  // preference, which is applied to routing the moment audio starts.
  $('#call-speaker').hidden = !IS_ANDROID || mode === 'incoming';
  $('#call-speaker').classList.toggle('on', callUi.speakerOn);
  // Call settings (gear, top-right): audio prefs modal — see below.
  $('#call-gear').hidden = mode === 'incoming';
  if (mode === 'connected') {
    // Sync persisted prefs into the backend on connect (a fresh process starts with
    // backend defaults, which may not match; routing resets with each audio session).
    invoke('call_set_noise_suppression', { on: nsOn() }).catch(() => {});
    // Device pins are re-asserted the same way. Setting one it already holds is a
    // no-op in the backend, so this never rebuilds a healthy stream mid-call.
    applyAudioDevicePrefs();
    if (IS_ANDROID && callUi.pendingRoute) {
      // Route picked while still ringing/connecting: apply now that audio exists.
      const want = callUi.pendingRoute;
      callUi.pendingRoute = null;
      invoke('call_set_route', { route: want })
        .then((r) => { callUi.routes = r; updateRouteBtn(); }).catch(() => {});
    } else if (IS_ANDROID && callUi.speakerOn && !(callUi.routes && callUi.routes.bt)) {
      invoke('call_set_speaker', { on: true }).catch(() => {});
    }
    refreshRoutes();
  }
  if (IS_ANDROID && mode && mode !== 'incoming') refreshRoutes();
  paintCallState(
    mode === 'connecting' ? '<span class="spinner-sm"></span> establishing secure connection…' :
    mode === 'incoming' ? 'incoming call' :
    mode === 'outgoing' ? 'ringing…' :
    // Re-entering 'connected' (reconnect) keeps the running timer's text.
    wasMode === 'connected' ? callStateHtml : '0:00');
  $('#callui').classList.toggle('ringing', mode !== 'connected');
  $('#callui').classList.toggle('incoming', mode === 'incoming');
  $('#callui').hidden = callUi.collapsed;
  $('#callmini').hidden = !callUi.collapsed;
  // Caller-side ringback while the peer's phone rings; stops the moment audio flows.
  // Callee-side in-app ringtone while the overlay shows 'incoming'; any transition
  // away (accept → connecting, decline/handled → hideCall) silences it.
  if (mode === 'outgoing') startRingback(); else stopRingback();
  if (mode === 'incoming') startIncomingRing(); else stopIncomingRing();
  setCallButtons();
  if (mode === 'connected' && !callUi.timer) {
    callUi.startedAt = Date.now();
    callUi.timer = setInterval(() => {
      // A tile whose frames stopped arriving is a tile that should not still be up.
      //
      // Belt and braces on purpose. A track going off is announced twice — a `peer_track`
      // event and a zero-sized frame — and this call has now twice ended with a stopped
      // share still showing its last picture on the far side, which means one or both of
      // those announcements does not always arrive. Rather than keep guessing which, the
      // absence of frames is treated as its own evidence: video that has stopped for this
      // long has stopped, whatever the control path said or failed to say.
      reapStaleTiles();
      if (callUi.reconnecting) return; // status line shows "reconnecting…"
      const t = mss(Math.floor((Date.now() - callUi.startedAt) / 1000));
      paintCallState(callUi.group ? `${t} · ${callUi.peers.size + 1} in call` : t);
      $('#cm-time').textContent = t;
    }, 500);
  }
}

function hideCall() {
  // End-of-call beep only when a live call ends; a ring that never connected
  // (declined / no answer / cancelled / missed) just goes quiet.
  if (callUi.mode === 'connected') endBeep();
  else { stopRingback(); stopIncomingRing(); }
  clearInterval(callUi.timer);
  callUi.mode = null; callUi.username = null; callUi.timer = null;
  callUi.muted = false;
  callUi.group = false; callUi.peers = new Set();
  callUi.reconnecting = false;
  callUi.speakerOn = false;
  callUi.routes = null; callUi.pendingRoute = null;
  $('#call-speaker').classList.remove('on');
  $('#call-speaker').innerHTML = icon('vol');
  $('#call-settings').hidden = true;
  // Fullscreen and the stream menus are per-call: a stage still covering the window
  // after a hang-up would leave the app looking wedged.
  if (typeof resetCallMenus === 'function') resetCallMenus();
  closeSharePick(); // the call ended while the picker was up
  callUi.videoReady = false; callUi.cameraOn = false; callUi.screenOn = false;
  callUi.screenAudioOn = false; callUi.peerCam = false; callUi.peerScr = false;
  $('#call-mute').innerHTML = icon('mic');
  $('#cm-mute').innerHTML = icon('mic');
  $('#cm-mute').classList.remove('on');
  $('#cm-time').textContent = '0:00';
  $('#cv-camera').hidden = true;
  $('#cv-screen').hidden = true;
  clearTiles();
  updateVideoStage();
  updateSelfStage();
  $$('#call-self .self-note').forEach((n) => (n.hidden = false)); // re-arm for the next call
  $('#callui').classList.remove('has-video');
  $('#callui').classList.remove('incoming');
  // Order matters: setCollapsed(false) puts the peer-video element back on the stage
  // before the overlay closes, so the next call starts with the DOM where it belongs.
  setCollapsed(false);
  $('#callui').hidden = true;
  $('#callmini').hidden = true;
}

$('#th-call').onclick = async () => {
  // Already in a call: the call button is the way back to it (you got here by
  // minimising it), not a second dial.
  if (callUi.mode) { setCollapsed(false); return; }
  if (cur.keyChanged || !cur.peer) return;
  // Overlay comes up instantly — key exchange, mic init and the room join run behind
  // this state, and the backend's "outgoing" event flips it to "ringing…".
  callUi.cancelled = false;
  if (cur.kind === 'group') {
    callUi.group = true;
    showCall('connecting', cur.username);
    try { await invoke('group_call_start', { groupId: cur.peer }); }
    catch (e) { toast(say(e), 'err'); hideCall(); }
    return;
  }
  if (cur.kind !== 'chat') return;
  showCall('connecting', cur.display || cur.username);
  try { await invoke('call_start', { username: cur.username }); }
  catch (e) { toast(say(e), 'err'); hideCall(); }
};
async function acceptIncoming() {
  callUi.cancelled = false;
  showCall('connecting');
  try { await invoke(callUi.group ? 'group_call_accept' : 'call_accept'); }
  catch (e) { toast(say(e), 'err'); hideCall(); }
}
$('#call-accept').onclick = acceptIncoming;

// Answer tapped on the OS ring notification is NOT handled here any more: it goes
// straight to the engine, which owns the one answer path (the same one Core-Telecom, a
// headset, and a watch use) and holds the answer for the exact call while the vault is
// opened. The old flag here answered whatever rang inside a 60-second window — including
// a later, unrelated call.
$('#call-hangup').onclick = async () => {
  if (callUi.mode === 'incoming') {
    try { await invoke(callUi.group ? 'group_call_decline' : 'call_decline'); } catch (_) {}
    hideCall();
    return;
  }
  // May race call setup: flag it so a late "outgoing"/"connected" event tears the
  // call down instead of resurrecting the overlay.
  const wasGroup = callUi.group;
  callUi.cancelled = true;
  hideCall();
  try { await invoke(wasGroup ? 'group_call_hangup' : 'call_hangup'); } catch (_) {}
};
$('#call-speaker').onclick = async () => {
  // Bluetooth headset connected: the button is a route chooser, not a toggle — the
  // headset is the default and staying on it must always be one tap away.
  if (callUi.routes && callUi.routes.bt) {
    const r = callUi.routes;
    const current = callUi.pendingRoute || r.route;
    const opts = [
      ['bluetooth', `Bluetooth — ${r.bt_name || 'headset'}`],
      ['speaker', 'Loudspeaker'],
      ['earpiece', 'Phone earpiece'],
    ];
    const card = openModal(`<h3>Audio output</h3>
      <div class="modal-list">${opts.map(([v, l]) =>
        `<button data-v="${v}" ${v === current ? 'class="sel"' : ''}>${l}${v === current ? '<em>current</em>' : ''}</button>`).join('')}</div>
      <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`, { onCall: true });
    card.querySelectorAll('[data-v]').forEach((b) => {
      b.onclick = async () => {
        closeModal();
        const want = b.dataset.v;
        if (callUi.mode !== 'connected') {
          // Armed — applied the moment audio starts (routing needs a live session).
          callUi.pendingRoute = want;
          callUi.routes = { ...callUi.routes, route: want };
          updateRouteBtn();
          return;
        }
        try {
          callUi.routes = await invoke('call_set_route', { route: want });
          updateRouteBtn();
        } catch (e) { toast(say(e), 'err'); }
      };
    });
    card.querySelector('#mo-no').onclick = closeModal;
    return;
  }
  // No headset: the classic loudspeaker toggle. Flip instantly (the tap must feel
  // immediate); the routing call confirms right after and reverts on failure.
  const want = !callUi.speakerOn;
  callUi.speakerOn = want;
  $('#call-speaker').classList.toggle('on', want);
  if (callUi.mode !== 'connected') return; // armed — applied when audio starts
  try {
    const on = await invoke('call_set_speaker', { on: want });
    callUi.speakerOn = on;
    $('#call-speaker').classList.toggle('on', on);
  } catch (e) {
    callUi.speakerOn = !want;
    $('#call-speaker').classList.toggle('on', !want);
    toast(say(e), 'err');
  }
};

// ── Call settings modal (gear, top-right of the call screen) ─────────────────────
// Noise suppression (desktop: RNNoise; Android: the platform NoiseSuppressor) and
// share-system-audio. Both persisted across calls and app restarts; on by default.
const nsOn = () => localStorage.getItem('sona-ns') !== '0';
const shareAudioPref = () => localStorage.getItem('sona-sharesysaudio') !== '0';
// One writer for the share-system-audio preference, because it is shown in two places
// (the gear's switch and the share picker's checkbox) and changing either has to move
// the other — including when the picker is what changed it.
function setShareAudioPref(on) {
  localStorage.setItem('sona-sharesysaudio', on ? '1' : '0');
  $('#cset-shareaudio').classList.toggle('on', on);
  $('#sp-audio').classList.toggle('on', on);
  $('#sp-audio').setAttribute('aria-checked', on ? 'true' : 'false');
}

$('#call-gear').onclick = async () => {
  const pane = $('#call-settings');
  pane.hidden = !pane.hidden;
  $('#cset-ns').classList.toggle('on', nsOn());
  $('#cset-shareaudio').classList.toggle('on', shareAudioPref());
  if (!pane.hidden) {
    // Row only where the platform can capture system audio (e.g. not macOS).
    await refreshScreenAudioAvail();
    $('#cset-shareaudio').hidden = !callUi.screenAudioAvail;
    $('#cset-shareaudio-hint').hidden = !callUi.screenAudioAvail;
    $('#cset-devices').hidden = IS_ANDROID || !audioDev.supported;
    if (!IS_ANDROID) refreshAudioDevices();
    // Where video encoding ended up, and on which transport. Shown only while it matters
    // (a call with video negotiated). 'idle' is its own answer, not a synonym for
    // software: nothing opens an encoder until this machine actually has a frame to send,
    // so a call where only the peer is sharing has not decided anything yet. Saying
    // "software" there was wrong, and it masked a real hardware failure on the other end.
    // The reason line is only worth showing when a backend declined and said why.
    const hw = $('#cset-hw');
    hw.hidden = !callUi.videoReady;
    const enc = {
      hardware: 'hardware (GPU)',
      software: 'software (CPU)',
      idle: 'not encoding yet',
    }[callUi.videoEncode] || 'software (CPU)';
    const via = callUi.transport === 'quic' ? 'QUIC'
      : callUi.transport === 'ws' ? 'WebSocket (fallback)' : null;
    hw.textContent = `Video encoding: ${enc}`
      + (via ? ` · media over ${via}` : '')
      + (callUi.videoEncode === 'software' && callUi.videoEncodeWhy
        ? ` — ${callUi.videoEncodeWhy}` : '');
  }
};
// Tap outside the card closes the modal.
$('#call-settings').onclick = (e) => {
  if (e.target === $('#call-settings')) $('#call-settings').hidden = true;
};
$('#cset-ns').onclick = async () => {
  const next = !nsOn();
  try {
    await invoke('call_set_noise_suppression', { on: next });
    localStorage.setItem('sona-ns', next ? '1' : '0');
    $('#cset-ns').classList.toggle('on', next);
  } catch (e) { toast(say(e), 'err'); }
};
$('#cset-shareaudio').onclick = async () => {
  const next = !shareAudioPref();
  setShareAudioPref(next);
  // Live-apply to a share already running; otherwise it just takes effect next share.
  if (callUi.screenOn && callUi.screenAudioAvail) {
    try {
      await invoke('call_set_screen_audio', { on: next });
      callUi.screenAudioOn = next;
    } catch (e) { toast(say(e), 'err'); }
  }
};

$('#call-mute').onclick = async () => {
  const next = !callUi.muted;
  try {
    await invoke(callUi.group ? 'group_call_set_muted' : 'call_set_muted', { muted: next });
    paintMuted(next);
  } catch (e) { toast(say(e), 'err'); }
};
$('#call-cam').onclick = async () => {
  const next = !callUi.cameraOn;
  try {
    await invoke('call_set_camera', { on: next });
    callUi.cameraOn = next;
    if (next) $('#self-cam .self-note').hidden = false; // spinner until first frame
    setCallButtons();
    updateSelfStage();
  } catch (e) { toast(say(e), 'err'); }
};
// Start (or stop) the screen-share track. `source` is the picker's choice — omitted on
// Android and as the fallback everywhere, meaning the primary monitor.
async function setScreenShare(on, source) {
  try {
    await invoke('call_set_screen', { on, source: source || null });
    callUi.screenOn = on;
    callUi.screenAudioOn = false; // backend clears audio with the share
    if (on) {
      $('#self-scr .self-note').hidden = false;
      // System audio rides the share per the preference the picker just confirmed.
      // Ordering is audio *after* share on purpose: the gap direction is silence,
      // never a leak (and on Android the bridge attaches capture once the projection
      // lands).
      if (callUi.screenAudioAvail && shareAudioPref()) {
        try {
          await invoke('call_set_screen_audio', { on: true });
          callUi.screenAudioOn = true;
        } catch (e) { toast(say(e), 'err'); }
      }
    }
    setCallButtons();
    updateSelfStage();
  } catch (e) { toast(say(e), 'err'); }
}

// Group-call events drive the same overlay in voice-only mode. Connectivity is
// per-peer: the first peer with flowing audio flips the overlay to "connected";
// the call stays up (users can wait alone) until WE hang up or the backend ends it.
function onGroupCallEvent(ev) {
  const p = ev.payload || {};
  if (callUi.cancelled && !callUi.mode && p.kind === 'outgoing') {
    invoke('group_call_hangup').catch(() => {});
    return;
  }
  switch (p.kind) {
    case 'incoming':
      callUi.group = true;
      showCall('incoming', p.name || 'Group');
      paintCallState(`incoming group call · ${escapeHtml(p.from || '')}`);
      break;
    case 'outgoing':
      callUi.group = true;
      showCall('outgoing', p.name);
      break;
    case 'peer_connected':
      callUi.peers.add(p.username);
      if (callUi.mode !== 'connected') showCall('connected');
      break;
    case 'peer_left':
    case 'peer_declined':
      if (p.username) callUi.peers.delete(p.username);
      if (p.kind === 'peer_declined' && callUi.mode) toast(`${p.username || 'Someone'} declined`);
      break;
    case 'claiming':
    case 'accepted': if (callUi.mode === 'incoming') showCall('connecting'); break;
    case 'no_answer': toast('No one answered'); hideCall(); break;
    case 'missed': if (callUi.mode === 'incoming') { toast('Missed group call'); hideCall(); } break;
    case 'handled': if (handledClosesUi()) { toast(handledText(p)); hideCall(); } break;
    case 'ended': if (callUi.group) { toast('Call ended'); hideCall(); } break;
  }
}

function onCallEvent(ev) {
  const p = ev.payload || {};
  // Hung up while setup was in flight? Kill whatever landed; don't resurrect the UI.
  if (callUi.cancelled && !callUi.mode && (p.kind === 'outgoing' || p.kind === 'connected')) {
    invoke('call_hangup').catch(() => {});
    return;
  }
  switch (p.kind) {
    case 'incoming': showCall('incoming', p.username); break;
    case 'outgoing': showCall('outgoing', p.username); bindMediaChannel(); break;
    case 'connected':
      callUi.reconnecting = false;
      showCall('connected');
      bindMediaChannel();
      break;
    // Media leg dropped; the backend is silently resuming. Keep the overlay (and the
    // running timer) — only the status line changes until 'connected' lands again.
    case 'reconnecting':
      callUi.reconnecting = true;
      if (!callUi.mode) showCall('connecting', p.username);
      paintCallState('<span class="spinner-sm"></span> reconnecting…');
      break;
    case 'video_ready': callUi.videoReady = !!p.ready; refreshScreenAudioAvail(); break;
    case 'peer_track': {
      if (p.track === 'camera') callUi.peerCam = !!p.on;
      if (p.track === 'screen') callUi.peerScr = !!p.on;
      // This is the other announcement of the same fact as the frame channel's zero-sized
      // marker, on a different transport, with no ordering between them — so whichever
      // lands first does the work and the other is a no-op.
      const id = p.track === 'camera' ? 1 : p.track === 'screen' ? 2 : 0;
      if (id) {
        if (p.on) trackCameOn(id);
        else trackWentOff(id);
      }
      // The share button's enabled state follows the peer's screen track.
      if (p.track === 'screen') setCallButtons();
      break;
    }
    // Answered via the headset button while the incoming overlay was up.
    case 'claiming':
    case 'accepted': if (callUi.mode === 'incoming') showCall('connecting'); break;
    case 'declined': toast('Call declined'); hideCall(); break;
    case 'no_answer': toast('No answer'); hideCall(); break;
    case 'missed': if (callUi.mode === 'incoming') { toast('Missed call'); hideCall(); } break;
    // Another of this account's devices, or the caller, ended the ring — say which.
    case 'handled': if (handledClosesUi()) { toast(handledText(p)); hideCall(); } break;
    // An answer is held over the keyguard and the OS can check nobody: ask for Sona's own.
    case 'unlock_credential': promptAnswerCredential(); break;
    case 'ended': toast('Call ended'); hideCall(); break;
  }
}

// Webview reloaded mid-call? Re-sync the overlay from backend state.
async function resyncCall() {
  try {
    const st = await invoke('call_status');
    if (st.active) {
      callUi.videoReady = !!st.active.video_ready;
      callUi.cameraOn = !!st.active.camera_on;
      callUi.screenOn = !!st.active.screen_on;
      callUi.screenAudioOn = !!st.active.screen_audio_on;
      callUi.screenAudioAvail = !!st.active.screen_audio_available;
      callUi.videoEncode = st.active.video_encode || 'idle';
      callUi.videoEncodeWhy = st.active.video_encode_why || null;
      callUi.transport = st.active.transport || null;
      callUi.peerCam = !!st.active.peer_camera;
      callUi.peerScr = !!st.active.peer_screen;
      showCall(st.active.connected ? 'connected' : 'outgoing', st.active.username);
      updateSelfStage();
      if (st.active.muted) paintMuted(true);
      bindMediaChannel(); // frames resume painting after a reload
    } else if (st.incoming) {
      showCall('incoming', st.incoming.username);
    } else if (st.claiming) {
      showCall('connecting', st.claiming.username);
    } else if (st.reconnecting) {
      callUi.reconnecting = true;
      showCall('connecting', st.reconnecting.username);
      paintCallState('<span class="spinner-sm"></span> reconnecting…');
    } else if (st.group_active) {
      callUi.group = true;
      callUi.peers = new Set(st.group_active.peers || []);
      showCall(callUi.peers.size ? 'connected' : 'outgoing', st.group_active.name);
      if (st.group_active.muted) paintMuted(true);
    } else if (st.group_incoming) {
      callUi.group = true;
      showCall('incoming', st.group_incoming.name);
      paintCallState(`incoming group call · ${escapeHtml(st.group_incoming.from || '')}`);
    } else if (st.group_claiming) {
      callUi.group = true;
      showCall('connecting', st.group_claiming.name);
    }
    // Answered over the keyguard, and the backend is waiting on a human check it could not
    // get from the OS. This flow *starts* the webview, so the event that asks for it is
    // usually sent before anything is listening — reading it here is what makes the request
    // survive a cold start.
    if (st.unlock_credential) promptAnswerCredential();
  } catch (_) {}
}

// Screen-audio availability is platform-static per call; cached from call_status.
async function refreshScreenAudioAvail() {
  try {
    const st = await invoke('call_status');
    callUi.screenAudioAvail = !!(st.active && st.active.screen_audio_available);
    // Re-read who is sharing from the backend, which holds the authoritative flag: the
    // `peer_track` event that normally maintains it can be missed, and the consequence of
    // a stale copy is an enabled share button the backend then refuses — a dead-feeling
    // button with an error toast instead of a greyed-out one that explains itself.
    callUi.peerScr = !!(st.active && st.active.peer_screen);
    callUi.peerCam = !!(st.active && st.active.peer_camera);
    callUi.videoEncode = (st.active && st.active.video_encode) || 'idle';
    callUi.videoEncodeWhy = (st.active && st.active.video_encode_why) || null;
    callUi.transport = (st.active && st.active.transport) || null;
  } catch (_) {}
  setCallButtons();
}

// ── Backend events ───────────────────────────────────────────────────────────────
// `sync` = new inbound state (repaint), `conn` = relay link up/down. If event
// registration fails (e.g. a missing capability), fall back to polling so the UI
// still refreshes — delivery must never depend on a silent promise rejection.
// A "seen" receipt is a promise the user actually LOOKED at the message. A thread
// left open behind a minimized / backgrounded window (taskbar, another virtual
// desktop, screen off) is NOT looked at — sending a read receipt then is a lie the
// sender sees as two blue ticks. Only ack as seen when the window is genuinely on
// screen and focused; otherwise the receipt waits for the next real focus.
function threadOnScreen() {
  return document.visibilityState === 'visible' && document.hasFocus();
}
async function onSync() {
  if (current === 'chats') loadChats();
  else if (current === 'requests') loadRequests();
  else if (current === 'thread' && cur.peer && !cur.keyChanged) {
    const seeable = threadOnScreen();
    if (cur.kind === 'group') {
      await renderGroupThread(cur.peer);
      if (seeable) { try { await invoke('mark_group_seen', { groupId: cur.peer }); } catch (_) {} }
    } else {
      await renderThread(cur.peer);
      if (seeable) markSeen(); // thread is open AND on screen — ack as seen
    }
  }
}
// Coming back to a thread that received messages while the window was hidden/blurred
// (where onSync deliberately withheld the receipt) — ack them now that they're seen.
window.addEventListener('focus', () => {
  if (current !== 'thread' || !cur.peer || cur.keyChanged || !threadOnScreen()) return;
  if (cur.kind === 'group') { invoke('mark_group_seen', { groupId: cur.peer }).catch(() => {}); }
  else markSeen();
});
(async () => {
  try {
    await listen('conn', (ev) => {
      const up = !!ev.payload;
      $('#conn-dot').classList.toggle('off', !up);
      $('#conn-note').hidden = up;
    });
    await listen('sync', onSync);
    // Something addressed to us arrived that we couldn't decrypt. We can't name the
    // sender (a non-prekey message carries none), so point at the cure rather than a
    // chat: without this the conversation just looks silent on both ends. Rate-limited
    // to one warning per app run so a backlog can't spam.
    await listen('undecryptable', () => {
      if (window.__undecWarned) return;
      window.__undecWarned = true;
      toast('A message arrived that could not be decrypted. If a chat has gone silent, open it → Reset secure session.', 'err');
    });
    await listen('call', onCallEvent);
    await listen('group_call', onGroupCallEvent);
    await listen('typing', (ev) => {
      const p = ev.payload || {};
      applyTyping(p.peer, p.group, !!p.typing, p.who || '');
    });
    await listen('navigate', (ev) => { handleNavigate(ev.payload || {}); });
    // Call-audio routing changed under us (headset connected/unplugged, auto-switch):
    // adapt the in-call button live.
    await listen('audio_route', (ev) => {
      if (!callUi.mode) return;
      callUi.routes = ev.payload || null;
      updateRouteBtn();
    });
    // The engine locked the vault while we were backgrounded (idle auto-lock):
    // sync the UI to the lock screen. doLock's own invoke('lock') is idempotent.
    await listen('locked', () => { doLock(true); });
  } catch (e) {
    console.error('event listen failed, falling back to polling:', e);
    setInterval(onSync, 1500);
  }
})();
