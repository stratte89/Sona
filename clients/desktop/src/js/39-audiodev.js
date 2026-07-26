// ═══════════════════════════════════════════════════════════════════════════════
// Device choice — microphone, output, camera (desktop only).
//
// One preference per device, several consumers: the call engine (native cpal streams
// and nokhwa capture), voice messages (the webview's own getUserMedia), and two places
// in the UI that both show it — the call-settings gear and the main Settings screen.
// Whichever one you change it in, the other reflects it, because both read the same
// localStorage keys and repaint through `paintAudioDevices()`.
//
// Android has none of this on purpose: a phone has one microphone, one camera the
// front/back button flips, and an output that goes through the
// earpiece/loudspeaker/Bluetooth route chooser in the call UI instead.
// ═══════════════════════════════════════════════════════════════════════════════
const DEV_KINDS = ['input', 'output', 'camera'];
const audioDev = { supported: !IS_ANDROID, inputs: [], outputs: [], cameras: [], loaded: false };

const DEV_KEY = { input: 'sona-audio-in', output: 'sona-audio-out', camera: 'sona-camera' };
// '' — the stored value for "system default" — must round-trip as the empty option.
const devPref = (kind) => localStorage.getItem(DEV_KEY[kind]) || '';

// Enumerating devices means talking to the sound server; cache it and refresh only
// when a picker is actually opened.
async function loadAudioDevices({ force = false } = {}) {
  if (IS_ANDROID) return audioDev;
  if (audioDev.loaded && !force) return audioDev;
  try {
    const d = await invoke('call_media_devices');
    audioDev.supported = !!d.supported;
    audioDev.inputs = d.inputs || [];
    audioDev.outputs = d.outputs || [];
    audioDev.cameras = d.cameras || [];
    audioDev.loaded = true;
  } catch (_) { audioDev.supported = false; }
  return audioDev;
}

// Push the stored preferences into the backend. Called at startup and again when a
// call connects: the backend starts each process on its own defaults, and re-asserting
// a preference it already holds is a no-op there (no stream rebuild).
async function applyAudioDevicePrefs() {
  if (IS_ANDROID) return;
  for (const kind of DEV_KINDS) {
    try { await invoke('call_set_media_device', { kind, id: devPref(kind) || null }); }
    catch (_) {}
  }
}

// Fill every device <select> on the page from the cached list. Both copies of the UI
// use the same markup, so this is the only writer.
function paintAudioDevices() {
  for (const kind of DEV_KINDS) {
    const list = { input: audioDev.inputs, output: audioDev.outputs, camera: audioDev.cameras }[kind];
    const want = devPref(kind);
    // A pinned device that has since been unplugged still gets an entry, so the
    // dropdown shows what it is set to rather than silently reading "System default"
    // while the backend is still holding the preference.
    const rows = list.slice();
    if (want && !rows.some((d) => d.id === want)) {
      rows.push({ id: want, name: 'Unavailable device', is_default: false });
    }
    const def = list.find((d) => d.is_default);
    for (const sel of $$(`select[data-dev="${kind}"]`)) {
      sel.innerHTML =
        `<option value="">${kind === 'camera' ? 'Default camera' : 'System default'}${
          def ? ` — ${escapeHtml(def.name)}` : ''
        }</option>` +
        rows.map((d) => `<option value="${escapeHtml(d.id)}">${escapeHtml(d.name)}</option>`).join('');
      sel.value = want;
      sel.disabled = !audioDev.supported;
    }
  }
}

async function setAudioDevice(kind, id) {
  try {
    await invoke('call_set_media_device', { kind, id: id || null });
    localStorage.setItem(DEV_KEY[kind], id || '');
  } catch (e) { toast(say(e), 'err'); }
  paintAudioDevices(); // both copies of the UI, whichever one was used
}

// Refresh + repaint; what every place that shows the dropdowns calls when it opens.
async function refreshAudioDevices() {
  await loadAudioDevices({ force: true });
  paintAudioDevices();
}

// One delegated listener covers every device <select>, wherever it lives.
document.addEventListener('change', (e) => {
  const sel = e.target.closest && e.target.closest('select[data-dev]');
  if (sel) setAudioDevice(sel.dataset.dev, sel.value);
});

// ── getUserMedia constraint for voice messages ────────────────────────────────────
// The webview enumerates devices in its own namespace, so the pinned cpal id means
// nothing to it; the device *name* is the only thing the two have in common. A match
// gives voice messages the same microphone as calls, and no match just means the
// browser default — the same thing that happened before there was a preference.
async function micConstraint() {
  if (IS_ANDROID) return true;
  const want = devPref('input');
  if (!want) return true;
  await loadAudioDevices();
  const pinned = audioDev.inputs.find((d) => d.id === want);
  if (!pinned) return true;
  const norm = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  const target = norm(pinned.name);
  try {
    const devs = await navigator.mediaDevices.enumerateDevices();
    // Labels are empty until microphone permission has been granted once; when they
    // are, there is nothing to match on and the default is the honest answer.
    const hit = devs.find((d) => {
      if (d.kind !== 'audioinput' || !d.label) return false;
      const l = norm(d.label);
      return l === target || l.includes(target) || target.includes(l);
    });
    if (hit && hit.deviceId) return { deviceId: { exact: hit.deviceId } };
  } catch (_) {}
  return true;
}

// Open the microphone honouring the pinned device, falling back to the default if the
// browser refuses that exact device (unplugged between the two calls, held by another
// app). A voice message must never fail to record over a *preference*.
async function openMicStream() {
  const audio = await micConstraint();
  try {
    return await navigator.mediaDevices.getUserMedia({ audio });
  } catch (e) {
    if (audio === true) throw e;
    return await navigator.mediaDevices.getUserMedia({ audio: true });
  }
}

// Startup: a fresh process holds backend defaults, which may not be what the user
// picked last time.
applyAudioDevicePrefs();
