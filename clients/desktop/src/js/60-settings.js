// ═══════════════════════════════════════════════════════════════════════════════
// Settings
// ═══════════════════════════════════════════════════════════════════════════════
async function openSettings() {
  show('settings');
  try {
    const st = await invoke('app_status');
    $('#se-user').textContent = st.account_id || '—';
    $('#se-relay').textContent = st.base_url || '—';
    // The invite QR carries the shared access token — for an open relay there is no
    // token and nothing to gate, so the button would only confuse.
    $('#se-relay-qr').hidden = !st.private_relay;
  } catch (e) { /* ignore */ }
  $('#se-audit-res').textContent = '';
  $('#se-audit-res').className = '';
  $('#se-clearmedia-state').textContent = mediaCacheLabel();
  // Current version on the updates row until a check replaces it.
  window.__TAURI__.app.getVersion()
    .then((v) => { if (!$('#se-update-state').textContent) $('#se-update-state').textContent = `v${v}`; })
    .catch(() => {});
  await renderMyAvatar();
  await renderAppLock();
  await renderPrivacy();
  renderDelivery(); // async fill-in (talks to the relay for capabilities)
  renderProxy();
  await renderDevices();
  await renderAudioDevices();
}

// Microphone/output/camera pickers. Desktop only, and the same preferences the
// call-settings gear writes — either place can change them, both show the result.
async function renderAudioDevices() {
  if (IS_ANDROID) return;
  await refreshAudioDevices();
  $('#se-audio-sec').hidden = !audioDev.supported;
}

// ── Own profile picture ──────────────────────────────────────────────────────────
// Broadcast to every contact we share a session with (over the ratchet, sealed — the
// relay never sees it). Stored (sanitized) locally first, so it sticks even if a send fails.
let myAvatar = null;
function paintMyAvatar() {
  const el = $('#se-avatar');
  const label = $('#se-user').textContent || '?';
  el.innerHTML = avatarInner(myAvatar, label, false) + `<span class="av-cam">${icon('cam')}</span>`;
  el.style.setProperty('--av-h', hue(label));
  $('#se-avatar-rm').hidden = !isAvatar(myAvatar);
}
async function renderMyAvatar() {
  try { myAvatar = await invoke('my_avatar'); } catch (_) { myAvatar = null; }
  paintMyAvatar();
}
async function saveMyAvatar(avatar) {
  try {
    await invoke('set_my_avatar', { avatar });
    myAvatar = avatar;
    paintMyAvatar();
    loadChats();
  } catch (e) { toast(say(e), 'err'); }
}
$('#se-avatar').onclick = async () => { const a = await pickAvatar(); if (a) saveMyAvatar(a); };
$('#se-avatar-rm').onclick = () => saveMyAvatar(null);

// ── Relay row: copy address, invite QR (private relays), explainer ───────────────
$('#se-relay-copy').onclick = async () => {
  const url = $('#se-relay').textContent;
  if (!url || url === '—') return;
  toast((await copyText(url)) ? 'Relay address copied' : 'Copy failed', 'ok');
};
$('#se-relay-qr').onclick = async () => {
  let inviteStr;
  try { inviteStr = await invoke('relay_invite'); } catch (e) { return toast(say(e), 'err'); }
  const card = openModal(
    `<h3>Invite to this relay</h3>
     <p>Scan on the new member's connect screen (<em>Scan an invite QR</em>) — it fills
        the relay address, the access token, and the pinned key in one go.</p>
     <div class="invite-qr" id="mo-invite-qr"></div>
     <p class="hint"><strong>Treat it like a key to the door:</strong> the QR contains the
        relay's shared access token. Share it only with people you'd let onto the relay.</p>
     <button class="btn btn-ghost btn-sm" id="mo-invite-copy">Copy as text instead</button>`);
  const box = card.querySelector('#mo-invite-qr');
  try {
    const qr = qrcode(0, 'M');
    qr.addData(inviteStr, 'Byte');
    qr.make();
    box.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true, alt: { text: 'relay invite' } });
  } catch (_) { box.textContent = 'QR too dense — use the text copy below'; }
  card.querySelector('#mo-invite-copy').onclick = async () =>
    toast((await copyText(inviteStr)) ? 'Invite copied — paste it into the relay address field' : 'Copy failed', 'ok');
};
$('#se-relay-info').onclick = () => {
  const qrVisible = !$('#se-relay-qr').hidden;
  openModal(
    `<h3>Sharing this relay</h3>
     <p><strong>Copy</strong> puts the relay address on the clipboard — handy for telling
        someone where to connect without typing it.</p>
     ${qrVisible
        ? `<p><strong>Invite QR</strong> appears because this relay is private (it requires
           an access token). The QR bundles the address, the token, and the relay's pinned
           key so a new member sets up with one scan. The token is a shared secret — anyone
           holding it can use the relay, so share invites only with people you trust. To
           evict someone, the relay operator rotates the token.</p>`
        : `<p>This relay is public (no access token configured), so there is no invite QR —
           anyone can connect with just the address.</p>`}
     <p>The pinned key in an invite is the relay's <em>Key Transparency</em> key: it lets
        the new member verify the relay never swaps anyone's identity keys unnoticed.</p>
     <button class="btn" id="mo-ok">Got it</button>`)
    .querySelector('#mo-ok').onclick = closeModal;
};

// ── Privacy settings (B/C/D) ─────────────────────────────────────────────────────
const NOTIF_LABELS = { sender_message: 'Sender & message', sender: 'Sender only', generic: "Generic" };
// Internal call-control records only — never call audio, and never the call history in
// your chats. There is deliberately no "forever". (The row's handler is in
// 62-callsettings.js; this map is read by renderPrivacy below.)
const CALL_RETENTION_LABELS = { 0: 'Until the call ends', 86400: '24 hours', 604800: '7 days', 2592000: '30 days' };
async function renderPrivacy() {
  let p;
  try { p = await invoke('privacy_prefs'); } catch (_) { return; }
  const setState = (id, on) => { const e = $(id); e.textContent = on ? 'On' : 'Off'; e.className = on ? 'ok' : ''; };
  setState('#se-typing-state', p.send_typing);
  setState('#se-receipts-state', p.send_receipts);
  $('#se-notif-state').textContent = NOTIF_LABELS[p.notif_level] || 'Sender only';
  // Call-record retention is an Android-only control: it governs the phone's own
  // call-control store (the records that let a locked device stop ringing), which no
  // other platform keeps.
  // Answering from a lock screen is a phone problem: desktop is unlocked whenever it is
  // usable, so the control only means something on Android.
  $('#se-callunlock').hidden = !IS_ANDROID;
  const unlockState = $('#se-callunlock-state');
  unlockState.textContent = p.require_unlock_to_answer ? 'On' : 'Off';
  unlockState.className = p.require_unlock_to_answer ? 'ok' : '';
  $('#se-callret').hidden = !IS_ANDROID;
  $('#se-callret-state').textContent = CALL_RETENTION_LABELS[p.call_retention_secs] || '7 days';
  cur.privacy = p;
  // Message requests (stored inside the sealed history, not prefs.json).
  try {
    const rp = await invoke('msg_request_prefs');
    cur.reqPrefs = rp;
    const st = $('#se-reqs-state');
    st.textContent = rp.enabled ? 'On' : 'Off';
    st.className = rp.enabled ? 'ok' : '';
    // The sub-choice only means something while requests are on.
    $('#se-reqtext').hidden = !rp.enabled;
    $('#se-reqtext-state').textContent = rp.allow_text ? 'Travels along' : 'Request only';
  } catch (_) {}
}

// Master switch: ask-first (requests) vs open messaging.
$('#se-reqs').onclick = () => {
  const p = cur.reqPrefs || { enabled: true, allow_text: false };
  const card = openModal(
    `<h3>Message requests</h3>
     <p>Who can start a conversation with you.</p>
     <div class="modal-list">
       <button data-v="on" ${p.enabled ? 'class="sel"' : ''}>${icon('users')}Ask first${p.enabled ? '<em>current</em>' : ''}
         <small>Someone new shows up as a request — nothing rings, nothing lands in your
         chats, until you accept. Recommended.</small></button>
       <button data-v="off" ${!p.enabled ? 'class="sel"' : ''}>${icon('chat')}Open${!p.enabled ? '<em>current</em>' : ''}
         <small>Anyone who knows your username can message and call you directly.
         Pending requests are accepted when you switch.</small></button>
     </div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-v]').forEach((b) => {
    b.onclick = async () => {
      closeModal();
      try {
        await invoke('set_msg_request_prefs', { enabled: b.dataset.v === 'on', allowText: p.allow_text });
        await renderPrivacy();
      } catch (e) { toast(say(e), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
};

// Sub-choice: does a requester's first message travel along with the request?
$('#se-reqtext').onclick = () => {
  const p = cur.reqPrefs || { enabled: true, allow_text: false };
  const card = openModal(
    `<h3>Message with request</h3>
     <p>What happens to a new person's first message while their request waits.</p>
     <div class="modal-list">
       <button data-v="off" ${!p.allow_text ? 'class="sel"' : ''}>${icon('shield')}Request only${!p.allow_text ? '<em>current</em>' : ''}
         <small>You only see that they want to chat — their messages stay out until you
         accept. Recommended.</small></button>
       <button data-v="on" ${p.allow_text ? 'class="sel"' : ''}>${icon('chat')}Message travels along${p.allow_text ? '<em>current</em>' : ''}
         <small>Their first messages ride with the request, so you can read them before
         deciding.</small></button>
     </div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-v]').forEach((b) => {
    b.onclick = async () => {
      closeModal();
      try {
        await invoke('set_msg_request_prefs', { enabled: p.enabled, allowText: b.dataset.v === 'on' });
        await renderPrivacy();
      } catch (e) { toast(say(e), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
};
$('#se-typing').onclick = async () => {
  const v = !(cur.privacy && cur.privacy.send_typing);
  try { await invoke('set_privacy', { sendTyping: v }); await renderPrivacy(); } catch (e) { toast(say(e), 'err'); }
};
$('#se-receipts').onclick = async () => {
  const v = !(cur.privacy && cur.privacy.send_receipts);
  try { await invoke('set_privacy', { sendReceipts: v }); await renderPrivacy(); } catch (e) { toast(say(e), 'err'); }
};
$('#se-notif').onclick = () => {
  const cur3 = (cur.privacy && cur.privacy.notif_level) || 'sender';
  const opts = [['sender_message', 'Sender & message'], ['sender', 'Sender only'], ['generic', "Generic (just 'New message')"]];
  const card = openModal(
    `<h3>Notification content</h3><p>How much a lock screen reveals when a message arrives.</p>
     <div class="modal-list">${opts.map(([v, l]) => `<button data-v="${v}" ${v === cur3 ? 'class="sel"' : ''}>${l}${v === cur3 ? '<em>current</em>' : ''}</button>`).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-v]').forEach((b) => {
    b.onclick = async () => { closeModal(); try { await invoke('set_privacy', { notifLevel: b.dataset.v }); await renderPrivacy(); } catch (e) { toast(say(e), 'err'); } };
  });
  card.querySelector('#mo-no').onclick = closeModal;
}

// Tor/SOCKS proxy: route every relay connection through a local SOCKS5 proxy
// (Tor, or Orbot on Android). Applied live — the subscriber reconnects through the
// new route on save. Calls silently skip the QUIC path while a proxy is set (UDP
// bypasses SOCKS) and use relay-bridged WebSocket media instead.
async function renderProxy() {
  let p = null;
  try { p = await invoke('socks_proxy'); } catch (_) { return; }
  $('#se-proxy-state').textContent = p ? 'On' : 'Off';
}
$('#se-proxy').onclick = async () => {
  let cur = null;
  try { cur = await invoke('socks_proxy'); } catch (_) {}
  const card = openModal(
    `<h3>Tor / SOCKS proxy</h3>
     <p>Route all relay traffic through a SOCKS5 proxy so the relay never sees this
     device's IP address. With Orbot installed, <b>socks5://127.0.0.1:9050</b> routes
     through Tor. Hostnames resolve through the proxy — no DNS leaks. While a proxy is
     set, calls use the relay-bridged path (slower, but nothing bypasses the proxy).</p>
     <input id="mo-proxy" type="text" autocomplete="off" spellcheck="false"
       placeholder="socks5://127.0.0.1:9050" value="${cur ? escapeHtml(cur) : ''}" />
     <div class="modal-btns">
       <button class="btn btn-sm" id="mo-save">Save</button>
       ${cur ? '<button class="btn btn-ghost btn-sm" id="mo-clear">Turn off</button>' : ''}
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>
     </div>`);
  card.querySelector('#mo-save').onclick = async () => {
    const v = card.querySelector('#mo-proxy').value.trim();
    if (!v) return;
    try {
      await invoke('set_socks_proxy', { proxy: v });
      closeModal();
      toast('Proxy enabled — reconnecting through it', 'ok');
    } catch (e) { toast(say(e), 'err'); }
    await renderProxy();
  };
  const clear = card.querySelector('#mo-clear');
  if (clear) clear.onclick = async () => {
    closeModal();
    try { await invoke('set_socks_proxy', { proxy: null }); toast('Proxy disabled', 'ok'); }
    catch (e) { toast(say(e), 'err'); }
    await renderProxy();
  };
  card.querySelector('#mo-no').onclick = closeModal;
};

// ── Storage: session media cache (RAM only; see clearMediaCaches in 30-thread) ───
function mediaCacheLabel() {
  const items = imgCache.map.size + vidCache.map.size + voiceCache.map.size;
  if (!items) return 'empty';
  // Only imgCache tracks byte cost (data URLs); video/voice are a few bounded blobs.
  const mb = imgCache.spent / (1024 * 1024);
  return mb >= 0.1 ? `≈${mb.toFixed(1)} MB · ${items} items` : `${items} items`;
}
$('#se-clearmedia').onclick = () => {
  clearMediaCaches();
  $('#se-clearmedia-state').textContent = 'empty';
  toast('Media cache cleared', 'ok');
};


// ── Notification-tap routing: cold start (pending intent) + warm (navigate event) ─
async function handleNavigate(p) {
  if (!p) return;
  if (p.open_chat) {
    try { if (!lastConvs.length) await loadChats(); } catch (_) {}
    const c = (lastConvs || []).find((c) => c.peer === p.open_chat);
    if (c) (c.kind === 'group' ? openGroup(c.peer, c.username) : openThread(c.username, c.peer, c.nickname || c.username));
  }
  // Answer is deliberately NOT handled here any more. A tap on the ring notification
  // goes straight to Rust (`answer_call`), which is the one answer path Core-Telecom,
  // headsets and the lock screen all use, and which holds the answer against the exact
  // call until the vault opens (internal/CALL_PLAN.md §8). The old time-scoped WebView flag
  // would answer whatever rang next.
}




// ── Devices: list, link, revoke, self-audit, re-sync, primary transfer ───────────
let linkedHistoryPending = false; // this (linked) device's history didn't transfer at link
async function renderDevices() {
  const box = $('#se-devices');
  $('#se-resync').hidden = !linkedHistoryPending;
  let devices = [];
  try { devices = await invoke('list_devices'); }
  catch (_) { box.innerHTML = '<div class="hint devrow-hint">Unavailable.</div>'; return; }
  // Only the primary can authorize, revoke, or hand over the primary role — the account
  // key lives there. (An empty list = single-device account = its own primary.)
  const mine = devices.find((d) => d.is_this_device);
  const iAmPrimary = !devices.length || !!(mine && mine.is_primary);
  $('#se-link').hidden = !iAmPrimary;
  // Renaming and account deletion are primary-only ceremonies (the account key lives there).
  $('#se-chuser').hidden = !iAmPrimary;
  $('#se-delacct').hidden = !iAmPrimary;
  if (!devices.length) {
    box.innerHTML = '<div class="hint devrow-hint">This account has one device. Link another to sync your chats across them.</div>';
  } else {
    box.innerHTML = devices.map((d) => {
      const label = d.is_this_device ? 'This device' : (d.is_primary ? 'Primary device' : 'Linked device');
      const idShort = d.is_primary ? 'primary' : d.device_id.slice(0, 10) + '…';
      const acts = (iAmPrimary && !d.is_this_device && !d.is_primary)
        ? `<button class="btn btn-sm btn-ghost dev-promote" data-id="${escapeHtml(d.device_id)}">Make primary…</button>
           <button class="btn btn-sm btn-danger dev-revoke" data-id="${escapeHtml(d.device_id)}">Revoke</button>` : '';
      return `<div class="devrow"><span class="rowico" data-icon="${d.is_primary ? 'shield' : 'lock'}"></span>
        <div class="devrow-body"><b>${escapeHtml(label)}</b><em class="mono">${escapeHtml(idShort)}</em></div>${acts}</div>`;
    }).join('');
    $$('[data-icon]', box).forEach((el) => (el.innerHTML = icon(el.dataset.icon)));
    $$('.dev-revoke', box).forEach((b) => (b.onclick = () => revokeDevice(b.dataset.id)));
    $$('.dev-promote', box).forEach((b) => (b.onclick = () => transferPrimaryModal(b.dataset.id)));
  }
  // Self-audit: surface an unknown/rogue device as a visible warning.
  const warn = $('#se-devices-warn');
  warn.hidden = true;
  try {
    const res = await invoke('audit_devices');
    if (res.startsWith('rogue:')) {
      warn.hidden = false;
      warn.textContent = '⚠ A device you don’t recognize is on your account (' +
        res.slice(6) + '). If you didn’t add it, revoke it and change your password.';
    }
  } catch (_) { /* audit is best-effort */ }
}

async function revokeDevice(deviceId) {
  if (!(await confirmModal('Revoke this device?',
    'It stops receiving your messages immediately and can no longer act as your account.',
    'Revoke'))) return;
  try {
    await invoke('revoke_device', { deviceId });
    toast('Device revoked', 'ok');
    renderDevices();
  } catch (e) { toast(say(e), 'err'); }
}

// ── QR scanner (camera → jsQR) ───────────────────────────────────────────────────
// The ~250 KB decoder is vendored (strict CSP: no remote assets) and injected only the
// first time the scanner opens.
let jsqrLoading = null;
function loadJsQR() {
  if (window.jsQR) return Promise.resolve();
  if (!jsqrLoading) {
    jsqrLoading = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'vendor/jsQR.js';
      s.onload = resolve;
      s.onerror = () => { jsqrLoading = null; reject(new Error('QR decoder failed to load')); };
      document.head.appendChild(s);
    });
  }
  return jsqrLoading;
}

// Strict shape check for a scanned/pasted link code BEFORE it is accepted: exact JSON
// with the LinkRequest fields only. Scanner input is data, never anything else.
function looksLikeLinkRequest(text) {
  if (typeof text !== 'string' || !text || text.length > 4096) return false;
  try {
    const o = JSON.parse(text);
    return !!(o && typeof o === 'object'
      && /^[0-9a-f]{32}$/.test(o.device_id || '')
      && /^[0-9a-f]{32}$/.test(o.provisioning_id || '')
      && typeof o.link_secret_b64 === 'string' && o.link_secret_b64.length <= 64
      && o.record && typeof o.record === 'object'
      && typeof o.record.identity_key === 'string'
      && typeof o.record.signing_key === 'string');
  } catch (_) { return false; }
}

// Open the camera and scan until a QR matching `accept` is read (default: a device
// link code). Resolves the decoded text, or null on cancel. The stream stays inside
// this function and is stopped on every exit.
async function scanQr(accept = looksLikeLinkRequest) {
  await loadJsQR();
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
  } catch (e) {
    throw new Error(e && (e.name === 'NotAllowedError' || e.name === 'SecurityError')
      ? 'camera permission denied' : 'camera unavailable');
  }
  const ui = $('#scanui'), video = $('#scan-video');
  video.srcObject = stream;
  ui.hidden = false;
  try { await video.play(); } catch (_) {}
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  return new Promise((resolve) => {
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      ui.hidden = true;
      video.srcObject = null;
      stream.getTracks().forEach((t) => t.stop());
      $('#scan-cancel').onclick = null;
      resolve(result);
    };
    $('#scan-cancel').onclick = () => finish(null);
    const tick = () => {
      if (done) return;
      if (video.readyState >= 2 && video.videoWidth) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const hit = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
        if (hit && accept(hit.data)) return finish(hit.data);
      }
      requestAnimationFrame(tick);
    };
    tick();
  });
}

// Primary: scan (or paste) a new device's link code + password to authorize it.
$('#se-link').onclick = () => {
  const canScan = !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  const card = openModal(
    `<h3>Link a device</h3>
     <p>On your new device, tap <em>Link this as a new device</em> — it shows a QR code.
        Scan it here (or paste the text code). Your password authorizes it and seals your
        history for transfer.</p>
     ${canScan ? '<button class="btn" id="mo-scan">Scan QR code</button>' : ''}
     <textarea id="mo-code" class="mono linkcode" rows="4" placeholder="…or paste the link code" spellcheck="false"></textarea>
     <p class="hint mono fingerprint" id="mo-fpr" hidden></p>
     <p class="hint" id="mo-attest" hidden></p>
     <input id="mo-pw" type="password" autocomplete="current-password" placeholder="account password" />
     <button class="btn" id="mo-ok">Authorize device</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  const codeEl = card.querySelector('#mo-code');
  const fprEl = card.querySelector('#mo-fpr');
  const attEl = card.querySelector('#mo-attest');
  // Hardware attestation (advisory): the new device may have parked a Keystore
  // attestation chain on the relay; the verdict says "genuine Android hardware" or why
  // not. Absent on desktop linkers — silence, not a warning.
  const updateAttest = async (t) => {
    attEl.hidden = true;
    let v;
    try { v = await invoke('attest_verdict', { linkRequest: t }); } catch (_) { return; }
    if (v.status === 'absent') return;
    const text = {
      verified: `✔ Hardware-verified device: ${v.detail}`,
      failed: `✖ Hardware attestation FAILED (${v.detail}) — make sure you trust this device before authorizing`,
      unavailable: `Hardware attestation couldn't be checked (${v.detail})`,
    }[v.status];
    if (!text) return;
    attEl.textContent = text;
    attEl.className = 'hint ' + (v.status === 'verified' ? 'ok' : v.status === 'failed' ? 'warn' : '');
    attEl.hidden = false;
  };
  // Fingerprint of the new device's key: compare it against the one shown under the QR
  // on the new device — a swapped/tampered code shows a different fingerprint.
  const updateFpr = async () => {
    const t = codeEl.value.trim();
    if (looksLikeLinkRequest(t)) {
      fprEl.textContent = 'New device key: ' + await keyFingerprint(JSON.parse(t).record.identity_key);
      fprEl.hidden = false;
      updateAttest(t); // async fill-in; never blocks the fingerprint
    } else {
      fprEl.hidden = true;
      attEl.hidden = true;
    }
  };
  codeEl.addEventListener('input', updateFpr);
  const scanBtn = card.querySelector('#mo-scan');
  if (scanBtn) scanBtn.onclick = async () => {
    busy(scanBtn, true, 'Opening camera…');
    try {
      const text = await scanQr();
      busy(scanBtn, false);
      if (text) {
        codeEl.value = text;
        await updateFpr();
        card.querySelector('#mo-pw').focus();
        toast('Code scanned — check the key fingerprint matches the new device', 'ok');
      }
    } catch (e) { busy(scanBtn, false); toast(say(e), 'err'); }
  };
  card.querySelector('#mo-no').onclick = closeModal;
  card.querySelector('#mo-ok').onclick = async () => {
    const linkRequest = codeEl.value.trim();
    const accountPassword = card.querySelector('#mo-pw').value;
    if (!linkRequest) return toast('Scan or paste the link code', 'err');
    if (!accountPassword) return toast('Enter your password', 'err');
    const btn = card.querySelector('#mo-ok');
    busy(btn, true, 'Authorizing…');
    try {
      await invoke('authorize_device', { linkRequest, accountPassword });
      closeModal();
      toast('Device authorized — finish on the new device', 'ok');
      renderDevices();
    } catch (e) { toast(say(e), 'err'); busy(btn, false); }
  };
};

// ── Primary-ownership transfer ────────────────────────────────────────────────────
// Primary side: offer the role to a linked device, then watch for the (target-published)
// rotation to appear in the log — that is the demotion signal; nothing can be *delivered*
// to us once the account mailbox changes hands.
function transferPrimaryModal(deviceId) {
  const card = openModal(
    `<h3>Make that device the primary?</h3>
     <p>The primary holds the account keys: it approves and revokes devices and anchors
        your identity. This device keeps your chats and keeps working as a linked device.
        Your contacts will see a key change — expected for a primary move. The other
        device must accept the offer with the account password.</p>
     <input id="mo-pw" type="password" autocomplete="current-password" placeholder="account password" />
     <button class="btn btn-danger" id="mo-ok">Offer primary role</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelector('#mo-no').onclick = closeModal;
  card.querySelector('#mo-ok').onclick = async () => {
    const pw = card.querySelector('#mo-pw').value;
    if (!pw) return toast('Enter your password', 'err');
    const btn = card.querySelector('#mo-ok');
    busy(btn, true, 'Sending offer…');
    try {
      await invoke('transfer_primary', { deviceId, accountPassword: pw });
      closeModal();
      toast('Offer sent — accept it on the other device', 'ok');
      startDemotionWatch();
    } catch (e) { toast(say(e), 'err'); busy(btn, false); }
  };
}

let demotionTimer = null;
function startDemotionWatch(intervalMs = 5000) {
  if (demotionTimer) return;
  let ticks = 0;
  demotionTimer = setInterval(async () => {
    ticks += 1;
    let res = 'pending';
    try { res = await invoke('check_transfer_cmd'); } catch (_) { /* offline — keep trying */ }
    if (res === 'demoted') {
      clearInterval(demotionTimer); demotionTimer = null;
      toast('Primary role transferred — this is now a linked device', 'ok');
      if (current === 'settings') renderDevices();
    } else if (res === 'none') {
      clearInterval(demotionTimer); demotionTimer = null;
    } else if (ticks > 24 && intervalMs < 60000) {
      // Still pending after ~2 min of snappy polling: NEVER give up while the offer is
      // out (once the target accepts, the account mailbox is no longer ours — this poll
      // is the only way this device learns it must demote), just slow to once a minute.
      clearInterval(demotionTimer); demotionTimer = null;
      startDemotionWatch(60000);
    }
  }, intervalMs);
}

// Re-arm the demotion watch after a restart/unlock while a transfer is still pending.
async function resumeDemotionWatch() {
  try {
    const res = await invoke('check_transfer_cmd');
    if (res === 'pending') startDemotionWatch();
    else if (res === 'demoted') toast('Primary role transferred — this is now a linked device', 'ok');
  } catch (_) { /* best-effort */ }
}

// The relay revoked this device (it was unlinked on another device). Hard lockout:
// close everything transient and pin the UI on the explanation screen — messaging is
// blocked in the backend too, so nothing works until a relink or a fresh account.
function showRevoked() {
  closeModal(); hideCtx();
  show('revoked');
}
listen('revoked', showRevoked);
$('#rv-relink').onclick = () => show('link');
$('#rv-newacc').onclick = () => show('create');

// The relay's access gate refused this device's shared token — the operator rotated it
// (re-key or eviction). The delivery loop already stopped (retrying is pointless); park
// the UI on the explanation screen. Reconnecting walks the normal connect flow with the
// relay URL + pinned key prefilled, the token deliberately blank, and then the usual
// sign-in — vault and history stay intact throughout.
function showAccessDenied() {
  closeModal(); hideCtx();
  show('accessdenied');
}
listen('relay_access_denied', showAccessDenied);
$('#ad-reconnect').onclick = () => show('connect');

// Target side: the primary offered US the role; confirm with the account password.
listen('primary_transfer', async () => {
  const password = await passwordPrompt('Become the primary device?',
    'Your primary device offered to move the primary role to THIS device. It will hold ' +
    'your account keys and approve future devices. Enter your account password to accept.');
  if (!password) {
    // The offer is kept (sealed, on disk) — it re-prompts at the next unlock.
    toast('Transfer offer kept — you can accept it after your next unlock', '');
    return;
  }
  try {
    await invoke('accept_primary_cmd', { accountPassword: password });
    toast('This device is now your primary', 'ok');
    if (current === 'settings') renderDevices();
  } catch (e) { toast(say(e), 'err'); }
});

// Linked device: history transfer expired — ask the primary to re-export, then poll.
$('#se-resync').onclick = async () => {
  const password = await passwordPrompt('Re-sync history',
    'Your account password unlocks the re-exported history once your primary device sends it.');
  if (!password) return;
  toast('Requesting history from your primary…', '');
  let prov;
  try { prov = await invoke('request_resync'); }
  catch (e) { return toast(say(e), 'err'); }
  const [provisioningId, linkSecretB64] = prov;
  // Poll for a minute; the primary approves with its password on its side.
  let tries = 0;
  const timer = setInterval(async () => {
    tries += 1;
    let got = false;
    try {
      got = await invoke('poll_resync_cmd', { provisioningId, linkSecretB64, accountPassword: password });
    } catch (e) { clearInterval(timer); return toast(say(e), 'err'); }
    if (got) {
      clearInterval(timer);
      linkedHistoryPending = false;
      toast('History synced', 'ok');
      renderDevices();
      loadChats();
    } else if (tries >= 20) {
      clearInterval(timer);
      toast('No history yet — approve the request on your primary device, then retry', '');
    }
  }, 3000);
};

// Primary: a linked device asked to re-sync history — prompt for the password to allow.
listen('resync_request', async (ev) => {
  const { sender_key, provisioning_id, link_secret_b64 } = ev.payload || {};
  if (!provisioning_id) return;
  const password = await passwordPrompt('Sync history to your other device?',
    'One of your devices asked for your chat history. Enter your password to seal and send it.');
  if (!password) return;
  try {
    await invoke('fulfill_resync_cmd', {
      senderKey: sender_key, provisioningId: provisioning_id,
      linkSecretB64: link_secret_b64, accountPassword: password,
    });
    toast('History sent to your device', 'ok');
  } catch (e) { toast(say(e), 'err'); }
});

