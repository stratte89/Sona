// ═══════════════════════════════════════════════════════════════════════════════
// Boot: decide the first screen.
// ═══════════════════════════════════════════════════════════════════════════════
let sec = null;        // last security_status snapshot (unlock methods, timers)
let remindPin = false; // this open crossed the PIN-reminder threshold

async function refreshSec() {
  try { sec = await invoke('security_status'); } catch (_) { /* keep the old snapshot */ }
  return sec;
}

async function boot() {
  try {
    const st = await invoke('app_status');
    if (!st.configured) return show('connect');
    try { remindPin = await invoke('note_app_open'); } catch (_) {}
    if (st.unlocked) return st.revoked ? showRevoked() : afterUnlock();
    if (!st.has_vault) return show('create');
    await refreshSec();
    // Auto-unlock (opt-in): no prompt at all when the device key opens the wrapped blob.
    try {
      if (await invoke('try_auto_unlock')) return afterUnlock();
    } catch (_) {}
    renderUnlock();
    show('unlock');
    // Fingerprint enabled? Offer it immediately; cancelling falls back to PIN/password.
    if (sec && sec.bio_enabled) bioUnlock();
  } catch (e) {
    toast(say(e), 'err');
    show('connect');
  }
}

// Every successful unlock lands here: open the app, arm the idle lock, run the
// periodic PIN reminder if this open crossed the threshold.
async function afterUnlock() {
  await refreshSec();
  try { myName = (await invoke('app_status')).account_id || ''; } catch (_) {}
  await openChats();
  try { await handleNavigate(await invoke('take_pending_intent')); } catch (_) {}
  probeGif(); // fire-and-forget capability probe (shows the composer GIF button)
  resyncCall();
  resumeDemotionWatch(); // primary transfer offered before a restart? (fire-and-forget)
  if (remindPin && sec && sec.pin_set) {
    remindPin = false;
    pinReminderModal();
  }
}

// ── Connect ─────────────────────────────────────────────────────────────────────
// The relay address is a scheme dropdown + a bare host[:port] input; combine them into a
// full URL for the backend. Pasting a full URL auto-moves the scheme into the dropdown.
function relayUrl() {
  return $('#cx-scheme').value + $('#cx-server').value.trim().replace(/\/+$/, '');
}
// Shared access token for private relays (ACCESS_MODE=token/stealth). Empty = open relay.
function relayToken() {
  const t = $('#cx-token').value.trim();
  return t || null;
}

// Copy text to the clipboard (Tauri webview async API, execCommand fallback).
async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
    return true;
  } catch (_) { return false; }
}

// ── Relay invites ──────────────────────────────────────────────────────────────
// One QR/paste carries everything a new member needs: relay URL, pinned KT key, and
// (private relays) the shared access token. Generated in Settings, consumed here.
function parseInvite(text) {
  try {
    const o = JSON.parse(text);
    if (o.sona !== 'invite' || o.v !== 1) return null;
    if (typeof o.url !== 'string' || !/^https?:\/\//i.test(o.url)) return null;
    if (typeof o.kt !== 'string' || !o.kt) return null;
    if (o.token != null && typeof o.token !== 'string') return null;
    return o;
  } catch (_) { return null; }
}
function applyInvite(inv) {
  const m = /^(https?:\/\/)(.*)$/i.exec(inv.url.trim().replace(/\/+$/, ''));
  $('#cx-scheme').value = m[1].toLowerCase();
  $('#cx-server').value = m[2];
  $('#cx-pin').value = inv.kt;
  $('#cx-token').value = inv.token || '';
  // Show the user what the invite filled in (token + pinned key live under Advanced).
  $('#cx-adv').open = true;
  toast('Invite applied — review and continue', 'ok');
}
$('#cx-scan').onclick = async () => {
  try {
    const text = await scanQr((t) => !!parseInvite(t));
    if (text) applyInvite(parseInvite(text));
  } catch (e) { toast(say(e), 'err'); }
};
$('#cx-server').addEventListener('input', () => {
  const el = $('#cx-server');
  // Pasting a whole invite (the QR's text form) into the address field applies it.
  const inv = parseInvite(el.value);
  if (inv) return applyInvite(inv);
  const m = /^(https?:\/\/)/i.exec(el.value);
  if (m) {
    $('#cx-scheme').value = m[1].toLowerCase();
    el.value = el.value.slice(m[1].length);
  }
});
// Dev default 127.0.0.1:5002 wants http:// (matches the old baked-in default).
(() => {
  const host = $('#cx-server').value.trim();
  if (/^(127\.0\.0\.1|localhost)(:|$)/.test(host)) $('#cx-scheme').value = 'http://';
})();
$('#cx-fetch').onclick = async () => {
  const url = relayUrl();
  if (!$('#cx-server').value.trim()) return toast('Enter a relay address first', 'err');
  try {
    $('#cx-pin').value = await invoke('fetch_kt_pubkey', { baseUrl: url, accessToken: relayToken() });
    $('#cx-fetch-hint').hidden = false;
  } catch (e) { toast('Fetch failed: ' + say(e), 'err'); }
};
async function finishConfigure(url, pin) {
  await invoke('configure', { baseUrl: url, pinnedKtKey: pin, accessToken: relayToken() });
  const st = await invoke('app_status');
  show(st.has_vault ? 'unlock' : 'create');
}
$('#cx-continue').onclick = async () => {
  const url = relayUrl();
  if (!$('#cx-server').value.trim()) return toast('Enter a relay address', 'err');
  const pastedPin = $('#cx-pin').value.trim();
  // Power path: a pin was pasted under Advanced — trust the user's out-of-band value.
  if (pastedPin) return finishConfigure(url, pastedPin).catch((e) => toast(say(e), 'err'));
  // Default path: fetch the KT key and show a fingerprint confirm step first.
  const btn = $('#cx-continue');
  busy(btn, true, 'Fetching key…');
  let key;
  try { key = await invoke('fetch_kt_pubkey', { baseUrl: url, accessToken: relayToken() }); }
  catch (e) { busy(btn, false); return toast('Could not reach relay: ' + say(e), 'err'); }
  busy(btn, false);
  const fpr = await keyFingerprint(key).catch(() => key);
  const card = openModal(
    `<h3>Confirm the relay's key</h3>
     <p>This is the relay's Key Transparency key. <strong>Confirm it out-of-band</strong>
        (with whoever runs the relay) — trusting it blindly defeats the point of pinning it.</p>
     <p class="hint mono fingerprint">${escapeHtml(fpr)}</p>
     <button class="btn" id="mo-ok">This matches — continue</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelector('#mo-ok').onclick = async () => { closeModal(); try { await finishConfigure(url, key); } catch (e) { toast(say(e), 'err'); } };
  card.querySelector('#mo-no').onclick = closeModal;
};

// ── Create account ───────────────────────────────────────────────────────────────
const crPass = $('#cr-pass');
const crPass2 = $('#cr-pass2');
// Both strength AND repeat must pass: there is no password reset — a typo'd
// password seals the vault behind a string the user can't reproduce.
function crMatchState() {
  const m = $('#cr-match');
  if (!crPass2.value) { m.textContent = ''; m.className = 'strength-reqs'; return false; }
  const ok = crPass2.value === crPass.value;
  m.textContent = ok ? 'Passwords match.' : 'Passwords do not match.';
  m.className = 'strength-reqs' + (ok ? ' ok' : '');
  return ok;
}
crPass.addEventListener('input', async () => {
  const pw = crPass.value;
  const bar = $('#cr-bar'), reqs = $('#cr-reqs');
  if (!pw) { bar.style.width = '0'; reqs.textContent = ''; crMatchState(); $('#cr-create').disabled = true; return; }
  const r = await invoke('password_strength', { password: pw });
  const filled = Math.max(1, 5 - r.problems.length);
  bar.style.width = (filled / 5 * 100) + '%';
  bar.style.background = r.acceptable ? 'var(--brand)' : filled >= 3 ? '#f59e0b' : 'var(--danger)';
  reqs.className = 'strength-reqs' + (r.acceptable ? ' ok' : '');
  reqs.textContent = r.acceptable ? 'Strong enough.' : 'Needs: ' + r.problems.join(', ');
  $('#cr-create').disabled = !r.acceptable || !$('#cr-user').value.trim() || !crMatchState();
});
crPass2.addEventListener('input', () => crPass.dispatchEvent(new Event('input')));
$('#cr-user').addEventListener('input', () => crPass.dispatchEvent(new Event('input')));
$('#cr-create').onclick = async () => {
  const btn = $('#cr-create');
  busy(btn, true, 'Creating identity…');
  try {
    await invoke('create_account', {
      username: $('#cr-user').value.trim(),
      password: crPass.value,
      inviteCode: $('#cr-invite').value.trim() || null,
    });
    crPass.value = '';
    crPass2.value = '';
    $('#cr-invite').value = '';
    busy(btn, false);
    toast('Identity created', 'ok');
    openChats();
  } catch (e) { toast(say(e), 'err'); busy(btn, false); }
};

// ── Unlock ────────────────────────────────────────────────────────────────────────
// The lock screen offers whatever quick-unlock methods exist (PIN, fingerprint) and
// keeps the password one tap away. `sec` decides what to show.
function renderUnlock() {
  const hasPin = !!(sec && sec.pin_set);
  const hasBio = !!(sec && sec.bio_enabled);
  $('#un-pin-area').hidden = !hasPin;
  $('#un-bio-btn').hidden = !hasBio;
  $('#un-pass-area').hidden = hasPin; // password stays reachable via the switch below
  $('#un-switch').hidden = !hasPin;
  $('#un-switch').textContent = 'Use password instead';
  $('#un-pin').value = '';
  $('#un-pass').value = '';
}
$('#un-switch').onclick = () => {
  const showingPin = !$('#un-pin-area').hidden;
  $('#un-pin-area').hidden = showingPin;
  $('#un-pass-area').hidden = !showingPin;
  $('#un-switch').textContent = showingPin ? 'Use PIN instead' : 'Use password instead';
  (showingPin ? $('#un-pass') : $('#un-pin')).focus();
};

$('#un-unlock').onclick = unlockNow;
$('#un-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockNow(); });
async function unlockNow() {
  const btn = $('#un-unlock');
  busy(btn, true, 'Unlocking…'); // Argon2 takes a moment by design — show it
  try {
    await invoke('unlock', { password: $('#un-pass').value });
    $('#un-pass').value = '';
    afterUnlock();
  } catch (e) { toast(say(e), 'err'); } finally { busy(btn, false); }
}

$('#un-pin-btn').onclick = pinUnlockNow;
$('#un-pin').addEventListener('keydown', (e) => { if (e.key === 'Enter') pinUnlockNow(); });
async function pinUnlockNow() {
  const pin = $('#un-pin').value;
  if (!pin) return;
  const btn = $('#un-pin-btn');
  busy(btn, true, 'Unlocking…');
  try {
    await invoke('unlock_pin', { pin });
    $('#un-pin').value = '';
    afterUnlock();
  } catch (e) {
    toast(say(e), 'err');
    $('#un-pin').value = '';
    // The counter may have wiped the PIN blob — re-render so password takes over.
    await refreshSec();
    renderUnlock();
  } finally { busy(btn, false); }
}

$('#un-bio-btn').onclick = bioUnlock;
async function bioUnlock() {
  try {
    await invoke('unlock_bio');
    afterUnlock();
  } catch (_) { /* cancelled or invalidated — PIN/password remain on screen */ }
}

// ── Link this install to an existing account (new device) ────────────────────────
// Flow: enter username+password → link_start returns the code → shown as a QR the
// primary scans (Settings → Devices → Link a device; text code as fallback) → back
// here, finish → complete_link_cmd.
let linkPending = false; // a code has been generated and is awaiting primary approval
$('#un-link').onclick = () => openLink();
$('#cr-link').onclick = () => openLink();
$('#lk-back').onclick = () => history.back();
function openLink() {
  $('#lk-codebox').hidden = true;
  $('#lk-code').value = '';
  $('#lk-qr').innerHTML = '';
  linkPending = false;
  linkShowText(false);
  show('link');
}

// A short human-checkable fingerprint of a device identity key: the first 8 bytes of
// SHA-256, hex-grouped. Shown under the QR on the new device AND on the primary after
// scan/paste, so the user can confirm the code wasn't swapped in transit.
async function keyFingerprint(identityKeyB64) {
  try {
    const data = new TextEncoder().encode('sona-device-fpr|' + identityKeyB64);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hex = [...new Uint8Array(digest)].slice(0, 8)
      .map((b) => b.toString(16).padStart(2, '0')).join('');
    return (hex.match(/.{4}/g) || [hex]).join(' ');
  } catch (_) {
    // No SubtleCrypto (shouldn't happen in the Tauri webview) — show the key head raw.
    return identityKeyB64.slice(0, 19);
  }
}

// Render the link code as a QR (inline SVG from the vendored encoder — no remote
// assets). ~500-byte payload → auto version, error-correction M.
function renderLinkQr(code) {
  const box = $('#lk-qr');
  try {
    const qr = qrcode(0, 'M');
    qr.addData(code, 'Byte');
    qr.make();
    box.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true, alt: { text: 'device link code' } });
    return true;
  } catch (_) {
    box.innerHTML = ''; // payload too dense for a QR — text code remains
    return false;
  }
}

// Toggle between the QR (default) and the copyable text code.
function linkShowText(showText) {
  $('#lk-qr').hidden = showText;
  $('#lk-code').hidden = !showText;
  $('#lk-copy').hidden = !showText;
  $('#lk-toggle').textContent = showText ? 'Show QR code' : 'Show text code';
}
$('#lk-toggle').onclick = () => linkShowText($('#lk-code').hidden);

$('#lk-gen').onclick = async () => {
  const username = $('#lk-user').value.trim();
  const password = $('#lk-pass').value;
  if (!username) return toast('Enter your account username', 'err');
  if (!password) return toast('Enter your account password', 'err');
  const btn = $('#lk-gen');
  busy(btn, true, 'Preparing…');
  try {
    const code = await invoke('link_start', { username, password });
    $('#lk-code').value = code;
    linkShowText(!renderLinkQr(code));
    const fpr = $('#lk-fpr');
    fpr.hidden = true;
    try {
      const req = JSON.parse(code);
      fpr.textContent = 'Device key: ' + await keyFingerprint(req.record.identity_key);
      fpr.hidden = false;
    } catch (_) {}
    $('#lk-codebox').hidden = false;
    linkPending = true;
    $('#lk-codebox').scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (e) { toast(say(e), 'err'); } finally { busy(btn, false); }
};
$('#lk-copy').onclick = async () => {
  const ta = $('#lk-code');
  try {
    // Tauri webviews expose the async clipboard; fall back to execCommand.
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(ta.value);
    } else {
      ta.removeAttribute('readonly'); ta.select();
      document.execCommand('copy'); ta.setAttribute('readonly', '');
    }
    toast('Code copied', 'ok');
  } catch (_) { ta.select(); toast('Select the code and copy it', ''); }
};
$('#lk-finish').onclick = async () => {
  if (!linkPending) return toast('Generate a code first', 'err');
  const password = $('#lk-pass').value;
  if (!password) return toast('Re-enter your account password', 'err');
  const btn = $('#lk-finish');
  busy(btn, true, 'Finishing…');
  try {
    const res = await invoke('complete_link_cmd', { accountPassword: password });
    $('#lk-pass').value = '';
    linkPending = false;
    if (res.history_synced) {
      toast('Device linked', 'ok');
    } else {
      // The device is linked and works; only pre-existing history didn't transfer.
      linkedHistoryPending = true;
      toast('Linked — history transfer expired, re-sync from Settings', '');
    }
    await afterUnlock();
  } catch (e) {
    // Most common: primary hasn't approved yet, or a mistyped password. Keep the code.
    toast(say(e), 'err');
  } finally { busy(btn, false); }
};

// ── Idle auto-lock: any input counts as activity; the timer is a security setting ──
let lastActivity = Date.now();
['pointerdown', 'keydown', 'touchstart', 'wheel'].forEach((ev) =>
  document.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true }));
setInterval(async () => {
  if (!sec || !sec.lock_after_secs) return;
  if (['loading', 'connect', 'create', 'unlock'].includes(current)) return;
  if (Date.now() - lastActivity >= sec.lock_after_secs * 1000) await doLock(true);
}, 5000);

async function doLock(auto) {
  try { await invoke('lock'); } catch (e) { return toast(say(e), 'err'); }
  closeModal(); hideCtx(); closeLightbox();
  // Locking drops the keys — drop the decrypted media this session cached too
  // (clear() runs each cache's onEvict: blob URLs revoked, audio released).
  cancelVoice(); stopNowPlaying();
  voiceCache.clear();
  imgCache.clear();
  vidCache.clear();
  await refreshSec();
  renderUnlock();
  show('unlock');
  if (auto) toast('Locked after inactivity');
}

// ── PIN reminder (every Nth open, so the PIN isn't forgotten) ─────────────────────
function pinReminderModal() {
  const card = openModal(
    `<h3>Quick PIN check</h3>
     <p>Enter your unlock PIN so it stays in memory — yours, not the phone's. Wrong
        entries count against the ${sec ? sec.pin_attempts_left : 5}-attempt limit.</p>
     <input id="mo-pin" type="password" inputmode="numeric" maxlength="8" autocomplete="off" placeholder="PIN" />
     <button class="btn" id="mo-ok">Verify</button>
     <button class="btn btn-ghost btn-sm" id="mo-later">Later</button>`);
  const pinEl = card.querySelector('#mo-pin');
  setTimeout(() => pinEl.focus(), 100);
  const go = async () => {
    const pin = pinEl.value;
    if (!pin) return;
    try {
      await invoke('verify_pin', { pin });
      closeModal();
      toast('PIN confirmed', 'ok');
    } catch (e) {
      pinEl.value = '';
      toast(say(e), 'err');
      if (String(say(e)).includes('disabled')) closeModal();
    }
  };
  card.querySelector('#mo-ok').onclick = go;
  pinEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  card.querySelector('#mo-later').onclick = closeModal;
}

