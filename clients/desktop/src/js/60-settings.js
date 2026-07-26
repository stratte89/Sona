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
async function renderPrivacy() {
  let p;
  try { p = await invoke('privacy_prefs'); } catch (_) { return; }
  const setState = (id, on) => { const e = $(id); e.textContent = on ? 'On' : 'Off'; e.className = on ? 'ok' : ''; };
  setState('#se-typing-state', p.send_typing);
  setState('#se-receipts-state', p.send_receipts);
  $('#se-notif-state').textContent = NOTIF_LABELS[p.notif_level] || 'Sender only';
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

// ── Notifications & delivery (docs/NOTIFICATIONS.md §7.1): mode radio, health panel, tests ─────
const MODE_LABELS = { c: 'Connection', cp: 'Connection + push', p: 'Push only' };
const CONN_LABELS = { connected: 'Connected', reconnecting: 'Reconnecting…', locked: 'Locked', off: 'Off' };
let lastDelivery = null;
async function renderDelivery() {
  let d;
  try { d = await invoke('delivery_status'); } catch (_) { return; }
  lastDelivery = d;
  $('#se-delivery-mode-state').textContent = MODE_LABELS[d.mode] || d.mode;
  const h = d.health;
  let issues = 0;
  if (h) {
    if (!h.battery_exempt && d.mode !== 'p') issues++;
    if (!h.notifications_enabled) issues++;
    if (!h.full_screen_intent) issues++;
    if (h.messages_channel_muted || h.calls_channel_muted) issues++;
  }
  const st = $('#se-delivery-health-state');
  // Device-offline (airplane mode, or the app's Network permission revoked on
  // GrapheneOS) outranks "Reconnecting…": nothing is wrong with delivery, the OS
  // presents no network. Not counted as an issue — it resolves itself on reconnect.
  const offline = h && h.network === false && d.conn === 'reconnecting';
  st.textContent = issues ? `${issues} issue${issues > 1 ? 's' : ''}` : offline ? 'No network' : (CONN_LABELS[d.conn] || d.conn);
  st.className = issues ? 'warn' : (d.conn === 'connected' ? 'ok' : '');
  // Push transport row: only shown where it matters — devices WITHOUT Play Services
  // (GrapheneOS etc.), or when a UnifiedPush distributor is already in use. Stock
  // devices keep their familiar Google-push settings untouched.
  const upRow = h && (!h.play_services || h.up_distributor);
  $('#se-up').hidden = !upRow;
  if (upRow) {
    $('#se-up-state').textContent =
      h.up_endpoint || d.up_endpoint ? 'UnifiedPush' :
      h.up_distributor ? 'Connecting…' : 'Off';
  }
}
$('#se-delivery-mode').onclick = () => {
  const d = lastDelivery || { mode: 'c', relay_fcm: false, relay_webhook: false, health: null };
  const h = d.health;
  // Desktop (Linux/Windows/macOS) has NO push transport of any kind — no FCM, no
  // UnifiedPush — and the tray keeps it permanently connected anyway. The delivery-health
  // payload is Android-only, so its absence marks desktop: there, "Connection" is the only
  // meaningful mode and the push options are dropped entirely (offering them was a bug —
  // they keyed off the RELAY's push support, not this device's).
  const isDesktop = !h && !d.up_endpoint;
  // Two audiences, two surfaces. Stock devices (Play Services present) keep the
  // familiar Google-push options exactly as they were. De-Googled devices
  // (GrapheneOS etc.) get the same modes powered by UnifiedPush instead — that is
  // the only place the UI changes.
  const googley = !h || h.play_services;
  const upOk = (h && (h.up_endpoint || h.up_available || h.up_distributor)) || d.up_endpoint;
  const pushOk = !isDesktop && (googley
    ? d.relay_fcm || ((d.relay_webhook || d.relay_fcm) && upOk)
    : (d.relay_webhook || d.relay_fcm) && upOk);
  const why = googley && !d.relay_fcm ? 'relay has no push support'
    : !(d.relay_webhook || d.relay_fcm) ? 'relay has no push support'
    : 'install a UnifiedPush app such as ntfy first';
  const wakeVia = googley ? 'a content-free wake-up' : 'a content-free wake-up through your UnifiedPush app';
  const opts = [
    ['c', 'Connection', isDesktop ? 'Always connected while Sona runs in the tray. Most private — no third party.' : 'Always connected. Most private — no third party. Uses more battery.', true],
    ...(isDesktop ? [] : [
      ['cp', 'Connection + push fallback', `Connected when possible; if Android kills the connection, ${wakeVia} restores delivery. Recommended.`, pushOk],
      ['p', 'Push only', `Battery saver. Messages arrive within seconds via ${wakeVia}. No persistent notification.`, pushOk],
    ]),
  ];
  const card = openModal(
    `<h3>Delivery mode</h3><p>How this device receives messages when the app is closed.</p>
     <div class="modal-list">${opts.map(([v, l, sub, ok]) =>
       `<button data-v="${v}" ${ok ? '' : 'disabled'} ${v === d.mode ? 'class="sel"' : ''}>${l}${v === d.mode ? '<em>current</em>' : ''}
        <small>${sub}${ok ? '' : ` — unavailable (${why})`}</small></button>`).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-v]').forEach((b) => {
    b.onclick = async () => {
      closeModal();
      try { await invoke('set_delivery_mode', { mode: b.dataset.v }); toast('Delivery mode updated', 'ok'); }
      catch (e) { toast(say(e), 'err'); }
      await renderDelivery();
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
};
// UnifiedPush distributor picker: the user-facing push transport. The system-push
// fallback is deliberately not offered here — no Google option in the UI; it only
// kicks in silently when no distributor exists.
$('#se-up').onclick = async () => {
  let dists = [];
  try { dists = await invoke('up_distributors'); } catch (_) {}
  const h = (lastDelivery && lastDelivery.health) || {};
  if (!dists.length) {
    openModal(`<h3>Push wake-ups</h3>
      <p>No UnifiedPush app is installed. Install a distributor — <b>ntfy</b> (F-Droid /
      Play) is the easiest — then choose it here. It keeps one battery-friendly
      connection for all your apps and delivers Sona's content-free wake-ups without
      any Google involvement. You can also self-host the ntfy server.</p>
      <button class="btn btn-ghost btn-sm" id="mo-no">Close</button>`)
      .querySelector('#mo-no').onclick = closeModal;
    return;
  }
  const rows = dists.map((x) =>
    `<button data-pkg="${escapeHtml(x.pkg)}" ${h.up_distributor === x.pkg ? 'class="sel"' : ''}>${escapeHtml(x.label)}
     ${h.up_distributor === x.pkg ? '<em>current</em>' : ''}<small>${escapeHtml(x.pkg)}</small></button>`).join('');
  const card = openModal(`<h3>Push wake-ups</h3>
    <p>Deliver content-free wake-ups through a UnifiedPush app you choose — no Google.</p>
    <div class="modal-list">${rows}
      ${h.up_distributor ? '<button data-off="1">Stop using UnifiedPush<small>falls back to the system push if this phone has one, else connection mode only</small></button>' : ''}
    </div>
    <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-pkg]').forEach((b) => {
    b.onclick = async () => {
      closeModal();
      try { await invoke('up_select', { pkg: b.dataset.pkg }); toast('Waiting for the push app to connect…', 'ok'); }
      catch (e) { toast(say(e), 'err'); }
      setTimeout(renderDelivery, 2000); // endpoint lands async from the distributor
    };
  });
  const off = card.querySelector('[data-off]');
  if (off) off.onclick = async () => {
    closeModal();
    try { await invoke('up_clear'); toast('UnifiedPush disabled', 'ok'); } catch (e) { toast(say(e), 'err'); }
    await renderDelivery();
  };
  card.querySelector('#mo-no').onclick = closeModal;
};
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
// Phone makers whose battery "optimizers" kill background apps beyond stock Android.
// No API can detect or fix it — dontkillmyapp.com documents each maker's switches.
const OEM_KILLERS = ['samsung', 'xiaomi', 'redmi', 'poco', 'huawei', 'honor', 'oneplus',
  'oppo', 'realme', 'vivo', 'meizu', 'asus', 'sony', 'lenovo', 'nokia', 'hmd global',
  'unihertz', 'tecno', 'infinix', 'blackview'];

// The health panel re-checks every 2 s while open, so a fix made in system settings
// turns its row green the moment the user comes back — no reopen dance.
function healthBodyHtml(d) {
  const h = d.health;
  const row = (ok, good, bad, fix, fixLabel) =>
    `<div class="health-row"><span class="${ok ? 'ok' : 'warn'}">${ok ? '✓' : '!'}</span> ${ok ? good : bad}
     ${!ok && fix !== undefined ? `<button class="btn btn-ghost btn-sm" data-fix="${fix}">${fixLabel || 'Fix'}</button>` : ''}</div>`;
  const checks = [];
  if (h) {
    checks.push([h.notifications_enabled,
      'Notifications are allowed', 'Notifications are blocked — nothing can be shown', 1]);
    if (d.mode !== 'p') checks.push([h.battery_exempt,
      'Android lets Sona stay connected', 'Android may put Sona to sleep and delay messages', 0]);
    checks.push([h.full_screen_intent,
      'Calls can ring over the lock screen', 'Calls can’t take over the lock screen', 2]);
    checks.push([!h.messages_channel_muted && !h.calls_channel_muted,
      'Message and call sounds are on',
      'A notification channel is muted in system settings', 1]);
    checks.push([h.up_endpoint || h.play_services || d.mode === 'c',
      h.up_endpoint ? 'Push wake-ups ready (UnifiedPush)' : 'Push wake-ups ready',
      'No push wake-ups — install a UnifiedPush app such as ntfy', undefined]);
  }
  const issues = checks.filter((c) => !c[0]).length;
  const connPhrase =
    d.conn === 'connected' ? 'Connected to your relay right now.' :
    d.conn === 'reconnecting' ? 'Reconnecting to your relay…' :
    d.conn === 'locked' ? 'Locked — delivery resumes when you unlock Sona.' :
    d.mode === 'p' ? 'Push mode — this phone wakes up when a message arrives.' :
    'Delivery is off.';
  const good = issues === 0 && d.conn !== 'locked';
  let out = `<div class="health-hero ${issues ? 'bad' : good ? 'good' : ''}">
    <span class="h-ico">${issues ? '⚠️' : '✅'}</span>
    <span><b>${issues ? `${issues} thing${issues > 1 ? 's' : ''} need${issues > 1 ? '' : 's'} your attention`
      : 'Everything looks good'}</b>
    <small>${connPhrase}${issues ? ' This screen updates by itself as you fix things.' : ''}</small></span></div>`;
  out += checks.map((c) => row(c[0], c[1], c[2], c[3], c[4])).join('');
  if (h) {
    const maker = String(h.manufacturer || '').toLowerCase();
    if (OEM_KILLERS.includes(maker)) {
      const nice = maker.charAt(0).toUpperCase() + maker.slice(1);
      out += row(false,
        '', `${escapeHtml(nice)} phones aggressively kill background apps — a 2-minute guide fixes it for good`,
        3, 'Guide');
    }
    if (d.push_registered) out += '<p class="hint">A push wake-up endpoint is registered with your relay.</p>';
  } else {
    out += '<p class="hint">Health probes are Android-only; the desktop tray keeps delivery alive.</p>';
  }
  return out;
}

$('#se-delivery-health').onclick = async () => {
  await renderDelivery();
  if (!lastDelivery) return;
  const card = openModal(`<h3>Delivery health</h3><div id="hl-body">${healthBodyHtml(lastDelivery)}</div>
    <button class="btn btn-ghost btn-sm" id="mo-no">Close</button>`);
  const wireFixes = () => {
    card.querySelectorAll('[data-fix]').forEach((b) => {
      b.onclick = () => {
        b.textContent = '…';
        invoke('delivery_fixit', { what: Number(b.dataset.fix) }).catch(() => {});
      };
    });
  };
  wireFixes();
  // Live refresh: system settings changes show up here without reopening. The
  // interval dies with the modal (body node gone → clear). Compare against the last
  // GENERATED html (innerHTML round-trips normalize entities) so an unchanged state
  // never re-renders — no flicker, and a pressed Fix button keeps its "…" state.
  let lastHtml = healthBodyHtml(lastDelivery);
  const timer = setInterval(async () => {
    const body = document.getElementById('hl-body');
    // Modal gone via Esc/backdrop too: refresh the settings row so the issue count
    // doesn't stay stale after the user fixed things and closed the panel.
    if (!body) { clearInterval(timer); renderDelivery(); return; }
    try {
      await renderDelivery(); // updates lastDelivery AND the settings row behind the modal
      const html = healthBodyHtml(lastDelivery);
      if (html !== lastHtml) { lastHtml = html; body.innerHTML = html; wireFixes(); }
    } catch (_) {}
  }, 2000);
  card.querySelector('#mo-no').onclick = () => { clearInterval(timer); closeModal(); renderDelivery(); };
};
$('#se-test-notif').onclick = () => { invoke('test_notification').catch((e) => toast(say(e), 'err')); toast('Test notification sent', 'ok'); };
$('#se-test-ring').onclick = () => { invoke('test_ring').catch((e) => toast(say(e), 'err')); toast('Test ring — auto-stops in 5 s', 'ok'); };

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
  // Answer tapped on the ring notification (or its full-screen intent): accept as soon
  // as the incoming-call UI exists. On a cold/locked start the incoming state only
  // materializes after unlock + drain, so arm a short-lived flag that the 'incoming'
  // event / call_status resync redeems. (The generic locked ring carries
  // call="locked-call"; the real offer has a different id — the flag is time-scoped,
  // not id-matched, because tapping Answer can only refer to the one live ring.)
  if (p.call_action === 'answer') armAutoAnswer();
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

