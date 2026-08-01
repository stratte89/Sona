// Delivery: mode, push transport, and the health panel (docs/NOTIFICATIONS.md §7.1).
//
// Split out of 60-settings.js — the mode picker, the UnifiedPush distributor picker
// and the health panel are one surface, and the GrapheneOS guidance (internal/CALL_PLAN.md
// §10) belongs beside them. `renderDelivery` is called from openSettings.

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
    // Same rule as the modal's fallback row, so the count behind it matches.
    if (d.mode !== 'c' && !d.push_registered) issues++;
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
      ['cp', 'Connection + push fallback', `Connected when possible; if Android kills the connection, ${wakeVia} restores delivery. Recommended — and the default wherever a wake-up path exists.`, pushOk],
      ['p', 'Push only', `Battery saver. Messages arrive within seconds via ${wakeVia}. No persistent notification — incoming calls may ring later than on your other devices.`, pushOk],
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

// Phone makers whose battery "optimizers" kill background apps beyond stock Android.
// No API can detect or fix it — dontkillmyapp.com documents each maker's switches.
const OEM_KILLERS = ['samsung', 'xiaomi', 'redmi', 'poco', 'huawei', 'honor', 'oneplus',
  'oppo', 'realme', 'vivo', 'meizu', 'asus', 'sony', 'lenovo', 'nokia', 'hmd global',
  'unihertz', 'tecno', 'infinix', 'blackview'];

// Guidance for the platform states no delivery architecture can engineer around
// (internal/CALL_PLAN.md §10.1–§10.3). Written for GrapheneOS because that is where they are
// normal rather than exotic — a de-Googled phone, a per-profile sandboxed Play, a
// revoked Network permission — but every line is true of stock Android too.
function grapheneHints(d, h) {
  let out = '';
  if (h.network === false) {
    out += `<p class="hint">Android is giving Sona no network right now. If this phone
      isn't in airplane mode, check Sona's <b>Network</b> permission — with it off,
      nothing can be delivered by any transport.</p>`;
  }
  if (h.play_installed === false && !h.up_endpoint) {
    out += `<p class="hint">No Google Play services on this phone. Sona doesn't need it:
      install a UnifiedPush app such as <b>ntfy</b> for battery-cheap wake-ups, or stay in
      Connection mode and Sona's own connection carries everything.</p>`;
  } else if (h.play_installed && !d.push_token && !h.up_endpoint) {
    out += `<p class="hint">Google Play services is installed but hasn't returned a push
      token yet. On GrapheneOS, sandboxed Play needs <b>unrestricted</b> battery use
      (Settings → Apps → Google Play services → Battery) before its wake-ups are
      reliable. Sona never needs a Google account, and the wake-ups carry no content.</p>`;
  }
  out += `<p class="hint">Nothing can reach this phone while Sona is <b>force-stopped</b>,
    while its profile is <b>paused</b>, or before the first unlock after a reboot. Those
    are OS guarantees, not Sona faults — reopening Sona restores delivery.</p>`;
  return out;
}

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
    // Without the grant the ring still arrives, and since the lock-screen notification
    // carries its own Answer and Decline it is still answerable — what is lost is the
    // call screen opening by itself, which is the difference between a phone ringing and
    // a phone notifying. Say that, rather than implying calls are broken.
    checks.push([h.full_screen_intent,
      'Calls open a full-screen call screen over the lock screen',
      'Calls can only arrive as a notification — allow full-screen for a real call screen', 2]);
    checks.push([!h.messages_channel_muted && !h.calls_channel_muted,
      'Message and call sounds are on',
      'A notification channel is muted in system settings', 1]);
    // The push fallback, judged by what the RELAY can actually reach — an endpoint
    // registered for this device, not a transport that merely exists on the phone.
    // Only a check in the modes that depend on it: connection mode has no fallback by
    // design, and calling that an issue would nag every de-Googled user (the hint
    // below still states it, because §9 forbids silently implying push coverage).
    if (d.mode !== 'c') {
      checks.push([d.push_registered,
        h.up_endpoint ? 'Push fallback ready (UnifiedPush)' : 'Push fallback ready',
        d.mode === 'p' ? 'Push fallback not configured — nothing can wake this phone'
          : 'Push fallback not configured — delivery relies on the connection alone',
        undefined]);
    }
    // E-2 — "can an incoming call reach this phone right now?", answered as one line.
    //
    // Every ingredient was already on this panel, spread across four rows the user has to
    // assemble themselves. The state that prompted this had them all green and still could
    // not be woken: locked, no socket, and the foreground service stopped, so the process
    // was reclaimed and a call produced nothing at all — no ring, no notification, no
    // missed call, while the caller rang out believing the phone was ringing.
    //
    // Deliberately phrased about CALLS. Messages waiting for an unlock is normal and
    // expected; a call that cannot arrive is not, and the two must not read as one thing.
    if (d.mode !== 'c') {
      const wakeable = d.push_registered && h.notifications_enabled && h.network !== false;
      checks.push([wakeable,
        'Incoming calls can reach this phone, even locked',
        'Incoming calls cannot reach this phone right now', 1]);
    }
  }
  const issues = checks.filter((c) => !c[0]).length;
  const connPhrase =
    d.conn === 'connected' ? 'Connected to your relay right now.' :
    d.conn === 'reconnecting' ? 'Reconnecting to your relay…' :
    d.conn === 'locked' ? 'Locked — delivery resumes when you unlock Sona.' :
    // Locked, but still wakeable: messages wait for the unlock, calls do not. Said plainly
    // because the difference between this and 'locked' is whether the phone rings (E-2).
    d.conn === 'locked_wakeable'
      ? 'Locked — messages resume when you unlock Sona. Incoming calls still ring.' :
    d.mode === 'p' ? 'Push mode — this phone wakes up when a message arrives.' :
    'Delivery is off.';
  // A wakeable lock is not a problem to flag: it is the state this device is *meant* to be
  // in while the vault is closed, and the phone still rings.
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
    out += grapheneHints(d, h);
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
