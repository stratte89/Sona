// ── App-lock rows: reflect security_status into the settings page ────────────────
async function renderAppLock() {
  await refreshSec();
  if (!sec) return;
  $('#se-pin-state').textContent = sec.pin_set ? 'on' : 'off';
  const bioRow = $('#se-bio');
  bioRow.hidden = !(sec.bio_available || sec.bio_enabled);
  $('#se-bio-state').textContent = sec.bio_enabled ? 'on' : 'off';
  $('#se-auto-state').textContent = sec.auto_unlock ? 'on' : 'off';
  $('#se-locktimer-state').textContent = sec.lock_after_secs ? tlabel(sec.lock_after_secs) : 'off';
  $('#se-reminder-state').textContent = sec.pin_reminder_every ? `every ${sec.pin_reminder_every} opens` : 'off';
}

// Ask for the vault password (gates every quick-unlock enable). Resolves the string or
// null on cancel.
function passwordPrompt(title, desc) {
  return new Promise((resolve) => {
    const card = openModal(
      `<h3>${escapeHtml(title)}</h3><p>${escapeHtml(desc)}</p>
       <input id="mo-pw" type="password" autocomplete="current-password" placeholder="password" />
       <button class="btn" id="mo-ok">Continue</button>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    const pw = card.querySelector('#mo-pw');
    setTimeout(() => pw.focus(), 100);
    const done = (v) => { closeModal(); resolve(v); };
    card.querySelector('#mo-ok').onclick = () => done(pw.value || null);
    pw.addEventListener('keydown', (e) => { if (e.key === 'Enter') done(pw.value || null); });
    card.querySelector('#mo-no').onclick = () => done(null);
  });
}

// Authorize a quick-unlock enable with whichever knowledge factor the user prefers: the
// vault password, or the unlock PIN when one is set (the backend accepts either — see
// `authorize_quick_enable`). The PIN is the default when it exists: on a phone it is what
// people actually type, and typing a long password to turn on fingerprint unlock is the
// friction this whole feature exists to remove. Resolves { password } | { pin } | null.
function unlockAuthPrompt(title, desc) {
  const hasPin = !!(sec && sec.pin_set);
  return new Promise((resolve) => {
    const card = openModal(
      `<h3>${escapeHtml(title)}</h3><p>${escapeHtml(desc)}</p>
       <div id="mo-pin-area"${hasPin ? '' : ' hidden'}>
         <input id="mo-pin" type="password" inputmode="numeric" maxlength="8" autocomplete="off" placeholder="unlock PIN" />
       </div>
       <div id="mo-pw-area"${hasPin ? ' hidden' : ''}>
         <input id="mo-pw" type="password" autocomplete="current-password" placeholder="password" />
       </div>
       ${hasPin ? '<button class="btn btn-ghost btn-sm" id="mo-swap">Use password instead</button>' : ''}
       <button class="btn" id="mo-ok">Continue</button>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    const pinArea = card.querySelector('#mo-pin-area');
    const pwArea = card.querySelector('#mo-pw-area');
    const pinEl = card.querySelector('#mo-pin');
    const pwEl = card.querySelector('#mo-pw');
    const swap = card.querySelector('#mo-swap');
    const usingPin = () => !pinArea.hidden;
    setTimeout(() => (usingPin() ? pinEl : pwEl).focus(), 100);
    const done = (v) => { closeModal(); resolve(v); };
    const submit = () => {
      if (usingPin()) return pinEl.value ? done({ pin: pinEl.value }) : null;
      return pwEl.value ? done({ password: pwEl.value }) : null;
    };
    if (swap) {
      swap.onclick = () => {
        pinArea.hidden = !pinArea.hidden;
        pwArea.hidden = !pwArea.hidden;
        swap.textContent = usingPin() ? 'Use password instead' : 'Use PIN instead';
        (usingPin() ? pinEl : pwEl).focus();
      };
    }
    for (const el of [pinEl, pwEl]) {
      el.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
    }
    card.querySelector('#mo-ok').onclick = submit;
    card.querySelector('#mo-no').onclick = () => done(null);
  });
}

// Set / change / remove the unlock PIN.
$('#se-pin').onclick = async () => {
  await refreshSec();
  if (!sec) return;
  if (!sec.device_key_available) {
    return toast('No OS key store on this device — PIN unlock unavailable', 'err');
  }
  if (!sec.pin_set) return setPinModal();
  const card = openModal(
    `<h3>Unlock PIN</h3>
     <div class="modal-list">
       <button id="mo-change">${icon('edit')}Change PIN</button>
       <button id="mo-remove">${icon('trash')}Remove PIN</button>
     </div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelector('#mo-change').onclick = () => { closeModal(); setPinModal(); };
  card.querySelector('#mo-remove').onclick = async () => {
    closeModal();
    try { await invoke('disable_pin'); toast('PIN removed', 'ok'); renderAppLock(); }
    catch (e) { toast(say(e), 'err'); }
  };
  card.querySelector('#mo-no').onclick = closeModal;
};

function setPinModal() {
  const card = openModal(
    `<h3>Set unlock PIN</h3>
     <p>4–8 characters — digits or anything you can type. ${sec.ceremony_min_pin_len}+
        needed to authorize username/password changes. Your password is required to
        set it.</p>
     <input id="mo-pw" type="password" autocomplete="current-password" placeholder="current password" />
     <input id="mo-pin1" type="password" inputmode="numeric" maxlength="8" autocomplete="off" placeholder="new PIN" />
     <input id="mo-pin2" type="password" inputmode="numeric" maxlength="8" autocomplete="off" placeholder="repeat PIN" />
     <p class="hint" id="mo-pin-hint"></p>
     <button class="btn" id="mo-ok">Set PIN</button>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  const hint = card.querySelector('#mo-pin-hint');
  card.querySelector('#mo-pin1').addEventListener('input', async (e) => {
    const pin = e.target.value;
    if (!pin) { hint.textContent = ''; return; }
    try {
      const r = await invoke('pin_strength', { pin });
      hint.textContent = r.acceptable
        ? (r.ceremony_grade ? 'Good — long enough for account changes too.' : 'OK for unlock; 6+ characters to authorize account changes.')
        : 'Needs: ' + r.problems.join(', ');
    } catch (_) {}
  });
  card.querySelector('#mo-ok').onclick = async () => {
    const password = card.querySelector('#mo-pw').value;
    const p1 = card.querySelector('#mo-pin1').value;
    const p2 = card.querySelector('#mo-pin2').value;
    if (p1 !== p2) return toast('PINs do not match', 'err');
    try {
      await invoke('set_pin', { password, pin: p1 });
      closeModal();
      toast('PIN set', 'ok');
      renderAppLock();
    } catch (e) { toast(say(e), 'err'); }
  };
  card.querySelector('#mo-no').onclick = closeModal;
}

// Fingerprint unlock (Android). Enabling prompts for the password, then a fingerprint
// (the Keystore wrap itself is auth-gated).
$('#se-bio').onclick = async () => {
  await refreshSec();
  if (!sec) return;
  if (sec.bio_enabled) {
    try { await invoke('set_bio_unlock', { password: null, pin: null, enable: false }); toast('Fingerprint unlock off', 'ok'); }
    catch (e) { toast(say(e), 'err'); }
    return renderAppLock();
  }
  // Mutually exclusive with auto-unlock (the backend enforces it too).
  if (sec.auto_unlock) return toast('Turn off auto-unlock first — only one of the two can be on', 'err');
  const auth = await unlockAuthPrompt('Enable fingerprint unlock',
    'Your vault key gets wrapped by a key inside the Android Keystore that only a fingerprint can use. A new enrolled fingerprint voids it.');
  if (!auth) return;
  try {
    await invoke('set_bio_unlock', { password: auth.password || null, pin: auth.pin || null, enable: true });
    toast('Fingerprint unlock on', 'ok');
  } catch (e) { toast(say(e), 'err'); }
  renderAppLock();
};

// Auto-unlock at start (no prompt at all — device possession is the gate).
$('#se-auto').onclick = async () => {
  await refreshSec();
  if (!sec) return;
  if (sec.auto_unlock) {
    try { await invoke('set_auto_unlock', { password: null, pin: null, enable: false }); toast('Auto-unlock off', 'ok'); }
    catch (e) { toast(say(e), 'err'); }
    return renderAppLock();
  }
  if (!sec.device_key_available) {
    return toast('No OS key store on this device — auto-unlock unavailable', 'err');
  }
  // Mutually exclusive with fingerprint unlock (the backend enforces it too).
  if (sec.bio_enabled) return toast('Turn off fingerprint unlock first — only one of the two can be on', 'err');
  const auth = await unlockAuthPrompt('Enable auto-unlock',
    'Sona opens without any prompt on this device. Anyone who can use your unlocked device/session can read your chats — the sealed vault still protects a stolen disk or backup.');
  if (!auth) return;
  try {
    await invoke('set_auto_unlock', { password: auth.password || null, pin: auth.pin || null, enable: true });
    toast('Auto-unlock on', 'ok');
  } catch (e) { toast(say(e), 'err'); }
  renderAppLock();
};

// Idle auto-lock timer.
$('#se-locktimer').onclick = () => {
  const opts = [['Off', null], ['1 minute', 60], ['5 minutes', 300], ['15 minutes', 900], ['1 hour', 3600]];
  const card = openModal(
    `<h3>Lock when idle</h3><p>After this long with no input, Sona locks itself and the
       keys leave memory.</p>
     <div class="modal-list">${opts.map(([l], i) => `<button data-i="${i}">${icon('clock')}${l}</button>`).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-i]').forEach((b) => {
    b.onclick = async () => {
      closeModal();
      try {
        await invoke('set_lock_after', { secs: opts[Number(b.dataset.i)][1] });
        lastActivity = Date.now();
        renderAppLock();
      } catch (e) { toast(say(e), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
};

// PIN reminder cadence.
$('#se-reminder').onclick = () => {
  const opts = [['Off', null], ['Every 5th open', 5], ['Every 10th open', 10], ['Every 25th open', 25]];
  const card = openModal(
    `<h3>PIN reminders</h3><p>Sona asks for your PIN now and then so you don't forget it
       while quick unlock does the daily work.</p>
     <div class="modal-list">${opts.map(([l], i) => `<button data-i="${i}">${icon('bell')}${l}</button>`).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-i]').forEach((b) => {
    b.onclick = async () => {
      closeModal();
      try { await invoke('set_pin_reminder', { every: opts[Number(b.dataset.i)][1] }); renderAppLock(); }
      catch (e) { toast(say(e), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
};

// ── Change username / password, delete account:
//    password → OS check (Android) → PIN → final value/confirmation ──
$('#se-chuser').onclick = () => ceremonyWizard('username');
$('#se-chpass').onclick = () => ceremonyWizard('password');
$('#se-delacct').onclick = () => ceremonyWizard('delete');

async function ceremonyWizard(kind) {
  await refreshSec();
  if (!sec) return toast('Security status unavailable', 'err');
  if (!sec.pin_set) {
    return toast(`Set an unlock PIN (${sec.ceremony_min_pin_len}+ characters) first — Settings → App lock`, 'err');
  }
  const what = kind === 'username' ? 'username' : 'password';
  const title = kind === 'delete' ? 'Delete account' : `Change ${escapeHtml(what)}`;
  const state = { password: null, pin: null };

  // Deletion opens with the plain-words consequences, before any credential is asked.
  if (kind === 'delete') {
    const ok = await new Promise((resolve) => {
      const card = openModal(
        `<h3>Delete your account?</h3>
         <p>This is permanent. Here is exactly what happens:</p>
         <ul class="del-list">
           <li>The relay forgets you: your mailboxes, queued messages, and push
               registrations are erased.</li>
           <li>Your other devices are unlinked and stop working immediately.</li>
           <li>Your username is released — after the 7-day grace period anyone can
               claim it.</li>
           <li>This device is wiped: keys, chats, and settings. There is no recovery —
               nobody, including the relay, can restore any of it.</li>
           <li>Your contacts are <em>not</em> notified; your messages on
               <em>their</em> devices stay with them.</li>
         </ul>
         <button class="btn btn-danger" id="mo-ok">Continue — start the ceremony</button>
         <button class="btn btn-ghost btn-sm" id="mo-no">Keep my account</button>`);
      card.querySelector('#mo-ok').onclick = () => { closeModal(); resolve(true); };
      card.querySelector('#mo-no').onclick = () => { closeModal(); resolve(false); };
    });
    if (!ok) return;
  }

  // Step 1 — current password.
  state.password = await passwordPrompt(`${title} — step 1`,
    'First, your current password.');
  if (!state.password) return;
  try { await invoke('verify_password', { password: state.password }); }
  catch (e) { return toast(say(e), 'err'); }

  // Step 2 — OS presence check (fingerprint → device credential → skipped when the
  // device has neither). Desktop builds skip it entirely.
  if (sec.os_auth !== 'none') {
    const ok = await new Promise((resolve) => {
      const card = openModal(
        `<h3>${title} — step 2</h3>
         <p>${sec.os_auth === 'biometric'
            ? 'Confirm with your fingerprint.'
            : 'Confirm with your device PIN/pattern/password.'}</p>
         <button class="btn" id="mo-ok">Verify with device</button>
         <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
      card.querySelector('#mo-ok').onclick = async () => {
        try { await invoke('os_presence_check'); closeModal(); resolve(true); }
        catch (e) { toast(say(e), 'err'); resolve(false); closeModal(); }
      };
      card.querySelector('#mo-no').onclick = () => { closeModal(); resolve(false); };
    });
    if (!ok) return;
  } else {
    // Still stamp the (auto-passing) presence step so the backend gate is satisfied.
    try { await invoke('os_presence_check'); } catch (_) {}
  }

  // Step 3 — the app PIN.
  state.pin = await new Promise((resolve) => {
    const card = openModal(
      `<h3>${title} — step 3</h3>
       <p>Your Sona PIN (${sec.ceremony_min_pin_len}+ characters).</p>
       <input id="mo-pin" type="password" inputmode="numeric" maxlength="8" autocomplete="off" placeholder="PIN" />
       <button class="btn" id="mo-ok">Continue</button>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    const pinEl = card.querySelector('#mo-pin');
    setTimeout(() => pinEl.focus(), 100);
    const done = (v) => { closeModal(); resolve(v); };
    card.querySelector('#mo-ok').onclick = () => done(pinEl.value || null);
    pinEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') done(pinEl.value || null); });
    card.querySelector('#mo-no').onclick = () => done(null);
  });
  if (!state.pin) return;

  // Step 4 (delete) — type the username, then the one red button. The backend
  // re-verifies the whole chain (password, presence, PIN, typed name) atomically.
  if (kind === 'delete') {
    let me = '';
    try { me = (await invoke('app_status')).account_id || ''; } catch (_) {}
    const card = openModal(
      `<h3>Delete account — final step</h3>
       <p>Type your username <b class="mono">${escapeHtml(me)}</b> to confirm. This is
          the point of no return.</p>
       <input id="mo-confirm" type="text" autocomplete="off" spellcheck="false" autocapitalize="none" placeholder="your username" />
       <button class="btn btn-danger" id="mo-ok" disabled>Delete my account forever</button>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    const confirmEl = card.querySelector('#mo-confirm');
    const okBtn = card.querySelector('#mo-ok');
    confirmEl.addEventListener('input', () => { okBtn.disabled = confirmEl.value.trim() !== me; });
    card.querySelector('#mo-no').onclick = closeModal;
    okBtn.onclick = async () => {
      busy(okBtn, true, 'Deleting…');
      try {
        const notes = await invoke('delete_account', {
          currentPassword: state.password, pin: state.pin,
          confirmUsername: confirmEl.value.trim(),
        });
        closeModal();
        // Everything account-shaped on this device is gone — reset the UI to a
        // fresh start on the same relay.
        myName = '';
        lastConvs = [];
        cur.peer = null;
        toast(notes ? `Account deleted (${notes})` : 'Account deleted', 'ok');
        show('create');
      } catch (e) { busy(okBtn, false); toast(say(e), 'err'); }
    };
    return;
  }

  // Step 4 — the new value, then the backend re-verifies the whole chain atomically.
  if (kind === 'username') {
    const card = openModal(
      `<h3>New username</h3>
       <p>Your keys and safety numbers stay the same. Contacts are told over the
          encrypted session; the old name's mailbox keeps being drained so nothing in
          flight is lost. The old name stays visible in the public transparency log.</p>
       <input id="mo-new" type="text" autocomplete="off" spellcheck="false" autocapitalize="none" placeholder="new username" />
       <button class="btn" id="mo-ok">Change username</button>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    card.querySelector('#mo-no').onclick = closeModal;
    card.querySelector('#mo-ok').onclick = async () => {
      const newUsername = card.querySelector('#mo-new').value.trim();
      if (!newUsername) return;
      const btn = card.querySelector('#mo-ok');
      busy(btn, true, 'Claiming…');
      const run = async (confirmUnlink) => invoke('change_username', {
        currentPassword: state.password, pin: state.pin, newUsername, confirmUnlink,
      });
      try {
        const result = await run(false);
        closeModal();
        toast('Username changed: ' + result, 'ok');
        myName = result;
        openSettings();
      } catch (e) {
        const m = /^confirm_unlink:(\d+)$/.exec(String(e));
        if (!m) { busy(btn, false); return toast(say(e), 'err'); }
        // Linked devices exist: renaming unlinks them first. Explicit, count-aware
        // consent before anything is touched.
        closeModal();
        const n = Number(m[1]);
        const card2 = openModal(
          `<h3>Unlink ${n} device${n === 1 ? '' : 's'}?</h3>
           <p>Changing your username unlinks your other ${n === 1 ? 'device' : `${n} devices`} first.
              ${n === 1 ? 'It' : 'They'} will show the unlinked screen and must be relinked by QR
              afterwards — chat history transfers again at relink. If claiming the new name then
              fails, the ${n === 1 ? 'device stays' : 'devices stay'} unlinked.</p>
           <button class="btn btn-danger" id="mo-ok">Unlink and change username</button>
           <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
        card2.querySelector('#mo-no').onclick = closeModal;
        card2.querySelector('#mo-ok').onclick = async () => {
          const btn2 = card2.querySelector('#mo-ok');
          busy(btn2, true, 'Unlinking…');
          try {
            const result = await run(true);
            closeModal();
            toast('Username changed: ' + result, 'ok');
        myName = result;
            openSettings();
          } catch (e2) { busy(btn2, false); toast(say(e2), 'err'); }
        };
      }
    };
  } else {
    const card = openModal(
      `<h3>New password</h3>
       <p>The vault is re-sealed under the new password. PIN and auto-unlock follow it
          automatically; fingerprint unlock must be re-enabled afterwards.</p>
       <input id="mo-new" type="password" autocomplete="new-password" placeholder="new password (12+ chars, mixed)" />
       <p class="hint" id="mo-new-hint"></p>
       <button class="btn" id="mo-ok">Change password</button>
       <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
    const hint = card.querySelector('#mo-new-hint');
    card.querySelector('#mo-new').addEventListener('input', async (e) => {
      if (!e.target.value) { hint.textContent = ''; return; }
      try {
        const r = await invoke('password_strength', { password: e.target.value });
        hint.textContent = r.acceptable ? 'Strong enough.' : 'Needs: ' + r.problems.join(', ');
      } catch (_) {}
    });
    card.querySelector('#mo-no').onclick = closeModal;
    card.querySelector('#mo-ok').onclick = async () => {
      const newPassword = card.querySelector('#mo-new').value;
      if (!newPassword) return;
      const btn = card.querySelector('#mo-ok');
      busy(btn, true, 'Re-sealing…');
      try {
        const bioDropped = await invoke('change_password', {
          currentPassword: state.password, pin: state.pin, newPassword,
        });
        closeModal();
        toast(bioDropped
          ? 'Password changed — re-enable fingerprint unlock in Settings'
          : 'Password changed', 'ok');
        renderAppLock();
      } catch (e) { busy(btn, false); toast(say(e), 'err'); }
    };
  }
}
$('#se-audit').onclick = async () => {
  const res = $('#se-audit-res');
  res.textContent = 'checking…'; res.className = '';
  try {
    const r = await invoke('audit_own_key');
    if (r === 'ok') { res.textContent = 'binding intact'; res.className = 'ok'; }
    else if (r === 'not_registered') { res.textContent = 'not registered'; res.className = 'bad'; }
    else { res.textContent = 'ROGUE KEY!'; res.className = 'bad'; toast('A key was published under your name — do not trust this relay', 'err'); }
  } catch (e) { res.textContent = 'check failed'; res.className = 'bad'; toast(say(e), 'err'); }
};
$('#se-lock').onclick = () => doLock(false);

