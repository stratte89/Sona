// Call settings (Android): how this device answers, and what it remembers about calls.
//
// Both rows are phone-only. A desktop is unlocked whenever it is usable, so "unlock to
// answer" has nothing to gate; and the call-control store these records live in is the
// Android locked-delivery subsystem (internal/CALL_PLAN.md §6, §8). `renderPrivacy` in
// 60-settings.js paints their state; the handlers live here.

$('#se-callunlock').onclick = async () => {
  const on = !!(cur.privacy && cur.privacy.require_unlock_to_answer);
  if (on) {
    // Turning it off means anyone holding the phone can answer. Say so, and make the
    // device verify it is you before it happens.
    const card = openModal(`<h3>Unlock to answer calls</h3>
      <p>With this on, answering a call from the lock screen costs a check that it is you —
      your fingerprint or screen lock, or Sona's own password if this phone has neither — so
      a call is never answered by whoever is holding your phone. Answering from inside Sona,
      on an unlocked phone, is unaffected. Turning it off lets this device answer straight
      from the lock screen.</p>
      <div class="modal-list"><button data-v="off">Turn off</button></div>
      <button class="btn btn-ghost btn-sm" id="mo-no">Keep it on</button>`);
    card.querySelector('[data-v]').onclick = async () => {
      closeModal();
      try {
        await invoke('os_presence_check');
        await invoke('set_privacy', { requireUnlockToAnswer: false });
        await renderPrivacy();
      } catch (e) { toast(say(e), 'err'); }
    };
    card.querySelector('#mo-no').onclick = closeModal;
    return;
  }
  try { await invoke('set_privacy', { requireUnlockToAnswer: true }); await renderPrivacy(); }
  catch (e) { toast(say(e), 'err'); }
};

$('#se-callret').onclick = () => {
  const cur4 = (cur.privacy && cur.privacy.call_retention_secs) ?? 604800;
  const opts = [[0, 'Until the call ends'], [86400, '24 hours'], [604800, '7 days'], [2592000, '30 days']];
  const card = openModal(
    `<h3>Keep call records</h3><p>How long this phone keeps its own call-control records —
      the notes that let it stop ringing for a call you answered elsewhere. No call audio is
      ever stored, and the call history in your chats is not affected.</p>
     <div class="modal-list">${opts.map(([v, l]) => `<button data-v="${v}" ${v === cur4 ? 'class="sel"' : ''}>${l}${v === cur4 ? '<em>current</em>' : ''}</button>`).join('')}</div>
     <button class="btn btn-ghost btn-sm" id="mo-no">Cancel</button>`);
  card.querySelectorAll('[data-v]').forEach((b) => {
    b.onclick = async () => {
      closeModal();
      try { await invoke('set_privacy', { callRetentionSecs: Number(b.dataset.v) }); await renderPrivacy(); }
      catch (e) { toast(say(e), 'err'); }
    };
  });
  card.querySelector('#mo-no').onclick = closeModal;
};
