// ═══════════════════════════════════════════════════════════════════════════════
// In-app updates (settings row) — split from 60-settings.js (no-monolith)
// ═══════════════════════════════════════════════════════════════════════════════
// ── Updates: manual check against the operator's signed channel (update.rs).
// Everything is verified device-side (minisign) before any install action; the
// backend re-fetches the manifest at install time so this UI holds no authority.
let updateBusy = false;
// Blocking progress modal fed by backend `update_state` events (checking →
// downloading N% → verifying → installing). Present only while an install runs.
function updateProgressModal(version) {
  openModal(
    `<h3>Updating to ${escapeHtml(version)}</h3>
     <div class="spinner" style="margin:14px auto"></div>
     <p id="up-stage" style="text-align:center">starting…</p>`);
}
listen('update_state', (ev) => {
  const el = $('#up-stage');
  if (!el) return;
  const p = ev.payload || {};
  const label = { downloading: 'Downloading', verifying: 'Verifying signature', installing: 'Installing' }[p.stage] || p.stage;
  el.textContent = p.pct != null ? `${label}… ${p.pct}%` : `${label}…`;
});

// After the "install unknown apps" bounce the user lands back here — resume the
// update automatically instead of making them find the button again.
let updateResumePending = false;
function maybeResumeUpdate() {
  if (!updateResumePending || document.hidden) return;
  updateResumePending = false;
  runUpdateInstall(lastUpdateInfo);
}
window.addEventListener('focus', maybeResumeUpdate);
document.addEventListener('visibilitychange', maybeResumeUpdate);

let lastUpdateInfo = null;
async function runUpdateInstall(info) {
  if (updateBusy || !info) return;
  updateBusy = true;
  const st = $('#se-update-state');
  updateProgressModal(info.latest);
  try {
    const msg = await invoke('update_install');
    closeModal();
    st.textContent = 'done';
    toast(msg, 'ok');
  } catch (e) {
    closeModal();
    if (String(e).includes('needs-install-permission')) {
      st.textContent = 'permission needed';
      if (await confirmModal('Allow app updates?',
        'Android needs a one-time permission for Sona to install its own updates. Turn on "Allow from this source" on the next screen, then come back — the update continues by itself.',
        'Open settings')) {
        updateResumePending = true;
        invoke('update_open_install_settings').catch(() => {});
      }
    } else {
      st.textContent = 'failed';
      toast(say(e), 'err');
    }
  } finally { updateBusy = false; }
}

$('#se-update').onclick = async () => {
  if (updateBusy) return;
  updateBusy = true;
  const st = $('#se-update-state');
  try {
    st.textContent = 'checking…';
    const info = await invoke('update_check');
    if (!info.configured) { st.textContent = 'no update channel in this build'; return; }
    if (!info.available) { st.textContent = `up to date (v${info.current})`; return; }
    st.textContent = `v${info.latest} available`;
    const how = info.method === 'apt'
      ? 'Sona updates through your system package manager — you may be asked for your password. Your messages and settings are untouched.'
      : info.method === 'installer'
        ? 'Sona closes for a few seconds while the update applies, then reopens by itself. Your messages and settings are untouched.'
        : "The verified update is handed to Android's installer. Your messages and settings are untouched.";
    const notes = info.notes ? ` ${info.notes}` : '';
    if (!(await confirmModal(`Update to ${info.latest}?`, `You have ${info.current}. ${how}${notes}`, 'Update'))) return;
    lastUpdateInfo = info;
    updateBusy = false;
    return runUpdateInstall(info);
  } catch (e) {
    st.textContent = 'failed';
    toast(say(e), 'err');
  } finally { updateBusy = false; }
};
