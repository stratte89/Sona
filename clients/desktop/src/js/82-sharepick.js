// ═══════════════════════════════════════════════════════════════════════════════
// Share picker — which screen, or which window.
//
// Desktop only: nothing leaves the machine until a source is picked here. Android
// keeps its old behaviour, where the share is the whole device and the system's own
// MediaProjection dialog is the consent step, so its share button goes straight
// through to `setScreenShare`.
//
// Owns `#call-share` (the control-bar button), because on desktop starting a share IS
// this flow. `setScreenShare` in 80-calls.js stays the only writer of the track.
// ═══════════════════════════════════════════════════════════════════════════════
const sharePick = { open: false, tab: 'screen', sources: [], sel: null };

function spRender() {
  const rows = sharePick.sources.filter((s) => s.kind === sharePick.tab);
  const grid = $('#sp-grid');
  // Names and details are window titles — arbitrary text chosen by whatever program
  // opened the window — so they are escaped, and the preview is only emitted when it
  // is the inline PNG the backend is supposed to have produced.
  const thumb = (s) =>
    /^data:image\/png;base64,[A-Za-z0-9+/=]*$/.test(s.thumb || '')
      ? `<img src="${s.thumb}" alt="" draggable="false">`
      : '<span class="sp-noimg">No preview</span>';
  const picked = (s) => sharePick.sel && sharePick.sel.kind === s.kind && sharePick.sel.id === s.id;
  grid.innerHTML = rows
    .map(
      (s) => `<button class="sp-item${picked(s) ? ' sel' : ''}" role="radio"
          aria-checked="${picked(s)}" data-kind="${s.kind}" data-id="${s.id}">
        <span class="sp-thumb">${thumb(s)}<span class="sp-tick" aria-hidden="true"></span></span>
        <span class="sp-name">${escapeHtml(s.name)}</span>
        <span class="sp-detail">${escapeHtml(s.detail || '')}</span>
      </button>`
    )
    .join('');
  const empty = $('#sp-empty');
  empty.hidden = rows.length > 0;
  empty.textContent = sharePick.tab === 'window'
    ? 'No open application windows to share.'
    : 'No screens found.';
  grid.querySelectorAll('.sp-item').forEach((b) => {
    b.onclick = () => {
      sharePick.sel = { kind: b.dataset.kind, id: Number(b.dataset.id) };
      spRender();
    };
  });
  // Name the pick on the button. A selection made on one tab stays made when you look
  // at the other — losing it would be worse — but then nothing on screen is
  // highlighted, and an enabled "Share" with no visible selection is a trap. Saying
  // "Share Screen 2" removes the doubt without throwing the choice away.
  const sel = sharePick.sel && sharePick.sources.find((s) => picked(s));
  $('#sp-go').textContent = sel ? `Share ${sel.name}` : 'Share';
  $('#sp-go').disabled = !sel;
  for (const t of $$('.sp-tab')) {
    const on = t.dataset.tab === sharePick.tab;
    t.classList.toggle('on', on);
    t.setAttribute('aria-selected', on ? 'true' : 'false');
  }
}

function closeSharePick() {
  sharePick.open = false;
  sharePick.sources = [];
  sharePick.sel = null;
  $('#sharepick').hidden = true;
  $('#sp-grid').innerHTML = ''; // drop the preview images; they are megabytes of data URLs
}

async function openSharePick() {
  sharePick.open = true;
  sharePick.tab = 'screen';
  sharePick.sel = null;
  sharePick.sources = [];
  $('#sharepick').hidden = false;
  $('#sp-grid').innerHTML = '';
  $('#sp-empty').hidden = false;
  $('#sp-empty').innerHTML = '<span class="spinner-sm"></span> Looking for screens and windows…';
  $('#sp-go').textContent = 'Share'; // clear the last session's "Share <name>"
  $('#sp-go').disabled = true;
  // The checkbox starts wherever the call-settings switch is, and moves it if changed.
  await refreshScreenAudioAvail();
  $('#sp-audio').hidden = !callUi.screenAudioAvail;
  setShareAudioPref(shareAudioPref());
  // Focus inside the dialog so Escape reaches its handler (and screen readers land in
  // it) before the enumeration — which takes a moment — finishes.
  $('.sp-card').focus();
  let list;
  try {
    list = await invoke('screen_sources');
  } catch (e) {
    closeSharePick();
    toast(say(e), 'err');
    return;
  }
  if (!sharePick.open) return; // cancelled while we were enumerating
  sharePick.sources = (list && list.sources) || [];
  // Preselect the primary screen so the obvious choice is one click, not two.
  const first = sharePick.sources.find((s) => s.kind === 'screen' && s.primary)
    || sharePick.sources.find((s) => s.kind === 'screen')
    || sharePick.sources[0];
  if (first) sharePick.sel = { kind: first.kind, id: first.id };
  spRender();
}

$$('.sp-tab').forEach((t) => {
  t.onclick = () => { sharePick.tab = t.dataset.tab; spRender(); };
});
$('#sp-x').onclick = closeSharePick;
$('#sharepick').addEventListener('click', (e) => {
  if (e.target === $('#sharepick')) closeSharePick();
});
$('#sharepick').addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { e.preventDefault(); closeSharePick(); }
});
$('#sp-audio').onclick = () => setShareAudioPref(!shareAudioPref());
$('#sp-go').onclick = async () => {
  const source = sharePick.sel;
  if (!source) return;
  closeSharePick();
  // The call can end (or the share can be started elsewhere) while the picker is up.
  if (callUi.mode !== 'connected' || callUi.screenOn) return;
  await setScreenShare(true, source);
};

$('#call-share').onclick = async () => {
  if (callUi.screenOn) { await setScreenShare(false); return; }
  if (IS_ANDROID) { await setScreenShare(true); return; }
  await openSharePick();
};
