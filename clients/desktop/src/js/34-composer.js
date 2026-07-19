// ═══════════════════════════════════════════════════════════════════════════════
// Signal-style composer chrome: the idle/composed state machine, the media
// selector sheet, the in-app camera, and the emoji/GIF panel that docks under
// the composer where the keyboard was.
//
// Idle:      [🙂 | message… | 📷 🎤]  (＋)   — ＋ opens the media selector
// Composing: [🙂 | message…      ＋]  (➤)   — side tools collapse to an inline ＋,
//                                             the round button morphs into send.
// The swap is driven by ONE CSS class (`composed`) so the transition is pure CSS:
// instant, interruptible, no layout thrash.
// ═══════════════════════════════════════════════════════════════════════════════

function cmpComposed() {
  return !!($('#th-input').value.trim() || attachQueue.length);
}
function updateCmp() {
  $('#th-form').classList.toggle('composed', cmpComposed());
}
$('#th-input').addEventListener('input', updateCmp);

// Round main button: send when composing, media selector when idle.
$('#th-main').onclick = () => {
  if (cmpComposed()) $('#th-form').requestSubmit();
  else openMsel();
};
$('#th-plusinline').onclick = () => openMsel();

// ── Media selector: Gallery / File, off the "+" ─────────────────────────────────
function openMsel() {
  if (!cur.peer || cur.keyChanged || cur.left) return;
  const m = $('#msel');
  m.hidden = false;
  requestAnimationFrame(() => m.classList.add('open'));
}
function closeMsel() {
  const m = $('#msel');
  m.classList.remove('open');
  m.hidden = true;
}
$('#msel-backdrop').onclick = closeMsel;
// The one hidden <input type=file> serves both entries — the accept attr is set per
// use (Android turns image/video accept into the photo picker).
function pickFiles(accept) {
  const f = $('#th-file');
  if (accept) f.setAttribute('accept', accept);
  else f.removeAttribute('accept');
  f.click();
}
$('#ms-gallery').onclick = () => { closeMsel(); pickFiles('image/*,video/*'); };
$('#ms-file').onclick = () => { closeMsel(); pickFiles(null); };

// ── In-app camera: shoot → review → send ────────────────────────────────────────
// getUserMedia (same permission plumbing as the QR scanner) instead of a native
// camera intent: the frame never touches disk, and the photo rides the ordinary
// E2E attachment pipeline.
let camStream = null;
let camFacing = 'environment';
let camShot = null; // captured File awaiting review
async function openCamera() {
  if (!cur.peer || cur.keyChanged || cur.left) return;
  closeCmpPanel();
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: camFacing }, width: { ideal: 1920 }, height: { ideal: 1080 } },
      audio: false,
    });
  } catch (e) {
    return toast(e && (e.name === 'NotAllowedError' || e.name === 'SecurityError')
      ? 'Camera permission denied' : 'Camera unavailable', 'err');
  }
  camStream = stream;
  const video = $('#cam-video');
  video.srcObject = stream;
  // Mirror the front camera preview (what everyone expects to see).
  video.classList.toggle('mirror', camFacing === 'user');
  camReviewMode(false);
  $('#camui').hidden = false;
  try { await video.play(); } catch (_) {}
}
function camReviewMode(on) {
  $('#cam-video').hidden = on;
  $('#cam-still').hidden = !on;
  $('#cam-live').hidden = on;
  $('#cam-review').hidden = !on;
  if (!on) {
    const still = $('#cam-still');
    if (still.src) { URL.revokeObjectURL(still.src); still.removeAttribute('src'); }
    camShot = null;
  }
}
function closeCamera() {
  camReviewMode(false);
  $('#camui').hidden = true;
  $('#cam-video').srcObject = null;
  if (camStream) { camStream.getTracks().forEach((t) => t.stop()); camStream = null; }
}
$('#cam-close').onclick = closeCamera;
$('#cam-flip').onclick = async () => {
  camFacing = camFacing === 'environment' ? 'user' : 'environment';
  closeCamera();
  await openCamera();
};
$('#cam-shot').onclick = () => {
  const video = $('#cam-video');
  if (!video.videoWidth) return;
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext('2d');
  // Capture what the preview showed: the front camera is mirrored there too.
  if (camFacing === 'user') { ctx.translate(canvas.width, 0); ctx.scale(-1, 1); }
  ctx.drawImage(video, 0, 0);
  canvas.toBlob((blob) => {
    if (!blob) return toast('Capture failed', 'err');
    camShot = new File([blob], `photo-${Date.now()}.jpg`, { type: 'image/jpeg' });
    $('#cam-still').src = URL.createObjectURL(blob);
    camReviewMode(true);
  }, 'image/jpeg', 0.9);
};
$('#cam-retake').onclick = () => camReviewMode(false);
$('#cam-send').onclick = async () => {
  const f = camShot;
  camShot = null; // keep camReviewMode(false) inside closeCamera from clearing a sent file
  closeCamera();
  if (!f) return;
  const isGroup = cur.kind === 'group';
  const peer = cur.peer;
  if ((await sendOneFile({ file: f, name: f.name, isImage: true, thumb: null }, null)) === 'key_changed') return;
  if (cur.peer === peer) await (isGroup ? renderGroupThread(peer) : renderThread(peer));
  loadChats();
};
$('#th-camera').onclick = () => openCamera();
// No camera stack (old desktop webview): the button would be a dead end.
if (!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)) $('#th-camera').hidden = true;

// ── Emoji / GIF panel ───────────────────────────────────────────────────────────
// Docks under the composer (where the keyboard sits), Signal-style: the emoji
// button becomes a keyboard button while it's open, tapping the input swaps the
// panel back for the keyboard.
let cmpTab = 'emoji';
function cmpPanelOpen() { return !$('#cmp-panel').hidden; }
function openCmpPanel(tab) {
  if (!cur.peer || cur.keyChanged) return;
  const box = $('#th-thread');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  $('#th-input').blur(); // trade the keyboard for the panel
  $('#cpt-gif').hidden = !gifOk;
  $('#cmp-panel').hidden = false;
  $('#th-emoji').innerHTML = icon('keyboard');
  setCmpTab(tab || cmpTab || 'emoji');
  if (nearBottom) box.scrollTop = box.scrollHeight; // panel shrank the thread — keep the tail visible
}
function closeCmpPanel(focus) {
  if (!cmpPanelOpen()) return;
  $('#cmp-panel').hidden = true;
  closeEmojiPicker(); // returns the inline-mounted picker to its overlay home
  $('#th-emoji').innerHTML = icon('smile');
  if (focus) $('#th-input').focus();
}
$('#th-emoji').onclick = () => {
  if (cmpPanelOpen()) closeCmpPanel(true);
  else openCmpPanel('emoji');
};
// Tapping the input while the panel is up = "give me the keyboard back".
$('#th-input').addEventListener('focus', () => closeCmpPanel());

function setCmpTab(tab) {
  cmpTab = tab;
  $('#cpt-emoji').classList.toggle('sel', tab === 'emoji');
  $('#cpt-gif').classList.toggle('sel', tab === 'gif');
  $('#cpp-emoji').hidden = tab !== 'emoji';
  $('#cpp-gif').hidden = tab !== 'gif';
  if (tab === 'emoji') {
    openEmojiPicker({
      mount: $('#cpp-emoji'),
      sticky: true,
      onPick: (em) => {
        insertAtCaret($('#th-input'), em);
        if (!TOUCH_UI) $('#th-input').focus();
      },
    });
  } else {
    gifPaneShow();
  }
}
$('#cpt-emoji').onclick = () => setCmpTab('emoji');
$('#cpt-gif').onclick = () => setCmpTab('gif');

// ── GIF pane: trending as suggestions (relay pre-loads them), search on type ────
let gifTrendingCache = null; // slimmed results — one fetch per session, relay caches upstream
let gifPaneSeq = 0;
let gifQTimer = null;
const gifPreviewCache = new Map(); // url -> data-URL promise (bounded)
function gifPreviewData(url) {
  let p = gifPreviewCache.get(url);
  if (!p) {
    p = invoke('gif_preview', { url });
    p.catch(() => gifPreviewCache.delete(url)); // failed fetches may retry later
    if (gifPreviewCache.size > 150) gifPreviewCache.delete(gifPreviewCache.keys().next().value);
    gifPreviewCache.set(url, p);
  }
  return p;
}
async function gifPaneShow() {
  const grid = $('#cpg-grid');
  const query = $('#cpg-q').value.trim();
  const my = ++gifPaneSeq;
  let results;
  if (!query && gifTrendingCache) {
    results = gifTrendingCache;
  } else {
    grid.innerHTML = '<p class="hint cmp-gifhint"><span class="spinner-sm"></span> loading…</p>';
    try {
      const res = await (query
        ? invoke('gif_search', { query, pos: null })
        : invoke('gif_trending'));
      results = (res && res.results) || [];
      if (!query) gifTrendingCache = results;
    } catch (e) {
      if (my === gifPaneSeq) {
        grid.innerHTML = `<p class="hint cmp-gifhint">${query ? 'Search failed: ' + escapeHtml(say(e)) : 'Type to search GIFs'}</p>`;
      }
      return;
    }
  }
  if (my !== gifPaneSeq) return; // superseded by newer keystrokes
  grid.innerHTML = '';
  if (!results.length) {
    grid.innerHTML = '<p class="hint cmp-gifhint">No results</p>';
    return;
  }
  for (const r of results) {
    const tile = document.createElement('button');
    tile.type = 'button';
    tile.className = 'gif-tile';
    if (r.width && r.height) tile.style.aspectRatio = `${r.width} / ${r.height}`;
    grid.appendChild(tile);
    tile.onclick = () => sendPickedGif(r.url);
    gifPreviewData(r.preview || r.url)
      .then((data) => { if (my === gifPaneSeq) tile.innerHTML = `<img src="${data}" alt="GIF" loading="lazy" />`; })
      .catch(() => tile.remove());
  }
}
$('#cpg-q').addEventListener('input', () => {
  clearTimeout(gifQTimer);
  gifQTimer = setTimeout(gifPaneShow, 400);
});
async function sendPickedGif(url) {
  const isGroup = cur.kind === 'group';
  const peer = cur.peer;
  closeCmpPanel();
  toast('Sending GIF…', '');
  try {
    await invoke('send_gif', {
      username: isGroup ? '' : cur.username,
      groupId: isGroup ? peer : null,
      url,
    });
    if (cur.peer === peer) await (isGroup ? renderGroupThread(peer) : renderThread(peer));
    loadChats();
  } catch (e) { toast('GIF failed: ' + say(e), 'err'); }
}
