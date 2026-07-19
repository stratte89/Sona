// ── GIFs: search through the relay's privacy proxy (the GIF provider never sees this
//    client's IP — not for search, not for previews, not for the send). ─────────────
let gifOk = false; // relay capability; probed at unlock, re-probed until it succeeds
let gifProbing = false;
// The probe is one HTTP GET. On Android a quick unlock (PIN/fingerprint/auto) lands
// here milliseconds after process start, before the network stack is ready — a single
// failed probe must not hide the GIF button for the whole session, so retry with
// backoff and re-probe on thread open until the capability is confirmed.
async function probeGif() {
  if (gifOk || gifProbing) return;
  gifProbing = true;
  try {
    for (let i = 0; i < 4 && !gifOk; i++) {
      if (i) await new Promise((r) => setTimeout(r, 2000 * i));
      try { gifOk = await invoke('gif_available'); } catch (_) { gifOk = false; }
    }
  } finally { gifProbing = false; }
  // The GIF surface is a tab inside the composer's emoji/GIF panel — a probe that
  // lands while the panel is already open reveals the tab in place.
  if (gifOk && cmpPanelOpen()) $('#cpt-gif').hidden = false;
}
$('#th-file').onchange = () => {
  const files = [...$('#th-file').files];
  $('#th-file').value = '';
  if (files.length && cur.username) enqueueFiles(files);
};

// Drag-and-drop onto the thread → enqueue, with a visible drop zone.
(() => {
  const zone = $('#th-thread');
  const overlay = $('#th-drop');
  let depth = 0;
  const show = () => { if (cur.peer && !cur.keyChanged && !cur.left) overlay.hidden = false; };
  const hide = () => { overlay.hidden = true; };
  zone.addEventListener('dragenter', (e) => { e.preventDefault(); depth++; show(); });
  zone.addEventListener('dragover', (e) => { e.preventDefault(); });
  zone.addEventListener('dragleave', (e) => { e.preventDefault(); if (--depth <= 0) { depth = 0; hide(); } });
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); depth = 0; hide();
    if (!cur.peer || cur.left) return;
    const files = [...(e.dataTransfer?.files || [])];
    if (files.length) enqueueFiles(files);
  });
})();

// Paste an image (or any file) from the clipboard → enqueue. This is also how
// keyboard GIF/sticker insertion arrives on Android: Chromium translates the IME's
// commitContent into a paste event carrying the image as a clipboard file.
//
// Two extraction paths, because webviews genuinely differ: Chromium delivers the
// image in the paste event itself (files/items); WebKitGTK (the Linux desktop
// webview) fires the paste event with NO file payload for images — there the async
// clipboard API works, and we're inside the paste gesture it requires.
function filesFromClipboardEvent(e) {
  const out = [...(e.clipboardData?.files || [])];
  if (!out.length) {
    for (const it of e.clipboardData?.items || []) {
      if (it.kind === 'file') {
        const f = it.getAsFile();
        if (f) out.push(f);
      }
    }
  }
  return out;
}
async function readClipboardImages() {
  try {
    const items = await navigator.clipboard.read();
    const out = [];
    for (const item of items) {
      const type = (item.types || []).find((t) => t.startsWith('image/'));
      if (!type) continue;
      const blob = await item.getType(type);
      const ext = type.split('/')[1].replace('+xml', '');
      out.push(new File([blob], `pasted.${ext}`, { type }));
    }
    return out;
  } catch (_) {
    return []; // unsupported or denied: the sync path already had its chance
  }
}
function acceptPastedFiles(files) {
  if (cur.keyChanged) { toast('Verify the new key first', 'err'); return; }
  if (cur.left) { toast("You're no longer in this group", 'err'); return; }
  enqueueFiles(files);
}
// Android tier-3: the WebView never exposes clipboard images to JS in a textarea
// (empty paste events, clipboard.read() denied), so ask the native side to read the
// system clipboard directly. Runs only from an explicit paste gesture.
async function nativeClipboardImage() {
  if (!IS_ANDROID) return [];
  try {
    const r = await invoke('clipboard_image');
    if (!r || !r.b64) return [];
    const bin = atob(r.b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return [new File([bytes], r.name || 'pasted.png', { type: r.mime || 'image/png' })];
  } catch (_) { return []; }
}
function handleClipboardPaste(e) {
  if (!cur.peer) return; // no thread open
  const files = filesFromClipboardEvent(e);
  if (files.length) {
    e.preventDefault();
    acceptPastedFiles(files);
    return;
  }
  // Nothing in the event: async fallbacks. No preventDefault — if the clipboard
  // turns out to be plain text, the default paste must still land.
  (async () => {
    let imgs = await readClipboardImages();
    if (!imgs.length) imgs = await nativeClipboardImage();
    if (!imgs.length) return;
    acceptPastedFiles(imgs);
    // Pasting an image-only clip can leave its content:// URI as text in the
    // composer (the paste menu coerces) — wipe that residue, keep real text.
    const inp = $('#th-input');
    if (/^content:\/\/\S*$/.test(inp.value.trim())) {
      inp.value = '';
      inp.style.height = 'auto';
    }
  })();
}
$('#th-input').addEventListener('paste', handleClipboardPaste);
// Desktop muscle memory: Ctrl+V with the thread (not the composer) focused still
// pastes the screenshot. Skip when the composer already handled it, and never steal
// pastes from other text fields (search, settings inputs…).
document.addEventListener('paste', (e) => {
  const t = e.target;
  if (t === $('#th-input') || (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA'))) return;
  const thread = document.querySelector('.screen[data-screen="thread"]');
  if (!thread || !thread.classList.contains('is-active')) return;
  handleClipboardPaste(e);
});

// ── Outgoing typing indicator (B): throttle to ~1 send / 4s while typing, plus an
// explicit stop on send/idle. Backend drops it entirely when the privacy toggle is off.
let typingSentAt = 0;
let typingStopTimer = null;
function sendTypingSignal(typing) {
  const peer = cur.peer, username = cur.username, kind = cur.kind;
  if (!peer || peer === NOTE_PEER) return; // notes have no audience
  if (kind === 'group') invoke('set_group_typing', { groupId: peer, typing }).catch(() => {});
  else invoke('set_typing', { username, peer, typing }).catch(() => {});
}
function onComposerActivity() {
  const now = Date.now();
  if (now - typingSentAt > 4000) { typingSentAt = now; sendTypingSignal(true); }
  clearTimeout(typingStopTimer);
  typingStopTimer = setTimeout(stopTyping, 5000);
}
function stopTyping() {
  clearTimeout(typingStopTimer);
  if (typingSentAt) { typingSentAt = 0; sendTypingSignal(false); }
}

// Composer.
const input = $('#th-input');
input.addEventListener('input', () => {
  input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 120) + 'px';
  if (input.value.trim()) onComposerActivity(); else stopTyping();
});
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('#th-form').requestSubmit(); }
});
$('#th-form').onsubmit = async (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text && !attachQueue.length) return;
  // Attachments queued? Send them (with this text as caption) instead of a plain message.
  if (attachQueue.length) { input.value = ''; input.style.height = 'auto'; stopTyping(); return sendQueue(text); }
  if (!text) return;
  input.value = ''; input.style.height = 'auto';
  updateCmp(); // programmatic clear fires no input event — reset to the idle chrome
  stopTyping();
  const rt = replyTo;
  clearReply();
  await sendTextMessage(text, rt);
};

// The text send itself (composer submit + failed-bubble Retry share it). On failure the
// message is parked as a red Retry/Discard bubble — a repaint can never eat it.
async function sendTextMessage(text, rt) {
  const peer = cur.peer;
  const sentFromKey = draftKey(); // failed entries file under the ORIGIN chat, not wherever the user is later
  const box = $('#th-thread');
  if (peer === NOTE_PEER) {
    // Note-to-self: the local record IS the send — failure here is a real bug, not
    // an offline relay, so no optimistic bubble theater.
    try {
      await invoke('send_note', { text, replyTo: rt || null });
      await renderThread(NOTE_PEER);
      loadChats();
    } catch (err) { toast('Note failed: ' + say(err), 'err'); }
    return;
  }
  if (cur.kind === 'group') {
    const optimistic = document.createElement('div');
    optimistic.className = 'bubble out';
    optimistic.innerHTML = `${escapeHtml(text)}<span class="t">${hhmm(Math.floor(Date.now() / 1000))}<i class="tick spin"></i></span>`;
    box.appendChild(optimistic);
    box.scrollTop = box.scrollHeight;
    try {
      await invoke('send_group_msg', { groupId: peer, text, replyTo: rt || null });
      if (cur.peer === peer) await renderGroupThread(peer);
      loadChats();
    } catch (err) {
      optimistic.remove();
      noteFailedSend({ kind: 'text', text, replyTo: rt || null }, sentFromKey);
      if (cur.peer === peer) await renderGroupThread(peer);
      toast('Send failed: ' + say(err), 'err');
    }
    return;
  }
  // Optimistic: show the message immediately with a "sending" spinner — no frozen wait.
  const optimistic = bubble({
    direction: 'outgoing', body: text, sent_at: Math.floor(Date.now() / 1000),
    delete_at: cur.timer ? Math.floor(Date.now() / 1000) + cur.timer : undefined,
  }, true);
  box.appendChild(optimistic);
  box.scrollTop = box.scrollHeight;
  try {
    await invoke('send', { username: cur.username, text, replyTo: rt });
    if (cur.peer === peer) await renderThread(peer); // replace optimistic with persisted (✓ sent)
    loadChats();
  } catch (err) {
    optimistic.remove();
    if (say(err) === 'KEY_CHANGED') { input.value = text; return openThread(cur.username, cur.peer); }
    noteFailedSend({ kind: 'text', text, replyTo: rt || null }, sentFromKey);
    if (cur.peer === peer) await renderThread(peer);
    toast('Send failed: ' + say(err), 'err');
  }
}

