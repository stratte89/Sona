// ═══════════════════════════════════════════════════════════════════════════════
// Media gallery (per chat/group) + the video viewer overlay. Everything decrypts
// through the same E2E pipeline as the thread (fetch_attachment); nothing here talks
// to the network directly. Session-only caches (imgCache/vidCache) are shared with
// the thread renderers, so a thumbnail seen in the gallery is free in the thread.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Video viewer: the lightbox's sibling, a <video> instead of an <img> ──────────
const vb2 = { peer: null, msgId: null };
function openVidbox(url, peer, msgId) {
  vb2.peer = peer;
  vb2.msgId = msgId;
  stopNowPlaying(); // a voice note must not talk over the video
  stopGalleryVoice();
  const v = $('#vb2-video');
  v.src = url;
  $('#vidbox').hidden = false;
  v.play().catch(() => {}); // some webviews want a direct gesture — controls remain
}
function closeVidbox() {
  const v = $('#vb2-video');
  v.pause();
  v.removeAttribute('src');
  v.load();
  $('#vidbox').hidden = true;
}
$('#vb2-close').onclick = closeVidbox;
$('#vidbox').onclick = (e) => { if (e.target === $('#vidbox')) closeVidbox(); };
$('#vb2-save').onclick = () => { if (vb2.peer) saveAtt(vb2.peer, vb2.msgId); };

// ── Gallery modal: Media / Files / Voice tabs over the open conversation ─────────
async function mediaGalleryModal() {
  const isGroup = cur.kind === 'group';
  const peer = cur.peer;
  if (!peer) return;
  let msgs = [];
  try {
    const t = await invoke(isGroup ? 'group_thread' : 'thread', isGroup ? { groupId: peer } : { peer });
    msgs = t.messages.filter((m) => m.attachment && !m.system);
  } catch (e) { return toast(say(e), 'err'); }
  // Newest first — the thing you're looking for is almost always recent. Voice notes
  // are audio blobs whose container extension (.webm) also matches VIDEO_EXT — the
  // voice flag wins, so they show ONLY under Voice.
  const media = msgs.filter((m) => !m.voice && (IMG_EXT.test(m.body) || VIDEO_EXT.test(m.body))).reverse();
  const voice = msgs.filter((m) => m.voice).reverse();
  const files = msgs.filter((m) => !m.voice && !IMG_EXT.test(m.body) && !VIDEO_EXT.test(m.body)).reverse();
  const card = openModal(
    `<h3>Media, files & voice</h3>
     <div class="mg-tabs" id="mg-tabs">
       <button data-t="media" class="on">Media<em>${media.length}</em></button>
       <button data-t="files">Files<em>${files.length}</em></button>
       <button data-t="voice">Voice<em>${voice.length}</em></button>
     </div>
     <div class="mg-body" id="mg-body"></div>`);
  const body = card.querySelector('#mg-body');

  // "Jump to message": close the gallery and scroll the thread to the source bubble.
  const jumpBtn = (msgId, cls) => {
    const j = document.createElement('button');
    j.type = 'button';
    j.className = cls;
    j.title = 'Jump to message';
    j.innerHTML = icon('chat');
    j.onclick = (e) => { e.stopPropagation(); closeModal(); jumpToMsg(msgId); };
    return j;
  };

  const renderMedia = () => {
    stopGalleryVoice();
    if (!media.length) { body.innerHTML = '<p class="hint">No photos or videos in this chat yet.</p>'; return; }
    body.innerHTML = '<div class="mg-grid"></div>';
    const grid = body.querySelector('.mg-grid');
    const jobs = [];
    for (const m of media) {
      // A <div> (not <button>) so the jump overlay can nest — buttons can't contain buttons.
      const tile = document.createElement('div');
      tile.className = 'mg-tile';
      if (VIDEO_EXT.test(m.body)) {
        tile.classList.add('vid');
        tile.innerHTML = `<span class="mg-play">${icon('play')}</span><span class="mg-vname">${escapeHtml(m.body)}</span>`;
        tile.appendChild(jumpBtn(m.msg_id, 'mg-tjump'));
        tile.onclick = async () => {
          const p = tile.querySelector('.mg-play');
          p.innerHTML = '<span class="spinner-sm"></span>';
          try { openVidbox(await loadVideoUrl(peer, m), peer, m.msg_id); }
          catch (e) { toast('Video failed: ' + say(e), 'err'); }
          p.innerHTML = icon('play');
        };
      } else {
        tile.innerHTML = '<span class="spinner-sm"></span>';
        // Decrypt lazily through a small worker pool below (3-wide, stops if the
        // modal is gone) — never all at once.
        jobs.push(async () => {
          try {
            const b64 = imgCache.get(m.msg_id) ||
              `data:${mimeFor(m.body)};base64,` + await invoke('fetch_attachment', { peer, msgId: m.msg_id });
            imgCache.set(m.msg_id, b64);
            if (!tile.isConnected) return;
            tile.innerHTML = `<img src="${b64}" alt="" loading="lazy" />`;
            tile.appendChild(jumpBtn(m.msg_id, 'mg-tjump'));
            // The lightbox sits ABOVE the modal, so the gallery is still there on close.
            tile.onclick = () => openLightbox(b64, peer, m.msg_id);
          } catch (_) {
            if (tile.isConnected) tile.innerHTML = `<span class="mg-broken">${icon('file')}</span>`;
          }
        });
      }
      grid.appendChild(tile);
    }
    (async () => {
      const q = jobs.slice();
      const worker = async () => {
        let j;
        while ((j = q.shift())) {
          if (!grid.isConnected) return; // modal closed — stop decrypting
          await j();
        }
      };
      await Promise.all([worker(), worker(), worker()]);
    })();
  };

  // A list row plus its jump companion; returns { wrap, row } — append `wrap`, style
  // playback state on `row`.
  const rowFor = (m, sub, onclick) => {
    const wrap = document.createElement('div');
    wrap.className = 'mg-rowwrap';
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'mg-row';
    row.innerHTML =
      `<span class="mg-rowico">${icon(m.voice ? 'mic' : 'file')}</span>
       <span class="mg-rowbody"><b>${escapeHtml(m.voice ? 'Voice message' : m.body)}</b><em>${escapeHtml(sub)}</em></span>`;
    row.onclick = onclick;
    wrap.append(row, jumpBtn(m.msg_id, 'mg-jump'));
    return { wrap, row };
  };
  const dayOf = (ts) => relday(ts) + ' · ' + hhmm(ts);

  const renderFiles = () => {
    stopGalleryVoice();
    if (!files.length) { body.innerHTML = '<p class="hint">No files in this chat yet.</p>'; return; }
    body.innerHTML = '<div class="mg-list"></div>';
    const list = body.querySelector('.mg-list');
    for (const m of files) {
      list.appendChild(rowFor(m, dayOf(m.sent_at) + ' — tap to save', () => saveAtt(peer, m.msg_id)).wrap);
    }
  };

  const renderVoice = () => {
    stopGalleryVoice();
    if (!voice.length) { body.innerHTML = '<p class="hint">No voice messages in this chat yet.</p>'; return; }
    body.innerHTML = '<div class="mg-list"></div>';
    const list = body.querySelector('.mg-list');
    for (const m of voice) {
      const { wrap, row } = rowFor(m, mss(m.duration_secs) + ' · ' + dayOf(m.sent_at), () => toggleGalleryVoice(m, row));
      list.appendChild(wrap);
    }
  };

  card.querySelectorAll('#mg-tabs button').forEach((b) => {
    b.onclick = () => {
      card.querySelectorAll('#mg-tabs button').forEach((x) => x.classList.toggle('on', x === b));
      ({ media: renderMedia, files: renderFiles, voice: renderVoice })[b.dataset.t]();
    };
  });
  renderMedia();
}

// One-at-a-time voice playback inside the gallery (reuses the thread's decrypted cache
// via loadVoice; also silences the thread player and vice versa via stopNowPlaying).
let galAudio = null;
let galRow = null;
let galMsgId = null;
function stopGalleryVoice() {
  if (galAudio) { galAudio.pause(); galAudio = null; }
  if (galRow && galRow.isConnected) galRow.classList.remove('playing');
  galRow = null;
  galMsgId = null;
}
async function toggleGalleryVoice(m, row) {
  if (galMsgId === m.msg_id) return stopGalleryVoice();
  stopGalleryVoice();
  stopNowPlaying();
  try {
    const { audio } = await loadVoice(m);
    galAudio = audio;
    galRow = row;
    galMsgId = m.msg_id;
    row.classList.add('playing');
    audio.onended = () => stopGalleryVoice();
    audio.currentTime = 0;
    await audio.play();
  } catch (e) { stopGalleryVoice(); toast('Playback failed: ' + say(e), 'err'); }
}

// Entry points: the chat-settings row (1:1) — the group info sheet wires its own
// button in 35-attach.js.
$('#cs-media').onclick = () => mediaGalleryModal();

// Closing the modal (any path: backdrop, Esc, back gesture) must silence gallery audio.
const closeModalBaseForGallery = closeModal;
closeModal = function () {
  stopGalleryVoice();
  return closeModalBaseForGallery();
};
