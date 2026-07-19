// ═══════════════════════════════════════════════════════════════════════════════
// Voice messages: record (MediaRecorder, WAV fallback) → E2E attachment → player.
// ═══════════════════════════════════════════════════════════════════════════════
const VOICE_MAX_SECS = 180;
let vrec = null; // active recording/preview state

function mss(s) { s = Math.max(0, s | 0); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); }

function vbShow(mode) { // 'init' | 'rec' | 'preview' | null (hidden)
  $('#th-voicebar').hidden = !mode;
  $('#th-form').style.display = mode ? 'none' : '';
  $('#vb-init').hidden = mode !== 'init';
  $('#vb-stop').hidden = mode !== 'rec';
  $('#vb-dot').hidden = mode !== 'rec';
  $('#vb-play').hidden = mode !== 'preview';
  $('#vb-send').hidden = mode !== 'preview';
  $('#vb-note').textContent =
    mode === 'preview' ? 'Ready to send' :
    mode === 'init' ? 'Starting microphone…' : 'Recording…';
}

// Mic supports both gestures: a quick TAP starts recording and leaves the bar up for a
// manual stop/send; a PRESS-AND-HOLD records only while held and drops to preview on
// release. Pointer events cover mouse, touch and pen alike.
const HOLD_MS = 350;
let micDownAt = 0;
(() => {
  const mic = $('#th-mic');
  mic.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    if (!cur.peer || cur.keyChanged || vrec) return;
    micDownAt = Date.now();
    try { mic.setPointerCapture(e.pointerId); } catch (_) {}
    startVoice();
  });
  const release = () => {
    if (!micDownAt) return;
    const held = Date.now() - micDownAt;
    micDownAt = 0;
    // Held past the threshold ⇒ push-to-talk: stop into preview. Short tap ⇒ keep
    // recording so stop/send stay under the user's control.
    if (held >= HOLD_MS && vrec && !vrec.starting && !vrec.blob) stopVoice();
  };
  mic.addEventListener('pointerup', (e) => { e.preventDefault(); release(); });
  mic.addEventListener('pointercancel', () => { micDownAt = 0; });
})();
async function startVoice() {
  if (!cur.peer || cur.keyChanged || vrec) return; // 1:1 and groups alike
  closeCmpPanel(); // the recording bar replaces the composer — the panel goes with it
  // The bar appears before the mic is open — device init (permission prompt, device
  // warm-up) can take a couple of seconds and must not look like a dead button.
  vrec = { starting: true };
  $('#vb-time').textContent = '0:00';
  vbShow('init');
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (e) {
    vrec = null;
    vbShow(null);
    return toast('Microphone unavailable: ' + say(e), 'err');
  }
  if (!vrec || !vrec.starting) { // cancelled while the mic was starting
    stream.getTracks().forEach((t) => t.stop());
    return;
  }
  vrec = { stream, startedAt: Date.now(), chunks: [], mime: '', blob: null, url: null,
           mr: null, ctx: null, proc: null, src: null, pcm: null, rate: 0,
           duration: 0, preview: null, timer: null,
           pkCtx: null, analyser: null, pkSrc: null, pkBuf: null, peaks: [], finalPeaks: [] };
  // Amplitude capture for the waveform (G): a light analyser over the same stream, sampled
  // on the UI tick. Independent of the recorder type, best-effort (ignored on failure).
  try {
    vrec.pkCtx = new (window.AudioContext || window.webkitAudioContext)();
    vrec.analyser = vrec.pkCtx.createAnalyser();
    vrec.analyser.fftSize = 256;
    vrec.pkSrc = vrec.pkCtx.createMediaStreamSource(stream);
    vrec.pkSrc.connect(vrec.analyser);
    vrec.pkBuf = new Uint8Array(vrec.analyser.frequencyBinCount);
    // WebViews (Android especially) hand out SUSPENDED AudioContexts — a suspended tap
    // reads constant 128s, i.e. a flat waveform. We're inside the mic-press gesture, so
    // resume() is allowed here.
    if (vrec.pkCtx.state !== 'running') vrec.pkCtx.resume().catch(() => {});
  } catch (_) { vrec.analyser = null; }
  const candidates = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/webm', 'audio/mp4'];
  const mime = (window.MediaRecorder && candidates.find((m) => MediaRecorder.isTypeSupported(m))) || null;
  if (mime) {
    vrec.mime = mime.split(';')[0];
    vrec.mr = new MediaRecorder(stream, { mimeType: mime, audioBitsPerSecond: 32000 });
    vrec.mr.ondataavailable = (e) => { if (e.data && e.data.size && vrec) vrec.chunks.push(e.data); };
    vrec.mr.start(250);
  } else {
    // WebKitGTK without MediaRecorder: raw PCM via ScriptProcessor, encoded to 16 kHz
    // mono WAV on stop. Bigger than opus but plays everywhere.
    vrec.mime = 'audio/wav';
    vrec.ctx = new (window.AudioContext || window.webkitAudioContext)();
    vrec.rate = vrec.ctx.sampleRate;
    vrec.pcm = [];
    vrec.src = vrec.ctx.createMediaStreamSource(stream);
    vrec.proc = vrec.ctx.createScriptProcessor(4096, 1, 1);
    vrec.proc.onaudioprocess = (e) => { if (vrec && vrec.pcm) vrec.pcm.push(new Float32Array(e.inputBuffer.getChannelData(0))); };
    vrec.src.connect(vrec.proc);
    vrec.proc.connect(vrec.ctx.destination);
  }
  $('#vb-time').textContent = '0:00';
  vbShow('rec');
  vrec.timer = setInterval(() => {
    if (!vrec) return;
    if (vrec.analyser) {
      vrec.analyser.getByteTimeDomainData(vrec.pkBuf);
      let max = 0;
      for (const v of vrec.pkBuf) max = Math.max(max, Math.abs(v - 128));
      vrec.peaks.push(max); // 0..128
    }
    const s = Math.floor((Date.now() - vrec.startedAt) / 1000);
    $('#vb-time').textContent = mss(s);
    if (s >= VOICE_MAX_SECS && !vrec.blob) stopVoice();
  }, 250);
}

// 0..255 bars from raw magnitudes. The reference level is the 95th percentile, NOT the
// absolute maximum — one clap/click used to become the scale ceiling and squash the
// whole note into a near-flat line. A sqrt loudness curve then lifts quiet speech into
// the visible range (amplitude is perceived logarithmically; linear bars read flat).
function scalePeaks(vals) {
  if (!vals || !vals.length) return [];
  const sorted = [...vals].sort((a, b) => a - b);
  const ref = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))] || 0;
  if (ref <= 0) return vals.map(() => 8); // silence: uniform stubs
  return vals.map((v) => {
    const r = Math.sqrt(Math.min(1, v / ref));
    return Math.max(8, Math.min(255, Math.round(r * 255)));
  });
}
// Resample live-captured amplitude samples to `buckets` bars (fallback path — the
// primary waveform is decoded from the finished blob in peaksFromBlob).
function downsamplePeaks(samples, buckets) {
  if (!samples || !samples.length) return [];
  const out = [];
  const per = samples.length / buckets;
  for (let i = 0; i < buckets; i++) {
    let m = 0;
    for (let j = Math.floor(i * per); j < Math.floor((i + 1) * per); j++) m = Math.max(m, samples[j] || 0);
    out.push(m);
  }
  return scalePeaks(out);
}
// The real waveform: decode the finished recording and take per-bucket RMS. This is
// deterministic — unlike the live analyser, which sampled one 128-sample window every
// 250 ms (missing most of the audio) and reads flat when Android leaves the tap
// AudioContext suspended. RMS over everything the mic actually recorded is what the
// spikes should look like. Subsampled (every 4th sample) — a 3-minute note stays fast.
async function peaksFromBlob(blob, buckets) {
  const ac = new (window.AudioContext || window.webkitAudioContext)();
  try {
    const buf = await ac.decodeAudioData(await blob.arrayBuffer());
    const data = buf.getChannelData(0);
    if (!data.length) return [];
    const per = Math.max(1, Math.floor(data.length / buckets));
    const rms = [];
    for (let i = 0; i < buckets; i++) {
      let sum = 0, n = 0;
      const end = Math.min((i + 1) * per, data.length);
      for (let j = i * per; j < end; j += 4) { const v = data[j]; sum += v * v; n++; }
      rms.push(n ? Math.sqrt(sum / n) : 0);
    }
    return scalePeaks(rms);
  } finally {
    try { ac.close(); } catch (_) {}
  }
}

// 16 kHz mono 16-bit WAV from Float32 chunks (nearest-sample downsample — fine for speech).
function encodeWav(chunks, inRate) {
  let len = 0;
  for (const c of chunks) len += c.length;
  const all = new Float32Array(len);
  let o = 0;
  for (const c of chunks) { all.set(c, o); o += c.length; }
  const outRate = Math.min(16000, inRate), ratio = inRate / outRate;
  const n = Math.floor(all.length / ratio);
  const buf = new ArrayBuffer(44 + n * 2), dv = new DataView(buf);
  const wstr = (off, s) => { for (let i = 0; i < s.length; i++) dv.setUint8(off + i, s.charCodeAt(i)); };
  wstr(0, 'RIFF'); dv.setUint32(4, 36 + n * 2, true); wstr(8, 'WAVE');
  wstr(12, 'fmt '); dv.setUint32(16, 16, true); dv.setUint16(20, 1, true); dv.setUint16(22, 1, true);
  dv.setUint32(24, outRate, true); dv.setUint32(28, outRate * 2, true);
  dv.setUint16(32, 2, true); dv.setUint16(34, 16, true);
  wstr(36, 'data'); dv.setUint32(40, n * 2, true);
  for (let i = 0; i < n; i++) {
    const v = Math.max(-1, Math.min(1, all[Math.floor(i * ratio)]));
    dv.setInt16(44 + i * 2, v < 0 ? v * 0x8000 : v * 0x7fff, true);
  }
  return new Blob([buf], { type: 'audio/wav' });
}

async function stopVoice() {
  if (!vrec || vrec.starting || vrec.blob) return;
  clearInterval(vrec.timer);
  vrec.duration = Math.max(1, Math.round((Date.now() - vrec.startedAt) / 1000));
  if (vrec.mr) {
    const mr = vrec.mr;
    await new Promise((resolve) => { mr.onstop = resolve; mr.stop(); });
    if (!vrec) return; // cancelled while stopping
    vrec.blob = new Blob(vrec.chunks, { type: vrec.mime });
  } else {
    vrec.proc.disconnect(); vrec.src.disconnect();
    vrec.blob = encodeWav(vrec.pcm, vrec.rate);
    vrec.pcm = null;
    vrec.ctx.close();
  }
  vrec.stream.getTracks().forEach((t) => t.stop());
  vrec.finalPeaks = downsamplePeaks(vrec.peaks, 60); // provisional (live capture)
  try { if (vrec.pkCtx) { vrec.pkSrc.disconnect(); vrec.pkCtx.close(); } } catch (_) {}
  vrec.url = URL.createObjectURL(vrec.blob);
  $('#vb-time').textContent = mss(vrec.duration);
  vbShow('preview');
  // Upgrade to the decoded-from-blob waveform (the accurate one). Async: guard
  // against a cancel/send that raced the decode.
  const blob = vrec.blob;
  try {
    const p = await peaksFromBlob(blob, 60);
    if (p.length && vrec && vrec.blob === blob) vrec.finalPeaks = p;
  } catch (_) { /* fallback peaks already in place */ }
}

function cancelVoice() {
  if (!vrec) return;
  if (vrec.starting) { vrec = null; vbShow(null); return; } // mic never opened
  clearInterval(vrec.timer);
  try { if (vrec.mr && vrec.mr.state !== 'inactive') vrec.mr.stop(); } catch (_) {}
  try { if (vrec.proc) { vrec.proc.disconnect(); vrec.src.disconnect(); vrec.ctx.close(); } } catch (_) {}
  try { if (vrec.pkCtx) { vrec.pkSrc.disconnect(); vrec.pkCtx.close(); } } catch (_) {}
  vrec.stream.getTracks().forEach((t) => t.stop());
  if (vrec.preview) { vrec.preview.pause(); }
  if (vrec.url) URL.revokeObjectURL(vrec.url);
  vrec = null;
  vbShow(null);
}

$('#vb-stop').onclick = stopVoice;
$('#vb-cancel').onclick = cancelVoice;
$('#vb-play').onclick = () => {
  if (!vrec || !vrec.url) return;
  if (vrec.preview && !vrec.preview.paused) { vrec.preview.pause(); $('#vb-play').innerHTML = icon('play'); return; }
  vrec.preview = vrec.preview || new Audio(vrec.url);
  vrec.preview.onended = () => { $('#vb-play').innerHTML = icon('play'); };
  vrec.preview.currentTime = 0;
  vrec.preview.play();
  $('#vb-play').innerHTML = icon('pause');
};
$('#vb-send').onclick = async () => {
  if (!vrec || !vrec.blob) return;
  const { blob, mime, duration, finalPeaks } = vrec;
  cancelVoice(); // hide the bar immediately; the optimistic bubble takes over
  await sendVoiceBlob({ blob, mime, duration, peaks: finalPeaks });
};

// The voice send itself (send button + failed-bubble Retry share it). A failure parks
// the note as a red Retry/Discard bubble — the recording is never lost to a repaint.
async function sendVoiceBlob({ blob, mime, duration, peaks }) {
  const username = cur.username, peer = cur.peer;
  const isGroup = cur.kind === 'group';
  const sentFromKey = draftKey();
  const box = $('#th-thread');
  const optimistic = bubble({ direction: 'outgoing', body: 'voice message',
    sent_at: Math.floor(Date.now() / 1000), attachment: true, voice: true,
    duration_secs: duration }, true);
  box.appendChild(optimistic);
  box.scrollTop = box.scrollHeight;
  try {
    const b64 = toB64(new Uint8Array(await blob.arrayBuffer()));
    await invoke('send_voice', {
      username: isGroup ? '' : username,
      groupId: isGroup ? peer : null,
      // Flat junk (suspended-capture zeros) must not travel: recipients synthesize or
      // decode a real shape from the audio instead.
      dataB64: b64, mime, durationSecs: duration, peaks: flatPeaks(peaks) ? [] : peaks,
    });
    if (cur.peer === peer) await (isGroup ? renderGroupThread(peer) : renderThread(peer));
    loadChats();
  } catch (err) {
    optimistic.remove();
    if (!isGroup && say(err) === 'KEY_CHANGED') return openThread(username, peer);
    noteFailedSend({ kind: 'voice', blob, mime, duration, peaks }, sentFromKey);
    if (cur.peer === peer) await (isGroup ? renderGroupThread(peer) : renderThread(peer));
    toast('Send failed: ' + say(err), 'err');
  }
}

// ── Playback: one shared "now playing" so two notes never talk over each other ──
// msg_id -> { url, audio }; LRU-bounded (eviction stops + releases the note — the one
// playing is by construction the most recently used, so it's effectively never hit).
const voiceCache = new LruCache({
  max: 24,
  onEvict: (v) => {
    if (nowPlaying && nowPlaying.audio === v.audio) stopNowPlaying();
    v.audio.pause();
    v.audio.removeAttribute('src');
    URL.revokeObjectURL(v.url);
  },
});
let nowPlaying = null; // { audio, chip }

function voiceMime(name) {
  const ext = (String(name).split('.').pop() || '').toLowerCase();
  return { webm: 'audio/webm', ogg: 'audio/ogg', wav: 'audio/wav', m4a: 'audio/mp4' }[ext] || 'audio/webm';
}

const VOICE_SPEEDS = [1, 1.5, 2];
let voiceSpeedIdx = 0;
// Deterministic pseudo-waveform for notes with no captured amplitude (old messages, or
// Android WebView where the analyser can't tap the mic stream). Seeded by the message so
// the shape is stable across re-renders, with a speech-like fade-in/out envelope.
function synthPeaks(seed, n) {
  let s = 0;
  const str = String(seed || 'v');
  for (let i = 0; i < str.length; i++) s = (s * 31 + str.charCodeAt(i)) >>> 0;
  const out = [];
  for (let i = 0; i < n; i++) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const r = s / 0x7fffffff;                 // 0..1 pseudo-random
    const env = Math.sin((i / (n - 1)) * Math.PI); // 0→1→0 across the bar
    out.push(Math.round(40 + r * 175 * (0.35 + 0.65 * env)));
  }
  return out;
}
// Legacy notes (sent before peaks travelled in the reference) have no real waveform
// until first play: the decoded blob backfills this session cache and the bars swap
// in place (see toggleVoice). Keyed by msg id; bounded.
const voicePeaksCache = new Map();
function noteDecodedPeaks(msgId, peaks) {
  if (!msgId || !peaks.length) return;
  if (voicePeaksCache.size > 200) voicePeaksCache.delete(voicePeaksCache.keys().next().value);
  voicePeaksCache.set(msgId, peaks);
}
// Peaks that carry no shape (absent, or all-equal bars from a suspended tap context)
// are as good as missing: the renderer falls back to synth/decoded spikes instead.
function flatPeaks(p) {
  if (!p || !p.length) return true;
  let min = 255, max = 0;
  for (const v of p) { if (v < min) min = v; if (v > max) max = v; }
  return max - min < 12;
}
// Max-pool resample to at most `n` bars (keeps the 0..255 scale and the spike shape).
function fitBars(p, n) {
  if (p.length <= n) return p;
  const out = [], per = p.length / n;
  for (let i = 0; i < n; i++) {
    let m = 0;
    for (let j = Math.floor(i * per); j < Math.floor((i + 1) * per); j++) m = Math.max(m, p[j]);
    out.push(m);
  }
  return out;
}
// Build the waveform — real peaks when we have them (from the message, or decoded on a
// previous play), a synthesized shape otherwise. Rendered as one scalable SVG (bars in
// a fixed viewBox that stretches with the chip), so a long note can NEVER overflow the
// bubble the way per-bar min-widths did. Rects keep the .wb class + --i index that the
// progress painter and the playing-equalizer animation key off.
function waveBars(p) {
  const rects = p.map((v, i) => {
    const h = Math.max(10, (v / 255) * 100);
    return `<rect class="wb" style="--i:${i}" x="${i * 3}" y="${(100 - h) / 2}" width="2" height="${h}" rx="1"></rect>`;
  }).join('');
  return `<svg viewBox="0 0 ${p.length * 3 - 1} 100" preserveAspectRatio="none" aria-hidden="true">${rects}</svg>`;
}
function waveMarkup(peaks, seed, secs) {
  // Longer notes get a denser wave (Signal-style), bounded so it stays readable.
  const n = Math.max(28, Math.min(56, 28 + Math.round((secs || 0) / 6)));
  const real = !flatPeaks(peaks) ? peaks : voicePeaksCache.get(seed);
  const p = (real && real.length) ? fitBars(real, n) : synthPeaks(seed, n);
  return '<span class="vc-wave">' + waveBars(p) + '</span>';
}
function renderVoice(el, m, time, uploading) {
  const speed = VOICE_SPEEDS[voiceSpeedIdx];
  el.innerHTML =
    `<span class="voice-chip">
       <button class="vc-btn" type="button" ${uploading ? 'disabled' : ''}>${uploading ? '<span class="spinner-sm"></span>' : icon('play')}</button>
       ${waveMarkup(m.peaks, m.msg_id || m.duration_secs, m.duration_secs)}
       <span class="vc-dur">${mss(m.duration_secs)}</span>
       <button class="vc-speed" type="button" ${uploading ? 'disabled' : ''}>${speed}×</button>
     </span>${time}`;
  if (uploading) return;
  const chip = el.querySelector('.voice-chip');
  const btn = chip.querySelector('.vc-btn');
  btn.onclick = async (e) => {
    e.stopPropagation();
    try { await toggleVoice(m, chip); }
    catch (err) { toast('Playback failed: ' + say(err), 'err'); }
  };
  // Tap/click the waveform to seek: scrub within the playing note, or start this note
  // right at that point.
  const wave = chip.querySelector('.vc-wave');
  if (wave) wave.onclick = async (e) => {
    e.stopPropagation();
    const r = wave.getBoundingClientRect();
    const frac = Math.min(1, Math.max(0, (e.clientX - r.left) / (r.width || 1)));
    if (nowPlaying && nowPlaying.msgId === m.msg_id) {
      const a = nowPlaying.audio;
      const total = a.duration && isFinite(a.duration) ? a.duration : m.duration_secs || 1;
      a.currentTime = frac * total;
      paintVoiceProgress(chip, frac);
      return;
    }
    try { await toggleVoice(m, chip, frac); }
    catch (err) { toast('Playback failed: ' + say(err), 'err'); }
  };
  const sp = chip.querySelector('.vc-speed');
  sp.onclick = (e) => {
    e.stopPropagation();
    voiceSpeedIdx = (voiceSpeedIdx + 1) % VOICE_SPEEDS.length;
    sp.textContent = VOICE_SPEEDS[voiceSpeedIdx] + '×';
    if (nowPlaying && nowPlaying.audio) nowPlaying.audio.playbackRate = VOICE_SPEEDS[voiceSpeedIdx];
  };
}
// Paint the waveform's played portion (bars up to `frac`) or the flat fill.
function paintVoiceProgress(chip, frac) {
  const bars = $$('.vc-wave .wb', chip);
  if (bars.length) {
    const cut = Math.floor(frac * bars.length);
    bars.forEach((b, i) => b.classList.toggle('on', i <= cut));
    return;
  }
  const fill = chip.querySelector('.vc-fill');
  if (fill) fill.style.width = Math.min(100, frac * 100) + '%';
}

async function loadVoice(m) {
  let v = voiceCache.get(m.msg_id);
  if (v) return v;
  const b64 = await invoke('fetch_attachment', { peer: cur.peer, msgId: m.msg_id });
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const blob = new Blob([bytes], { type: voiceMime(m.body) });
  const url = URL.createObjectURL(blob);
  v = { url, audio: new Audio(url), blob };
  voiceCache.set(m.msg_id, v);
  return v;
}

function stopNowPlaying() {
  if (!nowPlaying) return;
  nowPlaying.audio.pause();
  if (nowPlaying.chip.isConnected) {
    nowPlaying.chip.querySelector('.vc-btn').innerHTML = icon('play');
    nowPlaying.chip.querySelector('.vc-wave')?.classList.remove('playing');
    paintVoiceProgress(nowPlaying.chip, 0);
  }
  nowPlaying = null;
}

async function toggleVoice(m, chip, startFrac = 0) {
  if (nowPlaying && nowPlaying.msgId === m.msg_id) return stopNowPlaying();
  stopNowPlaying();
  const btn = chip.querySelector('.vc-btn');
  btn.innerHTML = '<span class="spinner-sm"></span>';
  const { audio, blob } = await loadVoice(m);
  btn.innerHTML = icon('pause');
  chip.querySelector('.vc-wave')?.classList.add('playing');
  // Note without a usable travelled waveform (legacy, or flat junk from a suspended
  // capture): decode the now-local audio once and swap the real spikes in for the
  // synthesized bars (cached for future repaints).
  if (flatPeaks(m.peaks) && !voicePeaksCache.has(m.msg_id) && blob) {
    peaksFromBlob(blob, 44).then((p) => {
      noteDecodedPeaks(m.msg_id, p);
      const wave = chip.querySelector('.vc-wave');
      if (p.length && wave && wave.isConnected) wave.innerHTML = waveBars(p);
    }).catch(() => {});
  }
  audio.playbackRate = VOICE_SPEEDS[voiceSpeedIdx];
  nowPlaying = { audio, chip, msgId: m.msg_id };
  const dur = chip.querySelector('.vc-dur');
  audio.ontimeupdate = () => {
    if (!chip.isConnected) return;
    const total = audio.duration && isFinite(audio.duration) ? audio.duration : m.duration_secs || 1;
    paintVoiceProgress(chip, audio.currentTime / total);
    dur.textContent = mss(audio.currentTime);
  };
  audio.onended = () => {
    if (chip.isConnected) {
      btn.innerHTML = icon('play');
      chip.querySelector('.vc-wave')?.classList.remove('playing');
      paintVoiceProgress(chip, 0);
      dur.textContent = mss(m.duration_secs);
    }
    nowPlaying = null;
  };
  const total = audio.duration && isFinite(audio.duration) ? audio.duration : m.duration_secs || 1;
  audio.currentTime = startFrac > 0 ? startFrac * total : 0;
  await audio.play();
}

// ── Attachment queue: drag-drop, paste, multi-select. Files sit in a chip strip above
// the composer until Send; a caption typed alongside rides the FIRST attachment (E).
let attachQueue = []; // { file, name, isImage, thumb }
function renderQueue() {
  const q = $('#th-queue');
  q.innerHTML = '';
  q.hidden = attachQueue.length === 0;
  attachQueue.forEach((it, i) => {
    const chip = document.createElement('div');
    chip.className = 'aq-chip';
    if (it.thumb) chip.innerHTML = `<img class="aq-thumb" src="${it.thumb}" alt="" />`;
    else chip.innerHTML = `<span class="aq-ico">${icon('file')}</span>`;
    const name = document.createElement('span');
    name.className = 'aq-name'; name.textContent = it.name;
    chip.appendChild(name);
    const rm = document.createElement('button');
    rm.className = 'aq-rm'; rm.type = 'button'; rm.innerHTML = icon('x'); rm.title = 'Remove';
    rm.onclick = () => { if (it.thumb) URL.revokeObjectURL(it.thumb); attachQueue.splice(i, 1); renderQueue(); };
    chip.appendChild(rm);
    q.appendChild(chip);
  });
  updateCmp(); // queued files count as "composing" — the main button becomes send
}
function enqueueFiles(files) {
  for (const f of files) {
    if (f.size > 10 * 1024 * 1024) { toast(`"${f.name}" is over 10 MB`, 'err'); continue; }
    const isImage = (f.type || '').startsWith('image/') || IMG_EXT.test(f.name || '');
    // Snapshot the bytes NOW, while the picker's grant on the underlying file is
    // fresh. A queued File read later (after earlier uploads, or after the activity
    // cycled behind the picker) can throw NotReadableError on Android — the
    // content-provider reference behind the File object does not live forever.
    const bytes = f.arrayBuffer();
    bytes.catch(() => {}); // surfaced at send time; never an unhandled rejection
    attachQueue.push({ file: f, bytes, name: f.name || 'image.png', isImage, thumb: isImage ? URL.createObjectURL(f) : null });
  }
  renderQueue();
  $('#th-input').focus();
}
function clearQueue() {
  for (const it of attachQueue) if (it.thumb) URL.revokeObjectURL(it.thumb);
  attachQueue = [];
  renderQueue();
}
// One attachment over the E2E pipeline, with an optimistic bubble. On failure the file
// is parked as a red Retry/Discard bubble (the File object stays in memory) — used by
// both the queue send and the failed-bubble Retry. Returns 'key_changed' when the 1:1
// send aborted on a key change (the caller stops its loop).
async function sendOneFile(it, cap) {
  const isGroup = cur.kind === 'group';
  const peer = cur.peer, username = cur.username;
  const sentFromKey = draftKey();
  const box = $('#th-thread');
  const optimistic = bubble({ direction: 'outgoing', body: it.name, sent_at: Math.floor(Date.now() / 1000), attachment: true, caption: cap }, true);
  box.appendChild(optimistic);
  box.scrollTop = box.scrollHeight;
  try {
    // Prefer the bytes snapshotted at enqueue time; if that read itself failed,
    // fall back to a fresh read of the File (its grant may still be alive).
    const buf = it.bytes
      ? await it.bytes.catch(() => it.file.arrayBuffer())
      : await it.file.arrayBuffer();
    const b64 = toB64(new Uint8Array(buf));
    await invoke('send_file', {
      username: isGroup ? '' : username,
      groupId: isGroup ? peer : null,
      filename: it.name, dataB64: b64, caption: cap,
    });
  } catch (err) {
    optimistic.remove();
    if (!isGroup && say(err) === 'KEY_CHANGED') { openThread(username, peer); return 'key_changed'; }
    noteFailedSend({ kind: 'file', file: it.file, bytes: it.bytes, name: it.name, caption: cap }, sentFromKey);
    toast(`Send failed for "${it.name}": ` + say(err), 'err');
  }
  return 'done';
}
// Send the queued files sequentially over the existing attachment path; caption on the 1st.
// One bad upload parks itself for Retry and must not eat the files after it.
async function sendQueue(caption) {
  if (cur.keyChanged) { toast('Verify the new key first', 'err'); return; }
  const items = attachQueue.slice();
  clearQueue();
  const isGroup = cur.kind === 'group';
  const peer = cur.peer;
  for (let i = 0; i < items.length; i++) {
    const cap = i === 0 ? (caption || null) : null;
    if ((await sendOneFile(items[i], cap)) === 'key_changed') return;
  }
  if (cur.peer === peer) await (isGroup ? renderGroupThread(peer) : renderThread(peer));
  loadChats();
}

