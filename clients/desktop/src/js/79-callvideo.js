// ═══════════════════════════════════════════════════════════════════════════════
// Call video tiles: the WebGL I420 painter and the per-track canvases it owns.
// Split out of 80-calls.js, which is overlay state and button wiring — this is the
// GPU-side paint path and shares nothing with it but `tileFor`.
// ═══════════════════════════════════════════════════════════════════════════════
// ── WebGL I420 painter ────────────────────────────────────────────────────────────
// Decoded peer frames arrive as raw I420 planes over a Tauri IPC channel; a tiny
// fragment shader does YUV→RGB on the GPU so even 1080p screen shares paint cheaply.
class YuvCanvas {
  constructor(canvas) {
    this.canvas = canvas;
    // A WebGL context is not forever. Any GPU driver reset — Windows TDR, a driver
    // update, an unrelated application hanging the GPU — invalidates every D3D11 device
    // on the machine, and the webview's WebGL context dies with them. That is not
    // hypothetical: it took a call's video to a permanently black tile while the audio
    // carried on, because a lost context keeps accepting draw calls and silently draws
    // nothing. `preventDefault` on the loss event is what makes the browser willing to
    // restore it at all; the restore then rebuilds the program and textures from
    // scratch, and the peer's next frame (20 a second) repaints. Nothing above needs to
    // know it happened.
    canvas.addEventListener('webglcontextlost', (e) => {
      e.preventDefault();
      this.gl = null;
      console.warn('call video: WebGL context lost (GPU reset?) — awaiting restore');
    });
    canvas.addEventListener('webglcontextrestored', () => {
      console.warn('call video: WebGL context restored');
      this._init();
    });
    this._init();
  }

  _init() {
    const canvas = this.canvas;
    const gl = canvas.getContext('webgl', { preserveDrawingBuffer: false });
    this.gl = gl;
    if (!gl) return; // painted never; tile stays black (webgl unavailable)
    // Force a resize on the next paint: after a restore the drawing buffer is new and
    // the cached dimensions would otherwise suppress the viewport setup.
    this.canvas.width = 1;
    this.canvas.height = 1;
    const vs = 'attribute vec2 p;varying vec2 t;void main(){t=vec2((p.x+1.)/2.,(1.-p.y)/2.);gl_Position=vec4(p,0.,1.);}';
    const fs = 'precision mediump float;varying vec2 t;uniform sampler2D y,u,v;' +
      'void main(){float Y=1.1643*(texture2D(y,t).r-0.0625);float U=texture2D(u,t).r-0.5;float V=texture2D(v,t).r-0.5;' +
      'gl_FragColor=vec4(Y+1.5958*V,Y-0.39173*U-0.8129*V,Y+2.017*U,1.);}';
    const sh = (type, src) => {
      const h = gl.createShader(type);
      gl.shaderSource(h, src); gl.compileShader(h);
      return h;
    };
    const prog = gl.createProgram();
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, vs));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, fs));
    gl.linkProgram(prog); gl.useProgram(prog);
    const quad = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, quad);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    this.tex = ['y', 'u', 'v'].map((n, i) => {
      const t = gl.createTexture();
      gl.activeTexture(gl.TEXTURE0 + i);
      gl.bindTexture(gl.TEXTURE_2D, t);
      for (const [k, w] of [['TEXTURE_MIN_FILTER', 'LINEAR'], ['TEXTURE_MAG_FILTER', 'LINEAR'],
        ['TEXTURE_WRAP_S', 'CLAMP_TO_EDGE'], ['TEXTURE_WRAP_T', 'CLAMP_TO_EDGE']]) {
        gl.texParameteri(gl.TEXTURE_2D, gl[k], gl[w]);
      }
      gl.uniform1i(gl.getUniformLocation(prog, n), i);
      return t;
    });
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);
  }
  paint(w, h, bytes) {
    const gl = this.gl;
    // `isContextLost` as well as the null check: the loss event is delivered on a later
    // task, so between the GPU reset and the handler running there is a window where the
    // context is dead but still looks usable. Uploading three planes of a 1080p frame
    // into it every 50 ms for that window is pure waste.
    if (!gl || gl.isContextLost()) return;
    if (this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas.width = w; this.canvas.height = h;
      gl.viewport(0, 0, w, h);
      // The tile's on-screen box just changed shape, and the overlay controls sit on
      // its corner — see positionStreamControls.
      if (typeof positionStreamControls === 'function') positionStreamControls();
    }
    const ysz = w * h, csz = ysz >> 2, cw = w >> 1, ch = h >> 1;
    const planes = [[w, h, bytes.subarray(0, ysz)], [cw, ch, bytes.subarray(ysz, ysz + csz)],
      [cw, ch, bytes.subarray(ysz + csz, ysz + 2 * csz)]];
    planes.forEach(([pw, ph, data], i) => {
      gl.activeTexture(gl.TEXTURE0 + i);
      gl.bindTexture(gl.TEXTURE_2D, this.tex[i]);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.LUMINANCE, pw, ph, 0, gl.LUMINANCE, gl.UNSIGNED_BYTE, data);
    });
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  }
  // Forget the picture. Resizing the canvas is what actually does it — that drops the
  // drawing buffer and reallocates it as transparent black — and it hands a 1080p
  // share's worth of GPU memory back at the same time. `paint` resizes again on the
  // next frame, so nothing else has to know this happened.
  clear() {
    if (!this.gl) return;
    this.canvas.width = 1;
    this.canvas.height = 1;
    this.gl.viewport(0, 0, 1, 1);
  }
}
const yuvTiles = {}; // track id → YuvCanvas (1 = peer camera, 2 = peer screen, 101/102 = self)

function tileFor(track) {
  const el = { 1: $('#cv-camera'), 2: $('#cv-screen'), 101: $('#cv-self-cam'), 102: $('#cv-self-scr') }[track];
  if (!yuvTiles[track]) yuvTiles[track] = new YuvCanvas(el);
  return { el, painter: yuvTiles[track] };
}

// Wipe every tile. Hiding one is not enough: a hidden canvas keeps the last frame it
// was given, so the next thing to reveal it shows the *previous* call's picture — which
// is how the peer's shared screen ended up behind the ringing state of the call after
// it. It is also somebody's screen sitting in GPU memory long after they stopped
// sharing it, which is not ours to keep.
function clearTiles() {
  Object.values(yuvTiles).forEach((t) => t.clear());
}

// ── Peer track on/off, across three transports that do not agree on order ──────────
// A track stopping is announced twice: as a `peer_track` app event, and as a zero-sized
// frame on the media channel. Neither is ordered against the frames themselves (see
// onMediaFrame). So "off" is recorded as a timestamp and frames for that track are
// ignored until the peer says it is on again — an explicit `peer_track on` clears it
// immediately, and the window is only a backstop for the case where that is late too.
const OFF_GUARD_MS = 1500;
// How long a visible tile may go without a frame before it is taken down anyway. Well
// past any real gap: the sender paces screen video at 20 fps and camera at 30, so even a
// heavily governed share is tens of frames inside this.
const STALE_TILE_MS = 2500;
const trackOffAt = { 1: 0, 2: 0 };
const lastFrameAt = { 1: 0, 2: 0 };

// Take down any tile that has stopped receiving. The off signals remain the fast path —
// this only catches the case where one never arrives.
function reapStaleTiles() {
  if (callUi.mode !== 'connected') return;
  for (const track of [1, 2]) {
    const el = { 1: $('#cv-camera'), 2: $('#cv-screen') }[track];
    if (el.hidden) continue;
    const last = lastFrameAt[track] || 0;
    if (last && Date.now() - last > STALE_TILE_MS) trackWentOff(track);
  }
}
function offGuardActive(track) {
  const t = trackOffAt[track] || 0;
  return t !== 0 && Date.now() - t < OFF_GUARD_MS;
}
function trackWentOff(track) {
  trackOffAt[track] = Date.now();
  const { el, painter } = tileFor(track);
  el.hidden = true;
  // Drop the picture as well as the tile: a hidden canvas keeps its last frame, and that
  // frame is somebody's screen sitting in GPU memory after they stopped sharing it.
  painter.clear();
  // The track is off, so the flags that describe it must say so too.
  //
  // Taking the tile down without this was worse than the bug it fixed: the watchdog hid a
  // stopped share correctly, `peerScr` stayed true because the control message it depends
  // on never arrived, and the share button stayed greyed out for the rest of the call —
  // nobody could share at all. Whatever evidence is good enough to remove the picture is
  // good enough to update the state behind it.
  if (track === 1) callUi.peerCam = false;
  if (track === 2) callUi.peerScr = false;
  updateVideoStage();
  setCallButtons();
}
function trackCameOn(track) {
  trackOffAt[track] = 0;
  lastFrameAt[track] = Date.now(); // don't reap a track that has only just been announced
}

// Show the video stage when any peer tile is live; drop back to the avatar card
// when both are off.
function updateVideoStage() {
  const cam = !$('#cv-camera').hidden, scr = !$('#cv-screen').hidden;
  $('#call-video').hidden = !(cam || scr);
  $('#callui').classList.toggle('has-video', cam || scr);
  $('#call-video').classList.toggle('both', cam && scr);
  // The bubble shows the peer's video when there is one, the avatar otherwise.
  $('#cm-avatar').hidden = cam || scr;
  // Overlay controls (three dots / fullscreen) follow the picture they belong to.
  if (typeof syncCallMenus === 'function') syncCallMenus();
}
