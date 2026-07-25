//! Platform capture + render plumbing for video calls and screen share (desktop).
//!
//! The client-core engine ([`client_core::media`]) owns codecs and crypto; this module
//! feeds it raw I420 frames and system audio, and pushes the peer's decoded frames to
//! the webview over a Tauri IPC channel (the UI paints them onto a WebGL canvas — no
//! frame ever touches disk or the DOM as an image element).
//!
//! Capture is *lazy and self-stopping*: the engine polls a source only while its track
//! is toggled on, so each capture thread starts on the first poll and exits (releasing
//! the camera / stopping screen grabs — and the camera LED) about a second after polls
//! stop. Nothing captures while a track is off.
//!
//! Backends:
//! * camera — `nokhwa` (V4L2 / AVFoundation / MSMF)
//! * screen — X11 `GetImage` via pure-Rust `x11rb` on Linux (Wayland needs a PipeWire
//!   portal — not wired yet, see the README), `xcap` on Windows/macOS
//! * screen audio — cpal: WASAPI loopback on Windows (input stream on the output
//!   device), a PulseAudio/PipeWire "monitor" input on Linux when one is exposed;
//!   absent otherwise and the toggle reports unavailable rather than failing the share
//! * Android — capture comes from Kotlin bridges over JNI (see `android_media`); the
//!   same sources read frames from the JNI slots instead of spawning threads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use client_core::media::{
    video, MediaSink, ScreenAudioSource, Track, VideoSource, SCREEN_AUDIO_SAMPLES,
};

/// How long after the last engine poll a capture thread keeps running. Polls arrive
/// every ~10 ms while a track is on; 1.5 s of silence means the track is off (or the
/// call ended) and the device must be released.
const CAPTURE_LINGER: Duration = Duration::from_millis(1500);

/// Self-view preview: local capture is mirrored to the UI channel so the user sees
/// what they're sending. Track ids on the wire are offset past the real [`Track`]
/// ids (camera → 101, screen → 102) so the UI can tell self from peer.
const SELF_TRACK_BASE: u8 = 100;
/// Preview cadence (10 fps) and width cap — it's a thumbnail, not the encode path.
const PREVIEW_INTERVAL: Duration = Duration::from_millis(100);
const PREVIEW_MAX_W: usize = 480;

// ── Pixel conversion ────────────────────────────────────────────────────────────────

/// Convert packed RGB-ish pixels to planar I420 with optional integer decimation.
/// `ro/go/bo` are the channel offsets inside one `step`-byte pixel (so RGB, RGBA and
/// BGRX all funnel through here). Nearest-neighbour decimation: cheap, and for screen
/// content it keeps text edges crisper than a box filter at the same cost.
pub(crate) fn packed_to_i420(
    data: &[u8],
    w: usize,
    h: usize,
    step: usize,
    (ro, go, bo): (usize, usize, usize),
    decim: usize,
) -> Option<video::Frame> {
    if decim == 0 || w < 16 * decim || h < 16 * decim || data.len() < w * h * step {
        return None;
    }
    let ow = (w / decim) & !1;
    let oh = (h / decim) & !1;
    let mut i420 = vec![0u8; ow * oh * 3 / 2];
    let (ypl, uv) = i420.split_at_mut(ow * oh);
    let (upl, vpl) = uv.split_at_mut(ow * oh / 4);
    for oy in 0..oh {
        let sy = oy * decim;
        for ox in 0..ow {
            let p = (sy * w + ox * decim) * step;
            let (r, g, b) = (
                data[p + ro] as i32,
                data[p + go] as i32,
                data[p + bo] as i32,
            );
            ypl[oy * ow + ox] = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16).clamp(0, 255) as u8;
            if oy % 2 == 0 && ox % 2 == 0 {
                let c = (oy / 2) * (ow / 2) + ox / 2;
                upl[c] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
                vpl[c] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
            }
        }
    }
    Some(video::Frame {
        width: ow,
        height: oh,
        i420,
    })
}

/// Rotate a tight I420 frame clockwise by 0/90/180/270 degrees. Android camera sensors
/// are landscape-mounted; the Kotlin bridge passes the rotation that makes the frame
/// upright (see `nativeVideoFrame`). Unused on desktop builds (cameras arrive upright).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn rotate_i420(frame: video::Frame, deg: u32) -> video::Frame {
    if deg == 0 || !frame.valid() {
        return frame;
    }
    let (w, h) = (frame.width, frame.height);
    fn rot_plane(src: &[u8], w: usize, h: usize, deg: u32, dst: &mut Vec<u8>) {
        match deg {
            90 => {
                // dst is h×w; dst[r][c] = src[h-1-c][r]
                for r in 0..w {
                    for c in 0..h {
                        dst.push(src[(h - 1 - c) * w + r]);
                    }
                }
            }
            180 => dst.extend(src[..w * h].iter().rev()),
            270 => {
                // dst is h×w; dst[r][c] = src[c][w-1-r]
                for r in 0..w {
                    for c in 0..h {
                        dst.push(src[c * w + (w - 1 - r)]);
                    }
                }
            }
            _ => dst.extend_from_slice(&src[..w * h]),
        }
    }
    let (cw, ch) = (w / 2, h / 2);
    let ysz = w * h;
    let csz = cw * ch;
    let mut out = Vec::with_capacity(frame.i420.len());
    rot_plane(&frame.i420[..ysz], w, h, deg, &mut out);
    rot_plane(&frame.i420[ysz..ysz + csz], cw, ch, deg, &mut out);
    rot_plane(&frame.i420[ysz + csz..ysz + 2 * csz], cw, ch, deg, &mut out);
    let (ow, oh) = if deg == 180 { (w, h) } else { (h, w) };
    video::Frame {
        width: ow,
        height: oh,
        i420: out,
    }
}

/// Decimation factor that brings `w` at or under `max_w`.
pub(crate) fn decim_for(w: usize, max_w: usize) -> usize {
    let mut d = 1;
    while w / d > max_w {
        d += 1;
    }
    d
}

/// Nearest-neighbour decimation of an I420 frame, used for the self-view thumbnail
/// (shipping the full capture resolution over IPC would be wasted bandwidth).
fn shrink_i420(f: &video::Frame, max_w: usize) -> video::Frame {
    let d = decim_for(f.width, max_w);
    if d <= 1 {
        return f.clone();
    }
    let (w, h) = (f.width, f.height);
    let ow = (w / d) & !1;
    let oh = (h / d) & !1;
    let mut out = vec![0u8; ow * oh * 3 / 2];
    let (y_src, uv_src) = f.i420.split_at(w * h);
    let (u_src, v_src) = uv_src.split_at(w * h / 4);
    let (y_dst, uv_dst) = out.split_at_mut(ow * oh);
    let (u_dst, v_dst) = uv_dst.split_at_mut(ow * oh / 4);
    for oy in 0..oh {
        for ox in 0..ow {
            y_dst[oy * ow + ox] = y_src[oy * d * w + ox * d];
        }
    }
    let (cw, ch) = (w / 2, h / 2);
    let (ocw, och) = (ow / 2, oh / 2);
    for oy in 0..och {
        let sy = (oy * d).min(ch - 1);
        for ox in 0..ocw {
            let sx = (ox * d).min(cw - 1);
            u_dst[oy * ocw + ox] = u_src[sy * cw + sx];
            v_dst[oy * ocw + ox] = v_src[sy * cw + sx];
        }
    }
    video::Frame {
        width: ow,
        height: oh,
        i420: out,
    }
}

// ── Lazy capture sources ────────────────────────────────────────────────────────────

/// Latest-frame mailbox shared between a capture thread and the engine.
struct SlotShared {
    slot: Mutex<Option<video::Frame>>,
    last_poll: Mutex<Instant>,
    running: AtomicBool,
}

impl SlotShared {
    fn new() -> Arc<SlotShared> {
        Arc::new(SlotShared {
            slot: Mutex::new(None),
            last_poll: Mutex::new(Instant::now()),
            running: AtomicBool::new(false),
        })
    }
    /// Capture threads call this to decide whether to keep going.
    fn wanted(&self) -> bool {
        self.last_poll
            .lock()
            .map(|t| t.elapsed() < CAPTURE_LINGER)
            .unwrap_or(false)
    }
    fn publish(&self, frame: video::Frame) {
        if let Ok(mut s) = self.slot.lock() {
            *s = Some(frame);
        }
    }
}

#[derive(Clone, Copy)]
enum CaptureKind {
    Camera,
    Screen,
}

/// Which screen source to capture: a specific monitor, a specific window, or the
/// primary monitor as fallback. Set by `call_set_screen` and read by the capture
/// thread at startup; changing it stops the old thread (via `running` flag) so the
/// next poll restarts capture with the new source.
#[derive(Clone, Copy, Debug, Default)]
pub enum CaptureSource {
    #[default]
    PrimaryMonitor,
    Monitor(usize),
    Window(usize),
}

/// Parse a source string like "monitor:1" or "window:5" into a CaptureSource.
/// `None` or unrecognized → PrimaryMonitor.
pub fn parse_source(s: &str) -> CaptureSource {
    let (kind, idx) = s.split_once(':').unwrap_or(("", "0"));
    let idx: usize = idx.parse().unwrap_or(0);
    match kind {
        "monitor" => CaptureSource::Monitor(idx),
        "window" => CaptureSource::Window(idx),
        _ => CaptureSource::PrimaryMonitor,
    }
}

/// List available monitors and windows for the source picker UI.
/// Returns JSON-serializable info; filters out tiny/system windows.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn list_sources() -> serde_json::Value {
    use serde_json::json;
    let monitors: Vec<serde_json::Value> = xcap::Monitor::all()
        .map(|ms| {
            ms.iter()
                .map(|m| {
                    json!({
                        "id": format!("monitor:{}", m.id().unwrap_or(0)),
                        "name": m.name().unwrap_or_default().to_string(),
                        "width": m.width().unwrap_or(0),
                        "height": m.height().unwrap_or(0),
                        "is_primary": m.is_primary().unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let windows: Vec<serde_json::Value> = xcap::Window::all()
        .map(|ws| {
            ws.iter()
                .filter(|w| {
                    let w_h = w.width().unwrap_or(0) * w.height().unwrap_or(0);
                    w_h > 100 * 100 && !w.is_minimized().unwrap_or(true)
                })
                .map(|w| {
                    json!({
                        "id": format!("window:{}", w.id().unwrap_or(0)),
                        "title": w.title().unwrap_or_default().to_string(),
                        "width": w.width().unwrap_or(0),
                        "height": w.height().unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({ "monitors": monitors, "windows": windows })
}

#[cfg(target_os = "linux")]
pub fn list_sources() -> serde_json::Value {
    use serde_json::json;
    let monitors: Vec<serde_json::Value> = (|| {
        use x11rb::connection::Connection;
        use x11rb::protocol::randr::ConnectionExt as _;
        let (conn, screen_num) = x11rb::connect(None).ok()?;
        let screen = &conn.setup().roots[screen_num];
        let mons = conn.randr_get_monitors(screen.root, true).ok()?.reply().ok()?;
        Some(mons.monitors.iter().enumerate().map(|(i, m)| {
            json!({
                "id": format!("monitor:{}", i),
                "name": format!("Display {}", i + 1),
                "width": m.width,
                "height": m.height,
                "is_primary": m.primary != 0,
            })
        }).collect())
    })().unwrap_or_default();
    json!({ "monitors": monitors, "windows": [] })
}

#[cfg(target_os = "android")]
pub fn list_sources() -> serde_json::Value {
    serde_json::json!({ "monitors": [], "windows": [] })
}

/// A [`VideoSource`] backed by a lazily-spawned platform capture thread (desktop) or
/// the Kotlin JNI bridge (Android, where the bridge fills the slot instead). Every
/// frame handed to the engine is also mirrored (throttled + shrunk) to the UI channel
/// as the user's self-view.
pub struct SlotSource {
    shared: Arc<SlotShared>,
    kind: CaptureKind,
    ui: UiChannel,
    last_preview: Instant,
    /// Screen capture source selector — shared with the command handler so
    /// `call_set_screen` can change it and the capture thread picks it up.
    screen_source: Arc<Mutex<CaptureSource>>,
}

impl SlotSource {
    pub fn camera(ui: UiChannel) -> SlotSource {
        SlotSource {
            shared: SlotShared::new(),
            kind: CaptureKind::Camera,
            ui,
            last_preview: Instant::now() - PREVIEW_INTERVAL,
            screen_source: Arc::new(Mutex::new(CaptureSource::PrimaryMonitor)),
        }
    }
    pub fn screen(ui: UiChannel, source: Arc<Mutex<CaptureSource>>) -> SlotSource {
        SlotSource {
            shared: SlotShared::new(),
            kind: CaptureKind::Screen,
            ui,
            last_preview: Instant::now() - PREVIEW_INTERVAL,
            screen_source: source,
        }
    }

    /// Mirror a captured frame to the webview as the self-view thumbnail.
    fn send_preview(&mut self, f: &video::Frame) {
        if self.last_preview.elapsed() < PREVIEW_INTERVAL {
            return;
        }
        self.last_preview = Instant::now();
        if let Ok(ch) = self.ui.lock() {
            if let Some(ch) = ch.as_ref() {
                let track = SELF_TRACK_BASE
                    + match self.kind {
                        CaptureKind::Camera => Track::Camera as u8,
                        CaptureKind::Screen => Track::Screen as u8,
                    };
                let small = shrink_i420(f, PREVIEW_MAX_W);
                let _ = ch.send(tauri::ipc::InvokeResponseBody::Raw(ui_frame(
                    track,
                    Some(&small),
                )));
            }
        }
    }
}

impl VideoSource for SlotSource {
    fn frame(&mut self) -> Option<video::Frame> {
        if let Ok(mut t) = self.shared.last_poll.lock() {
            *t = Instant::now();
        }
        #[cfg(not(target_os = "android"))]
        if !self.shared.running.swap(true, Ordering::Relaxed) {
            let shared = self.shared.clone();
            let kind = self.kind;
            let source = self.screen_source.clone();
            std::thread::Builder::new()
                .name("sona-media-capture".into())
                .spawn(move || {
                    let r = match kind {
                        CaptureKind::Camera => capture_camera(&shared),
                        CaptureKind::Screen => {
                            let src = source.lock()
                                .map(|s| *s)
                                .unwrap_or(CaptureSource::PrimaryMonitor);
                            capture_screen(&shared, src)
                        }
                    };
                    if let Err(e) = r {
                        eprintln!("[media] capture ended: {e}");
                    }
                    shared.running.store(false, Ordering::Relaxed);
                })
                .ok();
        }
        // Kotlin pushes frames over JNI into per-track slots (see android_media);
        // start/stop is driven by the toggle commands, not by polling.
        #[cfg(target_os = "android")]
        let frame = crate::android_media::take_frame(matches!(self.kind, CaptureKind::Camera));
        #[cfg(not(target_os = "android"))]
        let frame = self.shared.slot.lock().ok()?.take();
        if let Some(f) = frame.as_ref() {
            self.send_preview(f);
        }
        frame
    }
}

// ── Camera capture (desktop) ────────────────────────────────────────────────────────

#[cfg(not(target_os = "android"))]
fn capture_camera(shared: &SlotShared) -> Result<(), String> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{
        CameraFormat, CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType, Resolution,
    };
    // VGA@30 is the call target; `Closest` tolerates cameras that can't do it exactly.
    let want = RequestedFormat::new::<RgbFormat>(RequestedFormatType::Closest(CameraFormat::new(
        Resolution::new(640, 480),
        FrameFormat::MJPEG,
        30,
    )));
    let mut cam =
        nokhwa::Camera::new(CameraIndex::Index(0), want).map_err(|e| format!("no camera: {e}"))?;
    cam.open_stream()
        .map_err(|e| format!("camera stream: {e}"))?;
    while shared.wanted() {
        // Blocks at the device frame rate — that's the pacing.
        let frame = match cam.frame() {
            Ok(f) => f,
            Err(_) => break,
        };
        let Ok(img) = frame.decode_image::<RgbFormat>() else {
            continue;
        };
        let (w, h) = (img.width() as usize, img.height() as usize);
        let d = decim_for(w, 960);
        if let Some(f) = packed_to_i420(img.as_raw(), w, h, 3, (0, 1, 2), d) {
            shared.publish(f);
        }
    }
    let _ = cam.stop_stream();
    Ok(())
}

// ── Screen capture ──────────────────────────────────────────────────────────────────

/// Screen share frame rate. With hardware encoding (NVENC/VCN/QuickSync) the GPU
/// handles 60 fps at <5% usage; without it the software fallback (OpenH264) runs at
/// a conservative 20 fps to avoid saturating the CPU.
#[cfg(not(target_os = "android"))]
const SCREEN_FPS_INTERVAL: Duration = Duration::from_millis(16); // ~60 fps

/// Linux/X11: grab the specified monitor via pure-Rust XCB. No system deps beyond the X
/// server itself. (Wayland sessions need the PipeWire portal — not wired yet.)
#[cfg(target_os = "linux")]
fn capture_screen(shared: &SlotShared, source: CaptureSource) -> Result<(), String> {
    use x11rb::connection::Connection;
    use x11rb::protocol::randr::ConnectionExt as _;
    use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat};

    let (conn, screen_num) = x11rb::connect(None).map_err(|e| format!("X11: {e}"))?;
    let screen = &conn.setup().roots[screen_num];
    let monitors = conn
        .randr_get_monitors(screen.root, true)
        .map_err(|e| e.to_string())?
        .reply()
        .map_err(|e| format!("randr: {e}"))?;
    let mon = match source {
        CaptureSource::Monitor(idx) => monitors
            .monitors
            .get(idx)
            .ok_or("monitor index out of range")?,
        _ => monitors
            .monitors
            .iter()
            .find(|m| m.primary)
            .or_else(|| monitors.monitors.first())
            .ok_or("no monitor")?,
    };
    let (mx, my, mw, mh) = (mon.x, mon.y, mon.width, mon.height);

    while shared.wanted() {
        let t = Instant::now();
        let img = conn
            .get_image(ImageFormat::Z_PIXMAP, screen.root, mx, my, mw, mh, !0)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| format!("get_image: {e}"))?;
        // Z_PIXMAP depth-24 on little-endian X: B,G,R,X per pixel.
        let d = decim_for(mw as usize, 1920);
        if let Some(f) = packed_to_i420(&img.data, mw as usize, mh as usize, 4, (2, 1, 0), d) {
            shared.publish(f);
        }
        std::thread::sleep(SCREEN_FPS_INTERVAL.saturating_sub(t.elapsed()));
    }
    Ok(())
}

/// Windows/macOS: `xcap` (Windows Graphics Capture / CoreGraphics).
/// Supports monitor selection and window capture (game windows in borderless
/// fullscreen are visible via Windows Graphics Capture's swap-chain capture).
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn capture_screen(shared: &SlotShared, source: CaptureSource) -> Result<(), String> {
    match source {
        CaptureSource::PrimaryMonitor => {
            let monitors = xcap::Monitor::all().map_err(|e| e.to_string())?;
            let mon = monitors
                .iter()
                .find(|m| m.is_primary().unwrap_or(false))
                .or_else(|| monitors.first())
                .ok_or("no monitor")?;
            capture_xcap_monitor(shared, mon)
        }
        CaptureSource::Monitor(idx) => {
            let monitors = xcap::Monitor::all().map_err(|e| e.to_string())?;
            let mon = monitors.get(idx).ok_or("monitor index out of range")?;
            capture_xcap_monitor(shared, mon)
        }
        CaptureSource::Window(idx) => {
            let windows = xcap::Window::all().map_err(|e| e.to_string())?;
            let win = windows.get(idx).ok_or("window index out of range")?;
            while shared.wanted() {
                let t = Instant::now();
                let img = win.capture_image().map_err(|e| e.to_string())?;
                let (w, h) = (img.width() as usize, img.height() as usize);
                let d = decim_for(w, 1920);
                if let Some(f) = packed_to_i420(img.as_raw(), w, h, 4, (0, 1, 2), d) {
                    shared.publish(f);
                }
                std::thread::sleep(SCREEN_FPS_INTERVAL.saturating_sub(t.elapsed()));
            }
            Ok(())
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn capture_xcap_monitor(shared: &SlotShared, mon: &xcap::Monitor) -> Result<(), String> {
    while shared.wanted() {
        let t = Instant::now();
        let img = mon.capture_image().map_err(|e| e.to_string())?;
        let (w, h) = (img.width() as usize, img.height() as usize);
        let d = decim_for(w, 1920);
        if let Some(f) = packed_to_i420(img.as_raw(), w, h, 4, (0, 1, 2), d) {
            shared.publish(f);
        }
        std::thread::sleep(SCREEN_FPS_INTERVAL.saturating_sub(t.elapsed()));
    }
    Ok(())
}

// ── Screen audio (system sound) ─────────────────────────────────────────────────────

/// Where system-audio capture comes from on this platform, if anywhere.
///
/// * Windows: WASAPI loopback — an *input* stream opened on the default *output*
///   device captures what the machine is playing.
/// * Linux: the sound server's "monitor" source of the default sink, reached through
///   cpal's PulseAudio host (see [`pulse_monitor_source`]). Plain-ALSA setups have
///   none unless a capture device calls itself a monitor.
/// * macOS: no OS loopback without a virtual driver — unavailable.
#[cfg(not(target_os = "android"))]
fn system_audio_device() -> Option<cpal::Device> {
    #[cfg(target_os = "windows")]
    {
        use cpal::traits::HostTrait;
        cpal::default_host().default_output_device()
    }
    #[cfg(not(target_os = "windows"))]
    {
        use cpal::traits::{DeviceTrait, HostTrait};
        #[cfg(target_os = "linux")]
        if let Some(d) = pulse_monitor_source() {
            return Some(d);
        }
        // Plain-ALSA (or exotic) setups: fall back to any capture device that
        // describes itself as a monitor.
        cpal::default_host().input_devices().ok()?.find(|d| {
            d.description()
                .map(|desc| desc.name().to_lowercase().contains("monitor"))
                .unwrap_or(false)
        })
    }
}

/// Monitor source of the default sink via cpal's PulseAudio host. The default (ALSA)
/// host cannot enumerate monitor sources at all — this is the path that actually
/// works on stock Pulse and PipeWire (pipewire-pulse) desktops.
#[cfg(target_os = "linux")]
fn pulse_monitor_source() -> Option<cpal::Device> {
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::host_from_id(cpal::HostId::PulseAudio).ok()?;
    // Pulse names the default sink's monitor "<sink>.monitor"; prefer it so the
    // shared audio follows what the user actually hears.
    let want = host
        .default_output_device()
        .and_then(|d| d.id().ok())
        .map(|id| format!("{}.monitor", id.id()));
    let mut first = None;
    for d in host.input_devices().ok()? {
        let Ok(id) = d.id() else { continue };
        if !id.id().ends_with(".monitor") {
            continue;
        }
        if want.as_deref() == Some(id.id()) {
            return Some(d);
        }
        first.get_or_insert(d);
    }
    first
}

/// Can this machine share system audio? (UI greys the toggle out when false.)
///
/// Cached: probing means connecting to the sound server, and `call_status` asks on
/// every refresh. Whether a loopback/monitor source exists is static for the life of
/// the process for all practical purposes.
pub fn screen_audio_available() -> bool {
    #[cfg(target_os = "android")]
    {
        true // AudioPlaybackCapture rides the MediaProjection (Android 10+)
    }
    #[cfg(not(target_os = "android"))]
    {
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *AVAILABLE.get_or_init(|| system_audio_device().is_some())
    }
}

/// [`ScreenAudioSource`] backed by a lazily-started system-audio stream. Same
/// linger/watchdog pattern as video capture.
pub struct SystemAudioSource {
    rx: Option<Receiver<[i16; SCREEN_AUDIO_SAMPLES]>>,
    last_poll: Arc<Mutex<Instant>>,
    running: Arc<AtomicBool>,
}

impl SystemAudioSource {
    pub fn new() -> SystemAudioSource {
        SystemAudioSource {
            rx: None,
            last_poll: Arc::new(Mutex::new(Instant::now())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ScreenAudioSource for SystemAudioSource {
    fn read_frame(&mut self, buf: &mut [i16; SCREEN_AUDIO_SAMPLES]) -> bool {
        if let Ok(mut t) = self.last_poll.lock() {
            *t = Instant::now();
        }
        #[cfg(not(target_os = "android"))]
        if !self.running.swap(true, Ordering::Relaxed) {
            let (tx, rx) = sync_channel::<[i16; SCREEN_AUDIO_SAMPLES]>(8);
            self.rx = Some(rx);
            let last_poll = self.last_poll.clone();
            let running = self.running.clone();
            std::thread::Builder::new()
                .name("sona-sysaudio".into())
                .spawn(move || {
                    if let Err(e) = system_audio_thread(tx, last_poll) {
                        eprintln!("[media] system audio ended: {e}");
                    }
                    running.store(false, Ordering::Relaxed);
                })
                .ok();
        }
        #[cfg(target_os = "android")]
        {
            return crate::android_media::read_system_audio(buf);
        }
        #[cfg(not(target_os = "android"))]
        match self.rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            Some(frame) => {
                *buf = frame;
                true
            }
            None => false, // warming up / nothing playing → engine sends silence
        }
    }
}

/// Capture system audio → 48 kHz stereo 20 ms frames until polls stop.
#[cfg(not(target_os = "android"))]
fn system_audio_thread(
    tx: SyncSender<[i16; SCREEN_AUDIO_SAMPLES]>,
    last_poll: Arc<Mutex<Instant>>,
) -> Result<(), String> {
    use cpal::traits::{DeviceTrait, StreamTrait};

    let device = system_audio_device().ok_or("no system-audio source on this platform")?;
    // Windows: loopback needs the device's *output* config; elsewhere it's an input.
    #[cfg(target_os = "windows")]
    let cfg = device.default_output_config().map_err(|e| e.to_string())?;
    #[cfg(not(target_os = "windows"))]
    let cfg = device.default_input_config().map_err(|e| e.to_string())?;
    let rate = cfg.sample_rate();
    let ch = cfg.channels() as usize;

    fn build<T>(
        device: &cpal::Device,
        cfg: cpal::StreamConfig,
        ch: usize,
        rate: u32,
        tx: SyncSender<[i16; SCREEN_AUDIO_SAMPLES]>,
    ) -> Result<cpal::Stream, String>
    where
        T: cpal::SizedSample,
        f32: cpal::FromSample<T>,
    {
        use client_core::call::{SAMPLES_PER_FRAME, SAMPLE_RATE};
        let mut left = Vec::<f32>::new();
        let mut right = Vec::<f32>::new();
        let mut l48 = Vec::<f32>::new();
        let mut r48 = Vec::<f32>::new();
        let mut pending = Vec::<i16>::new(); // interleaved stereo @48k
        device
            .build_input_stream(
                cfg,
                move |data: &[T], _| {
                    use cpal::Sample as _;
                    left.clear();
                    right.clear();
                    for frame in data.chunks(ch) {
                        let l = f32::from_sample(frame[0]);
                        let r = f32::from_sample(*frame.get(1).unwrap_or(&frame[0]));
                        left.push(l);
                        right.push(r);
                    }
                    crate::audio::resample(&left, rate, SAMPLE_RATE, &mut l48);
                    crate::audio::resample(&right, rate, SAMPLE_RATE, &mut r48);
                    for i in 0..l48.len().min(r48.len()) {
                        pending.push((l48[i].clamp(-1.0, 1.0) * 32767.0) as i16);
                        pending.push((r48[i].clamp(-1.0, 1.0) * 32767.0) as i16);
                    }
                    while pending.len() >= SAMPLES_PER_FRAME * 2 {
                        let mut out = [0i16; SCREEN_AUDIO_SAMPLES];
                        out.copy_from_slice(&pending[..SAMPLES_PER_FRAME * 2]);
                        pending.drain(..SAMPLES_PER_FRAME * 2);
                        let _ = tx.try_send(out); // full → drop; latency beats backlog
                    }
                },
                |e| eprintln!("[media] system audio error: {e}"),
                None,
            )
            .map_err(|e| format!("system audio stream: {e}"))
    }

    let stream = match cfg.sample_format() {
        cpal::SampleFormat::F32 => build::<f32>(&device, cfg.into(), ch, rate, tx)?,
        cpal::SampleFormat::F64 => build::<f64>(&device, cfg.into(), ch, rate, tx)?,
        cpal::SampleFormat::I16 => build::<i16>(&device, cfg.into(), ch, rate, tx)?,
        cpal::SampleFormat::U16 => build::<u16>(&device, cfg.into(), ch, rate, tx)?,
        // The PulseAudio host's monitor sources default to I32 on PipeWire boxes.
        cpal::SampleFormat::I32 => build::<i32>(&device, cfg.into(), ch, rate, tx)?,
        cpal::SampleFormat::U32 => build::<u32>(&device, cfg.into(), ch, rate, tx)?,
        other => return Err(format!("unsupported sample format {other:?}")),
    };
    stream.play().map_err(|e| e.to_string())?;
    while last_poll
        .lock()
        .map(|t| t.elapsed() < CAPTURE_LINGER)
        .unwrap_or(false)
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

// ── Sink: decoded peer media → UI channel + speaker mixer ───────────────────────────

/// Wire format of one UI video message: `track(1) || w(2 BE) || h(2 BE) || I420`.
/// `w == h == 0` means "track off — hide the tile". The UI feeds the planes straight
/// into a WebGL YUV shader; nothing is re-encoded. `track` is a raw byte: real
/// [`Track`] ids for peer media, [`SELF_TRACK_BASE`]-offset ids for the self-view.
fn ui_frame(track: u8, frame: Option<&video::Frame>) -> Vec<u8> {
    let (w, h, planes): (u16, u16, &[u8]) = match frame {
        Some(f) => (f.width as u16, f.height as u16, &f.i420),
        None => (0, 0, &[]),
    };
    let mut msg = Vec::with_capacity(5 + planes.len());
    msg.push(track);
    msg.extend_from_slice(&w.to_be_bytes());
    msg.extend_from_slice(&h.to_be_bytes());
    msg.extend_from_slice(planes);
    msg
}

/// Live handle the UI (re)binds its IPC channel to; survives webview reloads.
pub type UiChannel = Arc<Mutex<Option<tauri::ipc::Channel<tauri::ipc::InvokeResponseBody>>>>;

/// [`MediaSink`] pushing video to the webview and screen audio into the speaker mix.
pub struct ShellSink {
    pub ui: UiChannel,
    /// Into the playout mixer in `audio.rs` (summed with the peer's voice).
    pub aux: SyncSender<[i16; SCREEN_AUDIO_SAMPLES]>,
}

impl MediaSink for ShellSink {
    fn video(&mut self, track: Track, frame: video::Frame) {
        if let Ok(ch) = self.ui.lock() {
            if let Some(ch) = ch.as_ref() {
                let _ = ch.send(tauri::ipc::InvokeResponseBody::Raw(ui_frame(
                    track as u8,
                    Some(&frame),
                )));
            }
        }
    }
    fn video_off(&mut self, track: Track) {
        if let Ok(ch) = self.ui.lock() {
            if let Some(ch) = ch.as_ref() {
                let _ = ch.send(tauri::ipc::InvokeResponseBody::Raw(ui_frame(
                    track as u8,
                    None,
                )));
            }
        }
    }
    fn screen_audio(&mut self, pcm: &[i16; SCREEN_AUDIO_SAMPLES]) {
        let _ = self.aux.try_send(*pcm); // mixer full → drop late audio
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: usize, h: usize) -> video::Frame {
        let mut i420 = vec![0u8; w * h * 3 / 2];
        for (i, b) in i420.iter_mut().enumerate() {
            *b = (i % 251) as u8; // non-power-of-two modulus: no accidental symmetry
        }
        video::Frame {
            width: w,
            height: h,
            i420,
        }
    }

    #[test]
    fn rotate_90_moves_top_row_to_right_column() {
        let (w, h) = (32, 16);
        let mut f = frame(w, h);
        for x in 0..w {
            f.i420[x] = 255; // paint the top Y row
        }
        let r = rotate_i420(f, 90);
        assert_eq!((r.width, r.height), (h, w));
        assert!(r.valid());
        for row in 0..r.height {
            assert_eq!(r.i420[row * r.width + (r.width - 1)], 255);
        }
    }

    #[test]
    fn four_quarter_turns_are_identity_and_two_are_a_half_turn() {
        let same = |a: &video::Frame, b: &video::Frame| {
            a.width == b.width && a.height == b.height && a.i420 == b.i420
        };
        let f = frame(32, 16);
        let two = rotate_i420(rotate_i420(f.clone(), 90), 90);
        assert!(same(&two, &rotate_i420(f.clone(), 180)));
        let four = rotate_i420(rotate_i420(two, 90), 90);
        assert!(same(&four, &f));
        assert!(same(&rotate_i420(rotate_i420(f.clone(), 270), 90), &f));
    }

    #[test]
    fn i420_conversion_shapes_and_decimation() {
        let (w, h) = (64usize, 48usize);
        let rgb = vec![200u8; w * h * 3];
        let f = packed_to_i420(&rgb, w, h, 3, (0, 1, 2), 1).unwrap();
        assert_eq!((f.width, f.height), (64, 48));
        assert!(f.valid());
        let f2 = packed_to_i420(&rgb, w, h, 3, (0, 1, 2), 2).unwrap();
        assert_eq!((f2.width, f2.height), (32, 24));
        // Grey input → mid chroma, bright luma.
        assert!(f.i420[0] > 150);
        let c = f.i420[w * h];
        assert!((120..=136).contains(&c));
        // Undersized buffer refused.
        assert!(packed_to_i420(&rgb[..10], w, h, 3, (0, 1, 2), 1).is_none());
    }

    #[test]
    fn decimation_targets() {
        assert_eq!(decim_for(640, 960), 1);
        assert_eq!(decim_for(1920, 960), 2);
        assert_eq!(decim_for(3840, 1920), 2);
        assert_eq!(decim_for(1920, 1920), 1);
    }

    #[test]
    fn ui_frame_layout() {
        let f = video::Frame {
            width: 32,
            height: 16,
            i420: vec![7u8; 32 * 16 * 3 / 2],
        };
        let m = ui_frame(Track::Camera as u8, Some(&f));
        assert_eq!(m[0], Track::Camera as u8);
        assert_eq!(u16::from_be_bytes([m[1], m[2]]), 32);
        assert_eq!(u16::from_be_bytes([m[3], m[4]]), 16);
        assert_eq!(m.len(), 5 + 32 * 16 * 3 / 2);
        let off = ui_frame(Track::Screen as u8, None);
        assert_eq!(off.len(), 5);
        assert_eq!(&off[1..5], &[0, 0, 0, 0]);
    }

    #[test]
    fn shrink_preserves_shape_and_passthrough() {
        let f = video::Frame {
            width: 640,
            height: 480,
            i420: vec![90u8; 640 * 480 * 3 / 2],
        };
        let s = shrink_i420(&f, 480);
        assert_eq!((s.width, s.height), (320, 240));
        assert!(s.valid());
        assert!(s.i420.iter().all(|&b| b == 90));
        // Already small enough → untouched copy.
        let p = shrink_i420(&f, 640);
        assert_eq!((p.width, p.height), (640, 480));
    }
}
