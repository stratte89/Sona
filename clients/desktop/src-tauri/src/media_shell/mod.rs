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
//! * screen — X11 `GetImage` via pure-Rust `x11rb` on Linux, through the MIT-SHM
//!   extension where the server offers it (Wayland needs a PipeWire portal — not
//!   wired yet, see the README); `xcap` on Windows/macOS
//! * screen audio — cpal: WASAPI loopback on Windows (input stream on the output
//!   device), a PulseAudio/PipeWire "monitor" input on Linux when one is exposed;
//!   absent otherwise and the toggle reports unavailable rather than failing the share
//! * Android — capture comes from Kotlin bridges over JNI (see `android_media`); the
//!   same sources read frames from the JNI slots instead of spawning threads.
//!
//! Desktop shares are *targeted*: the user picks a monitor or a single application
//! window before the share starts ([`ScreenTarget`], [`screen_sources`]). Sharing
//! whichever monitor the platform calls primary is the wrong guess on any multi-head
//! desk — the game is on the other screen.

//! The pieces live in submodules by device: [`pixels`] (colour conversion shared by
//! all of them), [`camera`], [`screen`] (+ its X11 backend), and [`sysaudio`]. What
//! stays here is what they have in common — the lazy capture-thread mailbox every
//! video source is built on, and the sink that pushes decoded peer media out.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use client_core::media::{video, MediaSink, Track, VideoSource, SCREEN_AUDIO_SAMPLES};

// Which sink our playout uses, PulseAudio only (see the module docs).
#[cfg(target_os = "linux")]
mod appaudio;
mod camera;
// A local harness for the screen-share echo canceller: real playout, real monitor
// capture, real suppressor, on whatever machine runs the tests.
#[cfg(all(test, target_os = "linux"))]
mod echo_loopback_test;
// Is the captured timeline the same timeline the reference describes? Splits "these two
// signals do not correlate" into its two possible causes.
#[cfg(all(test, target_os = "linux"))]
mod echo_timebase_test;
mod pixels;
mod screen;
mod sysaudio;

use pixels::shrink_i420;
// The capture threads are desktop-only: on Android the Kotlin bridge fills the frame
// slots over JNI and there is nothing for `SlotSource` to spawn.
#[cfg(not(target_os = "android"))]
use camera::capture_camera;
#[cfg(not(target_os = "android"))]
use screen::capture_screen;

// Android feeds its JNI frames through the same conversion the desktop capture paths
// use; on desktop those callers are inside this module already.
#[cfg(not(target_os = "android"))]
pub use camera::{list_cameras, pinned_camera, set_camera};
#[cfg(target_os = "android")]
pub(crate) use pixels::{decim_for, packed_to_i420, rotate_i420};
#[cfg(not(target_os = "android"))]
pub use screen::screen_sources;
pub use screen::{set_screen_target, ScreenTarget};
pub use sysaudio::{screen_audio_available, SystemAudioSource};

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

/// Width cap for the peer's frames on their way to the webview. Not an encode setting —
/// the wire still carries whatever the sender chose — only a bound on what the display
/// path has to move, which is the thing that could not keep up. See [`ShellSink::video`].
const PEER_MAX_W: usize = 1280;

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

/// A [`VideoSource`] backed by a lazily-spawned platform capture thread (desktop) or
/// the Kotlin JNI bridge (Android, where the bridge fills the slot instead). Every
/// frame handed to the engine is also mirrored (throttled + shrunk) to the UI channel
/// as the user's self-view.
pub struct SlotSource {
    shared: Arc<SlotShared>,
    kind: CaptureKind,
    ui: UiChannel,
    last_preview: Instant,
    screen_width: Option<Arc<std::sync::atomic::AtomicU32>>,
}

impl SlotSource {
    pub fn camera(ui: UiChannel) -> SlotSource {
        SlotSource {
            shared: SlotShared::new(),
            kind: CaptureKind::Camera,
            ui,
            last_preview: Instant::now() - PREVIEW_INTERVAL,
            screen_width: None,
        }
    }
    /// `width` is the encode governor's target capture width (see
    /// `client_core::media::SCREEN_WIDTHS`): it drops when the machine cannot encode
    /// full resolution inside its CPU budget, and the capture follows it live.
    pub fn screen(ui: UiChannel, width: Arc<std::sync::atomic::AtomicU32>) -> SlotSource {
        SlotSource {
            shared: SlotShared::new(),
            kind: CaptureKind::Screen,
            ui,
            last_preview: Instant::now() - PREVIEW_INTERVAL,
            screen_width: Some(width),
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
            let width = self.screen_width.clone();
            std::thread::Builder::new()
                .name("sona-media-capture".into())
                .spawn(move || {
                    let r = match kind {
                        CaptureKind::Camera => capture_camera(&shared),
                        CaptureKind::Screen => capture_screen(&shared, width),
                    };
                    if let Err(e) = r {
                        crate::diag!("[media] capture ended: {e}");
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

/// Flow control for peer frames on their way to the webview.
///
/// The webview acknowledges each frame once it has painted it ([`crate::call::cmd`]'s
/// `call_frame_ack`), which is the only signal available that it has actually consumed
/// one — Tauri's channel is fire-and-forget and its pending-payload map is unbounded.
pub mod frames {
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Frames allowed in flight *per track*. Two: one being painted, one already on its
    /// way, which keeps the pipe busy without letting a backlog form. At 1080p this caps
    /// what the delivery path can be holding at ~6 MB per track.
    ///
    /// Per track, not per call, because camera and screen can both be live and a shared
    /// budget would make each starve the other — two tracks against two credits is one
    /// each, and a frame that loses the race is simply dropped.
    const MAX_IN_FLIGHT: u32 = 2;
    /// After this long an unacknowledged frame is written off. Acks can genuinely go
    /// missing — a webview reload drops whatever it had in hand — and without this the
    /// counter would never come back down and video would stop for the rest of the call.
    const ACK_TIMEOUT: Duration = Duration::from_secs(1);

    /// Indexed by [`super::Track`] id; only camera (1) and screen (2) are ever used.
    const TRACKS: usize = 4;
    static IN_FLIGHT: [AtomicU32; TRACKS] = [
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
    ];
    /// Millis since the epoch of the oldest unacknowledged send, per track.
    static SINCE: [AtomicU64; TRACKS] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn slot(track: u8) -> usize {
        (track as usize).min(TRACKS - 1)
    }

    /// Claim a slot for one frame of `track`, or refuse. `false` = drop the frame.
    pub fn reserve(track: u8) -> bool {
        let i = slot(track);
        if IN_FLIGHT[i].load(Ordering::Relaxed) >= MAX_IN_FLIGHT {
            let waited = now_ms().saturating_sub(SINCE[i].load(Ordering::Relaxed));
            if waited < ACK_TIMEOUT.as_millis() as u64 {
                return false;
            }
            // Stuck: the acks are not coming. Forget them and start again rather than
            // leave the tile frozen.
            IN_FLIGHT[i].store(0, Ordering::Relaxed);
        }
        if IN_FLIGHT[i].fetch_add(1, Ordering::Relaxed) == 0 {
            SINCE[i].store(now_ms(), Ordering::Relaxed);
        }
        true
    }

    /// One frame painted (or a send that never happened).
    pub fn release(track: u8) {
        let i = slot(track);
        let _ = IN_FLIGHT[i].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            Some(n.saturating_sub(1))
        });
        SINCE[i].store(now_ms(), Ordering::Relaxed);
    }

    /// Forget everything outstanding — the webview just (re)bound its channel, so nothing
    /// sent before this point is ever going to be acknowledged.
    pub fn reset() {
        for i in 0..TRACKS {
            IN_FLIGHT[i].store(0, Ordering::Relaxed);
            SINCE[i].store(now_ms(), Ordering::Relaxed);
        }
    }
}

/// Live handle the UI (re)binds its IPC channel to; survives webview reloads.
pub type UiChannel = Arc<Mutex<Option<tauri::ipc::Channel<tauri::ipc::InvokeResponseBody>>>>;

/// [`MediaSink`] pushing video to the webview and screen audio into the speaker mix.
pub struct ShellSink {
    pub ui: UiChannel,
    /// Into the playout mixer in `audio.rs` (summed with the peer's voice).
    pub aux: crate::audio::AuxSink,
}

impl MediaSink for ShellSink {
    fn video(&mut self, track: Track, frame: video::Frame) {
        // Do not hand the webview a frame while it still owes us for the last ones.
        //
        // A 1080p I420 frame is 3.1 MB, and Tauri delivers a payload this size by parking
        // it in a process-wide map and asking the webview to come and fetch it. That map
        // is unbounded. Sending unconditionally at 20 fps therefore does not "run slowly"
        // when the webview cannot keep up — it accumulates 62 MB a second of frames nobody
        // has collected, until the UI stops responding and the process dies. Both ends of
        // a call saw exactly that, and only once a hardware encoder started delivering a
        // real 20 fps: the software encoder had been rate-limiting this path by accident.
        //
        // The self-view beside this has always been throttled and shrunk; peer frames were
        // the one video path with no limit of any kind on them.
        if !frames::reserve(track as u8) {
            return; // webview is behind — drop this frame, keep the newest
        }
        // Shrink before crossing to the webview. The credit above stops a slow webview
        // from being buried, but dropping frames is how it pays for that, and the reported
        // result was exactly what that trades for: no more freezing, plenty of choppiness.
        // Every megabyte here costs the delivery path twice — once to hand over, once to
        // fetch — so a 1080p frame at 3.1 MB is most of the reason the webview cannot keep
        // up in the first place. At [`PEER_MAX_W`] it is 1.4 MB and the same webview paints
        // more than twice as many of them.
        //
        // The cost is sharpness on a full-screen share of small text, which is real; the
        // benefit is a share that moves. A frozen sharp frame is worth less than a soft
        // moving one, and the encoder still sends full resolution — this is only what the
        // *display* path carries.
        let frame = if frame.width > PEER_MAX_W {
            shrink_i420(&frame, PEER_MAX_W)
        } else {
            frame
        };
        if let Ok(ch) = self.ui.lock() {
            if let Some(ch) = ch.as_ref() {
                let _ = ch.send(tauri::ipc::InvokeResponseBody::Raw(ui_frame(
                    track as u8,
                    Some(&frame),
                )));
                return;
            }
        }
        frames::release(track as u8); // no channel bound; reservation unspent
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
        self.aux.push(*pcm); // mixer full → the oldest frame goes, not this one
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
