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

mod camera;
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
    pub aux: crate::audio::AuxSink,
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
