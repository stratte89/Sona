//! What a screen share points at, how the picker lists the options, and the capture
//! loops that pull frames from the chosen one. The X11 backend lives in [`x11`].

use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::pixels::{decim_for, packed_to_i420};
use super::SlotShared;

#[cfg(target_os = "linux")]
mod x11;

/// What the screen-share track points at.
///
/// The default is the platform's primary monitor — the behaviour before there was a
/// picker, what Android (a single MediaProjection of the whole device) always does, and
/// the only sane fallback when a chosen window closes mid-share.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ScreenTarget {
    #[default]
    Primary,
    /// A monitor, by platform id (RandR monitor index on X11, `xcap` id elsewhere).
    Screen(u32),
    /// A single application window, by platform id (X11 window / HWND / CGWindowID).
    Window(u32),
}

#[cfg(not(target_os = "android"))]
static TARGET: Mutex<ScreenTarget> = Mutex::new(ScreenTarget::Primary);
/// Bumped on every change so a running capture loop notices without holding a lock per
/// frame — and so the *same* target picked twice still re-resolves (a window may have
/// moved to another monitor, a monitor may have been re-plugged).
#[cfg(not(target_os = "android"))]
static TARGET_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Point the next (or current) share at a source. Android ignores this: its share is
/// the whole device, granted by the MediaProjection consent dialog.
pub fn set_screen_target(t: ScreenTarget) {
    #[cfg(not(target_os = "android"))]
    {
        if let Ok(mut cur) = TARGET.lock() {
            *cur = t;
        }
        TARGET_EPOCH.fetch_add(1, Ordering::SeqCst);
    }
    #[cfg(target_os = "android")]
    let _ = t;
}

#[cfg(not(target_os = "android"))]
fn screen_target() -> ScreenTarget {
    TARGET.lock().map(|t| *t).unwrap_or_default()
}

/// One pickable share source, with a still preview for the picker.
#[cfg(not(target_os = "android"))]
#[derive(serde::Serialize)]
pub struct ScreenSourceView {
    /// `"screen"` or `"window"`.
    pub kind: &'static str,
    pub id: u32,
    pub name: String,
    /// Secondary line: the monitor's resolution, or the window's application.
    pub detail: String,
    /// `data:image/png;base64,…` preview, or empty when the grab failed (the row is
    /// still offered — a preview that could not be taken is not a source that cannot
    /// be shared).
    pub thumb: String,
    pub primary: bool,
}

/// Split a window's application name and title into the picker's two lines, leading
/// with whichever one is actually there.
///
/// The application comes from the platform in whatever case it stores it (X11's
/// `WM_CLASS` is usually all lowercase — `firefox`, `discord`), so the first letter is
/// raised; nothing else is touched, because guessing further turns `jetbrains-webstorm`
/// into something no more readable and risks mangling names that were already right.
#[cfg(not(target_os = "android"))]
fn window_labels(app: &str, title: &str) -> (String, String) {
    let (app, title) = (app.trim(), title.trim());
    if app.is_empty() {
        return (title.to_string(), String::new());
    }
    let mut chars = app.chars();
    let name = match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    };
    (name, title.to_string())
}

/// Longest edge of a picker preview. Small on purpose: the whole list is one IPC
/// message, and these are thumbnails behind a 220 px card.
#[cfg(not(target_os = "android"))]
const THUMB_W: usize = 320;

/// Nearest-neighbour downscale to RGB, then PNG, then a data URL. Nearest-neighbour
/// keeps window text legible at thumbnail size where a box filter turns it to mush.
#[cfg(not(target_os = "android"))]
fn thumb_png(
    data: &[u8],
    w: usize,
    h: usize,
    step: usize,
    (ro, go, bo): (usize, usize, usize),
) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if w == 0 || h == 0 || data.len() < w * h * step {
        return String::new();
    }
    let d = decim_for(w, THUMB_W).max(1);
    let (tw, th) = ((w / d).max(1), (h / d).max(1));
    let mut rgb = Vec::with_capacity(tw * th * 3);
    for y in 0..th {
        let src = &data[(y * d) * w * step..(y * d + 1) * w * step];
        for x in 0..tw {
            let p = x * d * step;
            rgb.extend_from_slice(&[src[p + ro], src[p + go], src[p + bo]]);
        }
    }
    let mut png = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut png, tw as u32, th as u32);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Fast);
        let Ok(mut writer) = enc.write_header() else {
            return String::new();
        };
        if writer.write_image_data(&rgb).is_err() {
            return String::new();
        }
    }
    format!("data:image/png;base64,{}", STANDARD.encode(&png))
}

/// Everything the user could share right now: every monitor, then every ordinary
/// application window, each with a preview. Best-effort throughout — one unreadable
/// window must not empty the picker.
#[cfg(not(target_os = "android"))]
pub fn screen_sources() -> Result<Vec<ScreenSourceView>, String> {
    #[cfg(target_os = "linux")]
    {
        x11::sources()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut out = Vec::new();
        for (i, m) in xcap::Monitor::all()
            .map_err(|e| e.to_string())?
            .iter()
            .enumerate()
        {
            let (w, h) = (m.width().unwrap_or(0), m.height().unwrap_or(0));
            let thumb = m
                .capture_image()
                .ok()
                .map(|img| {
                    thumb_png(
                        img.as_raw(),
                        img.width() as usize,
                        img.height() as usize,
                        4,
                        (0, 1, 2),
                    )
                })
                .unwrap_or_default();
            out.push(ScreenSourceView {
                kind: "screen",
                id: m.id().unwrap_or(i as u32),
                name: format!("Screen {}", i + 1),
                detail: m
                    .friendly_name()
                    .ok()
                    .filter(|n| !n.is_empty())
                    .map(|n| format!("{n} · {w}×{h}"))
                    .unwrap_or_else(|| format!("{w}×{h}")),
                thumb,
                primary: m.is_primary().unwrap_or(false),
            });
        }
        for win in xcap::Window::all().map_err(|e| e.to_string())?.iter() {
            if win.is_minimized().unwrap_or(false) {
                continue;
            }
            let (w, h) = (win.width().unwrap_or(0), win.height().unwrap_or(0));
            if w < 96 || h < 96 {
                continue;
            }
            let title = win.title().unwrap_or_default();
            let app = win.app_name().unwrap_or_default();
            if title.trim().is_empty() && app.trim().is_empty() {
                continue;
            }
            let thumb = win
                .capture_image()
                .ok()
                .map(|img| {
                    thumb_png(
                        img.as_raw(),
                        img.width() as usize,
                        img.height() as usize,
                        4,
                        (0, 1, 2),
                    )
                })
                .unwrap_or_default();
            let Ok(id) = win.id() else { continue };
            let (name, detail) = window_labels(&app, &title);
            out.push(ScreenSourceView {
                kind: "window",
                id,
                name,
                detail,
                thumb,
                primary: false,
            });
        }
        Ok(out)
    }
}

// ── Screen capture: pulling frames ──────────────────────────────────────────────────

/// Screen share frame interval (20 fps). Motion — which is what people actually share,
/// games included — reads as "laggy" long before it reads as "low resolution", and the
/// encoder is threaded, so the frames are affordable. Matches
/// [`video::SCREEN_MAX_FPS`]; the rate controller drops what it cannot afford.
#[cfg(not(target_os = "android"))]
const SCREEN_FPS_INTERVAL: Duration = Duration::from_millis(50);

/// Widest frame handed to the encoder when nothing is throttling us. Beyond this the
/// source is decimated: 4K of pixels at screen-share bitrates is a blur, and it costs
/// capture, colour-conversion and encode time to produce. The encode governor lowers
/// the live target below this when the machine cannot keep up
/// (`client_core::media::SCREEN_WIDTHS`).
#[cfg(not(target_os = "android"))]
const SCREEN_MAX_W: usize = 1920;

/// The governor's current target, or [`SCREEN_MAX_W`] when there is none.
#[cfg(not(target_os = "android"))]
fn target_width(width: &Option<std::sync::Arc<std::sync::atomic::AtomicU32>>) -> usize {
    width
        .as_ref()
        .map(|w| w.load(Ordering::Relaxed) as usize)
        .filter(|w| *w > 0)
        .unwrap_or(SCREEN_MAX_W)
}

/// Linux/X11: grab the chosen monitor or window via pure-Rust XCB. No system deps
/// beyond the X server itself. (Wayland sessions need the PipeWire portal — not wired
/// yet.)
#[cfg(target_os = "linux")]
pub(super) fn capture_screen(
    shared: &SlotShared,
    width: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
) -> Result<(), String> {
    /// Consecutive failed grabs before a shared window is written off. X11 refuses to
    /// read a window that has been minimised or dragged off the visible screen
    /// (`BadMatch`), and that is a state the user can leave as fast as they entered it
    /// — so tolerate a second of it rather than tearing their share down over a
    /// mis-drag, and give up after that instead of failing at the frame rate forever.
    const GIVE_UP_AFTER: u32 = 20;

    let mut g = x11::Grabber::open()?;
    let mut epoch = u64::MAX;
    let mut area: Option<x11::Area> = None;
    let mut failures = 0u32;
    while shared.wanted() {
        let t = Instant::now();
        let now = TARGET_EPOCH.load(Ordering::Relaxed);
        if now != epoch || area.is_none() {
            epoch = now;
            area = x11::resolve(&g, screen_target());
        }
        // A shared window is resized and moved while it is being shared; re-reading its
        // geometry each frame is one round trip and the alternative is a torn grab.
        if let Some(a) = area.as_ref().filter(|a| a.track_geometry) {
            let id = a.drawable;
            area = x11::geometry_of(&g, id).or_else(|| {
                crate::diag!(
                    "[media] shared window {id} is gone — falling back to the primary screen"
                );
                set_screen_target(ScreenTarget::Primary);
                x11::resolve(&g, ScreenTarget::Primary)
            });
        }
        let Some(a) = area.as_ref() else {
            std::thread::sleep(SCREEN_FPS_INTERVAL);
            continue;
        };
        let (w, h, window) = (a.w as usize, a.h as usize, a.track_geometry);
        let d = decim_for(w, target_width(&width));
        match g.grab(a) {
            // Z_PIXMAP depth-24 on little-endian X: B,G,R,X per pixel.
            Ok(data) => {
                failures = 0;
                if let Some(f) = packed_to_i420(data, w, h, 4, (2, 1, 0), d) {
                    shared.publish(f);
                }
            }
            Err(e) => {
                failures += 1;
                if window && failures >= GIVE_UP_AFTER {
                    crate::diag!("[media] shared window is unreadable ({e}) — falling back to the primary screen");
                    set_screen_target(ScreenTarget::Primary);
                } else if failures == 1 {
                    crate::diag!("[media] screen grab: {e}");
                }
                area = None; // re-resolve on the next tick
            }
        }
        std::thread::sleep(SCREEN_FPS_INTERVAL.saturating_sub(t.elapsed()));
    }
    Ok(())
}

/// Windows/macOS: `xcap` (DXGI Desktop Duplication / CoreGraphics).
///
/// Monitors on Windows go through a **persistent recorder**, not a still per frame.
/// `Monitor::capture_image` there is GDI — `BitBlt` into a DIB and `GetDIBits` back to
/// system memory — which is a full-screen CPU copy every time it is called: about 8 MB
/// a frame at 1080p, synchronously, on the capture thread. At share frame rates that is
/// enough by itself to make the app stop responding, and it is pure waste, because
/// `Monitor::video_recorder` is DXGI Desktop Duplication: the compositor hands over
/// frames it already has, GPU-side. (Not for windows — xcap only offers the recorder
/// for monitors — and not for macOS, whose CoreGraphics still path is already cheap.)
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub(super) fn capture_screen(
    shared: &SlotShared,
    width: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
) -> Result<(), String> {
    /// A monitor recorder, held for as long as the target does not change. Stopped on
    /// drop so the duplication session never outlives the share.
    #[cfg(target_os = "windows")]
    struct Stream {
        rec: xcap::VideoRecorder,
        rx: std::sync::mpsc::Receiver<xcap::Frame>,
    }
    #[cfg(target_os = "windows")]
    impl Drop for Stream {
        fn drop(&mut self) {
            let _ = self.rec.stop();
        }
    }
    #[cfg(target_os = "windows")]
    impl Stream {
        fn open(m: &xcap::Monitor) -> Option<Stream> {
            let (rec, rx) = m.video_recorder().ok()?;
            rec.start().ok()?;
            Some(Stream { rec, rx })
        }
        /// Freshest frame the session has produced, or `None` if the screen has not
        /// changed since the last poll — duplication only reports damage, and an
        /// unchanged screen is not an error.
        fn latest(&self) -> Option<xcap::Frame> {
            let mut last = None;
            while let Ok(f) = self.rx.try_recv() {
                last = Some(f);
            }
            last
        }
    }

    /// Whatever the current target resolves to, as a thing that yields RGBA frames.
    enum Src {
        Mon(xcap::Monitor),
        Win(xcap::Window),
    }
    fn resolve(target: ScreenTarget) -> Option<Src> {
        let monitors = xcap::Monitor::all().ok()?;
        let primary = || {
            monitors
                .iter()
                .find(|m| m.is_primary().unwrap_or(false))
                .or_else(|| monitors.first())
                .cloned()
                .map(Src::Mon)
        };
        match target {
            ScreenTarget::Primary => primary(),
            ScreenTarget::Screen(id) => monitors
                .iter()
                .find(|m| m.id().is_ok_and(|i| i == id))
                .cloned()
                .map(Src::Mon)
                .or_else(primary),
            ScreenTarget::Window(id) => xcap::Window::all()
                .ok()
                .and_then(|w| w.into_iter().find(|w| w.id().is_ok_and(|i| i == id)))
                .map(Src::Win)
                .or_else(|| {
                    crate::diag!(
                        "[media] shared window {id} is gone — falling back to the primary screen"
                    );
                    set_screen_target(ScreenTarget::Primary);
                    primary()
                }),
        }
    }

    /// Consecutive failed grabs before the target is written off — the same tolerance
    /// the X11 path uses, for the same reason (a window can be minimised and restored
    /// faster than a share should react).
    const GIVE_UP_AFTER: u32 = 20;

    let mut epoch = u64::MAX;
    let mut src: Option<Src> = None;
    let mut failures = 0u32;
    #[cfg(target_os = "windows")]
    let mut stream: Option<Stream> = None;
    while shared.wanted() {
        let t = Instant::now();
        let now = TARGET_EPOCH.load(Ordering::Relaxed);
        if now != epoch || src.is_none() {
            epoch = now;
            src = resolve(screen_target());
            // Drop the old session before opening the new one: two duplication
            // sessions on one output is a needless second copy of every frame.
            #[cfg(target_os = "windows")]
            {
                // Explicit drop, not just reassignment: assigning would build the new
                // session first and release the old one after, leaving two duplication
                // sessions briefly live on the same output.
                drop(stream.take());
                stream = match src.as_ref() {
                    Some(Src::Mon(m)) => Stream::open(m),
                    _ => None,
                };
            }
        }
        // Windows monitors: take whatever the persistent session has produced. An
        // unchanged screen yields nothing, which is not a failure — publish nothing and
        // leave the peer on the frame it already has.
        #[cfg(target_os = "windows")]
        if let Some(st) = stream.as_ref() {
            failures = 0;
            if let Some(f) = st.latest() {
                let (w, h) = (f.width as usize, f.height as usize);
                let d = decim_for(w, target_width(&width));
                if let Some(frame) = packed_to_i420(&f.raw, w, h, 4, (0, 1, 2), d) {
                    shared.publish(frame);
                }
            }
            std::thread::sleep(SCREEN_FPS_INTERVAL.saturating_sub(t.elapsed()));
            continue;
        }
        let img = match src.as_ref() {
            Some(Src::Mon(m)) => m.capture_image(),
            Some(Src::Win(w)) => w.capture_image(),
            None => {
                std::thread::sleep(SCREEN_FPS_INTERVAL);
                continue;
            }
        };
        match img {
            Ok(img) => {
                failures = 0;
                let (w, h) = (img.width() as usize, img.height() as usize);
                let d = decim_for(w, target_width(&width));
                if let Some(f) = packed_to_i420(img.as_raw(), w, h, 4, (0, 1, 2), d) {
                    shared.publish(f);
                }
            }
            Err(e) => {
                // Do NOT drop the source here. Re-resolving means `Monitor::all()` and,
                // for a window target, `Window::all()` — a system-wide enumeration with
                // per-window queries. Running that on every failed grab, at the frame
                // rate, is enough on its own to wedge the app: a window that cannot be
                // captured (minimised, occluded, protected content) fails every single
                // frame, so the loop turns into 20 full window enumerations a second on
                // top of the encoder. Back off instead, and only re-resolve once it is
                // clear the target is really gone.
                failures += 1;
                if failures == 1 {
                    crate::diag!("[media] screen grab: {e}");
                }
                if failures >= GIVE_UP_AFTER {
                    crate::diag!(
                        "[media] shared source is unreadable — falling back to the primary screen"
                    );
                    set_screen_target(ScreenTarget::Primary);
                    src = None;
                    failures = 0;
                }
            }
        }
        std::thread::sleep(SCREEN_FPS_INTERVAL.saturating_sub(t.elapsed()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real display, real X server: `cargo test -- --ignored share_sources_smoke` on a
    /// machine with a desktop session. Ignored by default (CI runners have no display),
    /// but it is the check that covers everything the share picker depends on and unit
    /// tests cannot reach — RandR monitor enumeration, `_NET_CLIENT_LIST` window
    /// discovery, the MIT-SHM grab path and its plain-`GetImage` fallback, and PNG
    /// preview encoding.
    #[test]
    #[ignore]
    #[cfg(not(target_os = "android"))]
    fn share_sources_smoke() {
        let sources = screen_sources().expect("enumerate share sources");
        let screens = sources.iter().filter(|s| s.kind == "screen").count();
        assert!(screens > 0, "no monitors found");
        for s in &sources {
            assert!(!s.name.is_empty(), "unnamed {} source", s.kind);
            crate::diag!(
                "{} {} — {} ({}, {} B preview)",
                s.kind,
                s.id,
                s.name,
                s.detail,
                s.thumb.len()
            );
        }
        // Previews are best-effort per source, but a monitor grab that fails means the
        // capture path itself is broken, not just one awkward window.
        let screen = sources.iter().find(|s| s.kind == "screen").unwrap();
        assert!(
            screen.thumb.starts_with("data:image/png;base64,"),
            "no preview for {}",
            screen.name
        );
    }
}
