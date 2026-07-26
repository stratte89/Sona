//! Camera capture (desktop) and the device pin behind it.
//!
//! Android is not here: its frames arrive from the Kotlin bridge over JNI, and the
//! device choice there is the front/back flip in the call UI, not a list.

use std::sync::atomic::Ordering;
use std::sync::Mutex;

use super::pixels::{decim_for, packed_to_i420};
use super::SlotShared;

/// Pinned camera, by human-readable name. Names survive a replug where indices do not
/// — unplugging a webcam renumbers everything behind it — and the name is what the UI
/// showed the user in the first place. `None` = the first camera the platform lists.
///
/// Android is not here: its camera is the Kotlin bridge's, and the choice there is the
/// front/back flip in the call UI, not a device list.
#[cfg(not(target_os = "android"))]
static PREF_CAMERA: Mutex<Option<String>> = Mutex::new(None);
#[cfg(not(target_os = "android"))]
static CAMERA_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Pin (or, with `None`, un-pin) the camera. A capture already running ends at its next
/// frame; the engine's next poll starts a fresh one on the new device, which is the
/// same lazy-restart path a track toggle uses.
#[cfg(not(target_os = "android"))]
pub fn set_camera(name: Option<String>) {
    if let Ok(mut cur) = PREF_CAMERA.lock() {
        if *cur == name {
            return; // no-op: the UI re-asserts its preference on every connect
        }
        *cur = name;
    }
    CAMERA_EPOCH.fetch_add(1, Ordering::SeqCst);
}

#[cfg(not(target_os = "android"))]
pub fn pinned_camera() -> Option<String> {
    PREF_CAMERA.lock().ok().and_then(|c| c.clone())
}

/// The cameras this machine offers. Blocking and not especially fast (each backend
/// opens the device to ask what it can do), so callers run it off the async runtime.
///
/// Deduplicated by name: V4L2 gives one webcam two `/dev/video*` nodes — the capture
/// one and a metadata one — and nokhwa reports both, so a single camera otherwise
/// appears twice under an identical label with only one of the two able to produce a
/// frame. The cost is that two *identical models* collapse into one row; that is much
/// rarer than every Linux user seeing their one webcam listed twice, and
/// [`camera_index`] resolves names to the first match either way, so the list and the
/// device that opens always agree.
#[cfg(not(target_os = "android"))]
pub fn list_cameras() -> Vec<crate::audio::DeviceOption> {
    let mut out: Vec<crate::audio::DeviceOption> = Vec::new();
    for c in nokhwa::query(nokhwa::utils::ApiBackend::Auto).unwrap_or_default() {
        let name = c.human_name();
        if name.trim().is_empty() || out.iter().any(|o| o.name == name) {
            continue;
        }
        out.push(crate::audio::DeviceOption {
            id: name.clone(),
            // No platform notion of a "default" camera — the first one listed is what
            // an unpinned call opens, so that is the one the picker marks.
            is_default: out.is_empty(),
            name,
        });
    }
    out
}

/// Resolve the pinned camera to an index for this run. A pin that no longer matches
/// anything (unplugged since) falls back to the first camera rather than failing the
/// track — the same rule the audio pins follow.
#[cfg(not(target_os = "android"))]
fn camera_index() -> nokhwa::utils::CameraIndex {
    use nokhwa::utils::CameraIndex;
    let Some(want) = pinned_camera() else {
        return CameraIndex::Index(0);
    };
    nokhwa::query(nokhwa::utils::ApiBackend::Auto)
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.human_name() == want)
        .map(|c| c.index().clone())
        .unwrap_or(CameraIndex::Index(0))
}

#[cfg(not(target_os = "android"))]
pub(super) fn capture_camera(shared: &SlotShared) -> Result<(), String> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{
        CameraFormat, FrameFormat, RequestedFormat, RequestedFormatType, Resolution,
    };
    // VGA@30 is the call target; `Closest` tolerates cameras that can't do it exactly.
    let want = RequestedFormat::new::<RgbFormat>(RequestedFormatType::Closest(CameraFormat::new(
        Resolution::new(640, 480),
        FrameFormat::MJPEG,
        30,
    )));
    let epoch = CAMERA_EPOCH.load(Ordering::Relaxed);
    let mut cam =
        nokhwa::Camera::new(camera_index(), want).map_err(|e| format!("no camera: {e}"))?;
    cam.open_stream()
        .map_err(|e| format!("camera stream: {e}"))?;
    // Ending the loop releases the device (and its LED) and clears the `running` flag;
    // the engine's next poll spawns this again, on whatever camera is pinned by then.
    while shared.wanted() && CAMERA_EPOCH.load(Ordering::Relaxed) == epoch {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Real devices: `cargo test -- --ignored audio_devices_smoke`. Checks that the
    /// microphone/output/camera pickers get something to show and that ids round-trip
    /// the way the UI stores them.
    #[test]
    #[ignore]
    #[cfg(not(target_os = "android"))]
    fn audio_devices_smoke() {
        let (inputs, outputs) = crate::audio::list_devices();
        for d in inputs.iter().chain(outputs.iter()) {
            assert!(!d.id.is_empty() && !d.name.is_empty());
            eprintln!(
                "{}{}  [{}]",
                if d.is_default { "* " } else { "  " },
                d.name,
                d.id
            );
        }
        assert!(!outputs.is_empty(), "no audio outputs");
        for c in list_cameras() {
            assert!(!c.name.is_empty());
            eprintln!(
                "{}camera {}",
                if c.is_default { "* " } else { "  " },
                c.name
            );
        }
    }
}
