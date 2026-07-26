//! Enumerating and pinning the microphone and the output a call uses.
//!
//! Desktop only: a phone has one microphone, and its output is chosen by the
//! earpiece/loudspeaker/Bluetooth route chooser rather than from a device list.
#![cfg(not(target_os = "android"))]

use std::sync::atomic::Ordering;
use std::sync::Mutex;

use cpal::traits::{DeviceTrait, HostTrait};

use super::{call_hosts, DEVICE_EPOCH, PREF_INPUT, PREF_OUTPUT};

/// One selectable capture or playout device, as offered to the UI.
#[cfg(not(target_os = "android"))]
#[derive(serde::Serialize)]
pub struct DeviceOption {
    /// [`cpal::DeviceId`] string — stable across runs, and what [`set_device`] takes.
    pub id: String,
    pub name: String,
    /// True for the device the platform would pick on its own right now.
    pub is_default: bool,
}

/// Enumerate the microphones and outputs a call could use.
///
/// The first host in [`call_hosts`] that offers anything at all wins the whole list,
/// and no later host contributes. On Linux both hosts describe the same hardware —
/// ALSA as `HD-Audio Generic, ALC887-VD Analog`, PulseAudio as `Starship/Matisse HD
/// Audio Controller Analog Stereo` — so walking both would offer two rows per device
/// that look unrelated, behave differently, and route to the same speakers. Whichever
/// host a call would actually pick is the one the user should be choosing within.
#[cfg(not(target_os = "android"))]
pub fn list_devices() -> (Vec<DeviceOption>, Vec<DeviceOption>) {
    fn collect(hosts: &[cpal::Host], input: bool) -> Vec<DeviceOption> {
        for host in hosts {
            let def = if input {
                host.default_input_device()
            } else {
                host.default_output_device()
            }
            .and_then(|d| d.id().ok())
            .map(|i| i.to_string());
            let devices = if input {
                host.input_devices().ok().map(|d| d.collect::<Vec<_>>())
            } else {
                host.output_devices().ok().map(|d| d.collect::<Vec<_>>())
            };
            let mut out: Vec<DeviceOption> = Vec::new();
            for d in devices.unwrap_or_default() {
                let Ok(id) = d.id() else { continue };
                let name = device_name(&d);
                if is_pseudo_device(host, id.id()) {
                    continue;
                }
                // Monitor/loopback sources are the *screen-share* capture path, never a
                // microphone; listing them here only invites picking one by mistake.
                if input && is_monitor(id.id(), &name) {
                    continue;
                }
                if out.iter().any(|o| o.name == name) {
                    continue;
                }
                let id = id.to_string();
                out.push(DeviceOption {
                    is_default: def.as_deref() == Some(id.as_str()),
                    id,
                    name,
                });
            }
            if !out.is_empty() {
                return out;
            }
        }
        Vec::new()
    }
    let hosts = call_hosts();
    (collect(&hosts, true), collect(&hosts, false))
}

/// Is this ALSA entry a config plugin rather than something you can plug a cable into?
///
/// ALSA's device namespace is a config namespace: alongside the real cards it lists
/// every rate converter, upmixer, JACK/OSS/PulseAudio bridge and DSP plugin the system
/// has installed. cpal reports them as devices, and about twenty rows reading "Rate
/// Converter Plugin Using Speex Resampler" is not a microphone picker. Keep the
/// routing defaults and anything naming a concrete card; drop the rest. Only ALSA has
/// this problem — every other backend enumerates real endpoints.
#[cfg(not(target_os = "android"))]
fn is_pseudo_device(host: &cpal::Host, id: &str) -> bool {
    #[cfg(target_os = "linux")]
    if host.id() == cpal::HostId::Alsa {
        // Only concrete cards. `usbstream:` exposes a card's raw USB endpoint, which is
        // not a route anyone wants a call on and generally will not open at all; ALSA's
        // own `default`/`sysdefault` are dropped because "follow the system default" is
        // already what an unpinned device means — offering it again as a pinnable row
        // is the same behaviour under a second, more confusing name.
        let real_card = id.contains("CARD=") && !id.starts_with("usbstream");
        return !real_card;
    }
    let _ = (host, id);
    false
}

/// Human-readable device name, falling back to `Display` when the backend has no
/// structured description for it.
#[cfg(not(target_os = "android"))]
fn device_name(d: &cpal::Device) -> String {
    d.description()
        .map(|desc| desc.name().to_string())
        .unwrap_or_else(|_| d.to_string())
}

/// Is this capture device a loopback/monitor of an output rather than a real input?
#[cfg(not(target_os = "android"))]
fn is_monitor(id: &str, name: &str) -> bool {
    id.ends_with(".monitor") || name.to_lowercase().contains("monitor of ")
}

/// Pin (or, with `None`, un-pin) the capture or playout device. Applies to the live
/// call: the streams are rebuilt on the audio thread within ~100 ms.
#[cfg(not(target_os = "android"))]
pub fn set_device(input: bool, id: Option<String>) {
    let slot = if input { &PREF_INPUT } else { &PREF_OUTPUT };
    let mut cur = match slot.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    if *cur == id {
        return; // no-op: the UI re-asserts its preference on every connect
    }
    *cur = id;
    DEVICE_EPOCH.fetch_add(1, Ordering::SeqCst);
}

/// The pinned devices, for the UI to render as the current selection.
#[cfg(not(target_os = "android"))]
pub fn pinned_devices() -> (Option<String>, Option<String>) {
    let get = |m: &Mutex<Option<String>>| match m.lock() {
        Ok(v) => v.clone(),
        Err(p) => p.into_inner().clone(),
    };
    (get(&PREF_INPUT), get(&PREF_OUTPUT))
}

/// Resolve a pinned device id to a live device, searching every host (the id carries
/// its own host, and the pinned output may well live on a host the call would not
/// otherwise reach for). `None` — unpinned, or unplugged since — means "use the
/// platform default", which is the behaviour anyone would expect from a vanished
/// device.
#[cfg(not(target_os = "android"))]
pub(super) fn pinned_device(input: bool) -> Option<cpal::Device> {
    let (pi, po) = pinned_devices();
    let want = if input { pi } else { po }?;
    for host in call_hosts() {
        // A host that refuses to enumerate is a reason to try the next one, not to give
        // up on the pin and silently drop back to the default.
        let devices = if input {
            host.input_devices().ok().map(|d| d.collect::<Vec<_>>())
        } else {
            host.output_devices().ok().map(|d| d.collect::<Vec<_>>())
        };
        for d in devices.unwrap_or_default() {
            if d.id().ok().map(|i| i.to_string()).as_deref() == Some(want.as_str()) {
                return Some(d);
            }
        }
    }
    None
}
