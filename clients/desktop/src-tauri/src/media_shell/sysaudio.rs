//! System-audio ("what the machine is playing") capture for screen shares, and the
//! echo suppression that keeps the call's own playout out of it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use client_core::media::{ScreenAudioSource, SCREEN_AUDIO_SAMPLES};

use super::CAPTURE_LINGER;

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
///
/// The cpal callback only hands frames to this thread; the echo suppression that keeps
/// our own call playout out of the shared audio (see [`crate::aec`]) runs here, off the
/// audio callback, because its delay estimator is far too slow to run under one.
#[cfg(not(target_os = "android"))]
fn system_audio_thread(
    tx: SyncSender<[i16; SCREEN_AUDIO_SAMPLES]>,
    last_poll: Arc<Mutex<Instant>>,
) -> Result<(), String> {
    use client_core::call::SAMPLES_PER_FRAME;
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
        // One per channel: they consume the same input length, but each carries its own
        // interpolation seam.
        let mut rs_l = crate::audio::Resampler::new();
        let mut rs_r = crate::audio::Resampler::new();
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
                    rs_l.process(&left, rate, SAMPLE_RATE, &mut l48);
                    rs_r.process(&right, rate, SAMPLE_RATE, &mut r48);
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

    // Every cpal format, one dispatch (the PulseAudio host's monitor sources come out
    // I32 on PipeWire boxes) — see `build_for_format` for why the list is exhaustive.
    let (raw_tx, raw_rx) = sync_channel::<[i16; SCREEN_AUDIO_SAMPLES]>(8);
    let stream = crate::audio::build_for_format!(
        cfg.sample_format(),
        build,
        (&device, cfg.into(), ch, rate, raw_tx)
    )?;
    stream.play().map_err(|e| e.to_string())?;

    let reference = crate::aec::reference();
    let mut reader = crate::aec::RefReader::default();
    let mut suppressor = crate::aec::EchoSuppressor::new();
    let mut refblk = [0.0f32; SAMPLES_PER_FRAME];
    while last_poll
        .lock()
        .map(|t| t.elapsed() < CAPTURE_LINGER)
        .unwrap_or(false)
    {
        // One reference block consumed per captured frame, in order: that lockstep is
        // what lets the suppressor treat the echo delay as a constant it can measure.
        while let Ok(mut frame) = raw_rx.try_recv() {
            if !reader.pull(reference, &mut refblk) {
                suppressor.reset_alignment();
            }
            suppressor.process(&mut frame, &refblk);
            let _ = tx.try_send(frame); // full → drop; latency beats backlog
        }
        // Well under the 20 ms frame cadence, so the extra hop costs no real latency.
        std::thread::sleep(Duration::from_millis(3));
    }
    Ok(())
}
