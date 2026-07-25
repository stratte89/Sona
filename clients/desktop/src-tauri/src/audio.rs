//! Platform audio for voice calls: capture/playout bridged to the call engine's
//! [`AudioIo`] (20 ms frames of 48 kHz mono i16).
//!
//! cpal streams are not `Send`, so they live on a dedicated std thread that parks until
//! the call ends; the engine talks to them through bounded channels (audio callbacks
//! only ever `try_send`/`try_recv` — never block, never allocate unboundedly). Devices
//! run at whatever rate/channel count they prefer; this module downmixes and linearly
//! resamples to/from the engine format (plenty for speech).
//!
//! Echo & noise, per platform:
//! * **Android** — no cpal at all: the Kotlin `MediaBridge` owns both directions.
//!   Capture is a VOICE_COMMUNICATION AudioRecord (hardware AEC/NS/AGC +
//!   MODE_IN_COMMUNICATION routing) — cpal's AAudio input uses the generic preset,
//!   which bypasses the platform echo canceller, and loudspeaker → mic feedback
//!   builds into static within seconds of a phone↔phone call. Playout is a
//!   USAGE_VOICE_COMMUNICATION AudioTrack: playing the far end through a MEDIA-usage
//!   stream while the device sits in MODE_IN_COMMUNICATION is silently muted/ducked
//!   by many OEM ROMs (observed as a completely dead call), ignores the
//!   earpiece↔speaker communication routing, and never feeds the AEC its far-end
//!   reference.
//! * **Desktop** — cpal capture with RNNoise (`nnnoiseless`) noise suppression,
//!   gated by [`NOISE_SUPPRESSION`] (UI toggle, default on). Echo is structurally
//!   rarer (headsets, distance to speakers); the platform stacks
//!   (PipeWire/PulseAudio, CoreAudio, WASAPI voice mode) carry the AEC when speakers
//!   are used.
//!
//! Screen-share audio from the peer arrives on a second ("aux") channel as 48 kHz
//! stereo; the playout callback downmixes and sums it with the voice stream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

use client_core::call::{AudioIo, SAMPLES_PER_FRAME, SAMPLE_RATE};
use client_core::media::SCREEN_AUDIO_SAMPLES;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

/// Frames buffered toward the sound card (~120 ms jitter absorption) and from the mic.
const CHANNEL_FRAMES: usize = 6;

/// AEC toggle (UI, default on). Desktop: gates WebRTC AEC3 in the capture
/// callback. When the user wears a headset, echo is structurally impossible
/// and AEC can be disabled to avoid any signal degradation.
pub static ECHO_CANCELLATION: AtomicBool = AtomicBool::new(true);

/// Noise-suppression toggle (UI, default on). Desktop: gates RNNoise in the capture
/// callback, effective immediately mid-call. Android's equivalent is the platform
/// `NoiseSuppressor` effect, toggled over the Kotlin bridge instead — see
/// [`crate::android_media::set_voice_noise_suppression`].
pub static NOISE_SUPPRESSION: AtomicBool = AtomicBool::new(true);

/// Preferred input device name (empty = system default). Set by `call_set_audio_devices`.
pub static AUDIO_INPUT_DEVICE: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());
/// Preferred output device name (empty = system default). Set by `call_set_audio_devices`.
pub static AUDIO_OUTPUT_DEVICE: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

/// Per-peer volume gains for 1:1 calls: peer username → gain multiplier (0.0–2.0, 1.0 = unity).
/// Applied in the playout callback to the voice portion of the mix.
pub static PEER_VOLUME: std::sync::LazyLock<std::sync::RwLock<std::collections::HashMap<String, f32>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// Per-peer screen-audio volume gains: peer username → gain multiplier (0.0–2.0, 1.0 = unity).
/// Applied in the playout callback to the aux (screen audio) portion of the mix.
pub static SCREEN_VOLUME: std::sync::LazyLock<std::sync::RwLock<std::collections::HashMap<String, f32>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// List available audio input and output devices for the settings UI.
/// Returns JSON: `{ "inputs": [{"name": ..., "is_default": true}], "outputs": [...] }`.
#[cfg(not(target_os = "android"))]
pub fn list_audio_devices() -> serde_json::Value {
    use serde_json::json;
    let host = cpal::default_host();
    let default_in = host.default_input_device().and_then(|d| d.description().ok().map(|desc| desc.name().to_string()));
    let default_out = host.default_output_device().and_then(|d| d.description().ok().map(|desc| desc.name().to_string()));
    let inputs: Vec<serde_json::Value> = host
        .input_devices()
        .into_iter()
        .flatten()
        .filter_map(|d| d.description().ok().map(|desc| desc.name().to_string()))
        .map(|name| {
            json!({
                "name": name,
                "is_default": default_in.as_deref() == Some(&name),
            })
        })
        .collect();
    let outputs: Vec<serde_json::Value> = host
        .output_devices()
        .into_iter()
        .flatten()
        .filter_map(|d| d.description().ok().map(|desc| desc.name().to_string()))
        .map(|name| {
            json!({
                "name": name,
                "is_default": default_out.as_deref() == Some(&name),
            })
        })
        .collect();
    json!({ "inputs": inputs, "outputs": outputs })
}

#[cfg(target_os = "android")]
pub fn list_audio_devices() -> serde_json::Value {
    serde_json::json!({ "inputs": [], "outputs": [] })
}

/// Set preferred audio devices (empty string = system default). Applied on the next call start.
pub fn set_audio_devices(input: &str, output: &str) {
    if let Ok(mut w) = AUDIO_INPUT_DEVICE.write() {
        *w = input.to_string();
    }
    if let Ok(mut w) = AUDIO_OUTPUT_DEVICE.write() {
        *w = output.to_string();
    }
}

/// Set per-peer volume gain (0.0 = mute, 1.0 = unity, 2.0 = 2× loud). Applied live.
pub fn set_peer_volume(peer: &str, gain: f32) {
    if let Ok(mut w) = PEER_VOLUME.write() {
        w.insert(peer.to_string(), gain);
    }
}

/// Set per-peer screen-audio volume gain (0.0 = mute, 1.0 = unity, 2.0 = 2× loud). Applied live.
pub fn set_screen_volume(peer: &str, gain: f32) {
    if let Ok(mut w) = SCREEN_VOLUME.write() {
        w.insert(peer.to_string(), gain);
    }
}

/// Resolve a device by name, falling back to the system default.
#[cfg(not(target_os = "android"))]
fn find_device(host: &cpal::Host, name: &str, is_input: bool) -> Option<cpal::Device> {
    if name.is_empty() {
        return if is_input {
            host.default_input_device()
        } else {
            host.default_output_device()
        };
    }
    if is_input {
        host.input_devices()
            .into_iter()
            .flatten()
            .find(|d| d.description().map(|desc| desc.name() == name).unwrap_or(false))
            .or_else(|| host.default_input_device())
    } else {
        host.output_devices()
            .into_iter()
            .flatten()
            .find(|d| d.description().map(|desc| desc.name() == name).unwrap_or(false))
            .or_else(|| host.default_output_device())
    }
}

/// The engine-side endpoints. Dropping it (or the stop flag) ends the audio thread.
/// `render_tx` feeds the playout signal back to the capture thread for AEC.
pub struct ShellAudio {
    cap_rx: Receiver<[i16; SAMPLES_PER_FRAME]>,
    play_tx: SyncSender<[i16; SAMPLES_PER_FRAME]>,
    render_tx: SyncSender<[i16; SAMPLES_PER_FRAME]>,
    stop: Arc<AtomicBool>,
}

impl Drop for ShellAudio {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl AudioIo for ShellAudio {
    fn read_frame(&mut self, buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool {
        match self.cap_rx.try_recv() {
            Ok(frame) => {
                *buf = frame;
                true
            }
            Err(_) => false, // warming up / device hiccup → engine sends silence
        }
    }

    fn write_frame(&mut self, frame: &[i16; SAMPLES_PER_FRAME]) {
        // Feed the playout signal to the AEC render queue (non-blocking: if the
        // capture thread isn't consuming, we don't stall playout).
        let _ = self.render_tx.try_send(*frame);
        // If playout is full (device stalled), dropping late audio beats growing a lag.
        let _ = self.play_tx.try_send(*frame);
    }
}

/// Naive linear resampler, mono. Good enough for speech; avoids a DSP dependency.
pub(crate) fn resample(input: &[f32], from_hz: u32, to_hz: u32, out: &mut Vec<f32>) {
    out.clear();
    if input.is_empty() || from_hz == 0 || to_hz == 0 {
        return;
    }
    if from_hz == to_hz {
        out.extend_from_slice(input);
        return;
    }
    let ratio = from_hz as f64 / to_hz as f64;
    let n = ((input.len() as f64) / ratio).floor() as usize;
    for i in 0..n {
        let pos = i as f64 * ratio;
        let idx = pos as usize;
        let frac = (pos - idx as f64) as f32;
        let a = input[idx.min(input.len() - 1)];
        let b = input[(idx + 1).min(input.len() - 1)];
        out.push(a + (b - a) * frac);
    }
}

/// Start capture + playout on default devices. Returns the engine-side [`ShellAudio`]
/// plus the aux (peer screen-audio) sender for the sink, or a human-readable error
/// (no device, backend failure). `peer_username` is used for per-peer volume gain in
/// 1:1 calls; pass `None` for group calls (mixing is in the engine, not the playout).
pub fn start(peer_username: Option<String>) -> Result<(ShellAudio, SyncSender<[i16; SCREEN_AUDIO_SAMPLES]>), String> {
    let (cap_tx, cap_rx) = sync_channel::<[i16; SAMPLES_PER_FRAME]>(CHANNEL_FRAMES);
    let (play_tx, play_rx) = sync_channel::<[i16; SAMPLES_PER_FRAME]>(CHANNEL_FRAMES);
    let (aux_tx, aux_rx) = sync_channel::<[i16; SCREEN_AUDIO_SAMPLES]>(CHANNEL_FRAMES);
    let (render_tx, render_rx) = sync_channel::<[i16; SAMPLES_PER_FRAME]>(CHANNEL_FRAMES);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();

    // Probe devices on the caller thread so failures surface as command errors.
    // Android has no cpal devices to probe — both directions live in the Kotlin bridge.
    #[cfg(not(target_os = "android"))]
    {
        let host = cpal::default_host();
        host.default_input_device()
            .ok_or("no microphone available")?;
        host.default_output_device()
            .ok_or("no audio output available")?;
    }

    std::thread::Builder::new()
        .name("sona-call-audio".into())
        .spawn(move || {
            if let Err(e) = audio_thread(cap_tx, play_rx, aux_rx, render_rx, stop_thread, peer_username) {
                eprintln!("[call] audio thread ended: {e}");
            }
        })
        .map_err(|e| e.to_string())?;

    Ok((
        ShellAudio {
            cap_rx,
            play_tx,
            render_tx,
            stop,
        },
        aux_tx,
    ))
}

/// Raw pointer wrapper for AEC pipeline — !Send types like aec3's LinearPipeline
/// need to cross the Send boundary of cpal's build_input_stream. The callback
/// only runs on one thread, so this is sound.
struct AecSendPtr(*mut Option<aec3::pipelines::linear::LinearPipeline>);
unsafe impl Send for AecSendPtr {}
impl AecSendPtr {
    unsafe fn get(&mut self) -> &mut Option<aec3::pipelines::linear::LinearPipeline> {
        &mut *self.0
    }
}

#[cfg(not(target_os = "android"))]
fn audio_thread(
    cap_tx: SyncSender<[i16; SAMPLES_PER_FRAME]>,
    play_rx: Receiver<[i16; SAMPLES_PER_FRAME]>,
    aux_rx: Receiver<[i16; SCREEN_AUDIO_SAMPLES]>,
    render_rx: Receiver<[i16; SAMPLES_PER_FRAME]>,
    stop: Arc<AtomicBool>,
    peer_username: Option<String>,
) -> Result<(), String> {
    let host = cpal::default_host();
    let in_name = AUDIO_INPUT_DEVICE.read().map(|s| s.clone()).unwrap_or_default();
    let out_name = AUDIO_OUTPUT_DEVICE.read().map(|s| s.clone()).unwrap_or_default();
    let output = find_device(&host, &out_name, false).ok_or("no output")?;
    let out_cfg = output.default_output_config().map_err(|e| e.to_string())?;
    let out_rate = out_cfg.sample_rate();
    let out_ch = out_cfg.channels() as usize;

    // ── Capture: device format → mono f32 → 48 kHz → RNNoise (when enabled) → i16
    //    frames → engine. The default device format may be f32/i16/u16; monomorphize
    //    per format.
    fn build_capture<T>(
        device: &cpal::Device,
        cfg: cpal::StreamConfig,
        in_ch: usize,
        in_rate: u32,
        cap_tx: SyncSender<[i16; SAMPLES_PER_FRAME]>,
        render_rx: Receiver<[i16; SAMPLES_PER_FRAME]>,
    ) -> Result<cpal::Stream, String>
    where
        T: cpal::SizedSample,
        f32: cpal::FromSample<T>,
    {
        use nnnoiseless::DenoiseState;
        let mut mono = Vec::<f32>::new();
        let mut at48 = Vec::<f32>::new();
        // AEC: WebRTC AEC3 via the aec3 crate's linear pipeline. Processes 10 ms
        // blocks (480 samples at 48 kHz mono). The render signal (speaker playout)
        // is fed via render_rx; the AEC removes it from the captured mic signal.
        // Gated by ECHO_CANCELLATION. The pipeline is !Send (uses Rc internally)
        // but cpal's build_input_stream requires Send closures. The callback only
        // ever runs on one thread (cpal guarantee), so we store it as a raw pointer
        // in a Send wrapper and deref inside the callback.
        let aec_format = aec3::nodes::audio::AudioFormat::ten_ms(48_000, 1);
        let pipeline_box = Box::new(
            aec3::pipelines::linear::builder(aec_format, aec_format)
                .initial_delay_ms(116)
                .build()
                .ok()
        );
        let mut aec_ptr = AecSendPtr(Box::into_raw(pipeline_box));
        let aec_samples = aec_format.sample_count(); // 480
        let mut render_pending = Vec::<f32>::new();
        let mut capture_pending = Vec::<f32>::new();
        let mut aec_output = vec![0f32; aec_samples];
        // Noise suppression (gated by NOISE_SUPPRESSION): RNNoise runs on 10 ms blocks
        // (480 samples) in i16-range floats, exactly half an engine frame — no extra
        // buffering layer. When toggled off the samples pass through the same chunking
        // untouched, so flipping mid-call never disturbs the framing.
        let mut denoise = DenoiseState::new();
        let mut dn_in = Vec::<f32>::new();
        let mut dn_out = [0f32; DenoiseState::FRAME_SIZE];
        let mut pending = Vec::<i16>::new();
        device
            .build_input_stream(
                cfg,
                move |data: &[T], _| {
                    use cpal::Sample as _;
                    mono.clear();
                    for frame in data.chunks(in_ch) {
                        let sum: f32 = frame.iter().map(|s| f32::from_sample(*s)).sum();
                        mono.push(sum / in_ch as f32);
                    }
                    resample(&mono, in_rate, SAMPLE_RATE, &mut at48);
                    // Drain render reference frames from the playout path.
                    while let Ok(rframe) = render_rx.try_recv() {
                        for &s in rframe.iter() {
                            render_pending.push(s as f32 / 32768.0);
                        }
                    }
                    // AEC: process in 10 ms (480-sample) blocks.
                    capture_pending.extend(at48.iter().map(|s| s.clamp(-1.0, 1.0)));
                    if ECHO_CANCELLATION.load(Ordering::Relaxed) {
                        let aec_pipeline = unsafe { aec_ptr.get() };
                        if let Some(ref mut pipeline) = aec_pipeline {
                            while capture_pending.len() >= aec_samples && render_pending.len() >= aec_samples {
                                // Feed render frame (far-end / speaker reference).
                                let render_frame = render_pending[..aec_samples].to_vec();
                                let _ = pipeline.handle_render_frame(&render_frame);
                                // Process capture frame (near-end / mic).
                                let capture_frame = capture_pending[..aec_samples].to_vec();
                                if pipeline.process_capture_frame(&capture_frame, &mut aec_output).unwrap_or(false) {
                                    dn_in.extend(aec_output.iter().map(|s| s * 32767.0));
                                } else {
                                    // AEC not ready yet — pass through.
                                    dn_in.extend(capture_frame.iter().map(|s| s * 32767.0));
                                }
                                capture_pending.drain(..aec_samples);
                                render_pending.drain(..aec_samples);
                            }
                        } else {
                            // AEC pipeline failed to build — pass through.
                            dn_in.extend(capture_pending.drain(..).map(|s| s * 32767.0));
                            render_pending.clear();
                        }
                    } else {
                        // AEC disabled — pass through, draining render to avoid backlog.
                        dn_in.extend(capture_pending.drain(..).map(|s| s * 32767.0));
                        render_pending.clear();
                    }
                    while dn_in.len() >= DenoiseState::FRAME_SIZE {
                        if NOISE_SUPPRESSION.load(Ordering::Relaxed) {
                            denoise.process_frame(&mut dn_out, &dn_in[..DenoiseState::FRAME_SIZE]);
                        } else {
                            dn_out.copy_from_slice(&dn_in[..DenoiseState::FRAME_SIZE]);
                        }
                        dn_in.drain(..DenoiseState::FRAME_SIZE);
                        pending.extend(dn_out.iter().map(|s| s.clamp(-32768.0, 32767.0) as i16));
                    }
                    while pending.len() >= SAMPLES_PER_FRAME {
                        let mut frame = [0i16; SAMPLES_PER_FRAME];
                        frame.copy_from_slice(&pending[..SAMPLES_PER_FRAME]);
                        pending.drain(..SAMPLES_PER_FRAME);
                        match cap_tx.try_send(frame) {
                            Ok(()) | Err(TrySendError::Full(_)) => {}
                            Err(TrySendError::Disconnected(_)) => return,
                        }
                    }
                },
                |e| eprintln!("[call] capture error: {e}"),
                None,
            )
            .map_err(|e| format!("capture: {e}"))
    }
    let in_stream = {
        let input = find_device(&host, &in_name, true).ok_or("no microphone")?;
        let in_cfg = input.default_input_config().map_err(|e| e.to_string())?;
        let in_rate = in_cfg.sample_rate();
        let in_ch = in_cfg.channels() as usize;
        match in_cfg.sample_format() {
            cpal::SampleFormat::F32 => {
                build_capture::<f32>(&input, in_cfg.clone().into(), in_ch, in_rate, cap_tx, render_rx)?
            }
            cpal::SampleFormat::I16 => {
                build_capture::<i16>(&input, in_cfg.clone().into(), in_ch, in_rate, cap_tx, render_rx)?
            }
            cpal::SampleFormat::U16 => {
                build_capture::<u16>(&input, in_cfg.clone().into(), in_ch, in_rate, cap_tx, render_rx)?
            }
            other => return Err(format!("unsupported capture format {other:?}")),
        }
    };

    // ── Playout: engine frames (48 kHz mono voice + 48 kHz stereo peer screen audio)
    //    mixed, then taken to device rate/channels. ──
    fn build_playout<T>(
        device: &cpal::Device,
        cfg: cpal::StreamConfig,
        out_ch: usize,
        out_rate: u32,
        play_rx: Receiver<[i16; SAMPLES_PER_FRAME]>,
        aux_rx: Receiver<[i16; SCREEN_AUDIO_SAMPLES]>,
        peer_username: String,
    ) -> Result<cpal::Stream, String>
    where
        T: cpal::SizedSample + cpal::FromSample<f32>,
    {
        let mut queue = Vec::<f32>::new();
        let mut frame48 = Vec::<f32>::new();
        let mut updev = Vec::<f32>::new();
        device
            .build_output_stream(
                cfg,
                move |data: &mut [T], _| {
                    let needed = data.len() / out_ch;
                    while queue.len() < needed {
                        let voice = play_rx.try_recv().ok();
                        let aux = aux_rx.try_recv().ok();
                        if voice.is_none() && aux.is_none() {
                            break;
                        }
                        // Per-peer volume gain for 1:1 calls (1.0 = unity).
                        let gain = PEER_VOLUME
                            .read()
                            .ok()
                            .and_then(|m| m.get(&peer_username).copied())
                            .unwrap_or(1.0);
                        // Per-peer screen-audio volume gain (1.0 = unity).
                        let screen_gain = SCREEN_VOLUME
                            .read()
                            .ok()
                            .and_then(|m| m.get(&peer_username).copied())
                            .unwrap_or(1.0);
                        frame48.clear();
                        for i in 0..SAMPLES_PER_FRAME {
                            let v = voice.map_or(0.0, |f| (f[i] as f32 / 32768.0) * gain);
                            let a = aux.map_or(0.0, |f| {
                                ((f[2 * i] as f32 + f[2 * i + 1] as f32) / 2.0 / 32768.0) * screen_gain
                            });
                            frame48.push((v + a).clamp(-1.0, 1.0));
                        }
                        resample(&frame48, SAMPLE_RATE, out_rate, &mut updev);
                        queue.extend_from_slice(&updev);
                    }
                    for (i, frame) in data.chunks_mut(out_ch).enumerate() {
                        let s = queue.get(i).copied().unwrap_or(0.0);
                        for ch in frame.iter_mut() {
                            *ch = <T as cpal::FromSample<f32>>::from_sample_(s);
                        }
                    }
                    let consumed = needed.min(queue.len());
                    queue.drain(..consumed);
                },
                |e| eprintln!("[call] playout error: {e}"),
                None,
            )
            .map_err(|e| format!("playout: {e}"))
    }
    let out_stream = match out_cfg.sample_format() {
        cpal::SampleFormat::F32 => build_playout::<f32>(
            &output,
            out_cfg.clone().into(),
            out_ch,
            out_rate,
            play_rx,
            aux_rx,
            peer_username.clone().unwrap_or_default(),
        )?,
        cpal::SampleFormat::I16 => build_playout::<i16>(
            &output,
            out_cfg.clone().into(),
            out_ch,
            out_rate,
            play_rx,
            aux_rx,
            peer_username.clone().unwrap_or_default(),
        )?,
        cpal::SampleFormat::U16 => build_playout::<u16>(
            &output,
            out_cfg.clone().into(),
            out_ch,
            out_rate,
            play_rx,
            aux_rx,
            peer_username.clone().unwrap_or_default(),
        )?,
        other => return Err(format!("unsupported playout format {other:?}")),
    };

    in_stream.play().map_err(|e| e.to_string())?;
    out_stream.play().map_err(|e| e.to_string())?;

    // Streams run on backend threads; hold them alive until the call ends.
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}

/// Serial number of the newest Android voice-audio session. Consecutive sessions
/// overlap: a reconnect (or an instant re-dial) starts the new session's thread while
/// the old one is still winding down, and the old thread's bridge `stop` calls would
/// otherwise land AFTER the new thread's `start` calls — tearing down the freshly
/// started mic/AudioTrack and leaving the whole call one-way silent. Each thread takes
/// a ticket on start and only issues the stop calls if it is still the newest.
#[cfg(target_os = "android")]
static VOICE_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Android: both directions live in the Kotlin bridge (see the module docs — cpal's
/// AAudio streams are wrong for telephony in both directions). This thread pumps the
/// echo-cancelled voice mic into the engine and the engine's playout (voice + peer
/// screen audio, mixed) into the VOICE_COMMUNICATION AudioTrack. 5 ms poll on a 20 ms
/// frame cadence keeps added latency negligible.
#[cfg(target_os = "android")]
fn audio_thread(
    cap_tx: SyncSender<[i16; SAMPLES_PER_FRAME]>,
    play_rx: Receiver<[i16; SAMPLES_PER_FRAME]>,
    aux_rx: Receiver<[i16; SCREEN_AUDIO_SAMPLES]>,
    _render_rx: Receiver<[i16; SAMPLES_PER_FRAME]>,
    stop: Arc<AtomicBool>,
    _peer_username: Option<String>,
) -> Result<(), String> {
    let session = VOICE_SESSION.fetch_add(1, Ordering::SeqCst) + 1;
    crate::android_media::set_voice_capture(true);
    crate::android_media::set_voice_playout(true);
    let mut frame = [0i16; SAMPLES_PER_FRAME];
    let mut mixed = [0i16; SAMPLES_PER_FRAME];
    // Watchdog: a healthy mic delivers a frame every 20 ms regardless of mute (mute is
    // engine-side). Going quiet means the record died (route change, HAL restart) or
    // never started (permission granted mid-prompt) — re-kick the bridge, whose
    // start calls are "ensure alive": no-ops on a healthy pipeline, rebuilds otherwise.
    let mut last_frame = std::time::Instant::now();
    let mut last_kick = std::time::Instant::now();
    'run: while !stop.load(Ordering::Relaxed) {
        while crate::android_media::read_voice_frame(&mut frame) {
            last_frame = std::time::Instant::now();
            match cap_tx.try_send(frame) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => break 'run,
            }
        }
        if last_frame.elapsed().as_secs() >= 2 && last_kick.elapsed().as_secs() >= 2 {
            last_kick = std::time::Instant::now();
            crate::android_media::set_voice_capture(true);
            crate::android_media::set_voice_playout(true);
        }
        // One 20 ms step per queued frame: voice and/or peer screen audio, summed
        // exactly like the desktop playout callback (stereo aux downmixed — the voice
        // path is mono end-to-end). Everything is 48 kHz here; no resampling.
        loop {
            let voice = play_rx.try_recv().ok();
            let aux = aux_rx.try_recv().ok();
            if voice.is_none() && aux.is_none() {
                break; // caught up — the AudioTrack pads silence on underrun
            }
            for (i, out) in mixed.iter_mut().enumerate() {
                let v = voice.map_or(0.0, |f| f[i] as f32);
                let a = aux.map_or(0.0, |f| (f[2 * i] as f32 + f[2 * i + 1] as f32) / 2.0);
                *out = (v + a).clamp(-32768.0, 32767.0) as i16;
            }
            crate::android_media::push_playout_frame(&mixed);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // A newer session is already running its own mic/playout — leaving them alive is
    // the point (see VOICE_SESSION); stopping here would kill the successor's audio.
    if VOICE_SESSION.load(Ordering::SeqCst) == session {
        crate::android_media::set_voice_playout(false);
        crate::android_media::set_voice_capture(false);
    }
    Ok(())
}
