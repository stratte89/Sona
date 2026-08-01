//! Platform audio for voice calls: capture/playout bridged to the call engine's
//! [`AudioIo`] (20 ms frames of 48 kHz mono i16).
//!
//! cpal streams are not `Send`, so they live on a dedicated std thread that parks until
//! the call ends; the engine talks to them through bounded [`FrameRing`]s (audio
//! callbacks only ever push/pop — never block on the network, never allocate). Devices
//! run at whatever rate/channel count/sample format they prefer; this module downmixes,
//! converts and linearly resamples to/from the engine format (plenty for speech).
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
//! Screen-share audio from the peer arrives on a second ("aux") ring as 48 kHz
//! stereo; the playout callback downmixes and sums it with the voice stream. That
//! same mix is published to [`crate::aec`] as the reference used to keep our own
//! playout out of the system audio we share.
//!
//! Devices: by default the platform's own defaults, which is what most people want and
//! what mobile has no alternative to. Desktop users can pin a specific microphone and
//! output in the call settings ([`set_device`]); the choice is applied to the live call
//! by rebuilding both streams, so it is auditable immediately instead of "next call".

mod devices;
pub mod probe;
mod resample;

#[cfg(not(target_os = "android"))]
use devices::pinned_device;
#[cfg(not(target_os = "android"))]
pub use devices::{list_devices, pinned_devices, set_device, DeviceOption};
pub(crate) use resample::Resampler;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use client_core::call::{AudioIo, SAMPLES_PER_FRAME, SAMPLE_RATE};
use client_core::media::SCREEN_AUDIO_SAMPLES;
#[cfg_attr(target_os = "android", allow(unused_imports))]
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

/// Frames buffered toward the sound card (~120 ms of jitter absorption) and from the mic.
const RING_FRAMES: usize = 6;

/// Frames the playout ring must hold before the device starts draining it (and again
/// after any underrun). Without this cushion the callback drains the ring to empty on
/// its very first pull and then alternates one-frame-then-silence forever — audible as
/// a chop on every single word.
const PLAYOUT_PREFILL: usize = 2;

/// Noise-suppression toggle (UI, default on). Desktop: gates RNNoise in the capture
/// callback, effective immediately mid-call. Android's equivalent is the platform
/// `NoiseSuppressor` effect, toggled over the Kotlin bridge instead — see
/// [`crate::android_media::set_voice_noise_suppression`].
pub static NOISE_SUPPRESSION: AtomicBool = AtomicBool::new(true);

/// How loud to play the **peer's shared system audio**, in percent, and whether the
/// listener has muted it outright.
///
/// Not the same thing as the peer's voice, and not persisted: a share is a thing that
/// happens during one call, so the control resets with it. The default is deliberately
/// half — shared audio is a whole desktop's output arriving next to one person talking,
/// and at unity it buries them. Mute is separate from the level so that un-muting
/// returns to where the slider was rather than to the default.
///
/// Same 0-200 % range and the same curve as a voice
/// ([`client_core::call::gain_factor`]): a share can be too quiet as easily as too
/// loud, and one scale for both is one thing to learn.
pub static SHARE_AUDIO_GAIN: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(SHARE_AUDIO_DEFAULT);
pub static SHARE_AUDIO_MUTED: AtomicBool = AtomicBool::new(false);
/// Half. See [`SHARE_AUDIO_GAIN`].
pub const SHARE_AUDIO_DEFAULT: u32 = 50;

/// The gain the mixer should actually apply to shared audio right now.
pub fn share_audio_gain() -> u32 {
    if SHARE_AUDIO_MUTED.load(Ordering::Relaxed) {
        0
    } else {
        SHARE_AUDIO_GAIN.load(Ordering::Relaxed)
    }
}

/// Reset the share controls to their defaults. Called when a call ends: these are
/// per-call by design, and a level left over from the last call would be a surprise.
pub fn reset_share_audio() {
    SHARE_AUDIO_GAIN.store(SHARE_AUDIO_DEFAULT, Ordering::Relaxed);
    SHARE_AUDIO_MUTED.store(false, Ordering::Relaxed);
}

/// Pinned capture/playout devices, as [`cpal::DeviceId`] strings (`"host:id"`, which is
/// what `DeviceId`'s `Display` produces and what the UI round-trips). `None` — the
/// default — means "whatever the platform calls the default", including following it
/// when the user changes it in the OS.
#[cfg(not(target_os = "android"))]
static PREF_INPUT: Mutex<Option<String>> = Mutex::new(None);
#[cfg(not(target_os = "android"))]
static PREF_OUTPUT: Mutex<Option<String>> = Mutex::new(None);

/// Bumped whenever a pinned device changes. The audio thread watches it and rebuilds
/// both streams in place — a device swap must not require hanging up.
#[cfg(not(target_os = "android"))]
static DEVICE_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Bounded frame queue between an audio callback and the call engine.
///
/// Overflow drops the **oldest** frame. A queue that sheds the newest instead (what a
/// `SyncSender::try_send` does) stays permanently full of stale audio the moment the
/// consumer falls behind once: every later frame is discarded on arrival, and what does
/// get through is a fixed 120 ms late. Dropping from the front keeps the delay bounded
/// and costs one frame per overrun instead of all of them.
pub(crate) struct FrameRing<T> {
    q: Mutex<VecDeque<T>>,
    cap: usize,
    /// Where this ring's traffic and its evictions are counted (see [`probe`]). An
    /// eviction here is audio nobody ever hears, and it used to be entirely silent.
    pushed: &'static probe::Counter,
    dropped: &'static probe::Counter,
}

impl<T> FrameRing<T> {
    fn new(
        cap: usize,
        pushed: &'static probe::Counter,
        dropped: &'static probe::Counter,
    ) -> Arc<Self> {
        Arc::new(Self {
            q: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
            pushed,
            dropped,
        })
    }

    /// Append a frame, evicting the oldest when full. Called from audio callbacks and
    /// from the engine task; the critical section is a move of one 20 ms frame.
    pub(crate) fn push(&self, frame: T) {
        if let Ok(mut q) = self.q.lock() {
            self.pushed.bump();
            while q.len() >= self.cap {
                q.pop_front();
                self.dropped.bump();
            }
            q.push_back(frame);
        }
    }

    fn pop(&self) -> Option<T> {
        self.q.lock().ok().and_then(|mut q| q.pop_front())
    }

    fn len(&self) -> usize {
        self.q.lock().map(|q| q.len()).unwrap_or(0)
    }
}

/// Peer screen-share audio into the playout mixer (see [`crate::media_shell::ShellSink`]).
pub type AuxSink = Arc<FrameRing<[i16; SCREEN_AUDIO_SAMPLES]>>;

/// The engine-side endpoints. Dropping it (or the stop flag) ends the audio thread.
pub struct ShellAudio {
    cap: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    play: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    stop: Arc<AtomicBool>,
}

impl Drop for ShellAudio {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        end_timer_period();
    }
}

impl AudioIo for ShellAudio {
    fn read_frame(&mut self, buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool {
        match self.cap.pop() {
            Some(frame) => {
                *buf = frame;
                true
            }
            None => false, // warming up / device hiccup → engine sends silence
        }
    }

    fn write_frame(&mut self, frame: &[i16; SAMPLES_PER_FRAME]) {
        self.play.push(*frame);
    }

    fn playout_queued(&self) -> Option<usize> {
        Some(self.play.len())
    }
}

/// Windows quantises waitable timeouts to the system timer resolution — 15.6 ms by
/// default, so the engine's 20 ms tick actually fires every ~31 ms. At that cadence the
/// mic produces frames half again as fast as they are consumed (constant overruns) and
/// the far end is fed two thirds of a stream: exactly the "chunky" audio Windows callers
/// were reported with. Media apps raise the resolution for their process; we hold 1 ms
/// for the duration of every call and drop back afterwards.
#[cfg(target_os = "windows")]
mod timer_period {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[link(name = "winmm")]
    extern "system" {
        fn timeBeginPeriod(uPeriod: u32) -> u32;
        fn timeEndPeriod(uPeriod: u32) -> u32;
    }

    /// Concurrent calls (1:1 plus a group leg) share one period; the last one out ends it.
    static HOLDERS: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn begin() {
        if HOLDERS.fetch_add(1, Ordering::SeqCst) == 0 {
            unsafe { timeBeginPeriod(1) };
        }
    }

    pub(super) fn end() {
        // `fetch_update` and not a bare decrement: a stray extra drop must not underflow
        // into a flood of unbalanced timeEndPeriod calls.
        let _ = HOLDERS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            n.checked_sub(1).map(|next| {
                if next == 0 {
                    unsafe { timeEndPeriod(1) };
                }
                next
            })
        });
    }
}

#[cfg(target_os = "windows")]
fn begin_timer_period() {
    timer_period::begin();
}
#[cfg(target_os = "windows")]
fn end_timer_period() {
    timer_period::end();
}
#[cfg(not(target_os = "windows"))]
fn begin_timer_period() {}
#[cfg(not(target_os = "windows"))]
fn end_timer_period() {}

/// Call a stream builder monomorphised for whatever sample format the device picked.
///
/// Every format cpal can hand out is listed on purpose: a device format missing from
/// this match is not a degraded call, it is a **dead** one (the stream is never built,
/// both directions go silent), and the format a host reports is not something we get to
/// choose. PipeWire boxes hand the PulseAudio host `I32` — the omission that made every
/// Linux call silent in both directions.
macro_rules! build_for_format {
    ($fmt:expr, $build:ident, ($($arg:expr),* $(,)?)) => {{
        use cpal::SampleFormat as F;
        match $fmt {
            F::I8 => $build::<i8>($($arg),*),
            F::I16 => $build::<i16>($($arg),*),
            F::I32 => $build::<i32>($($arg),*),
            F::I64 => $build::<i64>($($arg),*),
            F::U8 => $build::<u8>($($arg),*),
            F::U16 => $build::<u16>($($arg),*),
            F::U32 => $build::<u32>($($arg),*),
            F::U64 => $build::<u64>($($arg),*),
            F::F32 => $build::<f32>($($arg),*),
            F::F64 => $build::<f64>($($arg),*),
            other => Err(format!("unsupported sample format {other:?}")),
        }
    }};
}
pub(crate) use build_for_format;

/// Start capture + playout. Returns the engine-side [`ShellAudio`] plus the aux (peer
/// screen-audio) ring for the sink, or a human-readable error.
///
/// Blocks until the audio thread has actually built and started both streams: a call
/// whose audio never came up must fail loudly at `call_start` (with the device error),
/// not connect and sit silent. The caller runs this on a blocking task concurrently
/// with the room join, so the wait costs nothing.
pub fn start() -> Result<(ShellAudio, AuxSink), String> {
    let cap = FrameRing::new(RING_FRAMES, &probe::CAP_PUSH, &probe::CAP_DROP);
    let play = FrameRing::new(RING_FRAMES, &probe::PLAY_PUSH, &probe::PLAY_DROP);
    let aux = FrameRing::new(RING_FRAMES, &probe::AUX_PUSH, &probe::AUX_DROP);
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

    begin_timer_period();
    let thread = {
        let (cap, play, aux, stop) = (cap.clone(), play.clone(), aux.clone(), stop.clone());
        std::thread::Builder::new()
            .name("sona-call-audio".into())
            .spawn(move || audio_thread(cap, play, aux, stop, ready_tx))
    };
    if let Err(e) = thread {
        end_timer_period();
        return Err(e.to_string());
    }

    // The thread reports once, either way; a disconnect means it panicked before that.
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            end_timer_period();
            return Err(e);
        }
        Err(_) => {
            end_timer_period();
            return Err("audio thread failed to start".into());
        }
    }

    Ok((ShellAudio { cap, play, stop }, aux))
}

/// Hosts to try for the call, best first.
///
/// Linux: ALSA before whatever `default_host()` picks. Enabling cpal's `pulseaudio`
/// feature (for screen-share monitor sources, which ALSA cannot enumerate) silently
/// changed `default_host()` to PulseAudio for *everything*, and that host is wrong for
/// telephony: its first playout callback asks for a two-second prefill, i.e. two seconds
/// of latency welded onto every call. ALSA's `default` PCM routes into PipeWire/Pulse
/// anyway, so this keeps the audio server's routing and drops the buffering. Pulse stays
/// as the fallback for boxes with no working ALSA `default` (no pipewire-alsa, no
/// libasound pulse plugin).
#[cfg(not(target_os = "android"))]
fn call_hosts() -> Vec<cpal::Host> {
    // Annotated: everywhere but Linux the `cfg` block below is compiled out, leaving
    // nothing to infer the element type from until the push after it.
    let mut hosts: Vec<cpal::Host> = Vec::new();
    #[cfg(target_os = "linux")]
    if let Ok(alsa) = cpal::host_from_id(cpal::HostId::Alsa) {
        hosts.push(alsa);
    }
    let default = cpal::default_host();
    if !hosts.iter().any(|h| h.id() == default.id()) {
        hosts.push(default);
    }
    hosts
}

#[cfg(not(target_os = "android"))]
fn audio_thread(
    cap: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    play: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    aux: Arc<FrameRing<[i16; SCREEN_AUDIO_SAMPLES]>>,
    stop: Arc<AtomicBool>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) {
    // Open once, then supervise: hold the streams until the call ends, rebuilding them
    // in place whenever the user pins a different microphone or output.
    let mut epoch = DEVICE_EPOCH.load(Ordering::SeqCst);
    let mut last_health = std::time::Instant::now();
    let mut health_base = probe::snapshot();
    // Has a single decoded frame ever arrived this session? Until it has, the peer simply
    // is not in the room yet and silence from them is not a fault.
    let mut heard_peer = false;
    let mut streams = match open_streams(&cap, &play, &aux, &stop) {
        Ok(s) => {
            let _ = ready.send(Ok(()));
            Some(s)
        }
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    while !stop.load(Ordering::Relaxed) {
        let now = DEVICE_EPOCH.load(Ordering::SeqCst);
        if now != epoch {
            epoch = now;
            // Release the old devices FIRST: many backends refuse to open a device
            // that is still held, and "pin the device I am already on" must not fail.
            drop(streams.take());
            match open_streams(&cap, &play, &aux, &stop) {
                Ok(s) => streams = Some(s),
                // Nothing to fall back to that hasn't already been tried (the last
                // attempt inside open_streams ignores the pin) — stay silent and retry
                // on the next change rather than kill a live call.
                Err(e) => crate::diag!("[call] audio device switch failed: {e}"),
            }
        }
        if last_health.elapsed() >= std::time::Duration::from_secs(5) {
            last_health = std::time::Instant::now();
            // Only speaks up when a direction is dead, so a healthy call stays silent in
            // the log and a broken one names which half broke.
            if let Some(line) = probe::voice_health_since(&health_base, &mut heard_peer) {
                crate::diag!("[call] {line}");
            }
            health_base = probe::snapshot();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(streams);
}

/// Build capture + playout, trying each host in turn.
///
/// Three attempts. The first two honour the pinned devices; a reconnect (or an instant
/// re-dial) builds the new session's streams while the previous one is still tearing
/// its devices down, and a capture device caught mid-release reports "busy" — a second
/// attempt a moment later succeeds, where failing outright would end an otherwise fine
/// call. The last attempt drops the pin: a call on the platform default beats no call
/// because a pinned device is wedged or gone.
#[cfg(not(target_os = "android"))]
fn open_streams(
    cap: &Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    play: &Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    aux: &Arc<FrameRing<[i16; SCREEN_AUDIO_SAMPLES]>>,
    stop: &Arc<AtomicBool>,
) -> Result<(cpal::Stream, cpal::Stream), String> {
    let mut errors = Vec::<String>::new();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            errors.clear();
        }
        if stop.load(Ordering::Relaxed) {
            break; // the call is already gone; nothing to retry for
        }
        let pinned = attempt < 2;
        for host in call_hosts() {
            match build_duplex(&host, pinned, cap, play, aux) {
                Ok(streams) => return Ok(streams),
                Err(e) => errors.push(format!("{}: {e}", host.id().name())),
            }
        }
    }
    Err(if errors.is_empty() {
        "no audio host available".into()
    } else {
        errors.join("; ")
    })
}

/// On the PulseAudio host, name the buffer size rather than letting the server pick it.
///
/// `BufferSize::Default` reaches PulseAudio as a `BufferAttr` of all-`u32::MAX` — the
/// protocol's "server, you decide" — and PulseAudio decides in *seconds*. That is why
/// [`call_hosts`] prefers ALSA in the first place, but Pulse is still the fallback for a
/// box with no working ALSA `default`, and there it welds seconds of latency onto the
/// call. Measured on the share-capture path, which had no such fallback and so wore the
/// whole fault for six releases: a rock-steady 2.012 s, cut to 32 ms by asking for one
/// frame. See [`crate::media_shell::sysaudio`] for the full measurement.
///
/// Deliberately *only* that host. The ALSA path already runs ~10 ms periods, Windows and
/// macOS were never affected, and a working low-latency path is not worth disturbing to
/// fix one that is not on it.
#[cfg(not(target_os = "android"))]
fn host_config(
    #[allow(unused_mut)] mut cfg: cpal::StreamConfig,
    host: cpal::HostId,
) -> cpal::StreamConfig {
    // `HostId::PulseAudio` only exists where cpal builds that host at all.
    #[cfg(target_os = "linux")]
    if host == cpal::HostId::PulseAudio {
        cfg.buffer_size = cpal::BufferSize::Fixed(SAMPLES_PER_FRAME as u32);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = host;
    cfg
}

/// Build and start capture + playout on the pinned devices, falling back to this
/// host's defaults for whichever side is not pinned (or whose pin has gone away).
#[cfg(not(target_os = "android"))]
fn build_duplex(
    host: &cpal::Host,
    pinned: bool,
    cap: &Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    play: &Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    aux: &Arc<FrameRing<[i16; SCREEN_AUDIO_SAMPLES]>>,
) -> Result<(cpal::Stream, cpal::Stream), String> {
    // ── Capture: device format → mono f32 → 48 kHz → RNNoise (when enabled) → i16
    //    frames → engine.
    fn build_capture<T>(
        device: &cpal::Device,
        cfg: cpal::StreamConfig,
        in_ch: usize,
        in_rate: u32,
        cap: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    ) -> Result<cpal::Stream, String>
    where
        T: cpal::SizedSample,
        f32: cpal::FromSample<T>,
    {
        use nnnoiseless::DenoiseState;
        let mut mono = Vec::<f32>::new();
        let mut at48 = Vec::<f32>::new();
        let mut rs = Resampler::new();
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
                    rs.process(&mono, in_rate, SAMPLE_RATE, &mut at48);
                    dn_in.extend(at48.iter().map(|s| s.clamp(-1.0, 1.0) * 32767.0));
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
                        cap.push(frame);
                    }
                },
                |e| crate::diag!("[call] capture error: {e}"),
                None,
            )
            .map_err(|e| format!("capture: {e}"))
    }

    // ── Playout: engine frames (48 kHz mono voice + 48 kHz stereo peer screen audio)
    //    mixed, then taken to device rate/channels. ──
    fn build_playout<T>(
        device: &cpal::Device,
        cfg: cpal::StreamConfig,
        out_ch: usize,
        out_rate: u32,
        play: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
        aux: Arc<FrameRing<[i16; SCREEN_AUDIO_SAMPLES]>>,
    ) -> Result<cpal::Stream, String>
    where
        T: cpal::SizedSample + cpal::FromSample<f32>,
    {
        let mut queue = Vec::<f32>::new(); // mono at device rate, pending output
        let mut frame48 = Vec::<f32>::new();
        let mut updev = Vec::<f32>::new();
        let mut rs = Resampler::new();
        // False until the ring has built its cushion again (see PLAYOUT_PREFILL).
        let mut armed = false;
        // Echo reference (see `crate::aec`): this stream owns the published timeline
        // until a newer playout stream claims it.
        let reference = crate::aec::reference();
        let token = reference.claim();
        // 48 kHz-domain samples the device has pulled but the mixer had nothing for.
        // Underruns and the pre-fill cushion are played as silence; the reference has
        // to contain those stretches or it drifts against the capture by their length.
        let mut owed = 0.0f64;
        device
            .build_output_stream(
                cfg,
                move |data: &mut [T], _| {
                    let needed = data.len() / out_ch;
                    probe::PLAYOUT_CB.bump();
                    probe::PLAYOUT_DEMAND
                        .add((needed as f64 * SAMPLE_RATE as f64 / out_rate as f64) as u64);
                    owed += needed as f64 * SAMPLE_RATE as f64 / out_rate as f64;
                    if !armed {
                        armed = play.len() >= PLAYOUT_PREFILL || aux.len() >= PLAYOUT_PREFILL;
                    }
                    while armed && queue.len() < needed {
                        // One 20 ms step: voice and/or screen audio, summed at 48 kHz
                        // (stereo aux downmixed — the voice path is mono end-to-end).
                        let voice = play.pop();
                        let aux_frame = aux.pop();
                        if voice.is_none() && aux_frame.is_none() {
                            probe::PLAYOUT_UNDERRUN.bump();
                            armed = false; // underrun → pad with silence, re-cushion
                            break;
                        }
                        if voice.is_some() {
                            probe::PLAY_POP.bump();
                        }
                        if aux_frame.is_some() {
                            probe::AUX_POP.bump();
                        }
                        frame48.clear();
                        // The listener's volume for the shared audio, applied to the aux
                        // contribution only — the peer's voice is a separate control and
                        // must not move when someone turns a screen share down.
                        //
                        // Read once per 20 ms frame rather than per sample: this runs in
                        // an audio callback, and it is the same value for the whole frame.
                        // The same curve the voice path uses, so a percentage means the
                        // same loudness change wherever it is shown.
                        let share = client_core::call::gain_factor(share_audio_gain());
                        for i in 0..SAMPLES_PER_FRAME {
                            let v = voice.map_or(0.0, |f| f[i] as f32 / 32768.0);
                            let a = aux_frame.map_or(0.0, |f| {
                                (f[2 * i] as f32 + f[2 * i + 1] as f32) / 2.0 / 32768.0
                            });
                            frame48.push((v + a * share).clamp(-1.0, 1.0));
                        }
                        // Publish before the device resampler: this is exactly what the
                        // machine is about to play, in the engine's own 48 kHz domain.
                        reference.publish(token, &frame48);
                        probe::REF_REAL.add(frame48.len() as u64);
                        owed -= SAMPLES_PER_FRAME as f64;
                        rs.process(&frame48, SAMPLE_RATE, out_rate, &mut updev);
                        queue.extend_from_slice(&updev);
                    }
                    if owed >= 1.0 {
                        reference.publish_silence(token, owed as usize);
                        probe::REF_SILENCE.add(owed as u64);
                        owed -= owed.floor();
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
                |e| crate::diag!("[call] playout error: {e}"),
                None,
            )
            .map_err(|e| format!("playout: {e}"))
    }

    let input = pinned
        .then(|| pinned_device(true))
        .flatten()
        .or_else(|| host.default_input_device())
        .ok_or("no microphone available")?;
    let in_cfg = input
        .default_input_config()
        .map_err(|e| format!("microphone config: {e}"))?;
    let output = pinned
        .then(|| pinned_device(false))
        .flatten()
        .or_else(|| host.default_output_device())
        .ok_or("no audio output available")?;
    let out_cfg = output
        .default_output_config()
        .map_err(|e| format!("output config: {e}"))?;
    // Name the device the call actually plays into, and at what rate.
    //
    // This is half of a comparison: the screen-share capture logs the source it monitors
    // (see `media_shell::sysaudio`). If the two are not the same device, the echo
    // canceller is being handed a reference for one signal and asked to find it in
    // another — which is indistinguishable, from inside the canceller, from an echo that
    // simply is not there, and a whole test round was spent unable to tell those apart.
    // The microphone too, for the same reason and one more: "I couldn't hear him" and "he
    // couldn't hear me" are different faults on different machines, and with only the
    // playout device logged a one-directional call could not be attributed at all. A
    // capture device that opens and delivers silence looks, from every other vantage point,
    // exactly like a peer who is not sending.
    {
        use cpal::traits::DeviceTrait;
        let name = input
            .id()
            .map(|i| i.id().to_string())
            .unwrap_or_else(|_| "<unnamed>".into());
        crate::diag!(
            "[media] call capture device: {name} @ {} Hz, {} ch",
            in_cfg.sample_rate(),
            in_cfg.channels()
        );
    }
    {
        use cpal::traits::DeviceTrait;
        let name = output
            .id()
            .map(|i| i.id().to_string())
            .unwrap_or_else(|_| "<unnamed>".into());
        crate::diag!(
            "[media] call playout device: {name} @ {} Hz, {} ch",
            out_cfg.sample_rate(),
            out_cfg.channels()
        );
    }

    let framed = |cfg: &cpal::SupportedStreamConfig| host_config((*cfg).into(), host.id());

    let in_stream = build_for_format!(
        in_cfg.sample_format(),
        build_capture,
        (
            &input,
            framed(&in_cfg),
            in_cfg.channels() as usize,
            in_cfg.sample_rate(),
            cap.clone(),
        )
    )?;
    let out_stream = build_for_format!(
        out_cfg.sample_format(),
        build_playout,
        (
            &output,
            framed(&out_cfg),
            out_cfg.channels() as usize,
            out_cfg.sample_rate(),
            play.clone(),
            aux.clone(),
        )
    )?;

    in_stream
        .play()
        .map_err(|e| format!("capture start: {e}"))?;
    out_stream
        .play()
        .map_err(|e| format!("playout start: {e}"))?;
    Ok((in_stream, out_stream))
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
    cap: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    play: Arc<FrameRing<[i16; SAMPLES_PER_FRAME]>>,
    aux: Arc<FrameRing<[i16; SCREEN_AUDIO_SAMPLES]>>,
    stop: Arc<AtomicBool>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let session = VOICE_SESSION.fetch_add(1, Ordering::SeqCst) + 1;
    let mut last_health = std::time::Instant::now();
    let mut health_base = probe::snapshot();
    // Has a single decoded frame ever arrived this session? Until it has, the peer simply
    // is not in the room yet and silence from them is not a fault.
    let mut heard_peer = false;
    crate::android_media::set_voice_capture(true);
    crate::android_media::set_voice_playout(true);
    // The bridge's start calls are best-effort "ensure alive" (the watchdog below
    // re-kicks them); there is no build step that can fail the call outright.
    let _ = ready.send(Ok(()));
    let mut frame = [0i16; SAMPLES_PER_FRAME];
    let mut mixed = [0i16; SAMPLES_PER_FRAME];
    // Watchdog: a healthy mic delivers a frame every 20 ms regardless of mute (mute is
    // engine-side). Going quiet means the record died (route change, HAL restart) or
    // never started (permission granted mid-prompt) — re-kick the bridge, whose
    // start calls are "ensure alive": no-ops on a healthy pipeline, rebuilds otherwise.
    let mut last_frame = std::time::Instant::now();
    let mut last_kick = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        while crate::android_media::read_voice_frame(&mut frame) {
            last_frame = std::time::Instant::now();
            cap.push(frame);
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
            let voice = play.pop();
            let aux_frame = aux.pop();
            if voice.is_none() && aux_frame.is_none() {
                break; // caught up — the AudioTrack pads silence on underrun
            }
            for (i, out) in mixed.iter_mut().enumerate() {
                let v = voice.map_or(0.0, |f| f[i] as f32);
                let a = aux_frame.map_or(0.0, |f| (f[2 * i] as f32 + f[2 * i + 1] as f32) / 2.0);
                *out = (v + a).clamp(-32768.0, 32767.0) as i16;
            }
            crate::android_media::push_playout_frame(&mixed);
        }
        if last_health.elapsed() >= std::time::Duration::from_secs(5) {
            last_health = std::time::Instant::now();
            // Same report as the desktop path, and the same counters: the Kotlin bridge
            // pushes into these very rings, so a dead microphone or a silent playout is
            // visible here too. Quiet while both directions are moving.
            if let Some(line) = probe::voice_health_since(&health_base, &mut heard_peer) {
                crate::diag!("[call] {line}");
            }
            health_base = probe::snapshot();
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // A newer session is already running its own mic/playout — leaving them alive is
    // the point (see VOICE_SESSION); stopping here would kill the successor's audio.
    if VOICE_SESSION.load(Ordering::SeqCst) == session {
        crate::android_media::set_voice_playout(false);
        crate::android_media::set_voice_capture(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression guard for the two-day screen-share echo bug.
    ///
    /// `BufferSize::Default` on the PulseAudio host means "server, you decide", and the
    /// server decides in seconds — 2.012 s, measured. Anything that searches for an echo,
    /// or simply expects a call to be answerable in real time, is dead at that latency.
    /// If this test ever fails because the line was tidied away, read
    /// [`host_config`] before changing it back.
    #[cfg(not(target_os = "android"))]
    #[test]
    fn the_pulse_host_is_never_left_to_pick_its_own_buffer_size() {
        let base = cpal::StreamConfig {
            channels: 2,
            sample_rate: SAMPLE_RATE,
            buffer_size: cpal::BufferSize::Default,
        };
        #[cfg(target_os = "linux")]
        {
            let pulse = host_config(base.clone(), cpal::HostId::PulseAudio);
            assert_eq!(
                pulse.buffer_size,
                cpal::BufferSize::Fixed(SAMPLES_PER_FRAME as u32),
                "the Pulse host was left to choose its own buffer size, which is how the \
                 screen-share echo ended up 2.012 s away from a 512 ms search"
            );
            // The low-latency host is deliberately untouched.
            let alsa = host_config(base.clone(), cpal::HostId::Alsa);
            assert_eq!(alsa.buffer_size, cpal::BufferSize::Default);
        }
        // Rate and channel count must survive either way.
        let out = host_config(base, cpal::default_host().id());
        assert_eq!((out.channels, out.sample_rate), (2, SAMPLE_RATE));
    }

    #[test]
    fn ring_drops_the_oldest_frame_not_the_newest() {
        let ring = FrameRing::<u8>::new(3, &probe::CAP_PUSH, &probe::CAP_DROP);
        for i in 0..5u8 {
            ring.push(i);
        }
        assert_eq!(ring.len(), 3);
        // 0 and 1 were evicted; the freshest audio survives.
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert_eq!(ring.pop(), Some(4));
        assert_eq!(ring.pop(), None);
    }

    /// Real devices, real streams: `cargo test -- --ignored duplex_smoke` on a machine
    /// with a microphone. Ignored by default (CI runners have no audio hardware), but
    /// it is the check that would have caught the silent Linux call — the failure was a
    /// device sample format (`I32`, what the PulseAudio host reports on PipeWire) that
    /// no stream was ever built for, so capture never produced a single frame.
    #[test]
    #[ignore]
    fn duplex_smoke() {
        let (mut audio, _aux) = start().expect("audio devices");
        std::thread::sleep(std::time::Duration::from_millis(600));
        let mut frame = [0i16; SAMPLES_PER_FRAME];
        let mut got = 0;
        for _ in 0..RING_FRAMES {
            if audio.read_frame(&mut frame) {
                got += 1;
            }
        }
        assert!(got > 0, "no capture frames in 600 ms");
        // Playout accepts frames and reports its depth (drives concealment).
        audio.write_frame(&frame);
        assert!(audio.playout_queued().is_some());
    }
}
