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

/// The monitor source to capture a screen share's system audio from.
///
/// The default (ALSA) host cannot enumerate monitor sources at all, so this goes through
/// cpal's PulseAudio host — the path that works on stock Pulse and PipeWire desktops.
#[cfg(target_os = "linux")]
fn pulse_monitor_source() -> Option<cpal::Device> {
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::host_from_id(cpal::HostId::PulseAudio).ok()?;

    // Ask the server which sink our own playout is attached to, and monitor that one.
    //
    // Everything before this picked a monitor by *name* — the pinned output device, or the
    // default sink — and hoped it was the sink the call plays into. When that guess is
    // wrong the canceller gets a reference for one signal and searches for it in another,
    // which from inside is indistinguishable from there being no echo at all. A field log
    // showed precisely that: a capture the far end could hear themselves in, correlating
    // with our playout no better than two unrelated signals. Windows never had the problem
    // because its loopback is opened *on* the output device and the two cannot disagree.
    //
    // Names are still the fallback, for a machine with no reachable server or a call that
    // has not started playing yet.
    let want = crate::media_shell::appaudio::our_monitor_source()
        .inspect(|m| crate::diag!("[media] share-audio: following the call's own sink ({m})"))
        .or_else(|| {
            crate::audio::pinned_devices()
                .1
                .or_else(|| {
                    host.default_output_device()
                        .and_then(|d| d.id().ok())
                        .map(|id| id.id().to_string())
                })
                .map(|sink| format!("{sink}.monitor"))
        });

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
                        crate::diag!("[media] system audio ended: {e}");
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

/// Name the capture buffer size instead of letting the sound server choose it.
///
/// **This one line is the whole screen-share echo bug. Do not "simplify" it back to
/// `cfg.into()`.** `BufferSize::Default` reaches PulseAudio as a `BufferAttr` with every
/// field set to `u32::MAX` — the protocol's "server, you decide" — and what PipeWire's
/// pulse-server decides for a record stream is **two seconds**.
///
/// Measured through production code with white noise: the monitor capture is a flawless
/// digital copy of our own playout (r = 1.00000 over thirteen seconds, gain 0.998, 60 dB
/// of the capture is us) at a rock-steady lag of 96 576 samples = **2.012 s**.
/// [`crate::aec::suppress::MAX_LAG_SAMPLES`] is 512 ms. The echo was four times outside
/// the range being searched, and a delay past the end of the window you search does not
/// read as a long delay — it reads as noise, indistinguishable from two unrelated signals
/// no matter how good the estimator is. Four estimator rewrites went into that gap over
/// six releases and two days.
///
/// Windows never had it: WASAPI loopback is opened on the render endpoint and clocked by
/// the same engine period as playout, so there is nothing to negotiate. That is exactly
/// the split the field logs showed — `locked at 219 ms` there, `NOT LOCKED, 0 dB` here.
///
/// Fixed, not merely smaller: a record stream's `BufferAttr` is `max_length` and
/// `fragment_size`, and cpal derives both from this one value.
fn capture_config(mut cfg: cpal::StreamConfig) -> cpal::StreamConfig {
    cfg.buffer_size = cpal::BufferSize::Fixed(client_core::call::SAMPLES_PER_FRAME as u32);
    cfg
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
    // The other half of the comparison logged by `crate::audio` when it opens the playout.
    // These two names have to refer to the same device, or there is no echo to find.
    {
        use cpal::traits::DeviceTrait;
        let name = device
            .id()
            .map(|i| i.id().to_string())
            .unwrap_or_else(|_| "<unnamed>".into());
        crate::diag!("[media] share-audio capture source: {name} @ {rate} Hz, {ch} ch");
    }

    let framed = capture_config(cfg.into());

    fn build<T>(
        device: &cpal::Device,
        cfg: cpal::StreamConfig,
        ch: usize,
        rate: u32,
        tx: SyncSender<[i16; SCREEN_AUDIO_SAMPLES]>,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
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
                        // Full → drop, because latency beats backlog. But the drop is
                        // *counted*: the suppressor's reference reader advances one block
                        // per frame it sees, so a frame that never arrives silently shifts
                        // the reference against the capture for the rest of the call.
                        crate::audio::probe::SYS_CAPTURED.bump();
                        if tx.try_send(out).is_err() {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            crate::audio::probe::SYS_RAW_DROP.bump();
                        }
                    }
                },
                |e| crate::diag!("[media] system audio error: {e}"),
                None,
            )
            .map_err(|e| format!("system audio stream: {e}"))
    }

    // Every cpal format, one dispatch (the PulseAudio host's monitor sources come out
    // I32 on PipeWire boxes) — see `build_for_format` for why the list is exhaustive.
    // Deep enough that an ordinary hiccup does not cost a frame at all. Eight was 160 ms,
    // and the delay estimator alone can occupy the consumer for longer than that when it
    // runs; every frame lost there used to desynchronise the reference.
    let (raw_tx, raw_rx) = sync_channel::<[i16; SCREEN_AUDIO_SAMPLES]>(64);
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stream = match crate::audio::build_for_format!(
        cfg.sample_format(),
        build,
        (&device, framed, ch, rate, raw_tx.clone(), dropped.clone())
    ) {
        Ok(s) => s,
        Err(e) => {
            // Say so loudly: on this path the fallback means the echo canceller is very
            // likely searching a range the echo is not in, and that failure is otherwise
            // completely silent (no lock and nothing to cancel share a code path).
            crate::diag!(
                "[media] share-audio: a 20 ms capture buffer was refused ({e}) — falling \
                 back to the server's own size, which on PulseAudio is two seconds and is \
                 far outside the echo canceller's search range"
            );
            crate::audio::build_for_format!(
                cfg.sample_format(),
                build,
                (&device, cfg.into(), ch, rate, raw_tx, dropped.clone())
            )?
        }
    };
    stream.play().map_err(|e| e.to_string())?;

    // Escape hatch for the local harness: with this set the captured audio is passed
    // through untouched. Measuring the canceller's *input* is impossible otherwise —
    // everything reaching the engine has already had a reference subtracted from it, so
    // correlating that against the reference measures the subtraction, not the signals.
    let bypass = std::env::var("SONA_AEC_BYPASS").is_ok();
    if bypass {
        crate::diag!("[media] share-audio echo: SUPPRESSOR BYPASSED (SONA_AEC_BYPASS)");
    }
    let reference = crate::aec::reference();
    let mut reader = crate::aec::RefReader::default();
    let mut suppressor = crate::aec::EchoSuppressor::new();
    let mut refblk = [0.0f32; SAMPLES_PER_FRAME];
    // Say out loud, periodically, whether the echo canceller is actually cancelling.
    // Its total-failure mode (no lock → pass-through) is silent and looks exactly like
    // the healthy no-op, which is how "the peer hears himself during a share" survived
    // two attempts at fixing it: there was no way to tell a broken canceller from an
    // idle one without a second machine and a pair of ears.
    let mut last_report = Instant::now();
    // How often the reference reader had to jump. The suppressor's whole model is that
    // reference and capture advance in lockstep, one block pulled per frame captured — so
    // a re-seat means that assumption just broke, and a stream of them means the reference
    // history it correlates against is a jumbled timeline rather than a signal.
    let (mut ahead, mut behind) = (0u32, 0u32);
    // Frames lost anywhere between the engine and the sound card, reported alongside the
    // lock. A canceller cannot be judged without them: a reference describing audio that
    // was never played, or a capture with holes in it, fails in exactly the way a bad
    // estimator does, and telling those apart used to need a rebuild.
    let mut loss_base = crate::audio::probe::snapshot();
    while last_poll
        .lock()
        .map(|t| t.elapsed() < CAPTURE_LINGER)
        .unwrap_or(false)
    {
        if last_report.elapsed() >= Duration::from_secs(5) {
            last_report = Instant::now();
            if let Some(lost) = crate::audio::probe::losses_since(&loss_base) {
                crate::diag!("[media] audio frames lost in the last 5 s: {lost}");
            }
            loss_base = crate::audio::probe::snapshot();
            let r = suppressor.report();
            // `corr`/`peak` are the two numbers that say whether the *estimator* had
            // anything to work with, which is the question the delay alone cannot answer:
            // a lock that keeps moving and a lock that holds look identical on one line.
            // `peak` near 1 means two delays correlated about equally well — the surface
            // was ambiguous and no estimate was believed.
            //
            // "removed", not "cancelled": see `EchoSuppressor::report` — the figure is
            // reduction of the whole captured mix, most of which is the shared audio that
            // is supposed to survive, so it reads far below the actual ERLE.
            let (seen_ahead, seen_behind) =
                (std::mem::take(&mut ahead), std::mem::take(&mut behind));
            match r.lag {
                Some(lag) => crate::diag!(
                    "[media] share-audio echo: locked at {:.0} ms, removed {:.1} dB \
                     (corr {:.2}, peak {:.1}x, ref {:.1}, cap {:.1}, reseat a{}/b{})",
                    lag * 1000.0 / client_core::call::SAMPLE_RATE as f64,
                    r.db,
                    r.corr,
                    r.dominance,
                    r.ref_rms,
                    r.cap_rms,
                    seen_ahead,
                    seen_behind
                ),
                None => crate::diag!(
                    "[media] share-audio echo: NOT LOCKED (corr {:.2}, peak {:.1}x, \
                     ref {:.1}, cap {:.1}, reseat a{}/b{}) — no delay stood out, so the audio \
                     passes through untouched and the peer may hear themselves",
                    r.corr,
                    r.dominance,
                    r.ref_rms,
                    r.cap_rms,
                    seen_ahead,
                    seen_behind
                ),
            }
        }
        // One reference block consumed per captured frame, in order: that lockstep is
        // what lets the suppressor treat the echo delay as a constant it can measure.
        let mut step = |reader: &mut crate::aec::RefReader,
                        s: &mut crate::aec::EchoSuppressor,
                        blk: &mut [f32; SAMPLES_PER_FRAME]| {
            match reader.pull_detail(reference, blk) {
                crate::aec::Pull::Aligned => {}
                crate::aec::Pull::ReseatAhead => {
                    ahead += 1;
                    s.reset_alignment();
                }
                crate::aec::Pull::ReseatBehind => {
                    behind += 1;
                    s.reset_alignment();
                }
            }
        };
        // Frames the capture queue lost still happened, and the playout published
        // reference for them. Consume that reference before touching the next real frame,
        // or every dropped frame slides the two timelines a block further apart.
        let missed = dropped.swap(0, Ordering::Relaxed);
        for _ in 0..missed {
            step(&mut reader, &mut suppressor, &mut refblk);
        }

        // Every captured frame is processed. None are skipped.
        //
        // A previous attempt drained this down to a couple of frames per pass, on the
        // theory that a backlog put the echo outside the search range. It did two kinds of
        // damage and fixed nothing. The monitor delivers in bursts, so "more than two
        // waiting" is normal arrival rather than a backlog, and discarding the rest threw
        // away four fifths of the shared audio — the far end heard the share stutter.
        // Worse, each discarded frame still consumed a reference block, so the reader
        // raced ahead of the playout and re-seated constantly, destroying the very
        // alignment it was meant to protect. The local harness shows both plainly: 211
        // frames delivered out of 985, and a stream of `a` re-seats.
        //
        // The pipeline delay it was worried about is real and harmless: it shows up as a
        // constant lag, which is exactly what the estimator exists to find, and it finds
        // it with a clearly dominant peak.
        while let Ok(mut frame) = raw_rx.try_recv() {
            // Wait for the reference this frame needs rather than declaring the alignment
            // lost. A burst of captured frames overtakes the playout for a few
            // milliseconds by arriving early, not by drifting, and treating that as a
            // re-seat threw away the per-bin echo path every time — which is why the lock
            // never held long enough to cancel anything. Bounded, so a playout that has
            // genuinely stopped cannot wedge the capture.
            let waited = Instant::now();
            while !reader.ready(reference, SAMPLES_PER_FRAME)
                && waited.elapsed() < Duration::from_millis(60)
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            step(&mut reader, &mut suppressor, &mut refblk);
            if !bypass {
                suppressor.process(&mut frame, &refblk);
            }
            // Full → drop; latency beats backlog. Counted, because the engine polls this
            // once per 20 ms tick while the monitor delivers in bursts, so "full" is not
            // an exotic condition — and a frame lost here is a gap in the audio the far
            // end hears, with nothing upstream aware of it.
            if tx.try_send(frame).is_err() {
                crate::audio::probe::SYS_OUT_DROP.bump();
            } else {
                crate::audio::probe::SYS_OUT.bump();
            }
        }
        // Well under the 20 ms frame cadence, so the extra hop costs no real latency.
        std::thread::sleep(Duration::from_millis(3));
    }
    Ok(())
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;

    /// The regression guard for the screen-share echo bug — see [`capture_config`].
    ///
    /// Two days and six releases went into an echo that sat 2.012 s away from a 512 ms
    /// search because this stream was opened with `BufferSize::Default`. The estimator was
    /// never at fault and rewriting it never could have helped. If this test fails because
    /// somebody tidied the call back to `cfg.into()`, read `capture_config` first.
    #[test]
    fn the_share_capture_never_lets_the_server_choose_its_buffer_size() {
        let got = capture_config(cpal::StreamConfig {
            channels: 2,
            sample_rate: client_core::call::SAMPLE_RATE,
            buffer_size: cpal::BufferSize::Default,
        });
        assert_eq!(
            got.buffer_size,
            cpal::BufferSize::Fixed(client_core::call::SAMPLES_PER_FRAME as u32),
            "system-audio capture was left to the sound server's own buffer size; on \
             PulseAudio that is two seconds, which puts the echo outside every search \
             range in this crate and silently disables cancellation"
        );
        // Rate and channel count are the device's to state, not ours to override.
        assert_eq!(
            (got.channels, got.sample_rate),
            (2, client_core::call::SAMPLE_RATE)
        );
    }
}
