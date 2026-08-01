//! The echo canceller against *this machine's* real audio stack.
//!
//! Six releases were spent testing echo-cancellation theories by shipping a build to
//! someone else and reading their log. That loop is hours long, costs another person a
//! call each time, and every round produced one number. All of it was avoidable: the
//! failing machine is a Linux desktop with PulseAudio, and so is this one — the same
//! playout path, the same monitor capture, the same suppressor.
//!
//! So this plays a known signal through the real playout, captures it back through the
//! real monitor source, runs the real [`crate::aec`] pipeline over it, and reports what
//! the canceller managed. Everything between the two ends is production code; nothing is
//! simulated.
//!
//! It makes noise, and it needs a sound server, so it is `#[ignore]`d:
//!
//! ```text
//! SONA_AUDIO_LOOPBACK=1 SONA_DEBUG=1 cargo test --release --lib -- --ignored --nocapture echo_loopback
//! ```
//!
//! `SONA_DEBUG=1` because the lines these tests exist to read — `share-audio echo: locked
//! at ... removed ... dB` — go through [`crate::diag`], which is off unless asked for
//! (`--debug` in the app). Without it the tests still run and still assert; they just say
//! nothing about what the canceller did.

use std::time::{Duration, Instant};

/// Long enough for the delay estimator to run several times, short enough that nobody has
/// to listen to it for long.
const SECONDS: u64 = 15;

use client_core::call::{AudioIo, SAMPLES_PER_FRAME};
use client_core::media::{ScreenAudioSource, SCREEN_AUDIO_SAMPLES};

/// Deterministic band-limited noise — speech-shaped enough to correlate like a voice.
pub(super) struct Voice {
    state: u32,
    lp: f32,
}

impl Voice {
    pub(super) fn new() -> Voice {
        Voice { state: 1, lp: 0.0 }
    }
    pub(super) fn next(&mut self) -> f32 {
        self.state = self
            .state
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        let white = (self.state >> 8) as f32 / 8_388_608.0 - 1.0;
        self.lp = 0.97 * self.lp + 0.03 * white;
        self.lp * 3.0
    }
}

/// Play a known signal, capture it back off the monitor, and see how much of it the
/// canceller removes.
///
/// What "working" looks like is the far end's own numbers: a lock that holds at one
/// delay, and double-digit dB removed. What the field kept showing instead was a lock
/// pinned at the edge of the search range and nothing removed.
#[test]
#[ignore]
fn echo_loopback_against_the_real_audio_stack() {
    // This test makes a noise out of the speakers of whatever machine runs it, and the
    // first version made a painfully loud one. `#[ignore]` is not enough of a guard —
    // it only stops the test running by accident, not someone running it *at* a person
    // who is wearing headphones. An explicit opt-in and a warning are the guard.
    if std::env::var("SONA_AUDIO_LOOPBACK").is_err() {
        eprintln!(
            "skipped: this test plays audible noise through the speakers.\n\
             Take your headphones off, then run it with SONA_AUDIO_LOOPBACK=1."
        );
        return;
    }
    eprintln!("*** playing {SECONDS} s of quiet noise through this machine's speakers ***");
    let (mut audio, _aux) = match crate::audio::start() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("no audio on this machine ({e}) — nothing to measure");
            return;
        }
    };
    let mut capture = super::SystemAudioSource::new();

    // Warm both paths up before measuring: the playout stream has to claim the reference
    // ring and the capture thread has to start, and neither is instant.
    // Tunable so the echo can be put above or below whatever else the machine is playing
    // without editing code — the difference between "buried" and "structurally broken" is
    // exactly this knob.
    let amplitude: f32 = std::env::var("SONA_AUDIO_LOOPBACK_LEVEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(700.0);
    let mut voice = Voice::new();
    let mut frame = [0i16; SAMPLES_PER_FRAME];
    let mut sink = [0i16; SCREEN_AUDIO_SAMPLES];
    let start = Instant::now();
    let mut pushed = 0u64;
    let mut got = 0u64;
    let mut silent_reads = 0u64;

    // 20 s at the engine's own cadence: one 20 ms frame of "far end voice" pushed into
    // playout, one frame of shared audio pulled back, exactly as a call does it.
    while start.elapsed() < Duration::from_secs(SECONDS) {
        for s in frame.iter_mut() {
            // ~2% of full scale. The field logs run at reference levels around 5-25 on
            // the scale the diagnostic prints, and this lands in that range — which is
            // both realistic and quiet. The first version used a third of full scale and
            // was genuinely painful to sit next to.
            *s = (voice.next().clamp(-1.0, 1.0) * amplitude) as i16;
        }
        audio.write_frame(&frame);
        pushed += 1;

        if capture.read_frame(&mut sink) {
            got += 1;
            let energy: i64 = sink.iter().map(|s| (*s as i64).abs()).sum();
            if energy / (SCREEN_AUDIO_SAMPLES as i64) < 4 {
                silent_reads += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    eprintln!("pushed {pushed} playout frames, captured {got}, of which {silent_reads} silent");
    assert!(
        got > 100,
        "the monitor produced almost nothing ({got} frames) — capture is not running"
    );
}

/// Where do the frames go?
///
/// Everything else here measures signals. This measures the plumbing: it pushes voice at
/// the engine's exact cadence for a while, drains the share capture the way the engine
/// does, and then prints every counter on both paths ([`crate::audio::probe`]).
///
/// The question it settles is the one six releases of estimator work assumed the answer
/// to. If frames are evicted unplayed, or the reference does not cover the device's
/// timeline, then the canceller is correlating a description of audio nobody heard
/// against a capture with holes in it, and no estimator can recover from that.
#[test]
#[ignore]
fn where_do_the_frames_go() {
    if std::env::var("SONA_AUDIO_LOOPBACK").is_err() {
        eprintln!("skipped: plays audible noise. Headphones off, then SONA_AUDIO_LOOPBACK=1.");
        return;
    }
    let (mut audio, _aux) = match crate::audio::start() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("no audio on this machine ({e})");
            return;
        }
    };
    let mut capture = super::SystemAudioSource::new();
    let mut sink = [0i16; SCREEN_AUDIO_SAMPLES];

    use crate::audio::probe;
    let mut voice = Voice::new();
    let mut next_push = Instant::now();
    let mut push = |audio: &mut crate::audio::ShellAudio| {
        let now = Instant::now();
        if now < next_push {
            std::thread::sleep(next_push - now);
        }
        next_push += Duration::from_millis(20);
        let mut frame = [0i16; SAMPLES_PER_FRAME];
        for s in frame.iter_mut() {
            *s = (voice.next().clamp(-1.0, 1.0) * 3000.0) as i16;
        }
        audio.write_frame(&frame);
    };

    // Opening a monitor source takes the best part of a second, and counting that stretch
    // as loss would make a healthy path look 16 % broken. Warm up, then measure a window.
    let warm = Instant::now();
    while warm.elapsed() < Duration::from_secs(3) {
        push(&mut audio);
        let _ = capture.read_frame(&mut sink);
    }

    let base = probe::snapshot();
    let mut engine_reads = 0u64;
    let run = Instant::now();
    // Poll the capture exactly as the engine does: once per 20 ms tick, one frame per
    // tick. Draining it in a tight loop (as the correlation tests do) hides the queue
    // between the suppressor and the engine, which is one of the places frames go.
    while run.elapsed() < Duration::from_secs(12) {
        push(&mut audio);
        if capture.read_frame(&mut sink) {
            engine_reads += 1;
        }
    }
    let secs = run.elapsed().as_secs_f64();

    eprintln!(
        "\n{:.1} s of call, after warm-up:\n{}",
        secs,
        probe::report_since(&base)
    );
    let due = (secs * 50.0) as u64;
    eprintln!("  engine read       {engine_reads} share frames ({due} due)");
    let (pushed, dropped, popped) = (
        probe::since(&base, &probe::PLAY_PUSH),
        probe::since(&base, &probe::PLAY_DROP),
        probe::since(&base, &probe::PLAY_POP),
    );
    eprintln!(
        "  voice: {pushed} pushed, {dropped} evicted unplayed ({:.1}%), {popped} mixed",
        100.0 * dropped as f64 / pushed.max(1) as f64
    );
    // The device's own clock is the yardstick: whatever it pulled, the reference has to
    // describe, or the two timelines are different lengths and the lag is not a constant.
    let demand = probe::since(&base, &probe::PLAYOUT_DEMAND);
    let real = probe::since(&base, &probe::REF_REAL);
    let silence = probe::since(&base, &probe::REF_SILENCE);
    eprintln!(
        "  device pulled {demand} samples ({:.2} s at 48 kHz), reference published {} \
         ({real} real + {silence} silence) — difference {} samples",
        demand as f64 / 48_000.0,
        real + silence,
        (real + silence) as i64 - demand as i64
    );
    // The capture side's own clock, against the same wall: a monitor source that hands
    // over less than real time is a capture with holes in it, which is fatal to any
    // correlation regardless of what the estimator does with it.
    let captured = probe::since(&base, &probe::SYS_CAPTURED);
    eprintln!(
        "  monitor produced {captured} frames in {secs:.2} s ({:.2} s of audio, {:+.1}% \
         against the wall clock)",
        captured as f64 / 50.0,
        100.0 * (captured as f64 / 50.0 / secs - 1.0)
    );
}

/// Measure the *true* loopback delay, independently of the canceller.
///
/// The estimator kept reporting no usable alignment even with the echo dominating the
/// capture, which is either a delay outside the range it searches or a fault in how the
/// two signals are paired. A click answers that without either: emit one, watch for it
/// coming back, and the gap is the delay. Dropped frames cannot distort it the way a
/// continuous correlation would.
///
/// **Run this with `SONA_AEC_BYPASS=1`.** Now that the canceller works it removes the
/// clicks: without the bypass the first round comes back and the rest vanish, which reads
/// like a broken capture and is exactly the opposite. With it, all five return together.
///
/// It measured the original fault too, misleadingly — at the two-second capture latency
/// this reported 321-443 ms and lost two clicks in five. Those were the *previous* round's
/// clicks arriving during this one: a 600 ms gap plus a 1200 ms watch is a 1.8 s cycle, so
/// a 2 s pipeline aliases straight into it. A delay longer than the window you watch does
/// not read as a long delay. It reads as noise, and it cost six releases.
#[test]
#[ignore]
fn measure_the_real_loopback_delay() {
    if std::env::var("SONA_AUDIO_LOOPBACK").is_err() {
        eprintln!("skipped: plays audible clicks. Headphones off, then SONA_AUDIO_LOOPBACK=1.");
        return;
    }
    let (mut audio, _aux) = match crate::audio::start() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("no audio on this machine ({e})");
            return;
        }
    };
    let mut capture = super::SystemAudioSource::new();
    let mut sink = [0i16; SCREEN_AUDIO_SAMPLES];
    let quiet = [0i16; SAMPLES_PER_FRAME];
    let mut click = [0i16; SAMPLES_PER_FRAME];
    for (i, s) in click.iter_mut().enumerate() {
        // A few milliseconds of tone, not a single sample: a lone impulse is inaudible in
        // the monitor after the sink's own filtering.
        *s = if i < 240 { 12000 } else { 0 };
    }

    // Let both paths settle before timing anything.
    let warm = Instant::now();
    while warm.elapsed() < Duration::from_secs(2) {
        audio.write_frame(&quiet);
        let _ = capture.read_frame(&mut sink);
        std::thread::sleep(Duration::from_millis(20));
    }

    // Whatever else the machine is playing sets a floor, and a click has to clear it by a
    // wide margin to be the click rather than a drum hit. Measure that floor first.
    let mut floor = 0u32;
    let base = Instant::now();
    while base.elapsed() < Duration::from_millis(800) {
        audio.write_frame(&quiet);
        if capture.read_frame(&mut sink) {
            let peak = sink
                .iter()
                .map(|s| s.unsigned_abs() as u32)
                .max()
                .unwrap_or(0);
            floor = floor.max(peak);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let threshold = (floor * 3).max(3000);
    eprintln!("other audio on this machine peaks at {floor}; counting a click above {threshold}");

    let mut delays = Vec::new();
    for round in 0..5 {
        let sent = Instant::now();
        audio.write_frame(&click);
        let mut seen = None;
        // Watch for it coming back for up to a second.
        while sent.elapsed() < Duration::from_millis(1200) {
            if capture.read_frame(&mut sink) {
                let peak = sink
                    .iter()
                    .map(|s| s.unsigned_abs() as u32)
                    .max()
                    .unwrap_or(0);
                if peak > threshold && seen.is_none() {
                    seen = Some(sent.elapsed());
                    break;
                }
            }
            audio.write_frame(&quiet);
            // 20 ms, the engine's own cadence. Pushing faster than the device drains the
            // ring fills it with silence and the click is discarded before it ever
            // reaches the speakers — a test that floods what it measures measures nothing.
            std::thread::sleep(Duration::from_millis(20));
        }
        match seen {
            Some(d) => {
                eprintln!(
                    "round {round}: click returned after {:.0} ms",
                    d.as_secs_f64() * 1000.0
                );
                delays.push(d.as_secs_f64() * 1000.0);
            }
            None => eprintln!("round {round}: click never came back"),
        }
        // Silence between rounds so the next click is unambiguous.
        let gap = Instant::now();
        while gap.elapsed() < Duration::from_millis(600) {
            audio.write_frame(&quiet);
            let _ = capture.read_frame(&mut sink);
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    assert!(
        !delays.is_empty(),
        "no click ever returned — the loopback is not connected"
    );
    let avg = delays.iter().sum::<f64>() / delays.len() as f64;
    eprintln!("true loopback delay ~{avg:.0} ms (search range is 0-512 ms)");
}

/// Does the capture contain our playout at all?
///
/// Everything so far assumed it does and argued about alignment. That assumption has
/// never actually been tested: the click test can be fooled by whatever else is playing,
/// and correlation says nothing about *why* two signals disagree. A pure tone settles it.
/// Play one frequency, look for exactly that frequency in what comes back, and compare it
/// against the rest of the spectrum. Either it is there or it is not.
#[test]
#[ignore]
fn capture_actually_contains_our_playout() {
    if std::env::var("SONA_AUDIO_LOOPBACK").is_err() {
        eprintln!("skipped: plays an audible tone. Headphones off, then SONA_AUDIO_LOOPBACK=1.");
        return;
    }
    let (mut audio, _aux) = match crate::audio::start() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("no audio on this machine ({e})");
            return;
        }
    };
    let mut capture = super::SystemAudioSource::new();
    let mut sink = [0i16; SCREEN_AUDIO_SAMPLES];

    const TONE_HZ: f64 = 997.0; // not a divisor of the frame rate, so it cannot alias into DC
    let mut phase = 0.0f64;
    let step = 2.0 * std::f64::consts::PI * TONE_HZ / 48_000.0;

    let warm = Instant::now();
    while warm.elapsed() < Duration::from_secs(1) {
        audio.write_frame(&[0i16; SAMPLES_PER_FRAME]);
        while capture.read_frame(&mut sink) {}
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut heard: Vec<f32> = Vec::new();
    // The reference is collected the same way and measured the same way. If the tone is in
    // the capture but not in the reference, the canceller is being handed something that is
    // not what the machine played, and no alignment work could ever matter.
    let reference = crate::aec::reference();
    let mut refs: Vec<f32> = Vec::new();
    let mut cursor = reference.wpos();
    let mut next_push = Instant::now();
    let run = Instant::now();
    while run.elapsed() < Duration::from_secs(8) {
        if Instant::now() >= next_push {
            next_push += Duration::from_millis(20);
            let mut frame = [0i16; SAMPLES_PER_FRAME];
            for s in frame.iter_mut() {
                *s = (phase.sin() * 6000.0) as i16;
                phase += step;
            }
            audio.write_frame(&frame);
        }
        let head = reference.wpos();
        if head > cursor {
            let n = ((head - cursor) as usize).min(8192);
            let mut buf = vec![0.0f32; n];
            reference.read(cursor, &mut buf);
            refs.extend_from_slice(&buf);
            cursor += n as u64;
        }
        while capture.read_frame(&mut sink) {
            heard.extend(
                (0..SAMPLES_PER_FRAME)
                    .map(|i| (sink[2 * i] as f32 + sink[2 * i + 1] as f32) / 2.0 / 32768.0),
            );
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(heard.len() > 48_000, "captured almost nothing");

    // Goertzel at the tone, and at two frequencies we never played, for comparison.
    let tail = &heard[heard.len() - 48_000..];
    let power_at = |hz: f64| -> f64 {
        let w = 2.0 * std::f64::consts::PI * hz / 48_000.0;
        let coeff = 2.0 * w.cos();
        let (mut s1, mut s2) = (0.0f64, 0.0f64);
        for x in tail {
            let s0 = *x as f64 + coeff * s1 - s2;
            s2 = s1;
            s1 = s0;
        }
        (s1 * s1 + s2 * s2 - coeff * s1 * s2).max(0.0).sqrt()
    };
    let tone = power_at(TONE_HZ);
    let off1 = power_at(1_499.0);
    let off2 = power_at(2_311.0);
    if refs.len() > 48_000 {
        let rtail = &refs[refs.len() - 48_000..];
        let rpower = |hz: f64| -> f64 {
            let w = 2.0 * std::f64::consts::PI * hz / 48_000.0;
            let coeff = 2.0 * w.cos();
            let (mut s1, mut s2) = (0.0f64, 0.0f64);
            for x in rtail {
                let s0 = *x as f64 + coeff * s1 - s2;
                s2 = s1;
                s1 = s0;
            }
            (s1 * s1 + s2 * s2 - coeff * s1 * s2).max(0.0).sqrt()
        };
        let rt = rpower(TONE_HZ);
        let rf = (rpower(1_499.0) + rpower(2_311.0)) / 2.0;
        eprintln!(
            "reference at {TONE_HZ} Hz: {rt:.1}; elsewhere {rf:.1}; ratio {:.1}x ({} samples)",
            rt / rf.max(1e-9),
            refs.len()
        );
    } else {
        eprintln!("reference collected only {} samples", refs.len());
    }
    let floor = (off1 + off2) / 2.0;
    eprintln!(
        "capture at {TONE_HZ} Hz: {tone:.1}; elsewhere: {off1:.1} / {off2:.1}; ratio {:.1}x",
        tone / floor.max(1e-9)
    );
    assert!(
        tone > floor * 5.0,
        "the tone we played is not in the capture (ratio {:.2}x) — the shared audio is \
         not the sink this call plays into",
        tone / floor.max(1e-9)
    );
}
