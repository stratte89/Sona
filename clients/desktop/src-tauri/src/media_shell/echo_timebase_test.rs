//! Is the capture on the same time base as the reference?
//!
//! [`super::echo_loopback_test`] established two facts that cannot both be innocent: the
//! 997 Hz tone we play comes back through the monitor at the same magnitude it went out
//! (4394.1 published, 4392.4 captured), and yet a 170 ms window of the published
//! reference correlates with the capture at r ≈ 0.2 — which, for the low-passed noise
//! used there and a search over three thousand lags, is exactly what two *unrelated*
//! signals produce. Nothing is being dropped on the way (`play.drop 0`,
//! `playout.underrun 0`, reference published == device demand, `sys.raw_drop 0`).
//!
//! **The answer, found here: the delay was 2.012 seconds and every search ever run was
//! too short to reach it.** The capture is a flawless digital copy of the playout —
//! r = 1.00000 across thirteen seconds, gain 0.998, 60 dB of the capture is us — sitting
//! at a rock-steady 96 576 samples. The suppressor searches 512 ms. The harness searched
//! one and two seconds; the two-second sweep missed by 576 samples. A delay past the end
//! of the window you look in does not read as a large delay. It reads as noise, and it is
//! indistinguishable from two unrelated signals no matter how good the estimator is.
//!
//! The cause was one enum: the monitor stream opened with `BufferSize::Default`, which
//! cpal turns into a PulseAudio `BufferAttr` of all-`u32::MAX` — "server, you decide" —
//! and PipeWire's pulse-server decides in seconds. Asking for a 20 ms buffer instead
//! (`media_shell::sysaudio`) took it to 32 ms, and the unchanged estimator locks
//! immediately and removes 36.8 dB.
//!
//! What survives is the method, because it is what the six preceding releases lacked.
//! One test, asking where each captured frame came from rather than whether two signals
//! correlate. It reads its own answer out: a slope that is not one is a rate error, a
//! staircase is repeated or skipped buffers, scatter is frames out of order, and a
//! uniformly random result means the echo is not inside the range being searched — so
//! widen the range before touching the estimator.
//!
//! It plays **white** noise deliberately. 960 samples of it identify a position in the
//! reference outright, where the band-limited `Voice` the other harness tests use is a
//! ~233 Hz rumble carrying about twenty independent samples per 4096 — which correlates
//! convincingly at pure chance and is how a window sweep talked us into four wrong
//! answers. Never judge an alignment with a narrowband probe.

use std::time::{Duration, Instant};

use client_core::call::{AudioIo, SAMPLES_PER_FRAME};
use client_core::media::{ScreenAudioSource, SCREEN_AUDIO_SAMPLES};

/// Cross-correlate `cap` against every position of `span`, by FFT.
///
/// Returns `corr[k] = Σ span[k+i]·cap[i]`, unnormalised. `span.len()` must be the FFT
/// size; positions past `span.len() - cap.len()` wrap and are meaningless.
fn xcorr(fft: &crate::aec::delay::Fft, span: &[f32], cap: &[f32]) -> Vec<f32> {
    let n = span.len();
    let (mut ar, mut ai) = (span.to_vec(), vec![0.0f32; n]);
    let (mut br, mut bi) = (vec![0.0f32; n], vec![0.0f32; n]);
    br[..cap.len()].copy_from_slice(cap);
    fft.run(&mut ar, &mut ai, false);
    fft.run(&mut br, &mut bi, false);
    for i in 0..n {
        // A · conj(B)
        let (re, im) = (ar[i] * br[i] + ai[i] * bi[i], ai[i] * br[i] - ar[i] * bi[i]);
        ar[i] = re;
        ai[i] = im;
    }
    fft.run(&mut ar, &mut ai, true);
    ar
}

/// Exact normalised correlation of `cap` against `refs[at..]`.
fn corr_at(refs: &[f32], cap: &[f32], at: usize) -> f64 {
    if at + cap.len() > refs.len() {
        return 0.0;
    }
    let r = &refs[at..at + cap.len()];
    let rn: f64 = r
        .iter()
        .map(|v| (*v as f64) * (*v as f64))
        .sum::<f64>()
        .sqrt();
    let cn: f64 = cap
        .iter()
        .map(|v| (*v as f64) * (*v as f64))
        .sum::<f64>()
        .sqrt();
    if rn == 0.0 || cn == 0.0 {
        return 0.0;
    }
    let dot: f64 = r
        .iter()
        .zip(cap.iter())
        .map(|(a, b)| (*a as f64) * (*b as f64))
        .sum();
    dot / (rn * cn)
}

fn rms(v: &[f32]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    (v.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>() / v.len() as f64).sqrt()
}

/// Where in the reference did each captured frame actually come from?
///
/// The band-limited `Voice` used elsewhere is a ~233 Hz rumble: in a 4096-sample window
/// it carries about twenty independent samples, so a correlation search over thousands of
/// lags finds a convincing-looking match by chance alone and no number means anything.
/// White noise fixes that — 960 samples of it identify a position in the reference
/// uniquely — and it turns the question from "do these correlate" into something much
/// more direct: for every 20 ms frame the monitor hands back, *which* 20 ms of playout is
/// it? A healthy path answers with a straight line of slope one. Anything else names its
/// own fault: a slope that is not one is a rate error, a staircase is repeated or skipped
/// buffers, and scatter is frames arriving out of order.
#[test]
#[ignore]
fn where_does_each_captured_frame_come_from() {
    if std::env::var("SONA_AUDIO_LOOPBACK").is_err() {
        eprintln!("skipped: plays audible noise. Headphones off, then SONA_AUDIO_LOOPBACK=1.");
        return;
    }
    // Both of these measure the canceller's *input*. Without the bypass the suppressor has
    // already subtracted the reference from everything reaching this point, so correlating
    // the two measures the subtraction and reports the healthy case as a total failure.
    if std::env::var("SONA_AEC_BYPASS").is_err() {
        eprintln!(
            "skipped: this measures what the canceller is HANDED, so it has to run with \
             SONA_AEC_BYPASS=1 — otherwise the echo has already been removed from the \
             capture and it correctly fails to match the reference."
        );
        return;
    }
    let (mut audio, _aux) = match crate::audio::start() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("no audio on this machine ({e})");
            return;
        }
    };
    let reference = crate::aec::reference();
    let mut capture = super::SystemAudioSource::new();
    let mut sink = [0i16; SCREEN_AUDIO_SAMPLES];

    let mut next_push = Instant::now();
    let warm = Instant::now();
    while warm.elapsed() < Duration::from_secs(3) {
        if Instant::now() >= next_push {
            next_push += Duration::from_millis(20);
            audio.write_frame(&[0i16; SAMPLES_PER_FRAME]);
        }
        while capture.read_frame(&mut sink) {}
        std::thread::sleep(Duration::from_millis(2));
    }

    // What is the machine playing that is not us? Everything below is a signal-to-noise
    // measurement, and a browser tab or a music player sits in the same monitor mix at a
    // level this quiet probe cannot compete with. Measured, not assumed: an assertion that
    // fails whenever somebody has Discord open is one that gets deleted.
    let mut quiet: Vec<f32> = Vec::new();
    let floor_run = Instant::now();
    while floor_run.elapsed() < Duration::from_millis(1500) {
        if Instant::now() >= next_push {
            next_push += Duration::from_millis(20);
            audio.write_frame(&[0i16; SAMPLES_PER_FRAME]);
        }
        while capture.read_frame(&mut sink) {
            quiet.extend(
                (0..SAMPLES_PER_FRAME)
                    .map(|i| (sink[2 * i] as f32 + sink[2 * i + 1] as f32) / 2.0 / 32768.0),
            );
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let floor = rms(&quiet);

    let base = crate::audio::probe::snapshot();
    let mut refs: Vec<f32> = Vec::new();
    let mut heard: Vec<f32> = Vec::new();
    let mut cursor = reference.wpos();
    let mut state = 12345u32;
    let run = Instant::now();
    while run.elapsed() < Duration::from_secs(15) {
        if Instant::now() >= next_push {
            next_push += Duration::from_millis(20);
            let mut frame = [0i16; SAMPLES_PER_FRAME];
            for s in frame.iter_mut() {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                // Flat to Nyquist, ~2 % of full scale: quiet, and every 20 ms of it is
                // unmistakably different from every other 20 ms.
                *s = (((state >> 8) as f32 / 8_388_608.0 - 1.0) * 900.0) as i16;
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

    eprintln!(
        "frame paths while this ran:\n{}",
        crate::audio::probe::report_since(&base)
    );
    eprintln!(
        "reference {} samples (rms {:.5}), capture {} (rms {:.5})",
        refs.len(),
        rms(&refs),
        heard.len(),
        rms(&heard)
    );
    assert!(
        heard.len() > 48_000 * 6 && refs.len() > 48_000 * 6,
        "recorded too little"
    );

    // Each frame is searched over 2.7 s of reference centred on where it would sit if the
    // path were sane, which is far wider than any delay this stack can produce.
    const N: usize = 1 << 17;
    let fft = crate::aec::delay::Fft::new(N);
    let frames = heard.len() / SAMPLES_PER_FRAME;
    let mut prev: Option<i64> = None;
    let mut matched = 0usize;
    let mut sequential = 0usize;
    eprintln!("\n  frame     from reference        r     step");
    for f in (0..frames).step_by(10) {
        let cap_at = f * SAMPLES_PER_FRAME;
        let cap = &heard[cap_at..cap_at + SAMPLES_PER_FRAME];
        if refs.len() < N {
            break;
        }
        // Centre the search span on the capture's own position: the true answer is a few
        // hundred ms behind it, and 2.7 s of span covers five times that either way.
        let span_at = cap_at.saturating_sub(N / 2).min(refs.len() - N);
        let span = &refs[span_at..span_at + N];
        let corr = xcorr(&fft, span, cap);
        let mut best = (0.0f32, 0usize);
        for (k, &v) in corr.iter().take(N - SAMPLES_PER_FRAME).enumerate() {
            if v > best.0 {
                best = (v, k);
            }
        }
        let at = span_at + best.1;
        let r = corr_at(&refs, cap, at);
        if r > 0.7 {
            matched += 1;
        }
        let step = prev.map(|p| at as i64 - p);
        if step == Some(SAMPLES_PER_FRAME as i64 * 10) {
            sequential += 1;
        }
        if f < 400 || r <= 0.7 {
            eprintln!(
                "  {f:>5}   {at:>9} ({:7.2} s)   {r:6.3}   {}",
                at as f64 / 48_000.0,
                step.map(|s| format!("{s:+}")).unwrap_or_else(|| "-".into())
            );
        }
        prev = Some(at as i64);
    }
    let probed = frames.div_ceil(10);
    eprintln!(
        "\n{matched}/{probed} captured frames were found in the reference at all (r > 0.7); \
         {sequential} of them followed the previous one exactly"
    );
    // Frames arriving in order at a constant offset is the *structural* claim, and it
    // survives interference: another app's audio buries individual frames but cannot
    // reorder ours. So this is asserted unconditionally.
    //
    // What this looked like when the capture buffer was the server's choice: 3/75 found
    // and 4 sequential, all of it chance. The whole echo bug is visible right here.
    assert!(
        sequential * 10 >= probed * 8,
        "captured frames are not arriving in order at a constant offset ({sequential} of \
         {probed} followed the previous one exactly): the delay is not a constant, and \
         the suppressor's entire model is that it is"
    );

    // Whether each individual frame is *findable* is a signal-to-noise question, and this
    // probe is deliberately quiet (~2 % of full scale). If the machine is playing anything
    // else, say so and stop — reporting "the capture is not a copy of the playout" because
    // someone left a video running would be a false alarm, and a guard that cries wolf is
    // a guard that gets deleted.
    let signal = rms(&heard);
    if floor > signal * 0.25 {
        eprintln!(
            "\nNOT JUDGED: this machine is playing something else (rms {floor:.5} with us \
             silent, {signal:.5} with us playing). Our probe is ~2 % of full scale and \
             cannot be picked out of that. The ordering check above still passed. Re-run \
             with nothing else playing to check per-frame recovery."
        );
        return;
    }
    assert!(
        matched * 10 >= probed * 9,
        "only {matched} of {probed} captured frames can be found in the reference, on a \
         quiet machine (floor {floor:.5} vs signal {signal:.5}): the capture is not a copy \
         of the playout at any alignment, so nothing downstream of it can cancel anything"
    );
}
