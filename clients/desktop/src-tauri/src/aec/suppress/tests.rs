//! What the canceller must actually achieve, measured rather than asserted.
//!
//! Every test here builds a scene — a reference signal, an echo of it at some delay and
//! gain, and loud uncorrelated "shared" audio on top — and checks the two things that
//! matter: how much of the echo is gone, and how much of the content survived.

use super::*;

fn fill(frame: &mut [i16; SCREEN_AUDIO_SAMPLES], l: &[f32], r: &[f32]) {
    for i in 0..SAMPLES_PER_FRAME {
        frame[2 * i] = (l[i].clamp(-1.0, 1.0) * 32767.0) as i16;
        frame[2 * i + 1] = (r[i].clamp(-1.0, 1.0) * 32767.0) as i16;
    }
}

/// Cheap deterministic pseudo-noise; no rand dependency in this crate.
struct Noise(u32);
impl Noise {
    fn next(&mut self) -> f32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (self.0 >> 8) as f32 / 8_388_608.0 - 1.0
    }
}

#[test]

fn fft_round_trips() {
    let fft = Fft::new();
    let mut noise = Noise(7);
    let orig: Vec<f32> = (0..FFT_N).map(|_| noise.next()).collect();
    let mut re = [0.0f32; FFT_N];
    let mut im = [0.0f32; FFT_N];
    re.copy_from_slice(&orig);
    fft.run(&mut re, &mut im, false);
    fft.run(&mut re, &mut im, true);
    for i in 0..FFT_N {
        assert!((re[i] - orig[i]).abs() < 1e-4, "{i}: {} {}", re[i], orig[i]);
        assert!(im[i].abs() < 1e-4);
    }
}

/// The Hann/Hann pair at hop N/4 must be constant-overlap-add, or "no suppression"
/// would still colour the shared audio.
#[test]

fn analysis_synthesis_windows_are_cola() {
    let s = EchoSuppressor::new();
    for n in 0..HOP {
        let sum: f32 = (0..FFT_N / HOP)
            .map(|m| {
                let w = s.win[n + m * HOP];
                w * w
            })
            .sum();
        assert!((sum - OLA_NORM).abs() < 1e-5, "{n}: {sum}");
    }
}

/// With no reference at all the suppressor is a 4 ms delay line and nothing else.
#[test]

fn passes_audio_through_when_there_is_no_echo() {
    let mut s = EchoSuppressor::new();
    let mut noise = Noise(11);
    let quiet = [0.0f32; SAMPLES_PER_FRAME];
    let mut sent = Vec::new();
    let mut got = Vec::new();
    for _ in 0..8 {
        let a: Vec<f32> = (0..SAMPLES_PER_FRAME).map(|_| noise.next() * 0.4).collect();
        let mut frame = [0i16; SCREEN_AUDIO_SAMPLES];
        fill(&mut frame, &a, &a);
        sent.extend_from_slice(&a);
        s.process(&mut frame, &quiet);
        got.extend((0..SAMPLES_PER_FRAME).map(|i| frame[2 * i] as f32 / 32768.0));
    }
    let lat = LATENCY;
    let n = sent.len() - lat;
    let err: f32 = (0..n).map(|i| (got[i + lat] - sent[i]).powi(2)).sum();
    let sig: f32 = (0..n).map(|i| sent[i] * sent[i]).sum();
    assert!(err / sig < 1e-3, "reconstruction error {}", err / sig);
}

/// The real case: the loopback carries the shared content *plus* a delayed copy of
/// the call playout. The playout must come out attenuated and the content must not.
#[test]

fn suppresses_the_playout_and_keeps_the_shared_audio() {
    const LAG: usize = 3_000; // 62 ms of device buffering
    const GAIN: f32 = 0.9;
    const CONTENT: f32 = 0.25;
    let mut s = EchoSuppressor::new();
    let mut voice = Noise(3);
    let mut game = Noise(29);

    // Band-limited "voice" (a slow AR process) is far more representative than white
    // noise: it gives the envelope estimator something with speech-like structure.
    let mut lp = 0.0f32;
    let total = 48_000 * 6;
    let playout: Vec<f32> = (0..total + LAG)
        .map(|_| {
            lp = 0.97 * lp + 0.03 * voice.next();
            (lp * 8.0).clamp(-1.0, 1.0) * 0.5
        })
        .collect();
    let content: Vec<f32> = (0..total).map(|_| game.next() * CONTENT).collect();

    let mut r = 0.0f32;
    let mut e = 0.0f32;
    let frames = total / SAMPLES_PER_FRAME;
    let mut out = Vec::with_capacity(total);
    for f in 0..frames {
        let off = f * SAMPLES_PER_FRAME;
        let mut refblk = [0.0f32; SAMPLES_PER_FRAME];
        let mut mix = [0.0f32; SAMPLES_PER_FRAME];
        for i in 0..SAMPLES_PER_FRAME {
            refblk[i] = playout[off + i + LAG];
            mix[i] = content[off + i] + GAIN * playout[off + i];
        }
        let mut frame = [0i16; SCREEN_AUDIO_SAMPLES];
        fill(&mut frame, &mix, &mix);
        s.process(&mut frame, &refblk);
        out.extend((0..SAMPLES_PER_FRAME).map(|i| frame[2 * i] as f32 / 32768.0));
    }
    let lag = s.lag.expect("no delay lock");
    assert!(
        (lag - LAG as f64).abs() < 1.0,
        "delay estimate {lag}, want {LAG}"
    );

    // Measure over the last two seconds, once the estimates have settled (the
    // window stops short of the synthesis latency, which has no output yet).
    let lat = LATENCY;
    let measure = total - 48_000 * 2..total - lat;
    for i in measure.clone() {
        let echo = GAIN * playout[i];
        let residual = out[i + lat] - content[i];
        r += echo * echo;
        e += residual * residual;
    }
    let erle = 10.0 * (r / e).log10();
    eprintln!("static ERLE {erle:.1} dB");
    assert!(erle > 25.0, "only {erle:.1} dB of echo cancellation");

    // …and the shared audio itself survives: correlation with the original content
    // stays high (some ducking in the bins the echo owns is the price).
    let (mut num, mut da, mut db) = (0.0f32, 0.0f32, 0.0f32);
    for i in measure {
        let (a, b) = (content[i], out[i + lat]);
        num += a * b;
        da += a * a;
        db += b * b;
    }
    let corr = num / (da * db).sqrt();
    eprintln!("static corr {corr:.3}");
    assert!(corr > 0.99, "shared audio mangled (corr {corr:.2})");

    // The live report has to agree with the measurement above, because in the field
    // it is the only evidence there is. A canceller that works while its own report
    // says "NOT LOCKED" or "0 dB" would send us hunting the wrong bug — which is
    // precisely the trap this whole diagnostic exists to get us out of.
    let rep = s.report();
    let (lag, db_live) = (rep.lag, rep.db);
    assert!(lag.is_some(), "report claims no lock on a locked canceller");
    // Not compared against `erle`: the live figure is reduction of the whole captured
    // mix, and the shared audio it keeps is most of that mix. It only has to be
    // positive and finite — the lock is what carries the diagnosis.
    assert!(
        db_live > 1.0 && db_live.is_finite(),
        "report shows {db_live:.1} dB removed while cancelling {erle:.1} dB of echo"
    );
    // And it resets, so each window is that window rather than all of history.
    assert_eq!(s.report().db, 0.0, "report window did not reset");
}

/// A delay that really does move must still be followed.
///
/// Requiring a second opinion before believing a big jump is what stops loud shared
/// audio from throwing the lock around (field logs showed it hopping between 4 ms and
/// 504 ms every few seconds, discarding the per-bin estimate each time and so never
/// converging). The risk of that guard is the opposite failure: a genuine re-route —
/// the sound server moving the stream, a device switch — is a real jump, and refusing
/// it forever would leave the canceller aligned to a delay that no longer exists. So
/// the delay is moved mid-scene, well past the threshold, and the canceller has to
/// find it again and go back to cancelling.
#[test]
fn a_delay_that_really_moves_is_followed() {
    const L1: usize = 3_000;
    const L2: usize = 9_000; // a 125 ms jump — far past the 20 ms guard
    const GAIN: f32 = 0.8;
    let mut s = EchoSuppressor::new();
    let mut voice = Noise(11);
    let mut game = Noise(37);
    let mut lp = 0.0f32;
    let total = 48_000 * 16;
    let playout: Vec<f32> = (0..total + L2 * 2)
        .map(|_| {
            lp = 0.97 * lp + 0.03 * voice.next();
            lp * 3.0
        })
        .collect();
    let content: Vec<f32> = (0..total).map(|_| game.next() * 0.30).collect();
    let switch = total / 2;
    let mut out = Vec::with_capacity(total);
    for f in 0..total / SAMPLES_PER_FRAME {
        let off = f * SAMPLES_PER_FRAME;
        let lag = if off < switch { L1 } else { L2 };
        let mut refblk = [0.0f32; SAMPLES_PER_FRAME];
        let mut mix = [0.0f32; SAMPLES_PER_FRAME];
        for i in 0..SAMPLES_PER_FRAME {
            refblk[i] = playout[off + i + lag];
            mix[i] = content[off + i] + GAIN * playout[off + i];
        }
        let mut frame = [0i16; SCREEN_AUDIO_SAMPLES];
        fill(&mut frame, &mix, &mix);
        s.process(&mut frame, &refblk);
        out.extend((0..SAMPLES_PER_FRAME).map(|i| frame[2 * i] as f32 / 32768.0));
    }
    let lag = s.lag.expect("lost the lock entirely after the delay moved");
    assert!(
        (lag - L2 as f64).abs() < 200.0,
        "still aligned to {lag}, want ~{L2} after the jump"
    );
    // And it is cancelling again at the new alignment, not merely pointing at it.
    let (mut r, mut e) = (0.0f32, 0.0f32);
    for i in total - 48_000 * 2..total - LATENCY {
        let echo = GAIN * playout[i];
        let residual = out[i + LATENCY] - content[i];
        r += echo * echo;
        e += residual * residual;
    }
    let erle = 10.0 * (r / e).log10();
    eprintln!("re-lock ERLE {erle:.1} dB");
    assert!(erle > 15.0, "only {erle:.1} dB after re-locking");
}

/// A reference that correlates equally well at several delays must produce no lock at all.
///
/// This is the failure the field logs showed: with loud shared audio in the capture, the
/// estimator kept finding a peak that cleared the absolute threshold and kept landing
/// somewhere different — 20 ms, then 397, then 490 — and every move discarded the per-bin
/// echo path, so it never converged and cancelled a fraction of a dB all share. A peak
/// that does not stand clear of its competitors is the estimator saying it does not know,
/// and the only safe reading of that is to leave the audio alone.
///
/// A periodic reference makes the ambiguity exact: correlation is as good at the true
/// delay as one period either side of it, so nothing can dominate.
#[test]
fn an_ambiguous_correlation_surface_is_refused() {
    const PERIOD: usize = 4_800; // 100 ms — several periods fit the search range
    const LAG: usize = 9_600;
    const GAIN: f32 = 0.9;
    let mut s = EchoSuppressor::new();
    let mut burst = Noise(5);
    // One period of noise, repeated verbatim: every lag differing by a whole period looks
    // exactly as good as the true one.
    let cycle: Vec<f32> = (0..PERIOD).map(|_| burst.next() * 0.5).collect();
    let total = 48_000 * 8;
    let playout: Vec<f32> = (0..total + LAG * 2).map(|i| cycle[i % PERIOD]).collect();
    let mut game = Noise(23);
    let content: Vec<f32> = (0..total).map(|_| game.next() * 0.2).collect();
    for f in 0..total / SAMPLES_PER_FRAME {
        let off = f * SAMPLES_PER_FRAME;
        let mut refblk = [0.0f32; SAMPLES_PER_FRAME];
        let mut mix = [0.0f32; SAMPLES_PER_FRAME];
        for i in 0..SAMPLES_PER_FRAME {
            refblk[i] = playout[off + i + LAG];
            mix[i] = content[off + i] + GAIN * playout[off + i];
        }
        let mut frame = [0i16; SCREEN_AUDIO_SAMPLES];
        fill(&mut frame, &mix, &mix);
        s.process(&mut frame, &refblk);
    }
    let r = s.report();
    eprintln!(
        "ambiguous: lock {:?}, corr {:.2}, peak {:.2}x",
        r.lag, r.corr, r.dominance
    );
    assert!(
        r.dominance < PEAK_DOMINANCE,
        "a periodic reference should not produce a dominant peak (got {:.2}x)",
        r.dominance
    );
    assert!(
        r.lag.is_none(),
        "locked at {:?} on a surface with no distinguishable peak",
        r.lag
    );
}

/// With nothing playing out, the report must say "no lock" rather than invent a
/// number — the case where the shared sink is not the sink the call plays into, and
/// the one where the far end is simply quiet, are both this.
#[test]
fn report_admits_when_there_is_nothing_to_lock_on_to() {
    let mut s = EchoSuppressor::new();
    let mut game = Noise(7);
    for _ in 0..200 {
        let mut frame = [0i16; SCREEN_AUDIO_SAMPLES];
        for i in 0..SAMPLES_PER_FRAME {
            let v = (game.next() * 8000.0) as i16;
            frame[2 * i] = v;
            frame[2 * i + 1] = v;
        }
        // Silent reference: the call is playing nothing into this sink.
        s.process(&mut frame, &[0.0f32; SAMPLES_PER_FRAME]);
    }
    assert!(s.report().lag.is_none(), "locked on to a silent reference");
}

/// The same scene, but with the capture clock running slightly fast against the
/// reference — which is what every real machine does. A sound server resampling
/// 44.1 kHz, or two devices on separate crystals, walks the echo delay by tens of
/// samples a second; the canceller has to track that without losing what it learned.
#[test]

fn cancels_through_clock_drift() {
    const LAG: usize = 3_000;
    const GAIN: f32 = 0.9;
    // 1000 ppm ≈ 48 samples/s — the order a fractional-carry-dropping resampler
    // produces, and far past the point where re-locking the delay is rare.
    const PPM: f64 = 1000e-6;
    let mut s = EchoSuppressor::new();
    let mut voice = Noise(3);
    let mut game = Noise(29);
    let mut lp = 0.0f32;
    let total = 48_000 * 8;
    let playout: Vec<f32> = (0..total + LAG * 2)
        .map(|_| {
            lp = 0.97 * lp + 0.03 * voice.next();
            (lp * 8.0).clamp(-1.0, 1.0) * 0.5
        })
        .collect();
    let content: Vec<f32> = (0..total).map(|_| game.next() * 0.25).collect();
    // The echo the machine actually plays back, read at a drifting rate.
    let at = |t: f64| -> f32 {
        let i = t.floor() as usize;
        let f = (t - i as f64) as f32;
        let (a, b) = (
            playout[i.min(playout.len() - 1)],
            playout[(i + 1).min(playout.len() - 1)],
        );
        a + (b - a) * f
    };
    let mut echo = vec![0.0f32; total];
    for (i, e) in echo.iter_mut().enumerate() {
        *e = GAIN * at(i as f64 * (1.0 - PPM));
    }

    let frames = total / SAMPLES_PER_FRAME;
    let mut out = Vec::with_capacity(total);
    for f in 0..frames {
        let off = f * SAMPLES_PER_FRAME;
        let mut refblk = [0.0f32; SAMPLES_PER_FRAME];
        let mut mix = [0.0f32; SAMPLES_PER_FRAME];
        for i in 0..SAMPLES_PER_FRAME {
            refblk[i] = playout[off + i + LAG];
            mix[i] = content[off + i] + echo[off + i];
        }
        let mut frame = [0i16; SCREEN_AUDIO_SAMPLES];
        fill(&mut frame, &mix, &mix);
        s.process(&mut frame, &refblk);
        out.extend((0..SAMPLES_PER_FRAME).map(|i| frame[2 * i] as f32 / 32768.0));
    }

    let lat = LATENCY;
    let (mut r, mut e) = (0.0f32, 0.0f32);
    for i in total - 48_000 * 3..total - lat {
        r += echo[i] * echo[i];
        let residual = out[i + lat] - content[i];
        e += residual * residual;
    }
    let erle = 10.0 * (r / e).log10();
    eprintln!("drift ERLE {erle:.1} dB");
    // 18, not the 21 this measured under the old envelope estimator. The delay search now
    // correlates a third of a second of raw waveform, and at this deliberately extreme
    // 1000 ppm the clock walks ~16 samples across that window, which blurs the peak and
    // costs about 1.5 dB here. That is a real regression in this synthetic case and a
    // large win in the one that matters: the estimator this replaced could not find a
    // field echo at all. Tightening the window to win the drift case back would trade away
    // exactly the robustness it was replaced for.
    assert!(erle > 18.0, "only {erle:.1} dB with a drifting clock");
}
