//! The property that matters: find the delay when the echo is *not* the loud part.
//!
//! Every case here buries a delayed copy of the reference under an uncorrelated
//! interferer at the levels a real screen share produces, and asks for the delay back.

use super::*;

/// Cheap deterministic pseudo-noise; no rand dependency in this crate.
struct Noise(u32);
impl Noise {
    fn next(&mut self) -> f32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (self.0 >> 8) as f32 / 8_388_608.0 - 1.0
    }
}

/// Speech-ish: noise through a one-pole low pass, so it has structure rather than being
/// flat across the spectrum.
fn voiceish(seed: u32, n: usize) -> Vec<f32> {
    let mut r = Noise(seed);
    let mut lp = 0.0f32;
    (0..n)
        .map(|_| {
            lp = 0.97 * lp + 0.03 * r.next();
            lp * 3.0
        })
        .collect()
}

const WIN: usize = 16_384;
const MAX_LAG: usize = 24_576;
const N: usize = 65_536;

/// Build (capture, reference) for an echo at `lag` samples and gain `echo_gain`, with an
/// interferer at `noise_gain` standing in for the audio actually being shared.
fn scene(lag: usize, echo_gain: f32, noise_gain: f32) -> (Vec<f32>, Vec<f32>) {
    let total = WIN + MAX_LAG + lag + 16;
    let play = voiceish(7, total);
    let mut game = Noise(31);
    // Reference spans the whole search range plus the capture window.
    let reference: Vec<f32> = play[..WIN + MAX_LAG].to_vec();
    // Capture starts `MAX_LAG - lag` into that span: the echo of the reference, delayed.
    let start = MAX_LAG - lag;
    let capture: Vec<f32> = (0..WIN)
        .map(|i| echo_gain * play[start + i] + noise_gain * game.next())
        .collect();
    (capture, reference)
}

/// The headline case, and the one the old estimator could not do: the shared audio is
/// four times the amplitude of the echo — 12 dB down — and the delay still comes back
/// exactly, with a peak that stands well clear of everything else.
#[test]
fn finds_the_delay_with_the_echo_buried_under_the_shared_audio() {
    let fft = Fft::new(N);
    for lag in [1_000usize, 7_500, 20_000] {
        let (cap, refr) = scene(lag, 0.25, 1.0);
        let e = estimate(&fft, &cap, &refr, MAX_LAG).expect("no estimate");
        eprintln!(
            "buried echo, lag {lag}: corr {:.3} peak {:.2}x",
            e.sharpness, e.dominance
        );
        assert!(
            e.lag.abs_diff(lag) <= 2,
            "lag {} for a true delay of {lag}",
            e.lag
        );
        // What a working case looks like, so a field number has something to be compared
        // against: an echo genuinely present in the capture correlates well clear of zero.
        assert!(
            e.sharpness > 0.05,
            "healthy case only correlated {:.3}",
            e.sharpness
        );
        assert!(
            e.dominance > 1.5,
            "peak only {:.2}x the best rival at lag {lag}",
            e.dominance
        );
    }
}

/// Further down still: 20 dB under the interferer. This is past where an envelope
/// correlation has anything left to work with.
#[test]
fn survives_the_echo_being_twenty_db_down() {
    let fft = Fft::new(N);
    let (cap, refr) = scene(5_000, 0.1, 1.0);
    let e = estimate(&fft, &cap, &refr, MAX_LAG).expect("no estimate");
    assert!(e.lag.abs_diff(5_000) <= 2, "lag {}, want 5000", e.lag);
    assert!(e.dominance > 1.5, "peak only {:.2}x", e.dominance);
}

/// No echo at all — only the interferer. There is no delay to find and none must be
/// invented, because a confident wrong answer is what makes the canceller inject noise.
#[test]
fn refuses_when_the_capture_holds_no_echo() {
    let fft = Fft::new(N);
    let mut game = Noise(99);
    let capture: Vec<f32> = (0..WIN).map(|_| game.next()).collect();
    let reference = voiceish(7, WIN + MAX_LAG);
    let e = estimate(&fft, &capture, &reference, MAX_LAG).expect("silence check only");
    eprintln!(
        "no echo present: corr {:.3} peak {:.2}x",
        e.sharpness, e.dominance
    );
    assert!(
        e.dominance < 1.5,
        "claimed a {:.2}x peak on unrelated signals",
        e.dominance
    );
}

/// Silence on either side is "nothing to align", not a failure to report.
#[test]
fn silence_is_not_an_answer() {
    let fft = Fft::new(N);
    let quiet = vec![0.0f32; WIN];
    let reference = voiceish(3, WIN + MAX_LAG);
    assert!(estimate(&fft, &quiet, &reference, MAX_LAG).is_none());
    let capture = voiceish(4, WIN);
    let quiet_ref = vec![0.0f32; WIN + MAX_LAG];
    assert!(estimate(&fft, &capture, &quiet_ref, MAX_LAG).is_none());
}

/// The transform has to be its own inverse, or every number above is meaningless.
#[test]
fn fft_round_trips() {
    let fft = Fft::new(1024);
    let mut r = Noise(17);
    let orig: Vec<f32> = (0..1024).map(|_| r.next()).collect();
    let (mut re, mut im) = (orig.clone(), vec![0.0f32; 1024]);
    fft.run(&mut re, &mut im, false);
    fft.run(&mut re, &mut im, true);
    for (a, b) in orig.iter().zip(re.iter()) {
        assert!((a - b).abs() < 1e-3, "{a} vs {b}");
    }
}

/// Exact recovery when nothing is in the way — the indexing check. If this drifts, every
/// other number in this file is measuring the wrong thing.
#[test]
fn recovers_the_delay_exactly_with_no_interferer() {
    let fft = Fft::new(N);
    for lag in [1_000usize, 5_000, 20_000] {
        let (cap, refr) = scene(lag, 1.0, 0.0);
        let e = estimate(&fft, &cap, &refr, MAX_LAG).unwrap();
        assert_eq!(e.lag, lag, "clean signal must give the delay back exactly");
        // Well clear of the 1.5x the caller demands; the reference mask trades some of
        // this headroom for the robustness the buried-echo cases need.
        assert!(e.dominance > 5.0, "clean peak only {:.1}x", e.dominance);
    }
}

/// Why this is not GCC-PHAT, kept as a test so the answer cannot rot.
///
/// Whitening is the textbook move for finding a signal under an interferer, and for this
/// echo it is actively harmful: the path is a digital mix rather than a room, the
/// reference is low-passed speech, and whitening hands the high bins — pure shared audio —
/// the same vote as the bins carrying the echo. Anyone who "corrects" this file to full
/// PHAT should see this fail rather than ship a canceller that cannot find its own echo.
#[test]
fn whitening_makes_this_worse_not_better() {
    let fft = Fft::new(N);
    let cases = [
        (1_000usize, 0.25f32),
        (7_500, 0.25),
        (20_000, 0.25),
        (5_000, 0.1),
    ];
    let worst = |beta: f32| {
        let mut err = 0usize;
        let mut dom = f32::INFINITY;
        for (lag, g) in cases {
            let (cap, refr) = scene(lag, g, 1.0);
            if let Some(e) = estimate_with(&fft, &cap, &refr, MAX_LAG, beta, REF_MASK) {
                err = err.max(e.lag.abs_diff(lag));
                dom = dom.min(e.dominance);
            }
        }
        (err, dom)
    };
    let (none_err, none_dom) = worst(0.0);
    let (full_err, full_dom) = worst(1.0);
    eprintln!(
        "whitening 0.0: err {none_err} dom {none_dom:.2} | 1.0: err {full_err} dom {full_dom:.2}"
    );
    assert!(
        none_err <= 3,
        "unwhitened must stay accurate, got {none_err}"
    );
    assert!(none_dom > 1.5, "unwhitened peak too weak: {none_dom:.2}");
    assert!(
        full_err > none_err * 10,
        "full whitening used to be far worse (err {full_err} vs {none_err}); \
         if that changed, re-run the sweep and revisit WHITENING"
    );
}
