//! The canceller itself: alignment tracking, the per-bin echo-path regression, and the
//! overlap-add resynthesis. See the module docs on [`super`] for why it is built this
//! way; this file is the arithmetic.

use client_core::call::{SAMPLES_PER_FRAME, SAMPLE_RATE};
use client_core::media::SCREEN_AUDIO_SAMPLES;

// ── Spectral echo suppression ───────────────────────────────────────────────────────

/// Analysis/synthesis window length (5.3 ms at 48 kHz). One complex tap per bin covers
/// the whole echo path at this size — the delay is compensated separately, leaving a
/// gain plus whatever short filter the resamplers on either side impose — and wider
/// windows measured no better while costing latency.
const FFT_N: usize = 256;
/// Hop. `FFT_N / 4` with a Hann window on both analysis and synthesis is COLA-exact
/// (the squared windows sum to a constant [`OLA_NORM`]), so unity gains reconstruct the
/// input exactly.
const HOP: usize = FFT_N / 4;
const BINS: usize = FFT_N / 2 + 1;
/// Σ hann²(n − mH) for H = N/4.
const OLA_NORM: f32 = 1.5;
/// Samples of delay the suppressor adds: the synthesis window's own `FFT_N - HOP`,
/// plus the hop of priming that keeps the output queue from running dry on frames that
/// complete one hop fewer than they consumed. ~10.7 ms at 48 kHz.
pub const LATENCY: usize = FFT_N;

/// Longest echo delay searched: device output buffering + loopback capture buffering +
/// the worker's own lag. Half a second is far past anything a sound server does.
const MAX_LAG_HOPS: usize = 384;
pub(super) const MAX_LAG_SAMPLES: usize = MAX_LAG_HOPS * HOP;
/// Correlation window for the delay estimate (~0.34 s of speech is plenty).
const EST_HOPS: usize = 256;
/// Envelope history: the whole search range plus the window laid against it.
const ENV_HOPS: usize = MAX_LAG_HOPS + EST_HOPS + 4;
/// Re-estimate the delay this often (~0.25 s) so drift is corrected long before it
/// exceeds one hop.
const EST_INTERVAL_HOPS: usize = 188;
/// Window for refining the hop-resolution estimate to a single sample (~0.1 s).
const FINE_WINDOW: usize = 4800;
/// Sample history per signal. Must hold the deepest aligned read — the fine
/// refinement's window laid `MAX_LAG` back — plus an analysis window.
const HIST: usize = 1 << 16;
const HIST_MASK: u64 = HIST as u64 - 1;

/// Minimum normalized envelope correlation to believe a delay estimate.
const LOCK_CORR: f32 = 0.35;
/// Reference power below which a bin says nothing about the echo path (−80 dBFS).
const REF_POW_FLOOR: f32 = 1e-8;
/// Forgetting factor of the per-bin echo-path regression. At 750 hops/s this is a
/// ~1.3 s memory. Long, deliberately: the echo path is a mixer gain, which does not
/// move, and every doubling of the memory halves the variance the shared audio injects
/// into the estimate. Still short enough to follow someone dragging a volume slider.
const LAMBDA: f32 = 0.999;
/// Ceiling on the estimated echo path. The mixer's gain is ~1; anything far above that
/// is a mis-estimate, and clamping keeps one bad frame from gutting a whole band.
const MAX_ECHO_GAIN: f32 = 4.0;

/// Radix-2 complex FFT with cached twiddles and bit-reversal — small, and the only DSP
/// primitive this module needs (the same reasoning as the hand-rolled resampler in
/// [`crate::audio`]: one page of code beats a dependency).
struct Fft {
    rev: Vec<u16>,
    cos: Vec<f32>,
    sin: Vec<f32>,
}

impl Fft {
    fn new() -> Fft {
        let bits = FFT_N.trailing_zeros();
        let rev = (0..FFT_N)
            .map(|i| (i as u32).reverse_bits() >> (32 - bits))
            .map(|i| i as u16)
            .collect();
        let (mut cos, mut sin) = (Vec::with_capacity(FFT_N / 2), Vec::with_capacity(FFT_N / 2));
        for k in 0..FFT_N / 2 {
            let a = -2.0 * std::f64::consts::PI * k as f64 / FFT_N as f64;
            cos.push(a.cos() as f32);
            sin.push(a.sin() as f32);
        }
        Fft { rev, cos, sin }
    }

    /// In-place forward (`inverse == false`) or inverse transform. The inverse is
    /// scaled by `1/N`, so `inverse(forward(x)) == x`.
    fn run(&self, re: &mut [f32; FFT_N], im: &mut [f32; FFT_N], inverse: bool) {
        for i in 0..FFT_N {
            let j = self.rev[i] as usize;
            if j > i {
                re.swap(i, j);
                im.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= FFT_N {
            let step = FFT_N / len;
            for start in (0..FFT_N).step_by(len) {
                for k in 0..len / 2 {
                    let t = k * step;
                    let (wr, wi) = (
                        self.cos[t],
                        if inverse { -self.sin[t] } else { self.sin[t] },
                    );
                    let (i0, i1) = (start + k, start + k + len / 2);
                    let (xr, xi) = (re[i1] * wr - im[i1] * wi, re[i1] * wi + im[i1] * wr);
                    re[i1] = re[i0] - xr;
                    im[i1] = im[i0] - xi;
                    re[i0] += xr;
                    im[i0] += xi;
                }
            }
            len <<= 1;
        }
        if inverse {
            let s = 1.0 / FFT_N as f32;
            for i in 0..FFT_N {
                re[i] *= s;
                im[i] *= s;
            }
        }
    }
}

/// Per-output-channel synthesis state.
struct Chan {
    hist: Box<[f32]>,
    /// Overlap-add accumulator; `ola[..HOP]` is the finished output of each hop.
    ola: [f32; FFT_N],
    out: std::collections::VecDeque<f32>,
}

impl Chan {
    fn new() -> Chan {
        Chan {
            hist: vec![0.0; HIST].into_boxed_slice(),
            ola: [0.0; FFT_N],
            // Primed so the total delay is exactly LATENCY: the synthesis window's own
            // `FFT_N - HOP`, plus the hop of slack that keeps this queue from running
            // dry on frames that complete one hop fewer than they consumed.
            out: std::collections::VecDeque::from(vec![0.0; LATENCY - (FFT_N - HOP)]),
        }
    }
}

/// Removes the call's own playout from a stereo system-audio capture stream.
///
/// Feed it 20 ms frames of interleaved 48 kHz stereo together with the reference block
/// that a [`super::RefReader`] pulled for the same samples; it returns the frame with the echo
/// suppressed. Output is delayed by [`LATENCY`] samples, primed with silence at the
/// start.
pub struct EchoSuppressor {
    fft: Fft,
    win: [f32; FFT_N],
    ch: [Chan; 2],
    refh: Box<[f32]>,
    /// Absolute sample index of everything ingested so far (capture and reference share
    /// it — that is what the lockstep pull buys).
    pos: u64,
    /// How far the analysis has advanced; trails [`pos`] by less than one hop.
    hopped: u64,
    cap_env: Box<[f32]>,
    ref_env: Box<[f32]>,
    hops: u64,
    /// Echo delay in samples, once the estimator has locked on to one. Fractional and
    /// continuously corrected: see [`EchoSuppressor::track_delay`].
    lag: Option<f64>,
    /// How fast that delay is moving, in samples per hop.
    drift: f64,
    since_est: usize,
    /// Running Σ λᵗ·Capture·conj(Reference) per channel and bin — the numerator of the
    /// echo-path regression.
    gnum: [[(f32, f32); BINS]; 2],
    /// Running Σ λᵗ·|Reference|², its denominator (channel-independent).
    gden: [f32; BINS],
}

impl Default for EchoSuppressor {
    fn default() -> Self {
        Self::new()
    }
}

impl EchoSuppressor {
    pub fn new() -> EchoSuppressor {
        let mut win = [0.0f32; FFT_N];
        for (n, w) in win.iter_mut().enumerate() {
            // Periodic Hann — the variant that satisfies COLA at hop N/4.
            *w = 0.5 - 0.5 * (2.0 * std::f64::consts::PI * n as f64 / FFT_N as f64).cos() as f32;
        }
        EchoSuppressor {
            fft: Fft::new(),
            win,
            ch: [Chan::new(), Chan::new()],
            refh: vec![0.0; HIST].into_boxed_slice(),
            // Start a whole window in: the history before the first sample then reads
            // as the silence it represents, instead of the analysis window running off
            // the front of the buffer and folding future samples into the first hops.
            pos: FFT_N as u64,
            hopped: FFT_N as u64,
            cap_env: vec![0.0; ENV_HOPS].into_boxed_slice(),
            ref_env: vec![0.0; ENV_HOPS].into_boxed_slice(),
            hops: 0,
            lag: None,
            drift: 0.0,
            since_est: 0,
            gnum: [[(0.0, 0.0); BINS]; 2],
            gden: [0.0; BINS],
        }
    }

    /// Drop the delay lock (the reference timeline moved, so nothing learned about it
    /// still applies). The per-bin echo path goes with it: it was measured against an
    /// alignment that no longer holds.
    pub fn reset_alignment(&mut self) {
        self.lag = None;
        self.drift = 0.0;
        self.since_est = 0;
        self.gnum = [[(0.0, 0.0); BINS]; 2];
        self.gden = [0.0; BINS];
    }

    /// Suppress the echo in one 20 ms interleaved-stereo frame, in place.
    /// `reference` is the matching 20 ms of playout (mono, same sample count per
    /// channel) from [`RefReader::pull`].
    pub fn process(
        &mut self,
        frame: &mut [i16; SCREEN_AUDIO_SAMPLES],
        reference: &[f32; SAMPLES_PER_FRAME],
    ) {
        for n in 0..SAMPLES_PER_FRAME {
            let i = ((self.pos + n as u64) & HIST_MASK) as usize;
            self.ch[0].hist[i] = frame[2 * n] as f32 / 32768.0;
            self.ch[1].hist[i] = frame[2 * n + 1] as f32 / 32768.0;
            self.refh[i] = reference[n];
        }
        self.pos += SAMPLES_PER_FRAME as u64;
        // A frame is not a whole number of hops, so run whatever hops it completed and
        // let the output queue carry the remainder into the next one.
        while self.pos - self.hopped >= HOP as u64 {
            self.hopped += HOP as u64;
            self.hop();
        }
        // Drain one frame back out. The queue is primed with a hop of silence at
        // construction, which is exactly the cushion that keeps this from running dry
        // on the frames that complete one hop fewer than they consumed.
        for (i, s) in frame.iter_mut().enumerate() {
            let c = i & 1;
            let v = self.ch[c].out.pop_front().unwrap_or(0.0);
            *s = (v * 32768.0).clamp(-32768.0, 32767.0) as i16;
        }
    }

    /// One analysis/synthesis hop: envelopes → delay tracking → per-bin echo path →
    /// subtract → residual suppression → overlap-add.
    fn hop(&mut self) {
        let slot = (self.hops % ENV_HOPS as u64) as usize;
        // Envelopes are amplitudes, not powers: a delay estimator wants speech shape,
        // and squaring exaggerates peaks into a near-impulse that correlates poorly.
        let mut cap_e = 0.0f32;
        let mut ref_e = 0.0f32;
        for k in 0..HOP {
            let i = ((self.hopped - HOP as u64 + k as u64) & HIST_MASK) as usize;
            cap_e += (self.ch[0].hist[i] + self.ch[1].hist[i]).abs() * 0.5;
            ref_e += self.refh[i].abs();
        }
        self.cap_env[slot] = cap_e / HOP as f32;
        self.ref_env[slot] = ref_e / HOP as f32;
        self.hops += 1;

        self.since_est += 1;
        if self.since_est >= EST_INTERVAL_HOPS && self.hops as usize >= ENV_HOPS {
            self.since_est = 0;
            self.estimate_lag();
        }

        // Reference spectrum at the aligned position. Without a lock there is nothing
        // to subtract and every gain stays at 1 — a COLA-exact pass-through.
        let mut rf = ([0.0f32; FFT_N], [0.0f32; FFT_N]);
        if let Some(lag) = self.lag.as_mut() {
            // Slide the delay by one hop's worth of drift before reading. Doing this
            // every hop, at fractional resolution, is what keeps the reference locked
            // to the capture clock between estimates — and therefore what lets the
            // per-bin echo path be a constant worth averaging over a second.
            *lag = (*lag + self.drift).clamp(0.0, MAX_LAG_SAMPLES as f64);
            let end = self.hopped as f64 - *lag;
            self.gather_at(&self.refh, end, &mut rf.0);
            self.fft.run(&mut rf.0, &mut rf.1, false);
        }

        let mut spec = [([0.0f32; FFT_N], [0.0f32; FFT_N]); 2];
        for (c, (re, im)) in spec.iter_mut().enumerate() {
            self.gather(&self.ch[c].hist, self.hopped, re);
            self.fft.run(re, im, false);
        }

        if self.lag.is_some() {
            self.track_echo(&rf, &spec);
        }

        for (c, sp) in spec.iter_mut().enumerate() {
            let mut clean = [(0.0f32, 0.0f32); BINS];
            let (mut cap_pow, mut err_pow) = (0.0f32, 0.0f32);
            for (k, slot) in clean.iter_mut().enumerate() {
                let cap = (sp.0[k], sp.1[k]);
                if self.lag.is_none() || self.gden[k] <= 0.0 {
                    *slot = cap;
                    continue;
                }
                // Echo path for this bin: the regression's least-squares solution.
                // Clamped, because a bin the reference barely touched can otherwise
                // produce an arbitrary ratio out of numerical noise.
                let (mut gr, mut gi) = (
                    self.gnum[c][k].0 / self.gden[k],
                    self.gnum[c][k].1 / self.gden[k],
                );
                let mag = (gr * gr + gi * gi).sqrt();
                if mag > MAX_ECHO_GAIN {
                    let s = MAX_ECHO_GAIN / mag;
                    gr *= s;
                    gi *= s;
                }
                // Subtract. The echo path really is one complex tap per bin — a digital
                // mix is a delay and a gain, and the delay has already been compensated
                // — so there is no residual-suppression stage after this and nothing
                // that attenuates the shared audio on suspicion. Anything the linear
                // stage cannot explain is, by construction, not the reference.
                let echo = (gr * rf.0[k] - gi * rf.1[k], gr * rf.1[k] + gi * rf.0[k]);
                let err = (cap.0 - echo.0, cap.1 - echo.1);
                cap_pow += cap.0 * cap.0 + cap.1 * cap.1;
                err_pow += err.0 * err.0 + err.1 * err.1;
                *slot = err;
            }
            // Divergence guard, whole-hop: a subtraction that made the frame *louder*
            // is a mis-estimate, and doubling the echo is worse than leaving it alone.
            //
            // Whole-hop, and not per bin, on purpose. Keeping whichever of the two is
            // smaller in each bin looks like a strictly safer version of the same idea
            // and is not: it shaves the low side off every bin's noise, which is a
            // systematic bite out of the shared audio — worth a good 13 dB of the
            // cancellation and audible as a thinning of the sound. At hop granularity
            // the test is unbiased, and in practice it never fires.
            if err_pow > cap_pow {
                for (k, slot) in clean.iter_mut().enumerate() {
                    *slot = (sp.0[k], sp.1[k]);
                }
            }
            let (re, im) = sp;
            for (k, &(cr, ci)) in clean.iter().enumerate() {
                re[k] = cr;
                im[k] = ci;
                if k > 0 && k < FFT_N / 2 {
                    // Keep the spectrum conjugate-symmetric so the inverse is real.
                    re[FFT_N - k] = cr;
                    im[FFT_N - k] = -ci;
                }
            }
            self.fft.run(re, im, true);
            let ch = &mut self.ch[c];
            for (n, w) in self.win.iter().enumerate() {
                ch.ola[n] += re[n] * w / OLA_NORM;
            }
            for n in 0..HOP {
                ch.out.push_back(ch.ola[n]);
            }
            ch.ola.copy_within(HOP.., 0);
            ch.ola[FFT_N - HOP..].fill(0.0);
        }
    }

    /// Windowed copy of the `FFT_N` samples ending at absolute index `end`.
    fn gather(&self, hist: &[f32], end: u64, out: &mut [f32; FFT_N]) {
        let start = end.saturating_sub(FFT_N as u64);
        for (n, o) in out.iter_mut().enumerate() {
            *o = hist[((start + n as u64) & HIST_MASK) as usize] * self.win[n];
        }
    }

    /// The same, at a *fractional* end position, linearly interpolated.
    ///
    /// This is the drift compensator. Rounding the delay to whole samples would leave
    /// the reference sliding up to half a sample against the capture, and half a sample
    /// is a quarter turn of phase at Nyquist — enough on its own to stop the per-bin
    /// estimate ever settling. Linear interpolation costs a fraction of a dB in the top
    /// octave (where an echo of speech has almost nothing) and is exact at DC.
    fn gather_at(&self, hist: &[f32], end: f64, out: &mut [f32; FFT_N]) {
        let start = end - FFT_N as f64;
        for (n, o) in out.iter_mut().enumerate() {
            let p = start + n as f64;
            let i = p.floor();
            let f = (p - i) as f32;
            let i = i as i64 as u64;
            let a = hist[(i & HIST_MASK) as usize];
            let b = hist[((i + 1) & HIST_MASK) as usize];
            *o = (a + (b - a) * f) * self.win[n];
        }
    }

    /// Update the per-bin echo path by exponentially-weighted least squares against the
    /// reference.
    ///
    /// This is the estimator that matters. The audio genuinely being shared is a large
    /// disturbance, but it is *uncorrelated* with the call's playout, so
    /// `Σ Capture·conj(Reference)` averages it away and the ratio converges on the real
    /// echo path — magnitude and phase — rather than on some level statistic that a
    /// loud game can drag around. Frozen while the reference is silent: there is
    /// nothing to learn from, and a bin that has only ever seen noise would otherwise
    /// wander.
    fn track_echo(
        &mut self,
        rf: &([f32; FFT_N], [f32; FFT_N]),
        spec: &[([f32; FFT_N], [f32; FFT_N]); 2],
    ) {
        for k in 0..BINS {
            let rp = rf.0[k] * rf.0[k] + rf.1[k] * rf.1[k];
            if rp <= REF_POW_FLOOR {
                continue;
            }
            self.gden[k] = LAMBDA * self.gden[k] + rp;
            for (c, cap) in spec.iter().enumerate() {
                let (cr, ci) = (cap.0[k], cap.1[k]);
                let acc = &mut self.gnum[c][k];
                // Capture · conj(Reference).
                acc.0 = LAMBDA * acc.0 + cr * rf.0[k] + ci * rf.1[k];
                acc.1 = LAMBDA * acc.1 + ci * rf.0[k] - cr * rf.1[k];
            }
        }
    }

    /// Normalized cross-correlation of the capture and reference envelopes over the
    /// search range. Uncorrelated content (the audio actually being shared) averages
    /// out, so the peak marks the echo delay even when the share is much louder than
    /// the call.
    fn estimate_lag(&mut self) {
        let cap: Vec<f32> = (0..EST_HOPS)
            .map(|i| self.env_at(self.hops - EST_HOPS as u64 + i as u64, true))
            .collect();
        let (cm, cvar) = mean_var(&cap);
        if cvar <= 0.0 {
            return;
        }
        let mut best = (0usize, 0.0f32);
        let mut win = vec![0.0f32; EST_HOPS];
        for lag in 0..MAX_LAG_HOPS {
            for (i, w) in win.iter_mut().enumerate() {
                *w = self.env_at(self.hops - EST_HOPS as u64 - lag as u64 + i as u64, false);
            }
            let (rm, rvar) = mean_var(&win);
            if rvar <= 0.0 {
                continue;
            }
            let mut num = 0.0f32;
            for i in 0..EST_HOPS {
                num += (cap[i] - cm) * (win[i] - rm);
            }
            let corr = num / (cvar * rvar).sqrt();
            if corr > best.1 {
                best = (lag, corr);
            }
        }
        if best.1 < LOCK_CORR {
            return;
        }
        self.track_delay(self.refine_lag(best.0 * HOP) as f64);
    }

    /// Fold a fresh delay measurement into the tracked position and rate.
    ///
    /// An alpha-beta tracker, because the delay is not a constant to be re-measured but
    /// a ramp to be followed: capture and playout run off clocks that are never exactly
    /// equal, so the true delay walks steadily — tens of samples a second is ordinary.
    /// Estimating position alone and re-seating it every quarter second leaves the
    /// reference misaligned by everything that accumulates in between, which at these
    /// window sizes is whole turns of phase in the upper bins; the per-bin estimate then
    /// never settles and the canceller sits at single-digit dB. Learning the *rate* lets
    /// [`hop`](Self::hop) slide the delay continuously between measurements, so the
    /// alignment the regression sees is genuinely static.
    fn track_delay(&mut self, meas: f64) {
        /// Correction applied to position, and to rate, per measurement. Low enough
        /// that one noisy correlation peak cannot yank the alignment.
        const ALPHA: f64 = 0.4;
        const BETA: f64 = 0.1;
        /// Rate ceiling, ±1 sample per hop — 780× any real crystal mismatch, and the
        /// point past which "drift" is really a lost lock.
        const MAX_DRIFT: f64 = 1.0;

        let Some(lag) = self.lag else {
            // First lock: take the measurement and assume the clocks agree until two
            // measurements say otherwise.
            self.lag = Some(meas);
            self.drift = 0.0;
            return;
        };
        let err = meas - lag;
        // A jump this large is not drift — the device changed, or the reference
        // timeline was re-seated. Start over rather than ramp slowly toward it.
        if err.abs() > HOP as f64 {
            self.lag = Some(meas);
            self.drift = 0.0;
            self.gnum = [[(0.0, 0.0); BINS]; 2];
            self.gden = [0.0; BINS];
            return;
        }
        self.lag = Some((lag + ALPHA * err).clamp(0.0, MAX_LAG_SAMPLES as f64));
        self.drift =
            (self.drift + BETA * err / EST_INTERVAL_HOPS as f64).clamp(-MAX_DRIFT, MAX_DRIFT);
    }

    /// Refine a hop-resolution delay to the sample, by cross-correlating the raw
    /// signals over ±1 hop around it.
    ///
    /// Worth the arithmetic: the linear subtraction models the echo path as one complex
    /// gain per bin, which is exactly right for a delay-and-gain path *once the delay is
    /// out of the way*. Left 60-odd samples off inside a 256-sample window, the same
    /// model has to describe a fractional-bin shift instead, and cancels far less.
    fn refine_lag(&self, coarse: usize) -> usize {
        let lo = coarse.saturating_sub(HOP);
        let hi = (coarse + HOP).min(MAX_LAG_SAMPLES);
        let n = FINE_WINDOW.min((self.hopped - FFT_N as u64) as usize);
        if n < HOP * 4 {
            return coarse.clamp(0, MAX_LAG_SAMPLES);
        }
        let cap: Vec<f32> = (0..n)
            .map(|i| self.ch[0].hist[((self.hopped - n as u64 + i as u64) & HIST_MASK) as usize])
            .collect();
        let mut best = (coarse.clamp(lo, hi), f32::NEG_INFINITY);
        for lag in lo..=hi {
            let start = self.hopped - n as u64 - lag as u64;
            let (mut num, mut den) = (0.0f32, 0.0f32);
            for (i, c) in cap.iter().enumerate() {
                let r = self.refh[((start + i as u64) & HIST_MASK) as usize];
                num += c * r;
                den += r * r;
            }
            // Normalised by the reference alone: the capture's own energy is the same
            // for every candidate, so this ranks lags without a square root per lag.
            let score = if den > 0.0 { num * num / den } else { 0.0 };
            if score > best.1 {
                best = (lag, score);
            }
        }
        best.0
    }

    /// Envelope sample by absolute hop index (the ring holds the last [`ENV_HOPS`]).
    fn env_at(&self, hop: u64, capture: bool) -> f32 {
        let src = if capture {
            &self.cap_env
        } else {
            &self.ref_env
        };
        src[(hop % ENV_HOPS as u64) as usize]
    }
}

/// Mean and (unnormalized) variance — the denominator halves of a Pearson correlation.
fn mean_var(v: &[f32]) -> (f32, f32) {
    let m = v.iter().sum::<f32>() / v.len() as f32;
    let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f32>();
    (m, var)
}

/// Sanity check kept next to the constants it constrains: the deepest aligned read must
/// stay inside the sample history, and a frame must be a whole number of hops.
const _: () = {
    assert!(MAX_LAG_SAMPLES + FFT_N + FINE_WINDOW <= HIST);
    // The output queue is primed with one hop, which only covers the shortfall of a
    // frame that completes one hop fewer than it consumed.
    assert!(HOP < SAMPLES_PER_FRAME);
    assert!(SCREEN_AUDIO_SAMPLES == SAMPLES_PER_FRAME * 2);
    assert!(SAMPLE_RATE == 48_000);
};

#[cfg(test)]
mod tests {
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
        assert!(erle > 20.0, "only {erle:.1} dB with a drifting clock");
    }
}
