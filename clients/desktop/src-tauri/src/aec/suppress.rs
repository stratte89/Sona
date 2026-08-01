//! The canceller itself: alignment tracking, the per-bin echo-path regression, and the
//! overlap-add resynthesis. See the module docs on [`super`] for why it is built this
//! way; this file is the arithmetic.

use super::delay;
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
/// the worker's own lag.
///
/// Half a second, and it is tighter than it looks: a click played through the real
/// playout and timed back off the real monitor on a PipeWire desktop takes 423-443 ms
/// (see `media_shell::echo_loopback_test`). Widening it to a second was tried and
/// reverted — it bought no lock in the harness and cost 1.9 dB in the drift test, because
/// a larger search range is also more room for a spurious peak. Left where it is until
/// something measured argues otherwise.
const MAX_LAG_HOPS: usize = 384;
pub(super) const MAX_LAG_SAMPLES: usize = MAX_LAG_HOPS * HOP;
/// Re-estimate the delay this often (~0.25 s) so drift is corrected long before it
/// exceeds one hop.
const EST_INTERVAL_HOPS: usize = 188;
/// Sample history per signal. Must hold the deepest aligned read — the fine
/// refinement's window laid `MAX_LAG` back — plus an analysis window.
const HIST: usize = 1 << 16;
const HIST_MASK: u64 = HIST as u64 - 1;

/// Capture window handed to the delay estimator (~0.34 s), and the transform size that
/// covers it plus the whole search range.
const DELAY_WIN: usize = 16_384;
const DELAY_FFT_N: usize = 65_536;
/// How far the winning peak must stand above the best competing peak elsewhere in the
/// search range before it is believed. A correlation surface with two comparable peaks is
/// telling us it does not know, and acting on it is worse than passing the audio through:
/// a wrong alignment is subtracted noise, and re-aligning discards everything learned
/// about the echo path.
const PEAK_DOMINANCE: f32 = 1.5;
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

/// What the canceller is doing right now, for the diagnostic line in the capture loop.
pub struct Report {
    /// Echo delay in samples, if the estimator is locked on to one.
    pub lag: Option<f64>,
    /// How much the captured mix was reduced by (not ERLE — see [`EchoSuppressor::report`]).
    pub db: f32,
    /// RMS of the reference over the window, x1000. If this is ~0 the playout is not
    /// reaching the canceller at all, which is a plumbing fault and not a DSP one — no
    /// estimator can find an echo of a signal it was never given.
    pub ref_rms: f32,
    /// RMS of the capture over the same window, x1000. Both are here because "one of them
    /// is silent" and "neither correlates" are completely different bugs.
    pub cap_rms: f32,
    /// Winning envelope correlation of the last search.
    pub corr: f32,
    /// How far that peak stood above the best competing one. Near 1 means the surface was
    /// ambiguous and the estimate was refused.
    pub dominance: f32,
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
    /// Transform for the delay search, built once — it is large and the search runs four
    /// times a second.
    delay_fft: delay::Fft,
    /// Quality of the last correlation search, for the diagnostic line: how far the peak
    /// rose above the surface, and how far it stood above the best competing peak.
    last_corr: f32,
    last_dominance: f32,
    /// A candidate delay far from the tracked one, waiting for a second opinion. See
    /// [`EchoSuppressor::estimate_lag`].
    pending_jump: Option<f64>,
    /// Reference and capture energy since the last report, for the plumbing check above.
    ref_energy: f64,
    cap_energy: f64,
    meas_blocks: u64,
    /// Energy in and out since the last [`EchoSuppressor::report`], for a live ERLE.
    ///
    /// The synthetic tests prove the algorithm cancels 20–35 dB; what they cannot prove
    /// is that a *particular desktop* gave it a reference that corresponds to what the
    /// monitor is capturing. When it did not, the failure is silent and total — no lock,
    /// no estimate, audio straight through, echo intact — and indistinguishable from the
    /// deliberate no-op it shares that path with. So the two numbers that separate those
    /// cases get measured and reported rather than assumed.
    seen_in: f64,
    seen_out: f64,
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
            hops: 0,
            lag: None,
            drift: 0.0,
            since_est: 0,
            gnum: [[(0.0, 0.0); BINS]; 2],
            gden: [0.0; BINS],
            delay_fft: delay::Fft::new(DELAY_FFT_N),
            last_corr: 0.0,
            last_dominance: 0.0,
            pending_jump: None,
            ref_energy: 0.0,
            cap_energy: 0.0,
            meas_blocks: 0,
            seen_in: 0.0,
            seen_out: 0.0,
        }
    }

    /// What the canceller is actually doing, and reset the window.
    ///
    /// `(delay in samples if locked, dB the captured mix was reduced by)`.
    ///
    /// The **lock is the diagnosis**. `None` means the estimator found no correlation
    /// between the playout it was handed and the audio being captured, which on a desktop
    /// means they are not the same signal — the call plays out of one device and a
    /// different one is being shared. Nothing downstream recovers from that and no amount
    /// of tuning the estimator changes it.
    ///
    /// The dB figure is deliberately *not* ERLE, which cannot be computed live: ERLE is
    /// echo against residual echo, and separating either from the audio genuinely being
    /// shared needs a copy of the content nobody has at runtime. This is the plainer
    /// thing — how much of the captured mix was removed — and it reads far lower than the
    /// ERLE, because the shared audio dominates the mix and is (correctly) kept. A
    /// 35 dB-effective canceller reports single digits here while the game is loud. Use it
    /// as "something correlated with the far end is being taken out", not as a score.
    pub fn report(&mut self) -> Report {
        let db = if self.seen_in > 0.0 && self.seen_out > 0.0 {
            10.0 * (self.seen_in / self.seen_out).log10() as f32
        } else {
            0.0
        };
        self.seen_in = 0.0;
        self.seen_out = 0.0;
        let blocks = self.meas_blocks.max(1) as f32;
        let rep_ref = (self.ref_energy / blocks as f64).sqrt() as f32 * 1000.0;
        let rep_cap = (self.cap_energy / blocks as f64).sqrt() as f32 * 1000.0;
        self.ref_energy = 0.0;
        self.cap_energy = 0.0;
        self.meas_blocks = 0;
        Report {
            lag: self.lag,
            db,
            ref_rms: rep_ref,
            cap_rms: rep_cap,
            corr: self.last_corr,
            dominance: self.last_dominance,
        }
    }

    /// Drop the delay lock (the reference timeline moved, so nothing learned about it
    /// still applies). The per-bin echo path goes with it: it was measured against an
    /// alignment that no longer holds.
    pub fn reset_alignment(&mut self) {
        self.lag = None;
        self.drift = 0.0;
        self.pending_jump = None;
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
        // Gate the measurement per *frame*, and over the whole frame.
        //
        // Doing it per sample was a measurement bug that produced nonsense: input energy
        // was summed only over samples where the reference was active while output energy
        // was summed over every sample of the frame, so the ratio compared two different
        // sample sets and read as much as -38 dB — "the canceller is amplifying" — on a
        // canceller that was working. Both sides now cover the same samples, and the frame
        // only counts at all when the far end was actually audible in it: with the far end
        // silent, in and out are equal by construction and averaging those in would drag a
        // working canceller's figure towards zero.
        let mut ref_e = 0.0f64;
        for n in 0..SAMPLES_PER_FRAME {
            let i = ((self.pos + n as u64) & HIST_MASK) as usize;
            self.ch[0].hist[i] = frame[2 * n] as f32 / 32768.0;
            self.ch[1].hist[i] = frame[2 * n + 1] as f32 / 32768.0;
            self.refh[i] = reference[n];
            ref_e += reference[n] as f64 * reference[n] as f64;
        }
        // Unconditional: the whole point is to see the levels even when nothing is loud
        // enough to measure cancellation on.
        self.ref_energy += ref_e / SAMPLES_PER_FRAME as f64;
        let cap_e: f64 = (0..SAMPLES_PER_FRAME)
            .map(|n| {
                let i = ((self.pos + n as u64) & HIST_MASK) as usize;
                let l = self.ch[0].hist[i] as f64;
                l * l
            })
            .sum();
        self.cap_energy += cap_e / SAMPLES_PER_FRAME as f64;
        self.meas_blocks += 1;
        let measuring = ref_e / SAMPLES_PER_FRAME as f64 > 1e-7;
        if measuring {
            for n in 0..SAMPLES_PER_FRAME {
                let i = ((self.pos + n as u64) & HIST_MASK) as usize;
                let l = self.ch[0].hist[i] as f64;
                let r = self.ch[1].hist[i] as f64;
                self.seen_in += l * l + r * r;
            }
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
        let mut out_e = 0.0f64;
        for (i, s) in frame.iter_mut().enumerate() {
            let c = i & 1;
            let v = self.ch[c].out.pop_front().unwrap_or(0.0);
            out_e += v as f64 * v as f64;
            *s = (v * 32768.0).clamp(-32768.0, 32767.0) as i16;
        }
        // Paired with the input energy above over the same samples of the same frames.
        if measuring {
            self.seen_out += out_e;
        }
    }

    /// One analysis/synthesis hop: delay tracking → per-bin echo path →
    /// subtract → residual suppression → overlap-add.
    fn hop(&mut self) {
        self.hops += 1;

        self.since_est += 1;
        if self.since_est >= EST_INTERVAL_HOPS {
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
        // Correlate the raw waveforms over the whole search range (see `super::delay`).
        // This replaced an envelope correlation that could not find a real echo at all
        // once loud shared audio was in the capture — every field log showed a flat
        // surface, the winning peak never more than ~1.3x its best rival.
        let end = self.hopped;
        if end < (DELAY_WIN + MAX_LAG_SAMPLES) as u64 {
            return; // not enough history yet
        }
        let start = end - (DELAY_WIN + MAX_LAG_SAMPLES) as u64;
        // Capture is the most recent window; the reference reaches `MAX_LAG_SAMPLES`
        // further back, because that is the span being searched.
        let cap: Vec<f32> = (0..DELAY_WIN)
            .map(|i| {
                let idx = ((end - DELAY_WIN as u64 + i as u64) & HIST_MASK) as usize;
                0.5 * (self.ch[0].hist[idx] + self.ch[1].hist[idx])
            })
            .collect();
        let refw: Vec<f32> = (0..DELAY_WIN + MAX_LAG_SAMPLES)
            .map(|i| self.refh[((start + i as u64) & HIST_MASK) as usize])
            .collect();
        let Some(est) = delay::estimate(&self.delay_fft, &cap, &refw, MAX_LAG_SAMPLES) else {
            self.last_corr = 0.0;
            self.last_dominance = 0.0;
            return;
        };
        self.last_corr = est.sharpness;
        self.last_dominance = est.dominance;
        // The peak has to be the only credible one. An ambiguous surface yields nothing,
        // and yielding nothing is a pass-through — the honest answer when we cannot tell
        // where the echo is, and far better than subtracting a wrong alignment.
        if est.dominance < PEAK_DOMINANCE {
            return;
        }
        let meas = est.lag as f64;
        // A big disagreement with the tracked delay has to happen twice before it is
        // believed.
        //
        // The envelope correlation is over speech shape, and loud shared audio — a game, a
        // video — puts plenty of structure into the capture that has nothing to do with the
        // far end. That throws up peaks past `LOCK_CORR` at delays that are simply wrong,
        // and field logs showed the lock hopping between 4 ms and 504 ms every few seconds.
        // Every hop discards the per-bin echo path (it was measured against an alignment
        // that no longer holds) so the regression never gets the second or so of stable
        // alignment it needs to converge, and the canceller spends the whole share
        // re-learning instead of cancelling. Ordinary clock drift is a ramp of tens of
        // samples a second, which `track_delay` follows without ever coming near this
        // threshold; only a genuine re-route jumps, and a genuine re-route persists.
        const JUMP: f64 = 0.02 * SAMPLE_RATE as f64; // 20 ms
        if let Some(lag) = self.lag {
            if (meas - lag).abs() > JUMP {
                match self.pending_jump {
                    Some(prev) if (meas - prev).abs() <= JUMP => {
                        self.pending_jump = None;
                        self.reset_alignment();
                        self.track_delay(meas);
                    }
                    _ => self.pending_jump = Some(meas),
                }
                return;
            }
            self.pending_jump = None;
        }
        self.track_delay(meas);
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
}

/// Sanity check kept next to the constants it constrains: the deepest aligned read must
/// stay inside the sample history, and a frame must be a whole number of hops.
const _: () = {
    assert!(MAX_LAG_SAMPLES + DELAY_WIN + FFT_N <= HIST);
    assert!(DELAY_WIN + MAX_LAG_SAMPLES <= DELAY_FFT_N);
    // The output queue is primed with one hop, which only covers the shortfall of a
    // frame that completes one hop fewer than it consumed.
    assert!(HOP < SAMPLES_PER_FRAME);
    assert!(SCREEN_AUDIO_SAMPLES == SAMPLES_PER_FRAME * 2);
    assert!(SAMPLE_RATE == 48_000);
};

#[cfg(test)]
mod tests;
