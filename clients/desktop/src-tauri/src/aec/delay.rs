//! Finding the echo delay when the echo is the quiet part of the signal.
//!
//! The estimator this replaces correlated *amplitude envelopes* — one number per 64
//! samples, no phase, no spectrum. That works when the echo dominates what was captured,
//! which is what the synthetic tests set up and why they measured 35 dB. It does not work
//! during a real screen share, and the field logs said so in one column: across a whole
//! call the winning peak never stood more than about 1.3x above the best competing one,
//! with correlations wandering between 0.12 and 0.66. A flat surface. Envelopes of two
//! loud busy signals correlate moderately at *every* lag, and the echo — a fraction of a
//! mix dominated by whatever is being shared — never produced a spike to find.
//!
//! The replacement is a **generalised cross-correlation** on the raw waveforms, computed
//! in the frequency domain: correlate reference against capture across the whole search
//! range at once, and take the peak.
//!
//! The obvious choice was GCC-**PHAT**, which whitens the cross-spectrum so every
//! frequency contributes only phase agreement and nothing loudness — the textbook
//! estimator for a signal buried under an interferer. Measured against this problem it
//! came last, badly. The sweep in the tests, over echoes 12 to 20 dB under the shared
//! audio:
//!
//! ```text
//!     whitening 0.00 -> worst error     2 samples, weakest peak 1.84x
//!     whitening 0.50 -> worst error     2 samples, weakest peak 1.45x
//!     whitening 0.75 -> worst error     3 samples, weakest peak 1.15x
//!     whitening 1.00 -> worst error 17220 samples, weakest peak 1.01x  (textbook PHAT)
//! ```
//!
//! Whitening is the right instinct for an *acoustic* echo, where the path is a room and
//! smears energy across the spectrum. This echo is a digital mix: one gain, one delay, no
//! room. The reference is speech, so its energy sits low, and whitening promotes the high
//! bins — where the capture is nothing but the shared audio — to equal weight with the
//! bins actually carrying the echo. No whitening means weighting by energy, which is the
//! matched filter for this, and the measurements agree.
//!
//! What survives from the PHAT idea is the part doing the real work: dropping bins where
//! the *reference* is silent, since those cannot say where its echo went.
//!
//! What comes out is a lag in samples plus the two numbers needed to decide whether to
//! believe it: how far the peak rises above the surface, and how far it stands above the
//! best peak elsewhere. An ambiguous surface still yields nothing.

/// Radix-2 complex FFT sized at construction. The one in [`super::suppress`] is a fixed
/// 256 points for the per-bin path; this needs tens of thousands, so it carries its own.
pub struct Fft {
    n: usize,
    rev: Vec<u32>,
    cos: Vec<f32>,
    sin: Vec<f32>,
}

impl Fft {
    /// `n` must be a power of two.
    pub fn new(n: usize) -> Fft {
        debug_assert!(n.is_power_of_two());
        let bits = n.trailing_zeros();
        let rev = (0..n)
            .map(|i| (i as u32).reverse_bits() >> (32 - bits))
            .collect();
        let (mut cos, mut sin) = (Vec::with_capacity(n / 2), Vec::with_capacity(n / 2));
        for k in 0..n / 2 {
            let a = -2.0 * std::f64::consts::PI * k as f64 / n as f64;
            cos.push(a.cos() as f32);
            sin.push(a.sin() as f32);
        }
        Fft { n, rev, cos, sin }
    }

    /// In-place transform; the inverse is scaled by `1/n`.
    pub fn run(&self, re: &mut [f32], im: &mut [f32], inverse: bool) {
        debug_assert_eq!(re.len(), self.n);
        debug_assert_eq!(im.len(), self.n);
        for i in 0..self.n {
            let j = self.rev[i] as usize;
            if j > i {
                re.swap(i, j);
                im.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= self.n {
            let step = self.n / len;
            for start in (0..self.n).step_by(len) {
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
            let s = 1.0 / self.n as f32;
            for i in 0..self.n {
                re[i] *= s;
                im[i] *= s;
            }
        }
    }
}

/// One delay measurement.
pub struct Estimate {
    /// Echo delay in samples.
    pub lag: usize,
    /// Peak height as a fraction of the geometric mean of the two signals' energies — a
    /// correlation coefficient, so 0 means "these two signals have nothing in common" and
    /// a large value means they do.
    ///
    /// Raw peak height was useless in the field: it scales with how loud everything
    /// happens to be, so the same number meant different things on two machines. What has
    /// to be distinguishable is "the echo is not in this capture" from "it is, and the
    /// alignment or the subtraction is wrong", and only a normalised figure says which.
    pub sharpness: f32,
    /// Peak height over the best peak outside its own neighbourhood.
    pub dominance: f32,
}

/// Magnitudes below this contribute nothing: dividing by the magnitude is what PHAT does,
/// and an empty bin would otherwise have its numerical noise amplified to full weight.
const MAG_FLOOR: f32 = 1e-6;
/// How much of the phase transform to apply; 0 = none. Kept as a named constant rather
/// than deleted because "why is this not PHAT?" is the obvious question about this file,
/// and the sweep that answers it is a test. Do not raise it without re-running that sweep:
/// every step towards 1.0 measured worse.
const WHITENING: f32 = 0.0;
/// Bins whose reference magnitude is below this fraction of the mean are dropped: the
/// reference is the only thing that knows where its own echo is, and where it is silent
/// there is nothing to find.
const REF_MASK: f32 = 0.5;
/// Half-width of the neighbourhood around the winner excluded when looking for a rival,
/// in samples. A real peak has width — its own shoulders are not competition.
const EXCLUDE: usize = 240; // 5 ms

/// Estimate the delay of `capture` behind `reference`, searching `0..=max_lag` samples.
///
/// `capture` is the window being explained; `reference` must extend `max_lag` samples
/// *further back* than it, because that is the range being searched. Returns `None` when
/// either signal is silent — there is nothing to align, which is not a failure.
pub fn estimate(fft: &Fft, capture: &[f32], reference: &[f32], max_lag: usize) -> Option<Estimate> {
    estimate_with(fft, capture, reference, max_lag, WHITENING, REF_MASK)
}

fn estimate_with(
    fft: &Fft,
    capture: &[f32],
    reference: &[f32],
    max_lag: usize,
    beta: f32,
    mask: f32,
) -> Option<Estimate> {
    let n = fft.n;
    debug_assert!(capture.len() + max_lag <= n);
    debug_assert_eq!(reference.len(), capture.len() + max_lag);

    let energy = |v: &[f32]| v.iter().map(|s| (*s as f64) * (*s as f64)).sum::<f64>();
    let (cap_e, ref_e) = (energy(capture), energy(reference));
    if cap_e <= 1e-9 || ref_e <= 1e-9 {
        return None;
    }

    let (mut cr, mut ci) = (vec![0.0f32; n], vec![0.0f32; n]);
    let (mut rr, mut ri) = (vec![0.0f32; n], vec![0.0f32; n]);
    cr[..capture.len()].copy_from_slice(capture);
    rr[..reference.len()].copy_from_slice(reference);
    fft.run(&mut cr, &mut ci, false);
    fft.run(&mut rr, &mut ri, false);

    // Bins where the reference has no energy say nothing about where its echo went, and
    // whitening would promote their numerical noise to full weight. Measure the reference
    // spectrum first so those can be dropped outright.
    let refmag: Vec<f32> = (0..n)
        .map(|k| (rr[k] * rr[k] + ri[k] * ri[k]).sqrt())
        .collect();
    let refmean = refmag.iter().map(|m| *m as f64).sum::<f64>() / n as f64;
    let floor = (refmean as f32) * mask;

    // Ref · conj(Cap), whitened by |P|^beta — the phase transform, partially applied.
    for k in 0..n {
        let (ar, ai) = (rr[k], ri[k]);
        let (br, bi) = (cr[k], -ci[k]);
        let (pr, pi) = (ar * br - ai * bi, ar * bi + ai * br);
        let mag = (pr * pr + pi * pi).sqrt();
        if mag < MAG_FLOOR || refmag[k] < floor {
            rr[k] = 0.0;
            ri[k] = 0.0;
        } else {
            let w = mag.powf(beta);
            rr[k] = pr / w;
            ri[k] = pi / w;
        }
    }
    fft.run(&mut rr, &mut ri, true);

    // Normalise every lag by the energy of the reference window it used.
    //
    // Raw cross-correlation is a matched filter only when the reference is stationary. It
    // is not: speech, music and silence pass through it, so a lag where the reference
    // happens to be *loud* scores higher than the lag where it actually *matches*, and the
    // argmax lands wherever the far end was shouting. The synthetic tests never caught it
    // because they use stationary noise throughout, and the field consequence was an
    // estimator that reported 1591 ms while a plain normalised scan of the same two
    // signals found the true peak at 389 ms.
    //
    // A prefix sum of squares makes the per-lag window energy O(1), so this costs one pass.
    let mut energy = vec![0.0f64; reference.len() + 1];
    for (i, v) in reference.iter().enumerate() {
        energy[i + 1] = energy[i] + (*v as f64) * (*v as f64);
    }
    let cap_norm = capture
        .iter()
        .map(|v| (*v as f64) * (*v as f64))
        .sum::<f64>()
        .sqrt();
    let win = capture.len();
    for (k, v) in rr.iter_mut().enumerate().take(max_lag + 1) {
        // Correlation index `k` read the reference starting at `k` (see below), so that is
        // the window whose energy this lag must be judged against.
        let hi = (k + win).min(reference.len());
        let ref_e = (energy[hi] - energy[k.min(hi)]).max(0.0).sqrt();
        let denom = ref_e * cap_norm;
        *v = if denom > 1e-12 {
            (*v as f64 / denom) as f32
        } else {
            0.0
        };
    }

    // Index `k` of the correlation corresponds to `lag = max_lag - k` (the reference
    // starts `max_lag` samples earlier than the capture window).
    let surface = &rr[..=max_lag];
    let mut best = (0usize, f32::NEG_INFINITY);
    let mut sum = 0.0f64;
    for (k, v) in surface.iter().enumerate() {
        sum += *v as f64;
        if *v > best.1 {
            best = (k, *v);
        }
    }
    if !best.1.is_finite() || best.1 <= 0.0 {
        return None;
    }
    let mean = (sum / surface.len() as f64) as f32;
    let rival = surface
        .iter()
        .enumerate()
        .filter(|(k, _)| k.abs_diff(best.0) > EXCLUDE)
        .map(|(_, v)| *v)
        .fold(f32::NEG_INFINITY, f32::max);

    Some(Estimate {
        lag: max_lag - best.0,
        // Already a correlation coefficient: the surface is normalised per lag above, so
        // the peak's height over the surface mean needs no further scaling.
        sharpness: best.1 - mean,
        dominance: if rival > 0.0 {
            best.1 / rival
        } else {
            f32::INFINITY
        },
    })
}

#[cfg(test)]
mod tests;
