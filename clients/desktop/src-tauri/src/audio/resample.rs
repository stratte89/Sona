//! Streaming sample-rate conversion between a device's rate and the engine's 48 kHz.

/// Linear resampler, mono, streaming. Good enough for speech; avoids a DSP dependency.
///
/// Stateful on purpose. Resampling each callback independently — starting at phase zero
/// and returning `floor(len / ratio)` samples — throws away the fractional remainder
/// every single time, which on any device that is not already 48 kHz leaks up to one
/// sample per callback. That is a *systematic* rate error, ~1000 ppm at typical buffer
/// sizes, and it is not cosmetic: it is what walks the screen-share echo canceller's
/// alignment off (see [`crate::aec`]), and it slowly starves or floods the frame rings
/// on every non-48 kHz machine. Carrying the phase and the boundary sample across calls
/// makes the conversion exact in rate.
pub(crate) struct Resampler {
    /// Source position for the next output sample, relative to the start of the next
    /// input block. Negative means "inside [`Resampler::prev`]".
    phase: f64,
    /// Final sample of the previous block, so interpolation spans the seam.
    prev: f32,
}

impl Resampler {
    pub(crate) fn new() -> Resampler {
        Resampler {
            phase: 0.0,
            prev: 0.0,
        }
    }

    pub(crate) fn process(&mut self, input: &[f32], from_hz: u32, to_hz: u32, out: &mut Vec<f32>) {
        out.clear();
        if input.is_empty() || from_hz == 0 || to_hz == 0 {
            return;
        }
        if from_hz == to_hz {
            out.extend_from_slice(input);
            return;
        }
        let ratio = from_hz as f64 / to_hz as f64;
        let len = input.len();
        let mut p = self.phase;
        while p < len as f64 {
            let base = p.floor();
            let f = (p - base) as f32;
            let i = base as isize;
            // i == -1 reads the previous block's last sample; i + 1 past the end means
            // the interpolation needs data we do not have yet, so leave it for the next
            // block — that is what carrying the phase is for.
            let a = if i < 0 { self.prev } else { input[i as usize] };
            let Some(&b) = input.get((i + 1) as usize) else {
                break;
            };
            out.push(a + (b - a) * f);
            p += ratio;
        }
        self.phase = p - len as f64;
        self.prev = input[len - 1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resample_matches_the_requested_rate_exactly() {
        // Equal rates are a byte-for-byte passthrough.
        let mut out = Vec::new();
        let input: Vec<f32> = (0..960).map(|i| i as f32).collect();
        Resampler::new().process(&input, 48_000, 48_000, &mut out);
        assert_eq!(out, input);

        // The property that matters: fed block after block, the output rate is right
        // and stays right. Resampling each block independently loses the fractional
        // remainder every call — about a sample per callback, which is the ~1000 ppm
        // drift that walks the echo canceller's alignment off and slowly empties the
        // frame rings on any device that is not already 48 kHz.
        for (from, to, block) in [
            (44_100, 48_000, 441),
            (48_000, 44_100, 480),
            (32_000, 48_000, 320),
        ] {
            let mut rs = Resampler::new();
            let mut produced = 0usize;
            let blocks = 200;
            for b in 0..blocks {
                let input: Vec<f32> = (0..block).map(|i| (b * block + i) as f32).collect();
                rs.process(&input, from, to, &mut out);
                produced += out.len();
            }
            let want = (blocks * block) as f64 * to as f64 / from as f64;
            let err = produced as f64 - want;
            assert!(
                err.abs() <= 2.0,
                "{from}→{to}: produced {produced}, want {want:.1} (drift {err:.1} samples)"
            );
        }
    }

    /// Upsampling a straight line must stay a straight line — the seam between blocks
    /// is where a resampler that forgets its previous sample shows a kink.
    #[test]
    fn resample_is_continuous_across_block_boundaries() {
        let mut rs = Resampler::new();
        let mut all = Vec::new();
        let mut out = Vec::new();
        for b in 0..8 {
            let input: Vec<f32> = (0..100).map(|i| (b * 100 + i) as f32).collect();
            rs.process(&input, 24_000, 48_000, &mut out);
            all.extend_from_slice(&out);
        }
        for w in all.windows(2).skip(2) {
            assert!(
                (w[1] - w[0] - 0.5).abs() < 1e-3,
                "kink at the block seam: {} → {}",
                w[0],
                w[1]
            );
        }
    }
}
