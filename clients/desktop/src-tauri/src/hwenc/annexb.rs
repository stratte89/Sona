//! Annex-B bitstream housekeeping shared by the hardware backends.
//!
//! Hardware encoders are much less consistent than a software one about *where* they put
//! the parameter sets. Many emit SPS/PPS once, ahead of the first IDR, and then never
//! again — which is fine for a file and wrong for a call: our peer asks for a fresh IDR
//! whenever its decoder loses sync, and an IDR with no parameter sets in front of it is
//! not something a decoder can start from. The peer would sit on a frozen picture while
//! we cheerfully sent it keyframes.
//!
//! So the parameter sets get remembered the first time they appear and re-attached to any
//! later IDR that arrives without them. This is all plain byte-slice work — no platform
//! API — which is why it lives here and is unit-tested on any host.

// Only the Windows and Linux backends consume this; the tests below still run everywhere,
// which is the point of keeping the bitstream logic platform-independent.
#![cfg_attr(not(any(target_os = "windows", target_os = "linux")), allow(dead_code))]

/// NAL unit types this module cares about (H.264, `nal_unit_type` in the low 5 bits).
const NAL_IDR: u8 = 5;
const NAL_SPS: u8 = 7;
const NAL_PPS: u8 = 8;

/// Offsets of each NAL payload in an Annex-B access unit, as `(start, end)` pairs that
/// *include* the leading start code. Anything before the first start code is ignored.
fn nal_ranges(au: &[u8]) -> Vec<(usize, usize)> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= au.len() {
        // 3- and 4-byte start codes are both legal and both appear in the wild.
        if au[i] == 0 && au[i + 1] == 0 && au[i + 2] == 1 {
            starts.push(i);
            i += 3;
        } else if i + 4 <= au.len() && au[i..i + 4] == [0, 0, 0, 1] {
            starts.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }
    (0..starts.len())
        .map(|n| {
            let end = starts.get(n + 1).copied().unwrap_or(au.len());
            (starts[n], end)
        })
        .collect()
}

/// `nal_unit_type` of the NAL beginning at `start`, if the header byte is there.
fn nal_type(au: &[u8], start: usize) -> Option<u8> {
    let hdr = if au.get(start + 2) == Some(&1) {
        start + 3
    } else {
        start + 4
    };
    au.get(hdr).map(|b| b & 0x1f)
}

/// Keeps the most recent parameter sets so every IDR can be made self-contained.
#[derive(Default)]
pub(super) struct ParameterSets {
    /// SPS and PPS NALs, start codes included, in the order they were first seen.
    sets: Vec<u8>,
}

impl ParameterSets {
    /// Learn from `au`, and return it with parameter sets guaranteed in front of any IDR.
    ///
    /// Non-IDR access units pass through untouched — a delta frame does not need them,
    /// and adding bytes to every frame would cost bitrate for nothing.
    pub(super) fn apply(&mut self, au: Vec<u8>) -> Vec<u8> {
        let ranges = nal_ranges(&au);
        let mut have_params = false;
        let mut idr = false;
        let mut seen = Vec::new();
        for &(s, e) in &ranges {
            match nal_type(&au, s) {
                Some(NAL_SPS) | Some(NAL_PPS) => {
                    have_params = true;
                    seen.extend_from_slice(&au[s..e]);
                }
                Some(NAL_IDR) => idr = true,
                _ => {}
            }
        }
        if have_params {
            self.sets = seen;
        }
        if !idr || have_params || self.sets.is_empty() {
            return au;
        }
        // An IDR with nothing to configure a decoder from: put the remembered sets in
        // front so a peer that just lost sync can actually start here.
        let mut out = Vec::with_capacity(self.sets.len() + au.len());
        out.extend_from_slice(&self.sets);
        out.extend_from_slice(&au);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nal(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0, 0, 0, 1, kind & 0x1f];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn finds_nals_behind_three_and_four_byte_start_codes() {
        let mut au = nal(NAL_SPS, &[1, 2]);
        au.extend_from_slice(&[0, 0, 1, NAL_PPS, 3]); // 3-byte start code
        au.extend_from_slice(&nal(NAL_IDR, &[4, 5]));
        let r = nal_ranges(&au);
        assert_eq!(r.len(), 3);
        let types: Vec<_> = r.iter().map(|&(s, _)| nal_type(&au, s)).collect();
        assert_eq!(types, vec![Some(NAL_SPS), Some(NAL_PPS), Some(NAL_IDR)]);
    }

    #[test]
    fn an_idr_that_already_carries_parameter_sets_is_untouched() {
        let mut ps = ParameterSets::default();
        let mut au = nal(NAL_SPS, &[9]);
        au.extend_from_slice(&nal(NAL_PPS, &[8]));
        au.extend_from_slice(&nal(NAL_IDR, &[7]));
        assert_eq!(ps.apply(au.clone()), au);
    }

    /// The case this exists for: an encoder that sends parameter sets once, then answers
    /// a later keyframe request with a bare IDR.
    #[test]
    fn a_later_bare_idr_gets_the_remembered_parameter_sets() {
        let mut ps = ParameterSets::default();
        let mut first = nal(NAL_SPS, &[9]);
        first.extend_from_slice(&nal(NAL_PPS, &[8]));
        first.extend_from_slice(&nal(NAL_IDR, &[7]));
        ps.apply(first);

        let bare = nal(NAL_IDR, &[6]);
        let fixed = ps.apply(bare.clone());
        assert!(
            fixed.len() > bare.len(),
            "parameter sets were not prepended"
        );
        let types: Vec<_> = nal_ranges(&fixed)
            .iter()
            .map(|&(s, _)| nal_type(&fixed, s))
            .collect();
        assert_eq!(types, vec![Some(NAL_SPS), Some(NAL_PPS), Some(NAL_IDR)]);
    }

    #[test]
    fn delta_frames_pass_through_and_cost_nothing() {
        let mut ps = ParameterSets::default();
        let mut first = nal(NAL_SPS, &[9]);
        first.extend_from_slice(&nal(NAL_IDR, &[7]));
        ps.apply(first);
        let delta = nal(1, &[5, 5, 5]); // non-IDR slice
        assert_eq!(ps.apply(delta.clone()), delta);
    }

    #[test]
    fn nothing_learned_yet_means_nothing_added() {
        let mut ps = ParameterSets::default();
        let bare = nal(NAL_IDR, &[6]);
        assert_eq!(ps.apply(bare.clone()), bare);
    }
}
