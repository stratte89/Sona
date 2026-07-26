//! Packed-pixel → planar I420 conversion, and the decimation every capture path uses
//! to keep frames inside the encoder's budget. Pure arithmetic over buffers: no
//! platform APIs, which is what makes it the part of the capture stack that unit tests
//! can actually reach.

use client_core::media::video;

/// Convert packed RGB-ish pixels to planar I420 with optional integer decimation.
/// `ro/go/bo` are the channel offsets inside one `step`-byte pixel (so RGB, RGBA and
/// BGRX all funnel through here). Nearest-neighbour decimation: cheap, and for screen
/// content it keeps text edges crisper than a box filter at the same cost.
pub(crate) fn packed_to_i420(
    data: &[u8],
    w: usize,
    h: usize,
    step: usize,
    (ro, go, bo): (usize, usize, usize),
    decim: usize,
) -> Option<video::Frame> {
    if decim == 0 || w < 16 * decim || h < 16 * decim || data.len() < w * h * step {
        return None;
    }
    let ow = (w / decim) & !1;
    let oh = (h / decim) & !1;
    let mut i420 = vec![0u8; ow * oh * 3 / 2];
    let (ypl, uv) = i420.split_at_mut(ow * oh);
    let (upl, vpl) = uv.split_at_mut(ow * oh / 4);
    // Row slices, and chroma only on even rows. A 4K screen grab is ~8 M output pixels
    // a frame; indexing the whole buffer per component (and re-testing the chroma
    // condition per pixel) is the difference between keeping the frame rate and not.
    for oy in 0..oh {
        let src = &data[(oy * decim) * w * step..(oy * decim + 1) * w * step];
        let ydst = &mut ypl[oy * ow..(oy + 1) * ow];
        let luma = |r: i32, g: i32, b: i32| {
            (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16).clamp(0, 255) as u8
        };
        if oy % 2 == 0 {
            let crow = (oy / 2) * (ow / 2);
            for (ox, y) in ydst.iter_mut().enumerate() {
                let p = ox * decim * step;
                let (r, g, b) = (src[p + ro] as i32, src[p + go] as i32, src[p + bo] as i32);
                *y = luma(r, g, b);
                if ox % 2 == 0 {
                    let c = crow + ox / 2;
                    upl[c] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
                    vpl[c] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
                }
            }
        } else {
            for (ox, y) in ydst.iter_mut().enumerate() {
                let p = ox * decim * step;
                *y = luma(src[p + ro] as i32, src[p + go] as i32, src[p + bo] as i32);
            }
        }
    }
    Some(video::Frame {
        width: ow,
        height: oh,
        i420,
    })
}

/// Rotate a tight I420 frame clockwise by 0/90/180/270 degrees. Android camera sensors
/// are landscape-mounted; the Kotlin bridge passes the rotation that makes the frame
/// upright (see `nativeVideoFrame`). Unused on desktop builds (cameras arrive upright).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn rotate_i420(frame: video::Frame, deg: u32) -> video::Frame {
    if deg == 0 || !frame.valid() {
        return frame;
    }
    let (w, h) = (frame.width, frame.height);
    fn rot_plane(src: &[u8], w: usize, h: usize, deg: u32, dst: &mut Vec<u8>) {
        match deg {
            90 => {
                // dst is h×w; dst[r][c] = src[h-1-c][r]
                for r in 0..w {
                    for c in 0..h {
                        dst.push(src[(h - 1 - c) * w + r]);
                    }
                }
            }
            180 => dst.extend(src[..w * h].iter().rev()),
            270 => {
                // dst is h×w; dst[r][c] = src[c][w-1-r]
                for r in 0..w {
                    for c in 0..h {
                        dst.push(src[c * w + (w - 1 - r)]);
                    }
                }
            }
            _ => dst.extend_from_slice(&src[..w * h]),
        }
    }
    let (cw, ch) = (w / 2, h / 2);
    let ysz = w * h;
    let csz = cw * ch;
    let mut out = Vec::with_capacity(frame.i420.len());
    rot_plane(&frame.i420[..ysz], w, h, deg, &mut out);
    rot_plane(&frame.i420[ysz..ysz + csz], cw, ch, deg, &mut out);
    rot_plane(&frame.i420[ysz + csz..ysz + 2 * csz], cw, ch, deg, &mut out);
    let (ow, oh) = if deg == 180 { (w, h) } else { (h, w) };
    video::Frame {
        width: ow,
        height: oh,
        i420: out,
    }
}

/// Decimation factor that brings `w` at or under `max_w`.
pub(crate) fn decim_for(w: usize, max_w: usize) -> usize {
    let mut d = 1;
    while w / d > max_w {
        d += 1;
    }
    d
}

/// Nearest-neighbour decimation of an I420 frame, used for the self-view thumbnail
/// (shipping the full capture resolution over IPC would be wasted bandwidth).
pub(super) fn shrink_i420(f: &video::Frame, max_w: usize) -> video::Frame {
    let d = decim_for(f.width, max_w);
    if d <= 1 {
        return f.clone();
    }
    let (w, h) = (f.width, f.height);
    let ow = (w / d) & !1;
    let oh = (h / d) & !1;
    let mut out = vec![0u8; ow * oh * 3 / 2];
    let (y_src, uv_src) = f.i420.split_at(w * h);
    let (u_src, v_src) = uv_src.split_at(w * h / 4);
    let (y_dst, uv_dst) = out.split_at_mut(ow * oh);
    let (u_dst, v_dst) = uv_dst.split_at_mut(ow * oh / 4);
    for oy in 0..oh {
        for ox in 0..ow {
            y_dst[oy * ow + ox] = y_src[oy * d * w + ox * d];
        }
    }
    let (cw, ch) = (w / 2, h / 2);
    let (ocw, och) = (ow / 2, oh / 2);
    for oy in 0..och {
        let sy = (oy * d).min(ch - 1);
        for ox in 0..ocw {
            let sx = (ox * d).min(cw - 1);
            u_dst[oy * ocw + ox] = u_src[sy * cw + sx];
            v_dst[oy * ocw + ox] = v_src[sy * cw + sx];
        }
    }
    video::Frame {
        width: ow,
        height: oh,
        i420: out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: usize, h: usize) -> video::Frame {
        let mut i420 = vec![0u8; w * h * 3 / 2];
        for (i, b) in i420.iter_mut().enumerate() {
            *b = (i % 251) as u8; // non-power-of-two modulus: no accidental symmetry
        }
        video::Frame {
            width: w,
            height: h,
            i420,
        }
    }

    #[test]
    fn rotate_90_moves_top_row_to_right_column() {
        let (w, h) = (32, 16);
        let mut f = frame(w, h);
        for x in 0..w {
            f.i420[x] = 255; // paint the top Y row
        }
        let r = rotate_i420(f, 90);
        assert_eq!((r.width, r.height), (h, w));
        assert!(r.valid());
        for row in 0..r.height {
            assert_eq!(r.i420[row * r.width + (r.width - 1)], 255);
        }
    }

    #[test]
    fn four_quarter_turns_are_identity_and_two_are_a_half_turn() {
        let same = |a: &video::Frame, b: &video::Frame| {
            a.width == b.width && a.height == b.height && a.i420 == b.i420
        };
        let f = frame(32, 16);
        let two = rotate_i420(rotate_i420(f.clone(), 90), 90);
        assert!(same(&two, &rotate_i420(f.clone(), 180)));
        let four = rotate_i420(rotate_i420(two, 90), 90);
        assert!(same(&four, &f));
        assert!(same(&rotate_i420(rotate_i420(f.clone(), 270), 90), &f));
    }

    #[test]
    fn i420_conversion_shapes_and_decimation() {
        let (w, h) = (64usize, 48usize);
        let rgb = vec![200u8; w * h * 3];
        let f = packed_to_i420(&rgb, w, h, 3, (0, 1, 2), 1).unwrap();
        assert_eq!((f.width, f.height), (64, 48));
        assert!(f.valid());
        let f2 = packed_to_i420(&rgb, w, h, 3, (0, 1, 2), 2).unwrap();
        assert_eq!((f2.width, f2.height), (32, 24));
        // Grey input → mid chroma, bright luma.
        assert!(f.i420[0] > 150);
        let c = f.i420[w * h];
        assert!((120..=136).contains(&c));
        // Undersized buffer refused.
        assert!(packed_to_i420(&rgb[..10], w, h, 3, (0, 1, 2), 1).is_none());
    }

    #[test]
    fn decimation_targets() {
        assert_eq!(decim_for(640, 960), 1);
        assert_eq!(decim_for(1920, 960), 2);
        assert_eq!(decim_for(3840, 1920), 2);
        assert_eq!(decim_for(1920, 1920), 1);
    }

    #[test]
    fn shrink_preserves_shape_and_passthrough() {
        let f = video::Frame {
            width: 640,
            height: 480,
            i420: vec![90u8; 640 * 480 * 3 / 2],
        };
        let s = shrink_i420(&f, 480);
        assert_eq!((s.width, s.height), (320, 240));
        assert!(s.valid());
        assert!(s.i420.iter().all(|&b| b == 90));
        // Already small enough → untouched copy.
        let p = shrink_i420(&f, 640);
        assert_eq!((p.width, p.height), (640, 480));
    }
}
