//! What can be checked anywhere, and what needs the GPU.
//!
//! The ABI is not tested here at all — it is asserted in [`super::abi`], and those
//! assertions have already run by the time this file compiles. What is left to check is
//! the two things a compiler cannot: that a machine *without* NVENC takes the fallback
//! quietly, and that a machine *with* it produces a bitstream our own decoder accepts.

use client_core::media::video::{self, H264Encode};

use super::*;

/// A moving gradient. Flat grey compresses to nothing and would let an encoder that emits
/// almost no data pass; a per-frame phase shift also forces real inter prediction rather
/// than a run of skipped frames.
fn frame(w: usize, h: usize, phase: usize) -> video::Frame {
    let mut i420 = vec![128u8; w * h * 3 / 2];
    for y in 0..h {
        for x in 0..w {
            i420[y * w + x] = ((x * 7 + y * 3 + phase * 11) % 255) as u8;
        }
    }
    video::Frame {
        width: w,
        height: h,
        i420,
    }
}

/// The failure path every non-NVIDIA Linux machine takes. A `dlopen` of something that is
/// not installed has to be an ordinary `Err` — if it were anything else (a panic, an abort,
/// a link-time `NEEDED` entry) the app would not start on those machines at all, which is
/// the single thing this backend is not allowed to cost.
#[test]
fn a_library_that_is_not_there_is_just_an_error() {
    let e = api::load_for_test("libnvidia-encode-not-a-real-library.so.1")
        .err()
        .expect("a bogus soname must not load");
    assert!(e.contains("not present"), "unexpected error: {e}");
}

/// Opening on a machine with no NVENC must report *permanent*, not transient: there is no
/// point retrying a driver that is not installed, and `hwenc` needs that answer to write
/// the backend off instead of paying for a failed open on every frame.
#[test]
fn opening_without_a_driver_is_permanent() {
    if api::api().is_ok() {
        return; // this box has NVENC; the real test below covers it
    }
    match Encoder::open(video::Content::Screen) {
        Err(OpenFailure::Permanent(_)) => {}
        Err(OpenFailure::Transient(e)) => panic!("a missing driver is not transient: {e}"),
        Ok(_) => panic!("opened an encoder with no NVENC library"),
    }
}

/// The acceptance test: real frames through the GPU, and back out through the decoder the
/// peer will actually use.
///
/// Ignored because it needs an NVIDIA GPU with a free encode session:
/// `cargo test --lib -- --ignored nvenc`.
#[test]
#[ignore]
fn encodes_screen_frames_that_our_own_decoder_can_read() {
    const W: usize = 1280;
    const H: usize = 720;
    let mut enc = match Encoder::open(video::Content::Screen) {
        Ok(e) => e,
        Err(e) => panic!("NVENC did not open: {e}"),
    };
    let mut dec = video::Decoder::new().expect("decoder");

    enc.force_keyframe();
    let mut decoded = 0;
    let mut first: Option<Vec<u8>> = None;
    for i in 0..30 {
        let au = enc.encode(&frame(W, H, i)).expect("encode");
        if au.is_empty() {
            continue;
        }
        assert!(
            au.starts_with(&[0, 0, 0, 1]) || au.starts_with(&[0, 0, 1]),
            "frame {i} is not Annex-B"
        );
        if first.is_none() {
            first = Some(au.clone());
        }
        if let Some(out) = dec.decode(&au).expect("decode") {
            assert_eq!(
                (out.width, out.height),
                (W, H),
                "frame {i} decoded wrong size"
            );
            decoded += 1;
        }
    }
    assert!(decoded > 20, "only {decoded} of 30 frames decoded");

    // The first access unit has to stand alone, because that is the one a peer joining or
    // recovering starts from. A fresh decoder is the only honest way to ask.
    let mut cold = video::Decoder::new().expect("decoder");
    let out = cold
        .decode(&first.expect("at least one access unit"))
        .expect("cold decode")
        .expect("first access unit carried no keyframe");
    assert_eq!((out.width, out.height), (W, H));
}

/// The governor steps the shared screen down mid-call, which tears the session down and
/// builds a new one. The new stream has to be self-contained from its first frame —
/// remembering the *old* session's parameter sets and prepending them would hand the peer
/// an SPS that does not describe the picture that follows it.
#[test]
#[ignore]
fn a_resize_starts_a_stream_the_peer_can_join() {
    let mut enc = match Encoder::open(video::Content::Screen) {
        Ok(e) => e,
        Err(e) => panic!("NVENC did not open: {e}"),
    };
    let mut warm = video::Decoder::new().expect("decoder");
    for i in 0..5 {
        let au = enc.encode(&frame(1280, 720, i)).expect("encode");
        if !au.is_empty() {
            let _ = warm.decode(&au);
        }
    }
    // Half the width: what `SCREEN_WIDTHS` stepping down looks like to the encoder.
    let mut after = Vec::new();
    for i in 0..5 {
        let au = enc
            .encode(&frame(640, 360, i))
            .expect("encode after resize");
        if !au.is_empty() && after.is_empty() {
            after = au;
        }
    }
    let mut cold = video::Decoder::new().expect("decoder");
    let out = cold
        .decode(&after)
        .expect("cold decode after resize")
        .expect("first post-resize access unit carried no keyframe");
    assert_eq!((out.width, out.height), (640, 360));
}

/// Two encoders at once is the ordinary case — a call with the camera on and the screen
/// shared. It is also how the session limit gets hit, so the second one is required either
/// to work or to say `Transient`, never to write the backend off while the first is fine.
#[test]
#[ignore]
fn a_second_encoder_never_condemns_the_first() {
    let Ok(mut screen) = Encoder::open(video::Content::Screen) else {
        panic!("NVENC did not open");
    };
    match Encoder::open(video::Content::Camera) {
        Ok(mut camera) => {
            assert!(!camera
                .encode(&frame(640, 480, 0))
                .expect("camera")
                .is_empty());
            assert!(!screen
                .encode(&frame(1280, 720, 0))
                .expect("screen")
                .is_empty());
        }
        Err(OpenFailure::Transient(_)) => {
            // No session to spare. The first encoder must be untouched by that.
            assert!(!screen
                .encode(&frame(1280, 720, 0))
                .expect("screen")
                .is_empty());
        }
        Err(OpenFailure::Permanent(e)) => {
            panic!("a second session failing is not permanent: {e}")
        }
    }
}
