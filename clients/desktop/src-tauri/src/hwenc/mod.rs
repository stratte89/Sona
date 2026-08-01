//! Hardware H.264 encoding, where the machine has one and it can prove it works.
//!
//! Screen sharing is the one thing in a call that can outrun a CPU. A full-resolution
//! software encode costs more per frame than the frame interval it is aiming for on
//! ordinary hardware, and when it does, the casualty is not the video — it is the 20 ms
//! voice tick, which now has to fight the encoder for a core. Every GPU made in the last
//! decade has a dedicated H.264 block sitting idle next to it.
//!
//! **This changes nothing about the privacy posture.** Encoding happens *before*
//! sealing: the encoder turns pixels into an H.264 access unit, and
//! [`client_core::media`] then seals that with the per-call, per-track key exactly as it
//! seals the software encoder's output. No key, no plaintext frame and no ciphertext
//! ever reaches a driver, and the relay sees the same padded cells either way. What a
//! hardware encoder does change is *which pixels the GPU driver sees* — and it already
//! sees them, because that is where the screen was captured from.
//!
//! ## Why a probe, and why it is not optional
//!
//! Vendor media stacks are the least predictable code on a desktop: a driver may expose
//! an encoder that cannot do the resolution asked of it, that produces output in a
//! format nobody documents, or that simply returns nothing. None of that may take a call
//! with it. So a backend is never trusted on the strength of existing — before its first
//! real frame it must encode a synthetic one and hand back something that parses as an
//! Annex-B keyframe ([`probe`]). One failure and the whole backend is written off for
//! the life of the process, permanently, atomically, for every call.
//!
//! The fallback is not a degraded mode. It is the software encoder that has always been
//! there, so "hardware did not work out" lands exactly on the behaviour of the build
//! before any of this existed.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use client_core::media::{video, EncoderFactory};

mod annexb;
#[cfg(target_os = "windows")]
mod mediafoundation;
#[cfg(target_os = "linux")]
mod nvenc;

/// Whether hardware encoding is available, as a state machine that only ever moves
/// toward "no": `UNKNOWN` → `READY` or `OFF`, and `READY` → `OFF`. A backend that fails
/// once is never retried, because the failure modes here are configuration, not luck,
/// and retrying a broken driver every frame is how a stutter becomes a freeze.
const UNKNOWN: u8 = 0;
const READY: u8 = 1;
const OFF: u8 = 2;
static STATE: AtomicU8 = AtomicU8::new(UNKNOWN);

/// The last thing that went wrong, for the diagnostic in the call's gear panel.
///
/// Without this, the panel could say "software" and nothing else, which is the least
/// useful true statement available: it cannot distinguish a machine with no encoder from a
/// driver that refused one from a backend that has simply not been asked yet. Debugging
/// "hardware encoding isn't happening" then means guessing, which is how a Windows MFT
/// that was failing at its very first call went unnoticed (see
/// [`mediafoundation::unlock_async`]).
static WHY: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn note(why: &str) {
    if let Ok(mut slot) = WHY.lock() {
        *slot = Some(why.to_string());
    }
}

/// Give up on hardware encoding for the rest of the process.
fn disable(why: &str) {
    note(why);
    if STATE.swap(OFF, Ordering::SeqCst) != OFF {
        crate::diag!("[media] hardware H.264 unavailable ({why}) — using software encode");
    }
}

/// Why a backend would not open, and — the part that matters — whether asking again could
/// ever give a different answer.
///
/// Collapsing these two was a real bug: any failure to open flipped the whole process to
/// `OFF`. NVENC makes the difference concrete, because it caps how many encode sessions
/// exist at once and other applications spend from the same budget. A camera leg and a
/// screen leg are already two sessions; a browser tab or OBS can take the rest. The screen
/// leg losing that race says nothing at all about the camera leg that is encoding happily,
/// and must not switch hardware encoding off underneath it — it must fall back to software
/// for that one leg and leave the state machine alone.
enum OpenFailure {
    /// This machine will never encode in hardware: no library, a driver older than the API
    /// this build targets, no encode block on the GPU. Writes the backend off.
    Permanent(String),
    /// Not right now — no free session, no memory. This leg goes to software; the next one
    /// to ask gets a fresh attempt.
    ///
    /// Never constructed on Windows: Media Foundation hands out a fresh MFT per encoder
    /// and has no equivalent of NVENC's per-driver session budget, so every way it can
    /// fail to enumerate one is a property of the machine.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Transient(String),
}

impl std::fmt::Display for OpenFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenFailure::Permanent(e) | OpenFailure::Transient(e) => f.write_str(e),
        }
    }
}

/// What the shell hands the engine. Called on the encode task when a leg needs an
/// encoder — never on the socket task, so a slow driver probe cannot delay voice.
pub fn factory() -> EncoderFactory {
    Arc::new(|content| {
        if STATE.load(Ordering::SeqCst) == OFF {
            return None; // engine falls back to software
        }
        // A machine can have more than one hardware encoder, and the first one is not
        // necessarily the good one. The case that forced this: an RTX 3080 behind an
        // Intel UHD iGPU on a five-year-old driver, where Media Foundation is free to
        // offer the Intel encoder first. Failing the probe on candidate 0 used to write
        // hardware encoding off for the process, so the best encoder in the machine was
        // never asked. Each candidate now gets its own probe, and only running out of
        // them means this machine cannot do it.
        for skip in 0..MAX_BACKENDS {
            let mut enc = match open(content, skip) {
                Ok(e) => e,
                Err(OpenFailure::Permanent(e)) => {
                    // Out of candidates (or none to begin with): that is the machine's
                    // answer, not this attempt's.
                    disable(&e);
                    return None;
                }
                Err(OpenFailure::Transient(e)) => {
                    note(&e);
                    crate::diag!("[media] hardware H.264 unavailable for this track ({e})");
                    return None; // engine falls back to software for this leg only
                }
            };
            if STATE.load(Ordering::SeqCst) != UNKNOWN {
                return Some(enc); // already proven; no probe, no search
            }
            // First one ever: make it prove itself before a call depends on it. The
            // encoder that is about to be handed out is the one probed, rather than a
            // second one opened alongside it — a spare session is exactly what a machine
            // at its session limit does not have, and proving a *different* encoder works
            // would not be proving this one does.
            match probe(enc.as_mut(), content) {
                Ok(()) => {
                    STATE.store(READY, Ordering::SeqCst);
                    crate::diag!("[media] hardware H.264 encode active");
                    return Some(enc);
                }
                Err(e) => {
                    // This encoder, not this machine. Say which one failed and why, then
                    // let the next backend try; `enc` is dropped here, so its session is
                    // released before the replacement asks for one.
                    note(&e);
                    crate::diag!("[media] hardware H.264 candidate {skip} rejected ({e})");
                }
            }
        }
        disable("no hardware encoder passed the probe");
        None
    })
}

/// How many hardware encoders to try before concluding the machine has none that work.
/// Four covers every plausible desktop: an iGPU, a discrete card, and room to spare.
const MAX_BACKENDS: usize = 4;

/// The size a backend opens a leg at, and therefore the only size worth proving it can
/// encode. Both backends configure themselves from this and [`probe`] uses it too — the
/// three agreeing is the whole point of it being one function.
///
/// It used to be that the probe made up its own small frame (320x240) while the backends
/// opened at full size. That looked harmless and cost us the entire Windows hardware path:
/// a hardware encoder MFT is free to reject a resolution, several reject small ones, and
/// his did — `SetOutputType` answered `0x80004005` for 320x240 on a GPU that encodes 1080p
/// perfectly well. The probe then condemned the backend for the life of the process over a
/// frame size no call would ever ask it for. Prove the real thing or prove nothing.
pub(super) fn open_dims(content: video::Content) -> (u32, u32) {
    match content {
        video::Content::Camera => (640, 480),
        video::Content::Screen => (1920, 1080),
    }
}

/// Build a backend encoder for this platform, skipping the first `skip` candidates.
///
/// `Permanent` for a `skip` past the end means "no more to try", which is what ends the
/// search in [`factory`].
#[cfg(target_os = "windows")]
fn open(content: video::Content, skip: usize) -> Result<Box<dyn video::H264Encode>, OpenFailure> {
    mediafoundation::Encoder::open(content, skip)
        .map(|e| Box::new(e) as Box<dyn video::H264Encode>)
        .map_err(OpenFailure::Permanent)
}

/// NVENC is one vendor's driver, not an enumeration: there is exactly one candidate.
#[cfg(target_os = "linux")]
fn open(content: video::Content, skip: usize) -> Result<Box<dyn video::H264Encode>, OpenFailure> {
    if skip > 0 {
        return Err(OpenFailure::Permanent("no other NVENC device".into()));
    }
    nvenc::open(content)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn open(_content: video::Content, _skip: usize) -> Result<Box<dyn video::H264Encode>, OpenFailure> {
    Err(OpenFailure::Permanent(
        "no hardware encode backend on this platform".into(),
    ))
}

/// Encode a synthetic frame and insist the result looks like H.264.
///
/// Deliberately not a smoke test of "did the call succeed": a driver returning an empty
/// buffer, or a length-prefixed stream where Annex-B was asked for, would sail through
/// that and then feed the peer's decoder garbage for the whole call. What has to be true
/// is that the very first frame is a keyframe a decoder could start from, so that is
/// what gets checked — and checked with our own decoder, the same one the peer will use.
///
/// Probed at [`open_dims`], the size this leg is actually configured for, so the answer is
/// about the encoder a call will use rather than about some other resolution.
fn probe(enc: &mut dyn video::H264Encode, content: video::Content) -> Result<(), String> {
    /// Attempts at 5 ms apart — a fifth of a second in the worst case, once per process.
    const ATTEMPTS: usize = 40;
    let (dw, dh) = open_dims(content);
    let (w, h) = (dw as usize, dh as usize);
    let mut dec = video::Decoder::new().map_err(|e| format!("probe decoder: {e}"))?;
    // Gradient, not flat grey: a uniform frame compresses to almost nothing and would
    // not exercise the encoder's output path in any representative way.
    let mut i420 = vec![128u8; w * h * 3 / 2];
    for y in 0..h {
        for x in 0..w {
            i420[y * w + x] = ((x * 7 + y * 3) % 255) as u8;
        }
    }
    let frame = video::Frame {
        width: w,
        height: h,
        i420,
    };
    enc.force_keyframe();
    // A hardware encoder may want a few frames before it emits anything; that is normal
    // pipelining, not failure. But it has to produce *something* promptly.
    //
    // Paced, not spun. An asynchronous Media Foundation encoder is driven by events it
    // raises on its own thread, so a tight loop can out-run it and see an empty queue every
    // time — the encoder would be working fine and the probe would call it dead. A few
    // milliseconds between attempts is what makes the answer about the encoder rather than
    // about scheduling luck, and this runs once per process, before any call depends on it.
    for _ in 0..ATTEMPTS {
        std::thread::sleep(std::time::Duration::from_millis(5));
        let au = enc
            .encode(&frame)
            .map_err(|e| format!("probe encode: {e}"))?;
        if au.is_empty() {
            continue;
        }
        if !au.starts_with(&[0, 0, 0, 1]) && !au.starts_with(&[0, 0, 1]) {
            return Err("encoder output is not Annex-B".into());
        }
        return match dec.decode(&au) {
            Ok(Some(out)) if out.width == w && out.height == h => Ok(()),
            Ok(Some(out)) => Err(format!(
                "probe decoded {}x{}, want {w}x{h}",
                out.width, out.height
            )),
            // Parsed as H.264 but carried no picture: parameter sets without a frame
            // means the first access unit is not something a peer could start from.
            Ok(None) => Err("first access unit carried no keyframe".into()),
            Err(e) => Err(format!("probe decode: {e}")),
        };
    }
    Err("encoder produced nothing".into())
}

/// Where video encoding stands, for the diagnostic in `call_status`.
///
/// Three answers, not two. "Not yet" is a real and common state — nothing opens an encoder
/// until a camera or a share actually produces a frame, so a call where only the *peer* is
/// sharing has never asked this machine to encode anything. Reporting that as "software"
/// was a plain misstatement, and one that sent us looking for a Linux fault that was not
/// there while the real Windows fault hid behind the identical wording on both ends.
pub fn status() -> (&'static str, Option<String>) {
    (
        state_word(STATE.load(Ordering::SeqCst)),
        WHY.lock().ok().and_then(|w| w.clone()),
    )
}

fn state_word(state: u8) -> &'static str {
    match state {
        READY => "hardware",
        OFF => "software",
        _ => "idle",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole design rests on: with no hardware backend compiled in (or
    /// none on the box), the factory declines and the engine is left with software. It
    /// must never hand back a half-working encoder.
    #[test]
    fn factory_declines_rather_than_returning_something_unproven() {
        let f = factory();
        // Whatever this machine has, the outcome is either a proven encoder or None —
        // and after any failure the state is OFF, not UNKNOWN, so it is not retried.
        let got = f(video::Content::Screen);
        match STATE.load(Ordering::SeqCst) {
            READY => assert!(got.is_some(), "READY must mean a usable encoder"),
            OFF => assert!(got.is_none(), "OFF must decline"),
            _ => assert!(got.is_none(), "an unproven backend must not be handed out"),
        }
        // Once written off, it stays written off — and it says so, with a reason.
        disable("test");
        assert!(f(video::Content::Screen).is_none());
        assert_eq!(status().0, "software");
        assert_eq!(status().1.as_deref(), Some("test"));
    }

    /// Before anything has asked for an encoder, the honest answer is "idle" — not
    /// "software". Reporting the two as one word is what hid a Windows backend that was
    /// failing on its first call: both ends of a test call said "software", so the machine
    /// that had never been asked to encode looked exactly like the one that had failed.
    #[test]
    fn nothing_encoded_yet_is_not_the_same_as_software() {
        // `STATE` is process-global and the test above moves it, so this checks the
        // mapping rather than the live value.
        assert_eq!(state_word(UNKNOWN), "idle");
        assert_eq!(state_word(READY), "hardware");
        assert_eq!(state_word(OFF), "software");
    }
}
