//! Keeping the call's own playout out of the shared system audio.
//!
//! Sharing system audio means capturing what the machine is playing — WASAPI loopback
//! on the render endpoint (Windows), the sink's monitor source (Linux). Both are the
//! *post-mix* signal, so they also contain our own call playout: the peer's voice, at
//! full level. Sent back on the screen-audio track, the peer hears themselves a few
//! hundred milliseconds late — the "I hear my voice duplicated from the screenshare"
//! report. (Android is structurally immune: `AudioPlaybackCapture` never captures
//! `USAGE_VOICE_COMMUNICATION` streams, which is exactly what the Kotlin bridge plays
//! the call into, so none of this is compiled there.)
//!
//! There is no *room* in this echo path — it is a digital mix — so the echo is a plain
//! delay and gain of a reference we already have: the samples the playout mixer wrote.
//! A short-time canceller models that exactly, which is why this is subtraction and not
//! the usual suppression-by-attenuation:
//!
//! 1. [`Reference`] — the playout mixer publishes its 48 kHz mono output into a ring
//!    ([`crate::audio`]); the capture side reads it back in lockstep through a
//!    [`RefReader`], one reference sample consumed per captured sample.
//! 2. Bulk delay — envelope cross-correlation at hop resolution, refined to the sample,
//!    re-run continuously so device clock drift (and the naive per-callback resamplers
//!    on both paths) can't walk the alignment off.
//! 3. Per-bin echo path — exponentially-weighted least squares against the reference.
//!    The audio genuinely being shared is a large disturbance but is *uncorrelated*
//!    with the call, so it averages out of the estimate instead of biasing it.
//! 4. Subtract, and overlap-add back to PCM.
//!
//! The one thing this cannot survive is an echo that arrives from outside
//! [`suppress::MAX_LAG_SAMPLES`], and for a long time on Linux it did. The share capture
//! opened its monitor with `BufferSize::Default`, which PulseAudio reads as "server, you
//! decide" and answers in seconds: the echo sat at a rock-steady 2.012 s against a 512 ms
//! search. Nothing in this module was wrong; it was being asked to find a signal four
//! times outside the range it looks in, and four rewrites of the estimator went into that
//! gap. The capture now asks for a 20 ms buffer (see `media_shell::sysaudio`) and the same
//! unchanged estimator locks at 32 ms and removes 36.8 dB. **Measure the delay before
//! touching anything here.**
//!
//! Nothing here attenuates the shared audio on suspicion, and nothing decides per bin
//! which of two signals to keep — both of those cost far more of the content than they
//! save in echo, which is what the tests at the bottom of this file measure. Every
//! failure mode falls back to *doing nothing*: with no alignment (call audio on a
//! different device than the one being captured, nobody speaking, a dead playout
//! stream) there is no estimate, and the analysis/synthesis pair is COLA-exact, so
//! "doing nothing" really is the input back [`LATENCY`] samples later — there is no
//! bypass switch to click on.

use std::sync::{Arc, Mutex, OnceLock};

pub(crate) mod delay;
mod suppress;

pub use suppress::EchoSuppressor;
use suppress::MAX_LAG_SAMPLES;

// ── Reference ring (playout mixer → capture side) ───────────────────────────────────

/// What one [`RefReader::pull_detail`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pull {
    /// Continued where the last pull left off — the lockstep the suppressor needs.
    Aligned,
    /// Reader had overtaken the writer: playout is not producing.
    ReseatAhead,
    /// Reader had fallen out of the search range behind the writer: capture frames were
    /// lost, or the two clocks have drifted a long way apart.
    ReseatBehind,
}

/// Reference ring capacity in samples (~1.4 s at 48 kHz). Only ever read within
/// [`MAX_LAG_SAMPLES`] of the write head, so this is pure headroom.
const RING: usize = 1 << 16;
const RING_MASK: u64 = RING as u64 - 1;

/// The playout mixer's output, published for the capture side to subtract.
///
/// One publisher at a time: concurrent call sessions (a 1:1 leg plus a group leg, or a
/// reconnect overlapping its predecessor) each render their own playout stream, and
/// interleaving two unrelated signals into one timeline would produce a reference that
/// matches neither. The newest session [`claim`](Reference::claim)s the ring and older
/// ones go quiet; the suppressor re-aligns on the switch, and in the worst case it
/// finds no alignment and passes audio through.
pub struct Reference {
    inner: Mutex<RingState>,
}

struct RingState {
    buf: Vec<f32>,
    /// Absolute count of samples ever written — the index space everything else uses.
    wpos: u64,
    owner: u64,
}

/// Process-wide reference ring. One playout stream publishes; one system-audio capture
/// reads. Both are per-call and short-lived, the ring is not.
pub fn reference() -> &'static Arc<Reference> {
    static REF: OnceLock<Arc<Reference>> = OnceLock::new();
    REF.get_or_init(|| {
        Arc::new(Reference {
            inner: Mutex::new(RingState {
                buf: vec![0.0; RING],
                wpos: 0,
                owner: 0,
            }),
        })
    })
}

impl Reference {
    /// Take over publishing; the returned token must accompany every write. Older
    /// holders' writes are dropped from here on.
    pub fn claim(&self) -> u64 {
        let mut s = match self.inner.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        s.owner += 1;
        s.owner
    }

    /// Append the mixer's 48 kHz mono output. Called from the playout audio callback:
    /// one lock, one copy of at most a frame, no allocation.
    pub fn publish(&self, token: u64, samples: &[f32]) {
        let Ok(mut s) = self.inner.lock() else { return };
        if s.owner != token {
            return;
        }
        for &v in samples {
            let i = (s.wpos & RING_MASK) as usize;
            s.buf[i] = v;
            s.wpos += 1;
        }
    }

    /// Advance the timeline by `n` samples of silence.
    ///
    /// The device pulls on its own clock whether or not the mixer had anything to give
    /// it (underruns, the pre-fill cushion): those stretches are played as silence, and
    /// the reference timeline has to contain them or it drifts against the capture by
    /// exactly the length of every gap.
    pub fn publish_silence(&self, token: u64, n: usize) {
        let Ok(mut s) = self.inner.lock() else { return };
        if s.owner != token {
            return;
        }
        for _ in 0..n {
            let i = (s.wpos & RING_MASK) as usize;
            s.buf[i] = 0.0;
            s.wpos += 1;
        }
    }

    pub(crate) fn wpos(&self) -> u64 {
        self.inner.lock().map(|s| s.wpos).unwrap_or(0)
    }

    /// Copy `out.len()` samples starting at absolute index `from`. Anything outside the
    /// ring's live window reads as silence.
    pub(crate) fn read(&self, from: u64, out: &mut [f32]) {
        let Ok(s) = self.inner.lock() else {
            out.fill(0.0);
            return;
        };
        for (k, slot) in out.iter_mut().enumerate() {
            let idx = from.wrapping_add(k as u64);
            *slot = if idx < s.wpos && s.wpos - idx <= RING as u64 {
                s.buf[(idx & RING_MASK) as usize]
            } else {
                0.0
            };
        }
    }
}

/// Reads the reference back in lockstep with the capture stream: exactly one reference
/// sample per captured sample, so the two share an index space and the echo delay is a
/// constant the suppressor can estimate once and then track.
#[derive(Default)]
pub struct RefReader {
    cursor: Option<u64>,
}

impl RefReader {
    /// Pull the block of reference that lines up with the next `out.len()` captured
    /// samples. Returns `false` when the cursor had to be re-seated (first block, or
    /// the two streams drifted out of the searchable range) — the caller must drop its
    /// alignment estimate, since the index space just moved under it.
    /// Is a full block of reference available at the cursor yet?
    ///
    /// The capture side arrives in bursts — a monitor source hands over several frames at
    /// once — while the playout publishes steadily in real time. Consuming a burst in
    /// lockstep therefore overtakes the writer for a few milliseconds, every burst. Left
    /// to `pull`, each of those looked like lost alignment and reset everything learned
    /// about the echo path, so the estimate never survived long enough to converge. It is
    /// not lost alignment; it is arriving early. The caller waits instead.
    pub fn ready(&self, r: &Reference, n: usize) -> bool {
        match self.cursor {
            Some(c) => c + n as u64 <= r.wpos(),
            None => true, // nothing seated yet; `pull` will seat against the write head
        }
    }

    pub fn pull(&mut self, r: &Reference, out: &mut [f32]) -> bool {
        matches!(self.pull_detail(r, out), Pull::Aligned)
    }

    /// As [`RefReader::pull`], saying *which way* alignment was lost when it was.
    ///
    /// The two are different faults with different fixes and they were indistinguishable
    /// in the logs: running ahead means the playout stopped publishing (a dead or idle
    /// output stream), running behind means capture frames went missing (a full queue).
    /// One round of field logs spent narrowing that down is one round too many.
    pub fn pull_detail(&mut self, r: &Reference, out: &mut [f32]) -> Pull {
        let n = out.len() as u64;
        let wpos = r.wpos();
        // Seat the cursor on the newest reference: the sound in this capture block was
        // played BEFORE now, so its reference lies at or behind the write head and the
        // lag the suppressor searches for is non-negative by construction.
        let seat = wpos.saturating_sub(n);
        let (cursor, how) = match self.cursor {
            // Reader past the writer: the playout is not publishing as fast as the capture
            // is consuming, so there is no reference for this block yet.
            Some(c) if c + n > wpos => (seat, Pull::ReseatAhead),
            // So far behind that the true lag has left the search range — re-seat rather
            // than feed the suppressor a reference it can never line up.
            Some(c) if wpos - (c + n) > MAX_LAG_SAMPLES as u64 => (seat, Pull::ReseatBehind),
            Some(c) => (c, Pull::Aligned),
            None => (seat, Pull::ReseatBehind),
        };
        r.read(cursor, out);
        self.cursor = Some(cursor + n);
        how
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::call::SAMPLES_PER_FRAME;

    #[test]
    fn reader_reseats_when_the_streams_drift_apart() {
        let r = Reference {
            inner: Mutex::new(RingState {
                buf: vec![0.0; RING],
                wpos: 0,
                owner: 0,
            }),
        };
        let token = r.claim();
        r.publish(token, &vec![0.5; SAMPLES_PER_FRAME * 4]);
        let mut reader = RefReader::default();
        let mut out = [0.0f32; SAMPLES_PER_FRAME];
        // First pull seats the cursor: not aligned yet, and it lands on the newest block.
        assert!(!reader.pull(&r, &mut out));
        assert!(out.iter().all(|&v| v == 0.5));
        // Writer keeps up → alignment holds.
        r.publish(token, &vec![0.25; SAMPLES_PER_FRAME]);
        assert!(reader.pull(&r, &mut out));
        // Writer runs past the search range (capture stalled) → re-seat, drop the lock.
        r.publish(token, &vec![0.1; MAX_LAG_SAMPLES + 2 * SAMPLES_PER_FRAME]);
        assert!(!reader.pull(&r, &mut out));
        // Writer stops entirely → reader would pass it → re-seat again.
        assert!(!reader.pull(&r, &mut out));
    }

    #[test]
    fn a_stale_publisher_cannot_write_over_the_live_reference() {
        let r = Reference {
            inner: Mutex::new(RingState {
                buf: vec![0.0; RING],
                wpos: 0,
                owner: 0,
            }),
        };
        let old = r.claim();
        let new = r.claim();
        r.publish(old, &[1.0; 64]);
        assert_eq!(r.wpos(), 0, "the superseded session still wrote");
        r.publish(new, &[1.0; 64]);
        assert_eq!(r.wpos(), 64);
        r.publish_silence(old, 64);
        assert_eq!(r.wpos(), 64);
        r.publish_silence(new, 64);
        assert_eq!(r.wpos(), 128);
    }
}
