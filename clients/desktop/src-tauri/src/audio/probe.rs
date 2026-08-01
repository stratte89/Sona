//! Counters for every place a 20 ms frame can go missing between the call engine and
//! the sound card (and back).
//!
//! Six releases were spent on the screen-share echo canceller before anyone checked
//! whether the audio it was handed was intact. It was not: a click test on an idle
//! machine found two of five frames never reached the speakers at all. That is invisible
//! from inside the canceller — a reference that describes audio nobody heard, and a
//! capture missing the frames that were dropped, look exactly like two signals that
//! simply do not correlate.
//!
//! So every drop is counted at the point it happens, and [`report`] prints the whole
//! path in one line. Relaxed atomics on paths that already take a mutex or run a
//! resampler: the cost does not show up.

use std::sync::atomic::{AtomicU64, Ordering};

/// One counted event. Named so a snapshot can print itself without a parallel table.
pub struct Counter {
    n: AtomicU64,
    label: &'static str,
}

impl Counter {
    const fn new(label: &'static str) -> Counter {
        Counter {
            n: AtomicU64::new(0),
            label,
        }
    }

    #[inline]
    pub(crate) fn bump(&self) {
        self.n.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add(&self, n: u64) {
        self.n.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.n.load(Ordering::Relaxed)
    }
}

// ── Playout: engine → ring → mixer → device ─────────────────────────────────────────

/// Voice frames the engine handed to [`crate::audio::ShellAudio::write_frame`].
pub static PLAY_PUSH: Counter = Counter::new("play.push");
/// …of which the ring evicted, unplayed, because it was full.
pub static PLAY_DROP: Counter = Counter::new("play.drop");
/// …and which the playout callback actually mixed.
pub static PLAY_POP: Counter = Counter::new("play.pop");

/// Peer screen-share audio frames pushed into the aux ring, evicted, and mixed.
pub static AUX_PUSH: Counter = Counter::new("aux.push");
pub static AUX_DROP: Counter = Counter::new("aux.drop");
pub static AUX_POP: Counter = Counter::new("aux.pop");

/// Mic frames the capture callback produced, and those the ring evicted before the
/// engine read them.
pub static CAP_PUSH: Counter = Counter::new("cap.push");
pub static CAP_DROP: Counter = Counter::new("cap.drop");

/// Playout callbacks served, and 48 kHz-domain samples the device asked for across them.
pub static PLAYOUT_CB: Counter = Counter::new("playout.cb");
pub static PLAYOUT_DEMAND: Counter = Counter::new("playout.demand");
/// Times the mixer ran dry mid-callback and re-armed the pre-fill cushion.
pub static PLAYOUT_UNDERRUN: Counter = Counter::new("playout.underrun");

/// Reference samples published as real mixer output, and as silence for stretches the
/// device pulled through with nothing to give it.
pub static REF_REAL: Counter = Counter::new("ref.real");
pub static REF_SILENCE: Counter = Counter::new("ref.silence");

// ── Share capture: monitor → suppressor → engine ────────────────────────────────────

/// Frames the monitor callback produced.
pub static SYS_CAPTURED: Counter = Counter::new("sys.captured");
/// …dropped before the suppressor because its queue was full (these slide the reference
/// against the capture unless compensated — see `media_shell::sysaudio`).
pub static SYS_RAW_DROP: Counter = Counter::new("sys.raw_drop");
/// …handed to the engine after suppression, and dropped because the engine was not
/// reading fast enough.
pub static SYS_OUT: Counter = Counter::new("sys.out");
pub static SYS_OUT_DROP: Counter = Counter::new("sys.out_drop");

const ALL: &[&Counter] = &[
    &PLAY_PUSH,
    &PLAY_DROP,
    &PLAY_POP,
    &AUX_PUSH,
    &AUX_DROP,
    &AUX_POP,
    &CAP_PUSH,
    &CAP_DROP,
    &PLAYOUT_CB,
    &PLAYOUT_DEMAND,
    &PLAYOUT_UNDERRUN,
    &REF_REAL,
    &REF_SILENCE,
    &SYS_CAPTURED,
    &SYS_RAW_DROP,
    &SYS_OUT,
    &SYS_OUT_DROP,
];

/// Every counter as of now, for [`report_since`] to subtract.
///
/// Start-up is not steady state — opening a monitor source takes the best part of a
/// second, and counting that stretch as loss makes a healthy path look broken. Measure a
/// window, not a lifetime.
pub fn snapshot() -> Vec<u64> {
    ALL.iter().map(|c| c.get()).collect()
}

/// The drop counters that moved since `base`, or `None` if nothing was lost.
///
/// This is the production half: the share-audio diagnostic prints it every five seconds,
/// so a path that is quietly shedding frames says so in the field instead of only under
/// the local harness. Silence here is the healthy answer and costs one line of nothing.
pub fn losses_since(base: &[u64]) -> Option<String> {
    let lost: Vec<String> = [
        &PLAY_DROP,
        &AUX_DROP,
        &CAP_DROP,
        &PLAYOUT_UNDERRUN,
        &SYS_RAW_DROP,
        &SYS_OUT_DROP,
    ]
    .iter()
    .filter_map(|c| {
        let n = since(base, c);
        (n > 0).then(|| format!("{} {n}", c.label))
    })
    .collect();
    (!lost.is_empty()).then(|| lost.join(", "))
}

/// Every counter, one per line, zeroes included — a zero is the answer to "did this path
/// lose anything" just as much as a large number is. `base` from [`snapshot`], or an
/// empty slice for totals since process start.
#[cfg(test)]
pub fn report_since(base: &[u64]) -> String {
    let mut s = String::new();
    for (i, c) in ALL.iter().enumerate() {
        s.push_str(&format!(
            "  {:<18} {}\n",
            c.label,
            c.get() - base.get(i).copied().unwrap_or(0)
        ));
    }
    s
}

/// One counter's value since `base`, by the same index order as [`snapshot`].
pub fn since(base: &[u64], c: &Counter) -> u64 {
    let i = ALL.iter().position(|x| std::ptr::eq(*x, c));
    c.get() - i.and_then(|i| base.get(i).copied()).unwrap_or(0)
}

/// A one-line health report for the **voice** path, or `None` while it is healthy.
///
/// The existing [`losses_since`] answers "did anything get dropped", which is the wrong
/// question for a one-directional call: a microphone that opens and delivers *nothing* drops
/// nothing either. And it is only called from the screen-share loop, so a plain voice call
/// had no periodic audio diagnostic at all — "I couldn't hear him" and "he couldn't hear me"
/// were indistinguishable from outside, on two different machines.
///
/// `cap` is frames this device's microphone produced; `play` is decoded frames handed to the
/// speaker. Zero of the first means we are sending silence whatever the peer does; zero of
/// the second means nothing is arriving to play.
pub fn voice_health_since(base: &[u64], heard_peer: &mut bool) -> Option<String> {
    let cap = since(base, &CAP_PUSH);
    let play = since(base, &PLAY_PUSH);
    if play > 0 {
        *heard_peer = true;
    }
    if cap > 0 && play > 0 {
        return None; // both directions moving: nothing worth a line
    }
    // A caller joins the room the moment it dials and sits there while the callee's phone
    // rings — so "nothing to play" is the *normal* state for as long as that takes, and
    // reporting it was crying wolf on every outgoing call. Once a frame has arrived, the
    // peer is demonstrably there and silence afterwards is a real fault worth a line.
    //
    // Nothing is lost by waiting: a call that never produces a single frame is exactly what
    // `VOICE_SILENCE_GIVEUP` already ends and reports (E-7).
    if play == 0 && !*heard_peer && cap > 0 {
        return None;
    }
    Some(format!(
        "capture {} frame(s), playout {} frame(s) in the last 5 s{}",
        cap,
        play,
        match (cap, play) {
            (0, 0) => " — NO audio in either direction",
            (0, _) => " — MICROPHONE produced nothing (the peer hears silence)",
            (_, 0) => " — nothing decoded to play (we hear silence)",
            _ => "",
        }
    ))
}
