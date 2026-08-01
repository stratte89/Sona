# Call audio, and the echo canceller

How voice and screen-share audio move through the desktop client, and — mostly — the
traps that have already cost releases. Written after one of them cost two days and six.

## The path

```
                    engine (20 ms frames, 48 kHz mono i16)
                      │  write_frame                        read_frame  ▲
                      ▼                                                 │
   ┌──────────────────────────────┐              ┌──────────────────────┴───────┐
   │ play ring   (FrameRing, 6)   │              │ cap ring   (FrameRing, 6)    │
   └──────────────┬───────────────┘              └──────────────▲───────────────┘
                  │  peer share audio ─→ aux ring               │  RNNoise
                  ▼                                             │
        playout callback  ──── mix ──── resample ──→ SOUND CARD ─┴─ mic capture callback
                  │
                  │ publishes the mix, pre-resampler, in the engine's own 48 kHz domain
                  ▼
            aec::Reference (ring)
                  │                                    ┌─────────────────────────┐
                  │  RefReader: one block per frame    │ system-audio capture    │
                  └───────────────────────────────────→│  (monitor / loopback)   │
                                 EchoSuppressor ◀───────┤  = the post-mix signal, │
                                        │               │  which contains OUR own │
                                        │               │  playout at full level  │
                                        ▼               └─────────────────────────┘
                              shared audio, echo removed ──→ peer
```

Sharing "system audio" means capturing what the machine is playing, and that mix contains
the call's own playout — the peer's voice, at full level. Send it back untouched and the
peer hears themselves a few hundred milliseconds late. There is no *room* in that echo
path; it is a digital mix, so the echo is a plain delay and gain of a reference we already
have. `aec/` subtracts it rather than attenuating anything.

Android is structurally immune: `AudioPlaybackCapture` never captures
`USAGE_VOICE_COMMUNICATION` streams, which is what the Kotlin bridge plays the call into.
None of `aec/` is compiled there.

## The trap that cost two days

**Never open an audio stream with `BufferSize::Default` on the PulseAudio host.**

cpal turns `BufferSize::Default` into a PulseAudio `BufferAttr` with every field set to
`u32::MAX` — the protocol's "server, you decide". What PipeWire's pulse-server decides for
a record stream, asked by a client that expressed no latency preference, is **two
seconds**. That is the correct default for "record the monitor to a file". It is fatal for
an echo reference.

Measured through production code with white noise, on an idle machine:

| | before | after |
|---|---|---|
| loopback delay | **96 576 samples = 2012 ms** | **1536 = 32 ms** |
| correlation at that lag | r = 1.00000, gain 0.998 | unchanged |
| how much of the capture is our playout | 60 dB | unchanged |
| canceller | `NOT LOCKED`, 0 dB | `locked at 32 ms`, 47.8 dB, `reseat a0/b0` |
| captured frames traceable to the reference | 3 / 75 (all chance) | 74 / 75, 73 in order |

`aec::suppress::MAX_LAG_SAMPLES` is 512 ms. The echo was four times outside the range
being searched. The capture was a *flawless* digital copy the entire time.

**Windows never had it.** WASAPI loopback is an input stream opened on the *render*
endpoint, clocked by the same engine period as playout — there is nothing to negotiate and
no server to ask. That is exactly the split the field logs showed for six releases:
`locked at 219 ms, removed 14-25 dB` on Windows, `NOT LOCKED, 0 dB` on Linux, same build,
same call. It was read as "the DSP is worse on Linux". The two platforms were doing
entirely different things.

Guarded now by `capture_config` / `host_config` and two unit tests that run in CI. If one
of them fails because the call was tidied back to `cfg.into()`, read the doc comment
before changing it back.

## Why it survived six releases

**A delay past the end of the window you search does not read as a long delay. It reads as
noise** — indistinguishable from two unrelated signals, no matter how good the estimator
is. Every instrument pointed the wrong way:

- The suppressor searched 512 ms and reported `NOT LOCKED`, which is the *same code path*
  as "there is no echo here" — the healthy no-op. Locally the share sounds perfect. Only
  the peer hears the problem.
- The harness searched 1 s, then 2 s. The two-second sweep **missed by 576 samples**.
- The click test reported 321-443 ms and lost two clicks in five. Those were the
  *previous* round's clicks: a 600 ms gap plus a 1200 ms watch is a 1.8 s cycle, and a 2 s
  pipeline aliases straight into it. It corroborated a wrong answer with a plausible number.
- Correlation was computed with a band-limited probe (`Voice`, a one-pole lowpass at
  ~233 Hz). In a 4096-sample window that carries about twenty independent samples, so a
  search over thousands of lags returns r ≈ 0.3 *by chance* — which is what it returned,
  and it was read as a weak signal rather than no signal.

Four estimator rewrites went into that gap.

### Rules that follow

1. **Measure the delay with an unbounded search before touching `aec/`.** Not the
   estimator's search — an independent one, wide enough to be absurd.
2. **Check the inputs before the algorithm.** `audio::probe` counts every push, eviction,
   underrun and published reference sample on both paths. A reference that describes audio
   nobody played, or a capture with holes in it, fails exactly the way a bad estimator
   does. On this bug the counters came back perfect, which is what moved the search to the
   time base.
3. **Probe with white noise, not speech-shaped noise.** 960 white samples identify a
   position in the reference outright.
4. **A correlation number is meaningless without its chance level.** With `L` lag
   candidates and `N` *independent* samples, the max of pure noise is about
   `sqrt(2·ln L)/sqrt(N)`. Compute it before believing a peak.

## Dead ends — measured, do not retry

| Attempt | Result |
|---|---|
| Envelope cross-correlation | flat in the field; two loud busy signals correlate at every lag |
| GCC-PHAT (full whitening) | **worse than no whitening** — 17 220-sample error vs 2. A test in `aec/delay.rs` enforces this. The echo is a digital mix, not a room; whitening promotes bins carrying only the shared audio |
| Peak-dominance gating, two-strike jump guard | no gain |
| Widening `MAX_LAG` to 1 s | cost 1.9 dB, gained nothing — the delay was 2 s |
| Draining the capture queue to 2 frames | threw away 4/5 of the shared audio (far end heard stutter) *and* raced the reference reader ahead, destroying the alignment it was meant to protect. Shipped as 0.1.29; fixed in 0.1.30 |

## Listener-side volume

Three controls, all local — none of it reaches the wire, so the other side never learns
they were turned down or muted.

| Control | Range | Default | Lifetime | Applied |
|---|---|---|---|---|
| A person's voice | 0-200 % | 100 % | **saved per contact** | after decode, per leg |
| A screen share's audio | 0-200 % | **50 %** | that call only | in the playout mixer, on the aux ring |
| Mute (either) | — | off | that call only | as gain 0 |

**The percentage is not a multiplier.** `gain_factor` squares it, so the slider spreads
its numbers over twice the decibel range and the ends mean something:

```text
    0 %  →  silence          50 %  →  0.25x  (-12 dB)
   25 %  →  0.06x (-24 dB)  100 %  →  1.00x  (unchanged, exactly)
                            200 %  →  4.00x  (+12 dB)
```

A linear percentage is a poor volume control: loudness is roughly logarithmic, so a
linear slider does almost nothing across its top half and everything in a narrow band
near the bottom, and "200 %" is only +6 dB — much less than the word suggests. The
percentage stays the thing shown, stored and sent, because it is what a person reasons
about; `gain_factor` is the single place it becomes a number to multiply by, so voice
and shared audio cannot drift apart.

Voice is the one that persists, in `ContactPin::voice_gain` inside the encrypted history:
a voice that is too quiet is a property of somebody's microphone and room, not of one
call, and being made to fix it again on every call is the actual complaint. It applies to
group calls too — the group engine keys gains by identity key and seeds a member's saved
level as their leg connects.

Shared audio defaults to half deliberately. It is a whole desktop's output arriving next
to one person talking, and at unity it buries them.

Mute is kept *separate* from the level rather than being "level 0", so un-muting returns
to wherever the slider was instead of to the default.

Where each one is applied is not a free choice:

- **Per-peer voice must be scaled before the mix.** `run_group_call` sums legs into an
  `i32` and saturates; once summed there is no separating them again.
- **Share audio is scaled in the playout mixer**, on the aux contribution only — the
  voice path is summed into the same frame and must not move when someone turns a screen
  share down.
- **Gain is saturating, in `i32`.** A boosted loud frame reaches the rails, and wrapping
  there turns a peak into a full-scale sign flip: a click on every peak, which is much
  worse than clipping. `apply_gain` is exact at unity (bit-for-bit untouched, the common
  path) and at zero (silence, not "very quiet").
- **It is a percentage end to end** — slider, Tauri command, vault. An integer that reads
  the same everywhere cannot drift the way a rounded float would.

Note the interaction with this file's subject: turning a share down does **not** reduce
the echo the canceller has to remove. The reference is published pre-gain, from the same
mixer output that is played, so the two stay consistent — see the invariant below.

## Invariants

- **The playout mixer owns the reference timeline.** It publishes the mix *before* the
  device resampler, and publishes silence for any stretch the device pulled through with
  nothing to give it (underruns, the pre-fill cushion). Skip that and the reference drifts
  against the capture by exactly the length of every gap.
- **One publisher.** Concurrent sessions (a 1:1 leg plus a group leg, a reconnect
  overlapping its predecessor) each render their own playout stream; the newest `claim`s
  the ring and older ones go quiet. Interleaving two signals produces a reference matching
  neither.
- **Lockstep.** One reference block consumed per captured frame — that is what makes the
  delay a constant the suppressor can measure once and track. Frames the capture queue
  loses still happened, so their reference blocks are consumed too (counted in the cpal
  callback, at the point of loss).
- **Bursts are not drift.** A monitor source delivers several frames at once, so the
  reader overtakes the writer for a few milliseconds every burst. It waits, bounded,
  rather than declaring alignment lost — treating that as a re-seat threw away the per-bin
  echo path every time.
- **`reseat a<n>/b<n>` is directional and it matters.** *ahead* = playout stopped
  publishing; *behind* = capture frames were lost. Different faults, different fixes.
- **Rings drop the oldest, never the newest.** A queue shedding the newest stays
  permanently full of stale audio the moment the consumer falls behind once.
- **Every failure falls back to doing nothing.** With no alignment there is no estimate,
  and the analysis/synthesis pair is COLA-exact, so "doing nothing" is the input back
  `LATENCY` samples later. There is no bypass switch to click on — which is precisely why
  a total failure is silent, and why the diagnostic line exists.

## Measuring it yourself

See [clients/README.md](../clients/README.md#measuring-the-call-audio-path-locally). The
whole path is testable on any Linux desktop with a sound server, using production code end
to end — real playout, real monitor capture, real suppressor. Nothing is simulated. There
is no reason to ever debug this by shipping a build to another person again.

**Those tests play audible noise through the speakers.** Headphones off first.
