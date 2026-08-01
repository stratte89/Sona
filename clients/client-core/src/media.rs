//! Media v2: camera video, screen sharing, and screen audio on top of the voice-call
//! engine — same blind relay room, same E2E posture, extra tracks.
//!
//! Design (what changed vs. [`crate::call`] and why):
//!
//! * **One room, multiplexed tracks.** Video does not get its own relay room (a second
//!   room would give the relay a linkable "this call has video" record and a second
//!   join event to correlate). Instead every wire frame carries a track id; voice keeps
//!   the exact v1 format so a v2 client interoperates with a v1 peer bit-for-bit.
//! * **Wire compatibility by construction.** A v1 voice frame is `seq(8) || ct` and its
//!   first byte is the high byte of a u64 sequence counter — zero for the next ~45
//!   million years of 20 ms frames. v2 cells start with a nonzero track byte
//!   (1/2/3/15), so the two framings cannot collide and no version handshake is needed
//!   on the media socket itself. A v1 peer that somehow receives a v2 cell drops it as
//!   an unauthenticated frame; nothing breaks.
//! * **Per-track, per-direction keys.** Each track direction gets its own AEAD key from
//!   HKDF over the same per-call root key (`sona-call-v2 <dir> track <id>`), so nonces
//!   are counters with no cross-track collision surface, and each track's sequence is
//!   independently replay-checked. Voice stays under the v1 labels — untouched.
//! * **Padded cells, honest threat model.** Video is bursty by nature (keyframes).
//!   Every cell's plaintext is padded to a 1 KiB multiple (max 16 KiB; larger encoded
//!   frames fragment), the encoder runs CBR-ish with periodic-IDR only, and screen
//!   audio/control ride constant-size cells — but unlike voice, video's *rate* still
//!   varies with motion, and track on/off is visible to the relay as a bandwidth
//!   change. We do not pretend otherwise: the relay learns "call with video-ish
//!   bandwidth", never content. Voice retains its perfectly constant cadence.
//! * **Negotiated, three ways.** Video tracks are enabled only when (a) the peer
//!   advertised the `media2` capability inside the ratchet-encrypted offer/answer,
//!   and (b) the relay's `joined` message reports `media >= 2` (an old relay closes
//!   connections on video-sized frames — better to degrade to voice than drop calls).
//! * **Latency discipline.** Encoding is skipped — never queued — when the socket is
//!   backlogged (drop-before-encode keeps the H.264 reference chain intact), capture
//!   sources hand over only their freshest frame, and decode runs off the socket task
//!   so a slow decode can't stall voice.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::call::{
    codec, AudioIo, CallKeys, CallMedia, CallWireEvent, SAMPLES_PER_FRAME, SAMPLE_RATE, WIRE_FRAME,
};
use crate::{ClientError, Result};

/// Capability string advertised in v2 call offers/answer claims by clients that can
/// run this module. Absent (old client) ⇒ the call runs voice-only, v1 wire format.
pub const MEDIA2_CAP: &str = "media2";

/// The caps this client advertises when offering/answering a call.
pub fn local_caps() -> Vec<String> {
    vec![MEDIA2_CAP.to_string()]
}

/// Did the peer advertise media v2?
pub fn peer_supports_media2(caps: &[String]) -> bool {
    caps.iter().any(|c| c == MEDIA2_CAP)
}

// ── Tracks ──────────────────────────────────────────────────────────────────────────

/// Media tracks multiplexed over one call room. Voice is implicit track 0 (v1 wire
/// format, no track byte). Byte values are on the wire — never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Track {
    /// Camera video (H.264, camera-tuned realtime encoder).
    Camera = 1,
    /// Screen-share video (H.264, screen-content realtime encoder).
    Screen = 2,
    /// Screen-share audio (Opus stereo, CBR — system sound, not the mic).
    ScreenAudio = 3,
    /// In-band control: track on/off, keyframe requests. Sealed like everything else.
    Control = 15,
}

impl Track {
    pub fn from_byte(b: u8) -> Option<Track> {
        match b {
            1 => Some(Track::Camera),
            2 => Some(Track::Screen),
            3 => Some(Track::ScreenAudio),
            15 => Some(Track::Control),
            _ => None,
        }
    }
}

/// What kind of frame arrived on the call socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireClass {
    /// A v1 voice frame (open with [`CallKeys`]).
    VoiceV1,
    /// A v2 media cell for this track (open with [`TrackOpen`]).
    Cell(Track),
}

/// Classify a raw relay frame. `None` = not ours (drop it; the relay is untrusted).
pub fn classify(frame: &[u8]) -> Option<WireClass> {
    let first = *frame.first()?;
    if frame.len() == WIRE_FRAME && first == 0 {
        return Some(WireClass::VoiceV1);
    }
    Track::from_byte(first).map(WireClass::Cell)
}

// ── Cells: sealed, padded, fragmenting wire units ──────────────────────────────────

/// How long a call may have both parties in the room and still no voice frame that opens
/// before it is given up on (E-7).
///
/// Generous by an order of magnitude: with the room up and the keys agreeing, the first
/// frame opens within a frame interval. This is not a "poor network" threshold — a lossy
/// link still lands frames, and the ones that arrive still open — it is the threshold for
/// "these two endpoints cannot talk to each other at all", which is what a `caller`-flag
/// disagreement produces, in both directions, permanently.
pub const VOICE_SILENCE_GIVEUP: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a session waits for the **peer to join the room at all** before giving up.
///
/// [`VOICE_SILENCE_GIVEUP`] only starts counting once the peer has joined, so it says nothing
/// about a peer that never arrives — and nothing else bounded that wait. A call whose room
/// never assembles therefore hung indefinitely: both ends held a live call, the callee sat on
/// "establishing secure connection…" with no timeout at all, and the only thing that ever
/// ended it was the signal TTL minutes later. Measured 2026-08-01, on the fifth call of a run
/// with a minute between each, so not a teardown race.
///
/// Bounded well inside the ring timeout, because by the time this expires the answer has
/// already happened and the user is looking at a call that is going nowhere.
pub const PEER_JOIN_GIVEUP: std::time::Duration = std::time::Duration::from_secs(20);

/// Cell plaintexts are padded to a multiple of this (coarse size hiding).
pub const CELL_QUANTUM: usize = 1024;
/// Largest single cell plaintext; bigger messages fragment across cells.
pub const MAX_CELL_PLAINTEXT: usize = 16 * 1024;
/// Cell plaintext header: `more(1) || chunk_len(4, BE)`.
const CELL_HEADER: usize = 5;
/// Largest wire cell: `track(1) || seq(8) || ct(plaintext + 16 tag)`. The relay's
/// per-frame cap must admit this.
pub const MAX_WIRE_CELL: usize = 1 + 8 + MAX_CELL_PLAINTEXT + 16;
/// Reassembly bound: no encoded media message may exceed this (a hostile relay must
/// not be able to balloon our memory by never sending a final fragment).
pub const MAX_MEDIA_MESSAGE: usize = 256 * 1024;
/// Fixed plaintext size for control cells (tiny JSON, constant on the wire).
pub const CONTROL_PLAINTEXT: usize = 128;
/// Fixed plaintext size for screen-audio cells (Opus stereo CBR fits with headroom).
pub const SCREEN_AUDIO_PLAINTEXT: usize = 256;

/// Round a plaintext length up to the cell padding grid.
fn bucket(n: usize) -> usize {
    n.div_ceil(CELL_QUANTUM) * CELL_QUANTUM
}

fn derive_track_key(key_b64: &str, caller_to_callee: bool, track: Track) -> Result<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    let raw = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(key_b64)
            .map_err(|_| ClientError::Crypto("bad call key".into()))?,
    );
    if raw.len() != 32 {
        return Err(ClientError::Crypto("bad call key length".into()));
    }
    let hk = Hkdf::<Sha256>::new(None, &raw);
    let mut info = Vec::with_capacity(48);
    info.extend_from_slice(b"sona-call-v2 ");
    info.extend_from_slice(if caller_to_callee {
        b"caller->callee"
    } else {
        b"callee->caller"
    });
    info.extend_from_slice(b" track ");
    info.push(track as u8);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|e| ClientError::Crypto(e.to_string()))?;
    Ok(key)
}

/// XChaCha20 nonce for a cell: track byte, zeros, then the counter (big-endian). Keys
/// are per track+direction, so counters can never collide across tracks anyway; the
/// track byte in the nonce (and AAD) is belt-and-suspenders.
fn cell_nonce(track: Track, seq: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[0] = track as u8;
    n[16..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Sealing half of one track direction. Zeroized on drop.
pub struct TrackSeal {
    key: [u8; 32],
    track: Track,
    next_seq: u64,
}

impl Drop for TrackSeal {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl TrackSeal {
    /// `caller: true` on the side that minted the offer (we seal caller→callee).
    pub fn derive(key_b64: &str, caller: bool, track: Track) -> Result<TrackSeal> {
        Ok(TrackSeal {
            key: derive_track_key(key_b64, caller, track)?,
            track,
            next_seq: 0,
        })
    }

    fn seal_one(&mut self, more: bool, chunk: &[u8], padded_plaintext: usize) -> Result<Vec<u8>> {
        debug_assert!(CELL_HEADER + chunk.len() <= padded_plaintext);
        let seq = self.next_seq;
        self.next_seq += 1;
        let mut plain = Zeroizing::new(vec![0u8; padded_plaintext]);
        plain[0] = more as u8;
        plain[1..5].copy_from_slice(&(chunk.len() as u32).to_be_bytes());
        plain[5..5 + chunk.len()].copy_from_slice(chunk);

        let mut wire = Vec::with_capacity(1 + 8 + padded_plaintext + 16);
        wire.push(self.track as u8);
        wire.extend_from_slice(&seq.to_be_bytes());
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&cell_nonce(self.track, seq)),
                chacha20poly1305::aead::Payload {
                    msg: &plain,
                    aad: &wire[..9], // track byte + sequence
                },
            )
            .map_err(|_| ClientError::Crypto("seal failed".into()))?;
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    /// Seal one encoded media message into 1..n cells, each padded to the 1 KiB grid.
    pub fn seal_cells(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() || data.len() > MAX_MEDIA_MESSAGE {
            return Err(ClientError::Crypto("media message size".into()));
        }
        let max_chunk = MAX_CELL_PLAINTEXT - CELL_HEADER;
        let mut cells = Vec::with_capacity(data.len().div_ceil(max_chunk));
        let mut chunks = data.chunks(max_chunk).peekable();
        while let Some(chunk) = chunks.next() {
            let more = chunks.peek().is_some();
            cells.push(self.seal_one(more, chunk, bucket(CELL_HEADER + chunk.len()))?);
        }
        Ok(cells)
    }

    /// Seal a small message into a single cell with an exact (constant) plaintext size.
    /// Used for control and screen-audio cells so their wire size never varies.
    pub fn seal_padded(&mut self, data: &[u8], padded_plaintext: usize) -> Result<Vec<u8>> {
        if CELL_HEADER + data.len() > padded_plaintext {
            return Err(ClientError::Crypto("cell payload too large".into()));
        }
        self.seal_one(false, data, padded_plaintext)
    }
}

/// Opening half of one track direction: authenticates, replay-checks, reassembles
/// fragments. Zeroized on drop.
pub struct TrackOpen {
    key: [u8; 32],
    track: Track,
    last_seq: Option<u64>,
    partial: Vec<u8>,
}

impl Drop for TrackOpen {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl TrackOpen {
    /// `caller: true` on the side that minted the offer (we open callee→caller).
    pub fn derive(key_b64: &str, caller: bool, track: Track) -> Result<TrackOpen> {
        Ok(TrackOpen {
            key: derive_track_key(key_b64, !caller, track)?,
            track,
            last_seq: None,
            partial: Vec::new(),
        })
    }

    /// Open one wire cell. `Ok(Some(msg))` when a complete message is reassembled,
    /// `Ok(None)` for a middle fragment. Errors are non-fatal to the call: the relay is
    /// untrusted, so a bad cell is dropped and any half-built message is discarded.
    pub fn open_cell(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>> {
        if wire.len() < 1 + 8 + CELL_HEADER + 16
            || wire.len() > MAX_WIRE_CELL
            || wire[0] != self.track as u8
        {
            self.partial.clear();
            return Err(ClientError::Crypto("bad cell".into()));
        }
        let seq = u64::from_be_bytes(wire[1..9].try_into().expect("8 bytes"));
        if self.last_seq.is_some_and(|last| seq <= last) {
            self.partial.clear();
            return Err(ClientError::Crypto("replayed media cell".into()));
        }
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&cell_nonce(self.track, seq)),
                    chacha20poly1305::aead::Payload {
                        msg: &wire[9..],
                        aad: &wire[..9],
                    },
                )
                .map_err(|_| {
                    self.partial.clear();
                    ClientError::Crypto("cell authentication failed".into())
                })?,
        );
        self.last_seq = Some(seq);
        let more = match plain[0] {
            0 => false,
            1 => true,
            _ => {
                self.partial.clear();
                return Err(ClientError::Crypto("bad cell header".into()));
            }
        };
        let len = u32::from_be_bytes(plain[1..5].try_into().expect("4 bytes")) as usize;
        if CELL_HEADER + len > plain.len() || self.partial.len() + len > MAX_MEDIA_MESSAGE {
            self.partial.clear();
            return Err(ClientError::Crypto("bad cell length".into()));
        }
        self.partial.extend_from_slice(&plain[5..5 + len]);
        if more {
            return Ok(None);
        }
        Ok(Some(std::mem::take(&mut self.partial)))
    }
}

// ── In-band control ─────────────────────────────────────────────────────────────────

/// Control messages on [`Track::Control`]. Sealed and replay-checked like media; the
/// relay sees only a constant-size cell.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ControlMsg {
    /// The sender started streaming this track.
    TrackOn { track: u8 },
    /// The sender stopped this track (peer hides the tile / resets its decoder).
    TrackOff { track: u8 },
    /// Ask the sender to force an IDR on this track (our decoder lost sync).
    KeyframeReq { track: u8 },
}

impl ControlMsg {
    pub fn seal(&self, seal: &mut TrackSeal) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(|e| ClientError::Crypto(e.to_string()))?;
        seal.seal_padded(&json, CONTROL_PLAINTEXT)
    }

    pub fn open(open: &mut TrackOpen, wire: &[u8]) -> Result<ControlMsg> {
        let msg = open
            .open_cell(wire)?
            .ok_or_else(|| ClientError::Crypto("fragmented control cell".into()))?;
        serde_json::from_slice(&msg).map_err(|e| ClientError::Crypto(e.to_string()))
    }
}

// ── Video codec (openh264, realtime) ────────────────────────────────────────────────

/// Thin realtime-tuned wrapper over the `openh264` crate (safe Rust bindings over
/// Cisco's C++ encoder/decoder, vendored + built from source). H.264 baseline-ish,
/// zero frame lag, no B-frames — every encoded frame decodes immediately.
pub mod video {
    use openh264::decoder;
    use openh264::encoder::{
        self, BitRate, Complexity, EncoderConfig, FrameRate, IntraFramePeriod, RateControlMode,
        UsageType,
    };
    use openh264::formats::{YUVBuffer, YUVSource};
    use openh264::OpenH264API;

    /// One raw video frame, packed planar I420 (Y then U then V, even dimensions).
    #[derive(Clone)]
    pub struct Frame {
        pub width: usize,
        pub height: usize,
        pub i420: Vec<u8>,
    }

    impl Frame {
        /// Wellformedness: even dimensions, exact plane sizes, sane bounds.
        pub fn valid(&self) -> bool {
            self.width >= 16
                && self.height >= 16
                && self.width <= 4096
                && self.height <= 4096
                && self.width.is_multiple_of(2)
                && self.height.is_multiple_of(2)
                && self.i420.len() == self.width * self.height * 3 / 2
        }
    }

    /// What the encoder is looking at — picks the tuning profile.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Content {
        Camera,
        Screen,
    }

    /// Camera encode target: ~600 kb/s @ up to 30 fps (VGA-ish source).
    pub const CAMERA_BITRATE: u32 = 600_000;
    pub const CAMERA_MAX_FPS: f32 = 30.0;
    /// Screen encode target: ~3 Mb/s @ up to 20 fps.
    ///
    /// The original 1.5 Mb/s @ 15 fps was chosen for a shared text editor. What people
    /// actually share is motion — a game, a video, a scrolling page — and at that
    /// budget a 1080p source spends the whole frame on quantisation noise and still
    /// stutters. Motion reads as "laggy" long before resolution reads as "soft", so
    /// the rate and the frame rate both go up; the capture side caps resolution
    /// instead (`media_shell::SCREEN_MAX_W`).
    pub const SCREEN_BITRATE: u32 = 3_000_000;
    pub const SCREEN_MAX_FPS: f32 = 20.0;
    /// Periodic IDR interval in frames: bounded damage after any decoder hiccup, and a
    /// keyframe-request never waits forever even if the control cell were lost.
    const IDR_INTERVAL_FRAMES: u32 = 300;

    /// One H.264 encoder, whatever is actually doing the work.
    ///
    /// The software encoder below always exists; a platform may offer a hardware one
    /// through [`super::EncoderFactory`]. Everything downstream — the sealing, the
    /// cells, the wire — is identical either way: this trait hands back an Annex-B
    /// access unit and nothing above it knows or cares where it came from.
    pub trait H264Encode: Send {
        /// Encode one frame. An empty return means "the rate controller skipped this
        /// one, send nothing", which is not an error.
        fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>, String>;
        /// Make the next encoded frame an IDR (the peer's decoder lost sync).
        fn force_keyframe(&mut self);
    }

    pub struct Encoder {
        inner: encoder::Encoder,
    }

    impl H264Encode for Encoder {
        fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>, String> {
            Encoder::encode(self, frame)
        }
        fn force_keyframe(&mut self) {
            Encoder::force_keyframe(self)
        }
    }

    impl Encoder {
        pub fn realtime(content: Content) -> Result<Encoder, String> {
            let (usage, bitrate, fps, complexity) = match content {
                Content::Camera => (
                    UsageType::CameraVideoRealTime,
                    CAMERA_BITRATE,
                    CAMERA_MAX_FPS,
                    Complexity::Medium,
                ),
                // Screen frames are 4–9× the pixels of a camera frame at a comparable
                // deadline. Low complexity buys back the encode time that a full-screen
                // share needs to hit its frame rate at all, and the extra bitrate above
                // more than pays for the coding efficiency it gives up.
                Content::Screen => (
                    UsageType::ScreenContentRealTime,
                    SCREEN_BITRATE,
                    SCREEN_MAX_FPS,
                    Complexity::Low,
                ),
            };
            let cfg = EncoderConfig::new()
                .usage_type(usage)
                .bitrate(BitRate::from_bps(bitrate))
                .max_frame_rate(FrameRate::from_hz(fps))
                .rate_control_mode(RateControlMode::Bitrate)
                .complexity(complexity)
                // Auto — one encode thread per core the machine has. Single-threaded
                // 1080p screen encoding costs more than the whole inter-frame budget on
                // an ordinary laptop, which is most of where "the share was laggy"
                // comes from.
                .num_threads(0)
                .intra_frame_period(IntraFramePeriod::from_num_frames(IDR_INTERVAL_FRAMES));
            Ok(Encoder {
                inner: encoder::Encoder::with_api_config(OpenH264API::from_source(), cfg)
                    .map_err(|e| e.to_string())?,
            })
        }

        /// Encode one frame; returns the Annex-B access unit (may be empty when the
        /// rate controller skips a frame — send nothing). Dimension changes mid-stream
        /// are handled by the underlying encoder (it reinitializes and emits an IDR).
        pub fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>, String> {
            if !frame.valid() {
                return Err("invalid frame".into());
            }
            let buf = YUVBuffer::from_vec(frame.i420.clone(), frame.width, frame.height);
            Ok(self.inner.encode(&buf).map_err(|e| e.to_string())?.to_vec())
        }

        /// Force the next encoded frame to be an IDR (peer decoder asked for sync).
        pub fn force_keyframe(&mut self) {
            self.inner.force_intra_frame();
        }
    }

    pub struct Decoder {
        inner: decoder::Decoder,
    }

    impl Decoder {
        pub fn new() -> Result<Decoder, String> {
            Ok(Decoder {
                inner: decoder::Decoder::new().map_err(|e| e.to_string())?,
            })
        }

        /// Decode one access unit. `Ok(None)` = no picture yet (e.g. bare SPS/PPS).
        pub fn decode(&mut self, packet: &[u8]) -> Result<Option<Frame>, String> {
            let Some(yuv) = self.inner.decode(packet).map_err(|e| e.to_string())? else {
                return Ok(None);
            };
            let (w, h) = yuv.dimensions();
            // Bound decoder-reported dimensions before allocating: the stream is only
            // peer-authenticated, so a malicious call peer could otherwise declare huge
            // dimensions to force an oversized allocation (memory amplification). Reuse the
            // same 4096 cap the encode side enforces via `Frame::valid` (L-4).
            if w == 0 || h == 0 || w > 4096 || h > 4096 || w % 2 != 0 || h % 2 != 0 {
                return Err(format!("decoded frame dimensions out of bounds: {w}x{h}"));
            }
            let (sy, su, sv) = yuv.strides();
            let (cw, ch) = (w / 2, h / 2);
            // The decoder is only peer-authenticated, so its self-reported strides and plane
            // lengths are untrusted too. If the (dimensions, stride, plane-length) triple is
            // inconsistent, the per-row `plane[row*stride .. row*stride + width]` slices below
            // would panic and take down the call-media task — return an error instead so a
            // crafted stream is a dropped frame, not a crash.
            if sy < w
                || su < cw
                || sv < cw
                || yuv.y().len() < (h - 1) * sy + w
                || yuv.u().len() < (ch - 1) * su + cw
                || yuv.v().len() < (ch - 1) * sv + cw
            {
                return Err("decoded frame planes inconsistent with dimensions".into());
            }
            let mut i420 = vec![0u8; w * h * 3 / 2];
            for (row, dst) in i420[..w * h].chunks_exact_mut(w).enumerate() {
                dst.copy_from_slice(&yuv.y()[row * sy..row * sy + w]);
            }
            let (upl, vpl) = i420[w * h..].split_at_mut(cw * ch);
            for (row, dst) in upl.chunks_exact_mut(cw).enumerate() {
                dst.copy_from_slice(&yuv.u()[row * su..row * su + cw]);
            }
            for (row, dst) in vpl.chunks_exact_mut(cw).enumerate() {
                dst.copy_from_slice(&yuv.v()[row * sv..row * sv + cw]);
            }
            Ok(Some(Frame {
                width: w,
                height: h,
                i420,
            }))
        }
    }
}

// ── Engine ──────────────────────────────────────────────────────────────────────────

/// Screen audio format: 20 ms of 48 kHz *stereo*, interleaved.
pub const SCREEN_AUDIO_SAMPLES: usize = SAMPLES_PER_FRAME * 2;
/// Opus stereo CBR for system sound (music survives; 160 B/frame fits the padded cell).
pub const SCREEN_AUDIO_BITRATE: i32 = 64_000;

/// A camera or screen frame source. `frame()` must be non-blocking and hand over only
/// a *fresh* frame (return `None` if nothing new since the last poll) — the capture
/// thread paces the frame rate, the engine just drains it.
pub trait VideoSource: Send + 'static {
    fn frame(&mut self) -> Option<video::Frame>;
}

/// Screen-audio (system sound) source; same non-blocking contract as [`AudioIo`].
pub trait ScreenAudioSource: Send + 'static {
    fn read_frame(&mut self, buf: &mut [i16; SCREEN_AUDIO_SAMPLES]) -> bool;
}

/// Where decoded peer media lands. Must not block (called from engine tasks).
pub trait MediaSink: Send + 'static {
    /// A decoded peer video frame for this track.
    fn video(&mut self, track: Track, frame: video::Frame);
    /// The peer stopped this video track — hide the tile.
    fn video_off(&mut self, track: Track);
    /// 20 ms of decoded peer screen audio (48 kHz stereo, interleaved).
    fn screen_audio(&mut self, pcm: &[i16; SCREEN_AUDIO_SAMPLES]);
}

/// Sources that produce nothing — for voice-only shells/tests and the callee side of
/// capability-degraded calls.
pub struct NoVideo;
impl VideoSource for NoVideo {
    fn frame(&mut self) -> Option<video::Frame> {
        None
    }
}
pub struct NoScreenAudio;
impl ScreenAudioSource for NoScreenAudio {
    fn read_frame(&mut self, _buf: &mut [i16; SCREEN_AUDIO_SAMPLES]) -> bool {
        false
    }
}

/// Live toggles shared with the shell. All flips are safe at any time; the engine
/// notices within one tick. Mic mute keeps the voice cadence (silence goes out);
/// camera/screen toggles start/stop those tracks (visible to the relay as bandwidth —
/// see the module docs).
#[derive(Clone)]
pub struct MediaToggles {
    pub muted: Arc<AtomicBool>,
    pub camera_on: Arc<AtomicBool>,
    pub screen_on: Arc<AtomicBool>,
    pub screen_audio_on: Arc<AtomicBool>,
    /// Width the screen capture should decimate to, written by the encode governor and
    /// read by the platform capture source. See [`SCREEN_WIDTHS`].
    pub screen_width: Arc<AtomicU32>,
    /// How loud to play *this peer's voice*, in percent ([`crate::call::GAIN_UNITY`] =
    /// as sent, 0 = muted for us only). The listener's own setting: it never reaches the
    /// wire, so the peer cannot tell they have been turned down, and it is applied after
    /// decode so a boost lifts concealed frames with the rest.
    pub voice_gain: Arc<AtomicU32>,
}

impl Default for MediaToggles {
    fn default() -> Self {
        MediaToggles {
            muted: Arc::default(),
            camera_on: Arc::default(),
            screen_on: Arc::default(),
            screen_audio_on: Arc::default(),
            screen_width: Arc::new(AtomicU32::new(SCREEN_WIDTHS[0])),
            voice_gain: Arc::new(AtomicU32::new(crate::call::GAIN_UNITY)),
        }
    }
}

/// Capture widths the governor walks between, widest first. Dropping resolution is the
/// lever with the most effect per step: encode cost is roughly linear in pixels, so
/// 1920 → 1280 is well over half the work.
pub const SCREEN_WIDTHS: [u32; 4] = [1920, 1440, 1280, 960];

/// Share of one core's wall time the screen encoder may spend. Above this the machine
/// has nothing left for the 20 ms voice tick, and the call — which is the part that
/// must not break — starts stuttering before the video does.
const ENCODE_BUDGET: f32 = 0.5;

/// Session events surfaced to the shell/UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaEvent {
    /// Both parties are **in the room**. Nothing more: it is the relay reporting
    /// `peers >= 2`, and it is not evidence that a single byte has decrypted.
    ///
    /// It used to say "voice is flowing", and the shell believed it — starting the call
    /// timer and taking the system call out of CONNECTING on the strength of it. So a call
    /// whose frames never opened at either end presented as a healthy running call in
    /// silence (E-7). [`MediaEvent::VoiceFlowing`] is the claim that was actually wanted.
    Connected,
    /// The first voice frame that **decrypted and decoded**. This is the honest "the call
    /// is up": it can only happen if the room, the relay, and — the case that made this
    /// necessary — the direction-derived track keys all agree.
    ///
    /// Safe to gate the UI on, because voice is sent at a constant cadence whether or not
    /// the peer is muted (a muted peer sends encoded silence, not nothing). A call that
    /// never produces this is broken, not quiet.
    VoiceFlowing,
    /// Video/screen tracks are (un)available on this call: requires the peer's
    /// `media2` capability *and* a relay that admits video-sized frames.
    VideoReady(bool),
    /// The peer toggled a track (show/hide the tile before/after frames arrive).
    PeerTrack { track: Track, on: bool },
    /// The peer hung up (or its connection died).
    PeerLeft,
    /// The session ended (stop signal, socket close, or fatal error).
    Ended,
}

/// How the engine obtains an encoder for a track.
///
/// The shell supplies this so platform-specific hardware encoders can live in the
/// platform crate — `client-core` stays free of any OS media API. Returning `None` (or
/// having no factory at all) means the built-in software encoder, which is also the
/// automatic outcome whenever a hardware encoder fails to prove itself; see the
/// shell's probe. Never called on the socket task.
pub type EncoderFactory =
    Arc<dyn Fn(video::Content) -> Option<Box<dyn video::H264Encode>> + Send + Sync>;

/// Everything the platform shell plugs into the engine.
pub struct MediaIo<A, C, S, SA, K>
where
    A: AudioIo,
    C: VideoSource,
    S: VideoSource,
    SA: ScreenAudioSource,
    K: MediaSink,
{
    pub audio: A,
    pub camera: C,
    pub screen: S,
    pub screen_audio: SA,
    pub sink: K,
    /// Optional hardware-encoder source; `None` = software only.
    pub encoders: Option<EncoderFactory>,
}

/// Slot for a peer video track in the liveness arrays. Written by hand rather than cast
/// from the discriminant: `Track::Camera as usize` is 1 and `Track::Screen` is 2, so any
/// arithmetic mapping reads backwards and silently crosses the two tracks over.
fn peer_slot(track: Track) -> usize {
    match track {
        Track::Screen => 1,
        _ => 0,
    }
}

/// How long a peer video track may go without a cell before it is treated as off.
///
/// Generous next to the frame intervals involved — screen video is paced at 20 fps and
/// camera at 30 — so this only fires when a track has genuinely stopped, not when it is
/// merely being governed down or dropping frames under load.
const PEER_TRACK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(2500);

/// Queued cells past which the decode task stops decoding and starts skipping, and the
/// depth it skips down to.
///
/// In cells, because that is what the queue holds: a 1080p frame at the screen bitrate is
/// roughly twenty of them, so this is about two and a half frames of slack — enough to
/// absorb one slow decode without letting a genuinely overloaded receiver build a queue it
/// will never work off.
const DECODE_BACKLOG_MAX: usize = 48;
const DECODE_BACKLOG_KEEP: usize = 16;

/// Cells from the socket to the decode task.
enum DecodeMsg {
    Cell(Vec<u8>),
    /// Peer turned a track off: drop decoder state, tell the sink.
    Reset(Track),
}

/// Run a full-duplex call with optional camera/screen/screen-audio tracks until
/// hangup/peer-loss. Voice behaves exactly like [`crate::call::run_call`] (same keys,
/// same wire); extra tracks activate only when negotiated (`peer_media2` from the
/// offer/answer caps, relay `media >= 2` from the join message).
///
/// `peer_media2` is a live flag because the caller doesn't know the callee's caps
/// until the v2 answer claim arrives over the ratchet — usually around the same moment
/// the callee joins the room. The shell flips it whenever the answer lands; the
/// engine re-evaluates every tick and emits [`MediaEvent::VideoReady`] on changes.
#[allow(clippy::too_many_arguments)] // a call session simply has this many moving parts
pub async fn run_media_call<A, C, S, SA, K>(
    mut media: CallMedia,
    key_b64: &str,
    caller: bool,
    peer_media2: Arc<AtomicBool>,
    io: MediaIo<A, C, S, SA, K>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    toggles: MediaToggles,
    events: tokio::sync::mpsc::UnboundedSender<MediaEvent>,
) -> Result<()>
where
    A: AudioIo,
    C: VideoSource,
    S: VideoSource,
    SA: ScreenAudioSource,
    K: MediaSink,
{
    let MediaIo {
        mut audio,
        camera,
        screen,
        mut screen_audio,
        sink,
        encoders,
    } = io;
    // No factory, or one that declines a track, means the built-in software encoder.
    let make: EncoderFactory = match encoders {
        Some(f) => Arc::new(move |content| {
            f(content).or_else(|| {
                video::Encoder::realtime(content)
                    .ok()
                    .map(|e| Box::new(e) as Box<dyn video::H264Encode>)
            })
        }),
        None => Arc::new(|content| {
            video::Encoder::realtime(content)
                .ok()
                .map(|e| Box::new(e) as Box<dyn video::H264Encode>)
        }),
    };

    // Voice: identical to v1 (keys, codec, framing).
    let mut voice_keys = CallKeys::derive(key_b64, caller)?;
    let mut voice_enc = codec::Encoder::voip_mono_cbr(SAMPLE_RATE, crate::call::OPUS_BITRATE)
        .map_err(ClientError::Crypto)?;
    let mut voice_dec = codec::Decoder::mono(SAMPLE_RATE).map_err(ClientError::Crypto)?;

    // v2 track crypto. Derived up front (cheap) even if never used.
    let mut ctl_seal = TrackSeal::derive(key_b64, caller, Track::Control)?;
    let mut ctl_open = TrackOpen::derive(key_b64, caller, Track::Control)?;
    let mut sa_seal = TrackSeal::derive(key_b64, caller, Track::ScreenAudio)?;
    let mut sa_open = TrackOpen::derive(key_b64, caller, Track::ScreenAudio)?;
    let mut sa_enc = codec::Encoder::audio_stereo_cbr(SAMPLE_RATE, SCREEN_AUDIO_BITRATE)
        .map_err(ClientError::Crypto)?;
    let mut sa_dec = codec::Decoder::stereo(SAMPLE_RATE).map_err(ClientError::Crypto)?;

    let sink = Arc::new(std::sync::Mutex::new(sink));

    // Video tracks may stream only when: peer is in the room, peer speaks v2, and the
    // relay admits video-sized frames.
    let video_active = Arc::new(AtomicBool::new(false));
    let kf_camera = Arc::new(AtomicBool::new(false));
    let kf_screen = Arc::new(AtomicBool::new(false));

    // ── Reliable-send task: everything that must arrive intact (video cells, control
    //    cells) goes out from here and nowhere else.
    //
    //    This is the one structural rule that keeps a screen share from wrecking the
    //    call. A reliable send waits — for congestion control, for a retransmit, for a
    //    free QUIC stream — and while the session loop below was the thing doing that
    //    waiting, it was simultaneously failing to capture voice, send voice, and decode
    //    the peer's voice, because a `select!` arm parked in an `await` blocks every other
    //    arm. Voice, screen audio and video all went choppy together the moment anyone
    //    shared a screen, and no amount of making the *encoder* faster could fix it: the
    //    stall was on the wire, not in the codec. Here, that wait costs only video.
    //
    //    Control cells are polled ahead of video (`biased`): a keyframe request the peer
    //    is waiting on must not sit behind a queued frame, and it is 1 KB against tens. ──
    let (cells_tx, mut cells_rx) = tokio::sync::mpsc::channel::<Vec<Vec<u8>>>(4);
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<Vec<u8>>>();
    let send_task = {
        let cells = media.cell_sender();
        let mut stop = stop.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = stop.changed() => break,
                    Some(group) = ctrl_rx.recv() => {
                        if cells.send_cells(group).await.is_err() {
                            break;
                        }
                    }
                    Some(group) = cells_rx.recv() => {
                        if cells.send_cells(group).await.is_err() {
                            break; // connection gone; the session loop sees it too
                        }
                    }
                    else => break,
                }
            }
        })
    };

    // ── Encode task: camera + screen → sealed cells. Skips (never queues) frames when
    //    the send side is backlogged; skipping happens *before* encoding so the
    //    peer's reference chain stays intact. ──
    let encode_task = {
        let seal_cam = TrackSeal::derive(key_b64, caller, Track::Camera)?;
        let seal_scr = TrackSeal::derive(key_b64, caller, Track::Screen)?;
        let toggles = toggles.clone();
        let video_active = video_active.clone();
        let (kf_camera, kf_screen) = (kf_camera.clone(), kf_screen.clone());
        let mut stop = stop.clone();
        tokio::spawn(async move {
            struct Leg<V: VideoSource> {
                source: V,
                seal: TrackSeal,
                content: video::Content,
                on: Arc<AtomicBool>,
                kf: Arc<AtomicBool>,
                enc: Option<Box<dyn video::H264Encode>>,
                /// Where a replacement comes from; see [`EncoderFactory`].
                make: EncoderFactory,
                /// Smoothed encode cost, seconds per frame.
                cost: f32,
                /// Earliest the next frame may be encoded — the governor's throttle.
                next_at: Option<std::time::Instant>,
                /// Index into [`SCREEN_WIDTHS`]; screen leg only.
                level: usize,
                width: Option<Arc<AtomicU32>>,
                /// Frame interval this leg is nominally aiming for.
                interval: std::time::Duration,
            }
            async fn pump<V: VideoSource>(
                leg: &mut Leg<V>,
                tx: &tokio::sync::mpsc::Sender<Vec<Vec<u8>>>,
            ) {
                if !leg.on.load(Ordering::Relaxed) {
                    leg.enc = None; // off→on later restarts with a fresh IDR
                    leg.next_at = None;
                    leg.cost = 0.0;
                    return;
                }
                if tx.capacity() == 0 {
                    return; // backlogged: drop before encoding
                }
                let now = std::time::Instant::now();
                if leg.next_at.is_some_and(|t| now < t) {
                    return; // governor is holding this leg back
                }
                let Some(frame) = leg.source.frame() else {
                    return;
                };
                if leg.enc.is_none() {
                    leg.enc = (leg.make)(leg.content);
                }
                let Some(enc) = leg.enc.as_mut() else { return };
                if leg.kf.swap(false, Ordering::Relaxed) {
                    enc.force_keyframe();
                }
                let started = std::time::Instant::now();
                let encoded = match enc.encode(&frame) {
                    Ok(e) if !e.is_empty() => e,
                    Ok(_) => return, // rate controller skipped the frame
                    Err(_) => {
                        leg.enc = None; // encoder wedged — rebuild on the next frame
                        return;
                    }
                };
                leg.govern(started.elapsed());
                if let Ok(cells) = leg.seal.seal_cells(&encoded) {
                    let _ = tx.try_send(cells);
                }
            }

            impl<V: VideoSource> Leg<V> {
                /// Keep the encoder inside its share of the machine.
                ///
                /// Software H.264 on a full-resolution screen can cost more than the
                /// frame interval it is trying to hit, and when it does, the thing that
                /// breaks first is not the video — it is the 20 ms voice tick, which now
                /// has to fight the encoder for a core. That is the "their voice broke up
                /// while I was sharing" report, and it is a scheduling problem, not a
                /// bandwidth one: the fix is to spend less CPU, not fewer bits.
                ///
                /// So measure what a frame actually costs and hold the leg to
                /// [`ENCODE_BUDGET`] of one core, first by pacing frames further apart,
                /// and — because cost is roughly linear in pixels — by stepping the
                /// capture down through [`SCREEN_WIDTHS`] when pacing alone is not
                /// enough. Both recover when the load does.
                fn govern(&mut self, took: std::time::Duration) {
                    let took = took.as_secs_f32();
                    // Fast to rise, slow to fall: react to a machine getting busy within
                    // a frame or two, give back resolution only once it has really eased.
                    self.cost = if took > self.cost {
                        0.5 * self.cost + 0.5 * took
                    } else {
                        0.95 * self.cost + 0.05 * took
                    };
                    let nominal = self.interval.as_secs_f32();
                    let paced = (self.cost / ENCODE_BUDGET).max(nominal);
                    self.next_at =
                        Some(std::time::Instant::now() + std::time::Duration::from_secs_f32(paced));

                    let Some(width) = self.width.as_ref() else {
                        return; // camera: VGA-ish, never the problem — pacing is enough
                    };
                    // Pacing is already at half rate and still over budget: fewer pixels.
                    if paced > nominal * 1.8 && self.level + 1 < SCREEN_WIDTHS.len() {
                        self.level += 1;
                    } else if paced < nominal * 1.05 && self.level > 0 && self.cost > 0.0 {
                        self.level -= 1;
                    } else {
                        return;
                    }
                    width.store(SCREEN_WIDTHS[self.level], Ordering::Relaxed);
                    // The next frame arrives at a new size; the encoder reinitialises
                    // and emits an IDR on its own, but drop it so the change is clean.
                    self.enc = None;
                }
            }

            let secs = |fps: f32| std::time::Duration::from_secs_f32(1.0 / fps);
            let mut cam = Leg {
                source: camera,
                seal: seal_cam,
                content: video::Content::Camera,
                on: toggles.camera_on,
                kf: kf_camera,
                enc: None,
                make: make.clone(),
                cost: 0.0,
                next_at: None,
                level: 0,
                width: None,
                interval: secs(video::CAMERA_MAX_FPS),
            };
            let mut scr = Leg {
                source: screen,
                seal: seal_scr,
                content: video::Content::Screen,
                on: toggles.screen_on,
                kf: kf_screen,
                enc: None,
                make,
                cost: 0.0,
                next_at: None,
                level: 0,
                width: Some(toggles.screen_width.clone()),
                interval: secs(video::SCREEN_MAX_FPS),
            };
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tick.tick() => {}
                }
                if !video_active.load(Ordering::Relaxed) {
                    cam.enc = None;
                    scr.enc = None;
                    continue;
                }
                pump(&mut cam, &cells_tx).await;
                pump(&mut scr, &cells_tx).await;
            }
        })
    };

    // ── Decode task: sealed video cells → frames → sink. Off the socket task so a
    //    slow decode can't delay voice. Requests a keyframe (rate-limited) on errors. ──
    let (dec_tx, mut dec_rx) = tokio::sync::mpsc::unbounded_channel::<DecodeMsg>();
    let (kfreq_tx, mut kfreq_rx) = tokio::sync::mpsc::unbounded_channel::<Track>();
    let decode_task = {
        let mut open_cam = TrackOpen::derive(key_b64, caller, Track::Camera)?;
        let mut open_scr = TrackOpen::derive(key_b64, caller, Track::Screen)?;
        let sink = sink.clone();
        tokio::spawn(async move {
            let mut dec_cam: Option<video::Decoder> = None;
            let mut dec_scr: Option<video::Decoder> = None;
            let mut last_kfreq: [Option<std::time::Instant>; 2] = [None, None];
            while let Some(msg) = dec_rx.recv().await {
                // Never decode a backlog. Video decoding is the slowest thing in a call —
                // ~10 ms per 1080p frame in software, 20 of them a second — and this queue
                // was unbounded, so a receiver that could not keep up did not drop frames,
                // it *accumulated* them: every frame decoded was staler than the last and
                // the delay grew without limit for the rest of the call. That is the "his
                // screen is minutes behind and freezing while the audio is fine" report,
                // and it only became visible once the sender got a hardware encoder and
                // started delivering a genuine 20 fps instead of a governed trickle.
                //
                // A live frame is worth decoding and a stale one is worth skipping, so when
                // the queue runs deep the oldest cells go and the newest are kept. Whole
                // frames simply fail to reassemble and the next keyframe recovers the
                // picture — the track's cell reassembler already treats an incomplete frame
                // as nothing at all, so there is no corrupt output to guard against.
                //
                // Only a cell is ever skipped past. `msg` itself being a `Reset` means a
                // track just went off, which is never stale and never dropped — it is the
                // reason a tile hides, and losing it leaves the peer's last frame frozen on
                // screen after they stopped sharing.
                let backlogged =
                    matches!(msg, DecodeMsg::Cell(_)) && dec_rx.len() > DECODE_BACKLOG_MAX;
                let msg = if backlogged {
                    let mut newest = msg;
                    while dec_rx.len() > DECODE_BACKLOG_KEEP {
                        match dec_rx.try_recv() {
                            // A track going off must not be skipped past: it is the reason
                            // a tile hides, and dropping it leaves the last frame frozen
                            // on screen after the peer stopped sending.
                            Ok(DecodeMsg::Reset(t)) => {
                                if let Ok(mut s) = sink.lock() {
                                    s.video_off(t);
                                }
                                match t {
                                    Track::Camera => dec_cam = None,
                                    Track::Screen => dec_scr = None,
                                    _ => {}
                                }
                            }
                            Ok(other) => newest = other,
                            Err(_) => break,
                        }
                    }
                    newest
                } else {
                    msg
                };
                match msg {
                    DecodeMsg::Reset(track) => {
                        match track {
                            Track::Camera => dec_cam = None,
                            Track::Screen => dec_scr = None,
                            _ => {}
                        }
                        if let Ok(mut s) = sink.lock() {
                            s.video_off(track);
                        }
                    }
                    DecodeMsg::Cell(wire) => {
                        let (track, open, dec, kf_slot) = match Track::from_byte(wire[0]) {
                            Some(Track::Camera) => {
                                (Track::Camera, &mut open_cam, &mut dec_cam, 0usize)
                            }
                            Some(Track::Screen) => {
                                (Track::Screen, &mut open_scr, &mut dec_scr, 1usize)
                            }
                            _ => continue,
                        };
                        // Bad cells are dropped (untrusted relay), not fatal.
                        let Ok(Some(encoded)) = open.open_cell(&wire) else {
                            continue;
                        };
                        if dec.is_none() {
                            *dec = video::Decoder::new().ok();
                        }
                        let Some(d) = dec.as_mut() else { continue };
                        match d.decode(&encoded) {
                            Ok(Some(frame)) => {
                                if let Ok(mut s) = sink.lock() {
                                    s.video(track, frame);
                                }
                            }
                            Ok(None) => {}
                            Err(_) => {
                                // Lost sync — rebuild and ask for an IDR, ≤ 1/s/track.
                                *dec = None;
                                let now = std::time::Instant::now();
                                let due = last_kfreq[kf_slot]
                                    .is_none_or(|t| now.duration_since(t).as_secs() >= 1);
                                if due {
                                    last_kfreq[kf_slot] = Some(now);
                                    let _ = kfreq_tx.send(track);
                                }
                            }
                        }
                    }
                }
            }
        })
    };

    // ── Socket task state ──
    let mut capture = [0i16; SAMPLES_PER_FRAME];
    let mut playout = [0i16; SAMPLES_PER_FRAME];
    let mut sa_capture = [0i16; SCREEN_AUDIO_SAMPLES];
    let mut sa_playout = [0i16; SCREEN_AUDIO_SAMPLES];
    let mut opus_buf = [0u8; crate::call::PADDED_PLAINTEXT];
    let mut peer_here = false;
    let mut connected_sent = false;
    // Has a single voice frame opened yet? (E-7)
    let mut voice_flowing_sent = false;
    // When the peer joined the room, so a call that never produces audio can be given up on
    // instead of presenting as a healthy running call in silence.
    let mut peer_here_since: Option<std::time::Instant> = None;
    // What the relay last said the room held, carried into the give-up error below.
    //
    // It is the one fact that splits the remaining question in two, and nothing reports it:
    // `peers: 1` means the relay believes this device is alone in the room — which it can,
    // because `join_room` prunes members that read as closed and then tells the newcomer the
    // count *after* pruning, so a peer dropped from the room leaves the joiner alone and the
    // peer, already in, is never sent a `peer_joined` either. `peers: 2` would mean the relay
    // paired them and the fault is on this side. `None` means no `joined` arrived at all.
    let mut last_joined_peers: Option<u8> = None;
    // Voice frames seen on the wire, and how many of those refused to open. Carried into the
    // give-up error because they separate three failures that look identical from outside:
    // nothing arriving (the relay or the room), arriving but not opening (the track keys
    // disagree), and opening but not decoding.
    let mut voice_frames_seen: u64 = 0;
    let mut voice_frames_unopened: u64 = 0;
    let mut conceal = crate::call::Conceal::default();
    // Hoisted out of the tick: the listener's volume for this peer, read once per frame.
    let voice_gain = toggles.voice_gain.clone();
    let mut relay_media2 = false;
    let mut video_ready_sent: Option<bool> = None;
    // Which of our tracks the peer currently believes are on (for edge-triggered
    // TrackOn/TrackOff control cells).
    let mut sent_on = [false; 3]; // camera, screen, screen-audio
                                  // When each of the peer's video tracks last produced a cell, and what we last told
                                  // the shell about it. A `TrackOff` is a single control cell and it does not always
                                  // arrive — twice now a stopped share has left the far side showing a frozen frame,
                                  // and once it left `peer_screen` stuck true so the share button refused for the rest
                                  // of the call. Frames stopping is evidence in its own right and it cannot go missing.
    let mut peer_seen: [Option<std::time::Instant>; 2] = [None, None];
    let mut peer_on = [false; 2];

    let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Armed once, for the whole session: the deadline by which the peer must have joined the
    // room. Disarmed by its own `if !connected_sent` guard the moment they do.
    let join_deadline = tokio::time::sleep(PEER_JOIN_GIVEUP);
    tokio::pin!(join_deadline);

    let result: Result<()> = 'session: {
        loop {
            // Biased: voice is the only track with a hard cadence, and a screen share
            // produces cells far faster than 50 Hz. Left to `select!`'s random choice,
            // a busy share wins the coin flip often enough to push the voice tick
            // around — the call itself starts sounding chunky the moment someone shares
            // their screen. Polled in order, the tick is served whenever it is due and
            // video only ever uses what is left.
            tokio::select! {
                biased;

                _ = stop.changed() => break 'session Ok(()),

                // The peer that never joins the room at all.
                //
                // This has to be its **own** arm, and getting that wrong is what left the
                // fault open for a whole round: the check first went inside the tick arm
                // below, which is guarded `if peer_here` — so the test for "the peer never
                // arrived" could only run once the peer had arrived. Unreachable in exactly
                // the case it was written for.
                //
                // With `peer_here` false the tick arm is disabled, so the loop has no live
                // arms left but this one, the wire receiver and the stop signal. That is the
                // hang the tester kept hitting: a media session that started cleanly (54 ms
                // from join to loop, on the phone) and then sat doing nothing at all while
                // the screen said "establishing secure connection…" — for minutes, ending
                // only when they hung up by hand.
                _ = &mut join_deadline, if !connected_sent => {
                    break 'session Err(ClientError::Protocol(match last_joined_peers {
                        Some(peers) => format!(
                            "the peer never joined the call room (the relay put {peers} \
                             member(s) in it)"
                        ),
                        None => "the call room never acknowledged this device's join".into(),
                    }));
                }

                _ = tick.tick(), if peer_here => {
                    // E-7. Both parties are in the room and not one frame has opened. Voice
                    // is sent at a constant cadence whether or not the peer is muted — a
                    // muted peer sends encoded silence, not nothing — so this is not a quiet
                    // call, it is a broken one: a relay that is not forwarding, or track
                    // keys that disagree, which are direction-derived and therefore fail in
                    // BOTH directions at once. Ending it says so; the alternative is what
                    // the tester saw, a running timer over total silence.
                    if !voice_flowing_sent
                        && peer_here_since
                            .is_some_and(|t| t.elapsed() >= VOICE_SILENCE_GIVEUP)
                    {
                        break 'session Err(ClientError::Protocol(format!(
                            "no voice frame opened after the peer joined \
                             ({voice_frames_seen} voice frames seen, {voice_frames_unopened} \
                             refused to open)"
                        )));
                    }
                    // Voice, exactly as v1: constant cadence, silence when muted.
                    if toggles.muted.load(Ordering::Relaxed) || !audio.read_frame(&mut capture) {
                        capture = [0i16; SAMPLES_PER_FRAME];
                    }
                    let wire = match voice_enc
                        .encode(&capture, &mut opus_buf)
                        .map_err(ClientError::Crypto)
                        .and_then(|n| voice_keys.seal_frame(&opus_buf[..n]))
                    {
                        Ok(w) => w,
                        Err(e) => break 'session Err(e),
                    };
                    if media.send_lossy(wire).await.is_err() {
                        break 'session Ok(());
                    }
                    // Nothing arrived this tick and the speaker has run dry: conceal
                    // the gap rather than hand playout a hole (clicks at both edges).
                    if conceal.tick(audio.playout_queued())
                        && voice_dec.conceal(&mut playout).is_ok()
                    {
                        crate::call::apply_gain(&mut playout, voice_gain.load(Ordering::Relaxed));
                        audio.write_frame(&playout);
                    }

                    // A peer track whose cells have stopped is off, whatever the control
                    // path did or did not say.
                    for track in [Track::Camera, Track::Screen] {
                        let i = peer_slot(track);
                        let live = peer_seen[i]
                            .is_some_and(|t| t.elapsed() < PEER_TRACK_TIMEOUT);
                        if live != peer_on[i] {
                            peer_on[i] = live;
                            let _ = events.send(MediaEvent::PeerTrack { track, on: live });
                            if !live {
                                let _ = dec_tx.send(DecodeMsg::Reset(track));
                            }
                        }
                    }

                    // Re-evaluate negotiation every tick: the answer's caps can land
                    // after the peer already joined the room.
                    let ready = relay_media2 && peer_media2.load(Ordering::Relaxed);
                    video_active.store(ready && peer_here, Ordering::Relaxed);
                    if video_ready_sent != Some(ready) {
                        video_ready_sent = Some(ready);
                        let _ = events.send(MediaEvent::VideoReady(ready));
                    }

                    let v2 = video_active.load(Ordering::Relaxed);
                    // Edge-triggered track state signaling.
                    let want = [
                        v2 && toggles.camera_on.load(Ordering::Relaxed),
                        v2 && toggles.screen_on.load(Ordering::Relaxed),
                        v2 && toggles.screen_audio_on.load(Ordering::Relaxed),
                    ];
                    for (i, track) in [Track::Camera, Track::Screen, Track::ScreenAudio].into_iter().enumerate() {
                        if want[i] != sent_on[i] {
                            sent_on[i] = want[i];
                            let msg = if want[i] {
                                ControlMsg::TrackOn { track: track as u8 }
                            } else {
                                ControlMsg::TrackOff { track: track as u8 }
                            };
                            let cell = match msg.seal(&mut ctl_seal) {
                                Ok(c) => c,
                                Err(e) => break 'session Err(e),
                            };
                            // Handed to the reliable-send task, never awaited here: the
                            // voice tick this is running inside must not wait on the wire.
                            let _ = ctrl_tx.send(vec![cell]);
                        }
                    }

                    // Screen audio rides the voice tick: constant 20 ms cadence while on.
                    if want[2] {
                        if !screen_audio.read_frame(&mut sa_capture) {
                            sa_capture = [0i16; SCREEN_AUDIO_SAMPLES];
                        }
                        let cell = match sa_enc
                            .encode(&sa_capture, &mut opus_buf)
                            .map_err(ClientError::Crypto)
                            .and_then(|n| sa_seal.seal_padded(&opus_buf[..n], SCREEN_AUDIO_PLAINTEXT))
                        {
                            Ok(c) => c,
                            Err(e) => break 'session Err(e),
                        };
                        if media.send_lossy(cell).await.is_err() {
                            break 'session Ok(());
                        }
                    }
                }

                ev = media.next_event() => match ev {
                    Err(e) => break 'session Err(e),
                    Ok(ev) => match ev {
                    CallWireEvent::Joined { peers, media: relay_media } => {
                        last_joined_peers = Some(peers);
                        relay_media2 = relay_media >= 2;
                        let ready = relay_media2 && peer_media2.load(Ordering::Relaxed);
                        if video_ready_sent != Some(ready) {
                            video_ready_sent = Some(ready);
                            let _ = events.send(MediaEvent::VideoReady(ready));
                        }
                        peer_here = peers >= 2;
                        if peer_here && peer_here_since.is_none() {
                            peer_here_since = Some(std::time::Instant::now());
                        }
                        video_active.store(ready && peer_here, Ordering::Relaxed);
                        if peer_here && !connected_sent {
                            connected_sent = true;
                            let _ = events.send(MediaEvent::Connected);
                        }
                    }
                    CallWireEvent::PeerJoined => {
                        peer_here = true;
                        if peer_here_since.is_none() {
                            peer_here_since = Some(std::time::Instant::now());
                        }
                        video_active.store(
                            relay_media2 && peer_media2.load(Ordering::Relaxed),
                            Ordering::Relaxed,
                        );
                        if !connected_sent {
                            connected_sent = true;
                            let _ = events.send(MediaEvent::Connected);
                        }
                    }
                    CallWireEvent::Frame(wire) => match classify(&wire) {
                        Some(WireClass::VoiceV1) => {
                            voice_frames_seen += 1;
                            // Bad frames dropped, not fatal (untrusted relay), as in v1 —
                            // but counted, because "frames arrive and none of them open" is
                            // a key disagreement while "no frames arrive" is the relay or the
                            // room, and silently dropping made those two indistinguishable.
                            let opened = voice_keys.open_frame(&wire);
                            if opened.is_err() {
                                voice_frames_unopened += 1;
                            }
                            if let Ok(opus_bytes) = opened {
                                // The first frame that actually opened. Everything upstream
                                // of here — the room, the relay, the direction-derived track
                                // keys — has just been proved to agree, which is the only
                                // honest basis for telling the user the call is up (E-7).
                                if !voice_flowing_sent {
                                    voice_flowing_sent = true;
                                    let _ = events.send(MediaEvent::VoiceFlowing);
                                }
                                if voice_dec.decode(&opus_bytes, &mut playout).is_ok() {
                                    conceal.on_frame();
                                    crate::call::apply_gain(
                                        &mut playout,
                                        voice_gain.load(Ordering::Relaxed),
                                    );
                                    audio.write_frame(&playout);
                                }
                            }
                        }
                        Some(WireClass::Cell(t @ (Track::Camera | Track::Screen))) => {
                            peer_seen[peer_slot(t)] = Some(std::time::Instant::now());
                            let _ = dec_tx.send(DecodeMsg::Cell(wire));
                        }
                        Some(WireClass::Cell(Track::ScreenAudio)) => {
                            if let Ok(Some(opus_bytes)) = sa_open.open_cell(&wire) {
                                if sa_dec.decode(&opus_bytes, &mut sa_playout).is_ok() {
                                    if let Ok(mut s) = sink.lock() {
                                        s.screen_audio(&sa_playout);
                                    }
                                }
                            }
                        }
                        Some(WireClass::Cell(Track::Control)) => {
                            if let Ok(msg) = ControlMsg::open(&mut ctl_open, &wire) {
                                match msg {
                                    ControlMsg::TrackOn { track } => {
                                        if let Some(t) = Track::from_byte(track) {
                                            let _ = events.send(MediaEvent::PeerTrack { track: t, on: true });
                                        }
                                    }
                                    ControlMsg::TrackOff { track } => {
                                        if let Some(t) = Track::from_byte(track) {
                                            let _ = events.send(MediaEvent::PeerTrack { track: t, on: false });
                                            if matches!(t, Track::Camera | Track::Screen) {
                                                let _ = dec_tx.send(DecodeMsg::Reset(t));
                                            }
                                        }
                                    }
                                    ControlMsg::KeyframeReq { track } => match Track::from_byte(track) {
                                        Some(Track::Camera) => kf_camera.store(true, Ordering::Relaxed),
                                        Some(Track::Screen) => kf_screen.store(true, Ordering::Relaxed),
                                        _ => {}
                                    },
                                }
                            }
                        }
                        None => {} // not ours — drop
                    },
                    CallWireEvent::PeerLeft => {
                        let _ = events.send(MediaEvent::PeerLeft);
                        break 'session Ok(());
                    }
                    CallWireEvent::Closed => break 'session Ok(()),
                    },
                },

                // Our decoder lost sync — ask the peer for an IDR. Queued on the reliable
                // path ahead of outbound video: an unanswered request costs the peer a
                // second of broken picture, one late video frame costs 50 ms.
                Some(track) = kfreq_rx.recv() => {
                    let cell = match (ControlMsg::KeyframeReq { track: track as u8 }).seal(&mut ctl_seal) {
                        Ok(c) => c,
                        Err(e) => break 'session Err(e),
                    };
                    let _ = ctrl_tx.send(vec![cell]);
                }

                // Outbound video is deliberately absent from this loop — it belongs to
                // `send_task`, because putting it here is what made a share stall voice.
            }
        }
    };

    encode_task.abort();
    send_task.abort();
    drop(dec_tx);
    decode_task.abort();
    media.close().await;
    let _ = events.send(MediaEvent::Ended);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::CallTicket;

    #[test]
    fn buckets_round_up_to_quantum() {
        assert_eq!(bucket(1), CELL_QUANTUM);
        assert_eq!(bucket(CELL_QUANTUM), CELL_QUANTUM);
        assert_eq!(bucket(CELL_QUANTUM + 1), 2 * CELL_QUANTUM);
    }

    #[test]
    fn classify_separates_v1_voice_from_v2_cells() {
        let t = CallTicket::mint();
        let mut voice = CallKeys::derive(&t.key_b64, true).unwrap();
        let w = voice.seal_frame(&[1u8; 60]).unwrap();
        assert_eq!(classify(&w), Some(WireClass::VoiceV1));

        let mut seal = TrackSeal::derive(&t.key_b64, true, Track::Camera).unwrap();
        let cells = seal.seal_cells(&[9u8; 100]).unwrap();
        assert_eq!(classify(&cells[0]), Some(WireClass::Cell(Track::Camera)));

        assert_eq!(classify(&[]), None);
        assert_eq!(classify(&[7u8; 32]), None); // unknown track byte
    }

    #[test]
    fn cells_round_trip_pad_and_fragment() {
        let t = CallTicket::mint();
        let mut seal = TrackSeal::derive(&t.key_b64, true, Track::Screen).unwrap();
        let mut open = TrackOpen::derive(&t.key_b64, false, Track::Screen).unwrap();

        // Small message: one cell, padded to the quantum grid.
        let small = vec![3u8; 100];
        let cells = seal.seal_cells(&small).unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].len(), 1 + 8 + CELL_QUANTUM + 16);
        assert_eq!(open.open_cell(&cells[0]).unwrap(), Some(small));

        // Two different sizes in the same bucket look identical on the wire.
        let a = seal.seal_cells(&[1u8; 10]).unwrap();
        let b = seal.seal_cells(&vec![2u8; 900]).unwrap();
        assert_eq!(a[0].len(), b[0].len());
        open.open_cell(&a[0]).unwrap();
        open.open_cell(&b[0]).unwrap();

        // Large message fragments and reassembles.
        let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let cells = seal.seal_cells(&big).unwrap();
        assert!(cells.len() >= 3);
        for c in &cells {
            assert!(c.len() <= MAX_WIRE_CELL);
        }
        let mut out = None;
        for c in &cells {
            let r = open.open_cell(c).unwrap();
            assert!(out.is_none());
            out = r;
        }
        assert_eq!(out.unwrap(), big);
    }

    #[test]
    fn cells_reject_replay_tamper_cross_track_and_wrong_direction() {
        let t = CallTicket::mint();
        let mut seal = TrackSeal::derive(&t.key_b64, true, Track::Camera).unwrap();
        let mut open = TrackOpen::derive(&t.key_b64, false, Track::Camera).unwrap();

        let cell = seal.seal_cells(&[5u8; 64]).unwrap().remove(0);
        assert!(open.open_cell(&cell).unwrap().is_some());
        // Replay.
        assert!(open.open_cell(&cell).is_err());

        // Tamper.
        let mut cell2 = seal.seal_cells(&[6u8; 64]).unwrap().remove(0);
        let last = cell2.len() - 1;
        cell2[last] ^= 0xff;
        assert!(open.open_cell(&cell2).is_err());

        // Cross-track: a Camera cell does not open as Screen even with Screen keys.
        let cam_cell = seal.seal_cells(&[7u8; 64]).unwrap().remove(0);
        let mut scr_open = TrackOpen::derive(&t.key_b64, false, Track::Screen).unwrap();
        assert!(scr_open.open_cell(&cam_cell).is_err());
        // ...even if the track byte is forged (AEAD covers it).
        let mut forged = cam_cell.clone();
        forged[0] = Track::Screen as u8;
        assert!(scr_open.open_cell(&forged).is_err());

        // Wrong direction: our own seals don't open with our own open-side keys.
        let mut same_dir = TrackOpen::derive(&t.key_b64, true, Track::Camera).unwrap();
        let cell3 = seal.seal_cells(&[8u8; 64]).unwrap().remove(0);
        assert!(same_dir.open_cell(&cell3).is_err());
    }

    #[test]
    fn interrupted_fragment_sequence_is_discarded() {
        let t = CallTicket::mint();
        let mut seal = TrackSeal::derive(&t.key_b64, true, Track::Screen).unwrap();
        let mut open = TrackOpen::derive(&t.key_b64, false, Track::Screen).unwrap();

        let big: Vec<u8> = vec![1u8; 3 * MAX_CELL_PLAINTEXT];
        let cells = seal.seal_cells(&big).unwrap();
        assert!(open.open_cell(&cells[0]).unwrap().is_none());
        // A replayed/garbage cell mid-stream clears the partial buffer.
        assert!(open.open_cell(&cells[0]).is_err());
        // The rest of the message no longer reassembles into the original.
        let mut tail = None;
        for c in &cells[1..] {
            tail = open.open_cell(c).unwrap();
        }
        assert_ne!(tail, Some(big));
    }

    #[test]
    fn control_messages_round_trip_constant_size() {
        let t = CallTicket::mint();
        let mut seal = TrackSeal::derive(&t.key_b64, false, Track::Control).unwrap();
        let mut open = TrackOpen::derive(&t.key_b64, true, Track::Control).unwrap();

        let on = ControlMsg::TrackOn {
            track: Track::Camera as u8,
        };
        let kf = ControlMsg::KeyframeReq {
            track: Track::Screen as u8,
        };
        let w1 = on.seal(&mut seal).unwrap();
        let w2 = kf.seal(&mut seal).unwrap();
        assert_eq!(w1.len(), w2.len()); // constant wire size
        assert_eq!(ControlMsg::open(&mut open, &w1).unwrap(), on);
        assert_eq!(ControlMsg::open(&mut open, &w2).unwrap(), kf);
    }

    #[test]
    fn screen_audio_cell_is_constant_size_and_fits() {
        let t = CallTicket::mint();
        let mut enc = codec::Encoder::audio_stereo_cbr(SAMPLE_RATE, SCREEN_AUDIO_BITRATE).unwrap();
        let mut seal = TrackSeal::derive(&t.key_b64, true, Track::ScreenAudio).unwrap();
        let mut out = [0u8; crate::call::PADDED_PLAINTEXT];

        let loud: Vec<i16> = (0..SCREEN_AUDIO_SAMPLES)
            .map(|i| (((i * 5417) % 65536) as i32 - 32768) as i16)
            .collect();
        let n_loud = enc.encode(&loud, &mut out).unwrap();
        let w1 = seal
            .seal_padded(&out[..n_loud], SCREEN_AUDIO_PLAINTEXT)
            .unwrap();

        let silent = [0i16; SCREEN_AUDIO_SAMPLES];
        let n_silent = enc.encode(&silent, &mut out).unwrap();
        let w2 = seal
            .seal_padded(&out[..n_silent], SCREEN_AUDIO_PLAINTEXT)
            .unwrap();

        assert_eq!(w1.len(), w2.len());
        assert!(n_loud + CELL_HEADER <= SCREEN_AUDIO_PLAINTEXT, "{n_loud}B");
    }

    #[test]
    fn video_codec_round_trips_and_screen_mode_works() {
        for content in [video::Content::Camera, video::Content::Screen] {
            let mut enc = video::Encoder::realtime(content).unwrap();
            let mut dec = video::Decoder::new().unwrap();
            let (w, h) = (320usize, 240usize);
            let mut decoded = 0;
            for i in 0..12u32 {
                let mut i420 = vec![128u8; w * h * 3 / 2];
                for y in 0..h {
                    for x in 0..w {
                        i420[y * w + x] = ((x + y) as u32 + i * 16) as u8;
                    }
                }
                let frame = video::Frame {
                    width: w,
                    height: h,
                    i420,
                };
                let encoded = enc.encode(&frame).unwrap();
                if encoded.is_empty() {
                    continue;
                }
                if let Some(out) = dec.decode(&encoded).unwrap() {
                    assert_eq!((out.width, out.height), (w, h));
                    decoded += 1;
                }
            }
            assert!(decoded >= 8, "{content:?}: only {decoded} frames decoded");
        }
    }

    #[test]
    fn encoder_rejects_malformed_frames() {
        let mut enc = video::Encoder::realtime(video::Content::Camera).unwrap();
        // Odd dimensions.
        assert!(enc
            .encode(&video::Frame {
                width: 321,
                height: 240,
                i420: vec![0; 321 * 240 * 3 / 2],
            })
            .is_err());
        // Wrong buffer size.
        assert!(enc
            .encode(&video::Frame {
                width: 320,
                height: 240,
                i420: vec![0; 100],
            })
            .is_err());
    }

    #[test]
    fn forced_keyframes_decode_on_a_fresh_decoder() {
        let mut enc = video::Encoder::realtime(video::Content::Camera).unwrap();
        let (w, h) = (320usize, 240usize);
        let frame = |seed: u8| video::Frame {
            width: w,
            height: h,
            i420: vec![seed; w * h * 3 / 2],
        };
        // Warm the encoder past its initial IDR.
        for i in 0..5 {
            let _ = enc.encode(&frame(i * 30)).unwrap();
        }
        // A fresh decoder can't join mid-stream…
        let mut late = video::Decoder::new().unwrap();
        let delta = enc.encode(&frame(200)).unwrap();
        let got = late.decode(&delta).unwrap_or(None);
        assert!(got.is_none(), "delta frame must not decode from cold");
        // …until the sender forces an IDR (what KeyframeReq triggers).
        enc.force_keyframe();
        let idr = enc.encode(&frame(210)).unwrap();
        assert!(late.decode(&idr).unwrap().is_some());
    }
}
