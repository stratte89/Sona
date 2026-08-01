//! Voice-call engine: end-to-end encrypted, relay-routed, traffic-analysis-resistant.
//!
//! Design (why it looks like this):
//!
//! * **Relay-routed, never peer-to-peer.** P2P (ICE/STUN) hands each party the other's
//!   IP address and adds a large unauthenticated network surface. Sona's posture is
//!   metadata-minimal, so media flows through the self-hosted relay's blind call rooms
//!   (`/v1/call/{id}`): the relay pairs two anonymous sockets by a random id and forwards
//!   opaque frames. Latency cost is one relay hop.
//! * **Signaling rides the Double Ratchet.** The v2 offer (logical IDs plus a random
//!   128-bit media-room id and random 32-byte call key) travels inside the existing E2E
//!   session — authenticated,
//!   forward-secret, invisible to the server. Whoever can decrypt the offer *is* the
//!   callee; the relay never learns identities (joining a room takes only the id, which
//!   is a capability token).
//! * **Per-direction frame keys.** HKDF-SHA256 over the call key with distinct labels for
//!   caller→callee and callee→caller, so the two streams can never collide nonces. Keys
//!   live only in call memory and die on hangup — compromise later reveals nothing.
//! * **Frames.** 20 ms of 48 kHz mono Opus, **CBR** (VBR would leak speech patterns in
//!   frame sizes), padded to a constant [`PADDED_PLAINTEXT`] bytes, sealed with
//!   XChaCha20-Poly1305 under a counter nonce. The wire shows a constant-size frame at a
//!   constant cadence — silence and mute included — so the relay/network learns "a call
//!   is happening" and nothing else. Sequence numbers are AEAD-bound and must strictly
//!   increase (TCP ordering makes any regression an attack or a bug, not reordering).

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{ClientError, Result};

// The transport lives next door (see `crate::callmedia`), re-exported here so
// `call::CallMedia` stays the one public path to it.
pub use crate::callmedia::{CallMedia, CallWireEvent, CellSender};

/// Minimal safe wrapper over libopus (`opusic-sys` — maintained bindings; the previous
/// ecosystem wrapper crates sit on an unmaintained `-sys`). Only what the engine needs:
/// a mono VoIP encoder pinned to CBR, and a mono decoder. All `unsafe` for calls lives
/// in these ~60 lines so it can be audited in one sitting.
pub mod codec {
    use opusic_sys as ffi;

    pub struct Encoder {
        ptr: *mut ffi::OpusEncoder,
        channels: i32,
    }
    // libopus states are plain heap structs; they are safe to move across threads as
    // long as they are used from one thread at a time (&mut enforces that).
    unsafe impl Send for Encoder {}

    impl Encoder {
        /// Mono VoIP encoder at `rate` Hz, CBR at `bitrate` b/s.
        pub fn voip_mono_cbr(rate: u32, bitrate: i32) -> Result<Encoder, String> {
            Self::cbr(rate, 1, ffi::OPUS_APPLICATION_VOIP, bitrate)
        }

        /// Stereo general-audio encoder (screen-share sound: music survives, speech too),
        /// CBR for the same reason as voice: frame sizes must not track content.
        pub fn audio_stereo_cbr(rate: u32, bitrate: i32) -> Result<Encoder, String> {
            Self::cbr(rate, 2, ffi::OPUS_APPLICATION_AUDIO, bitrate)
        }

        fn cbr(
            rate: u32,
            channels: i32,
            application: i32,
            bitrate: i32,
        ) -> Result<Encoder, String> {
            let mut err = 0i32;
            let p =
                unsafe { ffi::opus_encoder_create(rate as i32, channels, application, &mut err) };
            if err != ffi::OPUS_OK || p.is_null() {
                return Err(format!("opus encoder create: {err}"));
            }
            let enc = Encoder { ptr: p, channels };
            unsafe {
                if ffi::opus_encoder_ctl(enc.ptr, ffi::OPUS_SET_BITRATE_REQUEST, bitrate)
                    != ffi::OPUS_OK
                {
                    return Err("opus set bitrate".into());
                }
                // CBR: frame sizes must not track speech content.
                if ffi::opus_encoder_ctl(enc.ptr, ffi::OPUS_SET_VBR_REQUEST, 0i32) != ffi::OPUS_OK {
                    return Err("opus set cbr".into());
                }
            }
            Ok(enc)
        }

        /// Encode exactly one frame of PCM (interleaved when stereo); returns bytes written.
        pub fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, String> {
            let n = unsafe {
                ffi::opus_encode(
                    self.ptr,
                    pcm.as_ptr(),
                    (pcm.len() / self.channels as usize) as i32, // frame size is per channel
                    out.as_mut_ptr(),
                    out.len() as i32,
                )
            };
            if n < 0 {
                return Err(format!("opus encode: {n}"));
            }
            Ok(n as usize)
        }
    }

    impl Drop for Encoder {
        fn drop(&mut self) {
            unsafe { ffi::opus_encoder_destroy(self.ptr) }
        }
    }

    pub struct Decoder {
        ptr: *mut ffi::OpusDecoder,
        channels: i32,
    }
    unsafe impl Send for Decoder {}

    impl Decoder {
        pub fn mono(rate: u32) -> Result<Decoder, String> {
            Self::new(rate, 1)
        }

        pub fn stereo(rate: u32) -> Result<Decoder, String> {
            Self::new(rate, 2)
        }

        fn new(rate: u32, channels: i32) -> Result<Decoder, String> {
            let mut err = 0i32;
            let p = unsafe { ffi::opus_decoder_create(rate as i32, channels, &mut err) };
            if err != ffi::OPUS_OK || p.is_null() {
                return Err(format!("opus decoder create: {err}"));
            }
            Ok(Decoder { ptr: p, channels })
        }

        /// Decode one packet into `pcm` (interleaved when stereo); returns samples
        /// written *per channel*.
        pub fn decode(&mut self, packet: &[u8], pcm: &mut [i16]) -> Result<usize, String> {
            let n = unsafe {
                ffi::opus_decode(
                    self.ptr,
                    packet.as_ptr(),
                    packet.len() as i32,
                    pcm.as_mut_ptr(),
                    (pcm.len() / self.channels as usize) as i32,
                    0, // no FEC — frames are CBR, losses play as silence
                )
            };
            if n < 0 {
                return Err(format!("opus decode: {n}"));
            }
            Ok(n as usize)
        }

        /// Conceal one lost 20 ms frame: libopus extrapolates from decoder state
        /// (`opus_decode` with a NULL packet) instead of handing playout a hole.
        ///
        /// A gap filled with digital silence is a click at each edge, and a jittery
        /// link is nothing but such gaps — the difference between "choppy" and "a
        /// slightly soft syllable". The run is capped by the caller; libopus fades its
        /// own extrapolation out over a few frames anyway.
        pub fn conceal(&mut self, pcm: &mut [i16]) -> Result<usize, String> {
            let n = unsafe {
                ffi::opus_decode(
                    self.ptr,
                    std::ptr::null(),
                    0,
                    pcm.as_mut_ptr(),
                    (pcm.len() / self.channels as usize) as i32,
                    0,
                )
            };
            if n < 0 {
                return Err(format!("opus conceal: {n}"));
            }
            Ok(n as usize)
        }
    }

    impl Drop for Decoder {
        fn drop(&mut self) {
            unsafe { ffi::opus_decoder_destroy(self.ptr) }
        }
    }
}

/// Audio format: one frame = 20 ms of 48 kHz mono.
pub const SAMPLE_RATE: u32 = 48_000;
pub const CHANNELS: u16 = 1;
pub const SAMPLES_PER_FRAME: usize = 960; // 48_000 * 0.020
/// Opus bitrate. CBR: a 20 ms frame is a constant ~60 bytes regardless of content.
pub const OPUS_BITRATE: i32 = 24_000;
/// Playout gain, in percent, that means "exactly what was sent". Volume controls are
/// carried as percentages end to end: they come from a slider, they are shown to
/// someone as a number, and an integer that reads the same in the UI, the wire of a
/// Tauri command and the vault cannot drift the way a rounded float would.
pub const GAIN_UNITY: u32 = 100;
/// The loudest a listener may make someone. Past roughly this, a normalised voice
/// clips instead of getting louder, so the slider stops where the benefit does.
pub const GAIN_MAX: u32 = 200;

/// The amplitude multiplier a slider percentage means.
///
/// **Not linear.** A percentage that multiplies amplitude directly is a poor volume
/// control: loudness is roughly logarithmic, so a linear slider does almost nothing
/// across its top half and everything in a narrow band near the bottom, and "200 %"
/// is only +6 dB — much less than the word suggests. Squaring the ratio spreads the
/// same numbers over twice the decibel range, so the slider moves the sound about
/// evenly along its length and the ends mean something:
///
/// ```text
///     0 %  →  silence          50 %  →  0.25x  (-12 dB)
///    25 %  →  0.06x (-24 dB)  100 %  →  1.00x  (unchanged, exactly)
///                             200 %  →  4.00x  (+12 dB)
/// ```
///
/// The percentage stays the thing shown, stored and sent — it is what a person
/// reasons about — and this is the only place it becomes a number to multiply by.
pub fn gain_factor(percent: u32) -> f32 {
    let r = percent.min(GAIN_MAX) as f32 / GAIN_UNITY as f32;
    r * r
}

/// Scale 20 ms of playout in place. `GAIN_UNITY` is a no-op and costs nothing.
///
/// Saturating, in `i32`: a boosted loud frame *will* reach the rails, and wrapping
/// there turns a peak into a full-scale sign flip — which is not "a bit distorted",
/// it is a click on every peak.
pub fn apply_gain(frame: &mut [i16; SAMPLES_PER_FRAME], percent: u32) {
    if percent == GAIN_UNITY {
        return;
    }
    if percent == 0 {
        frame.fill(0);
        return;
    }
    let g = gain_factor(percent);
    for s in frame.iter_mut() {
        *s = (*s as f32 * g).clamp(i16::MIN as f32, i16::MAX as f32) as i16;
    }
}

/// Every plaintext frame is padded to exactly this many bytes before sealing, so the
/// ciphertext (and the wire frame) is constant-size. Leaves codec headroom.
pub const PADDED_PLAINTEXT: usize = 256;
/// Wire frame: `seq(8) || ciphertext(PADDED_PLAINTEXT + 16 tag)`.
pub const WIRE_FRAME: usize = 8 + PADDED_PLAINTEXT + 16;

/// The secret material minted by the caller and sent inside the ratchet.
pub struct CallTicket {
    /// 128-bit random room id, hex — the capability to join the relay room.
    pub call_id: String,
    /// 32-byte random call key, base64 — the root of both directions' frame keys.
    pub key_b64: String,
}

impl CallTicket {
    /// Mint a fresh call: random id + random key from OS entropy.
    pub fn mint() -> CallTicket {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let ticket = CallTicket {
            call_id: id.iter().map(|b| format!("{b:02x}")).collect(),
            key_b64: STANDARD_NO_PAD.encode(key),
        };
        key.zeroize();
        ticket
    }

    /// Strictly validate an untrusted media capability before it can create a ring or
    /// be interpolated into a relay URL.
    pub fn valid(call_id: &str, key_b64: &str) -> bool {
        if !crate::callstate::valid_call_id(call_id) || key_b64.len() != 43 {
            return false;
        }
        let Ok(mut key) = STANDARD_NO_PAD.decode(key_b64) else {
            return false;
        };
        let valid = key.len() == 32 && STANDARD_NO_PAD.encode(&key) == key_b64;
        key.zeroize();
        valid
    }
}

/// Per-direction AEAD keys derived from the call key. `caller: true` on the side that
/// minted the offer. Zeroized on drop.
pub struct CallKeys {
    seal_key: [u8; 32],
    open_key: [u8; 32],
    send_seq: u64,
    /// Highest sequence accepted from the peer; replays/regressions are rejected.
    recv_last: Option<u64>,
}

impl Drop for CallKeys {
    fn drop(&mut self) {
        self.seal_key.zeroize();
        self.open_key.zeroize();
    }
}

const INFO_CALLER: &[u8] = b"sona-call-v1 caller->callee";
const INFO_CALLEE: &[u8] = b"sona-call-v1 callee->caller";

impl CallKeys {
    pub fn derive(key_b64: &str, caller: bool) -> Result<CallKeys> {
        let raw = Zeroizing::new(
            STANDARD_NO_PAD
                .decode(key_b64)
                .map_err(|_| ClientError::Crypto("bad call key".into()))?,
        );
        if raw.len() != 32 {
            return Err(ClientError::Crypto("bad call key length".into()));
        }
        let hk = Hkdf::<Sha256>::new(None, &raw);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hk.expand(INFO_CALLER, &mut a)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        hk.expand(INFO_CALLEE, &mut b)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let (seal_key, open_key) = if caller { (a, b) } else { (b, a) };
        Ok(CallKeys {
            seal_key,
            open_key,
            send_seq: 0,
            recv_last: None,
        })
    }

    /// Nonce for a sequence number: 16 zero bytes + the counter, big-endian. Directions
    /// use distinct keys, so identical counters can never collide.
    fn nonce(seq: u64) -> [u8; 24] {
        let mut n = [0u8; 24];
        n[16..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    /// Seal one encoded audio frame into a constant-size wire frame.
    pub fn seal_frame(&mut self, opus: &[u8]) -> Result<Vec<u8>> {
        if opus.len() > PADDED_PLAINTEXT - 2 {
            return Err(ClientError::Crypto("audio frame too large".into()));
        }
        let seq = self.send_seq;
        self.send_seq += 1;
        // Constant-size plaintext: len(2, BE) || opus || zero padding.
        let mut plain = Zeroizing::new(vec![0u8; PADDED_PLAINTEXT]);
        plain[..2].copy_from_slice(&(opus.len() as u16).to_be_bytes());
        plain[2..2 + opus.len()].copy_from_slice(opus);

        let cipher = XChaCha20Poly1305::new((&self.seal_key).into());
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&Self::nonce(seq)),
                chacha20poly1305::aead::Payload {
                    msg: &plain,
                    aad: &seq.to_be_bytes(),
                },
            )
            .map_err(|_| ClientError::Crypto("seal failed".into()))?;

        let mut wire = Vec::with_capacity(WIRE_FRAME);
        wire.extend_from_slice(&seq.to_be_bytes());
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    /// Open a wire frame from the peer: authenticate, enforce strictly-increasing
    /// sequence (replay/regression ⇒ error), return the Opus payload.
    pub fn open_frame(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() != WIRE_FRAME {
            return Err(ClientError::Crypto("bad frame size".into()));
        }
        let seq = u64::from_be_bytes(wire[..8].try_into().expect("8 bytes"));
        if let Some(last) = self.recv_last {
            if seq <= last {
                return Err(ClientError::Crypto("replayed call frame".into()));
            }
        }
        let cipher = XChaCha20Poly1305::new((&self.open_key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&Self::nonce(seq)),
                    chacha20poly1305::aead::Payload {
                        msg: &wire[8..],
                        aad: &seq.to_be_bytes(),
                    },
                )
                .map_err(|_| ClientError::Crypto("frame authentication failed".into()))?,
        );
        let len = u16::from_be_bytes(plain[..2].try_into().expect("2 bytes")) as usize;
        if len > PADDED_PLAINTEXT - 2 {
            return Err(ClientError::Crypto("bad frame length".into()));
        }
        self.recv_last = Some(seq);
        Ok(plain[2..2 + len].to_vec())
    }
}

/// Platform audio hookup. The engine pulls capture frames and pushes playout frames;
/// the shell backs this with real devices (cpal), tests with buffers. Runs on the call
/// task — implementations must not block (use ring buffers to the audio callbacks).
pub trait AudioIo: Send + 'static {
    /// Fill `buf` with the next 20 ms of captured audio. Return `false` when no capture
    /// is available (device warming up, muted at the source) — the engine sends encoded
    /// silence so the wire cadence never changes.
    fn read_frame(&mut self, buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool;
    /// Hand 20 ms of decoded peer audio to the playout path.
    fn write_frame(&mut self, frame: &[i16; SAMPLES_PER_FRAME]);
    /// Frames still queued toward the speaker, when the implementation knows.
    ///
    /// Drives packet-loss concealment: the engine only synthesises a replacement frame
    /// once playout has genuinely run dry, so a burst that arrives late (rather than
    /// never) is played as sent instead of being padded into a longer, drifting stream.
    /// `None` — the default, and what the test doubles report — means "unknown", and
    /// concealment stays off.
    fn playout_queued(&self) -> Option<usize> {
        None
    }
}

/// Playout-gap tracking shared by the v1 and v2 session loops.
///
/// One tick of the session loop is one 20 ms frame of playout. When a tick passes with
/// no voice frame from the peer *and* the shell's playout queue has run dry, the gap is
/// real (not a late burst) and gets a concealed frame instead of a hole — see
/// [`codec::Decoder::conceal`].
#[derive(Default)]
pub(crate) struct Conceal {
    /// A voice frame arrived since the previous tick.
    got_frame: bool,
    /// Nothing is concealed before the first real frame: a call that has not started
    /// carrying audio yet must stay quiet, not hum.
    seen_any: bool,
    /// Consecutive concealed frames, so a peer that has gone away for good does not
    /// generate an endless synthesised stream.
    run: u16,
}

impl Conceal {
    /// 300 ms. Past that this is not jitter and libopus has faded to silence anyway.
    const MAX_RUN: u16 = 15;

    pub(crate) fn on_frame(&mut self) {
        self.got_frame = true;
        self.seen_any = true;
        self.run = 0;
    }

    /// Call once per tick: `true` when playout wants a concealed frame.
    pub(crate) fn tick(&mut self, playout_queued: Option<usize>) -> bool {
        if std::mem::take(&mut self.got_frame) || !self.seen_any || self.run >= Self::MAX_RUN {
            return false;
        }
        if playout_queued != Some(0) {
            return false; // still frames in flight toward the speaker (or unknown)
        }
        self.run += 1;
        true
    }
}

/// Session-level events surfaced to the shell/UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallEvent {
    /// Both parties are in the room; audio is flowing.
    Connected,
    /// The peer hung up (or its connection died).
    PeerLeft,
    /// The session ended (stop signal, socket close, or fatal error).
    Ended,
}

/// Live-session controls shared with the shell: flip `muted` any time (the wire keeps
/// its cadence — mute is invisible on the network); send `true` on `stop` to hang up.
pub struct CallControls {
    pub muted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub stop: tokio::sync::watch::Sender<bool>,
}

/// Run a full-duplex call over a joined room until hangup/peer-loss. Owns the codec
/// state; emits [`CallEvent`]s. `caller` picks the key direction and must match the
/// offer side.
pub async fn run_call(
    mut media: CallMedia,
    key_b64: &str,
    caller: bool,
    mut audio: impl AudioIo,
    mut stop: tokio::sync::watch::Receiver<bool>,
    muted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    events: tokio::sync::mpsc::UnboundedSender<CallEvent>,
) -> Result<()> {
    let mut keys = CallKeys::derive(key_b64, caller)?;
    let mut enc =
        codec::Encoder::voip_mono_cbr(SAMPLE_RATE, OPUS_BITRATE).map_err(ClientError::Crypto)?;
    let mut dec = codec::Decoder::mono(SAMPLE_RATE).map_err(ClientError::Crypto)?;

    let mut capture = [0i16; SAMPLES_PER_FRAME];
    let mut playout = [0i16; SAMPLES_PER_FRAME];
    let mut opus_buf = [0u8; PADDED_PLAINTEXT];
    // Stream only once the peer is present (frames sent into an empty room are dropped
    // by the relay anyway — this just avoids burning CPU while ringing).
    let mut peer_here = false;
    let mut connected_sent = false;
    let mut conceal = Conceal::default();

    let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tick.tick(), if peer_here => {
                // Capture (zeros when muted or unavailable) → Opus CBR → seal → wire.
                if muted.load(std::sync::atomic::Ordering::Relaxed)
                    || !audio.read_frame(&mut capture)
                {
                    capture = [0i16; SAMPLES_PER_FRAME];
                }
                let n = enc
                    .encode(&capture, &mut opus_buf)
                    .map_err(ClientError::Crypto)?;
                let wire = keys.seal_frame(&opus_buf[..n])?;
                if media.send_lossy(wire).await.is_err() {
                    let _ = events.send(CallEvent::Ended);
                    return Ok(());
                }
                // Nothing arrived this tick and the speaker has run dry: conceal.
                if conceal.tick(audio.playout_queued()) && dec.conceal(&mut playout).is_ok() {
                    audio.write_frame(&playout);
                }
            }
            ev = media.next_event() => match ev? {
                CallWireEvent::Joined { peers, .. } => {
                    peer_here = peers >= 2;
                    if peer_here && !connected_sent {
                        connected_sent = true;
                        let _ = events.send(CallEvent::Connected);
                    }
                }
                CallWireEvent::PeerJoined => {
                    peer_here = true;
                    if !connected_sent {
                        connected_sent = true;
                        let _ = events.send(CallEvent::Connected);
                    }
                }
                CallWireEvent::Frame(wire) => {
                    // A frame that fails to authenticate/replay-check is dropped, not
                    // fatal: the relay is untrusted and must not be able to kill a call
                    // by injecting garbage.
                    if let Ok(opus_bytes) = keys.open_frame(&wire) {
                        if dec.decode(&opus_bytes, &mut playout).is_ok() {
                            conceal.on_frame();
                            audio.write_frame(&playout);
                        }
                    }
                }
                CallWireEvent::PeerLeft => {
                    let _ = events.send(CallEvent::PeerLeft);
                    break;
                }
                CallWireEvent::Closed => break,
            },
        }
    }
    media.close().await;
    let _ = events.send(CallEvent::Ended);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_shape() {
        let t = CallTicket::mint();
        assert_eq!(t.call_id.len(), 32);
        assert!(t.call_id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(STANDARD_NO_PAD.decode(&t.key_b64).unwrap().len(), 32);
        assert!(CallTicket::valid(&t.call_id, &t.key_b64));
        assert!(!CallTicket::valid("../not-a-room", &t.key_b64));
        assert!(!CallTicket::valid(&t.call_id, "not-a-key"));
        assert_ne!(CallTicket::mint().call_id, t.call_id);
    }

    /// Volume is a percentage, and the two ends of the range have to be exact: unity
    /// must not touch a sample (it is the common path), and zero must be silence rather
    /// than "very quiet".
    #[test]
    fn gain_is_exact_at_unity_and_zero_and_saturates_between() {
        let orig = [1000i16, -1000, 32_767, -32_768, 0, 7];
        let mut f = [0i16; SAMPLES_PER_FRAME];
        f[..orig.len()].copy_from_slice(&orig);

        let mut unity = f;
        apply_gain(&mut unity, GAIN_UNITY);
        assert_eq!(unity, f, "unity gain must be bit-for-bit untouched");

        let mut silent = f;
        apply_gain(&mut silent, 0);
        assert!(silent.iter().all(|&s| s == 0));

        // Half the slider is a quarter of the amplitude — the curve, not a typo.
        let mut half = f;
        apply_gain(&mut half, 50);
        assert_eq!(&half[..orig.len()], &[250, -250, 8191, -8192, 0, 1]);

        // Boosting a full-scale sample must hit the rail, not wrap round to the other
        // one — a wrap is a click on every peak, which is far worse than clipping.
        let mut loud = f;
        apply_gain(&mut loud, GAIN_MAX);
        assert_eq!(
            &loud[..orig.len()],
            &[4000, -4000, i16::MAX, i16::MIN, 0, 28]
        );

        // The curve itself, at the points a person actually reads off the slider.
        assert_eq!(
            gain_factor(GAIN_UNITY),
            1.0,
            "100 % must be exactly unchanged"
        );
        assert_eq!(gain_factor(0), 0.0);
        assert_eq!(gain_factor(50), 0.25);
        assert_eq!(gain_factor(GAIN_MAX), 4.0);

        // Past the top of the slider the gain is held, not extrapolated.
        let mut absurd = f;
        apply_gain(&mut absurd, 10_000);
        let mut capped = f;
        apply_gain(&mut capped, GAIN_MAX);
        assert_eq!(absurd, capped);
    }

    #[test]
    fn frames_round_trip_constant_size_and_reject_replay_and_forgery() {
        let t = CallTicket::mint();
        let mut caller = CallKeys::derive(&t.key_b64, true).unwrap();
        let mut callee = CallKeys::derive(&t.key_b64, false).unwrap();

        // Different payload sizes → identical wire size (padding hides content length).
        let w1 = caller.seal_frame(&[7u8; 60]).unwrap();
        let w2 = caller.seal_frame(&[7u8; 3]).unwrap();
        assert_eq!(w1.len(), WIRE_FRAME);
        assert_eq!(w2.len(), WIRE_FRAME);

        assert_eq!(callee.open_frame(&w1).unwrap(), vec![7u8; 60]);
        assert_eq!(callee.open_frame(&w2).unwrap(), vec![7u8; 3]);

        // Replay is rejected.
        assert!(callee.open_frame(&w2).is_err());

        // Tampering is rejected.
        let mut bad = caller.seal_frame(&[1u8; 10]).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(callee.open_frame(&bad).is_err());

        // Directions are keyed apart: a caller frame does not open with caller keys.
        let w3 = caller.seal_frame(&[2u8; 10]).unwrap();
        let mut caller2 = CallKeys::derive(&t.key_b64, true).unwrap();
        assert!(caller2.open_frame(&w3).is_err());

        // A different call's keys open nothing.
        let other = CallTicket::mint();
        let mut wrong = CallKeys::derive(&other.key_b64, false).unwrap();
        let w4 = caller.seal_frame(&[3u8; 10]).unwrap();
        assert!(wrong.open_frame(&w4).is_err());
    }

    #[test]
    fn conceal_only_fires_on_a_real_gap_and_stops_when_the_peer_is_gone() {
        let mut c = Conceal::default();
        // Nothing has ever arrived: silence, not synthesised audio.
        assert!(!c.tick(Some(0)));

        c.on_frame();
        assert!(
            !c.tick(Some(0)),
            "the frame that arrived this tick is the frame"
        );
        // Gap, but audio is still queued toward the speaker → it was a late burst.
        assert!(!c.tick(Some(2)));
        // Shell that cannot report its queue (test doubles) never conceals.
        assert!(!c.tick(None));
        // Dry playout and nothing arriving: conceal, up to the run cap.
        for _ in 0..Conceal::MAX_RUN {
            assert!(c.tick(Some(0)));
        }
        assert!(!c.tick(Some(0)), "peer is gone, not jittering");
        // A frame re-arms the whole thing.
        c.on_frame();
        let _ = c.tick(Some(0));
        assert!(c.tick(Some(0)));
    }

    #[test]
    fn concealed_frames_decode_and_fade() {
        let mut enc = codec::Encoder::voip_mono_cbr(SAMPLE_RATE, OPUS_BITRATE).unwrap();
        let mut dec = codec::Decoder::mono(SAMPLE_RATE).unwrap();
        let mut packet = [0u8; PADDED_PLAINTEXT];
        let mut pcm = [0i16; SAMPLES_PER_FRAME];
        // Feed a loud tone so the decoder has state to extrapolate from.
        let tone: Vec<i16> = (0..SAMPLES_PER_FRAME)
            .map(|i| ((i as f32 * 0.09).sin() * 12000.0) as i16)
            .collect();
        for _ in 0..5 {
            let n = enc.encode(&tone, &mut packet).unwrap();
            dec.decode(&packet[..n], &mut pcm).unwrap();
        }
        assert_eq!(dec.conceal(&mut pcm).unwrap(), SAMPLES_PER_FRAME);
        // A long run of concealment must not run away into noise.
        for _ in 0..Conceal::MAX_RUN {
            dec.conceal(&mut pcm).unwrap();
        }
        let peak = pcm.iter().map(|s| s.unsigned_abs()).max().unwrap();
        assert!(peak < 12000, "concealment should fade, peaked at {peak}");
    }

    #[test]
    fn opus_cbr_stays_within_padding() {
        let mut enc = codec::Encoder::voip_mono_cbr(SAMPLE_RATE, OPUS_BITRATE).unwrap();
        let mut out = [0u8; PADDED_PLAINTEXT];
        // Loud noise and pure silence must both fit (and be near-constant size).
        let loud: Vec<i16> = (0..SAMPLES_PER_FRAME)
            .map(|i| (((i * 7919) % 65536) as i32 - 32768) as i16)
            .collect();
        let n_loud = enc.encode(&loud, &mut out).unwrap();
        let silent = [0i16; SAMPLES_PER_FRAME];
        let n_silent = enc.encode(&silent, &mut out).unwrap();
        assert!(n_loud <= PADDED_PLAINTEXT - 2, "loud frame {n_loud}B");
        assert!(n_silent <= PADDED_PLAINTEXT - 2, "silent frame {n_silent}B");
    }
}
