//! Voice-call engine: end-to-end encrypted, relay-routed, traffic-analysis-resistant.
//!
//! Design (why it looks like this):
//!
//! * **Relay-routed, never peer-to-peer.** P2P (ICE/STUN) hands each party the other's
//!   IP address and adds a large unauthenticated network surface. Sona's posture is
//!   metadata-minimal, so media flows through the self-hosted relay's blind call rooms
//!   (`/v1/call/{id}`): the relay pairs two anonymous sockets by a random id and forwards
//!   opaque frames. Latency cost is one relay hop.
//! * **Signaling rides the Double Ratchet.** `CallOffer` (random 128-bit call id + random
//!   32-byte call key) travels inside the existing E2E session — authenticated,
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
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use zeroize::{Zeroize, Zeroizing};

use crate::{Client, ClientError, Result};

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

/// What the relay room socket yields.
#[derive(Debug)]
pub enum CallWireEvent {
    /// We are in the room; `peers` counts members including us. `media` is the relay's
    /// media protocol level: 1 = voice-only frame cap (legacy relay), 2 = video-size
    /// frames allowed. Video/screen tracks are enabled only when the relay says 2.
    Joined { peers: u8, media: u8 },
    /// The other party arrived — start streaming.
    PeerJoined,
    /// The other party left/hung up.
    PeerLeft,
    /// An opaque media frame from the peer (still sealed).
    Frame(Vec<u8>),
    /// Socket closed.
    Closed,
}

/// One leg of a call room, over either transport. QUIC is preferred (no TCP
/// head-of-line blocking: lost voice frames become silence, not stalls; each video
/// frame rides its own short reliable stream); WebSocket is the always-works fallback
/// for old relays and UDP-hostile networks. Same blind room, same E2E media.
pub struct CallMedia {
    inner: MediaTransport,
}

enum MediaTransport {
    // Boxed: the tungstenite stream is ~3x the QUIC handle, and there is exactly one
    // CallMedia per call — indirection is free here and keeps the enum lean.
    Ws(Box<crate::WsStream>),
    Quic(crate::quicmedia::QuicMedia),
}

/// The relay's QUIC discovery document (`GET /v1/call/quic`).
#[derive(serde::Deserialize)]
struct QuicInfoResp {
    enabled: bool,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    cert_sha256: String,
}

impl Client {
    /// The relay-room URL for a call id (same host as the delivery socket).
    pub fn call_ws_url(&self, call_id: &str) -> String {
        let base = self.ws_url.trim_end_matches("/v1/ws");
        format!("{base}/v1/call/{call_id}")
    }

    /// Join a call room. No identity is presented — the random id is the capability.
    /// Tries the QUIC media path first (lower latency on lossy links) and falls back
    /// to WebSocket silently; the choice is invisible to the engine and the peer (the
    /// relay bridges transports).
    pub async fn join_call(&self, call_id: &str) -> Result<CallMedia> {
        if let Some(quic) = self.try_join_call_quic(call_id).await {
            return Ok(CallMedia {
                inner: MediaTransport::Quic(quic),
            });
        }
        self.join_call_ws(call_id).await
    }

    /// Join over WebSocket explicitly (fallback path; also useful in tests).
    pub async fn join_call_ws(&self, call_id: &str) -> Result<CallMedia> {
        let ws = self
            .ws_connect(self.ws_request(&self.call_ws_url(call_id))?)
            .await
            .map_err(|e| ClientError::Ws(e.to_string()))?;
        Ok(CallMedia {
            inner: MediaTransport::Ws(Box::new(ws)),
        })
    }

    /// Best-effort QUIC attempt: discovery + connect + join, all inside one short
    /// timeout. Any failure (endpoint disabled, old relay, UDP blocked, bad pin)
    /// returns `None` and costs the call nothing but the timeout.
    async fn try_join_call_quic(&self, call_id: &str) -> Option<crate::quicmedia::QuicMedia> {
        // SOCKS proxy set: QUIC is UDP, which neither SOCKS5-over-TCP nor Tor carries —
        // a direct connect would bypass the proxy and leak the real IP it is hiding.
        // Skip straight to the relay-bridged WebSocket media path (proxied).
        if self.proxy_active() {
            return None;
        }
        tokio::time::timeout(crate::quicmedia::CONNECT_TIMEOUT, async {
            let info: QuicInfoResp = self
                .http
                .get(format!("{}/v1/call/quic", self.base_url))
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            if !info.enabled || info.port == 0 {
                return None;
            }
            use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
            let hash: [u8; 32] = STANDARD_NO_PAD
                .decode(&info.cert_sha256)
                .ok()?
                .try_into()
                .ok()?;
            let host = reqwest::Url::parse(&self.base_url)
                .ok()?
                .host_str()?
                .to_string();
            let addr = tokio::net::lookup_host((host.as_str(), info.port))
                .await
                .ok()?
                .next()?;
            crate::quicmedia::QuicMedia::connect(
                addr,
                &host,
                hash,
                call_id,
                self.access_token.as_deref(),
            )
            .await
            .ok()
        })
        .await
        .ok()
        .flatten()
    }
}

impl CallMedia {
    /// Which transport this leg runs on (`"quic"` or `"ws"`), for status/UI/tests.
    pub fn transport(&self) -> &'static str {
        match &self.inner {
            MediaTransport::Ws(_) => "ws",
            MediaTransport::Quic(_) => "quic",
        }
    }

    /// Send one loss-tolerant wire frame (voice, screen audio). Over QUIC this is an
    /// unreliable datagram — a dropped frame plays as 20 ms of silence and never
    /// stalls the stream. `Err` means the connection itself is gone.
    pub async fn send_lossy(&mut self, wire: Vec<u8>) -> Result<()> {
        match &mut self.inner {
            MediaTransport::Ws(ws) => ws
                .send(WsMessage::Binary(wire))
                .await
                .map_err(|e| ClientError::Ws(e.to_string())),
            MediaTransport::Quic(q) => q.send_lossy(wire),
        }
    }

    /// Send a group of cells that must arrive intact and together (one encoded video
    /// frame's fragments, or a control cell). Over QUIC the group gets its own short
    /// reliable stream, so a retransmit delays only this frame.
    pub async fn send_cells(&mut self, cells: Vec<Vec<u8>>) -> Result<()> {
        match &mut self.inner {
            MediaTransport::Ws(ws) => {
                for cell in cells {
                    ws.send(WsMessage::Binary(cell))
                        .await
                        .map_err(|e| ClientError::Ws(e.to_string()))?;
                }
                Ok(())
            }
            MediaTransport::Quic(q) => q.send_cells(cells).await,
        }
    }

    /// Await the next room event. Cancel-safe (a dropped future loses nothing).
    pub async fn next_event(&mut self) -> Result<CallWireEvent> {
        match &mut self.inner {
            MediaTransport::Quic(q) => Ok(q.next_event().await),
            MediaTransport::Ws(ws) => {
                while let Some(frame) = ws.next().await {
                    match frame.map_err(|e| ClientError::Ws(e.to_string()))? {
                        WsMessage::Binary(b) => return Ok(CallWireEvent::Frame(b.to_vec())),
                        WsMessage::Text(t) => {
                            let v: serde_json::Value = match serde_json::from_str(t.as_str()) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            match v["type"].as_str() {
                                Some("joined") => {
                                    return Ok(CallWireEvent::Joined {
                                        peers: v["peers"].as_u64().unwrap_or(1) as u8,
                                        media: v["media"].as_u64().unwrap_or(1) as u8,
                                    })
                                }
                                Some("peer_joined") => return Ok(CallWireEvent::PeerJoined),
                                Some("peer_left") => return Ok(CallWireEvent::PeerLeft),
                                _ => continue,
                            }
                        }
                        WsMessage::Ping(p) => {
                            let _ = ws.send(WsMessage::Pong(p)).await;
                        }
                        WsMessage::Close(_) => return Ok(CallWireEvent::Closed),
                        _ => continue,
                    }
                }
                Ok(CallWireEvent::Closed)
            }
        }
    }

    pub async fn close(self) {
        match self.inner {
            MediaTransport::Ws(mut ws) => {
                // Fully qualified: on Box<WsStream>, plain `.close(None)` resolves to
                // tungstenite's inherent close on some targets and to SinkExt::close
                // (zero-arg) on others (seen: x86_64 vs aarch64-android) — the latter
                // is a compile error. Pin the inherent method explicitly.
                let _ = tokio_tungstenite::WebSocketStream::close(&mut ws, None).await;
            }
            MediaTransport::Quic(q) => q.close(),
        }
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
        assert_ne!(CallTicket::mint().call_id, t.call_id);
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
