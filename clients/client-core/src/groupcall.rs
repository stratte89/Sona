//! Group-call engine: a full mesh of the 1:1 call's blind relay rooms.
//!
//! Design (why a mesh and not a server mixer/SFU):
//!
//! * **Zero relay changes, zero new crypto.** Every participant pair runs one ordinary
//!   two-member blind room ([`crate::call`]) with its own random id + key, minted by the
//!   pair's *owner* (the lexicographically smaller identity key — see
//!   `ChatPayload::GroupCallOffer`) and carried only inside that pair's Double Ratchet
//!   session. Each leg therefore inherits the 1:1 call's security wholesale: E2E
//!   XChaCha20-Poly1305 under per-direction HKDF keys, strictly-increasing AEAD-bound
//!   sequence numbers, constant-size CBR frames at constant cadence, and a relay that
//!   never learns identities. An N-member relay room would have needed sender-tagged
//!   frames, per-sender key distribution, and fan-out logic on the server — all new
//!   attack surface; the mesh needs none of it.
//! * **Latency: one relay hop**, identical to a 1:1 call. Audio is encoded **once** per
//!   20 ms tick and sealed per leg (an XChaCha seal is ~µs; the Opus encode dominates).
//! * **Cost is client upload**: N-1 constant-rate voice streams (~112 kb/s each with
//!   padding). Fine for voice at the group sizes Sona targets; this is why group calls
//!   are voice-only (video mesh would multiply megabit streams — if group video ever
//!   lands it needs an SFU design, not this module).
//! * **Membership changes are free.** A joiner mints/receives fresh pair tickets; a
//!   leaver's legs simply die. No shared group key to rotate, so there is nothing a
//!   removed member can keep decrypting.
//!
//! Mixing: each leg gets its own Opus decoder and a short jitter queue; every tick the
//! engine pops at most one frame per leg, sums into i32, saturates to i16, and plays out.
//! A leg with an empty queue contributes silence for that tick (same as 1:1 packet loss).

use std::collections::HashMap;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::call::{
    codec, AudioIo, CallKeys, CallMedia, CallWireEvent, OPUS_BITRATE, PADDED_PLAINTEXT,
    SAMPLES_PER_FRAME, SAMPLE_RATE,
};
use crate::{ClientError, Result};

/// Max buffered playout frames per leg (60 ms): enough to ride out scheduling jitter,
/// small enough that a slow leg can't build audible lag before frames are dropped.
const JITTER_FRAMES: usize = 3;

/// One pair leg handed to the engine: an already-joined room plus the pair's ticket
/// material. `caller` = we minted the ticket (we are the pair's owner) and picks the
/// HKDF direction labels, exactly as in a 1:1 call.
pub struct GroupLeg {
    /// The peer's ratchet-authenticated identity key (who this leg reaches).
    pub peer_key: String,
    pub media: CallMedia,
    pub key_b64: String,
    pub caller: bool,
}

/// Session events surfaced to the shell/UI, per peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupCallEvent {
    /// This peer's leg is up and audio is flowing both ways.
    PeerConnected { peer_key: String },
    /// This peer's leg ended (hangup, drop, or room dissolved).
    PeerLeft { peer_key: String },
    /// The engine exited (stop signal or fatal local error).
    Ended,
}

/// Per-leg engine state. The socket itself lives in a pump task; the engine owns only
/// what the tick loop needs.
struct LegState {
    peer_key: String,
    keys: CallKeys,
    decoder: codec::Decoder,
    /// Sealed-frame writer toward the pump task (unbounded: a stalled socket must never
    /// block the 20 ms capture tick for everyone else).
    out_tx: UnboundedSender<Vec<u8>>,
    /// Decoded frames awaiting playout (jitter queue, capped at [`JITTER_FRAMES`]).
    playout: std::collections::VecDeque<[i16; SAMPLES_PER_FRAME]>,
    /// The peer's socket is in the room (stream only then — same rule as 1:1).
    peer_here: bool,
    connected_reported: bool,
}

/// Drive one leg's socket: forward sealed frames out, room events in. Owns the
/// `CallMedia`; exits (and closes the socket) when the engine drops the leg or the
/// room dies.
fn spawn_leg_pump(
    mut media: CallMedia,
    leg_id: u64,
    in_tx: UnboundedSender<(u64, CallWireEvent)>,
    mut out_rx: UnboundedReceiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                out = out_rx.recv() => match out {
                    Some(wire) => {
                        if media.send_lossy(wire).await.is_err() {
                            let _ = in_tx.send((leg_id, CallWireEvent::Closed));
                            break;
                        }
                    }
                    None => break, // engine dropped the leg
                },
                ev = media.next_event() => {
                    let ev = ev.unwrap_or(CallWireEvent::Closed);
                    let done = matches!(ev, CallWireEvent::Closed | CallWireEvent::PeerLeft);
                    if in_tx.send((leg_id, ev)).is_err() || done {
                        break;
                    }
                }
            }
        }
        media.close().await;
    });
}

/// Run a group call until hangup: encode local audio once per tick, seal + send per
/// leg, decode + mix inbound legs. Legs arrive dynamically on `legs_rx` (people join
/// mid-call); the channel closing does **not** end the call — only `stop` (local
/// hangup / lock) does, because a participant may sit alone waiting for others.
pub async fn run_group_call(
    mut legs_rx: UnboundedReceiver<GroupLeg>,
    mut audio: impl AudioIo,
    mut stop: tokio::sync::watch::Receiver<bool>,
    muted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    events: UnboundedSender<GroupCallEvent>,
) -> Result<()> {
    let mut enc =
        codec::Encoder::voip_mono_cbr(SAMPLE_RATE, OPUS_BITRATE).map_err(ClientError::Crypto)?;

    let (in_tx, mut in_rx) = unbounded_channel::<(u64, CallWireEvent)>();
    let mut legs: HashMap<u64, LegState> = HashMap::new();
    let mut next_leg_id: u64 = 0;
    let mut legs_open = true;

    let mut capture = [0i16; SAMPLES_PER_FRAME];
    let mut opus_buf = [0u8; PADDED_PLAINTEXT];
    let mut playout = [0i16; SAMPLES_PER_FRAME];
    let mut decode_buf = [0i16; SAMPLES_PER_FRAME];

    let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = stop.changed() => break,

            leg = legs_rx.recv(), if legs_open => match leg {
                Some(leg) => {
                    let keys = CallKeys::derive(&leg.key_b64, leg.caller)?;
                    let decoder = codec::Decoder::mono(SAMPLE_RATE).map_err(ClientError::Crypto)?;
                    let (out_tx, out_rx) = unbounded_channel();
                    let id = next_leg_id;
                    next_leg_id += 1;
                    spawn_leg_pump(leg.media, id, in_tx.clone(), out_rx);
                    legs.insert(id, LegState {
                        peer_key: leg.peer_key,
                        keys,
                        decoder,
                        out_tx,
                        playout: std::collections::VecDeque::new(),
                        peer_here: false,
                        connected_reported: false,
                    });
                }
                None => legs_open = false, // shell dropped the sender; call runs on
            },

            Some((id, ev)) = in_rx.recv() => {
                let Some(leg) = legs.get_mut(&id) else { continue };
                match ev {
                    CallWireEvent::Joined { peers, .. } => leg.peer_here = peers >= 2,
                    CallWireEvent::PeerJoined => leg.peer_here = true,
                    CallWireEvent::Frame(wire) => {
                        // Bad frames are dropped, never fatal: the relay is untrusted
                        // and must not be able to kill a call by injecting garbage.
                        if let Ok(opus_bytes) = leg.keys.open_frame(&wire) {
                            if leg.decoder.decode(&opus_bytes, &mut decode_buf).is_ok() {
                                if !leg.connected_reported {
                                    leg.connected_reported = true;
                                    let _ = events.send(GroupCallEvent::PeerConnected {
                                        peer_key: leg.peer_key.clone(),
                                    });
                                }
                                if leg.playout.len() >= JITTER_FRAMES {
                                    leg.playout.pop_front();
                                }
                                leg.playout.push_back(decode_buf);
                            }
                        }
                    }
                    CallWireEvent::PeerLeft | CallWireEvent::Closed => {
                        let leg = legs.remove(&id).expect("checked above");
                        let _ = events.send(GroupCallEvent::PeerLeft { peer_key: leg.peer_key });
                    }
                }
            }

            _ = tick.tick() => {
                // ── Capture → encode once → seal per live leg. ──
                if legs.values().any(|l| l.peer_here) {
                    if muted.load(std::sync::atomic::Ordering::Relaxed)
                        || !audio.read_frame(&mut capture)
                    {
                        capture = [0i16; SAMPLES_PER_FRAME];
                    }
                    let n = enc.encode(&capture, &mut opus_buf).map_err(ClientError::Crypto)?;
                    for leg in legs.values_mut().filter(|l| l.peer_here) {
                        // Sealing is per-leg (own key, own sequence); a failed send just
                        // means the pump died — its Closed event will reap the leg.
                        let _ = leg.out_tx.send(leg.keys.seal_frame(&opus_buf[..n])?);
                    }
                }
                // ── Mix one playout frame per leg with buffered audio. ──
                let mut mix = [0i32; SAMPLES_PER_FRAME];
                let mut any = false;
                for leg in legs.values_mut() {
                    if let Some(frame) = leg.playout.pop_front() {
                        any = true;
                        for (m, s) in mix.iter_mut().zip(frame.iter()) {
                            *m += *s as i32;
                        }
                    }
                }
                if any {
                    for (out, m) in playout.iter_mut().zip(mix.iter()) {
                        *out = (*m).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                    }
                    audio.write_frame(&playout);
                }
            }
        }
    }

    // Dropping the leg states closes every out_tx; each pump task exits and closes its
    // socket. Keys zeroize on drop (CallKeys).
    drop(legs);
    let _ = events.send(GroupCallEvent::Ended);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::CallTicket;

    /// Mixing math: sum + saturate, silence for empty queues.
    #[test]
    fn mix_sums_and_saturates() {
        let a = [i16::MAX; 4];
        let b = [1000i16; 4];
        let mut mix = [0i32; 4];
        for s in [&a[..], &b[..]] {
            for (m, v) in mix.iter_mut().zip(s.iter()) {
                *m += *v as i32;
            }
        }
        let out: Vec<i16> = mix
            .iter()
            .map(|m| (*m).clamp(i16::MIN as i32, i16::MAX as i32) as i16)
            .collect();
        assert_eq!(out, vec![i16::MAX; 4]); // saturated, no wraparound
    }

    /// Every pair leg is keyed independently: a frame sealed for one leg neither opens
    /// on another leg nor replays on its own leg.
    #[test]
    fn legs_are_cryptographically_independent() {
        let t_ab = CallTicket::mint();
        let t_ac = CallTicket::mint();
        // A is the owner (caller=true) on both of its legs.
        let mut a_to_b = CallKeys::derive(&t_ab.key_b64, true).unwrap();
        let mut b_from_a = CallKeys::derive(&t_ab.key_b64, false).unwrap();
        let mut c_from_a = CallKeys::derive(&t_ac.key_b64, false).unwrap();

        let wire = a_to_b.seal_frame(&[9u8; 40]).unwrap();
        // C cannot open B's leg even though both frames carry A's voice.
        assert!(c_from_a.open_frame(&wire).is_err());
        // B opens it once; a relayed replay is rejected.
        assert_eq!(b_from_a.open_frame(&wire).unwrap(), vec![9u8; 40]);
        assert!(b_from_a.open_frame(&wire).is_err());
    }

    /// The wire format on a group leg is byte-compatible with a 1:1 voice call
    /// (constant size, lossy-classified) — the relay cannot tell them apart.
    #[test]
    fn group_leg_frames_look_like_v1_voice() {
        let t = CallTicket::mint();
        let mut k = CallKeys::derive(&t.key_b64, true).unwrap();
        let wire = k.seal_frame(&[5u8; 60]).unwrap();
        assert_eq!(wire.len(), crate::call::WIRE_FRAME);
        assert!(protocol_types::quicwire::lossy_ok(&wire));
    }
}
