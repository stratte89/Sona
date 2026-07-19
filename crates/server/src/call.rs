//! Blind call relay: pairs two WebSockets by a random room id and forwards opaque
//! binary frames between them. This is the media path for voice calls.
//!
//! What the server can and cannot see, by construction:
//!
//! * **No identities.** Joining takes only the 128-bit random `call_id` — a capability
//!   token that travels exclusively inside the two parties' Double-Ratchet session
//!   (`CallOffer`). The relay never learns *who* is in a call, and cannot join a call to
//!   the mailboxes involved. (An authenticated join would tie both identity hashes to
//!   one room — strictly worse metadata.)
//! * **No content.** Frames are XChaCha20-Poly1305 ciphertext under a per-call key the
//!   server never sees; a man-in-the-middle relay can drop frames but not read or forge
//!   them (the AEAD covers a strictly-increasing sequence number).
//! * **No patterns.** Voice frames are constant-size at a constant cadence (CBR Opus
//!   plus padding, silence included), so timing/size analysis yields "a call is
//!   happening" and nothing else — which the relay necessarily knows anyway. Video and
//!   screen-share cells (media v2) are padded to a 1 KiB grid by the clients but are
//!   inherently bursty; the relay additionally learns "call with video-ish bandwidth",
//!   still never content or identities.
//!
//! Abuse bounds: room ids must be 32 hex chars; at most two members; oversized frames
//! (> [`MAX_FRAME_BYTES`]) close the connection; each member gets a byte-rate budget
//! ([`RATE_BYTES_PER_SEC`]) so the blind relay cannot be repurposed as a free bulk
//! pipe; joins are rate-limited alongside the other endpoints; stale rooms are
//! garbage-collected lazily on join.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use crate::state::{now, AppState};

/// Hard cap per media frame: the largest media-v2 wire cell,
/// `track(1) || seq(8) || ciphertext(16 KiB plaintext + 16 tag)` (see the client's
/// `media` module — the two constants must agree). Anything bigger is a protocol
/// violation, not a codec setting.
pub const MAX_FRAME_BYTES: usize = 1 + 8 + 16 * 1024 + 16;
/// Media protocol level advertised in the `joined` message. Clients enable video-size
/// frames only when the relay says `media >= 2` (an old relay would close on them).
pub const MEDIA_LEVEL: u8 = 2;
/// Sustained per-member byte-rate budget (token bucket): 1 MiB/s comfortably covers
/// voice + camera + screen + screen audio (~0.3 MiB/s) while capping bulk abuse.
pub const RATE_BYTES_PER_SEC: u64 = 1024 * 1024;
/// Token-bucket burst allowance (keyframes + fragmented cells arrive in clumps).
pub const RATE_BURST_BYTES: u64 = 4 * 1024 * 1024;
/// A room with one member older than this is a call nobody answered — reap it. Reaped by
/// age alone (see [`CallRooms::gc`]): a client that merely holds a half-open room's socket
/// open can no longer pin a slot past this window (M-4). Longer than any real ring.
const LONELY_ROOM_TTL_SECS: u64 = 120;
/// Absolute room lifetime backstop (a stuck pair of sockets can't pin memory forever).
const MAX_ROOM_AGE_SECS: u64 = 6 * 3600;
/// Default cap on total concurrent rooms; override with the `MAX_ROOMS` env var
/// (`Config::max_rooms`). Small by default, so the reaping policy matters (M-4).
pub const DEFAULT_MAX_ROOMS: usize = 1024;

// Datagram-vs-stream policy is shared with the clients (protocol-types::quicwire).
pub use protocol_types::quicwire::lossy_ok;

/// Member ids distinguish the two anonymous sockets in a room (nothing else does —
/// that's the point). Process-wide counter; ids are never reused.
static NEXT_MEMBER_ID: AtomicU64 = AtomicU64::new(1);

/// How a member's leg reaches it: the WebSocket writer queue, or a QUIC connection
/// (media goes straight on the connection; room-control lines go through the control
/// stream's writer queue).
#[derive(Clone)]
pub enum MemberTx {
    Ws(UnboundedSender<Message>),
    Quic(crate::quic::QuicMemberTx),
}

/// One anonymous room member, over either transport.
#[derive(Clone)]
pub struct Member {
    pub id: u64,
    pub tx: MemberTx,
}

impl Member {
    pub fn new(tx: MemberTx) -> Member {
        Member {
            id: NEXT_MEMBER_ID.fetch_add(1, Ordering::Relaxed),
            tx,
        }
    }

    fn closed(&self) -> bool {
        match &self.tx {
            MemberTx::Ws(tx) => tx.is_closed(),
            MemberTx::Quic(q) => q.closed(),
        }
    }

    /// Room-control notice (`joined` / `peer_joined` / `peer_left`): WS text frame or a
    /// line on the QUIC control stream. Reliable on both transports.
    pub fn send_text(&self, s: &str) {
        match &self.tx {
            MemberTx::Ws(tx) => {
                let _ = tx.send(Message::Text(s.to_string().into()));
            }
            MemberTx::Quic(q) => q.send_text(s),
        }
    }

    /// Forward one media frame that arrived as a standalone unit (WS binary or QUIC
    /// datagram). Toward QUIC, loss-tolerant frames go as datagrams and the rest get a
    /// small reliable stream.
    pub fn forward_frame(&self, frame: Vec<u8>) {
        match &self.tx {
            MemberTx::Ws(tx) => {
                let _ = tx.send(Message::Binary(frame.into()));
            }
            MemberTx::Quic(q) => {
                if lossy_ok(&frame) {
                    q.send_datagram(frame);
                } else {
                    q.send_cells_stream(crate::quic::frame_cells(&[frame]));
                }
            }
        }
    }

    /// Forward a group of cells that arrived together on one reliable QUIC stream
    /// (one encoded video frame's fragments, or a control cell). Toward WS each cell
    /// becomes its own binary frame; toward QUIC the grouping is preserved.
    pub fn forward_cells(&self, cells: Vec<Vec<u8>>) {
        match &self.tx {
            MemberTx::Ws(tx) => {
                for cell in cells {
                    let _ = tx.send(Message::Binary(cell.into()));
                }
            }
            MemberTx::Quic(q) => q.send_cells_stream(crate::quic::frame_cells(&cells)),
        }
    }

    /// Ask the transport to shut down (peer hung up and the room dissolved).
    pub fn close(&self) {
        match &self.tx {
            MemberTx::Ws(tx) => {
                let _ = tx.send(Message::Close(None));
            }
            MemberTx::Quic(q) => q.close(),
        }
    }
}

/// One live call room: up to two anonymous members.
#[derive(Default)]
pub struct CallRoom {
    pub created_at: u64,
    members: Vec<Member>,
}

/// All rooms, keyed by call id. Lives in its own mutex (media frames every 20 ms must
/// not contend with the message-store lock).
#[derive(Default)]
pub struct CallRooms {
    rooms: HashMap<String, CallRoom>,
}

impl CallRooms {
    /// GC: drop abandoned single-member rooms and anything past the age backstop. A
    /// lonely (half-open) room is reaped purely on **age** — not gated on the member
    /// socket being closed — so holding a connection open cannot pin a slot past
    /// [`LONELY_ROOM_TTL_SECS`] (M-4). Called lazily on every join and by the reaper.
    pub fn gc(&mut self, t: u64) {
        self.rooms.retain(|_, r| {
            let lonely_expired =
                r.members.len() < 2 && t.saturating_sub(r.created_at) > LONELY_ROOM_TTL_SECS;
            let too_old = t.saturating_sub(r.created_at) > MAX_ROOM_AGE_SECS;
            !(lonely_expired || too_old)
        });
    }
}

/// Join a room over either transport: enforce caps, notify the earlier member, send
/// the `joined` message to the newcomer. Returns the member id, or `None` when the
/// join is refused (relay full / room full).
pub fn join_room(state: &AppState, call_id: &str, member: Member) -> Option<u64> {
    let mut calls = state.calls.lock().unwrap();
    let t = now();
    calls.gc(t);
    if calls.rooms.len() >= state.config.max_rooms && !calls.rooms.contains_key(call_id) {
        return None; // relay full — caller retries or gives up
    }
    let room = calls
        .rooms
        .entry(call_id.to_string())
        .or_insert_with(|| CallRoom {
            created_at: t,
            members: Vec::new(),
        });
    room.members.retain(|m| !m.closed());
    if room.members.len() >= 2 {
        return None; // full: the two legitimate parties are already here
    }
    for m in &room.members {
        m.send_text(r#"{"type":"peer_joined"}"#);
    }
    let joined = format!(
        r#"{{"type":"joined","peers":{},"media":{}}}"#,
        room.members.len() + 1,
        MEDIA_LEVEL
    );
    member.send_text(&joined);
    let id = member.id;
    room.members.push(member);
    Some(id)
}

/// Find the *other* member of a room (the forward target).
pub fn peer_of(state: &AppState, call_id: &str, my_id: u64) -> Option<Member> {
    let calls = state.calls.lock().unwrap();
    calls
        .rooms
        .get(call_id)
        .and_then(|room| room.members.iter().find(|m| m.id != my_id).cloned())
}

/// Leave: dissolve the room and tell the peer (a call ends when either side hangs up
/// or drops; there is no rejoin — a new call mints a new id + key).
pub fn leave_room(state: &AppState, call_id: &str, my_id: u64) {
    let peer = {
        let mut calls = state.calls.lock().unwrap();
        let peer = calls
            .rooms
            .get(call_id)
            .and_then(|room| room.members.iter().find(|m| m.id != my_id).cloned());
        calls.rooms.remove(call_id);
        peer
    };
    if let Some(peer) = peer {
        peer.send_text(r#"{"type":"peer_left"}"#);
        peer.close();
    }
}

/// Per-connection byte-rate budget (token bucket), shared by the WS and QUIC legs.
pub struct RateBudget {
    budget: i64,
    last_refill: tokio::time::Instant,
}

impl Default for RateBudget {
    fn default() -> Self {
        RateBudget {
            budget: RATE_BURST_BYTES as i64,
            last_refill: tokio::time::Instant::now(),
        }
    }
}

impl RateBudget {
    /// Spend `n` bytes; `false` = over budget (drop the connection).
    pub fn spend(&mut self, n: usize) -> bool {
        let t = tokio::time::Instant::now();
        let refill =
            (t.duration_since(self.last_refill).as_secs_f64() * RATE_BYTES_PER_SEC as f64) as i64;
        self.last_refill = t;
        self.budget = (self.budget + refill).min(RATE_BURST_BYTES as i64) - n as i64;
        self.budget >= 0
    }
}

/// A syntactically valid call id: exactly 32 lowercase hex chars (128 bits).
pub(crate) fn valid_call_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Drive one member's WebSocket: join the room, forward its binary frames to the peer,
/// relay join/leave notices, tear down on close. (The QUIC twin lives in
/// [`crate::quic`]; both share the room/join/leave/budget logic above.)
pub async fn handle_call_socket(socket: WebSocket, state: AppState, call_id: String) {
    if !valid_call_id(&call_id) {
        return;
    }
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = unbounded_channel::<Message>();

    // ── Join ──
    let Some(my_id) = join_room(&state, &call_id, Member::new(MemberTx::Ws(tx))) else {
        return;
    };

    // ── Pump outbound (peer → this member), with a keepalive ping. ──
    let forward = tokio::spawn(async move {
        let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
        ping.tick().await;
        loop {
            tokio::select! {
                frame = rx.recv() => match frame {
                    Some(frame) => {
                        if sink.send(frame).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // ── Inbound: opaque binary frames go to the other member, nothing is stored. ──
    // Byte-rate budget: refilled continuously, spent per frame. Overspending closes
    // the connection (legitimate clients sit far below the sustained rate).
    let mut budget = RateBudget::default();
    while let Some(Ok(msg)) = stream.next().await {
        match msg {
            Message::Binary(b) => {
                if b.len() > MAX_FRAME_BYTES {
                    break; // protocol violation — drop the connection
                }
                if !budget.spend(b.len()) {
                    break; // over the media budget — this is not a bulk pipe
                }
                if let Some(peer) = peer_of(&state, &call_id, my_id) {
                    peer.forward_frame(b.to_vec());
                }
            }
            Message::Close(_) => break,
            _ => {} // text/pings from clients carry nothing here
        }
    }

    // ── Leave: notify the peer and dissolve the room. ──
    forward.abort();
    leave_room(&state, &call_id, my_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_id_validation() {
        assert!(valid_call_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_call_id("0123456789ABCDEF0123456789ABCDEF")); // uppercase
        assert!(!valid_call_id("0123456789abcdef0123456789abcde")); // short
        assert!(!valid_call_id("0123456789abcdef0123456789abcdefx")); // long
        assert!(!valid_call_id("../../../../../../etc/passwd"));
        assert!(!valid_call_id(""));
    }

    #[test]
    fn gc_reaps_lonely_and_ancient_rooms() {
        let mut rooms = CallRooms::default();
        // Lonely room with a dead channel, past TTL.
        let (tx, rx) = unbounded_channel::<Message>();
        drop(rx);
        rooms.rooms.insert(
            "a".into(),
            CallRoom {
                created_at: 0,
                members: vec![Member::new(MemberTx::Ws(tx))],
            },
        );
        // Fresh lonely room with a live channel — stays.
        let (tx2, _rx2) = unbounded_channel::<Message>();
        rooms.rooms.insert(
            "b".into(),
            CallRoom {
                created_at: LONELY_ROOM_TTL_SECS + 10,
                members: vec![Member::new(MemberTx::Ws(tx2))],
            },
        );
        rooms.gc(LONELY_ROOM_TTL_SECS + 30);
        assert!(!rooms.rooms.contains_key("a"));
        assert!(rooms.rooms.contains_key("b"));
        // Age backstop kills anything.
        rooms.gc(MAX_ROOM_AGE_SECS + LONELY_ROOM_TTL_SECS + 60);
        assert!(rooms.rooms.is_empty());
    }

    #[test]
    fn gc_reaps_a_lonely_room_by_age_even_with_a_live_socket() {
        // M-4: an attacker holding a half-open room's connection OPEN used to pin the slot
        // until the 6h backstop, because lonely reap required the socket to be closed. Now
        // it's reaped on age alone.
        let mut rooms = CallRooms::default();
        let (tx, _rx) = unbounded_channel::<Message>(); // live channel (not dropped)
        rooms.rooms.insert(
            "held".into(),
            CallRoom {
                created_at: 0,
                members: vec![Member::new(MemberTx::Ws(tx))],
            },
        );
        rooms.gc(LONELY_ROOM_TTL_SECS + 1);
        assert!(!rooms.rooms.contains_key("held"));
    }
}
