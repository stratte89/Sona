//! QUIC media path for the blind call relay — same rooms, same privacy, lower latency.
//!
//! WebSocket media rides TCP: one lost packet stalls everything behind it (head-of-line
//! blocking), which is exactly what a live call cannot afford on a lossy link. This
//! module adds a QUIC endpoint speaking a minimal mapping:
//!
//! * **Room control** — the client opens one bidirectional stream and writes the 32-hex
//!   call id; the server answers with the same JSON lines the WebSocket path uses
//!   (`joined` / `peer_joined` / `peer_left`), reliably, for the life of the call.
//!   Closing the connection is leaving the room.
//! * **Loss-tolerant media** (voice frames, screen-audio cells — first wire byte 0/3)
//!   — QUIC **datagrams**: unreliable, unordered, never retransmitted. A lost frame is
//!   20 ms of silence, not a stall.
//! * **Loss-intolerant media** (video cells, control cells) — one short
//!   **unidirectional stream per group** (one encoded video frame's fragments travel
//!   together), each cell length-prefixed (`u16 BE || cell`). Reliable *within* the
//!   frame, independent *between* frames: a retransmit delays only its own frame.
//!
//! TLS: QUIC requires it, but self-hosters shouldn't have to plumb certificates into
//! the relay — so the endpoint mints a **self-signed certificate at boot** and the
//! HTTP API (`GET /v1/call/quic`) advertises `{port, cert_sha256}`. Clients fetch that
//! over the HTTPS channel they already trust and pin the exact certificate. The QUIC
//! TLS layer is transport armor only; media is end-to-end encrypted above it and the
//! relay remains blind either way.
//!
//! Privacy is unchanged from the WebSocket path: join by capability id only, no
//! identities, nothing stored, same per-connection byte budget. Rooms are shared, so
//! a WS caller and a QUIC callee interoperate — the relay bridges the framings.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use sha2::{Digest, Sha256};

use crate::call::{
    join_room, leave_room, lossy_ok, peer_of, Member, MemberTx, RateBudget, MAX_FRAME_BYTES,
};
use crate::state::AppState;

// Wire constants + cell framing are shared with the clients via `protocol-types`
// (the relay bridges WS and QUIC members, so all three must agree byte-for-byte).
pub use protocol_types::quicwire::{frame_cells, parse_cells, ALPN, MAX_STREAM_GROUP_BYTES};

/// A client that opens a connection must present its call id promptly.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// What the HTTP discovery endpoint advertises.
#[derive(Clone)]
pub struct QuicInfo {
    pub port: u16,
    /// Base64 (no pad) SHA-256 of the DER certificate — the client's pin.
    pub cert_sha256_b64: String,
}

/// The QUIC leg of one room member, as seen by the forwarding code in `call.rs`.
/// Media goes straight onto the connection; control lines go through the writer task
/// that owns the control stream.
#[derive(Clone)]
pub struct QuicMemberTx {
    conn: quinn::Connection,
    ctrl: tokio::sync::mpsc::UnboundedSender<String>,
}

impl QuicMemberTx {
    pub fn closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    pub fn send_text(&self, s: &str) {
        let _ = self.ctrl.send(s.to_string());
    }

    /// Lossy media: fire-and-forget. Errors (path MTU, closed) drop the frame — that
    /// is the datagram contract.
    pub fn send_datagram(&self, frame: Vec<u8>) {
        let _ = self.conn.send_datagram(frame.into());
    }

    /// Reliable media: one short unidirectional stream carrying pre-framed cells.
    pub fn send_cells_stream(&self, framed: Vec<u8>) {
        let conn = self.conn.clone();
        tokio::spawn(async move {
            if let Ok(mut s) = conn.open_uni().await {
                let _ = s.write_all(&framed).await;
                let _ = s.finish();
            }
        });
    }

    /// The peer hung up and the room dissolved. The `peer_left` control line may still
    /// be sitting unflushed in the writer when the connection closes, so the close
    /// *reason* carries the same meaning — CONNECTION_CLOSE delivers it atomically and
    /// the client maps it back to a peer-left event.
    pub fn close(&self) {
        self.conn.close(0u32.into(), b"peer_left");
    }
}

/// Start the QUIC media endpoint on `port`. Returns the discovery info; the accept
/// loop runs until the endpoint is dropped (process lifetime).
pub fn start(state: AppState, port: u16) -> Result<QuicInfo, String> {
    // Fresh self-signed certificate every boot. Clients pin the hash they fetch from
    // the HTTP API per call, so rotation costs nothing and there is no key to manage.
    // The SAN is random: a fixed name (this used to be "sona-relay") let any UDP prober
    // fingerprint the host as a Sona relay from the handshake alone. Clients verify by
    // pinned hash, never by name, so the name is free to be meaningless.
    let san = {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        hex::encode(b)
    };
    let cert = rcgen::generate_simple_self_signed(vec![san]).map_err(|e| format!("cert: {e}"))?;
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_sha256_b64 = {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        STANDARD_NO_PAD.encode(Sha256::digest(cert_der.as_ref()))
    };

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|e| format!("tls: {e}"))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).map_err(|e| format!("quic tls: {e}"))?,
    ));
    let mut transport = quinn::TransportConfig::default();
    // Calls are latency-critical and low-throughput; keep the connection alive through
    // NATs and notice dead peers quickly (leave semantics depend on it).
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("idle")));
    // One control stream from the client plus per-frame media streams.
    transport.max_concurrent_uni_streams(64u32.into());
    transport.max_concurrent_bidi_streams(4u32.into());
    server_cfg.transport_config(Arc::new(transport));

    let endpoint =
        quinn::Endpoint::server(server_cfg, std::net::SocketAddr::from(([0, 0, 0, 0], port)))
            .map_err(|e| format!("bind udp {port}: {e}"))?;
    let bound_port = endpoint
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))?
        .port();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    handle_connection(conn, state).await;
                }
            });
        }
    });

    Ok(QuicInfo {
        port: bound_port,
        cert_sha256_b64,
    })
}

/// Drive one member's QUIC connection: control-stream join, then forward datagrams and
/// stream groups to the room peer until the connection dies.
async fn handle_connection(conn: quinn::Connection, state: AppState) {
    // ── Perimeter first (SP-14). `access::check` does both the IP allowlist and the
    //    token, but it only runs as axum middleware, which the UDP endpoint never
    //    traverses — so `ACCESS_MODE=open` + `IP_ALLOWLIST=…` (the documented "only these
    //    addresses may use the relay" posture) left this port answering anyone, who could
    //    then fingerprint the relay by ALPN and create rooms up to MAX_ROOMS. Checked
    //    before any read so an off-allowlist peer costs nothing.
    //
    //    QUIC is published straight to clients, so the socket peer address IS the client:
    //    use `remote_address()`, never the proxy header the HTTP path trusts. Enforced
    //    unconditionally — the HTTP path's dev bypass exists only because a missing proxy
    //    header is ambiguous, and here there is always a real address.
    if !crate::access::ip_allowed(&state.config, conn.remote_address().ip()) {
        conn.close(5u32.into(), b"address not allowed");
        return;
    }
    // ── Join: the client's first bidi stream carries the 32-hex call id. ──
    let Ok(Ok((ctrl_send, mut ctrl_recv))) =
        tokio::time::timeout(JOIN_TIMEOUT, conn.accept_bi()).await
    else {
        conn.close(1u32.into(), b"no join");
        return;
    };
    let mut id_buf = [0u8; 32];
    if tokio::time::timeout(JOIN_TIMEOUT, ctrl_recv.read_exact(&mut id_buf))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        conn.close(1u32.into(), b"no join");
        return;
    }
    let Ok(call_id) = std::str::from_utf8(&id_buf).map(str::to_string) else {
        conn.close(1u32.into(), b"bad id");
        return;
    };
    if !crate::call::valid_call_id(&call_id) {
        conn.close(1u32.into(), b"bad id");
        return;
    }

    // Token mode: the join must also carry the shared access token (newline-terminated,
    // right after the 32-byte id). Without this, the QUIC port was the one hole in the
    // token perimeter — joinable by anyone holding a call id, and fingerprintable by
    // ALPN. Open mode reads nothing extra, so pre-token clients stay compatible; a
    // token-carrying client against an open relay leaves bytes unread, which is
    // harmless (the server never reads the control stream after the join).
    // (Stealth never gets here — it forces the QUIC endpoint off entirely.)
    if state.config.access_mode == crate::access::AccessMode::Token {
        let token_line = tokio::time::timeout(JOIN_TIMEOUT, async {
            let mut line: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 64];
            loop {
                match ctrl_recv.read(&mut chunk).await {
                    Ok(Some(n)) => {
                        line.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = line.iter().position(|&b| b == b'\n') {
                            line.truncate(pos);
                            return Some(line);
                        }
                        if line.len() > 512 {
                            return None; // no sane token is this long
                        }
                    }
                    _ => return None,
                }
            }
        })
        .await
        .ok()
        .flatten();
        let ok = token_line
            .and_then(|l| String::from_utf8(l).ok())
            .map(|t| crate::access::token_digest(t.trim()))
            .is_some_and(|d| state.config.access_token_hashes.contains(&d));
        if !ok {
            conn.close(4u32.into(), b"unauthorized");
            return;
        }
    }

    // Per-client join rate limit, mirroring the WebSocket `call_upgrade` path (M-4). The
    // WS leg keys on the proxy's `X-Real-IP`; QUIC is published straight to the client, so
    // the socket peer address *is* the client — pseudonymize it under the same salt and
    // charge the same `call:` bucket so neither transport is an un-throttled way in.
    let peer_key = crate::auth::pseudonymize(
        &conn.remote_address().ip().to_string(),
        &state.config.rate_salt,
    );
    {
        let key = format!("call:{peer_key}");
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&key, crate::state::now()) {
            conn.close(3u32.into(), b"rate limited");
            return;
        }
    }

    // Control-line writer: owns the send half of the control stream.
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut ctrl_send = ctrl_send;
        while let Some(line) = ctrl_rx.recv().await {
            let framed = format!("{line}\n");
            if ctrl_send.write_all(framed.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let member = Member::new(MemberTx::Quic(QuicMemberTx {
        conn: conn.clone(),
        ctrl: ctrl_tx,
    }));
    let Some(my_id) = join_room(&state, &call_id, member, &peer_key) else {
        conn.close(2u32.into(), b"room full");
        writer.abort();
        return;
    };

    // ── Media pumps: datagrams (lossy) + uni streams (reliable groups). ──
    //
    // Two independent tasks, not two arms of one `select!`, and that is the whole point.
    // Draining a video frame's stream means awaiting the *rest of its bytes*, which on a
    // congested or lossy uplink is a retransmit away — tens to hundreds of milliseconds.
    // Sharing a task with `read_datagram` made that wait a wait for voice too: the
    // sender's audio sat in the kernel while the relay was parked mid-video-frame, so a
    // screen share made both directions of the call break up. Voice is loss-tolerant and
    // never waits for anything; video is reliable and may. They must not share a task.
    //
    // The stream loop stays sequential, so frames are forwarded in the order they were
    // sent (a decoder handed frames out of order loses its reference chain — worse than a
    // late frame). The byte budget is shared, since it is a property of the connection.
    let budget = Arc::new(std::sync::Mutex::new(RateBudget::default()));
    let spend = {
        let budget = budget.clone();
        move |n: usize| budget.lock().map(|mut b| b.spend(n)).unwrap_or(false)
    };

    let mut datagrams = {
        let (conn, state, call_id, spend) =
            (conn.clone(), state.clone(), call_id.clone(), spend.clone());
        tokio::spawn(async move {
            loop {
                let Ok(b) = conn.read_datagram().await else {
                    break;
                }; // closed/lost
                if b.len() > MAX_FRAME_BYTES || !spend(b.len()) {
                    break; // protocol violation / bulk abuse
                }
                // Only loss-tolerant frames belong in datagrams; anything else is a
                // protocol violation (a client bug or a probe), not worth forwarding.
                if !lossy_ok(&b) {
                    break;
                }
                if let Some(peer) = peer_of(&state, &call_id, my_id) {
                    peer.forward_frame(b.to_vec());
                }
            }
        })
    };

    let mut streams = {
        let (conn, state, call_id) = (conn.clone(), state.clone(), call_id.clone());
        tokio::spawn(async move {
            loop {
                let Ok(mut s) = conn.accept_uni().await else {
                    break;
                };
                let Ok(group) = s.read_to_end(MAX_STREAM_GROUP_BYTES).await else {
                    break; // oversized group — protocol violation
                };
                if !spend(group.len()) {
                    break;
                }
                let Some(cells) = parse_cells(&group) else {
                    continue; // malformed framing — drop the group, keep the call
                };
                if cells.iter().any(|c| c.len() > MAX_FRAME_BYTES) {
                    break;
                }
                if let Some(peer) = peer_of(&state, &call_id, my_id) {
                    peer.forward_cells(cells);
                }
            }
        })
    };

    // Either pump ending means this member is done (connection gone, or it broke the
    // protocol on one of the two paths) — the room must not keep a half-live member, and
    // the surviving pump must not outlive the room entry it forwards into.
    tokio::select! {
        _ = &mut datagrams => {}
        _ = &mut streams => {}
    }
    datagrams.abort();
    streams.abort();

    writer.abort();
    leave_room(&state, &call_id, my_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_framing_round_trips_and_rejects_garbage() {
        let cells = vec![vec![1u8; 10], vec![2u8; 1049], vec![3u8; 1]];
        let framed = frame_cells(&cells);
        assert_eq!(parse_cells(&framed).unwrap(), cells);

        // Truncated, zero-length, oversized, empty: all refused.
        assert!(parse_cells(&framed[..framed.len() - 1]).is_none());
        assert!(parse_cells(&[0, 0]).is_none());
        let mut huge = ((MAX_FRAME_BYTES + 1) as u16).to_be_bytes().to_vec();
        huge.extend(vec![0u8; MAX_FRAME_BYTES + 1]);
        assert!(parse_cells(&huge).is_none());
        assert!(parse_cells(&[]).is_none());
    }

    #[test]
    fn lossy_policy_matches_tracks() {
        assert!(lossy_ok(&[0u8; 280])); // v1 voice
        assert!(lossy_ok(&[3u8; 281])); // screen audio
        assert!(!lossy_ok(&[1u8; 100])); // camera video
        assert!(!lossy_ok(&[2u8; 100])); // screen video
        assert!(!lossy_ok(&[15u8; 100])); // control
        assert!(!lossy_ok(&[]));
    }
}
