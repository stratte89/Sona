//! Call-relay integration: real server, real WebSockets. The relay must pair exactly
//! two anonymous members per room, forward opaque binary frames both ways, notify on
//! join/leave, refuse third members and oversized frames, and store nothing.

use futures_util::{SinkExt, StreamExt};
use server::{app, AppState};
use tokio_tungstenite::tungstenite::Message as Ws;

async fn spawn_relay() -> String {
    let state = AppState::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state).into_make_service())
            .await
            .unwrap();
    });
    format!("ws://{addr}")
}

type Sock =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn join(base: &str, id: &str) -> Sock {
    let (ws, _) = tokio_tungstenite::connect_async(format!("{base}/v1/call/{id}"))
        .await
        .unwrap();
    ws
}

/// Next text frame (skipping pings), with a timeout so a hang fails loudly.
async fn next_text(ws: &mut Sock) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await.expect("socket open").expect("frame ok") {
                Ws::Text(t) => return t.to_string(),
                Ws::Close(_) => return "<closed>".into(),
                _ => continue,
            }
        }
    })
    .await
    .expect("timed out waiting for a text frame")
}

async fn next_binary(ws: &mut Sock) -> Vec<u8> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await.expect("socket open").expect("frame ok") {
                Ws::Binary(b) => return b.to_vec(),
                _ => continue,
            }
        }
    })
    .await
    .expect("timed out waiting for a binary frame")
}

const CALL_ID: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn two_members_pair_and_frames_flow_both_ways() {
    let base = spawn_relay().await;

    let mut a = join(&base, CALL_ID).await;
    let joined = next_text(&mut a).await;
    assert!(joined.contains(r#""peers":1"#));
    // The relay advertises its media level so clients know video-size frames are OK.
    assert!(joined.contains(r#""media":2"#));

    let mut b = join(&base, CALL_ID).await;
    assert!(next_text(&mut b).await.contains(r#""peers":2"#));
    assert!(next_text(&mut a).await.contains("peer_joined"));

    // Opaque frames cross the room in both directions, unmodified.
    a.send(Ws::Binary(vec![1u8; 200])).await.unwrap();
    assert_eq!(next_binary(&mut b).await, vec![1u8; 200]);
    b.send(Ws::Binary(vec![2u8; 64])).await.unwrap();
    assert_eq!(next_binary(&mut a).await, vec![2u8; 64]);

    // Hang up: the peer is told, then the room dissolves.
    a.close(None).await.unwrap();
    assert!(next_text(&mut b).await.contains("peer_left"));
}

#[tokio::test]
async fn third_member_is_refused_and_bad_ids_rejected() {
    let base = spawn_relay().await;
    let mut a = join(&base, CALL_ID).await;
    let _ = next_text(&mut a).await;
    let mut b = join(&base, CALL_ID).await;
    let _ = next_text(&mut b).await;
    let _ = next_text(&mut a).await; // peer_joined

    // A third socket on the same id gets no room: the server drops it without a join
    // notice, and neither legitimate member hears anything.
    let mut c = join(&base, CALL_ID).await;
    let end = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            match c.next().await {
                None | Some(Err(_)) | Some(Ok(Ws::Close(_))) => return,
                _ => continue,
            }
        }
    })
    .await;
    assert!(
        end.is_ok(),
        "third member must be disconnected, not admitted"
    );

    // Malformed ids never open a room (uppercase / short / traversal shapes).
    for bad in ["ABCDEF", "0123", "..%2f..%2fetc"] {
        if let Ok((mut ws, _)) =
            tokio_tungstenite::connect_async(format!("{base}/v1/call/{bad}")).await
        {
            let end = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    match ws.next().await {
                        None | Some(Err(_)) | Some(Ok(Ws::Close(_))) => return,
                        _ => continue,
                    }
                }
            })
            .await;
            assert!(end.is_ok(), "bad id {bad} must be dropped");
        }
    }
}

#[tokio::test]
async fn oversized_frame_drops_the_sender_not_the_peer() {
    let base = spawn_relay().await;
    let mut a = join(&base, CALL_ID).await;
    let _ = next_text(&mut a).await;
    let mut b = join(&base, CALL_ID).await;
    let _ = next_text(&mut b).await;
    let _ = next_text(&mut a).await;

    // A video-sized cell (16 KiB-ish) is fine now; far past the cap is not.
    a.send(Ws::Binary(vec![0u8; server::call::MAX_FRAME_BYTES]))
        .await
        .unwrap();
    assert_eq!(
        next_binary(&mut b).await.len(),
        server::call::MAX_FRAME_BYTES
    );
    a.send(Ws::Binary(vec![0u8; server::call::MAX_FRAME_BYTES + 1]))
        .await
        .unwrap();
    // The peer observes the leave (the room dissolves with it).
    assert!(next_text(&mut b).await.contains("peer_left"));
}

#[tokio::test]
async fn bulk_transfer_blows_the_rate_budget() {
    let base = spawn_relay().await;
    let mut a = join(&base, CALL_ID).await;
    let _ = next_text(&mut a).await;
    let mut b = join(&base, CALL_ID).await;
    let _ = next_text(&mut b).await;
    let _ = next_text(&mut a).await;

    // Slam max-size frames with no pacing until the relay cuts us off: the burst
    // allowance (4 MiB) runs out and the sender is dropped — it is a call relay, not a
    // file pipe. A fixed frame count would be racy on slow runners (the bucket refills
    // at RATE_BYTES_PER_SEC while we send), so we rely on loopback throughput being
    // far above the refill rate and bound the attempt by wall clock instead.
    let frame = vec![0u8; server::call::MAX_FRAME_BYTES];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if a.send(Ws::Binary(frame.clone())).await.is_err() {
            break; // server closed us — that's the point
        }
    }
    assert!(next_text(&mut b).await.contains("peer_left"));
}

/// SP-08: the relay used to accept the tungstenite defaults — a 64 MiB message and a
/// 16 MiB frame — and every relay-side check (`MAX_FRAME_BYTES`, the ack JSON parse) ran
/// only *after* the whole message had been assembled. So any client could force a 64 MiB
/// allocation per socket, repeatedly, before anything looked at it. Both upgrades now cap
/// at the protocol's real maximum, which the transport enforces before buffering.
#[tokio::test]
async fn an_oversized_frame_is_refused_by_the_transport_not_buffered() {
    let base = spawn_relay().await;

    // Call socket: the cap is the media cell size plus framing slack.
    let mut call = join(&base, &"a".repeat(32)).await;
    let over = vec![0u8; server::call::MAX_FRAME_BYTES + 64 * 1024];
    let _ = call.send(Ws::Binary(over)).await;
    let mut forwarded = false;
    while let Some(Ok(m)) = call.next().await {
        if matches!(m, Ws::Binary(_)) {
            forwarded = true;
        }
    }
    assert!(!forwarded, "an oversized media frame must never be relayed");

    // Delivery socket: carries only the Auth frame and acks, so the cap is far tighter.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{base}/v1/ws"))
        .await
        .unwrap();
    let _ = ws.send(Ws::Text("x".repeat(1024 * 1024))).await;
    let mut authed = false;
    while let Some(Ok(m)) = ws.next().await {
        if let Ws::Text(t) = m {
            authed |= t.contains("ready");
        }
    }
    assert!(
        !authed,
        "an oversized delivery frame must never authenticate"
    );
}

/// SP-08: call sockets had no concurrency cap at all — only a 60/min join limiter —
/// while a paired room lives up to 6 h, so one address could accumulate sockets (and,
/// before the size cap, a 64 MiB buffer each).
#[tokio::test]
async fn one_address_cannot_hoard_call_sockets() {
    let state = AppState::new(server::Config {
        max_call_ws_per_client: 2,
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state).into_make_service())
            .await
            .unwrap();
    });
    let base = format!("ws://{addr}");

    let _a = join(&base, &"1".repeat(32)).await;
    let _b = join(&base, &"2".repeat(32)).await;
    assert!(
        tokio_tungstenite::connect_async(format!("{base}/v1/call/{}", "3".repeat(32)))
            .await
            .is_err(),
        "over the per-address call-socket cap the upgrade must be refused"
    );
}

/// SP-17: `room_tag` runs on the **raw path parameter**, before `valid_call_id` rejects
/// it, so it sees arbitrary attacker-supplied UTF-8. A byte slice at index 8 panicked on
/// anything multibyte (`"€€€"` is 9 bytes; index 8 lands mid-character) — a remote panic
/// in exactly the mode an operator turns on to debug a live incident. Only reachable with
/// `CALL_LOG=1`, so the test sets it.
#[tokio::test]
async fn a_multibyte_call_id_does_not_panic_the_log_tag() {
    std::env::set_var("CALL_LOG", "1");
    let base = spawn_relay().await;
    // Percent-encoded "€€€" — 9 bytes, 3 characters.
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("{base}/v1/call/%E2%82%AC%E2%82%AC%E2%82%AC"))
            .await
            .expect("the upgrade itself succeeds; the id is rejected after it");
    // The malformed id is refused after the upgrade — the socket just closes, and
    // crucially the relay is still alive to serve the next join.
    while ws.next().await.is_some() {}
    std::env::remove_var("CALL_LOG");

    let mut a = join(&base, &"b".repeat(32)).await;
    let mut b = join(&base, &"b".repeat(32)).await;
    assert!(next_text(&mut a).await.contains("joined"));
    assert!(next_text(&mut b).await.contains("joined"));
}

/// SP-11: `MAX_ROOMS` was a global counter one actor could exhaust — ~2048 paired
/// sockets, held so the rooms survive the lonely reap, cost about 35 IP-minutes at 60
/// joins/min, and every call on the relay was then refused for up to `MAX_ROOM_AGE_SECS`
/// (six hours). Room creation is now charged to the creating client.
///
/// The quota must NOT apply to joining a room someone else opened: that is the second
/// leg of a real call, and refusing it for a quota the caller does not control would
/// break calls rather than protect them.
#[tokio::test]
async fn one_address_cannot_claim_the_whole_room_pool() {
    let state = AppState::new(server::Config {
        max_rooms_per_client: 2,
        // Plenty of sockets, so this test isolates the ROOM quota from the socket cap.
        max_call_ws_per_client: 64,
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state).into_make_service())
            .await
            .unwrap();
    });
    let base = format!("ws://{addr}");

    let mut a = join(&base, &"a".repeat(32)).await;
    assert!(next_text(&mut a).await.contains("joined"));
    let mut b = join(&base, &"b".repeat(32)).await;
    assert!(next_text(&mut b).await.contains("joined"));

    // The third distinct room is over this client's quota: the socket upgrades (the
    // refusal happens after it, as it does for every room refusal) and then closes
    // without ever confirming a join.
    // A post-upgrade refusal drops the socket, which surfaces as a close or a reset —
    // either way, never a `joined`.
    let mut c = join(&base, &"c".repeat(32)).await;
    let mut joined = false;
    while let Some(frame) = c.next().await {
        match frame {
            Ok(Ws::Text(t)) => joined |= t.contains("joined"),
            _ => break,
        }
    }
    assert!(!joined, "the third room must be refused");

    // But the SECOND LEG of an already-open room still joins — a real callee must never
    // be refused because the caller's address is at its quota.
    let mut a2 = join(&base, &"a".repeat(32)).await;
    assert!(
        next_text(&mut a2).await.contains("joined"),
        "joining an existing room must not consume the creation quota"
    );

    // Hanging up gives the slot back, or the quota would leak on every normal call.
    drop(a);
    drop(a2);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut d = join(&base, &"d".repeat(32)).await;
    assert!(
        next_text(&mut d).await.contains("joined"),
        "a released room must return its slot to the creator"
    );
}
