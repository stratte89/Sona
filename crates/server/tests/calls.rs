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
