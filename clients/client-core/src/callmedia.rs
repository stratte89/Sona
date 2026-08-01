//! The call-room transport: joining a blind relay room and moving media through it.
//!
//! Split out of [`crate::call`], which owns the *cryptography and cadence* of a call —
//! keys, frame sealing, the 20 ms voice loop. This module owns the *pipe*: which
//! transport a leg negotiated, and the two very different disciplines media travels
//! under once it has one.
//!
//! That split is the point. Voice is loss-tolerant and on a hard deadline; video is
//! loss-intolerant and allowed to take its time. Keeping them apart is what
//! [`CellSender`] exists for, and having the transport in its own file makes the
//! asymmetry visible instead of buried in a thousand-line module.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::{Client, ClientError, Result};

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
    /// The relay's `joined`, consumed by the join itself and handed to the session on its
    /// first [`CallMedia::next_event`] so nothing downstream can tell the difference.
    ///
    /// The join has to *see* that message — see [`CallMedia::join_ack_timeout`] — but the
    /// media loop needs it too: its `peers` count is what tells a second joiner the peer is
    /// already in the room, and dropping it would trade one hang for another.
    pending: Option<CallWireEvent>,
}

/// How long a join waits for the relay to confirm it (`joined`) before failing.
///
/// The WebSocket upgrade completes before the relay checks anything, so a refused join — a
/// malformed room id, a room already full, a relay at capacity — arrives as a socket that
/// opens and is then silently dropped. Without this the client reported a successful join for
/// a room it had never been admitted to, started a media session, and waited for a peer the
/// relay had never paired it with. Measured 2026-08-01: the caller logged "room joined" for a
/// room the relay logged no join against at all.
const JOIN_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The write half of a WebSocket leg, shared between the voice path and the reliable
/// path. `tokio::sync::Mutex` rather than `std`: it is held across `await`s.
type WsSink = Arc<tokio::sync::Mutex<futures_util::stream::SplitSink<crate::WsStream, WsMessage>>>;

enum MediaTransport {
    /// Split, because the two halves belong to different tasks: the read half stays with
    /// the session loop, and the write half is shared with the reliable-send task through
    /// [`CellSender`].
    Ws {
        sink: WsSink,
        source: futures_util::stream::SplitStream<crate::WsStream>,
    },
    Quic(crate::quicmedia::QuicMedia),
}

/// Send-only handle for the **reliable** media path (video cells, control cells), cheap
/// to clone and safe to hand to another task.
///
/// This exists because a reliable send is allowed to take its time and a voice frame is
/// not. One encoded 1080p frame is tens of kilobytes; putting it on the wire means
/// waiting for congestion control, for a retransmit, or for a free QUIC stream — any of
/// which is tens to hundreds of milliseconds. While the session loop was doing that
/// wait inside its own `select!`, it was not capturing voice, not sending voice, and not
/// decoding the voice arriving from the peer: a screen share made the entire call — both
/// directions of speech, the share's own audio, and the video — go choppy at once. The
/// reliable path gets its own task so that wait costs nothing else.
#[derive(Clone)]
pub struct CellSender {
    inner: CellTransport,
}

#[derive(Clone)]
enum CellTransport {
    Ws(WsSink),
    Quic(crate::quicmedia::QuicCells),
}

impl CellSender {
    /// Send a group of cells that must arrive intact (one encoded video frame's
    /// fragments, or a control cell).
    pub async fn send_cells(&self, cells: Vec<Vec<u8>>) -> Result<()> {
        match &self.inner {
            // The lock is taken and released **per cell**, not per group: a voice frame
            // that comes due mid-frame gets the sink between two cells instead of waiting
            // for the whole group. Cells are individually addressed and reassembled by
            // the receiver, so interleaving costs nothing.
            CellTransport::Ws(sink) => {
                for cell in cells {
                    sink.lock()
                        .await
                        .send(WsMessage::Binary(cell))
                        .await
                        .map_err(|e| ClientError::Ws(e.to_string()))?;
                }
                Ok(())
            }
            CellTransport::Quic(q) => q.send_cells(cells).await,
        }
    }
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
                // The QUIC join negotiates on its own control stream and does not upgrade
                // first, so it has nothing to hold back here.
                pending: None,
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
        let (sink, source) = ws.split();
        let mut media = CallMedia {
            inner: MediaTransport::Ws {
                sink: Arc::new(tokio::sync::Mutex::new(sink)),
                source,
            },
            pending: None,
        };
        // Not joined until the relay says so. The upgrade proves only that the socket opened,
        // and every server-side refusal happens after it — so accepting the upgrade as a join
        // is what let a client hold a room it was never admitted to.
        let ack = tokio::time::timeout(JOIN_ACK_TIMEOUT, async {
            loop {
                match media.next_event().await? {
                    joined @ CallWireEvent::Joined { .. } => return Ok(joined),
                    // The refusal, seen from here: the socket opens and is then dropped
                    // without a word.
                    CallWireEvent::Closed => {
                        return Err(ClientError::Protocol(
                            "the relay closed the call socket without admitting it to the room"
                                .into(),
                        ))
                    }
                    // Anything else before `joined` is not ours to interpret; keep reading.
                    _ => continue,
                }
            }
        })
        .await
        .map_err(|_| {
            ClientError::Protocol("the relay never confirmed the call room join".into())
        })??;
        media.pending = Some(ack);
        Ok(media)
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
            MediaTransport::Ws { .. } => "ws",
            MediaTransport::Quic(_) => "quic",
        }
    }

    /// Send one loss-tolerant wire frame (voice, screen audio). Over QUIC this is an
    /// unreliable datagram — a dropped frame plays as 20 ms of silence and never
    /// stalls the stream. `Err` means the connection itself is gone.
    pub async fn send_lossy(&mut self, wire: Vec<u8>) -> Result<()> {
        match &mut self.inner {
            MediaTransport::Ws { sink, .. } => sink
                .lock()
                .await
                .send(WsMessage::Binary(wire))
                .await
                .map_err(|e| ClientError::Ws(e.to_string())),
            MediaTransport::Quic(q) => q.send_lossy(wire),
        }
    }

    /// A handle for the reliable path, to be driven from its own task. See [`CellSender`]
    /// for why that separation is not optional.
    pub fn cell_sender(&self) -> CellSender {
        CellSender {
            inner: match &self.inner {
                MediaTransport::Ws { sink, .. } => CellTransport::Ws(sink.clone()),
                MediaTransport::Quic(q) => CellTransport::Quic(q.cells()),
            },
        }
    }

    /// Await the next room event. Cancel-safe (a dropped future loses nothing).
    pub async fn next_event(&mut self) -> Result<CallWireEvent> {
        // The `joined` the join itself read, handed over once so the session sees the same
        // event stream it always did.
        if let Some(pending) = self.pending.take() {
            return Ok(pending);
        }
        match &mut self.inner {
            MediaTransport::Quic(q) => Ok(q.next_event().await),
            MediaTransport::Ws { sink, source } => {
                while let Some(frame) = source.next().await {
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
                            let _ = sink.lock().await.send(WsMessage::Pong(p)).await;
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
            // Send a Close frame and go. Deliberately *not* `SinkExt::close`, which drives
            // the full closing handshake and therefore waits for the peer's Close reply —
            // a reply nobody is left to read, because the read half of this split is being
            // dropped right here. That wait would never finish, and `close` is on the path
            // that ends a call: hanging in it would leave the session task alive forever.
            // The relay treats the socket going away as leaving the room regardless, so
            // the frame is a courtesy and the timeout is the guarantee.
            MediaTransport::Ws { sink, .. } => {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    sink.lock().await.send(WsMessage::Close(None)).await
                })
                .await;
            }
            MediaTransport::Quic(q) => q.close(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Tor invariant (`internal/CALL_PLAN.md` §10.3): with a SOCKS proxy set, the QUIC media
    /// path is never even attempted. QUIC is UDP, which SOCKS5-over-TCP does not carry,
    /// so a direct connect would bypass the proxy and leak the IP it exists to hide.
    /// Asserted against a base URL that resolves to nothing — the only way this can
    /// return `None` immediately is by refusing before the discovery request.
    #[tokio::test]
    async fn a_socks_proxy_disables_the_quic_media_path() {
        let client = Client::new(
            "http://invalid.invalid:1",
            "ws://invalid.invalid:1",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .with_proxy(Some("socks5://127.0.0.1:9050".into()));
        assert!(client.proxy_active());
        let started = std::time::Instant::now();
        assert!(client.try_join_call_quic("callid").await.is_none());
        assert!(
            started.elapsed() < crate::quicmedia::CONNECT_TIMEOUT,
            "the proxy check must short-circuit before the discovery timeout"
        );
    }

    /// `socks5://` is normalized to `socks5h://` — the relay hostname must be resolved
    /// BY the proxy, or every connection leaks a DNS lookup for it.
    #[test]
    fn proxy_urls_resolve_through_the_proxy() {
        for input in ["socks5://127.0.0.1:9050", "socks5h://127.0.0.1:9050"] {
            assert_eq!(
                crate::normalize_proxy(Some(input.into())).as_deref(),
                Some("socks5h://127.0.0.1:9050")
            );
        }
        assert_eq!(crate::normalize_proxy(Some("  ".into())), None);
    }
}
