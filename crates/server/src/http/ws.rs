use super::*;

/// Frames the client sends over the socket.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    /// First frame: prove control of `hash` by signing the issued `nonce`.
    Auth {
        hash: String,
        nonce: String,
        signature: String,
    },
    /// Delivery receipt — server deletes the delivered message.
    Ack { msg_id: String },
}

/// Frames the server sends over the socket.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ServerFrame {
    Ready,
    AuthFailed,
    /// The mailbox this connection authenticated (or tried to authenticate) against has
    /// no directory record — the device was revoked from its account's roster (or the
    /// account is gone). Terminal: the client must unlink locally, not retry.
    Revoked,
    Message {
        envelope: Envelope,
    },
}

pub(crate) async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &state) {
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    // The per-client socket cap needs a trusted client key — same fail-closed rule as
    // every other keyed limiter.
    let Some(client) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    ws.max_message_size(MAX_DELIVERY_FRAME_BYTES)
        .max_frame_size(MAX_DELIVERY_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state, client))
}

/// Cap on a single frame from a delivery-socket client. Axum/tungstenite default to a
/// 64 MiB message and a 16 MiB frame, and every relay-side limit is checked only *after*
/// the whole message has been assembled — so a client could force a 64 MiB allocation
/// per socket, repeatedly, before anything looked at it (SP-08).
///
/// This socket carries exactly two client frames: the `Auth` frame (a hash, a 32-byte
/// nonce, and a signature — a few hundred bytes) and `Ack` frames (~100 bytes). 8 KiB is
/// three orders of magnitude of headroom over the protocol's real maximum and still four
/// orders below the default.
const MAX_DELIVERY_FRAME_BYTES: usize = 8 * 1024;

/// Cap on a single frame from a call-socket client — the *media* maximum, which is a
/// different number from the delivery socket's and must be sized separately (SP-08).
/// `MAX_FRAME_BYTES` is exactly the media-v2 cell size; the slack covers WebSocket
/// framing only. Setting this below a real cell would truncate video and break calls.
const MAX_CALL_FRAME_BYTES: usize = crate::call::MAX_FRAME_BYTES + 1024;

/// Upgrade a call-relay socket. Join is by capability token only (the random call id
/// from the E2E call offer) — deliberately unauthenticated so the relay cannot link a
/// call to the identities in it. Same origin policy as the delivery socket; joins are
/// rate-limited per pseudonymized client.
pub(crate) async fn call_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &state) {
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    let Some(client) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    {
        let key = format!("call:{client}");
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&key, now()) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
    }
    // The join limiter bounds the *rate*, not the *count* — and a paired room lives up
    // to 6 h, so without a concurrency cap sockets accumulate (SP-08). Claimed here and
    // released by the RAII slot when the socket ends, same as the delivery path.
    let Some(slot) = WsSlot::claim(&state, &client, SocketKind::Call) else {
        return (StatusCode::TOO_MANY_REQUESTS, "too many call sockets").into_response();
    };
    ws.max_message_size(MAX_CALL_FRAME_BYTES)
        .max_frame_size(MAX_CALL_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            crate::call::handle_call_socket(socket, state, call_id, client).await;
            drop(slot);
        })
}

/// Discovery for the QUIC media path: UDP port + the exact certificate hash to pin.
/// Served over the channel clients already trust (their pinned relay URL), so a
/// network attacker cannot swap the certificate without also owning that channel —
/// and media is end-to-end encrypted above the transport anyway.
pub(crate) async fn quic_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    let quic = state.quic.lock().unwrap().clone();
    Json(match quic {
        Some(q) => serde_json::json!({
            "enabled": true,
            "port": q.port,
            "cert_sha256": q.cert_sha256_b64,
        }),
        None => serde_json::json!({ "enabled": false }),
    })
}

/// How long an accepted socket may sit silent before its first (Auth) frame. Without a
/// deadline, an attacker opens sockets and sends nothing — each one pins a task and an
/// fd forever, no authentication needed.
const WS_AUTH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Which per-client socket budget a [`WsSlot`] draws on. Delivery and call sockets are
/// counted separately — a device in a group call legitimately holds a delivery socket
/// *and* one call socket per mesh room.
#[derive(Clone, Copy)]
pub(crate) enum SocketKind {
    Delivery,
    Call,
}

/// RAII slot in the per-client socket count: dropping it (any exit path, including
/// panics and the auth-deadline return) releases the slot.
pub(crate) struct WsSlot {
    state: AppState,
    client: String,
    kind: SocketKind,
}

impl WsSlot {
    /// Claim a slot for `client`, or `None` if it is already at the cap.
    pub(crate) fn claim(state: &AppState, client: &str, kind: SocketKind) -> Option<Self> {
        let mut inner = state.inner.lock().unwrap();
        let cap = match kind {
            SocketKind::Delivery => state.config.max_ws_per_client,
            SocketKind::Call => state.config.max_call_ws_per_client,
        };
        let counts = match kind {
            SocketKind::Delivery => &mut inner.ws_count,
            SocketKind::Call => &mut inner.call_ws_count,
        };
        let n = counts.entry(client.to_string()).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(Self {
            state: state.clone(),
            client: client.to_string(),
            kind,
        })
    }
}

impl Drop for WsSlot {
    fn drop(&mut self) {
        let mut inner = self.state.inner.lock().unwrap();
        let counts = match self.kind {
            SocketKind::Delivery => &mut inner.ws_count,
            SocketKind::Call => &mut inner.call_ws_count,
        };
        if let Some(n) = counts.get_mut(&self.client) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&self.client);
            }
        }
    }
}

async fn handle_socket(socket: WebSocket, state: AppState, client: String) {
    // One address must not hoard sockets (each one costs a task + fd). Multiple
    // devices/tabs behind one NAT share the cap, so it is generous, not tight.
    let Some(_slot) = WsSlot::claim(&state, &client, SocketKind::Delivery) else {
        return; // over the cap — drop the socket
    };
    let (mut sink, mut stream) = socket.split();

    // ── Step 1: authenticate. The first frame must be a valid signed Auth, and it must
    //    arrive within the deadline (an idle pre-auth socket is a free resource pin). ──
    let first = match tokio::time::timeout(WS_AUTH_DEADLINE, stream.next()).await {
        Ok(frame) => frame,
        Err(_) => return, // silent too long — drop
    };
    let authed_hash = match first {
        Some(Ok(Message::Text(t))) => match authenticate(&state, t.as_str()) {
            AuthOutcome::Ok(hash) => hash,
            AuthOutcome::Revoked => {
                let _ = sink
                    .send(Message::Text(
                        serde_json::to_string(&ServerFrame::Revoked).unwrap().into(),
                    ))
                    .await;
                return;
            }
            AuthOutcome::Failed => {
                let _ = sink
                    .send(Message::Text(
                        serde_json::to_string(&ServerFrame::AuthFailed)
                            .unwrap()
                            .into(),
                    ))
                    .await;
                return;
            }
        },
        _ => return, // no/invalid first frame — drop the connection
    };

    // ── Step 2: register a live channel and flush anything queued. ──
    let (tx, mut rx) = unbounded_channel::<String>();
    {
        let mut inner = state.inner.lock().unwrap();
        inner
            .live
            .entry(authed_hash.clone())
            .or_default()
            .push(tx.clone());
        let hash = IdentityHash::from_hex(&authed_hash).expect("authed hash is valid hex");
        for env in inner.store.fetch(&hash, now()) {
            if let Ok(frame) = serde_json::to_string(&ServerFrame::Message { envelope: env }) {
                let _ = tx.send(frame);
            }
        }
    }
    let _ = tx.send(serde_json::to_string(&ServerFrame::Ready).unwrap());

    // ── Step 3: pump. One task forwards queued/live frames to the client; the main
    //    loop reads acks. Either side ending tears the connection down. ──
    // Precomputed so the forward task can recognize a revocation kick: after relaying
    // it, the task ends, which tears the whole connection down (the local `tx` clone
    // keeps the channel open, so senders dropping out of `live` alone can't end it).
    let revoked_frame = serde_json::to_string(&ServerFrame::Revoked).unwrap();
    let mut forward = tokio::spawn(async move {
        // Keepalive: ping every 30s so a half-dead connection (NAT timeout, dropped
        // Wi-Fi) fails fast and the client reconnects — otherwise the client sits on a
        // dead socket receiving nothing until TCP gives up.
        let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
        ping.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                frame = rx.recv() => match frame {
                    Some(frame) => {
                        let kicked = frame == revoked_frame;
                        if sink.send(Message::Text(frame.into())).await.is_err() || kicked {
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

    // The read loop also ends when the forward task does: a revocation kick drops this
    // connection's sender from `live`, which ends the forward task — without this select
    // the revoked socket would linger until the client went away on its own.
    loop {
        let msg = tokio::select! {
            m = stream.next() => match m {
                Some(Ok(m)) => m,
                _ => break,
            },
            _ = &mut forward => break,
        };
        match msg {
            Message::Text(t) => {
                if let Ok(ClientFrame::Ack { msg_id }) = serde_json::from_str(t.as_str()) {
                    if let Some(hash) = IdentityHash::from_hex(&authed_hash) {
                        let mut inner = state.inner.lock().unwrap();
                        // Both deletes must hit the SAME row set: the in-memory ack is
                        // scoped to the authenticated mailbox, so the durable one must be
                        // too (SP-05). `msg_id` alone is a shared namespace across every
                        // device and self-sync copy of one logical message.
                        inner.store.ack(&hash, &msg_id);
                        if let Some(db) = &inner.db {
                            let _ = db.delete_message(hash.as_str(), &msg_id);
                        }
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    // ── Cleanup: stop forwarding and drop this connection's live channel. ──
    forward.abort();
    let mut inner = state.inner.lock().unwrap();
    if let Some(senders) = inner.live.get_mut(&authed_hash) {
        senders.retain(|s| !s.same_channel(&tx));
        if senders.is_empty() {
            inner.live.remove(&authed_hash);
        }
    }
}

/// Outcome of validating an `Auth` frame.
enum AuthOutcome {
    /// Signature verified — the authenticated mailbox hash.
    Ok(String),
    /// The nonce was live but the hash has no directory record: the device was revoked
    /// (or the account deleted). Distinct from `Failed` so the client can unlink itself
    /// instead of retrying forever. Reveals nothing new: directory membership is already
    /// public via `GET /v1/bundle/{hash}`.
    Revoked,
    /// Bad frame, dead nonce, or bad signature.
    Failed,
}

/// Validate an `Auth` frame: nonce must be live + single-use, and the signature must
/// verify against the hash's registered signing key.
fn authenticate(state: &AppState, frame: &str) -> AuthOutcome {
    let Ok(ClientFrame::Auth {
        hash,
        nonce,
        signature,
    }) = serde_json::from_str(frame)
    else {
        return AuthOutcome::Failed;
    };
    let mut inner = state.inner.lock().unwrap();
    // Consume the nonce first (single-use even on failure).
    if !inner.challenges.consume(&hash, &nonce, now()) {
        return AuthOutcome::Failed;
    }
    let Some(signing_key) = inner.directory.get(&hash).map(|e| e.signing_key.clone()) else {
        return AuthOutcome::Revoked;
    };
    // SP-01: the client signs a domain-separated, mailbox-bound message — never the raw
    // nonce. Signing raw relay-chosen bytes with the account identity key was a blind
    // signing oracle (the relay could serve a KT roster/binding payload as the "nonce"
    // and harvest a genuine signature over it). Belt to the prefix's braces: refuse any
    // nonce that does not decode to exactly the 32 bytes `ChallengeStore::issue` mints,
    // so no longer structure can ride the challenge field even in a future context.
    match vodozemac::base64_decode(&nonce) {
        Ok(bytes) if bytes.len() == protocol_types::WS_AUTH_NONCE_LEN => {}
        _ => return AuthOutcome::Failed,
    }
    let message = protocol_types::ws_auth_signing_message(&hash, &nonce);
    if auth::verify(&signing_key, &message, &signature) {
        AuthOutcome::Ok(hash)
    } else {
        AuthOutcome::Failed
    }
}
