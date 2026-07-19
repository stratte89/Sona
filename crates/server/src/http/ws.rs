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
    ws.on_upgrade(move |socket| handle_socket(socket, state, client))
}

/// Upgrade a call-relay socket. Join is by capability token only (the random call id
/// from the E2E `CallOffer`) — deliberately unauthenticated so the relay cannot link a
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
    {
        let Some(client) = client_key(&headers, &state) else {
            return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
        };
        let key = format!("call:{client}");
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&key, now()) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
    }
    ws.on_upgrade(move |socket| crate::call::handle_call_socket(socket, state, call_id))
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

/// RAII slot in the per-client socket count: dropping it (any exit path, including
/// panics and the auth-deadline return) releases the slot.
struct WsSlot {
    state: AppState,
    client: String,
}

impl WsSlot {
    /// Claim a slot for `client`, or `None` if it is already at the cap.
    fn claim(state: &AppState, client: &str) -> Option<Self> {
        let mut inner = state.inner.lock().unwrap();
        let cap = state.config.max_ws_per_client;
        let n = inner.ws_count.entry(client.to_string()).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(Self {
            state: state.clone(),
            client: client.to_string(),
        })
    }
}

impl Drop for WsSlot {
    fn drop(&mut self) {
        let mut inner = self.state.inner.lock().unwrap();
        if let Some(n) = inner.ws_count.get_mut(&self.client) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inner.ws_count.remove(&self.client);
            }
        }
    }
}

async fn handle_socket(socket: WebSocket, state: AppState, client: String) {
    // One address must not hoard sockets (each one costs a task + fd). Multiple
    // devices/tabs behind one NAT share the cap, so it is generous, not tight.
    let Some(_slot) = WsSlot::claim(&state, &client) else {
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
                        inner.store.ack(&hash, &msg_id);
                        if let Some(db) = &inner.db {
                            let _ = db.delete_message(&msg_id);
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
    // The client signs the raw nonce bytes (base64-decoded).
    let Ok(nonce_bytes) = vodozemac::base64_decode(&nonce) else {
        return AuthOutcome::Failed;
    };
    if auth::verify(&signing_key, &nonce_bytes, &signature) {
        AuthOutcome::Ok(hash)
    } else {
        AuthOutcome::Failed
    }
}
