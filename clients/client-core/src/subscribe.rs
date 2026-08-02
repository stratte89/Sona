use super::*;

impl Client {
    /// Open the delivery socket and authenticate (signed challenge). Shared by the one-shot
    /// [`fetch_inbox`](Self::fetch_inbox) drain and the live [`subscribe`](Self::subscribe).
    pub(crate) async fn open_authed_socket(&self, account: &Account) -> Result<WsStream> {
        let hash = account.identity_hash().as_str().to_string();
        self.open_authed_socket_as(account, &hash).await
    }

    /// Like [`open_authed_socket`](Self::open_authed_socket), but for an explicit mailbox
    /// hash. Only works for hashes whose registered signing key is this account's — i.e.
    /// our *own* previous usernames after a rename (the server checks the challenge
    /// signature against the key registered for `hash`).
    pub(crate) async fn open_authed_socket_as(
        &self,
        account: &Account,
        hash: &str,
    ) -> Result<WsStream> {
        self.open_authed_socket_signed(hash, |nonce| account.ratchet_ref().sign(nonce))
            .await
    }

    /// [`open_authed_socket_as`](Self::open_authed_socket_as) with the signer supplied,
    /// so a mailbox whose directory record is keyed by something other than the account
    /// key can be authenticated — today the call-control mailbox, which a **locked**
    /// device drains with its call-control key while the account key stays sealed.
    pub(crate) async fn open_authed_socket_signed(
        &self,
        hash: &str,
        sign: impl Fn(&[u8]) -> String,
    ) -> Result<WsStream> {
        // A 401/404 HERE is the relay's ACCESS GATE, not account auth: `/v1/challenge`
        // itself never returns either (bad input is 400, pressure is 429), and mailbox
        // auth failures arrive as in-band `auth_failed`/`revoked` frames after the
        // upgrade. So these statuses mean the shared access token stopped working —
        // 401 in token mode, the uniform bare 404 in stealth — i.e. the operator
        // rotated it. Surfaced as [`ClientError::AccessDenied`] so shells can send the
        // user to a "get the new token" screen instead of retrying forever.
        let challenge_resp = self
            .http
            .get(format!("{}/v1/challenge?hash={hash}", self.base_url))
            .send()
            .await?;
        let challenge: Value = match challenge_resp.error_for_status() {
            Ok(resp) => resp.json().await?,
            Err(e) if matches!(e.status(), Some(s) if s.as_u16() == 401 || s.as_u16() == 404) => {
                return Err(ClientError::AccessDenied);
            }
            Err(e) => return Err(e.into()),
        };
        let nonce = challenge["nonce"]
            .as_str()
            .ok_or_else(|| ClientError::Protocol("missing nonce".into()))?;
        // SP-01: NEVER sign the raw nonce. The relay picks these bytes and the signer is
        // the account identity key (or the call-control key) — signing them unstructured
        // is a blind signing oracle: a hostile relay serves another context's signing
        // payload as the "nonce" and gets a genuine signature over it, one per reconnect.
        // Sign the domain-separated, mailbox-bound message instead, and refuse any nonce
        // that is not exactly the 32 random bytes the relay is supposed to issue.
        let nonce_bytes = STANDARD_NO_PAD
            .decode(nonce)
            .map_err(|e| ClientError::Protocol(format!("bad nonce: {e}")))?;
        if nonce_bytes.len() != protocol_types::WS_AUTH_NONCE_LEN {
            return Err(ClientError::Protocol(format!(
                "bad nonce: expected {} bytes, got {}",
                protocol_types::WS_AUTH_NONCE_LEN,
                nonce_bytes.len()
            )));
        }
        let signature = sign(&protocol_types::ws_auth_signing_message(hash, nonce));

        let mut ws = self
            .ws_connect(self.ws_request(&self.ws_url)?)
            .await
            .map_err(|e| match e {
                tokio_tungstenite::tungstenite::Error::Http(resp)
                    if resp.status().as_u16() == 401 || resp.status().as_u16() == 404 =>
                {
                    ClientError::AccessDenied
                }
                e => ClientError::Ws(e.to_string()),
            })?;
        let auth = json!({ "type": "auth", "hash": hash, "nonce": nonce, "signature": signature });
        ws.send(WsMessage::Text(auth.to_string()))
            .await
            .map_err(|e| ClientError::Ws(e.to_string()))?;
        Ok(ws)
    }

    /// Connect, authenticate, and drain every currently-queued message — decrypting and
    /// acking each — returning once the server signals `ready`, then closing. Deterministic
    /// snapshot of the inbox; for a live feed use [`subscribe`](Self::subscribe).
    pub async fn fetch_inbox(&self, account: &mut Account) -> Result<Vec<InboundEvent>> {
        let hash = account.identity_hash().as_str().to_string();
        self.fetch_inbox_as(account, &hash).await
    }

    /// Like [`fetch_inbox`](Self::fetch_inbox), but drains an explicit mailbox `hash` —
    /// used by a **linked device** to drain its own device mailbox (whose directory record
    /// carries this device's signing key, so the signed challenge authenticates), and by a
    /// former-username alias.
    pub async fn fetch_inbox_as(
        &self,
        account: &mut Account,
        hash: &str,
    ) -> Result<Vec<InboundEvent>> {
        let mut ws = self.open_authed_socket_as(account, hash).await?;
        let mut out = Vec::new();
        while let Some(frame) = ws.next().await {
            match frame.map_err(|e| ClientError::Ws(e.to_string()))? {
                WsMessage::Text(text) => match decode_frame(&text, account) {
                    Decoded::Ready => break,
                    Decoded::AuthFailed => return Err(ClientError::AuthRejected),
                    Decoded::Revoked => return Err(ClientError::DeviceRevoked),
                    Decoded::Event { event, ack_msg_id } => {
                        out.push(event);
                        ws.send(WsMessage::Text(ack_frame(&ack_msg_id)))
                            .await
                            .map_err(|e| ClientError::Ws(e.to_string()))?;
                    }
                    // Undecryptable forever — ack it out of the mailbox (see Decoded).
                    Decoded::Ignore {
                        ack_msg_id: Some(id),
                    } => {
                        let _ = ws.send(WsMessage::Text(ack_frame(&id))).await;
                    }
                    Decoded::Ignore { ack_msg_id: None } => {}
                },
                WsMessage::Close(_) => break,
                _ => {}
            }
        }
        let _ = ws.close(None).await;
        Ok(out)
    }
}

/// A live delivery feed. Stays connected; each [`next`](Self::next) yields the next event
/// (queued or freshly-arrived), decrypting and acking it. `None` when the socket closes.
pub struct Subscription {
    ws: WsStream,
    /// When anything last arrived (frame, ping, pong) — feeds the read watchdog.
    last_inbound: tokio::time::Instant,
    /// When we last sent anything — schedules the client keepalive ping.
    last_send: tokio::time::Instant,
}

/// Read watchdog: the server pings every 30 s and we ping every
/// [`KEEPALIVE_IDLE_SECS`], so 75 s of *total* inbound silence means the TCP
/// connection is a zombie (Doze parked the network, carrier NAT dropped the mapping)
/// — tear it down and reconnect instead of blocking on the OS TCP timeout (which can
/// exceed 15 minutes while the app believes it is connected).
pub const WATCHDOG_IDLE_SECS: u64 = 75;
/// Client keepalive ping after this much send-idle (Signal's NAT-proven interval):
/// detects death while the server is between pings and keeps NAT entries warm even if
/// a future server config lengthens its ping interval.
pub const KEEPALIVE_IDLE_SECS: u64 = 55;

impl Subscription {
    pub(crate) fn new(ws: WsStream) -> Self {
        let now = tokio::time::Instant::now();
        Subscription {
            ws,
            last_inbound: now,
            last_send: now,
        }
    }

    /// Await the next raw text frame. `Ok(None)` on a clean close. Needs **no account
    /// state**, and is cancel-safe: dropping the future mid-wait loses nothing (a
    /// partially received frame stays buffered in the stream). This is the primitive for
    /// callers that guard their account with a lock — wait here *unlocked*, then decode
    /// under the lock with [`decode_frame`], then [`ack`](Self::ack).
    ///
    /// Transport hardening lives here, at the frame wait only (never around
    /// decrypt+ack, preserving the cancel-safety invariant): a read watchdog errors
    /// out after [`WATCHDOG_IDLE_SECS`] of inbound silence, and a keepalive ping goes
    /// out after [`KEEPALIVE_IDLE_SECS`] of send-idle.
    pub async fn next_frame(&mut self) -> Result<Option<String>> {
        use std::time::Duration;
        loop {
            let watchdog = self.last_inbound + Duration::from_secs(WATCHDOG_IDLE_SECS);
            let keepalive = self.last_send + Duration::from_secs(KEEPALIVE_IDLE_SECS);
            tokio::select! {
                frame = self.ws.next() => {
                    let Some(frame) = frame else { return Ok(None) };
                    self.last_inbound = tokio::time::Instant::now();
                    match frame.map_err(|e| ClientError::Ws(e.to_string()))? {
                        WsMessage::Text(text) => return Ok(Some(text.to_string())),
                        WsMessage::Ping(p) => {
                            self.last_send = tokio::time::Instant::now();
                            let _ = self.ws.send(WsMessage::Pong(p)).await;
                        }
                        WsMessage::Close(_) => return Ok(None),
                        // Pong (answer to our keepalive) and binary frames: activity
                        // only — `last_inbound` above already recorded them.
                        _ => continue,
                    }
                }
                _ = tokio::time::sleep_until(watchdog) => {
                    return Err(ClientError::Ws(format!(
                        "read watchdog: no inbound traffic for {WATCHDOG_IDLE_SECS}s"
                    )));
                }
                _ = tokio::time::sleep_until(keepalive) => {
                    self.last_send = tokio::time::Instant::now();
                    self.ws
                        .send(WsMessage::Ping(Vec::new()))
                        .await
                        .map_err(|e| ClientError::Ws(format!("keepalive ping: {e}")))?;
                }
            }
        }
    }

    /// Send a delivery receipt (ack) for a message id — the server deletes it from the
    /// mailbox. Ack only after the event is durably applied, so a crash in between means
    /// redelivery, never loss.
    pub async fn ack(&mut self, msg_id: &str) -> Result<()> {
        self.last_send = tokio::time::Instant::now();
        self.ws
            .send(WsMessage::Text(ack_frame(msg_id)))
            .await
            .map_err(|e| ClientError::Ws(e.to_string()))
    }

    /// Await the next inbound event, decrypting and acking internally. `Ok(None)` on a
    /// clean close. NOT cancel-safe (an event can be lost if the future is dropped
    /// between decrypt and return) — do not wrap this in `tokio::time::timeout`; use the
    /// [`next_frame`](Self::next_frame)/[`decode_frame`]/[`ack`](Self::ack) primitives
    /// when you need cancellation.
    pub async fn next(&mut self, account: &mut Account) -> Result<Option<InboundEvent>> {
        loop {
            let Some(text) = self.next_frame().await? else {
                return Ok(None);
            };
            match decode_frame(&text, account) {
                Decoded::Ready => continue,
                Decoded::AuthFailed => return Err(ClientError::AuthRejected),
                Decoded::Revoked => return Err(ClientError::DeviceRevoked),
                Decoded::Event { event, ack_msg_id } => {
                    self.ack(&ack_msg_id).await?;
                    return Ok(Some(event));
                }
                // Permanently undecryptable — ack it away so it cannot poison the
                // mailbox (see decode_frame docs).
                Decoded::Ignore {
                    ack_msg_id: Some(id),
                } => {
                    let _ = self.ack(&id).await;
                }
                Decoded::Ignore { ack_msg_id: None } => continue,
            }
        }
    }

    /// Close the subscription's socket.
    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}
