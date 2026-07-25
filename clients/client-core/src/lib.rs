//! Headless Sona client.
//!
//! All client logic lives here so the GUI shells (Tauri desktop, Tauri Android) are thin
//! and the security-critical flows are tested without a UI. The crate ties together:
//!
//! * [`crypto_core`] — the vault, the Double Ratchet, KT entry minting, safety numbers.
//! * [`kt_log`]      — verifying a contact's key against the transparency log.
//! * [`protocol_types`] — the wire envelope.
//! * the relay transport — REST for registration/discovery, WebSocket for delivery.
//!
//! The security posture the client enforces:
//! * **KT before trust** — [`Client::add_contact`] refuses to start a session unless the
//!   contact's identity key is the one proven to be in the transparency log.
//! * **Sealed sender** — outbound envelopes name only the recipient hash; the recipient
//!   learns the sender from the (decrypted) ratchet message, never the server.
//! * **Signed challenge auth** — the WebSocket login signs a server nonce with the
//!   identity key; no password or token ever crosses the wire.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use crypto_core::kt::{safety_number, verify_contact_binding, KtCheck};
use crypto_core::Account;
use futures_util::{SinkExt, StreamExt};
use kt_log::{
    check_heads, verify_inclusion_b64, verify_roster_inclusion_b64, verify_sth_b64, GroupEpoch,
    KtEntry, KtRosterEntry, SignedTreeHead,
};

pub use kt_log::KtEntry as KtBindingEntry;
pub use kt_log::{
    DeviceRecord, GossipVerdict, GroupEpoch as GroupMembershipEpoch, GroupEpochError,
    GroupMemberEntry, SignedTreeHead as TreeHead, MAX_GROUP_MEMBERS, PRIMARY_DEVICE_ID,
};
use protocol_types::{CiphertextMessage, Envelope, IdentityHash, PayloadKind, PreKeyBundle};
pub use protocol_types::{WakeClass, CAP_INVITE_REGISTER, CAP_PUSH_FCM, CAP_PUSH_WEBHOOK};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message as WsMessage;

mod api;
pub mod attest;
pub mod call;
pub mod devicekey;
mod events;
pub mod groupcall;
pub mod history;
pub mod hw_codec;
pub mod media;
pub mod multidevice;
mod padding;
mod quicmedia;
mod subscribe;
mod types;
mod wire;
pub use events::InboundEvent;
pub use history::{
    ContactPin, Conversation, DeliveryStatus, Direction, GroupAdmin, GroupEpochOutcome,
    GroupRecord, History, StoredMessage,
};
pub use subscribe::{Subscription, KEEPALIVE_IDLE_SECS, WATCHDOG_IDLE_SECS};
pub(crate) use types::KtProofResponse;
pub use types::*;
pub(crate) use wire::{ack_frame, build_envelope, wake_class_for, ChatPayload};
pub use wire::{decode_frame, Decoded};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {0}")]
    Status(u16),
    /// Username lookup came back 404 — no such account on this relay. Distinct from
    /// [`ClientError::Http`] so shells can say "that username doesn't exist" instead
    /// of surfacing a raw network error.
    #[error("that username doesn't exist")]
    UserNotFound,
    #[error("malformed response: {0}")]
    Protocol(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("key transparency verification failed: {0:?}")]
    KtVerification(KtCheck),
    #[error("websocket error: {0}")]
    Ws(String),
    #[error("authentication rejected by server")]
    AuthRejected,
    /// The relay's ACCESS GATE refused us (401 in token mode, uniform 404 in stealth)
    /// on a path that never returns those statuses otherwise. Means the shared access
    /// token was rotated (or revoked): the user must get the new token from the relay
    /// operator and reconnect — retrying with the old one can never succeed.
    #[error("the relay no longer accepts this access token")]
    AccessDenied,
    /// The relay reports this device's mailbox no longer exists — it was revoked from
    /// the account's roster (or the account was deleted). Terminal: the caller must
    /// unlink locally (lock the UI, offer relink), never retry.
    #[error("this device was revoked from the account")]
    DeviceRevoked,
    /// A relay served an older device-roster epoch than we already pinned — a rollback /
    /// split-view attempt. The multi-device send path fails closed on this.
    #[error(transparent)]
    RosterRollback(#[from] history::RosterRollback),
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// A KT-verified contact: a confirmed `username → identity_key` binding plus the safety
/// number to compare out-of-band.
#[derive(Debug, Clone)]
pub struct Contact {
    pub username: String,
    pub identity_hash: String,
    pub identity_key: String,
    pub safety_number: String,
}

/// Build a minimal [`Contact`] for encrypting to a peer we **already** have a session with
/// (e.g. to send a receipt): the send path needs only the identity hash + key, and the
/// existing ratchet session — no fresh Key Transparency round-trip. Do NOT use this to
/// *start* a session; that must go through the KT-verified [`Client::add_contact`].
/// The mailbox/routing hash for a username — SHA-256, the only address the server sees.
/// Exposed so shells can compute the hashes of their own former usernames (mailbox
/// aliases after a rename) without depending on `protocol_types` directly.
/// Reserved conversation key for the local "Note to self" thread. Never a real identity
/// key (real keys are base64; the colon can't appear), so it can never collide with a
/// contact. Notes are stored under this peer key and synced ONLY to the account's own
/// devices (`SelfText`/`SelfFile` with this `peer_key`) — no recipient ever exists.
pub const NOTE_TO_SELF_PEER: &str = "note:self";

pub fn identity_hash_for(username: &str) -> String {
    IdentityHash::from_identifier(username).as_str().to_string()
}

pub fn contact_for(username: &str, identity_key: &str) -> Contact {
    Contact {
        username: username.to_string(),
        identity_hash: IdentityHash::from_identifier(username).as_str().to_string(),
        identity_key: identity_key.to_string(),
        safety_number: String::new(),
    }
}

/// A KT-verified contact discovered by [`Client::discover`] but not yet in a session.
/// Holds the bundle so [`Client::start_session`] can establish without re-fetching.
#[derive(Debug, Clone)]
pub struct Discovered {
    pub username: String,
    pub identity_hash: String,
    pub identity_key: String,
    pub safety_number: String,
    bundle: PreKeyBundle,
}

/// Result of a key-change-aware discovery ([`Client::add_contact_checked`]).
#[derive(Debug, Clone)]
pub enum ContactOutcome {
    /// First time we've seen this contact — session started; caller should pin the key.
    New(Contact),
    /// Key matches the one we pinned — session started.
    Unchanged(Contact),
    /// The published key differs from the one we pinned. **No session was started.**
    /// Have the user compare `new_safety_number` out-of-band before accepting.
    KeyChanged {
        username: String,
        previous_identity_key: String,
        new_identity_key: String,
        new_safety_number: String,
    },
}

/// Result of [`Client::audit_own_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The log binds our username to our real keys. All good.
    Ok,
    /// The log binds our username to a *different* key — a rogue entry under our name.
    RogueKey { published_identity_key: String },
    /// We are not registered in the log.
    NotRegistered,
}

/// Build the HTTP client, attaching the access token as a default header when present
/// (marked sensitive so proxies/logging layers redact it) and routing through the
/// SOCKS5 proxy when one is set.
fn build_http(access_token: Option<&str>, proxy: Option<&str>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if let Some(token) = access_token {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(mut v) = reqwest::header::HeaderValue::from_str(token) {
            v.set_sensitive(true);
            headers.insert(ACCESS_HEADER, v);
        }
        builder = builder.default_headers(headers);
    }
    if let Some(url) = proxy {
        // FAIL CLOSED: when a proxy is configured but its URL doesn't parse (corrupted
        // prefs edited outside the app — the settings path validates before saving),
        // every request must fail rather than silently go direct. A Tor user's traffic
        // leaking to the network unproxied is strictly worse than an outage, so the
        // fallback proxy is a guaranteed-dead loopback port.
        let p = reqwest::Proxy::all(url).unwrap_or_else(|_| {
            reqwest::Proxy::all("socks5h://127.0.0.1:1").expect("static fallback proxy parses")
        });
        builder = builder.proxy(p);
    }
    builder.build().expect("reqwest client builds")
}

/// Plain HTTPS GET returning the body, honoring the same fail-closed SOCKS proxy
/// semantics as every relay connection. For the app shell's update checks — anything
/// the relay client itself needs goes through [`Relay`] with the access token attached.
/// `max_len` caps the body (a hostile/broken server must not balloon memory).
pub async fn http_get_bytes(
    url: &str,
    proxy: Option<&str>,
    max_len: usize,
) -> std::result::Result<Vec<u8>, String> {
    http_get_bytes_progress(url, proxy, max_len, |_, _| {}).await
}

/// [`http_get_bytes`] with a progress callback: `(bytes_so_far, total_if_known)` after
/// every received chunk — for UIs showing a download bar (e.g. the in-app updater).
pub async fn http_get_bytes_progress(
    url: &str,
    proxy: Option<&str>,
    max_len: usize,
    mut progress: impl FnMut(u64, Option<u64>),
) -> std::result::Result<Vec<u8>, String> {
    let client = build_http(None, proxy);
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetch {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("fetch {url}: HTTP {}", resp.status()));
    }
    if let Some(len) = resp.content_length() {
        if len as usize > max_len {
            return Err(format!("fetch {url}: {len} bytes exceeds cap"));
        }
    }
    let total = resp.content_length();
    let mut out: Vec<u8> = Vec::new();
    let mut stream = resp;
    while let Some(chunk) = stream
        .chunk()
        .await
        .map_err(|e| format!("fetch {url}: {e}"))?
    {
        if out.len() + chunk.len() > max_len {
            return Err(format!("fetch {url}: body exceeds {max_len}-byte cap"));
        }
        out.extend_from_slice(&chunk);
        progress(out.len() as u64, total);
    }
    Ok(out)
}

/// Normalize a user-supplied SOCKS proxy string to a `socks5h://host:port` URL.
/// `socks5h` (hostname resolved BY the proxy) is forced even when the user typed
/// `socks5://`: with Tor, resolving the relay hostname locally would leak every
/// connection attempt to the local DNS resolver. Empty/whitespace input → `None`.
fn normalize_proxy(proxy: Option<String>) -> Option<String> {
    let p = proxy?.trim().to_string();
    if p.is_empty() {
        return None;
    }
    let rest = p
        .strip_prefix("socks5h://")
        .or_else(|| p.strip_prefix("socks5://"))
        .unwrap_or(&p);
    Some(format!("socks5h://{rest}"))
}

/// A handle to one relay. `pinned_kt_key` is the server's Key Transparency public key,
/// shipped to the client out-of-band (config/build) — the root of all key-binding trust.
pub struct Client {
    http: reqwest::Client,
    base_url: String,
    ws_url: String,
    pinned_kt_key: String,
    /// Shared access token for a private relay (`None` for open relays). One token per
    /// relay, common to all its members — deliberately NOT per-user, so sealed-sender
    /// sends stay unattributable.
    access_token: Option<String>,
    /// SOCKS5 proxy (`socks5h://host:port`, normalized) for every relay connection —
    /// HTTP and WebSocket both. Set for Tor/Orbot users. While set, the QUIC media
    /// path is disabled (UDP does not traverse SOCKS/Tor and a direct QUIC connect
    /// would leak the real IP the proxy is hiding); calls fall back to relay-bridged
    /// WebSocket media transparently.
    proxy: Option<String>,
}

impl Client {
    pub fn new(
        base_url: impl Into<String>,
        ws_url: impl Into<String>,
        pinned_kt_key: impl Into<String>,
    ) -> Self {
        Self::with_access_token(base_url, ws_url, pinned_kt_key, None)
    }

    /// Like [`Client::new`], for a relay that requires a shared access token.
    pub fn with_access_token(
        base_url: impl Into<String>,
        ws_url: impl Into<String>,
        pinned_kt_key: impl Into<String>,
        access_token: Option<String>,
    ) -> Self {
        let access_token = access_token.filter(|t| !t.trim().is_empty());
        Self {
            http: build_http(access_token.as_deref(), None),
            base_url: base_url.into(),
            ws_url: ws_url.into(),
            pinned_kt_key: pinned_kt_key.into(),
            access_token,
            proxy: None,
        }
    }

    /// Route every relay connection (HTTP + WebSocket) through a SOCKS5 proxy —
    /// typically Tor (`socks5://127.0.0.1:9050`, Orbot on Android). Consuming builder:
    /// call right after construction. `None`/empty clears. See the `proxy` field for
    /// the QUIC-disable side effect.
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = normalize_proxy(proxy);
        self.http = build_http(self.access_token.as_deref(), self.proxy.as_deref());
        self
    }

    /// Is a SOCKS proxy configured?
    pub fn proxy_active(&self) -> bool {
        self.proxy.is_some()
    }

    /// Connect a WebSocket, honoring the SOCKS proxy when set. All WS connects in this
    /// crate must go through here (as all upgrade requests go through `ws_request`).
    pub(crate) async fn ws_connect(
        &self,
        req: tokio_tungstenite::tungstenite::handshake::client::Request,
    ) -> std::result::Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::Error,
    > {
        use tokio_tungstenite::tungstenite::Error as WsError;
        let Some(proxy) = &self.proxy else {
            return tokio_tungstenite::connect_async(req)
                .await
                .map(|(ws, _)| ws);
        };
        // socks5h://host:port → the proxy's own address resolves locally (it IS local:
        // Tor/Orbot on loopback); the TARGET hostname goes to the proxy unresolved.
        let proxy_addr = proxy.trim_start_matches("socks5h://");
        let uri = req.uri();
        let host = uri
            .host()
            .ok_or_else(|| {
                WsError::Url(tokio_tungstenite::tungstenite::error::UrlError::NoHostName)
            })?
            .to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("wss") {
                443
            } else {
                80
            });
        let stream = tokio_socks::tcp::Socks5Stream::connect(proxy_addr, (host.as_str(), port))
            .await
            .map_err(|e| WsError::Io(std::io::Error::other(format!("socks proxy: {e}"))))?;
        // Hand the proxied TcpStream to tungstenite's TLS connector: same wss:// +
        // webpki-roots posture as the direct path, so certificate checking is identical.
        tokio_tungstenite::client_async_tls(req, stream.into_inner())
            .await
            .map(|(ws, _)| ws)
    }

    /// A WebSocket upgrade request for `url`, carrying the access token when set.
    /// tungstenite's plain-URL connect can't attach headers, so every WS connect in
    /// this crate must go through here or the relay's gate will refuse the upgrade.
    fn ws_request(
        &self,
        url: &str,
    ) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = url
            .into_client_request()
            .map_err(|e| ClientError::Ws(e.to_string()))?;
        if let Some(token) = &self.access_token {
            if let Ok(v) = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(token) {
                req.headers_mut().insert(ACCESS_HEADER, v);
            }
        }
        Ok(req)
    }

    // ── Multi-device (Phase 1 — capability-gated; single-device remains the default) ──
    //
    // Nothing in the default client flow calls these. A shell must first check
    // [`server_capabilities`](Self::server_capabilities) for
    // [`protocol_types::CAP_MULTI_DEVICE`] / [`protocol_types::CAP_HISTORY_SYNC`] and
    // keep the single-device path when absent (old relays 404). The full linking flow,
    // per-device fan-out, and history import/export are Phase 2/3 —
    // see `docs/MULTI_DEVICE.md`.

    /// Open a **live subscription**: authenticate and keep the socket open, delivering both
    /// the queued backlog and messages as they arrive in real time. Drive it by calling
    /// [`Subscription::next`] in a loop — or, for callers that guard the account with a
    /// lock, [`Subscription::next_frame`] (no account needed) + [`decode_frame`] +
    /// [`Subscription::ack`].
    pub async fn subscribe(&self, account: &Account) -> Result<Subscription> {
        let ws = self.open_authed_socket(account).await?;
        Ok(Subscription::new(ws))
    }

    /// Subscribe to one of our **own previous mailboxes** (by identity hash) after a
    /// username change: peers that haven't seen the rename yet still deliver to the old
    /// hash, and its registration still carries our keys, so the signed challenge
    /// authenticates. Frames decode exactly like the main subscription's.
    pub async fn subscribe_as(&self, account: &Account, hash: &str) -> Result<Subscription> {
        let ws = self.open_authed_socket_as(account, hash).await?;
        Ok(Subscription::new(ws))
    }
}

/// The device-targeted sealing primitive: encrypt `payload` under the ratchet session for
/// `device_identity_key` and address it to `mailbox_hash` with the given `msg_id`. This is
/// the single choke point through which both 1:1 sends and multi-device fan-out flow — a
/// caller must already hold a session with `device_identity_key` (KT-/roster-verified).
/// The shared `msg_id` lets every copy of one logical message dedup consistently.
/// Being the single choke point, it is also where every envelope gets its sender-declared
/// [`WakeClass`] — no send site can forget to tag.
pub(crate) fn seal_payload_to(
    account: &mut Account,
    mailbox_hash: &str,
    device_identity_key: &str,
    payload: &ChatPayload,
    msg_id: &str,
) -> Result<Envelope> {
    let json = serde_json::to_vec(payload).map_err(|e| ClientError::Protocol(e.to_string()))?;
    let wire = STANDARD_NO_PAD.encode(padding::pad(&json));
    let cipher = account
        .ratchet()
        .encrypt(device_identity_key, &wire)
        .map_err(|e| ClientError::Crypto(e.to_string()))?;
    let to = IdentityHash::from_hex(mailbox_hash)
        .ok_or_else(|| ClientError::Protocol("bad mailbox hash".into()))?;
    Ok(Envelope {
        to,
        ciphertext: serde_json::to_string(&cipher)
            .map_err(|e| ClientError::Protocol(e.to_string()))?,
        kind: PayloadKind::Message,
        msg_id: msg_id.to_string(),
        expires_at: None,
        wake: wake_class_for(payload),
        raw_identifier: None,
    })
}

/// The connected+authenticated WebSocket stream type.
pub(crate) type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Current unix time in seconds.
fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A random 32-hex-char (128-bit) message id for dedup / delivery receipts. 128 bits
/// matches the call/blob ids and puts birthday collisions out of reach, so the durable
/// store's `(target_hash, msg_id)` uniqueness can't silently drop a distinct message (L-3).
fn random_msg_id() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Turn a non-2xx response into a [`ClientError::Status`].
async fn ensure_ok(resp: reqwest::Response) -> Result<()> {
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(ClientError::Status(status.as_u16()))
    }
}
