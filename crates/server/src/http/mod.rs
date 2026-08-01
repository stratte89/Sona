//! The Axum surface: REST endpoints + the WebSocket relay.
//!
//! Endpoints (all under `/v1`):
//! * `POST /register`      — publish a key bundle for a hash (proven by self-signature).
//! * `GET  /bundle/{hash}` — fetch + consume one of a peer's one-time keys.
//! * `POST /messages`      — enqueue an opaque envelope for a recipient (sealed sender).
//! * `GET  /challenge`     — obtain a single-use login nonce.
//! * `POST /push/register` — register a content-free wake endpoint (challenge-signed).
//! * `POST /push/unregister` — remove it (challenge-signed).
//! * `GET  /ws`            — authenticated live delivery socket.
//!
//! Security posture: the server authenticates *recipients* (via Ed25519 challenge) but
//! not *senders* (sealed sender — anyone may deliver opaque ciphertext to a mailbox,
//! so the server cannot learn who talks to whom). Bodies are size-capped; sends are
//! rate-limited fail-closed; in production, WebSocket Origin is enforced.

use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::unbounded_channel;

use crate::auth;
use crate::state::{now, AppState, Config, DirectoryEntry, Inner, PushSub};
use kt_log::{KtEntry, KtRosterEntry, SignedTreeHead};
use protocol_types::{Envelope, IdentityHash, PreKeyBundle, WakeClass};

mod account;
mod blobs;
mod gif;
mod keys;
mod kt;
mod msg;
mod push;
mod sync;
mod ws;
pub use account::{ChallengeQuery, RegisterRequest};
pub use blobs::MAX_BLOB_BYTES;
pub use gif::{warm_gif_trending, GifProxyParams, GifSearchParams};
pub use keys::{OneTimeKeysRequest, MAX_ONE_TIME_KEYS};
pub use kt::ConsistencyQuery;
pub use push::{PushRegisterRequest, PushUnregisterRequest};
pub use sync::MAX_SYNC_BLOB_BYTES;
use ws::ServerFrame;

/// Max request body. Generous for a bundle with many one-time keys, tight enough to
/// blunt memory-exhaustion attempts.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Build the router. Pass the shared [`AppState`] in.
pub fn app(state: AppState) -> Router {
    // JSON/control endpoints get a tight body cap.
    let core = Router::new()
        .route("/v1/register", post(account::register))
        .route("/v1/bundle/{hash}", get(keys::fetch_bundle))
        .route("/v1/onetimekeys", post(keys::upload_one_time_keys))
        .route("/v1/keys/count/{hash}", get(keys::one_time_key_count))
        .route("/v1/messages", post(msg::send_message))
        .route("/v1/challenge", get(account::challenge))
        .route("/v1/account/delete", post(account::delete_account))
        .route("/v1/push/register", post(push::push_register))
        .route("/v1/push/unregister", post(push::push_unregister))
        .route("/v1/callkey", post(push::publish_call_key))
        .route("/v1/callkey/{hash}", get(push::fetch_call_key))
        .route("/v1/gif/search", get(gif::gif_search))
        .route("/v1/gif/trending", get(gif::gif_trending))
        .route("/v1/gif/proxy", get(gif::gif_proxy))
        .route("/v1/ws", get(ws::ws_upgrade))
        .route("/v1/call/{id}", get(ws::call_upgrade))
        .route("/v1/call/quic", get(ws::quic_info))
        // Key Transparency surface.
        .route("/v1/kt/pubkey", get(kt::kt_pubkey))
        .route("/v1/kt/sth", get(kt::kt_sth))
        .route("/v1/kt/proof/{hash}", get(kt::kt_proof))
        .route("/v1/kt/consistency", get(kt::kt_consistency))
        // Multi-device surface (capability-gated on the client side).
        .route("/v1/capabilities", get(account::capabilities))
        .route("/v1/kt/roster", post(kt::publish_roster))
        .route("/v1/kt/roster/{hash}", get(kt::kt_roster))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    // Attachment blobs (opaque, already E2E-encrypted) get a larger cap.
    let blobs = Router::new()
        .route("/v1/blobs", post(blobs::upload_blob))
        .route("/v1/blobs/{id}", get(blobs::download_blob))
        .layer(DefaultBodyLimit::max(MAX_BLOB_BYTES));

    // History-sync + provisioning blobs (opaque; sealed client-side under a password/PIN
    // + link secret, or a link secret alone for provisioning).
    let sync = Router::new()
        .route("/v1/sync", post(sync::upload_sync_blob))
        .route(
            "/v1/sync/{id}",
            get(sync::download_sync_blob).put(sync::put_sync_blob),
        )
        .layer(DefaultBodyLimit::max(MAX_SYNC_BLOB_BYTES));

    // The access gate is the OUTERMOST layer: in token/stealth mode (and for the IP
    // allowlist) a request is rejected before routing, body parsing, or any handler
    // logic — a bug anywhere below is unreachable without the token.
    core.merge(blobs)
        .merge(sync)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::access::gate,
        ))
        .with_state(state)
}

// ─────────────────────────── REST: send message ───────────────────────────

/// Pseudonymized rate-limit key for the caller. The trusted reverse proxy supplies the
/// real client IP in `X-Real-IP` and overwrites any client-supplied one (see
/// `deploy/Caddyfile`). In prod a missing/empty header means the request did not traverse
/// that proxy, so there is no trustworthy identity to key the limiter on — return `None`
/// and let the caller fail closed, rather than dumping every such request into a single
/// shared `"unknown"` bucket (a trivial all-users DoS). In dev (no proxy) fall back to a
/// constant so local testing still works.
fn client_key(headers: &HeaderMap, state: &AppState) -> Option<String> {
    let raw = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match raw {
        Some(ip) => Some(auth::pseudonymize(ip, &state.config.rate_salt)),
        None if state.config.prod => None,
        None => Some(auth::pseudonymize("unknown", &state.config.rate_salt)),
    }
}

// ─────────────────────────── REST: push (content-free wake) ───────────────────────────
//
// A client may register one push endpoint (UnifiedPush-style: any HTTPS URL that wakes
// its app when POSTed). When a message is enqueued for an offline recipient, the relay
// POSTs a constant body there — no content, no sender, no recipient identity. The push
// provider learns only "this endpoint was poked at time T"; the client then drains its
// mailbox over the authenticated channel. Registration requires proof of control of the
// mailbox (signed single-use challenge), otherwise an attacker could subscribe to a
// victim's message *timing*.

// The constant wake bodies live on `WakeClass::wake_body` in `protocol-types`: they are
// deliberately identical for every user and every message, and the Android UnifiedPush
// receiver parses them back into a wake class, so relay and client read one definition.

/// Wake POST timeout — a slow push provider must not pile up tasks.
const WAKE_TIMEOUT_SECS: u64 = 10;

// ─────────────────────────── WebSocket ───────────────────────────

/// Production `Origin` policy for the WebSocket upgrades. Dev (`prod=false`) or an empty
/// allowlist permits everything. Otherwise: a browser *always* attaches `Origin` and cannot
/// be scripted into omitting it, so a **present** Origin must be allowlisted (this fences off
/// hostile cross-site pages). A **missing** Origin is a native client (desktop/mobile), which
/// sends none and authenticates on the socket itself — permit it. Origin is never our
/// authentication; treating "absent" as deny would just lock out every non-browser client.
fn origin_ok(headers: &HeaderMap, state: &AppState) -> bool {
    if !state.config.prod || state.config.allowed_origins.is_empty() {
        return true;
    }
    match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(origin) => {
            let origin = origin.trim_end_matches('/');
            state.config.allowed_origins.iter().any(|o| o == origin)
        }
        None => true,
    }
}
