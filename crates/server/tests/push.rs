//! End-to-end tests for content-free push: authenticated registration, wake dispatch
//! to a real (mock) push receiver over real HTTP, debouncing, and unregistration.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::Router;
use crypto_core::ratchet::RatchetEngine;
use kt_log::KtEntry;
use protocol_types::{
    push_register_signing_message, push_unregister_signing_message, Envelope, IdentityHash,
    PayloadKind,
};
use serde_json::{json, Value};
use server::{app, AppState, Config};
use tower::ServiceExt;

// ─────────────────────────── helpers ───────────────────────────

async fn post_json(state: &AppState, uri: &str, body: Value) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

/// Register `engine` under `account_id` (KT claim + directory entry). Returns the hash.
async fn register(state: &AppState, engine: &RatchetEngine, account_id: &str) -> String {
    let hash = IdentityHash::from_identifier(account_id)
        .as_str()
        .to_string();
    let entry = KtEntry::new_claim(
        hash.clone(),
        engine.identity_key(),
        engine.signing_key(),
        100,
        |p| engine.sign(p),
    );
    let (status, _) = post_json(
        state,
        "/v1/register",
        json!({ "entry": entry, "one_time_keys": ["k1", "k2"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    hash
}

async fn fresh_nonce(state: &AppState, hash: &str) -> String {
    let (_, body) = get(state, &format!("/v1/challenge?hash={hash}")).await;
    serde_json::from_slice::<Value>(&body).unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A minimal envelope addressed to `to`.
fn envelope(to: &str, msg_id: &str) -> Value {
    envelope_class(to, msg_id, protocol_types::WakeClass::Normal)
}

fn envelope_class(to: &str, msg_id: &str, wake: protocol_types::WakeClass) -> Value {
    serde_json::to_value(Envelope {
        to: IdentityHash::from_hex(to).unwrap(),
        ciphertext: "b3BhcXVl".into(),
        kind: PayloadKind::Message,
        msg_id: msg_id.to_string(),
        expires_at: None,
        wake,
        raw_identifier: None,
    })
    .unwrap()
}

/// Mock push provider: records every POST (body) it receives. Returns (url, hits).
async fn mock_push_receiver() -> (String, Arc<Mutex<Vec<String>>>) {
    let hits: Arc<Mutex<Vec<String>>> = Arc::default();
    let recorded = hits.clone();
    let router = Router::new().route(
        "/up",
        post(move |body: String| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().unwrap().push(body);
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}/up"), hits)
}

/// Poll until `hits` reaches `n` (or time out) — wake POSTs are fire-and-forget.
async fn wait_for_hits(hits: &Arc<Mutex<Vec<String>>>, n: usize) {
    for _ in 0..100 {
        if hits.lock().unwrap().len() >= n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("push receiver never got {n} wake(s)");
}

// ─────────────────────────── tests ───────────────────────────

#[tokio::test]
async fn offline_message_fires_one_content_free_wake() {
    // Debounce window large → a burst of messages must produce exactly one wake.
    let state = AppState::new(Config {
        wake_debounce_secs: 3600,
        ..Config::default()
    });
    let (endpoint, hits) = mock_push_receiver().await;

    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-push").await;

    // Authenticated registration of the endpoint.
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_register_signing_message(&bob_hash, &endpoint, &nonce));
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Two quick messages while Bob is offline.
    for id in ["m1", "m2"] {
        let (status, _) = post_json(&state, "/v1/messages", envelope(&bob_hash, id)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    wait_for_hits(&hits, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let got = hits.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "burst must be debounced to one wake");
    // The wake is content-free: a constant, identical for every user and message.
    assert_eq!(got[0], "wake");
}

#[tokio::test]
async fn zero_debounce_wakes_per_message_and_unregister_stops_wakes() {
    let state = AppState::new(Config {
        wake_debounce_secs: 0,
        ..Config::default()
    });
    let (endpoint, hits) = mock_push_receiver().await;

    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-push2").await;

    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_register_signing_message(&bob_hash, &endpoint, &nonce));
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    post_json(&state, "/v1/messages", envelope(&bob_hash, "m1")).await;
    post_json(&state, "/v1/messages", envelope(&bob_hash, "m2")).await;
    wait_for_hits(&hits, 2).await;

    // Unregister (authenticated) → further messages fire nothing.
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_unregister_signing_message(&bob_hash, &nonce));
    let (status, _) = post_json(
        &state,
        "/v1/push/unregister",
        json!({ "hash": bob_hash, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    post_json(&state, "/v1/messages", envelope(&bob_hash, "m3")).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(hits.lock().unwrap().len(), 2, "no wake after unregister");
}

#[tokio::test]
async fn call_classes_bypass_debounce_and_none_class_never_wakes() {
    use protocol_types::WakeClass;
    // Huge message debounce so only the call class can produce extra wakes.
    let state = AppState::new(Config {
        wake_debounce_secs: 3600,
        call_wake_min_secs: 0,
        ..Config::default()
    });
    let (endpoint, hits) = mock_push_receiver().await;

    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-push-classes").await;
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_register_signing_message(&bob_hash, &endpoint, &nonce));
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // None-class traffic (receipt/typing shaped) fires nothing at all.
    post_json(
        &state,
        "/v1/messages",
        envelope_class(&bob_hash, "n1", WakeClass::None),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(hits.lock().unwrap().is_empty(), "None class must not wake");

    // A normal message claims the (huge) debounce window…
    post_json(&state, "/v1/messages", envelope(&bob_hash, "m1")).await;
    wait_for_hits(&hits, 1).await;
    // …a second normal one is debounced away…
    post_json(&state, "/v1/messages", envelope(&bob_hash, "m2")).await;
    // …but a call offer still wakes immediately, with the call-class body.
    post_json(
        &state,
        "/v1/messages",
        envelope_class(&bob_hash, "c1", WakeClass::Call),
    )
    .await;
    wait_for_hits(&hits, 2).await;
    // A cancellation/winner control is urgent too, but carries a distinct constant
    // body so locked Android never mistakes it for a request to start ringing.
    post_json(
        &state,
        "/v1/messages",
        envelope_class(&bob_hash, "x1", WakeClass::CallControl),
    )
    .await;
    wait_for_hits(&hits, 3).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let got = hits.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![
            "wake".to_string(),
            "wake-call".to_string(),
            "wake-call-control".to_string()
        ]
    );
}

/// A ring offer is throttled per recipient (offer spam must not become a battery DoS),
/// but a terminal control never is: the cancellation that stops a device ringing cannot
/// be merged away by a debounce slot, however many controls a call produces.
#[tokio::test]
async fn every_terminal_control_wakes_even_under_a_ring_throttle() {
    use protocol_types::WakeClass;
    // Both throttles set to an hour: only a class that bypasses them can wake twice.
    let state = AppState::new(Config {
        wake_debounce_secs: 3600,
        call_wake_min_secs: 3600,
        ..Config::default()
    });
    let (endpoint, hits) = mock_push_receiver().await;

    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-control-burst").await;
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_register_signing_message(&bob_hash, &endpoint, &nonce));
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // First ring wakes; a second offer inside the window rides on it.
    post_json(
        &state,
        "/v1/messages",
        envelope_class(&bob_hash, "c1", WakeClass::Call),
    )
    .await;
    wait_for_hits(&hits, 1).await;
    post_json(
        &state,
        "/v1/messages",
        envelope_class(&bob_hash, "c2", WakeClass::Call),
    )
    .await;
    // Every control of one answered call — winner, terminal, sibling self-terminal —
    // wakes on its own.
    for (index, id) in ["x1", "x2", "x3"].iter().enumerate() {
        post_json(
            &state,
            "/v1/messages",
            envelope_class(&bob_hash, id, WakeClass::CallControl),
        )
        .await;
        wait_for_hits(&hits, 2 + index).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        hits.lock().unwrap().clone(),
        vec![
            "wake-call".to_string(),
            "wake-call-control".to_string(),
            "wake-call-control".to_string(),
            "wake-call-control".to_string(),
        ],
        "the ring is throttled, the controls are not"
    );
}

/// The bound `claim_wake` relies on for the always-wakes control class: the envelope
/// rate limiter refuses a flood from one sender address, so an unthrottled wake class
/// cannot be turned into a battery DoS.
#[tokio::test]
async fn a_control_flood_is_bounded_by_the_sender_rate_limit() {
    use protocol_types::WakeClass;
    let state = AppState::new(Config::default());
    let bob_hash = IdentityHash::from_identifier("bob-control-flood")
        .as_str()
        .to_string();
    // 60 envelopes per minute per client address (RateLimiter::new(60, 60)).
    for i in 0..60 {
        let (status, _) = post_json(
            &state,
            "/v1/messages",
            envelope_class(&bob_hash, &format!("x{i}"), WakeClass::CallControl),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "envelope {i} inside the window"
        );
    }
    let (status, _) = post_json(
        &state,
        "/v1/messages",
        envelope_class(&bob_hash, "x60", WakeClass::CallControl),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn fcm_registration_refused_without_fcm_config() {
    let state = AppState::default(); // no FCM sender attached
    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-fcm-gate").await;

    let endpoint = format!("fcm:{}", "t".repeat(64));
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_register_signing_message(&bob_hash, &endpoint, &nonce));
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_requires_proof_of_mailbox_control() {
    let state = AppState::default();
    let (endpoint, _) = mock_push_receiver().await;

    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-push3").await;

    // An attacker (different key) tries to subscribe to Bob's message timing.
    let mallory = RatchetEngine::new();
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = mallory.sign(&push_register_signing_message(&bob_hash, &endpoint, &nonce));
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A signature over a *different* endpoint must not authorize this one (binding).
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_register_signing_message(
        &bob_hash,
        "http://attacker.example/up",
        &nonce,
    ));
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Nonces are single-use: replaying a consumed one fails even with a valid signature.
    let nonce = fresh_nonce(&state, &bob_hash).await;
    let sig = bob.sign(&push_register_signing_message(&bob_hash, &endpoint, &nonce));
    let body = json!({ "hash": bob_hash, "endpoint": endpoint, "nonce": nonce, "signature": sig });
    let (status, _) = post_json(&state, "/v1/push/register", body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post_json(&state, "/v1/push/register", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─────────────────────── call-control key shelf ───────────────────────

/// Build a call-key binding signed by `engine` (standing in for a device's roster key).
fn call_binding(hash: &str, engine: &RatchetEngine, call_key: &str, created_at: u64) -> Value {
    let signing_key = call_signing_key();
    let payload = {
        let mut v = Vec::new();
        v.extend_from_slice(b"sona-call-key-v1");
        for field in [
            hash.as_bytes(),
            b"0".as_slice(),
            call_key.as_bytes(),
            signing_key.as_bytes(),
        ] {
            v.extend_from_slice(&(field.len() as u64).to_be_bytes());
            v.extend_from_slice(field);
        }
        v.extend_from_slice(&created_at.to_be_bytes());
        v
    };
    json!({
        "device_id": "0",
        "call_key": call_key,
        "call_signing_key": signing_key,
        "created_at": created_at,
        "signature": engine.sign(&payload),
    })
}

/// The Ed25519 half published alongside the capsule key (any 32 bytes: the relay stores
/// it for mailbox challenges, and these tests never authenticate with it).
fn call_signing_key() -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    STANDARD_NO_PAD.encode([7u8; 32])
}

fn a_call_key() -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    STANDARD_NO_PAD.encode([9u8; 32])
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn publish_call_key(
    state: &AppState,
    hash: &str,
    engine: &RatchetEngine,
    call_key: &str,
    created_at: u64,
    signer: &RatchetEngine,
) -> StatusCode {
    let nonce = fresh_nonce(state, hash).await;
    let msg = protocol_types::call_key_publish_signing_message(hash, call_key, created_at, &nonce);
    let (status, _) = post_json(
        state,
        "/v1/callkey",
        json!({
            "hash": hash,
            "account_hash": hash,
            "nonce": nonce,
            "signature": signer.sign(&msg),
            "binding": call_binding(hash, engine, call_key, created_at),
        }),
    )
    .await;
    status
}

#[tokio::test]
async fn a_call_key_shelf_accepts_only_its_own_device_and_never_goes_backwards() {
    let state = AppState::new(Config::default());
    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-callkey").await;
    let now = unix_now();

    assert_eq!(
        publish_call_key(&state, &bob_hash, &bob, &a_call_key(), now, &bob).await,
        StatusCode::OK
    );
    let (status, body) = get(&state, &format!("/v1/callkey/{bob_hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let served: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(served["call_key"].as_str().unwrap(), a_call_key());

    // Somebody else's signature over the challenge cannot write this shelf.
    let mallory = RatchetEngine::new();
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    let other_key = STANDARD_NO_PAD.encode([4u8; 32]);
    assert_eq!(
        publish_call_key(&state, &bob_hash, &bob, &other_key, now + 1, &mallory).await,
        StatusCode::UNAUTHORIZED
    );

    // A replayed older publication is refused: the device is listening with the newer key.
    assert_eq!(
        publish_call_key(&state, &bob_hash, &bob, &other_key, now - 10, &bob).await,
        StatusCode::CONFLICT
    );
    // A key minted far in the future would out-rank every honest later publication.
    assert_eq!(
        publish_call_key(&state, &bob_hash, &bob, &other_key, now + 86_400, &bob).await,
        StatusCode::BAD_REQUEST
    );
    // The live key is still the first one.
    let (_, body) = get(&state, &format!("/v1/callkey/{bob_hash}")).await;
    let served: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(served["call_key"].as_str().unwrap(), a_call_key());

    // A newer one from the device itself does replace it.
    assert_eq!(
        publish_call_key(&state, &bob_hash, &bob, &other_key, now + 5, &bob).await,
        StatusCode::OK
    );
    let (_, body) = get(&state, &format!("/v1/callkey/{bob_hash}")).await;
    let served: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(served["call_key"].as_str().unwrap(), other_key);
}

#[tokio::test]
async fn a_malformed_or_absent_call_key_is_refused_not_guessed() {
    let state = AppState::new(Config::default());
    let bob = RatchetEngine::new();
    let bob_hash = register(&state, &bob, "bob-callkey-bad").await;

    // Nothing published yet.
    let (status, _) = get(&state, &format!("/v1/callkey/{bob_hash}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get(&state, "/v1/callkey/not-a-hash").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A key that is not 32 bytes never reaches signature verification.
    assert_eq!(
        publish_call_key(&state, &bob_hash, &bob, "short", unix_now(), &bob).await,
        StatusCode::BAD_REQUEST
    );
}
