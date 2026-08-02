//! SP-10 (second half) — a **distributed** one-time-key drain must not empty a mailbox.
//!
//! `/v1/bundle/{hash}` consumes one one-time key per call, is unauthenticated by design,
//! and is addressed by a publicly computable hash. The `bundle:{key}` limiter is per
//! *client*, so it bounds one address (60/min ⇒ a 100-key stock in about two minutes) and
//! does nothing about the same drain spread over many addresses. Once the stock is gone
//! every new session falls back to the single **reusable** fallback pre-key, so one later
//! key compromise exposes the initiating message of every session established meanwhile.
//!
//! The floor is per *recipient* and engages only inside the reserve band, and over-budget
//! fetches get the fallback key rather than an error — the same answer a fully drained
//! mailbox already gives, so nothing fails. These tests pin all three properties:
//! the stock survives a distributed drain, the endpoint keeps working while it does, and
//! an account with no fallback key is never held back (that would be a denial of service
//! dressed up as a defence).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use crypto_core::ratchet::RatchetEngine;
use kt_log::KtEntry;
use protocol_types::{IdentityHash, PreKeyBundle};
use serde_json::{json, Value};
use server::{app, AppState};
use tower::ServiceExt;

// ─────────────────────────── helpers ───────────────────────────

/// GET as a *specific* client address. The per-client `bundle:{key}` limiter keys on the
/// pseudonymized `x-real-ip`, so varying it is how a test spreads a drain across the
/// botnet the per-client limit cannot see.
async fn get_from(state: &AppState, uri: &str, ip: &str) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-real-ip", ip)
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

/// Register `engine` under `account_id` with `n` one-time keys, and a fallback key unless
/// `fallback` is false (accounts registered before fallback keys existed have none).
async fn register(
    state: &AppState,
    engine: &mut RatchetEngine,
    account_id: &str,
    n: usize,
    fallback: bool,
) -> String {
    let one_time_keys = engine.generate_one_time_keys(n);
    let fallback_key = fallback.then(|| engine.generate_fallback_key());
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
    let mut body = json!({
        "entry": serde_json::to_value(&entry).unwrap(),
        "one_time_keys": serde_json::to_value(&one_time_keys).unwrap(),
    });
    if let Some(fb) = fallback_key {
        body["fallback_key"] = Value::String(fb);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "registration should succeed");
    hash
}

/// Remaining fresh keys for `hash`, read straight out of the relay's directory. The
/// endpoint deliberately publishes only a coarse bucket (SP-10, first half), so the test
/// reads the state rather than reinstating the oracle it closed.
fn stock(state: &AppState, hash: &str) -> usize {
    state.inner.lock().unwrap().directory[hash]
        .one_time_keys
        .len()
}

/// Drain `n` bundles, each from a **different** client address, and return the keys served.
async fn drain(state: &AppState, hash: &str, n: usize) -> Vec<String> {
    let mut served = Vec::new();
    for i in 0..n {
        let (status, body) = get_from(
            state,
            &format!("/v1/bundle/{hash}"),
            &format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a bundle fetch must always answer");
        let bundle: PreKeyBundle = serde_json::from_slice(&body).unwrap();
        served.push(bundle.one_time_key);
    }
    served
}

// ─────────────────────────── tests ───────────────────────────

/// The finding itself: a drain spread over many addresses used to take the whole stock.
/// It must now stall inside the reserve band, having spent only that band's window budget.
#[tokio::test]
async fn a_distributed_drain_cannot_empty_a_mailbox() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let hash = register(&state, &mut bob, "bob-acct", 100, true).await;

    // 200 fetches, every one from a different address: past the per-client limiter, and
    // twice the entire published stock.
    let served = drain(&state, &hash, 200).await;

    let left = stock(&state, &hash);
    assert!(
        left >= server::http::OTK_DRAIN_RESERVE - server::http::OTK_DRAIN_PER_WINDOW as usize,
        "the drain must stall inside the reserve band, {left} keys left"
    );
    // Only the band's own window budget may be taken out of the band.
    assert!(
        left <= server::http::OTK_DRAIN_RESERVE,
        "everything above the band is still handed out freely, {left} keys left"
    );

    // Every fetch was answered, and the ones over the floor got the (reusable) fallback
    // key — the same answer a fully drained mailbox already gives. Nothing errored, so no
    // sender is left unable to start a session.
    let unique = served
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(
        unique,
        100 - left + 1,
        "distinct keys served = the fresh ones consumed, plus the one reused fallback"
    );
    let fallback = served.last().unwrap();
    assert!(
        served.iter().filter(|k| *k == fallback).count() > 100,
        "over the floor the fallback key is served repeatedly, not an error"
    );
}

/// Above the band nothing is metered: the common case must be untouched, including the
/// legitimate burst where every device of a busy group fetches a new member's bundle.
#[tokio::test]
async fn hand_outs_above_the_reserve_band_are_not_metered() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let hash = register(&state, &mut bob, "bob-acct", 100, true).await;

    let n = 100 - server::http::OTK_DRAIN_RESERVE;
    let served = drain(&state, &hash, n).await;

    assert_eq!(
        stock(&state, &hash),
        server::http::OTK_DRAIN_RESERVE,
        "every fetch above the band consumed a fresh key"
    );
    assert_eq!(
        served
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        n,
        "all distinct: no fallback key was served while the stock was healthy"
    );
}

/// The floor must never become the denial it prevents. An account with no fallback key
/// (registered before fallback keys existed) would answer `409 no keys available` if a
/// fresh key were held back — nobody could start a session with that user at all.
#[tokio::test]
async fn an_account_with_no_fallback_key_is_never_held_back() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let hash = register(&state, &mut bob, "bob-acct", 40, false).await;

    let served = drain(&state, &hash, 40).await;

    assert_eq!(stock(&state, &hash), 0, "every fresh key was still served");
    assert_eq!(
        served
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        40,
        "all distinct — no key was withheld and none was reused"
    );
    // Only now, with nothing left to serve, does the endpoint refuse.
    let (status, _) = get_from(&state, &format!("/v1/bundle/{hash}"), "10.9.9.9").await;
    assert_eq!(status, StatusCode::CONFLICT);
}

/// An empty stock must not burn the window budget: those fetches consume no key, and
/// charging them would leave the mailbox metered-out the instant its owner replenishes.
#[tokio::test]
async fn an_empty_stock_does_not_spend_the_window_budget() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let hash = register(&state, &mut bob, "bob-acct", 0, true).await;

    // Fetches against an empty stock — all served the fallback key, none metered.
    drain(&state, &hash, 50).await;

    // The owner replenishes; the band's budget must be intact for the fresh keys.
    let keys = bob.generate_one_time_keys(20);
    let msg = protocol_types::one_time_keys_signing_message(&hash, &keys);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/onetimekeys")
        .header("content-type", "application/json")
        .header("x-real-ip", "10.0.0.1")
        .body(Body::from(
            json!({
                "identity_hash": hash,
                "one_time_keys": keys,
                "signature": bob.sign(&msg),
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(stock(&state, &hash), 20);

    let served = drain(&state, &hash, 2).await;
    assert_eq!(
        stock(&state, &hash),
        18,
        "the replenished stock is still reachable at the metered rate"
    );
    assert_eq!(
        served
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        2,
        "both fetches got fresh keys, not the fallback"
    );
}
