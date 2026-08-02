//! End-to-end integration tests for the relay.
//!
//! These drive the real Axum app and the real client crypto engine (`crypto-core`),
//! so they exercise the full path: register a bundle → fetch it → Double Ratchet
//! encrypt → relay over HTTP → authenticated WebSocket delivery → decrypt. If the
//! server could see plaintext or accept forged auth, these would catch it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use crypto_core::ratchet::RatchetEngine;
use kt_log::{verify_inclusion_b64, verify_sth_b64, KtEntry};
use protocol_types::{
    one_time_keys_signing_message, CiphertextMessage, Envelope, IdentityHash, PayloadKind,
    PreKeyBundle,
};
use serde_json::{json, Value};
use server::{app, AppState};
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

/// A first-claim KT entry for `engine` under `account_id`, signed by the engine's key.
fn claim_entry(engine: &RatchetEngine, account_id: &str) -> (String, KtEntry) {
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
    (hash, entry)
}

/// Register `engine` under `account_id`, publishing `n` one-time keys. Returns the hash.
async fn register(
    state: &AppState,
    engine: &mut RatchetEngine,
    account_id: &str,
    n: usize,
) -> String {
    let one_time_keys = engine.generate_one_time_keys(n);
    let (hash, entry) = claim_entry(engine, account_id);
    let (status, _) = post_json(
        state,
        "/v1/register",
        json!({
            "entry": serde_json::to_value(&entry).unwrap(),
            "one_time_keys": serde_json::to_value(&one_time_keys).unwrap(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "registration should succeed");
    hash
}

/// Build a wire envelope: Double Ratchet ciphertext JSON-wrapped into `ciphertext`.
fn envelope(to_hash: &str, cipher: &CiphertextMessage, msg_id: &str) -> Value {
    let env = Envelope {
        to: IdentityHash::from_hex(to_hash).unwrap(),
        ciphertext: serde_json::to_string(cipher).unwrap(),
        kind: PayloadKind::Message,
        msg_id: msg_id.to_string(),
        expires_at: None,
        wake: Default::default(),
        raw_identifier: None,
    };
    serde_json::to_value(env).unwrap()
}

// ─────────────────────────── REST tests ───────────────────────────

#[tokio::test]
async fn register_fetch_bundle_and_session_setup() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 3).await;

    // Alice fetches Bob's bundle and can start a session with it.
    let (status, body) = get(&state, &format!("/v1/bundle/{bob_hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let bundle: PreKeyBundle = serde_json::from_slice(&body).unwrap();
    assert_eq!(bundle.identity_key, bob.identity_key());

    let mut alice = RatchetEngine::new();
    alice.establish_outbound(&bundle).unwrap();
    assert!(alice.has_session(&bob.identity_key()));
}

#[tokio::test]
async fn registration_rejects_bad_signature() {
    let state = AppState::default();
    let bob = RatchetEngine::new();
    let (_, mut entry) = claim_entry(&bob, "bob-acct");
    entry.signature = "AAAA".into(); // corrupt the self-signature
    let (status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": serde_json::to_value(&entry).unwrap(), "one_time_keys": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registration_refuses_to_rebind_keys_for_existing_hash() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let hash = register(&state, &mut bob, "bob-acct", 1).await;

    // An attacker who knows the hash tries to claim it afresh with their own keys.
    // The KT log rejects a second seq-0 claim for an existing username (broken chain).
    let attacker = RatchetEngine::new();
    let attacker_entry = KtEntry::new_claim(
        hash,
        attacker.identity_key(),
        attacker.signing_key(),
        100,
        |p| attacker.sign(p),
    );
    let (status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": serde_json::to_value(&attacker_entry).unwrap(), "one_time_keys": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "must not allow key hijack");
}

#[tokio::test]
async fn one_time_keys_deplete_then_replenish() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 1).await; // just 1 OTK

    // SP-10: the endpoint publishes a coarse bucket, never an exact count — an exact
    // count is a first-contact activity oracle, since each new inbound session consumes
    // exactly one key.
    let level = |body: &[u8]| {
        serde_json::from_slice::<Value>(body).unwrap()["level"]
            .as_str()
            .unwrap()
            .to_string()
    };

    let (_, body) = get(&state, &format!("/v1/keys/count/{bob_hash}")).await;
    assert_eq!(level(&body), "low");
    assert!(
        !String::from_utf8_lossy(&body).contains("remaining"),
        "the exact count must not be published"
    );

    // Consume the only key; the next bundle fetch has none left.
    assert_eq!(
        get(&state, &format!("/v1/bundle/{bob_hash}")).await.0,
        StatusCode::OK
    );
    assert_eq!(
        get(&state, &format!("/v1/bundle/{bob_hash}")).await.0,
        StatusCode::CONFLICT
    );

    // Replenish: sign an upload of 5 fresh keys with Bob's identity key.
    let keys = bob.generate_one_time_keys(5);
    let sig = bob.sign(&one_time_keys_signing_message(&bob_hash, &keys));
    let (status, _) = post_json(
        &state,
        "/v1/onetimekeys",
        json!({ "identity_hash": bob_hash, "one_time_keys": keys, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = get(&state, &format!("/v1/keys/count/{bob_hash}")).await;
    assert_eq!(level(&body), "low");
    // Sessions can be started again.
    assert_eq!(
        get(&state, &format!("/v1/bundle/{bob_hash}")).await.0,
        StatusCode::OK
    );

    // An unsigned/forged upload is rejected.
    let keys2 = bob.generate_one_time_keys(2);
    let (status, _) = post_json(
        &state,
        "/v1/onetimekeys",
        json!({ "identity_hash": bob_hash, "one_time_keys": keys2, "signature": "AAAA" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// SP-10: the count endpoint must never let a third party watch a specific user's
/// session activity. Each new inbound session consumes exactly one key, so an exact
/// remaining count was a first-contact feed for anyone who could spell a username.
#[tokio::test]
async fn the_otk_count_never_reveals_an_exact_number() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 40).await;

    let level = |body: &[u8]| {
        serde_json::from_slice::<Value>(body).unwrap()["level"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let count = || async {
        let (_, body) = get(&state, &format!("/v1/keys/count/{bob_hash}")).await;
        (level(&body), String::from_utf8_lossy(&body).to_string())
    };

    let (before, raw) = count().await;
    assert_eq!(before, "plenty");
    assert!(!raw.contains("40"), "no exact count in the body: {raw}");

    // One new session — the single event this oracle used to report — must not move it.
    assert_eq!(
        get(&state, &format!("/v1/bundle/{bob_hash}")).await.0,
        StatusCode::OK
    );
    assert_eq!(count().await.0, "plenty", "one session must be invisible");

    // Only crossing the watermark changes the answer at all.
    for _ in 0..35 {
        let _ = get(&state, &format!("/v1/bundle/{bob_hash}")).await;
    }
    assert_eq!(count().await.0, "low");
}

/// SP-19: `/v1/onetimekeys` was the only handler in the `core` router with neither a
/// trusted-client gate nor a rate limit, and it spends a directory lookup plus an
/// Ed25519 verify over a body up to 64 KiB *while holding the global mutex*. Both checks
/// now run before the verify, so a flood is rejected cheaply.
#[tokio::test]
async fn the_onetimekeys_upload_is_rate_limited_before_the_verify() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 1).await;

    // Deliberately unsigned: a rejection here proves the gate ran BEFORE the verify.
    let body = json!({
        "identity_hash": bob_hash,
        "one_time_keys": ["AAAA"],
        "signature": "not-a-signature",
    });
    let mut limited = false;
    for _ in 0..80 {
        let (status, _) = post_json(&state, "/v1/onetimekeys", body.clone()).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert!(
        limited,
        "an unmetered flood must eventually be rate limited"
    );
}

/// SP-19 / SP-04: the KT reads are the enumeration surface for a mailbox hash that is a
/// reversible SHA-256 of a human-chosen username, and they build Merkle proofs inside
/// the global mutex. They were completely unmetered.
#[tokio::test]
async fn the_kt_read_endpoints_are_metered() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 1).await;

    let mut limited = false;
    for _ in 0..80 {
        let (status, _) = get(&state, &format!("/v1/kt/proof/{bob_hash}")).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "a wordlist walk must eventually be rate limited");
    // The budget is far above any real cadence: the auditor and roster refresh poll on
    // the order of minutes, so a handful of reads on a fresh client is never touched.
    let fresh = AppState::default();
    let mut carol = RatchetEngine::new();
    let carol_hash = register(&fresh, &mut carol, "carol-acct", 1).await;
    for _ in 0..10 {
        let (status, _) = get(&fresh, &format!("/v1/kt/proof/{carol_hash}")).await;
        assert_eq!(status, StatusCode::OK);
    }
}

/// SP-11: three global ceilings were resources one actor could exhaust for everyone.
/// The KT log is the worst — unbounded, in-memory, never pruned, and replayed and
/// re-verified from the DB at every boot, so each accepted leaf is permanent, restart
/// time grows with the flood, and a memory-limited container eventually OOM-loops. A
/// per-minute limiter cannot bound something that only ever grows, so appended leaves
/// now also carry a per-client daily cap.
#[tokio::test]
async fn kt_growth_is_bounded_per_client_per_day() {
    let state = AppState::default();
    let mut refused = false;
    for i in 0..80 {
        let engine = RatchetEngine::new();
        let (_, entry) = claim_entry(&engine, &format!("kt-flood-{i}"));
        let (status, _) = post_json(
            &state,
            "/v1/register",
            json!({ "entry": entry, "one_time_keys": [] }),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused = true;
            break;
        }
        assert_eq!(status, StatusCode::OK, "claim {i} should be accepted");
    }
    assert!(
        refused,
        "a client must not be able to append unbounded permanent KT leaves"
    );
}

#[tokio::test]
async fn blob_upload_download_round_trip() {
    let state = AppState::default();
    let data = b"opaque client ciphertext \x00\x01\x02".to_vec();

    // Upload raw bytes.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/blobs")
        .body(Body::from(data.clone()))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let blob_id = serde_json::from_slice::<Value>(&body).unwrap()["blob_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Download returns the exact bytes.
    let (status, got) = get(&state, &format!("/v1/blobs/{blob_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, data);

    // Unknown id → 404.
    assert_eq!(
        get(&state, "/v1/blobs/deadbeef00").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn fallback_key_served_and_reused_when_otks_exhausted() {
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let (hash, entry) = claim_entry(&bob, "bob-acct");
    let otks = bob.generate_one_time_keys(1);
    let fallback = bob.generate_fallback_key();
    let (reg_status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": entry, "one_time_keys": otks, "fallback_key": fallback }),
    )
    .await;
    assert_eq!(reg_status, StatusCode::OK);

    let bundle_key = |body: &[u8]| {
        serde_json::from_slice::<PreKeyBundle>(body)
            .unwrap()
            .one_time_key
    };

    // First fetch consumes the single one-time key.
    let (s1, b1) = get(&state, &format!("/v1/bundle/{hash}")).await;
    assert_eq!(s1, StatusCode::OK);
    assert_ne!(bundle_key(&b1), fallback); // it was the real OTK

    // One-time keys now exhausted — the reusable fallback key is served instead of 409,
    // and it is served again on the next fetch (not consumed). No more drain-DoS.
    let (s2, b2) = get(&state, &format!("/v1/bundle/{hash}")).await;
    let (s3, b3) = get(&state, &format!("/v1/bundle/{hash}")).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(bundle_key(&b2), fallback);
    assert_eq!(bundle_key(&b3), fallback);
}

#[tokio::test]
async fn kt_proof_lets_client_verify_bundle_key() {
    // The whole point of Key Transparency: a client can cryptographically confirm that
    // the identity key it's about to trust really is the one published in the log.
    let state = AppState::default();
    let mut bob = RatchetEngine::new();
    let hash = register(&state, &mut bob, "bob-acct", 2).await;

    // Pin the server's KT key (out-of-band in reality; here via the bootstrap endpoint).
    let (_, body) = get(&state, "/v1/kt/pubkey").await;
    let pinned = serde_json::from_slice::<Value>(&body).unwrap()["pubkey"]
        .as_str()
        .unwrap()
        .to_string();

    // Fetch the bundle the sender would use, and the KT proof for that identity.
    let (_, body) = get(&state, &format!("/v1/bundle/{hash}")).await;
    let bundle: PreKeyBundle = serde_json::from_slice(&body).unwrap();

    let (status, body) = get(&state, &format!("/v1/kt/proof/{hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let entry: KtEntry = serde_json::from_value(v["entry"].clone()).unwrap();
    let index = v["index"].as_u64().unwrap();
    let proof_b64 = v["proof_b64"].as_str().unwrap();
    let sth: kt_log::SignedTreeHead = serde_json::from_value(v["sth"].clone()).unwrap();

    // Client-side checks, trusting only the pinned key and the proofs:
    assert!(
        verify_sth_b64(&pinned, &sth),
        "tree head must be signed by pinned key"
    );
    assert!(
        verify_inclusion_b64(&sth, &entry, index, proof_b64),
        "entry must be proven present in the log"
    );
    // And the key the sender would encrypt to is exactly the logged one — no swap.
    assert_eq!(entry.identity_key, bundle.identity_key);
    assert_eq!(entry.identity_key, bob.identity_key());
}

#[tokio::test]
async fn message_with_raw_identifier_is_rejected() {
    let state = AppState::default();
    let bob_hash = IdentityHash::from_identifier("bob-acct")
        .as_str()
        .to_string();
    let mut env = envelope(
        &bob_hash,
        &CiphertextMessage {
            message_type: 1,
            body: "Zm9v".into(),
        },
        "m1",
    );
    env["raw_identifier"] = json!("bob-real-uuid"); // zero-knowledge violation
    let (status, _) = post_json(&state, "/v1/messages", env).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ─────────────────────────── full WebSocket E2E ───────────────────────────

#[tokio::test]
async fn full_end_to_end_offline_then_live_delivery() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let state = AppState::default();

    // Spawn the real server on an ephemeral port, sharing the same AppState we drive
    // the REST calls against (Arc inside, so both see the same data).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });

    // Bob registers; Alice sets up a session from his bundle and sends a message
    // while Bob is OFFLINE (it must be queued).
    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 5).await;
    let bob_id = bob.identity_key();

    let (_, body) = get(&state, &format!("/v1/bundle/{bob_hash}")).await;
    let bundle: PreKeyBundle = serde_json::from_slice(&body).unwrap();
    let mut alice = RatchetEngine::new();
    let alice_id = alice.identity_key();
    alice.establish_outbound(&bundle).unwrap();

    let c1 = alice.encrypt(&bob_id, "queued hello").unwrap();
    let (status, _) = post_json(&state, "/v1/messages", envelope(&bob_hash, &c1, "m1")).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    // Bob comes online: get a challenge, sign it, open the WebSocket.
    let (_, body) = get(&state, &format!("/v1/challenge?hash={bob_hash}")).await;
    let nonce = serde_json::from_slice::<Value>(&body).unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let sig = bob.sign(&protocol_types::ws_auth_signing_message(&bob_hash, &nonce));

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws"))
        .await
        .unwrap();
    let auth_frame = json!({"type":"auth","hash":bob_hash,"nonce":nonce,"signature":sig});
    ws.send(WsMessage::Text(auth_frame.to_string()))
        .await
        .unwrap();

    // Read frames until the queued message arrives; decrypt and verify.
    let mut got_queued = false;
    while let Some(Ok(msg)) = ws.next().await {
        if let WsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            match v["type"].as_str() {
                Some("message") => {
                    let env: Envelope = serde_json::from_value(v["envelope"].clone()).unwrap();
                    let cipher: CiphertextMessage = serde_json::from_str(&env.ciphertext).unwrap();
                    let plain = bob.decrypt(&alice_id, &cipher).unwrap();
                    assert_eq!(plain, "queued hello");
                    got_queued = true;
                    break;
                }
                Some("auth_failed") => panic!("auth should have succeeded"),
                _ => {} // "ready" etc.
            }
        }
    }
    assert!(got_queued, "queued message must be delivered on connect");

    // Now test LIVE delivery: Alice sends again while Bob is connected.
    let c2 = alice.encrypt(&bob_id, "live hello").unwrap();
    let (status, _) = post_json(&state, "/v1/messages", envelope(&bob_hash, &c2, "m2")).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let mut got_live = false;
    while let Some(Ok(msg)) = ws.next().await {
        if let WsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if v["type"] == "message" {
                let env: Envelope = serde_json::from_value(v["envelope"].clone()).unwrap();
                let cipher: CiphertextMessage = serde_json::from_str(&env.ciphertext).unwrap();
                assert_eq!(bob.decrypt(&alice_id, &cipher).unwrap(), "live hello");
                got_live = true;
                break;
            }
        }
    }
    assert!(
        got_live,
        "live message must be pushed to the connected socket"
    );
}

#[tokio::test]
async fn websocket_rejects_forged_auth() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let state = AppState::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });

    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 1).await;

    // Get a valid nonce but sign it with the WRONG key (an attacker's).
    let (_, body) = get(&state, &format!("/v1/challenge?hash={bob_hash}")).await;
    let nonce = serde_json::from_slice::<Value>(&body).unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let attacker = RatchetEngine::new();
    let sig = attacker.sign(&protocol_types::ws_auth_signing_message(&bob_hash, &nonce));

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws"))
        .await
        .unwrap();
    let frame = json!({"type":"auth","hash":bob_hash,"nonce":nonce,"signature":sig});
    ws.send(WsMessage::Text(frame.to_string())).await.unwrap();

    // Server must respond auth_failed (or just close) — never "ready" or a message.
    let mut authed = false;
    while let Some(Ok(msg)) = ws.next().await {
        if let WsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if v["type"] == "ready" || v["type"] == "message" {
                authed = true;
            }
            break;
        }
    }
    assert!(
        !authed,
        "forged auth must never reach an authenticated state"
    );
}

/// SP-01 regression. The relay must refuse a signature over the **raw** nonce bytes:
/// that scheme let a hostile relay serve any other context's signing payload as the
/// "nonce" and harvest a genuine identity-key signature over it (blind signing oracle).
/// The signature below is produced by the account's real key over the real nonce — the
/// only thing wrong with it is that it is not domain-separated.
#[tokio::test]
async fn websocket_rejects_a_signature_over_the_raw_nonce() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let state = AppState::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });

    let mut bob = RatchetEngine::new();
    let bob_hash = register(&state, &mut bob, "bob-acct", 1).await;

    let (_, body) = get(&state, &format!("/v1/challenge?hash={bob_hash}")).await;
    let nonce = serde_json::from_slice::<Value>(&body).unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    // The pre-fix client behaviour: sign the base64-decoded nonce, unstructured.
    let sig = bob.sign(&vodozemac::base64_decode(&nonce).unwrap());

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws"))
        .await
        .unwrap();
    let frame = json!({"type":"auth","hash":bob_hash,"nonce":nonce,"signature":sig});
    ws.send(WsMessage::Text(frame.to_string())).await.unwrap();

    let mut authed = false;
    while let Some(Ok(msg)) = ws.next().await {
        if let WsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if v["type"] == "ready" || v["type"] == "message" {
                authed = true;
            }
            break;
        }
    }
    assert!(
        !authed,
        "a raw-nonce signature must not authenticate — that is the signing oracle"
    );
}
