//! Multi-device Phase 1 integration: device rosters in the KT log, per-device
//! mailboxes in the directory, and the opaque history-sync blob store.
//!
//! Drives the real Axum app with the real client crypto engine. If the server accepted
//! a rogue roster, skipped a proof, or could read a history blob, this would catch it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use crypto_core::ratchet::RatchetEngine;
use kt_log::{
    verify_roster_inclusion_b64, verify_sth_b64, DeviceRecord, KtEntry, KtRosterEntry,
    SignedTreeHead, PRIMARY_DEVICE_ID,
};
use protocol_types::{device_mailbox_hash, IdentityHash};
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

async fn post_bytes(state: &AppState, uri: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
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

/// Register `engine` as an account; returns its (account) hash.
async fn register(state: &AppState, engine: &mut RatchetEngine, account_id: &str) -> String {
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
    let one_time_keys = engine.generate_one_time_keys(2);
    let (status, _) = post_json(
        state,
        "/v1/register",
        json!({ "entry": entry, "one_time_keys": one_time_keys }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    hash
}

fn primary_record(engine: &RatchetEngine, hash: &str) -> DeviceRecord {
    DeviceRecord::new(
        hash,
        PRIMARY_DEVICE_ID.into(),
        engine.identity_key(),
        engine.signing_key(),
        100,
        |p| engine.sign(p),
    )
}

fn linked_record(engine: &RatchetEngine, hash: &str, device_id: &str) -> DeviceRecord {
    DeviceRecord::new(
        hash,
        device_id.into(),
        engine.identity_key(),
        engine.signing_key(),
        200,
        |p| engine.sign(p),
    )
}

fn roster(
    account: &RatchetEngine,
    hash: &str,
    seq: u64,
    devices: Vec<DeviceRecord>,
) -> KtRosterEntry {
    KtRosterEntry::new(seq, hash.into(), devices, 300, |p| account.sign(p))
}

// ─────────────────────────── tests ───────────────────────────

#[tokio::test]
async fn capabilities_are_advertised() {
    let state = AppState::default();
    let (status, body) = get(&state, "/v1/capabilities").await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let caps: Vec<&str> = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(caps.contains(&protocol_types::CAP_MULTI_DEVICE));
    assert!(caps.contains(&protocol_types::CAP_HISTORY_SYNC));
}

#[tokio::test]
async fn roster_publish_fetch_verify_and_device_mailbox_lifecycle() {
    let state = AppState::default();
    let pinned = state.inner.lock().unwrap().kt.verifying_key_b64();

    let mut primary = RatchetEngine::new();
    let hash = register(&state, &mut primary, "alice-acct").await;

    // A linked device with its own, fresh Olm identity.
    let mut linked = RatchetEngine::new();
    let device_id = "ab".repeat(16);
    let devices = vec![
        primary_record(&primary, &hash),
        linked_record(&linked, &hash, &device_id),
    ];

    // A rogue roster signed by the linked (non-account) key is refused.
    let rogue = roster(&linked, &hash, 0, devices.clone());
    let (status, _) = post_json(&state, "/v1/kt/roster", json!(rogue)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // No roster yet → 404 (single-device account, old-client behavior preserved).
    let (status, _) = get(&state, &format!("/v1/kt/roster/{hash}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The genuine roster (account-signed) is accepted.
    let good = roster(&primary, &hash, 0, devices.clone());
    let (status, _) = post_json(&state, "/v1/kt/roster", json!(good)).await;
    assert_eq!(status, StatusCode::OK);

    // Epoch replay is refused (continuity, like a binding chain).
    let replay = roster(&primary, &hash, 0, devices.clone());
    let (status, _) = post_json(&state, "/v1/kt/roster", json!(replay)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Fetch + client-side verification: pinned STH, Merkle inclusion of the roster
    // leaf, and semantic validation against the KT-proven account binding.
    let (status, body) = get(&state, &format!("/v1/kt/roster/{hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let fetched: KtRosterEntry = serde_json::from_value(v["roster"].clone()).unwrap();
    let sth: SignedTreeHead = serde_json::from_value(v["sth"].clone()).unwrap();
    let index = v["index"].as_u64().unwrap();
    let proof_b64 = v["proof_b64"].as_str().unwrap();
    assert!(verify_sth_b64(&pinned, &sth));
    assert!(verify_roster_inclusion_b64(
        &sth, &fetched, index, proof_b64
    ));
    let (_, entry_body) = get(&state, &format!("/v1/kt/proof/{hash}")).await;
    let entry: KtEntry = serde_json::from_value(
        serde_json::from_slice::<Value>(&entry_body).unwrap()["entry"].clone(),
    )
    .unwrap();
    assert_eq!(fetched.validate_against(&entry), Ok(()));

    // The linked device got a directory record under its derived mailbox: it can
    // replenish one-time keys (signed by ITS device key) and then serve bundles.
    let mailbox = device_mailbox_hash(&hash, &device_id)
        .unwrap()
        .as_str()
        .to_string();
    assert_ne!(mailbox, hash);
    let otks = linked.generate_one_time_keys(2);
    let msg = protocol_types::one_time_keys_signing_message(&mailbox, &otks);
    let sig = linked.sign(&msg);
    let (status, _) = post_json(
        &state,
        "/v1/onetimekeys",
        json!({ "identity_hash": mailbox, "one_time_keys": otks, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = get(&state, &format!("/v1/bundle/{mailbox}")).await;
    assert_eq!(status, StatusCode::OK);
    let bundle: protocol_types::PreKeyBundle = serde_json::from_slice(&body).unwrap();
    assert_eq!(bundle.identity_key, linked.identity_key());
    // A sender can establish a real session to the linked device from that bundle.
    let mut sender = RatchetEngine::new();
    sender.establish_outbound(&bundle).unwrap();

    // Removal: epoch 1 without the linked device revokes its mailbox record. A live
    // delivery channel on that mailbox is told why and then dropped (kick), so the
    // zombie device cannot keep an authenticated socket after the revocation.
    let (kick_tx, mut kick_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    state
        .inner
        .lock()
        .unwrap()
        .live
        .insert(mailbox.clone(), vec![kick_tx]);
    let removal = roster(&primary, &hash, 1, vec![primary_record(&primary, &hash)]);
    let (status, _) = post_json(&state, "/v1/kt/roster", json!(removal)).await;
    assert_eq!(status, StatusCode::OK);
    let kicked = kick_rx
        .recv()
        .await
        .expect("revoked frame sent to live socket");
    assert_eq!(kicked, r#"{"type":"revoked"}"#);
    assert!(kick_rx.recv().await.is_none(), "channel dropped after kick");
    assert!(!state.inner.lock().unwrap().live.contains_key(&mailbox));
    let (status, _) = get(&state, &format!("/v1/bundle/{mailbox}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The account's own (primary) record is untouched.
    let (status, _) = get(&state, &format!("/v1/bundle/{hash}")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn history_sync_blob_round_trip_is_opaque_to_the_relay() {
    let state = AppState::default();

    // Sealed client-side under a PIN + link secret; the relay sees only ciphertext.
    let link_secret = crypto_core::sync::generate_link_secret();
    let history = b"exported chat history: hello bob, hello carol";
    let blob = crypto_core::sync::seal_history("2846", &link_secret, history).unwrap();
    assert!(!blob.windows(5).any(|w| w == b"hello"));

    let (status, body) = post_bytes(&state, "/v1/sync", blob.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let id = v["sync_id"].as_str().unwrap();

    let (status, fetched) = get(&state, &format!("/v1/sync/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, blob);
    // Only the right PIN + link secret open it.
    assert_eq!(
        crypto_core::sync::open_history("2846", &link_secret, &fetched).unwrap(),
        history
    );
    assert!(crypto_core::sync::open_history("0000", &link_secret, &fetched).is_err());

    // Unknown capability id → 404.
    let (status, _) = get(&state, "/v1/sync/00000000000000000000000000000000").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn roster_survives_restart_via_db_replay() {
    let path = {
        use rand::RngCore;
        let mut n = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut n);
        std::env::temp_dir()
            .join(format!(
                "sona-md-test-{}.sqlite",
                n.iter().map(|x| format!("{x:02x}")).collect::<String>()
            ))
            .to_string_lossy()
            .into_owned()
    };
    let storage_key = [7u8; 32];
    let kt_seed = kt_log::KtLog::generate().signing_key_seed_b64();

    let mut primary = RatchetEngine::new();
    let mut linked = RatchetEngine::new();
    let device_id = "cd".repeat(16);
    let hash;
    {
        let db = server::Db::open(&path, &storage_key).unwrap();
        let state = AppState::persistent(
            server::Config::default(),
            kt_log::KtLog::from_seed_b64(&kt_seed).unwrap(),
            db,
        );
        hash = register(&state, &mut primary, "restart-acct").await;
        let devices = vec![
            primary_record(&primary, &hash),
            linked_record(&linked, &hash, &device_id),
        ];
        let r = roster(&primary, &hash, 0, devices);
        let (status, _) = post_json(&state, "/v1/kt/roster", json!(r)).await;
        assert_eq!(status, StatusCode::OK);
        // Seed the linked mailbox with a one-time key so the restarted relay can serve it.
        let mailbox = device_mailbox_hash(&hash, &device_id)
            .unwrap()
            .as_str()
            .to_string();
        let otks = linked.generate_one_time_keys(1);
        let msg = protocol_types::one_time_keys_signing_message(&mailbox, &otks);
        let sig = linked.sign(&msg);
        let (status, _) = post_json(
            &state,
            "/v1/onetimekeys",
            json!({ "identity_hash": mailbox, "one_time_keys": otks, "signature": sig }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // "Restart": rebuild state from the database with the same KT signing key.
    let db = server::Db::open(&path, &storage_key).unwrap();
    let state = AppState::persistent(
        server::Config::default(),
        kt_log::KtLog::from_seed_b64(&kt_seed).unwrap(),
        db,
    );
    let (status, body) = get(&state, &format!("/v1/kt/roster/{hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let fetched: KtRosterEntry = serde_json::from_value(v["roster"].clone()).unwrap();
    assert_eq!(fetched.devices.len(), 2);
    assert_eq!(fetched.seq, 0);
    // The replayed tree serves a verifiable inclusion proof for the roster leaf.
    let sth: SignedTreeHead = serde_json::from_value(v["sth"].clone()).unwrap();
    assert!(verify_roster_inclusion_b64(
        &sth,
        &fetched,
        v["index"].as_u64().unwrap(),
        v["proof_b64"].as_str().unwrap()
    ));
    // The linked device's directory record survived too.
    let mailbox = device_mailbox_hash(&hash, &device_id)
        .unwrap()
        .as_str()
        .to_string();
    let (status, _) = get(&state, &format!("/v1/bundle/{mailbox}")).await;
    assert_eq!(status, StatusCode::OK);

    let _ = std::fs::remove_file(&path);
}

/// Release/takeover lifecycle at the relay: a released name keeps its mailbox (peers
/// who missed the rename still reach the owner), refuses roster changes, rejects
/// future-dated entries (no gaming the grace window), and — once the grace passes —
/// a takeover swaps the directory record to the new owner atomically.
#[tokio::test]
async fn released_name_keeps_mailbox_and_takeover_swaps_it() {
    let state = AppState::new(server::Config {
        release_grace_secs: 0,
        ..server::Config::default()
    });
    let mut alice = RatchetEngine::new();
    let hash = register(&state, &mut alice, "alice").await;

    // Release (rotation with released = true, same keys, no key material riding along).
    let release = KtEntry::new_rotation(
        1,
        hash.clone(),
        alice.identity_key(),
        alice.signing_key(),
        alice.signing_key(),
        200,
        true,
        |p| alice.sign(p),
    );
    let (status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": release, "one_time_keys": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The mailbox (and its one-time-key stock) survives the release untouched.
    let (status, body) = get(&state, &format!("/v1/bundle/{hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["identity_key"].as_str().unwrap(), alice.identity_key());

    // No roster changes on a released name.
    let frozen = roster(&alice, &hash, 0, vec![primary_record(&alice, &hash)]);
    let (status, _) = post_json(&state, "/v1/kt/roster", json!(frozen)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // A future-dated takeover is refused outright (the grace rule compares signed
    // timestamps, so post-dating must never be accepted).
    let mut mallory = RatchetEngine::new();
    let far_future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 100_000;
    let postdated = KtEntry::new_reclaim(
        2,
        hash.clone(),
        mallory.identity_key(),
        mallory.signing_key(),
        far_future,
        |p| mallory.sign(p),
    );
    let (status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": postdated, "one_time_keys": mallory.generate_one_time_keys(2) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A honestly-dated takeover (grace = 0 here) succeeds and swaps the directory
    // record: discovery now serves the new owner's keys.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let takeover = KtEntry::new_reclaim(
        2,
        hash.clone(),
        mallory.identity_key(),
        mallory.signing_key(),
        now,
        |p| mallory.sign(p),
    );
    let (status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": takeover, "one_time_keys": mallory.generate_one_time_keys(2) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = get(&state, &format!("/v1/bundle/{hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["identity_key"].as_str().unwrap(), mallory.identity_key());

    // The old owner's chain is severed: their rotation is refused, and the new owner's
    // roster chain starts fresh at epoch 0.
    let stale = KtEntry::new_rotation(
        3,
        hash.clone(),
        alice.identity_key(),
        alice.signing_key(),
        alice.signing_key(),
        now,
        false,
        |p| alice.sign(p),
    );
    let (status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": stale, "one_time_keys": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let fresh = roster(&mallory, &hash, 0, vec![primary_record(&mallory, &hash)]);
    let (status, _) = post_json(&state, "/v1/kt/roster", json!(fresh)).await;
    assert_eq!(status, StatusCode::OK);
}

/// The relay backstops the 5-renames-per-week product limit: releases are capped per
/// signing key, and forged releases naming someone else's key cannot burn their budget.
#[tokio::test]
async fn release_rate_limit_caps_renames_per_key() {
    let state = AppState::default();
    let mut alice = RatchetEngine::new();

    // One account claims six names (a rename keeps the same keys, so from the relay's
    // view a serial renamer is one signing key releasing name after name).
    let mut hashes = Vec::new();
    for i in 0..6 {
        hashes.push(register(&state, &mut alice, &format!("alice-{i}")).await);
    }
    let release_for = |hash: &str, alice: &RatchetEngine| {
        KtEntry::new_rotation(
            1,
            hash.to_string(),
            alice.identity_key(),
            alice.signing_key(),
            alice.signing_key(),
            200,
            true,
            |p| alice.sign(p),
        )
    };
    for hash in hashes.iter().take(5) {
        let (status, _) = post_json(
            &state,
            "/v1/register",
            json!({ "entry": release_for(hash, &alice), "one_time_keys": [] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    // The sixth release inside the week is refused — and left OUT of the log.
    let (status, body) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": release_for(&hashes[5], &alice), "one_time_keys": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(String::from_utf8_lossy(&body).contains("username-change limit"));

    // A forged release naming the victim's signing key (but signed by the attacker's
    // own prev key) must not have touched the victim's budget above: verify a fresh
    // victim's budget survives a flood of such forgeries.
    let mut victim = RatchetEngine::new();
    let victim_hash = register(&state, &mut victim, "victim").await;
    let attacker = RatchetEngine::new();
    // Few enough to stay inside the generic per-client auth budget — this test is about
    // the per-key rename budget.
    for i in 0..3 {
        let forged = KtEntry::new_rotation(
            1,
            format!("{:064}", i), // arbitrary well-formed hash
            "x".into(),
            victim.signing_key(), // names the victim…
            attacker.signing_key(),
            200,
            true,
            |p| attacker.sign(p), // …but the attacker signs
        );
        let (status, _) = post_json(
            &state,
            "/v1/register",
            json!({ "entry": forged, "one_time_keys": [] }),
        )
        .await;
        assert_ne!(status, StatusCode::OK); // no chain — never appended
    }
    let (status, _) = post_json(
        &state,
        "/v1/register",
        json!({ "entry": release_for(&victim_hash, &victim), "one_time_keys": [] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "victim's own release must still work"
    );
}

// A LINKED device registers a push endpoint for its own device mailbox: the roster
// mirror gave that mailbox a directory record carrying the device's signing key, so
// the challenge-signed registration authenticates with the DEVICE key — and the
// primary's key must NOT authorize the linked mailbox (docs/NOTIFICATIONS.md §6.6).
#[tokio::test]
async fn linked_device_registers_push_for_its_device_mailbox() {
    let state = AppState::default();
    let mut primary = RatchetEngine::new();
    let linked = RatchetEngine::new();
    let hash = register(&state, &mut primary, "push-md-account").await;

    let device_id = "d".repeat(32);
    let devices = vec![
        primary_record(&primary, &hash),
        linked_record(&linked, &hash, &device_id),
    ];
    let (status, _) = post_json(
        &state,
        "/v1/kt/roster",
        json!(roster(&primary, &hash, 0, devices)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mailbox = device_mailbox_hash(&hash, &device_id)
        .unwrap()
        .as_str()
        .to_string();
    let endpoint = "https://push.example.org/up/linked";

    // The device's own signature over (mailbox|endpoint|nonce) is accepted.
    let (_, body) = get(&state, &format!("/v1/challenge?hash={mailbox}")).await;
    let nonce = serde_json::from_slice::<Value>(&body).unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let msg = protocol_types::push_register_signing_message(&mailbox, endpoint, &nonce);
    let sig = linked.sign(&msg);
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": mailbox, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The PRIMARY's signature must not authorize the linked device's mailbox.
    let (_, body) = get(&state, &format!("/v1/challenge?hash={mailbox}")).await;
    let nonce = serde_json::from_slice::<Value>(&body).unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let msg = protocol_types::push_register_signing_message(&mailbox, endpoint, &nonce);
    let sig = primary.sign(&msg);
    let (status, _) = post_json(
        &state,
        "/v1/push/register",
        json!({ "hash": mailbox, "endpoint": endpoint, "nonce": nonce, "signature": sig }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Revoking the device (roster epoch without it) also drops its push row.
    let (status, _) = post_json(
        &state,
        "/v1/kt/roster",
        json!(roster(
            &primary,
            &hash,
            1,
            vec![primary_record(&primary, &hash)]
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !state.inner.lock().unwrap().push.contains_key(&mailbox),
        "revocation must remove the device's push subscription"
    );
}
