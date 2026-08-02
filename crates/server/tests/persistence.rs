//! Durability test: a message queued before a restart must survive, be reloaded from the
//! encrypted database, and decrypt after a fresh boot. Also proves the directory and the
//! Key Transparency log are rebuilt across restart.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use crypto_core::ratchet::RatchetEngine;
use futures_util::{SinkExt, StreamExt};
use kt_log::{verify_inclusion_b64, verify_sth_b64, KtEntry, KtLog, SignedTreeHead};
use protocol_types::{CiphertextMessage, Envelope, IdentityHash, PayloadKind, PreKeyBundle};
use rand::RngCore;
use serde_json::{json, Value};
use server::{app, AppState, Config, Db};
use tokio_tungstenite::tungstenite::Message as Ws;
use tower::ServiceExt;

fn temp_db_path() -> String {
    let mut n = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut n);
    let hex: String = n.iter().map(|b| format!("{b:02x}")).collect();
    std::env::temp_dir()
        .join(format!("sc-persist-{hex}.sqlite"))
        .to_string_lossy()
        .into_owned()
}

async fn post_json(state: &AppState, uri: &str, body: Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    app(state.clone()).oneshot(req).await.unwrap().status()
}

async fn get_json(state: &AppState, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn claim(engine: &RatchetEngine, account_id: &str) -> (String, KtEntry) {
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

#[tokio::test]
async fn message_and_state_survive_a_restart() {
    let db_path = temp_db_path();
    let storage_key = [5u8; 32];
    // A stable KT signing key shared by both boots (so the pinned key is unchanged).
    let kt_seed = KtLog::generate().signing_key_seed_b64();
    let pinned = KtLog::from_seed_b64(&kt_seed).unwrap().verifying_key_b64();

    let mut bob = RatchetEngine::new();
    let mut alice = RatchetEngine::new();
    let alice_id = alice.identity_key();
    let (bob_hash, bob_entry) = claim(&bob, "bob");

    // ── Boot #1: register both, Alice sends to (offline) Bob. ──
    {
        let state = AppState::persistent(
            Config::default(),
            KtLog::from_seed_b64(&kt_seed).unwrap(),
            Db::open(&db_path, &storage_key).unwrap(),
        );

        let bob_otks = bob.generate_one_time_keys(5);
        assert_eq!(
            post_json(
                &state,
                "/v1/register",
                json!({ "entry": bob_entry, "one_time_keys": bob_otks }),
            )
            .await,
            StatusCode::OK
        );
        let (_, alice_entry) = claim(&alice, "alice");
        let alice_otks = alice.generate_one_time_keys(5);
        assert_eq!(
            post_json(
                &state,
                "/v1/register",
                json!({ "entry": alice_entry, "one_time_keys": alice_otks }),
            )
            .await,
            StatusCode::OK
        );

        // Alice fetches Bob's bundle, opens a session, and sends.
        let (_, bundle_v) = get_json(&state, &format!("/v1/bundle/{bob_hash}")).await;
        let bundle: PreKeyBundle = serde_json::from_value(bundle_v).unwrap();
        alice.establish_outbound(&bundle).unwrap();
        let cipher = alice
            .encrypt(&bob.identity_key(), "survives the restart")
            .unwrap();
        let envelope = Envelope {
            to: IdentityHash::from_hex(&bob_hash).unwrap(),
            ciphertext: serde_json::to_string(&cipher).unwrap(),
            kind: PayloadKind::Message,
            msg_id: "persist-1".into(),
            expires_at: None,
            wake: Default::default(),
            raw_identifier: None,
        };
        assert_eq!(
            post_json(
                &state,
                "/v1/messages",
                serde_json::to_value(&envelope).unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );
        // state (and its DB connection) dropped here — simulating shutdown.
    }

    // ── Boot #2: fresh state from the same encrypted DB + same KT key. ──
    let state = AppState::persistent(
        Config::default(),
        KtLog::from_seed_b64(&kt_seed).unwrap(),
        Db::open(&db_path, &storage_key).unwrap(),
    );

    // Directory survived: Bob's bundle is still served (with a remaining one-time key).
    let (status, bundle_v) = get_json(&state, &format!("/v1/bundle/{bob_hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let bundle: PreKeyBundle = serde_json::from_value(bundle_v).unwrap();
    assert_eq!(bundle.identity_key, bob.identity_key());

    // KT log rebuilt: the proof still verifies against the pinned key.
    let (status, proof_v) = get_json(&state, &format!("/v1/kt/proof/{bob_hash}")).await;
    assert_eq!(status, StatusCode::OK);
    let entry: KtEntry = serde_json::from_value(proof_v["entry"].clone()).unwrap();
    let index = proof_v["index"].as_u64().unwrap();
    let proof_b64 = proof_v["proof_b64"].as_str().unwrap();
    let sth: SignedTreeHead = serde_json::from_value(proof_v["sth"].clone()).unwrap();
    assert!(verify_sth_b64(&pinned, &sth));
    assert!(verify_inclusion_b64(&sth, &entry, index, proof_b64));

    // The queued message survived: Bob connects to the restarted server and receives it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(serve_state).into_make_service())
            .await
            .unwrap();
    });

    let (_, challenge) = get_json(&state, &format!("/v1/challenge?hash={bob_hash}")).await;
    let nonce = challenge["nonce"].as_str().unwrap();
    let sig = bob.sign(&protocol_types::ws_auth_signing_message(&bob_hash, nonce));

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws"))
        .await
        .unwrap();
    ws.send(Ws::Text(
        json!({ "type": "auth", "hash": bob_hash, "nonce": nonce, "signature": sig }).to_string(),
    ))
    .await
    .unwrap();

    let mut got = None;
    while let Some(Ok(Ws::Text(t))) = ws.next().await {
        let v: Value = serde_json::from_str(&t).unwrap();
        match v["type"].as_str() {
            Some("message") => {
                let env: Envelope = serde_json::from_value(v["envelope"].clone()).unwrap();
                let cipher: CiphertextMessage = serde_json::from_str(&env.ciphertext).unwrap();
                let (sender, text) = bob.decrypt_unattributed(&cipher).unwrap();
                got = Some((sender, text));
                break;
            }
            Some("ready") => break,
            _ => {}
        }
    }

    let (sender, text) = got.expect("queued message must survive the restart");
    assert_eq!(text, "survives the restart");
    assert_eq!(sender, alice_id);

    let _ = std::fs::remove_file(&db_path);
}
