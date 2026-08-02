//! SP-01 regression: the relay must not be able to use the login challenge as a blind
//! signing oracle on the account's identity key.
//!
//! The relay picks the challenge nonce and the client signs it unattended, once per
//! reconnect. When that signature covered the *raw* nonce bytes, a hostile relay could
//! serve another context's signing payload — a `KtRosterEntry` that adds an attacker's
//! device, a `KtEntry` rotation, an account-delete message — as the "nonce" and get a
//! genuine account-key signature over it. Every downstream check (KT inclusion proof,
//! roster validation, the auditor) then passes, because the signature is real.
//!
//! Both halves of the fix are exercised here against a deliberately hostile relay:
//! the length bound (a payload-shaped nonce is refused outright) and the domain
//! separator (what the client does sign is useless in any other context).

use std::sync::{Arc, Mutex};

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::Response,
    routing::get,
    Json, Router,
};
use client_core::Client;
use crypto_core::create_account_with_username;
use kt_log::verify_ed25519 as verify;

/// The hostile relay's shared state: the nonce it serves, and the Auth frame it captured.
#[derive(Clone, Default)]
struct Hostile {
    nonce: Arc<Mutex<String>>,
    captured: Arc<Mutex<Option<serde_json::Value>>>,
}

async fn challenge(State(h): State<Hostile>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "nonce": h.nonce.lock().unwrap().clone() }))
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(h): State<Hostile>) -> Response {
    ws.on_upgrade(move |socket| capture(socket, h))
}

async fn capture(mut socket: WebSocket, h: Hostile) {
    if let Some(Ok(Message::Text(t))) = socket.recv().await {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t.as_str()) {
            *h.captured.lock().unwrap() = Some(v);
        }
    }
}

/// Boot the hostile relay serving `nonce` as its challenge. Returns the client plus the
/// slot the captured Auth frame (if any) lands in.
async fn spawn_hostile(nonce: String) -> (Client, Arc<Mutex<Option<serde_json::Value>>>) {
    let h = Hostile {
        nonce: Arc::new(Mutex::new(nonce)),
        ..Default::default()
    };
    let captured = h.captured.clone();
    let router = Router::new()
        .route("/v1/challenge", get(challenge))
        .route("/v1/ws", get(ws_upgrade))
        .with_state(h);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (
        Client::new(
            format!("http://{addr}"),
            format!("ws://{addr}/v1/ws"),
            "unused-kt-pin",
        ),
        captured,
    )
}

/// The primary attack: serve a real `KtRosterEntry` signing payload as the nonce. The
/// client must never sign it — the payload is far longer than 32 bytes, so the length
/// bound rejects it before any signing happens.
#[tokio::test]
async fn a_roster_payload_served_as_the_nonce_is_never_signed() {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

    let (mut victim, _) =
        create_account_with_username("oracle-victim", "Victim-Pass-123!").unwrap();
    let victim_hash = victim.identity_hash().as_str().to_string();

    // Exactly the epoch a hostile relay would want signed: the victim's real primary
    // device plus an attacker device. Everything here is public information.
    let attacker = kt_log::DeviceRecord::new(
        &victim_hash,
        "f".repeat(32),
        "QXR0YWNrZXJJZGVudGl0eUtleUJhc2U2NEFBQUFBQUFB".into(),
        "QXR0YWNrZXJTaWduaW5nS2V5QmFzZTY0QUFBQUFBQUFBQQ".into(),
        1_700_000_000,
        |_| "c2ln".into(),
    );
    let hostile_epoch = kt_log::KtRosterEntry::new(
        1,
        victim_hash.clone(),
        vec![attacker],
        1_700_000_000,
        |_| String::new(),
    );
    let payload = hostile_epoch.signing_payload();
    let (client, captured) = spawn_hostile(STANDARD_NO_PAD.encode(&payload)).await;

    let result = client.fetch_inbox(&mut victim).await;
    assert!(
        result.is_err(),
        "client must refuse a challenge nonce that is not 32 bytes"
    );
    assert!(
        captured.lock().unwrap().is_none(),
        "client must not even send an Auth frame for a payload-shaped nonce — \
         that frame is the oracle's output"
    );
}

/// The second half: even for a well-formed 32-byte nonce, what the client signs is
/// domain-separated and mailbox-bound, so the harvested signature is worthless as a
/// signature over the raw nonce (or over anything else the relay might pick).
#[tokio::test]
async fn the_harvested_signature_only_covers_the_domain_separated_message() {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

    let (mut victim, _) =
        create_account_with_username("oracle-victim2", "Victim-Pass-456!").unwrap();
    let victim_hash = victim.identity_hash().as_str().to_string();
    let signing_key = victim.ratchet_ref().signing_key();

    // A legitimately-shaped nonce that also happens to be 32 bytes an attacker chose.
    let raw = [0x41u8; 32];
    let nonce = STANDARD_NO_PAD.encode(raw);
    let (client, captured) = spawn_hostile(nonce.clone()).await;

    // The socket closes right after the frame, so the drain errors out — the frame is
    // what we are after.
    let _ = client.fetch_inbox(&mut victim).await;

    let frame = captured
        .lock()
        .unwrap()
        .clone()
        .expect("client should authenticate against a well-formed nonce");
    let sig = frame["signature"].as_str().unwrap().to_string();

    // What it does cover.
    assert!(verify(
        &signing_key,
        &protocol_types::ws_auth_signing_message(&victim_hash, &nonce),
        &sig
    ));
    // What it must not cover: the raw bytes the relay chose (the old scheme) …
    assert!(!verify(&signing_key, &raw, &sig));
    // … the same nonce bound to a different mailbox the relay controls …
    assert!(!verify(
        &signing_key,
        &protocol_types::ws_auth_signing_message(&"bb".repeat(32), &nonce),
        &sig
    ));
    // … or any other signing context whose payload the relay could have chosen.
    assert!(!verify(
        &signing_key,
        &protocol_types::account_delete_signing_message(&victim_hash, &[], &nonce),
        &sig
    ));
}
