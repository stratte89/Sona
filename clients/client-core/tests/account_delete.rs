use client_core::{Client, ClientError};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

/// The full deletion contract, relay-side: directory record gone (no new sessions),
/// queued ciphertext purged, push subscription dropped, and the KT chain shows the
/// signed release — while the log itself keeps its history (append-only by design).
#[tokio::test]
async fn delete_account_erases_relay_state_and_releases_the_name() {
    let (base, ws, state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let alice_hash = alice.identity_hash().as_str().to_string();

    // Bob queues a message into Alice's mailbox; Alice registers a push endpoint.
    let alice_contact = client.add_contact(&mut bob, "alice").await.unwrap();
    client
        .send(&mut bob, &alice_contact, "you'll never read this")
        .await
        .unwrap();
    client
        .register_push(&alice, "http://127.0.0.1:9/up")
        .await
        .unwrap();
    {
        let inner = state.inner.lock().unwrap();
        assert!(inner.directory.contains_key(&alice_hash));
        assert!(inner.push.contains_key(&alice_hash));
    }

    // The deletion pair: release the name (KT unbind), then delete (relay forget).
    client.release_username(&alice, "alice").await.unwrap();
    client.delete_account(&alice, &[]).await.unwrap();

    // Relay state for Alice is gone…
    {
        let inner = state.inner.lock().unwrap();
        assert!(!inner.directory.contains_key(&alice_hash));
        assert!(!inner.push.contains_key(&alice_hash));
        assert_eq!(
            inner
                .store
                .depth(&protocol_types::IdentityHash::from_identifier("alice")),
            0,
            "queued ciphertext must not outlive the account"
        );
    }
    // …no new session can start with her…
    match client.add_contact(&mut bob, "alice").await {
        Err(ClientError::UserNotFound) => {}
        other => panic!("expected UserNotFound, got {other:?}"),
    }
    // …and the KT chain publicly shows the signed release (the log keeps history).
    {
        let inner = state.inner.lock().unwrap();
        let idx = inner.kt.latest_index_for(&alice_hash).unwrap();
        let entry = inner.kt.entry(idx).unwrap();
        assert!(entry.released, "the name must be released, not just gone");
    }
}

/// Deletion is authorized by the account's own signing key — a signature from anyone
/// else is refused, and a replayed/expired nonce never works.
#[tokio::test]
async fn delete_account_refuses_foreign_signatures() {
    let (base, ws, state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut mallory, _) = create_account_with_username("mallory", "Mallory-Pass-789!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut mallory, 5).await.unwrap();
    let alice_hash = alice.identity_hash().as_str().to_string();

    // Mallory forges a delete for ALICE's mailbox: nonce is for alice's hash, but the
    // signature comes from mallory's key. The relay must refuse and change nothing.
    let http = reqwest::Client::new();
    let nonce: serde_json::Value = http
        .get(format!("{base}/v1/challenge?hash={alice_hash}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce = nonce["nonce"].as_str().unwrap().to_string();
    let msg = protocol_types::account_delete_signing_message(&alice_hash, &[], &nonce);
    let forged = mallory.ratchet_ref().sign(&msg);
    let resp = http
        .post(format!("{base}/v1/account/delete"))
        .json(&serde_json::json!({
            "hash": alice_hash,
            "alias_hashes": [],
            "nonce": nonce,
            "signature": forged,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state
        .inner
        .lock()
        .unwrap()
        .directory
        .contains_key(&alice_hash));

    // A correctly-signed delete with a stale (just-burned) nonce is refused too.
    let msg = protocol_types::account_delete_signing_message(&alice_hash, &[], &nonce);
    let genuine = alice.ratchet_ref().sign(&msg);
    let resp = http
        .post(format!("{base}/v1/account/delete"))
        .json(&serde_json::json!({
            "hash": alice_hash,
            "alias_hashes": [],
            "nonce": nonce,
            "signature": genuine,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state
        .inner
        .lock()
        .unwrap()
        .directory
        .contains_key(&alice_hash));
}

/// Alias mailboxes (former usernames) die with the account — but only the ones the
/// signing key actually owns; someone else's mailbox named as an "alias" is untouched.
#[tokio::test]
async fn delete_account_takes_owned_aliases_and_spares_others() {
    let (base, ws, state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // Alice registers, then renames to alice2 — "alice" becomes her drained alias.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let old_hash = alice.identity_hash().as_str().to_string();
    let bob_hash = bob.identity_hash().as_str().to_string();
    alice.rename("alice2").unwrap();
    client.register(&mut alice, 5).await.unwrap();

    // Delete, claiming the real former name AND bob's mailbox as "aliases". Bob's
    // record carries a different signing key, so it must survive.
    client
        .delete_account(&alice, &["alice".into(), "bob".into()])
        .await
        .unwrap();

    let inner = state.inner.lock().unwrap();
    let new_hash = alice.identity_hash().as_str().to_string();
    assert!(!inner.directory.contains_key(&new_hash));
    assert!(!inner.directory.contains_key(&old_hash), "owned alias dies");
    assert!(
        inner.directory.contains_key(&bob_hash),
        "an alias claim can never widen deletion to another account"
    );
}
