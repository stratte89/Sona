use client_core::{AuditOutcome, Client, ContactOutcome, History, InboundEvent};
use crypto_core::create_account_with_username;
use server::{app, AppState};

mod common;
use common::spawn_relay;

#[tokio::test]
async fn username_change_re_registers_renames_at_peers_and_keeps_old_mailbox() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();

    // Established conversation both ways.
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    client
        .send(&mut alice, &bob_contact, "pre-rename")
        .await
        .unwrap();
    let mut bob_history = History::new();
    for e in client.fetch_inbox(&mut bob).await.unwrap() {
        bob_history.apply(&e);
    }
    assert_eq!(
        bob_history.pinned_contact_key("alice"),
        Some(alice.ratchet_ref().identity_key()).as_deref()
    );

    // Alice renames: local id swap + fresh KT claim/registration under the new name,
    // then the E2E rename notice to her contact.
    let old_hash = alice.identity_hash().as_str().to_string();
    alice.rename("alicia").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    // Regression: self-audit right after a rename is green — the new name's binding is
    // in the log and carries our keys ("not registered" here would mean the audit and
    // the registration disagreed about the identity hash).
    assert_eq!(
        client.audit_own_key(&alice, &History::new()).await.unwrap(),
        AuditOutcome::Ok
    );
    let bob_c = client_core::contact_for("bob", &bob_contact.identity_key);
    client
        .send_rename(&mut alice, &bob_c, "alicia")
        .await
        .unwrap();

    // Bob receives the rename and his address book moves the pin, key unchanged.
    for e in client.fetch_inbox(&mut bob).await.unwrap() {
        bob_history.apply(&e);
    }
    assert_eq!(bob_history.pinned_contact_key("alice"), None);
    assert_eq!(
        bob_history.pinned_contact_key("alicia"),
        Some(alice.ratchet_ref().identity_key()).as_deref()
    );

    // Bob can now discover "alicia" through KT — same identity key proves the binding.
    let alicia = client
        .add_contact_checked(&mut bob, "alicia", bob_history.pinned_contact_key("alicia"))
        .await
        .unwrap();
    let alicia_contact = match alicia {
        ContactOutcome::Unchanged(c) => c,
        other => panic!("expected unchanged key under new name, got {other:?}"),
    };
    client
        .send(&mut bob, &alicia_contact, "hello alicia")
        .await
        .unwrap();
    let got = client.fetch_inbox(&mut alice).await.unwrap();
    assert!(got
        .iter()
        .any(|e| matches!(e, InboundEvent::Message { body, .. } if body == "hello alicia")));

    // A peer that missed the rename still posts to the OLD hash; Alice keeps draining
    // that mailbox via subscribe_as (challenge signed with her unchanged keys).
    let (mut carol, _) = create_account_with_username("carol", "Carol-Password-789!").unwrap();
    client.register(&mut carol, 5).await.unwrap();
    let old_alice = client.add_contact(&mut carol, "alice").await.unwrap();
    client
        .send(&mut carol, &old_alice, "sent to the old name")
        .await
        .unwrap();

    let mut sub = client.subscribe_as(&alice, &old_hash).await.unwrap();
    let mut found = false;
    while let Some(ev) = sub.next(&mut alice).await.unwrap() {
        if matches!(&ev, InboundEvent::Message { body, .. } if body == "sent to the old name") {
            found = true;
            break;
        }
    }
    sub.close().await;
    assert!(
        found,
        "old-mailbox drain must deliver messages sent to the previous username"
    );

    // Regression: renaming BACK to a previously held name must succeed. The KT chain
    // for "alice" already exists and binds these exact keys — a fresh seq-0 claim is
    // refused by the append-only log (409), and register treats that as an idempotent
    // re-claim instead of a hard failure.
    alice.rename("alice").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    // ...and the audit stays green on the reclaimed name too (the reclaim appended a
    // rotation, so the latest binding again carries our keys).
    assert_eq!(
        client.audit_own_key(&alice, &History::new()).await.unwrap(),
        AuditOutcome::Ok
    );

    // The reclaimed name is fully live again: a new peer discovers "alice" through KT
    // (same identity key) and messages land in the reclaimed main mailbox.
    let (mut dave, _) = create_account_with_username("dave", "Dave-Password-000!").unwrap();
    client.register(&mut dave, 5).await.unwrap();
    let reclaimed = client.add_contact(&mut dave, "alice").await.unwrap();
    assert_eq!(reclaimed.identity_key, alice.ratchet_ref().identity_key());
    client
        .send(&mut dave, &reclaimed, "hello again alice")
        .await
        .unwrap();
    let got = client.fetch_inbox(&mut alice).await.unwrap();
    assert!(got
        .iter()
        .any(|e| matches!(e, InboundEvent::Message { body, .. } if body == "hello again alice")));

    // A name registered by SOMEONE ELSE stays a hard conflict: mallory cannot claim
    // the vacated "alicia" (its chain binds alice's keys) or steal "alice".
    let (mut mallory, _) = create_account_with_username("alice", "Mallory-Pass-666!").unwrap();
    assert!(client.register(&mut mallory, 5).await.is_err());
}

/// A renamed-away username is released: reserved to its owner through the grace period,
/// then claimable by anyone — an explicit, auditable takeover in the KT chain. Runs the
/// relay with a zero grace so the takeover happens immediately.
#[tokio::test]
async fn released_username_is_claimable_after_grace_and_alias_detects_takeover() {
    // Relay with RELEASE_GRACE_SECS = 0 (the kt-log unit tests cover a nonzero window).
    let state = AppState::new(server::Config {
        release_grace_secs: 0,
        ..server::Config::default()
    });
    let quic = server::quic::start(state.clone(), 0).expect("quic endpoint");
    *state.quic.lock().unwrap() = Some(quic);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });
    let (base, ws) = (format!("http://{addr}"), format!("ws://{addr}/v1/ws"));
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // Alice claims "alice", talks to bob (so bob pins her key), then renames away and
    // releases the old name.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut bob_hist = History::new();
    let old_alice = client.add_contact(&mut bob, "alice").await.unwrap();
    bob_hist.pin_contact("alice", &old_alice.identity_key, false);
    let alice_key = alice.ratchet_ref().identity_key();

    alice.rename("alicia").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.release_username(&alice, "alice").await.unwrap();
    // Idempotent: releasing again is a no-op, not an error.
    client.release_username(&alice, "alice").await.unwrap();
    assert!(client.owns_username(&alice, "alice").await.unwrap());

    // Grace (0s) elapsed: a brand-new account takes "alice" over.
    let (mut mallory, _) = create_account_with_username("alice", "Mallory-Pass-666!").unwrap();
    client.register(&mut mallory, 5).await.unwrap();
    let mallory_key = mallory.ratchet_ref().identity_key();

    // The name is no longer the old owner's: the KT-verified check the alias drains use
    // flips to false (drop the alias), while the current name stays theirs.
    assert!(!client.owns_username(&alice, "alice").await.unwrap());
    assert!(client.owns_username(&alice, "alicia").await.unwrap());

    // The old owner cannot take the name back (their chain was severed by the takeover)
    // — and the new owner's binding is what discovery now serves.
    let (mut alice_again, _) =
        create_account_with_username("alice", "Alice-Password-123!").unwrap();
    assert!(client.register(&mut alice_again, 5).await.is_err());

    // Bob, who pinned the OLD key for "alice", gets a loud KeyChanged — never a silent
    // swap to the new holder.
    match client
        .add_contact_checked(&mut bob, "alice", bob_hist.pinned_contact_key("alice"))
        .await
        .unwrap()
    {
        ContactOutcome::KeyChanged {
            previous_identity_key,
            new_identity_key,
            ..
        } => {
            assert_eq!(previous_identity_key, alice_key);
            assert_eq!(new_identity_key, mallory_key);
        }
        other => panic!("expected KeyChanged after a takeover, got {other:?}"),
    }
}
