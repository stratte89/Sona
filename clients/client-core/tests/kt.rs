use client_core::{AuditOutcome, Client, ClientError, GossipVerdict, History, InboundEvent};
use crypto_core::create_account_with_username;
use kt_log::KtLog;
use server::{app, AppState, Config};

mod common;
use common::spawn_relay;

#[tokio::test]
async fn safety_numbers_match_on_both_sides() {
    // Both parties, computing independently, must arrive at the same safety number —
    // otherwise out-of-band verification is meaningless.
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 3).await.unwrap();
    client.register(&mut bob, 3).await.unwrap();

    let bob_seen_by_alice = client.add_contact(&mut alice, "bob").await.unwrap();
    let alice_seen_by_bob = client.add_contact(&mut bob, "alice").await.unwrap();
    assert_eq!(
        bob_seen_by_alice.safety_number,
        alice_seen_by_bob.safety_number
    );
}

#[tokio::test]
async fn self_audit_confirms_own_key_binding() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();

    // Before registering: not in the log.
    assert_eq!(
        client.audit_own_key(&alice, &History::new()).await.unwrap(),
        AuditOutcome::NotRegistered
    );

    // After registering: the log binds our name to our real key.
    client.register(&mut alice, 3).await.unwrap();
    assert_eq!(
        client.audit_own_key(&alice, &History::new()).await.unwrap(),
        AuditOutcome::Ok
    );
}

#[tokio::test]
async fn gossip_witness_accepts_honest_append_only_growth() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);
    let mut hist = History::new();

    // First observation establishes the witness.
    let (h0, v0) = client.advance_witness(hist.witness()).await.unwrap();
    assert_eq!(v0, GossipVerdict::Consistent);
    hist.set_witness(h0.clone());

    // The log grows (registrations append entries).
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 3).await.unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut bob, 3).await.unwrap();

    // The new head must be a consistent, append-only continuation of the witness.
    let (h1, v1) = client.advance_witness(hist.witness()).await.unwrap();
    assert_eq!(v1, GossipVerdict::Consistent);
    assert!(h1.tree_size > h0.tree_size);
    hist.set_witness(h1.clone());

    // Grow again from a NON-empty witness — this exercises the real consistency proof.
    let (mut carol, _) = create_account_with_username("carol", "Carol-Password-1!").unwrap();
    client.register(&mut carol, 3).await.unwrap();
    let (h2, v2) = client.advance_witness(hist.witness()).await.unwrap();
    assert_eq!(v2, GossipVerdict::Consistent);
    assert!(h2.tree_size > h1.tree_size);
}

#[tokio::test]
async fn gossip_transport_carries_a_peer_head_and_verifies() {
    // On an honest server, a head carried in-band from Alice must verify as consistent
    // with Bob's own view — proving the transport wiring end-to-end.
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let alice_id = alice.ratchet_ref().identity_key();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();

    // Alice sends her current KT head to Bob.
    client.send_head(&mut alice, &bob_contact).await.unwrap();

    // Bob receives it as a PeerHead and checks it against his own view.
    let events = client.fetch_inbox(&mut bob).await.unwrap();
    let head = events
        .iter()
        .find_map(|e| match e {
            InboundEvent::PeerHead {
                head,
                sender_identity_key,
            } if *sender_identity_key == alice_id => Some(head.clone()),
            _ => None,
        })
        .expect("peer head event");
    assert_eq!(
        client.compare_foreign_head(&head).await.unwrap(),
        GossipVerdict::Consistent
    );
}

#[tokio::test]
async fn gossip_detects_a_split_view() {
    // Stand up a relay whose KT signing key we know, so we can forge a *validly signed*
    // conflicting head — exactly what an equivocating server would produce for a split view.
    let seed = KtLog::generate().signing_key_seed_b64();
    let pinned = KtLog::from_seed_b64(&seed).unwrap().verifying_key_b64();

    let state = AppState::with_kt(Config::default(), KtLog::from_seed_b64(&seed).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(serve_state).into_make_service())
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let ws = format!("ws://{addr}/v1/ws");
    let client = Client::new(&base, &ws, &pinned);

    // Real server view: one entry (Alice) → some root at size 1.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 3).await.unwrap();

    // Forge the "other" view a malicious server might have shown someone else: the same
    // KT key, but a different first entry → same size (1), different root.
    let mut fork = KtLog::from_seed_b64(&seed).unwrap();
    let (attacker, _) = create_account_with_username("attacker", "Attacker-Password-1!").unwrap();
    fork.append(attacker.kt_claim_entry(1)).unwrap();
    let foreign_head = fork.sth(1);

    // Comparing the two validly-signed-but-conflicting heads proves equivocation.
    assert_eq!(
        client.compare_foreign_head(&foreign_head).await.unwrap(),
        GossipVerdict::Equivocation
    );
}

#[tokio::test]
async fn discovering_unknown_username_fails() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 3).await.unwrap();

    // No "ghost" was ever registered — discovery must fail with the dedicated
    // not-found error (so shells can say "that username doesn't exist"), not a raw
    // network error, and never invent a key.
    let err = client.add_contact(&mut alice, "ghost").await.unwrap_err();
    assert!(matches!(err, ClientError::UserNotFound));
}
