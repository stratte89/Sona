use client_core::{Client, ContactOutcome, History, InboundEvent};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

#[tokio::test]
async fn alice_messages_bob_with_kt_verified_discovery() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // Two real accounts (username + password), both registered with the relay.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();

    // Alice discovers Bob by username — this verifies his key against Key Transparency.
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    assert_eq!(bob_contact.identity_key, bob.ratchet_ref().identity_key());
    assert_eq!(bob_contact.safety_number.split(' ').count(), 12);

    // Alice sends while Bob is offline; the relay queues it.
    client
        .send(&mut alice, &bob_contact, "hello bob, e2e")
        .await
        .unwrap();

    // Bob connects and drains his inbox — message decrypts, sender is correctly attributed.
    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert_eq!(inbox.len(), 1);
    match &inbox[0] {
        InboundEvent::Message {
            sender_identity_key,
            body,
            ..
        } => {
            assert_eq!(body, "hello bob, e2e");
            assert_eq!(*sender_identity_key, alice.ratchet_ref().identity_key());
        }
        _ => panic!("expected a chat message"),
    }

    // The message was acked, so a second drain returns nothing.
    let inbox2 = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(inbox2.is_empty());
}

#[tokio::test]
async fn client_replenishes_its_own_one_time_keys() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // Bob registers with only 1 one-time key, then tops himself up. The relay answers a
    // coarse bucket rather than an exact count (SP-10), so the client uploads a whole
    // batch instead of a computed difference — the relay dedups and caps.
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut bob, 1).await.unwrap();
    let added = client.replenish_own_keys(&mut bob, 20).await.unwrap();
    assert_eq!(added, 20);

    // A fresh contact can now start a session (consumes one of Bob's keys).
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 3).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    assert_eq!(bob_contact.identity_key, bob.ratchet_ref().identity_key());

    // Stock is comfortably above the relay's watermark → the next replenish is a no-op,
    // so a healthy client is not re-uploading (and re-sealing its vault) every cycle.
    let added2 = client.replenish_own_keys(&mut bob, 5).await.unwrap();
    assert_eq!(added2, 0);
}

#[tokio::test]
async fn fallback_key_lets_a_session_start_after_otks_drained() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // Bob registers with a single one-time key (plus the fallback key register uploads).
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut bob, 1).await.unwrap();
    let bob_key = bob.ratchet_ref().identity_key();

    // Carol drains the one-time key.
    let (mut carol, _) = create_account_with_username("carol", "Carol-Password-1!").unwrap();
    client.register(&mut carol, 1).await.unwrap();
    client.add_contact(&mut carol, "bob").await.unwrap();

    // Alice arrives after the drain — she must still be able to start a session (fallback),
    // and a message she sends must decrypt on Bob's side.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 1).await.unwrap();
    let alice_id = alice.ratchet_ref().identity_key();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    assert_eq!(bob_contact.identity_key, bob_key);
    client
        .send(&mut alice, &bob_contact, "via fallback")
        .await
        .unwrap();

    let events = client.fetch_inbox(&mut bob).await.unwrap();
    let got = events.iter().find_map(|e| match e {
        InboundEvent::Message {
            sender_identity_key,
            body,
            ..
        } if *sender_identity_key == alice_id => Some(body.clone()),
        _ => None,
    });
    assert_eq!(got.as_deref(), Some("via fallback"));
}

#[tokio::test]
async fn key_change_is_detected_not_silently_trusted() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_key = bob.ratchet_ref().identity_key();

    // First contact: no pinned key → New.
    match client
        .add_contact_checked(&mut alice, "bob", None)
        .await
        .unwrap()
    {
        ContactOutcome::New(c) => assert_eq!(c.identity_key, bob_key),
        other => panic!("expected New, got {other:?}"),
    }
    // Same key pinned → Unchanged.
    match client
        .add_contact_checked(&mut alice, "bob", Some(&bob_key))
        .await
        .unwrap()
    {
        ContactOutcome::Unchanged(_) => {}
        other => panic!("expected Unchanged, got {other:?}"),
    }
    // A different pinned key → KeyChanged, and NO session is silently established.
    match client
        .add_contact_checked(&mut alice, "bob", Some("some-old-different-key"))
        .await
        .unwrap()
    {
        ContactOutcome::KeyChanged {
            new_identity_key,
            previous_identity_key,
            ..
        } => {
            assert_eq!(new_identity_key, bob_key);
            assert_eq!(previous_identity_key, "some-old-different-key");
        }
        other => panic!("expected KeyChanged, got {other:?}"),
    }
}

#[tokio::test]
async fn live_subscription_delivers_backlog_and_realtime() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    let alice_id = alice.ratchet_ref().identity_key();

    // A message is queued BEFORE Bob subscribes (backlog).
    client
        .send(&mut alice, &bob_contact, "queued one")
        .await
        .unwrap();

    // Bob opens a live subscription. First next() yields the backlog message.
    let mut sub = client.subscribe(&bob).await.unwrap();
    let ev = sub.next(&mut bob).await.unwrap().expect("backlog event");
    match ev {
        InboundEvent::Message {
            body,
            sender_identity_key,
            ..
        } => {
            assert_eq!(body, "queued one");
            assert_eq!(sender_identity_key, alice_id);
        }
        _ => panic!("expected message"),
    }

    // Now Alice sends while Bob stays subscribed — it arrives live.
    client
        .send(&mut alice, &bob_contact, "live one")
        .await
        .unwrap();
    let ev = sub.next(&mut bob).await.unwrap().expect("live event");
    match ev {
        InboundEvent::Message { body, .. } => assert_eq!(body, "live one"),
        _ => panic!("expected message"),
    }
    sub.close().await;
}

#[tokio::test]
async fn group_fan_out_reaches_every_member() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    let (mut carol, _) = create_account_with_username("carol", "Carol-Password-1!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    client.register(&mut carol, 5).await.unwrap();
    let alice_id = alice.ratchet_ref().identity_key();

    // Alice adds both, then creates a group and messages it.
    let bob_c = client.add_contact(&mut alice, "bob").await.unwrap();
    let carol_c = client.add_contact(&mut alice, "carol").await.unwrap();
    let (group, _epoch) = client
        .create_group(&mut alice, "trip", &[bob_c, carol_c])
        .await
        .unwrap();
    assert_eq!(group.members.len(), 3); // bob, carol, + alice
    client
        .send_group(&mut alice, &group, "we leave at 8")
        .await
        .unwrap();

    // Each of Bob and Carol receives the invite AND the group message, into their history.
    // Both have accepted Alice — a stranger's brand-new group invite is held behind the
    // message-request gate otherwise.
    for (who, hist_owner) in [(&mut bob, "bob"), (&mut carol, "carol")] {
        let mut hist = History::new();
        hist.pin_contact("alice", &alice_id, false);
        let events = client.fetch_inbox(who).await.unwrap();
        for e in &events {
            hist.apply(e);
        }
        let g = hist
            .group(&group.id)
            .unwrap_or_else(|| panic!("{hist_owner} missing group"));
        assert_eq!(g.name, "trip");
        assert_eq!(g.members.len(), 3);
        assert_eq!(g.messages.len(), 1, "{hist_owner} missing group message");
        assert_eq!(g.messages[0].body, "we leave at 8");
        assert_eq!(g.messages[0].sender.as_deref(), Some(alice_id.as_str()));
    }
}

#[tokio::test]
async fn burst_of_messages_survives_lock_guarded_delivery_loop() {
    // Regression for the GUI delivery bug: the old loop wrapped `Subscription::next` in
    // a timeout (not cancel-safe → decrypted events could vanish). Mirror the new
    // client loop — wait for raw frames unlocked, decode under a lock, ack after — and
    // require every message of a rapid burst to arrive exactly once, in order.
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();

    // Two queued before subscribing (backlog), the rest sent live mid-loop.
    for i in 0..2 {
        client
            .send(&mut alice, &bob_contact, &format!("msg {i}"))
            .await
            .unwrap();
    }

    let bob = Arc::new(Mutex::new(bob));
    let mut sub = client.subscribe(&*bob.lock().await).await.unwrap();

    // Live burst: 13 more, no pacing.
    for i in 2..15 {
        client
            .send(&mut alice, &bob_contact, &format!("msg {i}"))
            .await
            .unwrap();
    }

    let mut got: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while got.len() < 15 {
        let frame = tokio::time::timeout_at(deadline, sub.next_frame())
            .await
            .expect("burst delivery timed out — messages were lost")
            .unwrap()
            .expect("socket closed unexpectedly");
        // Decode under the account lock (as the GUI does), ack after releasing it.
        let ack = {
            let mut account = bob.lock().await;
            match client_core::decode_frame(&frame, &mut account) {
                client_core::Decoded::Event { event, ack_msg_id } => {
                    if let InboundEvent::Message { body, .. } = event {
                        got.push(body);
                    }
                    Some(ack_msg_id)
                }
                client_core::Decoded::Ignore { ack_msg_id } => ack_msg_id,
                client_core::Decoded::Ready => None,
                client_core::Decoded::AuthFailed => panic!("auth failed"),
                client_core::Decoded::Revoked => panic!("device unexpectedly revoked"),
            }
        };
        if let Some(id) = ack {
            sub.ack(&id).await.unwrap();
        }
    }
    let expect: Vec<String> = (0..15).map(|i| format!("msg {i}")).collect();
    assert_eq!(got, expect, "all 15 messages, exactly once, in order");
    sub.close().await;
}

#[tokio::test]
async fn undecryptable_message_is_acked_away_not_poisoning_the_mailbox() {
    // A message the recipient can never decrypt (garbage, or a replay after the ratchet
    // advanced) must not sit in the mailbox forever: it would be redelivered on every
    // reconnect and eventually fill the mailbox cap, bouncing NEW messages.
    use protocol_types::{Envelope, IdentityHash, PayloadKind};

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();

    // Poison: a syntactically valid envelope whose ciphertext can never decrypt.
    let poison = Envelope {
        to: IdentityHash::from_identifier("bob"),
        ciphertext: r#"{"message_type":1,"body":"AAAA"}"#.into(),
        kind: PayloadKind::Message,
        msg_id: "deadbeef00000001".into(),
        expires_at: None,
        wake: Default::default(),
        raw_identifier: None,
    };
    reqwest::Client::new()
        .post(format!("{base}/v1/messages"))
        .json(&poison)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // First drain: nothing deliverable, but the poison is acked out of the mailbox.
    assert!(client.fetch_inbox(&mut bob).await.unwrap().is_empty());

    // A real message afterwards still arrives — and the poison is NOT redelivered.
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    client
        .send(&mut alice, &bob_contact, "after the poison")
        .await
        .unwrap();
    let events = client.fetch_inbox(&mut bob).await.unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        InboundEvent::Message { body, .. } => assert_eq!(body, "after the poison"),
        other => panic!("expected message, got {other:?}"),
    }
    // And the mailbox is now fully drained (nothing left to redeliver).
    assert!(client.fetch_inbox(&mut bob).await.unwrap().is_empty());
}

#[tokio::test]
async fn reopening_a_chat_does_not_burn_one_time_keys() {
    // Regression: every thread open used to fetch a fresh bundle (consuming one of the
    // contact's one-time keys) even when a live session already existed. With the KT-only
    // re-check, repeated opens must leave the key count untouched.
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 11).await.unwrap();
    let bob_hash = bob.identity_hash().as_str().to_string();

    // The relay publishes a coarse bucket, never an exact count (SP-10). Bob is
    // registered with watermark+1 keys, so "low" means exactly one key was burned and
    // "none" would mean the re-opens burned the rest — enough to tell the two apart.
    let level = |base: String, hash: String| async move {
        let v: serde_json::Value = reqwest::get(format!("{base}/v1/keys/count/{hash}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["level"].as_str().unwrap().to_string()
    };

    // First contact consumes exactly one key.
    let bob_contact = match client
        .add_contact_checked(&mut alice, "bob", None)
        .await
        .unwrap()
    {
        ContactOutcome::New(c) => c,
        other => panic!("expected New, got {other:?}"),
    };
    assert_eq!(level(base.clone(), bob_hash.clone()).await, "low");

    // Ten re-opens (known key + live session) consume none.
    for _ in 0..10 {
        match client
            .add_contact_checked(&mut alice, "bob", Some(&bob_contact.identity_key))
            .await
            .unwrap()
        {
            ContactOutcome::Unchanged(_) => {}
            other => panic!("expected Unchanged, got {other:?}"),
        }
    }
    assert_eq!(
        level(base.clone(), bob_hash.clone()).await,
        "low",
        "ten re-opens must burn no keys — \"none\" here would mean they did"
    );

    // And the session those re-opens preserved still delivers.
    client
        .send(&mut alice, &bob_contact, "still flowing")
        .await
        .unwrap();
    let events = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, InboundEvent::Message { body, .. } if body == "still flowing")));
}

#[tokio::test]
async fn seen_receipts_go_out_once_and_unread_counts_track() {
    // History-side contract the GUI relies on: unseen ids are receipted once, the unread
    // badge count drops to zero after, and re-opening produces no duplicate receipts.
    let mut h = History::new();
    h.pin_contact("alice", "alice-key", false); // accepted contact — gate not in play
    h.apply(&InboundEvent::Message {
        sender_identity_key: "alice-key".into(),
        sender_username: "alice".into(),
        msg_id: "m1".into(),
        body: "one".into(),
        sent_at: 100,
        reply: None,
        expire_secs: None,
        forwarded: false,
    });
    h.apply(&InboundEvent::Message {
        sender_identity_key: "alice-key".into(),
        sender_username: "alice".into(),
        msg_id: "m2".into(),
        body: "two".into(),
        sent_at: 101,
        reply: None,
        expire_secs: None,
        forwarded: false,
    });
    assert_eq!(h.unread_count("alice-key"), 2);
    let ids = h.unseen_incoming_ids("alice-key");
    assert_eq!(ids, vec!["m1".to_string(), "m2".to_string()]);

    h.mark_seen_receipted("alice-key", &ids);
    assert_eq!(h.unread_count("alice-key"), 0);
    assert!(h.unseen_incoming_ids("alice-key").is_empty());

    // A new message becomes the only unseen one.
    h.apply(&InboundEvent::Message {
        sender_identity_key: "alice-key".into(),
        sender_username: "alice".into(),
        msg_id: "m3".into(),
        body: "three".into(),
        sent_at: 102,
        reply: None,
        expire_secs: None,
        forwarded: false,
    });
    assert_eq!(h.unseen_incoming_ids("alice-key"), vec!["m3".to_string()]);
    // The auto-pin on first inbound message keeps the sender in the address book.
    assert_eq!(h.pinned_contact_key("alice"), Some("alice-key"));
}
