use client_core::{Client, Direction, History, InboundEvent};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

#[tokio::test]
async fn disappearing_messages_sync_and_delete_on_both_sides() {
    // Alice turns on a disappearing-messages timer, then sends. Bob's client must adopt
    // the SAME timer over the wire, and both sides must compute the SAME delete time and
    // drop the message together — with the server none the wiser.
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();

    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    let alice_key = alice.ratchet_ref().identity_key();
    let bob_key = bob.ratchet_ref().identity_key();

    // Each side keeps its own local history, encrypted under its own data key. Bob has
    // accepted Alice (else the message-request gate holds her traffic behind a request).
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();
    bob_hist.pin_contact("alice", &alice_key, false);

    // Alice enables a 100-second disappearing timer for the conversation and messages Bob.
    client
        .set_disappearing(&mut alice, &bob_contact, Some(100))
        .await
        .unwrap();
    alice_hist.set_timer(&bob_key, Some(100)); // Alice applies it locally too
    let sent = client
        .send(&mut alice, &bob_contact, "self-destructs")
        .await
        .unwrap();
    alice_hist.record(
        &bob_key,
        Direction::Outgoing,
        &sent.msg_id,
        "self-destructs",
        sent.sent_at,
    );

    // Bob drains: first a TimerUpdate, then the Message. He applies both to his history.
    let events = client.fetch_inbox(&mut bob).await.unwrap();
    assert_eq!(events.len(), 2);
    for ev in &events {
        bob_hist.apply(ev);
    }

    // Bob adopted the exact same timer.
    assert_eq!(bob_hist.timer(&alice_key), Some(100));

    // Both sides stored the message with the SAME delete time (sender ts + shared timer).
    let a_msg = &alice_hist.messages(&bob_key)[0];
    let b_msg = &bob_hist.messages(&alice_key)[0];
    assert_eq!(a_msg.body, "self-destructs");
    assert_eq!(b_msg.body, "self-destructs");
    assert_eq!(a_msg.delete_at, b_msg.delete_at);
    assert_eq!(a_msg.delete_at, Some(sent.sent_at + 100));

    // Reaping just before the deadline keeps it; at the deadline, both drop it together.
    let deadline = sent.sent_at + 100;
    assert_eq!(alice_hist.reap(deadline - 1), 0);
    assert_eq!(bob_hist.reap(deadline - 1), 0);
    assert_eq!(alice_hist.reap(deadline), 1);
    assert_eq!(bob_hist.reap(deadline), 1);
    assert!(alice_hist.messages(&bob_key).is_empty());
    assert!(bob_hist.messages(&alice_key).is_empty());
}

/// A disappearing-timer change must reach EVERY device: the peer's devices adopt it via
/// `TimerUpdate`, and the setter's own other devices via the `SelfTimer` self-sync —
/// so a message sent afterwards gets the SAME `delete_at` on every copy everywhere.
#[tokio::test]
async fn disappearing_timer_fans_out_to_peer_and_own_devices() {
    use client_core::Direction;

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();
    // Bob has accepted Alice — a stranger's timer change is gated otherwise.
    bob_hist.pin_contact("alice", &alice.ratchet_ref().identity_key(), false);

    // Alice links a second device.
    let (mut alice2, _) = create_account_with_username("alice", "Device2-Password-99!").unwrap();
    let req = client.create_link_request(&alice2);
    client
        .authorize_link(&alice, &mut alice_hist, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let linked = client
        .complete_link(&mut alice2, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let mut alice2_hist = linked.history;
    let alice2_mailbox = client.device_mailbox("alice", &req.device_id).unwrap();

    // Alice (primary) turns on a 100s timer: one copy per bob device, one self-sync.
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    let fan = client
        .prepare_timer_fanout(&mut alice, &mut alice_hist, &bob_contact, Some(100))
        .await
        .unwrap();
    assert_eq!(fan.immediate.len(), 1, "bob has one device");
    assert_eq!(fan.deferred.len(), 1, "one self-sync to the linked device");
    client.post_envelopes(&fan.immediate).await.unwrap();
    client.post_envelopes(&fan.deferred).await.unwrap();
    alice_hist.set_timer(&bob_contact.identity_key, Some(100));

    // Bob adopts the timer from the wire.
    for e in client.fetch_inbox(&mut bob).await.unwrap() {
        bob_hist.apply(&e);
    }
    let alice_key = alice.ratchet_ref().identity_key();
    assert_eq!(bob_hist.timer(&alice_key), Some(100));

    // Alice's LINKED device adopts it too, via the authenticated self-sync.
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(
        inbox2
            .iter()
            .any(|e| matches!(e, InboundEvent::SelfTimerUpdate { .. })),
        "linked device must receive the timer self-sync"
    );
    for e in &inbox2 {
        alice2_hist.apply(e);
    }
    assert_eq!(alice2_hist.timer(&bob_contact.identity_key), Some(100));

    // A message sent after the flip gets the SAME delete_at on all three histories.
    let fan = client
        .prepare_text_fanout(
            &mut alice,
            &mut alice_hist,
            &bob_contact,
            "burns",
            None,
            false,
        )
        .await
        .unwrap();
    client.post_envelopes(&fan.immediate).await.unwrap();
    client.post_envelopes(&fan.deferred).await.unwrap();
    alice_hist.record(
        &bob_contact.identity_key,
        Direction::Outgoing,
        &fan.msg_id,
        "burns",
        fan.sent_at,
    );
    for e in client.fetch_inbox(&mut bob).await.unwrap() {
        bob_hist.apply(&e);
    }
    for e in client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap()
    {
        alice2_hist.apply(&e);
    }
    let expect = Some(fan.sent_at + 100);
    assert_eq!(
        alice_hist.messages(&bob_contact.identity_key)[0].delete_at,
        expect
    );
    assert_eq!(bob_hist.messages(&alice_key)[0].delete_at, expect);
    assert_eq!(
        alice2_hist.messages(&bob_contact.identity_key)[0].delete_at,
        expect
    );

    // At the deadline every copy dies together.
    let deadline = fan.sent_at + 100;
    assert_eq!(alice_hist.reap(deadline), 1);
    assert_eq!(bob_hist.reap(deadline), 1);
    assert_eq!(alice2_hist.reap(deadline), 1);
}

/// The ordering race: a message posted right after a timer flip can reach the peer
/// BEFORE the Timer control copy (different delivery paths, outbox retries). The timer
/// travels inside the message, so the copy still expires exactly on time.
#[tokio::test]
async fn message_that_outruns_timer_control_still_expires() {
    use client_core::Direction;

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();
    // Bob has accepted Alice — the request gate would withhold a stranger's message.
    bob_hist.pin_contact("alice", &alice.ratchet_ref().identity_key(), false);

    // Alice flips the timer on locally and sends — but the Timer control message is
    // NEVER delivered (worst case of the race: it's still stuck in the outbox).
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    alice_hist.set_timer(&bob_contact.identity_key, Some(100));
    let fan = client
        .prepare_text_fanout(
            &mut alice,
            &mut alice_hist,
            &bob_contact,
            "burns",
            None,
            false,
        )
        .await
        .unwrap();
    client.post_envelopes(&fan.immediate).await.unwrap();
    alice_hist.record(
        &bob_contact.identity_key,
        Direction::Outgoing,
        &fan.msg_id,
        "burns",
        fan.sent_at,
    );

    // Bob's stored timer is still OFF, yet the copy must expire — the message carried it.
    for e in client.fetch_inbox(&mut bob).await.unwrap() {
        bob_hist.apply(&e);
    }
    let alice_key = alice.ratchet_ref().identity_key();
    assert_eq!(bob_hist.timer(&alice_key), None, "no Timer control arrived");
    let expect = Some(fan.sent_at + 100);
    assert_eq!(bob_hist.messages(&alice_key)[0].delete_at, expect);
    assert_eq!(
        alice_hist.messages(&bob_contact.identity_key)[0].delete_at,
        expect
    );
    assert_eq!(bob_hist.reap(fan.sent_at + 100), 1);
}

/// Group disappearing messages: a member's timer change reaches every other member,
/// group messages sent under it carry the timer, and every copy reaps together.
#[tokio::test]
async fn group_disappearing_timer_syncs_and_reaps_for_all_members() {
    use client_core::{Group, GroupMember};

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();

    let group = Group {
        id: "g1".into(),
        name: "trip".into(),
        members: vec![
            GroupMember {
                username: "alice".into(),
                identity_key: alice.ratchet_ref().identity_key(),
            },
            GroupMember {
                username: "bob".into(),
                identity_key: bob.ratchet_ref().identity_key(),
            },
        ],
    };
    // Admin-model group: alice mints the genesis membership epoch (she is the admin); both
    // sides adopt it. (`record_group` is gone — every group is admin-model now.)
    let epoch = client_core::GroupMembershipEpoch::genesis(
        "g1".into(),
        vec![
            client_core::GroupMemberEntry {
                username: "alice".into(),
                identity_key: alice.ratchet_ref().identity_key(),
            },
            client_core::GroupMemberEntry {
                username: "bob".into(),
                identity_key: bob.ratchet_ref().identity_key(),
            },
        ],
        alice.ratchet_ref().signing_key(),
        alice.ratchet_ref().identity_key(),
        0,
        |p| alice.ratchet_ref().sign(p),
    );
    alice_hist.adopt_group_epoch(&epoch);
    bob_hist.adopt_group_epoch(&epoch);
    alice_hist.set_group_name("g1", "trip");
    bob_hist.set_group_name("g1", "trip");
    let _ = client.add_contact(&mut alice, "bob").await.unwrap();

    // Alice sets a 100s group timer; Bob adopts it from the wire.
    client
        .send_group_timer_multi(&mut alice, &mut alice_hist, &group, Some(100))
        .await
        .unwrap();
    alice_hist.set_group_timer("g1", Some(100));
    for e in client.fetch_inbox(&mut bob).await.unwrap() {
        bob_hist.apply(&e);
    }
    assert_eq!(bob_hist.group_timer("g1"), Some(100));

    // A group message sent under the timer gets the same delete_at everywhere.
    let (msg_id, sent_at) = client
        .send_group_multi(&mut alice, &mut alice_hist, &group, "burns", None, false)
        .await
        .unwrap();
    alice_hist.record_group_message(
        "g1",
        &alice.ratchet_ref().identity_key(),
        &msg_id,
        "burns",
        sent_at,
        None,
        None,
    );
    for e in client.fetch_inbox(&mut bob).await.unwrap() {
        bob_hist.apply(&e);
    }
    let expect = Some(sent_at + 100);
    assert_eq!(
        alice_hist.group("g1").unwrap().messages[0].delete_at,
        expect
    );
    assert_eq!(bob_hist.group("g1").unwrap().messages[0].delete_at, expect);

    // Both reap the group copy together.
    assert_eq!(alice_hist.reap(sent_at + 100), 1);
    assert_eq!(bob_hist.reap(sent_at + 100), 1);
    assert!(alice_hist.group("g1").unwrap().messages.is_empty());
    assert!(bob_hist.group("g1").unwrap().messages.is_empty());
}
