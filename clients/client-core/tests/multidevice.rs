use client_core::{AuditOutcome, Client, History, InboundEvent};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

#[tokio::test]
async fn multi_device_roster_and_history_sync_are_capability_gated_and_verified() {
    use kt_log::PRIMARY_DEVICE_ID;

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // The relay advertises the multi-device surfaces; a client must check this before
    // taking any multi-device path (an old relay 404s → empty list → single-device).
    let caps = client.server_capabilities().await.unwrap();
    assert!(caps.contains(&protocol_types::CAP_MULTI_DEVICE.to_string()));
    assert!(caps.contains(&protocol_types::CAP_HISTORY_SYNC.to_string()));

    // Primary account registers as today (nothing multi-device about registration).
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 3).await.unwrap();
    let uhash = alice.identity_hash().as_str().to_string();

    // No roster published → None: peers keep the plain single-device path.
    assert!(client
        .fetch_verified_roster("alice")
        .await
        .unwrap()
        .is_none());

    // A "linked device" with its own fresh Olm identity. It mints a proof-of-possession
    // record for ALICE's account; the primary signs the roster epoch with the account key.
    let (linked, _) = crypto_core::create_account("Linked-Password-456!").unwrap();
    let device_id = "ef".repeat(16);
    let devices = vec![
        alice.device_record(&uhash, PRIMARY_DEVICE_ID, 1000),
        linked.device_record(&uhash, &device_id, 1001),
    ];
    let roster = alice.kt_roster_entry(0, devices, 1002);
    client.publish_roster(&roster).await.unwrap();

    // Any peer can now fetch and fully verify the roster (STH + inclusion + account
    // signature + per-device proofs) with nothing but the pinned KT key.
    let verified = client
        .fetch_verified_roster("alice")
        .await
        .unwrap()
        .expect("roster was published");
    assert_eq!(verified.devices.len(), 2);
    assert_eq!(verified.seq, 0);
    assert!(verified
        .devices
        .iter()
        .any(|d| d.identity_key == linked.ratchet_ref().identity_key()));

    // History sync: sealed under PIN + link secret, opaque to the relay, decrypted on
    // the new device only with both inputs.
    let link_secret = crypto_core::sync::generate_link_secret();
    let history = b"alice's exported history";
    let blob = crypto_core::sync::seal_history("2846", &link_secret, history).unwrap();
    let sync_id = client.upload_sync_blob(blob).await.unwrap();
    let fetched = client.download_sync_blob(&sync_id).await.unwrap();
    assert_eq!(
        crypto_core::sync::open_history("2846", &link_secret, &fetched).unwrap(),
        history
    );
    assert!(crypto_core::sync::open_history("9999", &link_secret, &fetched).is_err());
    assert!(client.download_sync_blob(&"0".repeat(32)).await.is_err());
}

/// The full Phase 2/3 vertical slice, headless against the real relay: a user links a
/// second device, a contact's message reaches BOTH devices, and the user's own send
/// self-syncs to the linked device.
#[tokio::test]
async fn multi_device_link_fanout_and_self_sync_end_to_end() {
    use client_core::Direction;

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // Alice's primary device + Bob (single device), both registered normally.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();

    // Alice links a SECOND device (its own fresh Olm identity, same username).
    let (mut alice2, _) = create_account_with_username("alice", "Device2-Password-99!").unwrap();
    let req = client.create_link_request(&alice2);
    let account_password = "Alice-Password-123!"; // the account password gates history sync

    // Primary authorizes: publishes roster epoch 0, seals+uploads history, PUTs provisioning.
    let seq = client
        .authorize_link(&alice, &mut alice_hist, &req, account_password)
        .await
        .unwrap();
    assert_eq!(seq, 0);
    assert!(alice_hist.is_primary_device());

    // New device completes linking: fetches provisioning + history, sets its identity.
    let linked = client
        .complete_link(&mut alice2, &req, account_password)
        .await
        .unwrap();
    assert!(linked.history_synced, "history blob should transfer");
    let mut alice2_hist = linked.history;
    assert_eq!(alice2_hist.self_device_id(), req.device_id);
    assert!(!alice2_hist.is_primary_device());
    let alice2_mailbox = client.device_mailbox("alice", &req.device_id).unwrap();

    // ── Inbound fan-out: Bob messages "alice" → reaches BOTH alice devices. ──
    let alice_contact = client.add_contact(&mut bob, "alice").await.unwrap();
    let fan = client
        .prepare_text_fanout(
            &mut bob,
            &mut bob_hist,
            &alice_contact,
            "hi across devices",
            None,
            false,
        )
        .await
        .unwrap();
    assert_eq!(fan.immediate.len(), 2, "one envelope per alice device");
    assert!(fan.deferred.is_empty(), "bob has no other devices");
    client.post_envelopes(&fan.immediate).await.unwrap();

    // Primary drains its account mailbox.
    let inbox = client.fetch_inbox(&mut alice).await.unwrap();
    assert!(inbox.iter().any(|e| matches!(e,
        InboundEvent::Message { body, .. } if body == "hi across devices")));
    // Linked device drains ITS device mailbox — same message.
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(inbox2.iter().any(|e| matches!(e,
        InboundEvent::Message { body, .. } if body == "hi across devices")));

    // ── Self-fan-out: Alice's primary sends to Bob; her linked device gets a self-sync. ──
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    let fan = client
        .prepare_text_fanout(
            &mut alice,
            &mut alice_hist,
            &bob_contact,
            "hi bob from primary",
            None,
            false,
        )
        .await
        .unwrap();
    assert_eq!(fan.immediate.len(), 1, "bob has one device");
    assert_eq!(
        fan.deferred.len(),
        1,
        "one self-sync copy to the linked device"
    );
    // SP-06: the recipient learns the shared logical id from their own copy, and our
    // device mailboxes are derivable from the public KT roster — so if the SELF-SYNC
    // envelopes reused that id, a hostile recipient could post junk under it into each
    // of our device mailboxes inside the self-sync jitter window, win the relay's
    // first-writer-wins dedup, and have every real self-sync copy silently discarded.
    // The envelope id must therefore be unpredictable; the logical id lives in the
    // (encrypted) payload, which is what devices actually dedup and thread on.
    for env in &fan.deferred {
        assert_ne!(
            env.msg_id, fan.msg_id,
            "a self-sync envelope must not reuse the id the recipient can see"
        );
    }
    for env in &fan.immediate {
        assert_ne!(env.msg_id, "", "recipient copies still carry a routable id");
    }

    client.post_envelopes(&fan.immediate).await.unwrap();
    client.post_envelopes(&fan.deferred).await.unwrap();

    // Bob receives the real message.
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(bob_inbox.iter().any(|e| matches!(e,
        InboundEvent::Message { body, .. } if body == "hi bob from primary")));

    // The linked device receives a self-sync and records it as OUTGOING under Bob's convo.
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    let self_sync = inbox2
        .iter()
        .find(|e| matches!(e, InboundEvent::SelfSentText { .. }));
    assert!(
        self_sync.is_some(),
        "linked device must receive the self-sync"
    );
    for e in &inbox2 {
        alice2_hist.apply(e);
    }
    let bob_key = bob.ratchet_ref().identity_key();
    let msgs = alice2_hist.messages(&bob_key);
    assert!(
        msgs.iter()
            .any(|m| m.body == "hi bob from primary" && m.direction == Direction::Outgoing),
        "self-sync must appear as an outgoing message on the linked device"
    );

    // ── Self-audit sees the roster and recognizes both devices. ──
    match client.audit_own_roster(&alice, &alice_hist).await.unwrap() {
        client_core::multidevice::RosterAudit::Ok { seq, devices } => {
            assert_eq!(seq, 0);
            assert_eq!(devices, 2);
        }
        other => panic!("unexpected audit result: {other:?}"),
    }
}

/// Epoch-rollback / roster-downgrade is refused fail-closed (the deferred Phase-1 gap).
#[tokio::test]
async fn multi_device_roster_rollback_is_refused() {
    use client_core::history::RosterRollback;

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 3).await.unwrap();
    let mut alice_hist = History::new();
    let (alice2, _) = create_account_with_username("alice", "Device2-Password-99!").unwrap();
    let req = client.create_link_request(&alice2);
    client
        .authorize_link(&alice, &mut alice_hist, &req, "Alice-Password-123!")
        .await
        .unwrap();

    // A resolver on a fresh history pins epoch 0.
    let mut peer_hist = History::new();
    let devs = client
        .resolve_account_devices(&mut peer_hist, "alice")
        .await
        .unwrap();
    assert_eq!(devs.roster_seq, Some(0));

    // Simulate a relay that later serves a LOWER epoch by hand-pinning a higher one first,
    // then asking to pin the old one: the history guard rejects it fail-closed.
    peer_hist
        .pin_roster("alice", 0, 5, &devs.primary_key, devs.devices.clone())
        .unwrap();
    let err = peer_hist
        .pin_roster("alice", 0, 0, &devs.primary_key, devs.devices.clone())
        .unwrap_err();
    assert_eq!(
        err,
        RosterRollback {
            username: "alice".into(),
            pinned_seq: 5,
            served_seq: 0
        }
    );

    // And end-to-end: after pinning epoch 5 locally, a real resolve (server still at 0) is
    // treated as a rollback and errors out — the send path would fail closed here.
    match client
        .resolve_account_devices(&mut peer_hist, "alice")
        .await
    {
        Err(client_core::ClientError::RosterRollback(_)) => {}
        other => panic!("expected rollback error, got {other:?}"),
    }
}

/// Revoking a linked device removes its mailbox (socket auth + new sessions die at once)
/// and the roster fan-out no longer targets it.
#[tokio::test]
async fn multi_device_revocation_removes_the_device() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 3).await.unwrap();
    let mut alice_hist = History::new();
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
    let mailbox = client.device_mailbox("alice", &req.device_id).unwrap();

    // Regression: a freshly linked device's self-audit is green — the binding carries
    // the PRIMARY's key (pinned at link time), not this device's own key, and the
    // roster holds only keys this device saw when it pinned at link time.
    assert_eq!(
        client.audit_own_key(&alice2, &alice2_hist).await.unwrap(),
        AuditOutcome::Ok
    );
    match client
        .audit_own_roster(&alice2, &alice2_hist)
        .await
        .unwrap()
    {
        client_core::multidevice::RosterAudit::Ok { devices, .. } => assert_eq!(devices, 2),
        other => panic!("fresh linked device audit: {other:?}"),
    }

    // Before revocation, a peer resolves two devices and the linked bundle is fetchable.
    let mut bob_hist = History::new();
    let devs = client
        .resolve_account_devices(&mut bob_hist, "alice")
        .await
        .unwrap();
    assert_eq!(devs.devices.len(), 2);

    // Revoke.
    let seq = client
        .revoke_device(&alice, &mut alice_hist, &req.device_id)
        .await
        .unwrap();
    assert_eq!(seq, 1);

    // The roster now has one device; the revoked device's directory record is gone.
    let devs = client
        .resolve_account_devices(&mut bob_hist, "alice")
        .await
        .unwrap();
    assert_eq!(devs.devices.len(), 1);
    // Fetching the revoked device's bundle now 404s (mailbox record removed).
    let status = reqwest::Client::new()
        .get(format!("{base}/v1/bundle/{mailbox}"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status.as_u16(), 404);

    // The revoked device verifies the relay's claim against the KT log: its key really
    // is gone from the roster — confirmed, lock out.
    assert_eq!(
        client
            .verify_device_revocation(&alice2, &mut alice2_hist)
            .await
            .unwrap(),
        client_core::multidevice::RevocationCheck::Revoked
    );
}

/// A legacy sender (single-mailbox addressing) reaches a multi-device account: the primary
/// forwards the message to the linked device, which records it as incoming.
#[tokio::test]
async fn multi_device_primary_forwards_legacy_sender_to_linked_device() {
    use client_core::Direction;

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();

    let (mut alice2, _) = create_account_with_username("alice", "Device2-Password-99!").unwrap();
    let req = client.create_link_request(&alice2);
    client
        .authorize_link(&alice, &mut alice_hist, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let mut alice2_hist = client
        .complete_link(&mut alice2, &req, "Alice-Password-123!")
        .await
        .unwrap()
        .history;
    let alice2_mailbox = client.device_mailbox("alice", &req.device_id).unwrap();

    // Bob is a LEGACY sender: he uses the plain 1:1 send (addresses only alice's account
    // mailbox), so the linked device gets no direct copy. Both alice devices have
    // accepted Bob — the message-request gate holds stranger traffic otherwise.
    let bob_key = bob.ratchet_ref().identity_key();
    alice_hist.pin_contact("bob", &bob_key, false);
    alice2_hist.pin_contact("bob", &bob_key, false);
    let alice_contact = client.add_contact(&mut bob, "alice").await.unwrap();
    client
        .send(&mut bob, &alice_contact, "legacy hello")
        .await
        .unwrap();

    // Primary drains, records, and forwards to its linked devices.
    let inbox = client.fetch_inbox(&mut alice).await.unwrap();
    let msg = inbox
        .iter()
        .find(|e| matches!(e, InboundEvent::Message { body, .. } if body == "legacy hello"))
        .cloned()
        .unwrap();
    alice_hist.apply(&msg);
    let fwd = client
        .forward_inbound_to_devices(&mut alice, &mut alice_hist, &msg)
        .await
        .unwrap();
    assert_eq!(fwd.len(), 1, "one forward to the linked device");
    client.post_envelopes(&fwd).await.unwrap();

    // Linked device receives the forward and records it as an incoming message from Bob.
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(inbox2.iter().any(
        |e| matches!(e, InboundEvent::ForwardedIncoming { body, .. } if body == "legacy hello")
    ));
    for e in &inbox2 {
        alice2_hist.apply(e);
    }
    assert!(alice2_hist
        .messages(&bob_key)
        .iter()
        .any(|m| m.body == "legacy hello" && m.direction == Direction::Incoming));
}

/// A group message fans out to every member's devices, including a linked device.
#[tokio::test]
async fn multi_device_group_message_reaches_linked_devices() {
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

    // Bob links a second device.
    let (mut bob2, _) = create_account_with_username("bob", "Bob2-Password-99!").unwrap();
    let req = client.create_link_request(&bob2);
    client
        .authorize_link(&bob, &mut bob_hist, &req, "Bob-Password-456!")
        .await
        .unwrap();
    let _ = client
        .complete_link(&mut bob2, &req, "Bob-Password-456!")
        .await
        .unwrap();
    let bob2_mailbox = client.device_mailbox("bob", &req.device_id).unwrap();

    // Alice forms a group with Bob and sends via fan-out.
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
    // Establish the KT-verified primary session first (as the shell does).
    let _ = client.add_contact(&mut alice, "bob").await.unwrap();
    client
        .send_group_multi(&mut alice, &mut alice_hist, &group, "group hi", None, false)
        .await
        .unwrap();

    // Both Bob's primary and Bob's linked device receive the group message.
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(bob_inbox
        .iter()
        .any(|e| matches!(e, InboundEvent::GroupMessage { body, .. } if body == "group hi")));
    let bob2_inbox = client
        .fetch_inbox_as(&mut bob2, &bob2_mailbox)
        .await
        .unwrap();
    assert!(bob2_inbox
        .iter()
        .any(|e| matches!(e, InboundEvent::GroupMessage { body, .. } if body == "group hi")));
}

/// History re-export: a linked device asks the primary to re-seal history; the primary
/// fulfills; the device polls and imports it.
#[tokio::test]
async fn multi_device_history_reexport_round_trip() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    let mut alice_hist = History::new();
    // Give the primary some history to sync.
    alice_hist.pin_contact("carol", "carolkey", true);
    alice_hist.record(
        "carolkey",
        client_core::Direction::Incoming,
        "m1",
        "old message",
        1,
    );

    let (mut alice2, _) = create_account_with_username("alice", "Device2-Password-99!").unwrap();
    let req = client.create_link_request(&alice2);
    client
        .authorize_link(&alice, &mut alice_hist, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let mut alice2_hist = client
        .complete_link(&mut alice2, &req, "Alice-Password-123!")
        .await
        .unwrap()
        .history;

    // The linked device requests a re-export; the primary receives + fulfills it.
    let (prov_id, ls_b64) = client
        .request_history_resync(&mut alice2, &mut alice2_hist)
        .await
        .unwrap();
    let inbox = client.fetch_inbox(&mut alice).await.unwrap();
    let request = inbox
        .iter()
        .find(|e| matches!(e, InboundEvent::SyncRequested { .. }));
    assert!(
        request.is_some(),
        "primary must receive the re-export request"
    );
    if let Some(InboundEvent::SyncRequested {
        sender_identity_key,
        provisioning_id,
        link_secret_b64,
    }) = request
    {
        assert!(
            alice_hist.is_own_device(sender_identity_key),
            "request must be from our own device"
        );
        client
            .fulfill_resync(
                &alice_hist,
                provisioning_id,
                link_secret_b64,
                "Alice-Password-123!",
            )
            .await
            .unwrap();
    }

    // The linked device polls and imports the re-exported history.
    let imported = client
        .poll_resync(&prov_id, &ls_b64, "Alice-Password-123!")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(imported.pinned_contact_key("carol"), Some("carolkey"));
    assert!(imported
        .messages("carolkey")
        .iter()
        .any(|m| m.body == "old message"));
}

/// Primary-ownership transfer, end to end against the real relay: the primary offers the
/// role to its linked device over the E2E channel; the linked device publishes the KT
/// rotation + a fresh roster naming itself primary; the old primary observes the log and
/// demotes itself. No private key crosses devices, peers resolve the new roster, and a
/// non-primary device can no longer authorize new devices.
#[tokio::test]
async fn primary_transfer_moves_the_role_end_to_end() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // Alice (primary) + Bob, plus Alice's linked second device.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();

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

    // A linked device cannot offer the transfer (no account keys, wrong state).
    assert!(client
        .offer_primary_transfer(&mut alice2, &mut alice2_hist, "0")
        .await
        .is_err());

    // Primary offers the role to the linked device (E2E to its device mailbox only).
    let demoted_id = client
        .offer_primary_transfer(&mut alice, &mut alice_hist, &req.device_id)
        .await
        .unwrap();
    assert!(alice_hist.pending_demotion().is_some());
    assert!(
        alice_hist.is_primary_device(),
        "offering must not demote until the target accepts"
    );
    // Nothing accepted yet — polling reports "still pending".
    assert!(!client
        .finish_primary_demotion(&alice, &mut alice_hist)
        .await
        .unwrap());

    // The linked device receives the authenticated offer on ITS mailbox.
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    let (entry, demoted) = inbox2
        .iter()
        .find_map(|e| match e {
            InboundEvent::PrimaryTransferOffered {
                sender_identity_key,
                entry,
                demoted,
            } => {
                assert_eq!(sender_identity_key, &alice.ratchet_ref().identity_key());
                Some((entry.clone(), demoted.clone()))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("linked device must receive the transfer offer; got {inbox2:?}"));
    assert_eq!(demoted.device_id, demoted_id);

    // A tampered offer (promoting some other key) is refused outright.
    let mut forged = entry.clone();
    forged.identity_key = "attacker-key".into();
    assert!(client
        .accept_primary_transfer(&mut alice2, &mut alice2_hist, &forged, &demoted)
        .await
        .is_err());

    // Accept: publishes the rotation + roster epoch 1; this device becomes primary.
    let seq = client
        .accept_primary_transfer(&mut alice2, &mut alice2_hist, &entry, &demoted)
        .await
        .unwrap();
    assert_eq!(seq, 1);
    assert!(alice2_hist.is_primary_device());
    assert_eq!(alice2_hist.self_device_id(), "0");

    // The old primary polls the log, sees the completed transfer, and demotes itself to
    // the pre-minted linked identity. Simulate the worst crash first: the pending
    // marker was lost (persist raced the process death) — the KT log alone must still
    // drive the demotion, or the device wedges thinking it is primary while the account
    // mailbox no longer authenticates it.
    alice_hist.clear_pending_demotion();
    assert!(client
        .finish_primary_demotion(&alice, &mut alice_hist)
        .await
        .unwrap());
    assert!(!alice_hist.is_primary_device());
    assert_eq!(alice_hist.self_device_id(), demoted_id);
    assert!(alice_hist.pending_demotion().is_none());

    // The demoted device stocks its new device mailbox with one-time keys — in the app
    // its delivery loop does this, exactly like any linked device.
    client
        .replenish_device_keys(&mut alice, "alice", &demoted_id, 20)
        .await
        .unwrap();

    // Peers resolve the new roster: primary key is the promoted device's, both devices
    // still enrolled, and a fan-out reaches both (new primary on the account mailbox,
    // old primary on its new device mailbox).
    let resolved = client
        .resolve_account_devices(&mut bob_hist, "alice")
        .await
        .unwrap();
    assert_eq!(resolved.primary_key, alice2.ratchet_ref().identity_key());
    assert_eq!(resolved.devices.len(), 2);
    let alice_contact = client_core::contact_for("alice", &alice2.ratchet_ref().identity_key());
    let fan = client
        .prepare_text_fanout(
            &mut bob,
            &mut bob_hist,
            &alice_contact,
            "post-transfer",
            None,
            false,
        )
        .await
        .unwrap();
    assert_eq!(fan.immediate.len(), 2);
    client.post_envelopes(&fan.immediate).await.unwrap();
    let new_primary_inbox = client.fetch_inbox(&mut alice2).await.unwrap();
    assert!(new_primary_inbox.iter().any(|e| matches!(e,
        InboundEvent::Message { body, .. } if body == "post-transfer")));
    let old_primary_mailbox = client.device_mailbox("alice", &demoted_id).unwrap();
    let old_primary_inbox = client
        .fetch_inbox_as(&mut alice, &old_primary_mailbox)
        .await
        .unwrap();
    assert!(old_primary_inbox.iter().any(|e| matches!(e,
        InboundEvent::Message { body, .. } if body == "post-transfer")));

    // Regression: self-audit stays green on BOTH devices across the transfer — the
    // binding now carries the promoted device's key (the demoted device checks it
    // against its updated pinned primary key), and the roster moved ids around without
    // introducing any key either device hadn't already authorized.
    assert_eq!(
        client.audit_own_key(&alice2, &alice2_hist).await.unwrap(),
        AuditOutcome::Ok
    );
    assert_eq!(
        client.audit_own_key(&alice, &alice_hist).await.unwrap(),
        AuditOutcome::Ok
    );
    match client.audit_own_roster(&alice, &alice_hist).await.unwrap() {
        client_core::multidevice::RosterAudit::Ok { devices, .. } => assert_eq!(devices, 2),
        other => panic!("demoted device roster audit: {other:?}"),
    }

    // Regression: the transfer tore down both devices' old mailboxes — the relay may
    // claim "revoked" to either. KT verification must recognize a MOVE (key still in
    // the account) and keep both devices active, never locking them out.
    use client_core::multidevice::RevocationCheck;
    assert_eq!(
        client
            .verify_device_revocation(&alice2, &mut alice2_hist)
            .await
            .unwrap(),
        RevocationCheck::StillActive
    );
    assert!(alice2_hist.is_primary_device());
    assert_eq!(
        client
            .verify_device_revocation(&alice, &mut alice_hist)
            .await
            .unwrap(),
        RevocationCheck::StillActive
    );
    assert!(!alice_hist.is_primary_device());
    assert_eq!(alice_hist.self_device_id(), demoted_id);

    // The demoted device can no longer act as the primary: a roster it signs is refused
    // by the log (its keys are no longer the KT-bound account keys).
    let (extra, _) = create_account_with_username("alice", "Device3-Password-77!").unwrap();
    let extra_req = client.create_link_request(&extra);
    assert!(client
        .authorize_link(&alice, &mut alice_hist, &extra_req, "Alice-Password-123!")
        .await
        .is_err());
}

// Hardware-attestation transport: the chain rides the relay's capability store sealed
// under the link secret (too big for the QR), and the verifier is bound to the request.
#[tokio::test]
async fn link_attestation_round_trips_and_binds_to_the_request() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (device, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let mut req = client.create_link_request(&device);
    assert!(req.attest_id.is_none(), "no attestation until attached");
    assert!(
        client.fetch_link_attestation(&req).await.unwrap().is_none(),
        "absent id → Ok(None), not an error"
    );

    // Attach a (structurally fake) chain; the transport must return it byte-identical.
    let chain = vec!["AAAA".to_string(), "BBBB".to_string()];
    client
        .attach_link_attestation(&mut req, &chain)
        .await
        .unwrap();
    assert!(req.attest_id.is_some());
    let fetched = client.fetch_link_attestation(&req).await.unwrap().unwrap();
    assert_eq!(fetched, chain);

    // A fake chain never verifies — and the entry point is challenge-bound to THIS
    // request, so even a real chain for another request would fail.
    assert!(Client::verify_link_attestation(&req, &fetched).is_err());

    // Tampered id (wrong capability): fetch errors rather than silently reporting
    // "no attestation" — the UI distinguishes "absent" from "couldn't check".
    let mut wrong = req.clone();
    wrong.attest_id = Some("0".repeat(32));
    assert!(client.fetch_link_attestation(&wrong).await.is_err());
}
