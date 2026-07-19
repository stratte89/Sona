// Regression: sending attachments to a group is roster-gated, never admin-gated — a
// non-admin member's picture must fan out (legacy and multi-device paths) and land
// in every member's thread.
use client_core::{Client, History};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

#[tokio::test]
async fn non_admin_member_can_send_group_attachment() {
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
    let bob_id = bob.ratchet_ref().identity_key();

    // Alice (admin) creates the group with bob + carol.
    let bob_c = client.add_contact(&mut alice, "bob").await.unwrap();
    let carol_c = client.add_contact(&mut alice, "carol").await.unwrap();
    let (group, _epoch) = client
        .create_group(&mut alice, "trip", &[bob_c, carol_c])
        .await
        .unwrap();

    // Bob ingests the invite so his roster is pinned like a real client's.
    let mut bob_hist = History::new();
    bob_hist.pin_contact("alice", &alice_id, false);
    for e in &client.fetch_inbox(&mut bob).await.unwrap() {
        bob_hist.apply(e);
    }
    let bg = bob_hist.group(&group.id).expect("bob has the group");
    assert!(!bg.left, "bob wrongly marked left");
    // Rebuild the Group shape the desktop shell would pass to send_group_file.
    let bob_group = client_core::Group {
        id: group.id.clone(),
        name: bg.name.clone(),
        members: bg.members.clone(),
    };

    // Bob (NOT the admin) uploads and fans a picture.
    let file = b"\x89PNG not-really-a-png".to_vec();
    let att = client.upload_attachment("pic.png", &file).await.unwrap();
    client
        .send_group_file(&mut bob, &bob_group, att, Some(0), false)
        .await
        .expect("non-admin group file send must succeed");

    // Carol receives and applies it — the picture must land in her group thread.
    let mut carol_hist = History::new();
    carol_hist.pin_contact("alice", &alice_id, false);
    for e in &client.fetch_inbox(&mut carol).await.unwrap() {
        carol_hist.apply(e);
    }
    let cg = carol_hist.group(&group.id).expect("carol has the group");
    let m = cg
        .messages
        .iter()
        .find(|m| m.attachment.is_some())
        .expect("carol must see bob's attachment");
    assert_eq!(m.sender.as_deref(), Some(bob_id.as_str()));
}

#[tokio::test]
async fn non_admin_member_can_send_group_attachment_multi_device_path() {
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

    let bob_c = client.add_contact(&mut alice, "bob").await.unwrap();
    let carol_c = client.add_contact(&mut alice, "carol").await.unwrap();
    let (group, _epoch) = client
        .create_group(&mut alice, "trip", &[bob_c, carol_c])
        .await
        .unwrap();

    // Bob ingests the invite, then sends a file over the MULTI-DEVICE fan — the path the
    // shell actually uses on a capability-detected relay.
    let mut bob_hist = History::new();
    bob_hist.pin_contact("alice", &alice_id, false);
    for e in &client.fetch_inbox(&mut bob).await.unwrap() {
        bob_hist.apply(e);
    }
    let bg = bob_hist.group(&group.id).expect("bob has the group");
    let bob_group = client_core::Group {
        id: group.id.clone(),
        name: bg.name.clone(),
        members: bg.members.clone(),
    };
    let att = client
        .upload_attachment("pic.png", b"\x89PNG bytes")
        .await
        .unwrap();
    client
        .send_group_file_multi(&mut bob, &mut bob_hist, &bob_group, att, false)
        .await
        .expect("non-admin multi-device group file send must succeed");

    let mut carol_hist = History::new();
    carol_hist.pin_contact("alice", &alice_id, false);
    for e in &client.fetch_inbox(&mut carol).await.unwrap() {
        carol_hist.apply(e);
    }
    let cg = carol_hist.group(&group.id).expect("carol has the group");
    assert!(
        cg.messages.iter().any(|m| m.attachment.is_some()),
        "carol must see bob's attachment"
    );
}
