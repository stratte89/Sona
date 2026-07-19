use client_core::{Client, InboundEvent};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

#[tokio::test]
async fn attachment_round_trips_and_server_stays_blind() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let alice_id = alice.ratchet_ref().identity_key();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();

    // Alice sends a "file" (bytes). Only ciphertext hits the relay.
    let file = b"\x89PNG fake-image bytes \x00\x01\x02\x03".to_vec();
    let sent = client
        .send_file(&mut alice, &bob_contact, "cat.png", &file)
        .await
        .unwrap();

    // The raw blob on the server is NOT the plaintext (it's encrypted client-side).
    let raw = reqwest::get(format!("{base}/v1/blobs/{}", sent.blob_id))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_ne!(raw.as_ref(), file.as_slice());

    // Bob receives an Attachment event, downloads, verifies, and decrypts to the original.
    let events = client.fetch_inbox(&mut bob).await.unwrap();
    let att = events
        .iter()
        .find_map(|e| match e {
            InboundEvent::Attachment {
                attachment,
                sender_identity_key,
                ..
            } if *sender_identity_key == alice_id => Some(attachment.clone()),
            _ => None,
        })
        .expect("attachment event");
    assert_eq!(att.filename, "cat.png");
    assert_eq!(att.size, file.len());
    assert_eq!(client.download_attachment(&att).await.unwrap(), file);

    // Tampered reference (wrong hash) is rejected before decryption.
    let mut bad = att.clone();
    bad.content_hash = "AAAA".into();
    assert!(client.download_attachment(&bad).await.is_err());
}

#[tokio::test]
async fn attachment_padding_hides_file_size() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();

    // Two files of very different sizes, both small enough to share a padding bucket.
    let s1 = client
        .send_file(&mut alice, &bob_contact, "a", &[1u8; 10])
        .await
        .unwrap();
    let s2 = client
        .send_file(&mut alice, &bob_contact, "b", &[2u8; 200])
        .await
        .unwrap();

    let blob_len = |id: &str| {
        let url = format!("{base}/v1/blobs/{id}");
        async move {
            reqwest::get(url)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .len()
        }
    };
    // Same on-wire length → the server can't tell a 10-byte file from a 200-byte one.
    assert_eq!(blob_len(&s1.blob_id).await, blob_len(&s2.blob_id).await);
}

#[tokio::test]
async fn voice_message_metadata_travels_inside_the_ratchet() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();

    // A "recording": upload through the normal E2E attachment path, then mark the
    // reference as a voice message before sealing it into the ratchet.
    let audio = vec![0x52u8; 4096]; // opaque bytes; format is a client concern
    let mut att = client
        .upload_attachment("voice-1.webm", &audio)
        .await
        .unwrap();
    att.voice = true;
    att.duration_secs = 7;
    let prepared = client
        .prepare_attachment(&mut alice, &bob_contact, att, None, false)
        .unwrap();
    client.post_envelope(&prepared.envelope).await.unwrap();

    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let got = inbox
        .iter()
        .find_map(|e| match e {
            InboundEvent::Attachment { attachment, .. } => Some(attachment.clone()),
            _ => None,
        })
        .expect("voice attachment delivered");
    assert!(got.voice, "voice flag must survive the ratchet round trip");
    assert_eq!(got.duration_secs, 7);
    // And the blob itself still decrypts + verifies like any attachment.
    assert_eq!(client.download_attachment(&got).await.unwrap(), audio);
}
