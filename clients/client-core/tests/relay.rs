use client_core::{Client, ClientError};
use crypto_core::create_account_with_username;
use server::{app, AppState, Config};

#[tokio::test]
async fn push_endpoint_registers_and_wakes_on_offline_message() {
    use std::sync::{Arc, Mutex};

    // Relay with zero debounce so each offline message wakes immediately.
    let state = AppState::new(Config {
        wake_debounce_secs: 0,
        ..Config::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let ws = format!("ws://{addr}/v1/ws");

    // Mock push provider recording every wake body.
    let hits: Arc<Mutex<Vec<String>>> = Arc::default();
    let recorded = hits.clone();
    let push_router = axum::Router::new().route(
        "/up",
        axum::routing::post(move |body: String| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().unwrap().push(body);
                axum::http::StatusCode::OK
            }
        }),
    );
    let push_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/up", push_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(push_listener, push_router).await.unwrap();
    });

    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);
    let (mut alice, _) = create_account_with_username("push-alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("push-bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();

    // Bob registers his wake endpoint through the SDK, then goes offline.
    client.register_push(&bob, &endpoint).await.unwrap();

    let bob_contact = client.add_contact(&mut alice, "push-bob").await.unwrap();
    client
        .send(&mut alice, &bob_contact, "wake up")
        .await
        .unwrap();

    // The wake arrives, and carries nothing but the constant body.
    for _ in 0..100 {
        if !hits.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(hits.lock().unwrap().as_slice(), ["wake".to_string()]);

    // Woken, Bob drains his mailbox as usual.
    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert_eq!(inbox.len(), 1);

    // Unregister → the next offline message stays silent.
    client.unregister_push(&bob).await.unwrap();
    client
        .send(&mut alice, &bob_contact, "silent")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(hits.lock().unwrap().len(), 1);
}

/// Media must wake exactly like text: a voice message / file attachment to an offline
/// push-registered recipient fires a Normal-class wake (the `File` payload declares
/// `WakeClass::Normal`, same as `Text`) — a push-only device gets its notification for
/// voice and media, not just for plain messages.
#[tokio::test]
async fn attachments_wake_offline_recipients_like_text() {
    use std::sync::{Arc, Mutex};

    let state = AppState::new(Config {
        wake_debounce_secs: 0,
        ..Config::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let ws = format!("ws://{addr}/v1/ws");

    let hits: Arc<Mutex<Vec<String>>> = Arc::default();
    let recorded = hits.clone();
    let push_router = axum::Router::new().route(
        "/up",
        axum::routing::post(move |body: String| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().unwrap().push(body);
                axum::http::StatusCode::OK
            }
        }),
    );
    let push_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/up", push_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(push_listener, push_router).await.unwrap();
    });

    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);
    let (mut alice, _) = create_account_with_username("att-alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("att-bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    client.register_push(&bob, &endpoint).await.unwrap();

    let bob_contact = client.add_contact(&mut alice, "att-bob").await.unwrap();

    // A voice message is a File payload with the voice flag set inside the E2E
    // reference — the relay only ever sees the envelope's wake class.
    let mut attachment = client
        .upload_attachment("voice.webm", b"opus-opus-opus")
        .await
        .unwrap();
    attachment.voice = true;
    attachment.duration_secs = 3;
    let prepared = client
        .prepare_attachment(&mut alice, &bob_contact, attachment, None, false)
        .unwrap();
    client.post_envelope(&prepared.envelope).await.unwrap();

    for _ in 0..100 {
        if !hits.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        hits.lock().unwrap().as_slice(),
        ["wake".to_string()],
        "a voice attachment must fire a Normal wake for an offline recipient"
    );

    // Plain file: same class, same wake.
    let attachment = client
        .upload_attachment("photo.jpg", b"jpegjpegjpeg")
        .await
        .unwrap();
    let prepared = client
        .prepare_attachment(&mut alice, &bob_contact, attachment, None, false)
        .unwrap();
    client.post_envelope(&prepared.envelope).await.unwrap();
    for _ in 0..100 {
        if hits.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(hits.lock().unwrap().len(), 2, "a file must wake too");

    // Receipts stay silent (WakeClass::None) — the wake budget is for content only.
    let receipt = client
        .prepare_receipt(&mut alice, &bob_contact, vec!["m1".into()], true)
        .unwrap()
        .unwrap();
    client.post_envelope(&receipt).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(hits.lock().unwrap().len(), 2, "a receipt must never wake");
}

/// A token-gated relay end to end: a client holding the shared token gets full service
/// (REST + the authenticated WebSocket drain); a client without it is refused before
/// any handler runs.
#[tokio::test]
async fn access_token_gates_rest_and_websocket() {
    let config = Config {
        access_mode: server::access::AccessMode::Token,
        access_token_hashes: vec![server::access::token_digest("shared-relay-token-1")],
        ..Config::default()
    };
    let state = AppState::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let ws = format!("ws://{addr}/v1/ws");

    // Without the token: even the bootstrap fetch is refused.
    assert!(Client::fetch_kt_pubkey(&base, None).await.is_err());

    // With it: the full flow works — register, discover, send, WS inbox drain.
    let pinned = Client::fetch_kt_pubkey(&base, Some("shared-relay-token-1"))
        .await
        .unwrap();
    let client =
        Client::with_access_token(&base, &ws, &pinned, Some("shared-relay-token-1".into()));
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    client
        .send(&mut alice, &bob_contact, "hello through the gate")
        .await
        .unwrap();
    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert_eq!(inbox.len(), 1);

    // A tokenless client cannot even open the delivery socket (upgrade refused).
    let bare = Client::new(&base, &ws, &pinned);
    // Specifically AccessDenied — the terminal "token rotated / evicted" signal that
    // sends the UI to the reconnect screen instead of retrying forever.
    assert!(matches!(
        bare.fetch_inbox(&mut bob).await,
        Err(ClientError::AccessDenied)
    ));
}

/// Invite-gated registration end to end: a fresh account needs an unused code, the code
/// burns on success, and the relay advertises the capability so clients know to ask.
#[tokio::test]
async fn invite_code_gates_new_accounts() {
    let config = Config {
        registration_code_hashes: vec![hex::encode(server::access::token_digest(
            "welcome-code-42",
        ))],
        ..Config::default()
    };
    let state = AppState::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_state).into_make_service())
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let ws = format!("ws://{addr}/v1/ws");
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    // The relay advertises the gate so the client shows the code field.
    let caps = client.server_capabilities().await.unwrap();
    assert!(caps.iter().any(|c| c == client_core::CAP_INVITE_REGISTER));

    // No code → refused. With the code → registered.
    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    assert!(client.register(&mut alice, 5).await.is_err());
    client
        .register_with_invite(&mut alice, 5, Some("welcome-code-42"))
        .await
        .unwrap();

    // Burned: a second account can't reuse it.
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    assert!(client
        .register_with_invite(&mut bob, 5, Some("welcome-code-42"))
        .await
        .is_err());

    // Alice's own re-register (rotation path) still works without any code.
    client.register(&mut alice, 5).await.unwrap();
}
