//! Shared integration-test harness: boots the real relay in-process.

use server::{app, AppState};

/// Boot the real relay on an ephemeral port; return (base_url, ws_url, shared state).
pub async fn spawn_relay() -> (String, String, AppState) {
    let state = AppState::default();
    // QUIC media endpoint on an ephemeral UDP port, discovered via /v1/call/quic —
    // call tests exercise the real preferred transport end to end.
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
    (
        format!("http://{addr}"),
        format!("ws://{addr}/v1/ws"),
        state,
    )
}
