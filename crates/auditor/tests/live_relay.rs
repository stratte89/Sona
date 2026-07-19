//! End-to-end: the auditor's HTTP observation loop against the *real* relay (real Axum
//! router, real TCP, real endpoint shapes). The unit tests in `lib.rs` prove the
//! witness math; this proves the wire contract — if a KT endpoint's path or JSON shape
//! drifts, this fails.

use auditor::{observe_once, AlarmKind, Outcome, Witness};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use kt_log::{KtEntry, KtLog};
use rand::rngs::OsRng;
use server::{app, AppState, Config};

fn b64e(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn claim(name: &str) -> KtEntry {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = b64e(sk.verifying_key().as_bytes());
    KtEntry::new_claim(name.into(), "id".into(), vk, 1, |p| {
        b64e(&sk.sign(p).to_bytes())
    })
}

/// Serve `state` on an ephemeral local port; returns the base URL.
async fn serve(state: AppState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state).into_make_service())
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn witnesses_honest_growth_over_real_http() {
    let state = AppState::new(Config::default());
    let pinned = state.inner.lock().unwrap().kt.verifying_key_b64();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let mut w = Witness::new(pinned);

    // Baseline on an empty log.
    assert_eq!(
        observe_once(&client, &base, &mut w).await.unwrap(),
        Outcome::FirstHead
    );
    assert_eq!(
        observe_once(&client, &base, &mut w).await.unwrap(),
        Outcome::Unchanged
    );

    // The log grows (as it would on registrations) → consistency proven over the wire.
    for name in ["alice", "bob"] {
        state.inner.lock().unwrap().kt.append(claim(name)).unwrap();
    }
    assert_eq!(
        observe_once(&client, &base, &mut w).await.unwrap(),
        Outcome::Extended { from: 0, to: 2 }
    );
    assert_eq!(
        observe_once(&client, &base, &mut w).await.unwrap(),
        Outcome::Unchanged
    );

    // Grow again from a non-empty baseline — this leg exercises the real consistency
    // proof served by /v1/kt/consistency.
    state
        .inner
        .lock()
        .unwrap()
        .kt
        .append(claim("carol"))
        .unwrap();
    assert_eq!(
        observe_once(&client, &base, &mut w).await.unwrap(),
        Outcome::Extended { from: 2, to: 3 }
    );
}

#[tokio::test]
async fn raises_rollback_alarm_when_relay_restores_a_smaller_log() {
    // A relay whose log has two entries…
    let seed = KtLog::generate().signing_key_seed_b64();
    let mut kt = KtLog::from_seed_b64(&seed).unwrap();
    kt.append(claim("alice")).unwrap();
    kt.append(claim("bob")).unwrap();
    let pinned = kt.verifying_key_b64();
    let state = AppState::with_kt(Config::default(), kt);
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let mut w = Witness::new(pinned);
    assert_eq!(
        observe_once(&client, &base, &mut w).await.unwrap(),
        Outcome::FirstHead
    );

    // …"restored from backup": same signing key, shorter history. The consistency
    // endpoint now 400s (from > size), which must surface as a rollback alarm, not a
    // transport error.
    let mut shorter = KtLog::from_seed_b64(&seed).unwrap();
    shorter.append(claim("alice")).unwrap();
    state.inner.lock().unwrap().kt = shorter;

    match observe_once(&client, &base, &mut w).await.unwrap() {
        Outcome::Alarm(a) => assert_eq!(a.kind, AlarmKind::Rollback),
        other => panic!("expected rollback alarm, got {other:?}"),
    }
}

#[tokio::test]
async fn raises_equivocation_alarm_over_real_http() {
    // Two logs signed by the same key, same size, different first entry.
    let seed = KtLog::generate().signing_key_seed_b64();
    let mut real = KtLog::from_seed_b64(&seed).unwrap();
    real.append(claim("alice")).unwrap();
    let pinned = real.verifying_key_b64();
    let state = AppState::with_kt(Config::default(), real);
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let mut w = Witness::new(pinned);
    assert_eq!(
        observe_once(&client, &base, &mut w).await.unwrap(),
        Outcome::FirstHead
    );

    let mut fork = KtLog::from_seed_b64(&seed).unwrap();
    fork.append(claim("attacker")).unwrap();
    state.inner.lock().unwrap().kt = fork;

    match observe_once(&client, &base, &mut w).await.unwrap() {
        Outcome::Alarm(a) => assert_eq!(a.kind, AlarmKind::Equivocation),
        other => panic!("expected equivocation alarm, got {other:?}"),
    }
}
