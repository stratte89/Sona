//! Access-tier integration: the gate must reject before anything else runs, stealth
//! must be indistinguishable from "nothing here", and the IP allowlist must honor the
//! trusted proxy header — all through the real router.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use server::access::{token_digest, AccessMode, Cidr};
use server::{app, AppState, Config};
use tower::ServiceExt;

const TOKEN: &str = "correct-horse-battery-staple";

fn state_with(config: Config) -> AppState {
    AppState::new(config)
}

async fn get(state: &AppState, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().uri(path).method("GET");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = app(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

fn token_config(mode: AccessMode) -> Config {
    Config {
        access_mode: mode,
        access_token_hashes: vec![token_digest(TOKEN)],
        ..Config::default()
    }
}

#[tokio::test]
async fn token_mode_rejects_missing_and_wrong_tokens() {
    let state = state_with(token_config(AccessMode::Token));
    // No token → 401, even on the most public endpoint.
    let (status, _) = get(&state, "/v1/kt/sth", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Wrong token → 401.
    let (status, _) = get(&state, "/v1/kt/sth", &[("x-sona-access", "wrong")]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Right token → normal service.
    let (status, _) = get(&state, "/v1/kt/sth", &[("x-sona-access", TOKEN)]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn token_mode_accepts_any_listed_token() {
    let mut config = token_config(AccessMode::Token);
    config
        .access_token_hashes
        .push(token_digest("second-token-for-rotation"));
    let state = state_with(config);
    let (status, _) = get(
        &state,
        "/v1/kt/sth",
        &[("x-sona-access", "second-token-for-rotation")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn stealth_mode_is_a_uniform_bare_404() {
    let state = state_with(token_config(AccessMode::Stealth));
    // A real endpoint without the token: bare 404, empty body...
    let (status, body) = get(&state, "/v1/kt/sth", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.is_empty(), "stealth deny must carry no body");
    // ...byte-identical to a bogus path (no fingerprint from the difference).
    let (status2, body2) = get(&state, "/no/such/path", &[]).await;
    assert_eq!(status, status2);
    assert_eq!(body, body2);
    // Wrong token: same bare 404, not a 401 (a 401 would say "something is here").
    let (status, body) = get(&state, "/v1/kt/sth", &[("x-sona-access", "wrong")]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.is_empty());
    // The token unlocks normal service.
    let (status, _) = get(&state, "/v1/kt/sth", &[("x-sona-access", TOKEN)]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn ip_allowlist_filters_by_proxy_header() {
    let config = Config {
        prod: true,
        allowed_origins: vec!["https://example.org".into()],
        ip_allowlist: vec![Cidr::parse("10.0.0.0/8").unwrap()],
        ..Config::default()
    };
    let state = state_with(config);
    // Allowlisted address passes.
    let (status, _) = get(&state, "/v1/kt/sth", &[("x-real-ip", "10.1.2.3")]).await;
    assert_eq!(status, StatusCode::OK);
    // Same address in IPv4-mapped-IPv6 form still matches.
    let (status, _) = get(&state, "/v1/kt/sth", &[("x-real-ip", "::ffff:10.1.2.3")]).await;
    assert_eq!(status, StatusCode::OK);
    // Outside the list → denied.
    let (status, _) = get(&state, "/v1/kt/sth", &[("x-real-ip", "203.0.113.7")]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // No trusted header in prod → fail closed.
    let (status, _) = get(&state, "/v1/kt/sth", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn open_mode_is_untouched() {
    let state = state_with(Config::default());
    let (status, _) = get(&state, "/v1/kt/sth", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

// ─────────────────────── Registration invite codes ───────────────────────

mod invites {
    use super::*;
    use crypto_core::ratchet::RatchetEngine;
    use kt_log::KtEntry;
    use protocol_types::IdentityHash;
    use serde_json::json;

    fn invite_config(codes: &[&str]) -> Config {
        Config {
            registration_code_hashes: codes.iter().map(|c| hex::encode(token_digest(c))).collect(),
            ..Config::default()
        }
    }

    fn claim_body(engine: &RatchetEngine, account_id: &str) -> serde_json::Value {
        let hash = IdentityHash::from_identifier(account_id)
            .as_str()
            .to_string();
        let entry = KtEntry::new_claim(
            hash,
            engine.identity_key(),
            engine.signing_key(),
            100,
            |p| engine.sign(p),
        );
        json!({ "entry": entry, "one_time_keys": ["k1"] })
    }

    async fn post_register(
        state: &AppState,
        body: serde_json::Value,
        invite: Option<&str>,
    ) -> StatusCode {
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/register")
            .header("content-type", "application/json");
        if let Some(code) = invite {
            req = req.header("x-sona-invite", code);
        }
        app(state.clone())
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn fresh_claims_need_an_unused_code_and_codes_are_single_use() {
        let state = AppState::new(invite_config(&["code-alpha-123", "code-beta-456"]));
        let alice = RatchetEngine::new();
        // No code → refused; nothing enters the log.
        assert_eq!(
            post_register(&state, claim_body(&alice, "alice"), None).await,
            StatusCode::FORBIDDEN
        );
        // Wrong code → refused.
        assert_eq!(
            post_register(&state, claim_body(&alice, "alice"), Some("nope")).await,
            StatusCode::FORBIDDEN
        );
        // Valid code → registered.
        assert_eq!(
            post_register(&state, claim_body(&alice, "alice"), Some("code-alpha-123")).await,
            StatusCode::OK
        );
        // The code is burned: a second brand-new claim with it is refused...
        let mallory = RatchetEngine::new();
        assert_eq!(
            post_register(
                &state,
                claim_body(&mallory, "mallory"),
                Some("code-alpha-123")
            )
            .await,
            StatusCode::FORBIDDEN
        );
        // ...but the second listed code still works.
        assert_eq!(
            post_register(
                &state,
                claim_body(&mallory, "mallory"),
                Some("code-beta-456")
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn rotations_are_never_gated() {
        let state = AppState::new(invite_config(&["only-code-1"]));
        let alice = RatchetEngine::new();
        assert_eq!(
            post_register(&state, claim_body(&alice, "alice"), Some("only-code-1")).await,
            StatusCode::OK
        );
        // Key rotation on the existing chain: no code, code list exhausted — still OK.
        let hash = IdentityHash::from_identifier("alice").as_str().to_string();
        let new_keys = RatchetEngine::new();
        let rotation = KtEntry::new_rotation(
            1,
            hash,
            new_keys.identity_key(),
            new_keys.signing_key(),
            alice.signing_key(),
            200,
            false,
            |p| alice.sign(p),
        );
        let body = json!({ "entry": rotation, "one_time_keys": ["k2"] });
        assert_eq!(post_register(&state, body, None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn no_codes_configured_means_open_registration() {
        let state = AppState::new(Config::default());
        let alice = RatchetEngine::new();
        assert_eq!(
            post_register(&state, claim_body(&alice, "alice"), None).await,
            StatusCode::OK
        );
    }
}

// ─────────────────────── Global storage quota ───────────────────────

#[tokio::test]
async fn storage_ceiling_refuses_uploads_when_full() {
    let config = Config {
        max_storage_bytes: 100,
        ..Config::default()
    };
    let state = state_with(config);
    let post = |body: Vec<u8>| {
        let app = app(state.clone());
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/blobs")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };
    // Fits (80 of 100).
    assert_eq!(post(vec![0u8; 80]).await, StatusCode::OK);
    // Would cross the ceiling (80 + 80 > 100) — refused, regardless of which address
    // sent it (per-client budgets don't help against many addresses; this does).
    assert_eq!(post(vec![0u8; 80]).await, StatusCode::INSUFFICIENT_STORAGE);
    // Small remainder still fits (80 + 20 = 100).
    assert_eq!(post(vec![0u8; 20]).await, StatusCode::OK);
}
