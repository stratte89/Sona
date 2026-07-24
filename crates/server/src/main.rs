//! Sona relay binary.
//!
//! Reads minimal config from the environment and serves the blind relay. TLS is
//! terminated by a reverse proxy in front (the relay speaks plain HTTP/WS on the bind
//! address); the proxy is responsible for `wss://`. See deployment docs.
//!
//! Env (in `PROD=1`, the starred secrets are REQUIRED — the relay refuses to start rather
//! than fall back to an insecure default or print a secret to logs; see `require_prod`):
//! * `BIND`             — listen address (default `127.0.0.1:5002`).
//! * `PROD`             — `1` to enforce WebSocket Origin checks and fail-closed config.
//! * `ALLOWED_ORIGINS`* — comma-separated origins permitted in production.
//! * `RATE_SALT`*       — secret salt for rate-limit pseudonymization.
//! * `KT_SIGNING_KEY`*  — base64 32-byte seed for the Key Transparency key. Off-prod, if
//!   unset a fresh one is generated and its seed printed (persist it!).
//! * `DB_PATH`          — SQLite file for durable storage. If unset, state is in-memory
//!   (lost on restart).
//! * `STORAGE_KEY`*     — base64 32-byte key encrypting message blobs at rest. Keep it
//!   OFF the data disk (env/secrets manager). Off-prod, if unset one is generated + printed.
//! * `MAX_ROOMS`        — max concurrent call rooms (default 1024).
//! * `GIPHY_API_KEY`    — enables the GIF privacy proxy (`/v1/gif/*`): the relay
//!   forwards search + media so client IPs never reach the GIF provider. Unset = off.
//! * `FCM_SERVICE_ACCOUNT_JSON` / `FCM_SERVICE_ACCOUNT_JSON_FILE` — a Firebase service
//!   account (inline JSON, or a path to it). Enables `fcm:<token>` push endpoints and
//!   the `push-fcm-v1` capability. Unset = FCM off; webhook push still works.
//! * `FCM_PROJECT_ID`   — overrides the project id from the service-account JSON.
//! * `WAKE_DEBOUNCE_SECS` / `CALL_WAKE_MIN_SECS` — per-recipient wake intervals for
//!   message-class (default 30) and call-class (default 2) pushes.
//! * `ACCESS_MODE`      — relay discoverability tier: `open` (default), `token`, or
//!   `stealth`. See `server::access` for the full design and threat model.
//! * `RELAY_ACCESS_TOKENS` — comma-separated shared access tokens (required when
//!   `ACCESS_MODE` is not `open`; a list so rotation can overlap). Min 16 chars each.
//! * `IP_ALLOWLIST`     — optional comma-separated CIDRs; only these addresses may use
//!   the relay. Empty/unset = off. Independent of `ACCESS_MODE`.
//! * `MAX_WS_PER_IP`    — max concurrent delivery sockets per client address (default 16).
//! * `MAX_STORAGE_BYTES` — global ceiling on stored attachment + sync bytes (default
//!   10 GiB). Uploads over it get `507`; TTL expiry frees space.
//! * `BLOB_TTL_DAYS`   — hard attachment retention cap in days (default 30). Blobs are
//!   deleted when it elapses regardless of chat state — E2EE deletion signals and
//!   sealed-sender uploads mean the relay cannot tie a blob to a message, so the
//!   schedule is the only deletion it can honestly perform.
//! * `REGISTRATION_CODES` — comma-separated single-use invite codes (min 8 chars each).
//!   Non-empty = brand-new account claims need an unused code (`x-sona-invite` header);
//!   rotations/renames/linked devices are never gated. Consumed codes persist in the DB.

use std::time::Duration;

use kt_log::KtLog;
use server::{app, AppState, Config, Db};

/// Decode a base64 (no-pad) 32-byte key, or exit with a clear message.
fn decode_key_32(var: &str, value: &str) -> [u8; 32] {
    vodozemac::base64_decode(value)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .unwrap_or_else(|| panic!("{var} must be base64 of exactly 32 bytes"))
}

/// Refuse to start rather than silently fall back to an insecure default. Used for the
/// secrets/origins that MUST be operator-supplied in production (L-5).
fn require_prod(var: &str, why: &str) -> ! {
    eprintln!("[FATAL] {var} must be set in production ({why}). Refusing to start.");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:5002".to_string());
    let prod = std::env::var("PROD").as_deref() == Ok("1");
    let allowed_origins = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    // Fail closed in production: an empty origin allowlist would disable WebSocket origin
    // checks, so require it explicitly rather than warning and running open (L-5).
    if prod && allowed_origins.is_empty() {
        require_prod(
            "ALLOWED_ORIGINS",
            "empty allowlist disables WebSocket origin checks",
        );
    }

    // The rate-limit salt must be operator-supplied in prod; the dev default is public and
    // would make pseudonymized rate keys predictable (L-5). Only fall back off-prod.
    let rate_salt = match std::env::var("RATE_SALT") {
        Ok(s) if !s.is_empty() => s,
        _ if prod => require_prod("RATE_SALT", "the dev default is public/predictable"),
        _ => "dev-rate-salt".to_string(),
    };

    // Load the Key Transparency key from a persisted seed. In prod it MUST be supplied
    // (a generated one would print a secret to logs AND rotate the pinned key on restart);
    // off-prod, generate one and tell the operator to persist it (L-5).
    let kt = match std::env::var("KT_SIGNING_KEY") {
        Ok(seed) => KtLog::from_seed_b64(&seed).expect("KT_SIGNING_KEY is not a valid base64 seed"),
        Err(_) if prod => require_prod(
            "KT_SIGNING_KEY",
            "would be auto-generated (secret to logs) and rotate the pinned key on restart",
        ),
        Err(_) => {
            let kt = KtLog::generate();
            eprintln!("[KT] No KT_SIGNING_KEY set — generated a new one (dev only).");
            eprintln!(
                "[KT]   persist this seed:   KT_SIGNING_KEY={}",
                kt.signing_key_seed_b64()
            );
            eprintln!("[KT]   pin this in clients:  {}", kt.verifying_key_b64());
            kt
        }
    };
    println!("[KT] pinned public key: {}", kt.verifying_key_b64());

    let max_rooms = std::env::var("MAX_ROOMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(server::call::DEFAULT_MAX_ROOMS);

    // GIF privacy proxy: search + media go through the relay so user IPs never reach
    // the provider. No key = endpoints off, clients hide the GIF UI.
    let giphy_key = std::env::var("GIPHY_API_KEY")
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());
    if giphy_key.is_some() {
        println!("[gif] Giphy proxy enabled (search + media via relay)");
    }

    // Released-username grace override (seconds) — for test relays exercising the
    // reclaim flow; production keeps the 7-day default.
    let release_grace_secs = std::env::var("RELEASE_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(kt_log::RELEASE_GRACE_SECS);
    if release_grace_secs != kt_log::RELEASE_GRACE_SECS {
        println!("[kt] release grace overridden: {release_grace_secs}s");
    }

    // Wake intervals (per recipient, per class) — defaults are fine for production;
    // overridable mostly for test relays.
    let wake_debounce_secs = std::env::var("WAKE_DEBOUNCE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(Config::default().wake_debounce_secs);
    let call_wake_min_secs = std::env::var("CALL_WAKE_MIN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(Config::default().call_wake_min_secs);

    // Access tier: open (default) / token / stealth. An unrecognized value is fatal —
    // a typo silently falling back to `open` would run a private relay wide open.
    let access_mode = match server::access::AccessMode::parse(
        &std::env::var("ACCESS_MODE").unwrap_or_default(),
    ) {
        Some(m) => m,
        None => {
            eprintln!("[FATAL] ACCESS_MODE must be one of: open, token, stealth.");
            std::process::exit(1);
        }
    };
    let access_token_hashes: Vec<[u8; 32]> = std::env::var("RELAY_ACCESS_TOKENS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            if t.len() < 16 {
                eprintln!(
                    "[FATAL] RELAY_ACCESS_TOKENS: token too short (min 16 chars). \
                     Generate one with:  head -c 32 /dev/urandom | base64 | tr -d '='"
                );
                std::process::exit(1);
            }
            server::access::token_digest(t)
        })
        .collect();
    if access_mode != server::access::AccessMode::Open && access_token_hashes.is_empty() {
        require_prod(
            "RELAY_ACCESS_TOKENS",
            "ACCESS_MODE=token/stealth without tokens would lock everyone out",
        );
    }
    match access_mode {
        server::access::AccessMode::Open => {}
        m => println!(
            "[access] mode={:?}: requests require the shared token ({} accepted)",
            m,
            access_token_hashes.len()
        ),
    }

    // Optional IP allowlist. A malformed entry is fatal (fail closed): silently skipping
    // it would admit addresses the operator meant to exclude.
    let ip_allowlist: Vec<server::access::Cidr> = std::env::var("IP_ALLOWLIST")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            server::access::Cidr::parse(s).unwrap_or_else(|| {
                eprintln!("[FATAL] IP_ALLOWLIST: malformed entry {s:?} (want addr or CIDR).");
                std::process::exit(1);
            })
        })
        .collect();
    if !ip_allowlist.is_empty() {
        println!(
            "[access] IP allowlist active ({} entries)",
            ip_allowlist.len()
        );
    }

    let max_ws_per_client = std::env::var("MAX_WS_PER_IP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(Config::default().max_ws_per_client);

    let max_storage_bytes = std::env::var("MAX_STORAGE_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(Config::default().max_storage_bytes);

    let blob_ttl_secs = std::env::var("BLOB_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|d| *d > 0)
        .map(|d| d * 24 * 3600)
        .unwrap_or(Config::default().blob_ttl_secs);

    // Single-use registration invite codes. Digests only in memory; consumed codes are
    // remembered durably (DB) so a restart can't resurrect one.
    let registration_code_hashes: Vec<String> = std::env::var("REGISTRATION_CODES")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| {
            if c.len() < 8 {
                eprintln!("[FATAL] REGISTRATION_CODES: code too short (min 8 chars).");
                std::process::exit(1);
            }
            hex::encode(server::access::token_digest(c))
        })
        .collect();
    if !registration_code_hashes.is_empty() {
        println!(
            "[access] registration gated by invite codes ({} configured)",
            registration_code_hashes.len()
        );
    }

    let config = Config {
        prod,
        allowed_origins,
        rate_salt,
        max_rooms,
        giphy_key,
        release_grace_secs,
        wake_debounce_secs,
        call_wake_min_secs,
        access_mode,
        access_token_hashes,
        ip_allowlist,
        max_ws_per_client,
        max_storage_bytes,
        blob_ttl_secs,
        registration_code_hashes,
    };

    // FCM wake adapter: needs a Firebase service account. Self-hosters without one
    // simply don't get the mode — fcm: registrations are refused, capability not
    // advertised, and the webhook (UnifiedPush-shaped) path is unaffected.
    let fcm_sa_json = match std::env::var("FCM_SERVICE_ACCOUNT_JSON") {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => std::env::var("FCM_SERVICE_ACCOUNT_JSON_FILE")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .map(|p| std::fs::read_to_string(p.trim()).expect("FCM_SERVICE_ACCOUNT_JSON_FILE")),
    };
    let fcm = fcm_sa_json.map(|json| {
        let project = std::env::var("FCM_PROJECT_ID")
            .ok()
            .filter(|p| !p.trim().is_empty());
        server::push::FcmSender::from_service_account_json(&json, project)
            .expect("invalid FCM service account")
    });
    if fcm.is_some() {
        println!("[push] FCM wake adapter enabled (fcm: endpoints accepted)");
    }

    // Durable storage if DB_PATH is set; otherwise in-memory (lost on restart).
    let mut state = match std::env::var("DB_PATH") {
        Ok(db_path) => {
            let storage_key = match std::env::var("STORAGE_KEY") {
                Ok(k) => decode_key_32("STORAGE_KEY", &k),
                Err(_) if prod => require_prod(
                    "STORAGE_KEY",
                    "would be auto-generated and printed to logs, defeating at-rest encryption",
                ),
                Err(_) => {
                    let mut k = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
                    eprintln!("[DB] No STORAGE_KEY set — generated one (dev only).");
                    eprintln!(
                        "[DB]   persist this (KEEP OFF THE DATA DISK):  STORAGE_KEY={}",
                        vodozemac::base64_encode(k)
                    );
                    k
                }
            };
            let db = Db::open(&db_path, &storage_key).expect("failed to open database");
            println!("[DB] durable storage at {db_path} (encrypted at rest)");
            AppState::persistent(config, kt, db)
        }
        Err(_) => {
            eprintln!("[DB] DB_PATH unset — running in-memory (state lost on restart).");
            AppState::with_kt(config, kt)
        }
    };
    if let Some(fcm) = fcm {
        state = state.with_fcm(fcm);
    }
    let state = state;

    // QUIC media endpoint: on by default (UDP), disable with QUIC_PORT=0. Uses a
    // boot-time self-signed cert; clients fetch + pin its hash via /v1/call/quic.
    let mut quic_port: u16 = std::env::var("QUIC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4443);
    // Stealth means "a scanner learns nothing" — but a QUIC handshake completes before
    // any token could be checked, so an open UDP media port is itself an answer. Force
    // it off; calls fall back to the WebSocket media path, which rides the token-gated
    // HTTP surface.
    if state.config.access_mode == server::access::AccessMode::Stealth && quic_port != 0 {
        println!("[access] stealth mode: QUIC media endpoint disabled (probe-able pre-auth)");
        quic_port = 0;
    }
    if quic_port != 0 {
        match server::quic::start(state.clone(), quic_port) {
            Ok(info) => {
                *state.quic.lock().unwrap() = Some(info.clone());
                println!(
                    "[QUIC] media endpoint on udp/{} (cert pinned via /v1/call/quic)",
                    info.port
                );
            }
            Err(e) => eprintln!("[QUIC] disabled — {e} (calls fall back to WebSocket)"),
        }
    } else {
        println!("[QUIC] disabled by QUIC_PORT=0 — calls use WebSocket only");
    }

    // GIF trending pre-load: warm the relay-side cache at boot so the first client to
    // open the GIF tab gets suggestions instantly (no-op when the proxy is disabled).
    if state.config.giphy_key.is_some() {
        let state = state.clone();
        tokio::spawn(server::http::warm_gif_trending(state));
    }

    // Periodic reaper: without it, prune only ran at startup, so expired messages/blobs,
    // spent nonces, stale rate buckets, and abandoned call rooms accumulated between
    // restarts (M-3, M-4). Sweep every 60s — cheap, and bounds every unbounded-growth path.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await; // fire immediately, then every 60s
            loop {
                tick.tick().await;
                let t = server::state::now();
                {
                    let mut inner = state.inner.lock().unwrap();
                    inner.store.prune(t);
                    inner.challenges.sweep(t);
                    inner.rate.sweep(t);
                    inner.auth_rate.sweep(t);
                    inner.upload_bytes.sweep(t);
                    inner.download_bytes.sweep(t);
                    inner.sync_blobs.retain(|_, (_, exp)| *exp > t);
                    if let Some(db) = &inner.db {
                        let _ = db.prune_expired(t);
                        let _ = db.prune_blobs(t);
                        let _ = db.prune_sync(t);
                        let _ = db.clamp_null_expiry(t + server::store::MAX_MESSAGE_TTL_SECS);
                    }
                }
                state.calls.lock().unwrap().gc(t);
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("failed to bind");
    println!("Sona relay listening on {bind} (prod={prod})");
    // Backstop layers (Caddy in front has its own timeouts; these hold even if the
    // relay is ever exposed directly): a global in-flight request cap so a request
    // flood degrades to queueing instead of memory growth, and a generous per-request
    // deadline that still ends stuck handlers/bodies. WebSocket sessions are unaffected
    // — the upgrade response completes fast and the socket lives outside the service.
    let service = app(state)
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(300),
        ))
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(1024));
    axum::serve(listener, service.into_make_service())
        .await
        .expect("server error");
}
