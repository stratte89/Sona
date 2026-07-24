use crate::*;

/// Password-policy check, surfaced live in the create-account form.
#[tauri::command]
pub fn password_strength(password: String) -> StrengthView {
    let r = check_password(&password);
    StrengthView {
        acceptable: r.acceptable,
        problems: r.problems,
    }
}

/// Where the UI should start: is a relay configured, does a vault exist, are we unlocked.
#[tauri::command]
pub async fn app_status(state: tauri::State<'_, AppState>) -> Result<StatusView, String> {
    let s = state.inner.lock().await;
    Ok(StatusView {
        configured: s.config.is_some(),
        has_vault: s.vault_path().exists(),
        unlocked: s.account.is_some(),
        account_id: s.account.as_ref().map(|a| a.account_id().to_string()),
        base_url: s.config.as_ref().map(|c| c.base_url.clone()),
        revoked: s.account.is_some() && s.history.revoked(),
        private_relay: s.config.as_ref().is_some_and(|c| c.access_token.is_some()),
    })
}

/// The relay invite payload: everything a new member needs in one scan/paste — URL,
/// pinned KT key, and (for a private relay) the shared access token. Rendered as a QR
/// in settings; consumed by the connect screen's scan/paste path.
#[tauri::command]
pub async fn relay_invite(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let s = state.inner.lock().await;
    let cfg = s.config.as_ref().ok_or("not configured")?;
    let mut v = serde_json::json!({
        "sona": "invite",
        "v": 1,
        "url": cfg.base_url,
        "kt": cfg.pinned_kt_key,
    });
    if let Some(token) = &cfg.access_token {
        v["token"] = serde_json::Value::String(token.clone());
    }
    Ok(v.to_string())
}

/// Does this relay gate new accounts behind an invite code (`CAP_INVITE_REGISTER`)?
/// The create-account screen shows the code field only when true.
#[tauri::command]
pub async fn registration_needs_invite(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let client = state
        .inner
        .lock()
        .await
        .client
        .clone()
        .ok_or("not configured")?;
    Ok(client
        .server_capabilities()
        .await
        .map(|caps| caps.iter().any(|c| c == client_core::CAP_INVITE_REGISTER))
        .unwrap_or(false))
}

/// Bootstrap helper for onboarding: fetch the relay's advertised KT public key so the user
/// can pre-fill the pin. The UI must warn that this value is to be confirmed out-of-band —
/// trusting it blindly defeats Key Transparency.
#[tauri::command]
pub async fn fetch_kt_pubkey(
    state: tauri::State<'_, AppState>,
    base_url: String,
    access_token: Option<String>,
) -> Result<String, String> {
    let token = access_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    // Honor an already-configured SOCKS proxy: the bootstrap fetch happening outside
    // Tor would leak the relay hostname and the user's IP before the pin is even set.
    let proxy = state.inner.lock().await.prefs.socks_proxy.clone();
    Client::fetch_kt_pubkey_via(base_url.trim(), token, proxy.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// Point the app at a relay and pin its KT public key. Persists `config.json` and builds
/// the client. Derives the WebSocket URL from the base URL.
#[tauri::command]
pub async fn configure(
    state: tauri::State<'_, AppState>,
    base_url: String,
    pinned_kt_key: String,
    access_token: Option<String>,
) -> Result<(), String> {
    let base_url = base_url.trim().trim_end_matches('/').to_string();
    let pinned_kt_key = pinned_kt_key.trim().to_string();
    let access_token = access_token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if base_url.is_empty() || pinned_kt_key.is_empty() {
        return Err("relay URL and pinned KT key are both required".into());
    }
    let ws_url = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
        + "/v1/ws";
    let cfg = RelayConfig {
        base_url: base_url.clone(),
        ws_url: ws_url.clone(),
        pinned_kt_key: pinned_kt_key.clone(),
        access_token: access_token.clone(),
    };
    let mut s = state.inner.lock().await;
    std::fs::write(
        s.config_path(),
        serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    s.client = Some(Arc::new(
        Client::with_access_token(base_url, ws_url, pinned_kt_key, access_token)
            .with_proxy(s.prefs.socks_proxy.clone()),
    ));
    s.config = Some(cfg);
    Ok(())
}

/// Current SOCKS proxy setting (`None` = direct).
#[tauri::command]
pub async fn socks_proxy(state: tauri::State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state.inner.lock().await.prefs.socks_proxy.clone())
}

/// Set or clear the SOCKS5 proxy (Tor/Orbot) for every relay connection. Persists the
/// pref, rebuilds the client, and — when a session is unlocked — restarts the
/// subscriber so the new route applies immediately (the old task stops via its watch
/// channel; in-flight sockets on the old route die with it).
#[tauri::command]
pub async fn set_socks_proxy(
    state: tauri::State<'_, AppState>,
    proxy: Option<String>,
) -> Result<(), String> {
    let proxy = proxy
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(p) = &proxy {
        let rest = p
            .strip_prefix("socks5h://")
            .or_else(|| p.strip_prefix("socks5://"))
            .unwrap_or(p);
        // host:port, both non-empty, port numeric — catches pasted garbage early
        // without trying to be a full URL parser.
        let ok = matches!(rest.rsplit_once(':'), Some((h, port)) if !h.is_empty()
            && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()));
        if !ok {
            return Err("expected socks5://host:port (e.g. socks5://127.0.0.1:9050)".into());
        }
    }
    let mut s = state.inner.lock().await;
    s.prefs.socks_proxy = proxy;
    s.save_prefs()?;
    if let Some(cfg) = s.config.clone() {
        s.client = Some(Arc::new(
            Client::with_access_token(
                cfg.base_url,
                cfg.ws_url,
                cfg.pinned_kt_key,
                cfg.access_token,
            )
            .with_proxy(s.prefs.socks_proxy.clone()),
        ));
        if s.account.is_some() {
            crate::runtime::spawn_subscriber(&state.inner, &mut s);
        }
    }
    Ok(())
}

/// Create a new account, register it, seal the vault + empty history to disk, and start
/// the live poll. Returns the new account id.
#[tauri::command]
pub async fn create_account(
    state: tauri::State<'_, AppState>,
    username: String,
    password: String,
    invite_code: Option<String>,
) -> Result<String, String> {
    let username = username.trim().to_string();
    let invite_code = invite_code
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    eprintln!("[create] start (deriving vault key + device binding)");
    let dk = device_key_or_create();
    eprintln!(
        "[create] device key: {}",
        if dk.is_some() { "bound" } else { "none" }
    );
    let (mut account, _vault) =
        create_account_with_username_bound(&username, &password, dk.as_ref())
            .map_err(|e| e.to_string())?;
    eprintln!("[create] vault sealed; registering with relay");
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    // `register` advances the ratchet (mints one-time keys); persist happens below.
    client
        .register_with_invite(&mut account, 20, invite_code.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("[create] registered");
    s.multi_device = detect_capabilities(&client).await;
    let id = account.account_id().to_string();
    let my_key = account.ratchet_ref().identity_key();
    s.account = Some(account);
    s.history = History::new();
    // A freshly created account is its own primary — seed the self key (see
    // `install_unlocked_account`).
    s.history.set_self_primary_key(&my_key);
    s.persist()?;
    spawn_subscriber(&state.inner, &mut s);
    drop(s);
    // First launch is the moment the delivery-mode default matters most: resolve it now
    // (mirrors `finish_unlock` — without this, a fresh account keeps "connection" until
    // the next app restart even when the relay supports push). The push registration
    // also kicks the FCM token fetch, whose arrival re-runs the auto-default.
    spawn_push_registration(&state.inner);
    {
        let inner = state.inner.clone();
        eng().spawn(async move {
            maybe_auto_delivery_mode(&inner).await;
        });
    }
    Ok(id)
}

/// Shared tail of every unlock path (password / PIN / biometric / auto): load history,
/// top up one-time keys, install the account, persist, start live delivery (main mailbox
/// plus former-username alias mailboxes). Any successful unlock resets the PIN counter.
pub(crate) async fn finish_unlock(
    inner: &Arc<Mutex<Session>>,
    s: &mut Session,
    account: Account,
) -> Result<String, String> {
    let id = install_unlocked_account(s, account).await?;
    spawn_subscriber(inner, s);
    // Delivery mode C+P / P: (re-)register the push endpoint — idempotent upsert, and
    // it self-heals a rotated FCM token (§6.4 token lifecycle).
    spawn_push_registration(inner);
    // No mode ever chosen in settings? Resolve the default now that the relay's
    // capabilities and this device's push transports can actually be probed.
    {
        let inner = inner.clone();
        eng().spawn(async move {
            maybe_auto_delivery_mode(&inner).await;
        });
    }
    // A primary-transfer offer (or a half-finished accept) survived the restart —
    // surface it again so the user can accept/retry.
    if s.history.pending_promotion().is_some() {
        eng().emit("primary_transfer", ());
    }
    // A revocation observed before the restart: re-surface the lockout immediately (the
    // delivery loop would also rediscover it, but only after a network round-trip).
    if s.history.revoked() {
        eng().emit("revoked", ());
    }
    Ok(id)
}

/// The delivery-agnostic half of an unlock: load + install history and the account,
/// top up keys, persist. Shared by the interactive unlock paths (which then start the
/// full subscriber) and the headless push drain (which starts a drain loop instead).
pub(crate) async fn install_unlocked_account(
    s: &mut Session,
    mut account: Account,
) -> Result<String, String> {
    // Load encrypted history (fail-soft to empty on a bad/missing blob).
    let mut history = match std::fs::read(s.history_path()) {
        Ok(hist_blob) => History::open(&account.data_key(), &hist_blob),
        Err(_) => History::new(),
    };
    // Heal any thread that drifted into self-sync arrival order on an older build; new
    // messages stay ordered on insert. One-time, cheap on already-ordered threads.
    history.normalize_message_order();
    // On the primary (which includes every single-device account) our own identity key IS
    // the account primary key. Seed it so History::apply can recognize "us" in a group
    // epoch (kick/re-add detection) without waiting for a multi-device selfsync to run —
    // on a single-device account no selfsync ever runs, so this is the only seed.
    if history.is_primary_device() {
        history.set_self_primary_key(&account.ratchet_ref().identity_key());
    }
    let id = account.account_id().to_string();
    // Best-effort key top-up so peers can keep starting sessions with us, plus a
    // capability probe (multi-device gating). A linked device tops up its DEVICE mailbox.
    if let Some(client) = s.client.clone() {
        s.multi_device = detect_capabilities(&client).await;
        if history.is_primary_device() {
            // Self-heal a relay that lost our binding (e.g. a non-persistent relay
            // restarted): the vault outlives the relay's KT log, and without the
            // binding nobody can discover us and the self-audit reads "not
            // registered". register() is idempotent for a name we own (and reclaims
            // through a release), so this is safe to run opportunistically.
            if matches!(
                client.audit_own_key(&account, &history).await,
                Ok(client_core::AuditOutcome::NotRegistered)
            ) {
                let _ = client.register(&mut account, 20).await;
            }
            let _ = client.replenish_own_keys(&mut account, 20).await;
        } else {
            let username = account.account_id().to_string();
            let _ = client
                .replenish_device_keys(&mut account, &username, &history.self_device_id(), 20)
                .await;
        }
    }
    s.account = Some(account);
    s.history = history;
    if s.prefs.pin_attempts != 0 {
        s.prefs.pin_attempts = 0;
        let _ = s.save_prefs();
    }
    s.persist()?;
    // Locked-state generics ("You may have new messages", the generic ring) are now
    // superseded: the subscriber/drain this unlock starts produces the real, leveled
    // notifications. A generic ring left ringing past this point reads as a second
    // incoming call (§7.4).
    notifier::clear_generics();
    Ok(id)
}

/// Unlock the on-disk vault with the password, load history, top up one-time keys, and
/// start the live poll. Returns the account id.
#[tauri::command]
pub async fn unlock(state: tauri::State<'_, AppState>, password: String) -> Result<String, String> {
    let mut s = state.inner.lock().await;
    let blob = std::fs::read(s.vault_path()).map_err(|_| "no vault on this device")?;
    let account =
        unlock_bound(&password, device_key().as_ref(), &blob).map_err(|e| e.to_string())?;
    finish_unlock(&state.inner, &mut s, account).await
}

/// Drop the unlocked identity from memory and stop the poller. The sealed vault stays on
/// disk; the relay config stays configured.
#[tauri::command]
pub async fn lock(state: tauri::State<'_, AppState>) -> Result<(), String> {
    do_lock(&state.inner).await;
    eng().set_conn_state(notifier::ConnState::Off);
    Ok(())
}

/// The lock itself — shared by the command and the engine's background auto-lock
/// (the UI-side idle timer freezes when the webview is backgrounded; see §7.3).
pub(crate) async fn do_lock(inner: &Arc<Mutex<Session>>) {
    let mut s = inner.lock().await;
    s.account = None;
    s.history = History::new();
    s.last_presence_ok = None;
    // Locking mid-call hangs up: the session keys leave memory, so must the call's.
    if let Some(call) = s.call.take() {
        let _ = call.stop.send(true);
    }
    s.incoming = None;
    s.reconnect = None;
    if let Some(gc) = s.group_call.take() {
        let _ = gc.stop.send(true);
    }
    s.group_incoming = None;
    if let Some(stop) = s.stop.take() {
        let _ = stop.send(true); // the live-delivery task exits promptly
    }
    // No session, no delivery: let Android freeze/kill the process again. The push
    // registration (if any) deliberately stays — locked-state wakes surface honest
    // generics instead of silent loss (docs/NOTIFICATIONS.md §7.4).
    delivery_service::set_background_delivery(false);
}
