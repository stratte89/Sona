use crate::*;

#[tauri::command]
pub async fn delivery_status(state: tauri::State<'_, AppState>) -> Result<DeliveryView, String> {
    let (mode, push_registered, client) = {
        let s = state.inner.lock().await;
        (
            s.prefs.delivery_mode.clone(),
            s.prefs.push_endpoint.is_some(),
            s.client.clone(),
        )
    };
    let caps = match client {
        Some(c) => c.server_capabilities().await.unwrap_or_default(),
        None => Vec::new(),
    };
    let conn = match eng().conn_state() {
        notifier::ConnState::Connected => "connected",
        notifier::ConnState::Reconnecting => "reconnecting",
        notifier::ConnState::Locked => "locked",
        notifier::ConnState::Off => "off",
    };
    Ok(DeliveryView {
        mode,
        conn,
        relay_fcm: caps.iter().any(|c| c == client_core::CAP_PUSH_FCM),
        relay_webhook: caps.iter().any(|c| c == client_core::CAP_PUSH_WEBHOOK),
        push_registered,
        push_token: eng().push_token().is_some(),
        up_endpoint: eng().up_endpoint().is_some(),
        health: notifier::health_json().and_then(|j| serde_json::from_str(&j).ok()),
    })
}

/// Installed UnifiedPush distributor apps: `[{pkg, label}]` (empty on desktop or
/// when none is installed — the settings UI then points at ntfy).
#[tauri::command]
pub fn up_distributors() -> serde_json::Value {
    notifier::up_distributors()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!([]))
}

/// Choose a UnifiedPush distributor. The endpoint arrives async from the distributor
/// (`nativeSetUpEndpoint`), which re-runs the relay registration — nothing else to do.
#[tauri::command]
pub fn up_select(pkg: String) {
    notifier::up_register(&pkg);
}

/// Stop using UnifiedPush: unregister from the distributor, then reconcile the relay
/// registration (falls back to the system push token, or unregisters entirely).
#[tauri::command]
pub async fn up_clear(state: tauri::State<'_, AppState>) -> Result<(), String> {
    notifier::up_unregister();
    eng().set_up_endpoint(None);
    do_push_registration(&state.inner).await;
    // An auto-defaulted "push only" without its wake transport must fall back to the
    // connection (exactly what this button's caption promises).
    maybe_auto_delivery_mode(&state.inner).await;
    Ok(())
}

/// Switch the delivery mode. Idempotent, crash-safe ordering: the incoming transport
/// comes up before the outgoing one goes down — never a gap with neither live.
#[tauri::command]
pub async fn set_delivery_mode(
    state: tauri::State<'_, AppState>,
    mode: String,
) -> Result<(), String> {
    if !matches!(mode.as_str(), "c" | "cp" | "p") {
        return Err("unknown delivery mode".into());
    }
    let unlocked = {
        let mut s = state.inner.lock().await;
        s.prefs.delivery_mode = mode.clone();
        s.prefs.delivery_mode_set = true; // explicit choice: the auto-default backs off for good
        s.save_prefs()?;
        s.account.is_some()
    };
    match mode.as_str() {
        // Connection modes: FGS up first, then reconcile the push registration
        // (cp registers, c unregisters).
        "c" | "cp" => {
            if unlocked {
                delivery_service::set_background_delivery(true);
                eng().set_conn_state(notifier::ConnState::Reconnecting);
                // A socket may already be live; the state settles on next conn event.
            }
            spawn_push_registration(&state.inner);
        }
        // Push only: register FIRST, stop the service after.
        _ => {
            let inner = state.inner.clone();
            eng().spawn(async move {
                do_push_registration(&inner).await;
                delivery_service::set_background_delivery(false);
                eng().set_conn_state(notifier::ConnState::Off);
            });
        }
    }
    Ok(())
}

/// "If you can see this, message notifications work."
#[tauri::command]
pub fn test_notification() {
    eng().notify_message(&NotifPlan {
        chat_key: "__test__".into(),
        title: "Sona".into(),
        body: "If you can see this, message notifications work".into(),
        msg_id: String::new(),
    });
}

/// Local fake ring through the full native pipeline; auto-cancels after 5 s.
#[tauri::command]
pub fn test_ring() {
    eng().show_ring("__test_ring__", "Sona (test ring)", false);
    eng().spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        eng().cancel_ring("__test_ring__", "");
    });
}

/// Health-panel fix-it buttons (Android): 0 battery exemption, 1 notification
/// settings, 2 full-screen-intent settings.
#[tauri::command]
pub fn delivery_fixit(what: i32) {
    notifier::open_fixit(what);
}

/// Background the app like the home button (Android; no-op elsewhere). The
/// double-back-to-exit gesture ends the SESSION, not the delivery engine.
#[tauri::command]
pub fn app_background() {
    #[cfg(target_os = "android")]
    android_media::move_task_to_back();
}

/// Routing extras from the notification tap that launched the app (cold start), if
/// any. The UI calls this once after load/unlock; warm taps arrive as `navigate`
/// events instead.
#[tauri::command]
pub fn take_pending_intent() -> Option<serde_json::Value> {
    eng().take_pending_intent()
}
