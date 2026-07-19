//! Headless JNI entry points (docs/NOTIFICATIONS.md §4.2) — how Android starts/pokes the delivery
//! engine when there is no Tauri activity at all: the sticky-restarted
//! `DeliveryService`, the boot receiver, the FCM/UnifiedPush wake receivers, the
//! connectivity callback, and notification actions.
//!
//! Every function here carries no secrets: paths, booleans, routing keys. Action
//! payloads are validated in Rust against live state (an unknown call id is a no-op).
//! The application context was installed by `SonaApp` (`nativeInitAppContext`) before
//! any of these can run — Kotlin loads the native library in `SonaApp.onCreate`.

use jni::objects::{JClass, JObject, JString};
use jni::sys::jboolean;
use jni::JNIEnv;

use crate::eng;

/// `SonaApp.onCreate` → hand the JavaVM + APPLICATION context to ndk-context. This is
/// the context every headless consumer (Keystore device key, service control, the
/// notification bridge) resolves classes through; it lives as long as the process.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_SonaApp_nativeInitAppContext(
    env: JNIEnv,
    _class: JClass,
    ctx: JObject,
) {
    crate::android_media::install_ndk_context(&env, &ctx, true);
}

/// Read a Java string parameter, best-effort.
fn jstr(env: &mut JNIEnv, s: &JString) -> Option<String> {
    env.get_string(s).ok().map(String::from)
}

/// Seed the engine's data dir from the path Kotlin passes (`context.dataDir` — the
/// exact directory Tauri's `app_data_dir` resolves to on Android). Idempotent.
fn ensure_engine_init(env: &mut JNIEnv, data_dir: &JString) {
    if let Some(dir) = jstr(env, data_dir) {
        eng().init_data_dir(std::path::PathBuf::from(dir));
    }
}

/// Sticky/boot restart of `DeliveryService` (mode C/C+P): boot the engine, try the
/// silent auto-unlock, resume full delivery — or set the truthful "Locked" status.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_DeliveryService_nativeStartHeadless(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) {
    ensure_engine_init(&mut env, &data_dir);
    let inner = eng().session.clone();
    eng().spawn(async move {
        crate::headless_start(&inner).await;
    });
}

/// A content-free push wake arrived (`{"t":"m"}` / `{"t":"c"}`): drain the mailbox in
/// a short burst (or ring/notify generically when the vault can't open headless). The
/// shortService is released through `NotificationBridge.drainFinished()` when the
/// engine is done.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_NotificationBridge_nativeWake(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
    call_class: jboolean,
) {
    ensure_engine_init(&mut env, &data_dir);
    let inner = eng().session.clone();
    let call = call_class != 0;
    eng().spawn(async move {
        crate::headless_wake(&inner, call).await;
    });
}

/// ConnectivityManager callback: network came back / changed — reconnect immediately
/// instead of sitting out the rest of a backoff.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_NotificationBridge_nativeNetworkChanged(
    _env: JNIEnv,
    _class: JClass,
) {
    eng().nudge_network();
}

/// MainActivity lifecycle → authoritative `focused` on Android (tao's focus events
/// stop arriving once the activity dies; the activity lifecycle never lies).
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_NotificationBridge_nativeActivityState(
    _env: JNIEnv,
    _class: JClass,
    resumed: jboolean,
) {
    eng().set_focused(resumed != 0);
}

/// A notification action (Decline, for now) from the OS shade.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_NotificationBridge_nativeNotifAction(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) {
    let Some(json) = jstr(&mut env, &json) else {
        return;
    };
    let inner = eng().session.clone();
    eng().spawn(async move {
        crate::notif_action(&inner, &json).await;
    });
}

/// A (possibly rotated) FCM registration token from Kotlin (`onNewToken`, or the
/// fetch kicked by the engine). Re-registers with the relay when it changed.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_NotificationBridge_nativeSetPushToken(
    mut env: JNIEnv,
    _class: JClass,
    token: JString,
) {
    if let Some(token) = jstr(&mut env, &token) {
        crate::on_new_push_token(token);
    }
}

/// The UnifiedPush distributor delivered (or revoked) an endpoint URL. Empty string =
/// endpoint gone (unregistered, distributor uninstalled, registration failed) — the
/// registration then falls back to the FCM token or unregisters from the relay.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_NotificationBridge_nativeSetUpEndpoint(
    mut env: JNIEnv,
    _class: JClass,
    endpoint: JString,
) {
    if let Some(endpoint) = jstr(&mut env, &endpoint) {
        crate::on_new_up_endpoint(endpoint);
    }
}

/// The user tapped a notification whose intent carries routing extras (open a chat /
/// answer a call). Forwarded from `MainActivity.onNewIntent`; the engine relays it to
/// the webview, which navigates after unlock.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_NotificationBridge_nativeOpenIntent(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) {
    if let Some(json) = jstr(&mut env, &json) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
            eng().set_pending_intent(v.clone());
            eng().emit("navigate", v);
        }
    }
}
