//! Platform notification pipeline — the one place OS notifications are posted from.
//!
//! Android: every call goes over JNI to the injected `NotificationBridge` (application
//! context, never the activity — RC-2 in docs/NOTIFICATIONS.md: the tauri notification plugin is
//! constructed against the Activity and dies with it, while the delivery engine keeps
//! running). Desktop: the tauri notification plugin, reached through the engine's
//! attached UI handle (the tray keeps the process and the handle alive).
//!
//! Everything here is best-effort: a notification that fails to post must never take
//! down a delivery loop — failures log and return.

/// Truthful foreground-service status (Android), mirrored into the persistent
/// notification's text so it can never lie about delivery state (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Connected,
    Reconnecting,
    /// Vault locked, no auto-unlock: delivery is paused and the user must know.
    Locked,
    /// Vault locked, **but a wake transport is registered and the process hold is kept**
    /// (E-2): messages wait for the unlock, and an incoming call can still reach this
    /// device. A state of its own rather than a nicer string for [`ConnState::Locked`],
    /// because the difference is exactly what §4.5 forbids being vague about — one of
    /// these two rings for an incoming call and the other does not.
    LockedWakeable,
    /// No delivery expected (mode P, or logged out) — no persistent notification.
    Off,
}

impl ConnState {
    /// Wire code for the Kotlin bridge (`setServiceStatus`); Android-only consumer.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn code(self) -> i32 {
        match self {
            ConnState::Connected => 0,
            ConnState::Reconnecting => 1,
            ConnState::Locked => 2,
            ConnState::Off => 3,
            ConnState::LockedWakeable => 4,
        }
    }
}

/// One MessagingStyle line (engine-buffered per chat and replayed on every post, so
/// the shade shows the last few messages of the chat, not just the newest).
#[derive(serde::Serialize, Clone)]
pub struct NotifLine {
    pub title: String,
    pub body: String,
    /// Unix millis.
    pub when: u64,
}

/// The call id the locked-vault generic ring is posted under (`showGeneric(1)` posts a
/// `CallStyle` notification for this id). Cancelling it is how the call-only subsystem
/// takes that ring down when a capsule says the call is already over.
pub const LOCKED_CALL_RING: &str = "locked-call";

/// Generic (content-free) notification kinds for the locked-vault degradation path.
#[derive(Debug, Clone, Copy)]
pub enum Generic {
    /// `"t":"m"` wake with no way to decrypt: "You may have new messages".
    MaybeMessages,
    /// `"t":"c"` wake with no way to decrypt: insistent generic ring.
    ///
    /// Only legitimate with a pending ring in the call-control store behind it, so that
    /// Answer and Decline both resolve to something (`internal/CALL_PLAN.md` §3.1). Where there is
    /// no such state, [`Generic::UnactionableCall`] is the honest surface.
    LockedCall,
    /// A call is happening and this device cannot act on it: no capsule survived the
    /// drain, there is no call-control identity, or the mailbox could not be screened.
    ///
    /// Deliberately **not** a ring. The user still has to learn a call is happening —
    /// L-11 settled that, and silence would be worse — but an `INSISTENT|NO_DISMISS`
    /// ringtone whose Answer and Decline buttons resolve to nothing is not how that
    /// requirement is met. This is dismissible, silent, and only opens the app.
    UnactionableCall,
}

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(not(target_os = "android"))]
pub use desktop::*;

// ─────────────────────────────── Android: JNI bridge ───────────────────────────────

#[cfg(target_os = "android")]
mod android {
    use super::{ConnState, Generic, NotifLine};
    use jni::objects::{JClass, JObject, JValue};

    const BRIDGE_CLASS: &str = "app.sona.messenger.NotificationBridge";

    /// Resolve the injected bridge class through the app context's classloader
    /// (`FindClass` on a native thread only sees system classes) and run `f`.
    fn with_bridge(
        f: impl for<'a> FnOnce(&mut jni::JNIEnv<'a>, &JClass<'a>) -> Result<(), String>,
    ) -> Result<(), String> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach: {e}"))?;
        let context = unsafe { JObject::from_raw(ctx.context().cast()) };
        let loader = env
            .call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
            .and_then(|v| v.l())
            .map_err(|e| format!("getClassLoader: {e}"))?;
        let name = env
            .new_string(BRIDGE_CLASS)
            .map_err(|e| format!("class name: {e}"))?;
        let class = env
            .call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )
            .and_then(|v| v.l())
            .map_err(|e| {
                let _ = env.exception_clear();
                format!("NotificationBridge not found (re-run harden-android.sh): {e}")
            })?;
        let class = JClass::from(class);
        let out = f(&mut env, &class);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return Err("NotificationBridge call raised a Java exception".into());
        }
        out
    }

    fn log_err(what: &str, r: Result<(), String>) {
        if let Err(e) = r {
            crate::diag!("[notifier] {what}: {e}");
        }
    }

    /// Bring the app forward so the user can unlock and finish answering a call.
    pub fn open_app_for_unlock() {
        log_err(
            "openAppForUnlock",
            with_bridge(|env, class| {
                env.call_static_method(class, "openAppForUnlock", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// Is the OS keyguard up? See `NotificationBridge.deviceLocked` for why this, and not
    /// the vault, is what "require unlock to answer" has to read. A probe that cannot be
    /// made at all counts as locked — the cost is a human check, never a call answered
    /// without one.
    pub fn device_locked() -> bool {
        let mut out = true;
        let r = with_bridge(|env, class| {
            out = env
                .call_static_method(class, "deviceLocked", "()Z", &[])
                .and_then(|v| v.z())
                .map_err(|e| e.to_string())?;
            Ok(())
        });
        log_err("deviceLocked", r);
        out
    }

    /// The unlock attempt resolved: take its prompt down.
    pub fn clear_unlock_prompt() {
        log_err(
            "clearUnlockPrompt",
            with_bridge(|env, class| {
                env.call_static_method(class, "clearUnlockPrompt", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// Post/refresh a chat's MessagingStyle notification with the buffered lines.
    pub fn show_message(chat_key: &str, lines: &[NotifLine]) {
        let json = serde_json::to_string(lines).unwrap_or_else(|_| "[]".into());
        log_err(
            "showMessage",
            with_bridge(|env, class| {
                let key = env.new_string(chat_key).map_err(|e| e.to_string())?;
                let lines = env.new_string(&json).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "showMessage",
                    "(Ljava/lang/String;Ljava/lang/String;)V",
                    &[JValue::Object(&key), JValue::Object(&lines)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    /// Remove a chat's notification (all its lines expired or the chat was opened).
    pub fn cancel_chat(chat_key: &str) {
        log_err(
            "cancelChat",
            with_bridge(|env, class| {
                let key = env.new_string(chat_key).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "cancelChat",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&key)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    /// Full native ring: CallStyle (API 31+) / high-priority actions (26–30) +
    /// full-screen intent + insistent channel ringtone; auto-times-out at the ring
    /// timeout. `title` is already privacy-leveled by the engine.
    pub fn show_call(call_id: &str, title: &str, is_group: bool) {
        log_err(
            "showCall",
            with_bridge(|env, class| {
                let id = env.new_string(call_id).map_err(|e| e.to_string())?;
                let t = env.new_string(title).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "showCall",
                    "(Ljava/lang/String;Ljava/lang/String;Z)V",
                    &[
                        JValue::Object(&id),
                        JValue::Object(&t),
                        JValue::Bool(is_group as u8),
                    ],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    /// Stop the ring. `missed_title` non-empty ⇒ also post a "Missed call" entry on
    /// the status channel (privacy-leveled by the engine).
    /// The ring was **answered** here: stop the ringtone and the call screen, but hand the
    /// foreground-service process hold to the unlock window rather than ending it (E-5).
    pub fn accept_call(call_id: &str) {
        log_err(
            "acceptCall",
            with_bridge(|env, class| {
                let id = env.new_string(call_id).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "acceptCall",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&id)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    /// Give back a process hold taken by an answer (E-5). No-op unless one is held, so
    /// every path that ends an answer's waiting period can call it blindly.
    pub fn release_call_hold() {
        log_err(
            "releaseCallHold",
            with_bridge(|env, class| {
                env.call_static_method(class, "releaseCallHold", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    pub fn cancel_call(call_id: &str, missed_title: &str) {
        log_err(
            "cancelCall",
            with_bridge(|env, class| {
                let id = env.new_string(call_id).map_err(|e| e.to_string())?;
                let t = env.new_string(missed_title).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "cancelCall",
                    "(Ljava/lang/String;Ljava/lang/String;)V",
                    &[JValue::Object(&id), JValue::Object(&t)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    /// The system clipboard's image, if any: `{"name","mime","b64"}` JSON, `None`
    /// when the clipboard holds no readable image. Paste-gesture fallback only.
    pub fn clipboard_image() -> Option<String> {
        let mut out = None;
        let r = with_bridge(|env, class| {
            let v = env
                .call_static_method(class, "clipboardImageJson", "()Ljava/lang/String;", &[])
                .and_then(|v| v.l())
                .map_err(|e| e.to_string())?;
            let s: String = env.get_string(&v.into()).map_err(|e| e.to_string())?.into();
            if !s.is_empty() {
                out = Some(s);
            }
            Ok(())
        });
        log_err("clipboardImageJson", r);
        out
    }

    /// Locked-vault degradation (§7.4): content-free generic per wake class.
    pub fn show_generic(kind: Generic) {
        let code = match kind {
            Generic::MaybeMessages => 0,
            Generic::LockedCall => 1,
            Generic::UnactionableCall => 2,
        };
        log_err(
            "showGeneric",
            with_bridge(|env, class| {
                env.call_static_method(class, "showGeneric", "(I)V", &[JValue::Int(code)])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// The vault unlocked: drop the locked-state generics (§7.4) — real notifications
    /// take over, and a stale generic ring must not outlive the unlock.
    pub fn clear_generics() {
        log_err(
            "clearGenerics",
            with_bridge(|env, class| {
                env.call_static_method(class, "clearGenerics", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// Truthful FGS status text (no-op when the service isn't running).
    pub fn set_service_status(state: ConnState) {
        log_err(
            "setServiceStatus",
            with_bridge(|env, class| {
                env.call_static_method(
                    class,
                    "setServiceStatus",
                    "(I)V",
                    &[JValue::Int(state.code())],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    /// A push-triggered drain finished — release the shortService.
    pub fn drain_finished() {
        log_err(
            "drainFinished",
            with_bridge(|env, class| {
                env.call_static_method(class, "drainFinished", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// Installed UnifiedPush distributor apps as a JSON array `[{pkg,label}]`.
    pub fn up_distributors() -> Option<String> {
        let mut out = None;
        let r = with_bridge(|env, class| {
            let v = env
                .call_static_method(class, "upDistributors", "()Ljava/lang/String;", &[])
                .and_then(|v| v.l())
                .map_err(|e| e.to_string())?;
            let s: String = env.get_string(&v.into()).map_err(|e| e.to_string())?.into();
            out = Some(s);
            Ok(())
        });
        log_err("upDistributors", r);
        out
    }

    /// Ask `pkg` (a distributor) for an endpoint; it lands async via
    /// `nativeSetUpEndpoint` once the distributor answers.
    pub fn up_register(pkg: &str) {
        log_err(
            "upRegister",
            with_bridge(|env, class| {
                let p = env.new_string(pkg).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "upRegister",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&p)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    /// Drop the distributor registration (also clears the endpoint via JNI).
    pub fn up_unregister() {
        log_err(
            "upUnregister",
            with_bridge(|env, class| {
                env.call_static_method(class, "upUnregister", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// Kick an async FCM token fetch (lands back via `nativeSetPushToken`).
    pub fn request_push_token() {
        log_err(
            "requestFcmToken",
            with_bridge(|env, class| {
                env.call_static_method(class, "requestFcmToken", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// Delivery-health snapshot (battery exemption, notification permission,
    /// full-screen-intent grant, Play Services presence) as a JSON string.
    pub fn health_json() -> Option<String> {
        let mut out = None;
        let r = with_bridge(|env, class| {
            let v = env
                .call_static_method(class, "healthJson", "()Ljava/lang/String;", &[])
                .and_then(|v| v.l())
                .map_err(|e| e.to_string())?;
            let s: String = env.get_string(&v.into()).map_err(|e| e.to_string())?.into();
            out = Some(s);
            Ok(())
        });
        log_err("healthJson", r);
        out
    }

    /// Fire the system dialogs the health panel's fix-it buttons need.
    /// `what`: 0 = battery exemption, 1 = notification settings, 2 = full-screen intent.
    pub fn open_fixit(what: i32) {
        log_err(
            "openFixit",
            with_bridge(|env, class| {
                env.call_static_method(class, "openFixit", "(I)V", &[JValue::Int(what)])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }
}

// ─────────────────────────────── Desktop: tauri plugin ───────────────────────────────

#[cfg(not(target_os = "android"))]
mod desktop {
    use super::{ConnState, Generic, NotifLine};

    // Linux: post through notify-rust directly so we control the app name and themed icon
    // (the tauri plugin sets neither, so notifications arrived anonymous). App name +
    // `Icon=sona-desktop` match Sona.desktop so the shell attributes us; no
    // `desktop-entry` hint (it's redundant once the pid resolves to the app).
    //
    // CRITICAL: keep the D-Bus connection (its bus sender name) alive while the banner is
    // on screen. freedesktop shells run `notificationDaemon._onNameVanished`, which
    // DESTROYS a notification the instant its sender disconnects — but only when the
    // notification resolved to an installed application:
    //
    //     if (!this.trayIcon && this.app) this.destroy();
    //
    // Sona's pid always resolves to Sona.desktop, so `this.app` is set. notify-rust opens
    // a fresh connection per show() and returns a handle that owns it; a throwaway
    // `thread::spawn` per notification dropped the handle the moment show() returned, the
    // sender vanished within milliseconds, and the shell tore the banner down ~10ms after
    // it appeared — the reported "sound but no popup" (the sound is our own in-app ping,
    // independent of the OS banner). notify-send is exempted by the `this.app` guard
    // above, which is why every ad-hoc probe showed a banner and only the real app failed.
    //
    // Fix: a single long-lived thread owns the handles and keeps each alive well past the
    // banner's on-screen lifetime (the daemon default is a few seconds), so the sender
    // never vanishes while it matters. Pruning drops them once the banner is long gone.
    #[cfg(target_os = "linux")]
    mod linux_notify {
        use notify_rust::{Notification, NotificationHandle};
        use std::sync::mpsc::{channel, Sender};
        use std::sync::OnceLock;
        use std::time::{Duration, Instant};

        static TX: OnceLock<Sender<(String, String)>> = OnceLock::new();

        // Comfortably past any daemon's on-screen timeout; by now the banner is gone and
        // dropping the handle (letting its sender vanish) is a no-op.
        const HOLD: Duration = Duration::from_secs(30);

        fn tx() -> &'static Sender<(String, String)> {
            TX.get_or_init(|| {
                let (tx, rx) = channel::<(String, String)>();
                std::thread::spawn(move || {
                    let mut live: Vec<(Instant, NotificationHandle)> = Vec::new();
                    while let Ok((title, body)) = rx.recv() {
                        live.retain(|(t, _)| t.elapsed() < HOLD);
                        match Notification::new()
                            .summary(&title)
                            .body(&body)
                            .appname("Sona")
                            .icon("sona-desktop")
                            .show()
                        {
                            Ok(h) => live.push((Instant::now(), h)),
                            Err(e) => crate::diag!("[notify] {e}"),
                        }
                    }
                });
                tx
            })
        }

        pub fn post(title: &str, body: &str) {
            let _ = tx().send((title.to_string(), body.to_string()));
        }
    }

    fn plugin_show(title: &str, body: &str) {
        // Never from a test run. The call paths post rings and generics as part of their
        // ordinary work, and on Linux this reaches the session bus directly — so
        // `cargo test` would put real notifications on the developer's own desktop.
        if cfg!(test) {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            linux_notify::post(title, body);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let Some(app) = crate::engine::global().ui_handle() else {
                return;
            };
            use tauri_plugin_notification::NotificationExt as _;
            if let Err(e) = app.notification().builder().title(title).body(body).show() {
                crate::diag!("[notify] {e}");
            }
        }
    }

    /// Desktop keeps the plugin's fire-and-forget model: post the newest line only.
    pub fn show_message(_chat_key: &str, lines: &[NotifLine]) {
        if let Some(last) = lines.last() {
            plugin_show(&last.title, &last.body);
        }
    }

    /// Desktop notifications can't be revoked portably through the plugin — accept the
    /// small gap (the tray model keeps desktop out of the lock-screen threat anyway).
    pub fn cancel_chat(_chat_key: &str) {}

    pub fn show_call(_call_id: &str, title: &str, is_group: bool) {
        plugin_show(
            title,
            if is_group {
                "Incoming group call"
            } else {
                "Incoming call"
            },
        );
    }

    /// No foreground service and no keyguard here, so accepting is exactly cancelling the
    /// presentation — recorded the same way, because A-18's assertion is about the ring
    /// stopping and that is equally true on this path.
    pub fn accept_call(call_id: &str) {
        #[cfg(test)]
        cancelled::record(call_id);
        let _ = call_id;
    }

    /// Nothing holds a desktop process up for a call, so there is nothing to give back.
    pub fn release_call_hold() {}

    pub fn cancel_call(call_id: &str, missed_title: &str) {
        #[cfg(test)]
        cancelled::record(call_id);
        let _ = call_id;
        if !missed_title.is_empty() {
            plugin_show(missed_title, "Missed call");
        }
    }

    /// Test-only record of the ids [`cancel_call`] was asked to take down.
    ///
    /// The ring that keeps sounding is a *notification*, and the platform owns it — so
    /// A-18 (a cancel skipped because the engine's in-memory ring was lost with the
    /// process) was a bug no host assertion could see. This makes the presentation half
    /// assertable the way A-2 made the system-call half assertable.
    #[cfg(test)]
    pub mod cancelled {
        use std::sync::Mutex;

        static IDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

        pub fn record(id: &str) {
            IDS.lock().unwrap().push(id.to_string());
        }

        pub fn contains(id: &str) -> bool {
            IDS.lock().unwrap().iter().any(|i| i == id)
        }
    }

    /// No lock screen to answer from: the desktop shell is unlocked whenever it is usable.
    pub fn open_app_for_unlock() {}
    /// No lock screen, so no prompt to revoke either.
    pub fn clear_unlock_prompt() {}

    /// There is no keyguard between the user and a desktop that is showing them a ring, so
    /// "require unlock to answer" stays Android-specific (§8) and the ordinary answer is
    /// untouched here.
    pub fn device_locked() -> bool {
        #[cfg(test)]
        let locked = keyguard::locked();
        #[cfg(not(test))]
        let locked = false;
        locked
    }

    /// Test-only keyguard, so the answer gate A-19 added is reachable from the host suites.
    /// The state it turns on is a *device* state, not something a session can hold, and it
    /// is the one no host test could describe before.
    #[cfg(test)]
    pub mod keyguard {
        use std::sync::atomic::{AtomicBool, Ordering};

        static LOCKED: AtomicBool = AtomicBool::new(false);

        pub fn locked() -> bool {
            LOCKED.load(Ordering::SeqCst)
        }

        pub fn set(locked: bool) {
            LOCKED.store(locked, Ordering::SeqCst);
        }
    }

    pub fn show_generic(kind: Generic) {
        match kind {
            Generic::MaybeMessages => plugin_show("Sona", "You may have new messages"),
            Generic::LockedCall => plugin_show("Sona", "Incoming call — unlock to answer"),
            Generic::UnactionableCall => plugin_show("Sona", "Incoming call — open Sona to answer"),
        }
    }

    /// Desktop generics are fire-and-forget plugin toasts — nothing to revoke.
    pub fn clear_generics() {}
    pub fn set_service_status(_state: ConnState) {}
    pub fn drain_finished() {}
    pub fn request_push_token() {}
    /// UnifiedPush is Android-only (desktop keeps the tray connection).
    pub fn up_distributors() -> Option<String> {
        None
    }
    pub fn up_register(_pkg: &str) {}
    pub fn up_unregister() {}
    /// Headset-button answer is Android-only (desktop has real keyboards).
    /// Desktop webviews expose clipboard files to JS directly; no native fallback.
    pub fn clipboard_image() -> Option<String> {
        None
    }
    pub fn health_json() -> Option<String> {
        None
    }
    pub fn open_fixit(_what: i32) {}
}
