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

/// Generic (content-free) notification kinds for the locked-vault degradation path.
#[derive(Debug, Clone, Copy)]
pub enum Generic {
    /// `"t":"m"` wake with no way to decrypt: "You may have new messages".
    MaybeMessages,
    /// `"t":"c"` wake with no way to decrypt: insistent generic ring.
    LockedCall,
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
            eprintln!("[notifier] {what}: {e}");
        }
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

    /// Headset-button MediaSession for the ring window (tap = answer, stop = decline).
    pub fn call_buttons_start(call_id: &str) {
        log_err(
            "callButtonsStart",
            with_bridge(|env, class| {
                let id = env.new_string(call_id).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "callButtonsStart",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&id)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        );
    }

    pub fn call_buttons_stop() {
        log_err(
            "callButtonsStop",
            with_bridge(|env, class| {
                env.call_static_method(class, "callButtonsStop", "()V", &[])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        );
    }

    /// Locked-vault degradation (§7.4): content-free generic per wake class.
    pub fn show_generic(kind: Generic) {
        let code = match kind {
            Generic::MaybeMessages => 0,
            Generic::LockedCall => 1,
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
                            Err(e) => eprintln!("[notify] {e}"),
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
                eprintln!("[notify] {e}");
            }
        }
    }

    /// Flash the Windows taskbar button orange (like Discord/Telegram) when a
    /// message arrives while the window is unfocused or minimized. Uses
    /// `FlashWindowEx` with `FLASHW_TIMERNOFG` so the highlight persists until
    /// the user actually focuses the window — exactly the UX users expect.
    #[cfg(target_os = "windows")]
    fn flash_taskbar() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            FlashWindowEx, FLASHWINFO, FLASHW_ALL, FLASHW_TIMERNOFG,
        };
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};

        let Some(app) = crate::engine::global().ui_handle() else {
            return;
        };
        use tauri::Manager as _;
        let Some(window) = app.get_webview_window("main") else {
            return;
        };
        let Ok(handle) = window.window_handle() else {
            return;
        };
        let RawWindowHandle::Win32(h) = handle.as_raw() else {
            return;
        };
        let hwnd = h.hwnd.get() as *mut _;
        let fi = FLASHWINFO {
            cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
            hwnd,
            dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
            uCount: 0,
            dwTimeout: 0,
        };
        unsafe {
            let _ = FlashWindowEx(&fi);
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn flash_taskbar() {}

    /// Desktop keeps the plugin's fire-and-forget model: post the newest line only.
    pub fn show_message(_chat_key: &str, lines: &[NotifLine]) {
        if let Some(last) = lines.last() {
            plugin_show(&last.title, &last.body);
            // Flash the taskbar button when the window is not focused (Discord-style).
            if !crate::engine::global().is_focused() {
                flash_taskbar();
            }
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

    pub fn cancel_call(_call_id: &str, missed_title: &str) {
        if !missed_title.is_empty() {
            plugin_show(missed_title, "Missed call");
        }
    }

    pub fn show_generic(kind: Generic) {
        match kind {
            Generic::MaybeMessages => plugin_show("Sona", "You may have new messages"),
            Generic::LockedCall => plugin_show("Sona", "Incoming call — unlock to answer"),
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
    pub fn call_buttons_start(_call_id: &str) {}
    pub fn call_buttons_stop() {}
    /// Desktop webviews expose clipboard files to JS directly; no native fallback.
    pub fn clipboard_image() -> Option<String> {
        None
    }
    pub fn health_json() -> Option<String> {
        None
    }
    pub fn open_fixit(_what: i32) {}
}
