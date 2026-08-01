//! Rust's half of the Core-Telecom bridge: what the shell asks the platform to do, and
//! the disconnect causes it says it with.
//!
//! Core-Telecom owns the system call — ringing, answered, active, held, disconnected —
//! and the audio route with it (`internal/CALL_PLAN.md` §7.3, §7.4). This module is deliberately a
//! thin facade over `TelecomBridge.kt`, in the same shape as [`crate::notifier`]: JNI
//! calls out, and `jni_entry` hands the callbacks back in.
//!
//! On every non-Android target these are no-ops that report "no telecom", so the shared
//! call paths can call them unconditionally and the desktop keeps its own ring.

/// `android.telecom.DisconnectCause` codes, named at the one boundary that uses them so a
/// bare integer never travels through the call paths.
#[allow(dead_code)]
pub(crate) mod cause {
    /// Something went wrong (audio would not start, transport failed).
    pub(crate) const ERROR: i32 = 1;
    /// This side hung up — including a decline.
    pub(crate) const LOCAL: i32 = 2;
    /// The peer hung up, or the caller cancelled.
    pub(crate) const REMOTE: i32 = 3;
    /// Rang out unanswered.
    pub(crate) const MISSED: i32 = 5;
    /// Declined here.
    pub(crate) const REJECTED: i32 = 6;
    /// Another call owns the device.
    pub(crate) const BUSY: i32 = 7;
    /// Answered on another device — Telecom has no word for it; "other" keeps the system
    /// log honest rather than claiming this device rejected the call.
    pub(crate) const ANSWERED_ELSEWHERE: i32 = 11;
}

#[cfg(target_os = "android")]
pub(crate) use android::*;

#[cfg(not(target_os = "android"))]
pub(crate) use desktop::*;

#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JClass, JObject, JValue};

    const BRIDGE_CLASS: &str = "app.sona.messenger.TelecomBridge";

    /// Resolve the injected bridge through the app context's classloader (a native thread
    /// only sees system classes with `FindClass`) and run `f`.
    fn with_bridge<T>(
        f: impl for<'a> FnOnce(&mut jni::JNIEnv<'a>, &JClass<'a>) -> Result<T, String>,
    ) -> Result<T, String> {
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
                format!("TelecomBridge not found (re-run harden-android.sh): {e}")
            })?;
        let class = JClass::from(class);
        let out = f(&mut env, &class);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return Err("TelecomBridge call raised a Java exception".into());
        }
        out
    }

    fn log_err<T: Default>(what: &str, r: Result<T, String>) -> T {
        match r {
            Ok(value) => value,
            Err(e) => {
                crate::diag!("[telecom] {what}: {e}");
                T::default()
            }
        }
    }

    /// Register this app with Telecom. Idempotent; `false` means the platform refused (no
    /// telecom service, missing permission) and the caller must fall back honestly.
    pub(crate) fn register() -> bool {
        log_err(
            "register",
            with_bridge(|env, class| {
                env.call_static_method(class, "register", "()Z", &[])
                    .and_then(|v| v.z())
                    .map_err(|e| e.to_string())
            }),
        )
    }

    /// Ring for an incoming call. `ring_id` is what every later transition names.
    pub(crate) fn add_incoming(ring_id: &str, display_name: &str, video: bool) -> bool {
        add_call("addIncoming", ring_id, display_name, video)
    }

    /// Tell the system an outgoing call is being placed.
    pub(crate) fn add_outgoing(ring_id: &str, display_name: &str, video: bool) -> bool {
        add_call("addOutgoing", ring_id, display_name, video)
    }

    fn add_call(method: &str, ring_id: &str, display_name: &str, video: bool) -> bool {
        log_err(
            method,
            with_bridge(|env, class| {
                let id = env.new_string(ring_id).map_err(|e| e.to_string())?;
                let name = env.new_string(display_name).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    method,
                    "(Ljava/lang/String;Ljava/lang/String;Z)Z",
                    &[
                        JValue::Object(&id),
                        JValue::Object(&name),
                        JValue::Bool(video as u8),
                    ],
                )
                .and_then(|v| v.z())
                .map_err(|e| e.to_string())
            }),
        )
    }

    /// Accept the platform's answer action for this call.
    pub(crate) fn answer(ring_id: &str, video: bool) {
        log_err(
            "answer",
            with_bridge(|env, class| {
                let id = env.new_string(ring_id).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "answer",
                    "(Ljava/lang/String;Z)V",
                    &[JValue::Object(&id), JValue::Bool(video as u8)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        )
    }

    pub(crate) fn set_active(ring_id: &str) {
        one_string("setActive", ring_id)
    }

    pub(crate) fn set_inactive(ring_id: &str) {
        one_string("setInactive", ring_id)
    }

    /// End this call in the system, with an honest [`super::cause`].
    pub(crate) fn disconnect(ring_id: &str, cause: i32) {
        log_err(
            "disconnect",
            with_bridge(|env, class| {
                let id = env.new_string(ring_id).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "disconnect",
                    "(Ljava/lang/String;I)V",
                    &[JValue::Object(&id), JValue::Int(cause)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        )
    }

    /// Ask Telecom for a route. The answer comes back as an `endpoint` event — Telecom
    /// decides, we never assume the request was honored.
    pub(crate) fn request_route(ring_id: &str, route: &str) {
        log_err(
            "requestRoute",
            with_bridge(|env, class| {
                let id = env.new_string(ring_id).map_err(|e| e.to_string())?;
                let route = env.new_string(route).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    "requestRoute",
                    "(Ljava/lang/String;Ljava/lang/String;)V",
                    &[JValue::Object(&id), JValue::Object(&route)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        )
    }

    /// The ring ids Telecom is holding right now — what a restarted process reconciles
    /// its stored pending rings against.
    pub(crate) fn active_calls() -> Vec<String> {
        let json: String = log_err(
            "activeCalls",
            with_bridge(|env, class| {
                let value = env
                    .call_static_method(class, "activeCalls", "()Ljava/lang/String;", &[])
                    .and_then(|v| v.l())
                    .map_err(|e| e.to_string())?;
                env.get_string((&value).into())
                    .map(|s| s.into())
                    .map_err(|e| e.to_string())
            }),
        );
        serde_json::from_str(&json).unwrap_or_default()
    }

    fn one_string(method: &str, ring_id: &str) {
        log_err(
            method,
            with_bridge(|env, class| {
                let id = env.new_string(ring_id).map_err(|e| e.to_string())?;
                env.call_static_method(
                    class,
                    method,
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&id)],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }),
        )
    }
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)] // the stubs exist so the shared call paths compile unconditionally
mod desktop {
    /// No Telecom off Android: the desktop shell keeps its own ring and audio routing is
    /// the OS mixer's job. Every entry point reports "not handled" so the shared call
    /// paths can call them unconditionally.
    pub(crate) fn register() -> bool {
        false
    }
    pub(crate) fn add_incoming(_ring_id: &str, _display_name: &str, _video: bool) -> bool {
        false
    }
    pub(crate) fn add_outgoing(_ring_id: &str, _display_name: &str, _video: bool) -> bool {
        false
    }
    pub(crate) fn answer(_ring_id: &str, _video: bool) {}
    pub(crate) fn set_active(_ring_id: &str) {}
    pub(crate) fn set_inactive(_ring_id: &str) {}
    pub(crate) fn disconnect(_ring_id: &str, _cause: i32) {}
    pub(crate) fn request_route(_ring_id: &str, _route: &str) {}
    pub(crate) fn active_calls() -> Vec<String> {
        Vec::new()
    }
}
