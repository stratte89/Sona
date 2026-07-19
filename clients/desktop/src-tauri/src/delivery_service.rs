//! Android background-delivery service control — the Rust side of `DeliveryService.kt`
//! (injected into the generated Android project by `scripts/harden-android.sh`).
//!
//! The delivery WebSocket lives in the Rust runtime and runs for as long as the process
//! does; Android freezing the backgrounded process is what kills it. The Kotlin side is
//! a foreground service whose only job is to keep the process unfrozen — started when a
//! session unlocks, stopped when it locks. See DeliveryService.kt for the rationale.
//!
//! On non-Android targets this is a no-op: the desktop process runs (hidden in the
//! tray after close) until the user quits it.

/// Start (`true`) or stop (`false`) the Android foreground delivery service.
/// Best-effort: failures log and delivery continues foreground-only.
#[cfg(not(target_os = "android"))]
pub fn set_background_delivery(_on: bool) {}

#[cfg(target_os = "android")]
pub fn set_background_delivery(on: bool) {
    if let Err(e) = imp::call(if on { "start" } else { "stop" }) {
        eprintln!("[delivery-service] {e}");
    }
}

#[cfg(target_os = "android")]
mod imp {
    use jni::objects::{JClass, JObject, JValue};

    const SERVICE_CLASS: &str = "app.sona.messenger.DeliveryService";

    /// Resolve the injected service class through the activity's classloader (like
    /// `crate::bio` — `FindClass` on a native thread only sees system classes) and
    /// invoke `DeliveryService.<method>(activity)`.
    pub fn call(method: &str) -> Result<(), String> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach: {e}"))?;
        let activity = unsafe { JObject::from_raw(ctx.context().cast()) };

        let loader = env
            .call_method(
                &activity,
                "getClassLoader",
                "()Ljava/lang/ClassLoader;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| format!("getClassLoader: {e}"))?;
        let name = env
            .new_string(SERVICE_CLASS)
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
                format!("DeliveryService not found (re-run harden-android.sh): {e}")
            })?;
        let class = JClass::from(class);

        env.call_static_method(
            &class,
            method,
            "(Landroid/content/Context;)V",
            &[JValue::Object(&activity)],
        )
        .map_err(|e| format!("{method}: {e}"))?;
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return Err(format!("DeliveryService.{method} raised a Java exception"));
        }
        Ok(())
    }
}
