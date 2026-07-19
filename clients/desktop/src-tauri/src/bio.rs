//! Android biometric gate — the Rust side of `BiometricGate.kt` (injected into the
//! generated Android project by `scripts/harden-android.sh`).
//!
//! Two distinct capabilities, both fingerprint-first (BIOMETRIC_STRONG = Android class 3,
//! which excludes the common camera-based face unlocks):
//!
//! * **Presence check** — "prove a human who can unlock this device is holding it".
//!   Fingerprint, falling back to the device credential (PIN/pattern/password) when no
//!   fingerprint is enrolled. Used as one step of the username/password-change ceremony.
//!   No key material involved.
//! * **Crypto-gated unlock** — the vault seal key is AES-GCM-wrapped by a **non-exportable
//!   Android Keystore key that requires a BIOMETRIC_STRONG authentication per use** and is
//!   invalidated when a new fingerprint is enrolled. Even code running inside the app
//!   process cannot unwrap the blob without a live fingerprint touch.
//!
//! Bridge mechanics: the Kotlin side must run its prompts on the UI thread and reports
//! back through `@Volatile` static fields (`resultCode`, `resultBlob`). Rust calls a
//! `begin*` static (which resets the fields, then posts to the UI thread) and polls the
//! fields from a blocking thread. Crude, but needs no JNI callback classes and no extra
//! Gradle dependencies — the whole thing survives `tauri android init` regeneration via
//! the harden script.
//!
//! On non-Android targets everything reports "unavailable" / auto-passes the presence
//! check (the ceremony spec only involves the OS check on Android).

/// How the device can vouch for the user, for [`availability`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))] // desktop constructs only `None`
pub enum OsAuth {
    /// A class-3 (strong) biometric — in practice a fingerprint — is enrolled.
    Biometric,
    /// No usable biometric, but a device credential (PIN/pattern/password) is set.
    CredentialOnly,
    /// Neither — the presence step of a ceremony must be skipped.
    None,
}

#[cfg(not(target_os = "android"))]
mod imp {
    use super::OsAuth;

    pub fn availability() -> OsAuth {
        OsAuth::None
    }

    /// Desktop: the ceremony has no OS step — treat as passed.
    pub fn presence_check() -> Result<bool, String> {
        Ok(true)
    }

    pub fn enroll(_seal_key: &[u8]) -> Result<Vec<u8>, String> {
        Err("biometric unlock is only available on Android".into())
    }

    pub fn unwrap(_blob: &[u8]) -> Result<Vec<u8>, String> {
        Err("biometric unlock is only available on Android".into())
    }
}

#[cfg(target_os = "android")]
mod imp {
    use super::OsAuth;
    use jni::objects::{JByteArray, JClass, JObject, JValue};
    use jni::JNIEnv;

    const GATE_CLASS: &str = "app.sona.messenger.BiometricGate";
    /// Result codes mirrored from BiometricGate.kt.
    const PENDING: i32 = -1;
    const OK: i32 = 0;

    /// Longest we wait for the user to answer a system prompt.
    const PROMPT_TIMEOUT_SECS: u64 = 120;

    /// Attach to the JVM and resolve the injected gate class **through the activity's
    /// classloader** — `FindClass` on a native (non-main) thread only sees system
    /// classes, so going through the app context is mandatory.
    fn with_gate<T>(
        f: impl for<'a> FnOnce(&mut JNIEnv<'a>, &JClass<'a>, &JObject<'a>) -> Result<T, String>,
    ) -> Result<T, String> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach: {e}"))?;
        // BiometricPrompt genuinely needs an Activity (context split, docs/NOTIFICATIONS.md §4.3):
        // headless there is none — fail with a clear message instead of a Java throw.
        let Some(activity_ptr) = crate::android_media::activity_obj() else {
            return Err("biometric prompt needs the app on screen".into());
        };
        let activity = unsafe { JObject::from_raw(activity_ptr.cast()) };

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
            .new_string(GATE_CLASS)
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
                format!("BiometricGate not found (regenerate with harden-android.sh): {e}")
            })?;
        let class = JClass::from(class);

        let out = f(&mut env, &class, &activity);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return Err("BiometricGate call raised a Java exception".into());
        }
        out
    }

    /// Poll `resultCode` until it leaves PENDING (or we time out), then collect the blob.
    fn wait_result(env: &mut JNIEnv, class: &JClass) -> Result<Vec<u8>, String> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(PROMPT_TIMEOUT_SECS);
        loop {
            let code = env
                .get_static_field(class, "resultCode", "I")
                .and_then(|v| v.i())
                .map_err(|e| format!("resultCode: {e}"))?;
            match code {
                PENDING => {
                    if std::time::Instant::now() >= deadline {
                        return Err("authentication prompt timed out".into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                OK => {
                    let blob = env
                        .get_static_field(class, "resultBlob", "[B")
                        .and_then(|v| v.l())
                        .map_err(|e| format!("resultBlob: {e}"))?;
                    if blob.is_null() {
                        return Ok(Vec::new());
                    }
                    let arr: JByteArray = blob.into();
                    return env
                        .convert_byte_array(&arr)
                        .map_err(|e| format!("blob bytes: {e}"));
                }
                1 => return Err("authentication was cancelled".into()),
                _ => return Err("biometric hardware error".into()),
            }
        }
    }

    pub fn availability() -> OsAuth {
        with_gate(|env, class, activity| {
            env.call_static_method(
                class,
                "availability",
                "(Landroid/app/Activity;)I",
                &[JValue::Object(activity)],
            )
            .and_then(|v| v.i())
            .map_err(|e| format!("availability: {e}"))
        })
        .map(|code| match code {
            0 => OsAuth::Biometric,
            1 => OsAuth::CredentialOnly,
            _ => OsAuth::None,
        })
        .unwrap_or(OsAuth::None)
    }

    /// Fingerprint-or-device-credential presence prompt. `Ok(true)` = user verified,
    /// `Ok(false)` = device has neither factor (step is skipped per the ceremony spec).
    pub fn presence_check() -> Result<bool, String> {
        if availability() == OsAuth::None {
            return Ok(false);
        }
        with_gate(|env, class, activity| {
            env.call_static_method(
                class,
                "beginPresenceCheck",
                "(Landroid/app/Activity;)V",
                &[JValue::Object(activity)],
            )
            .map_err(|e| format!("beginPresenceCheck: {e}"))?;
            wait_result(env, class).map(|_| true)
        })
    }

    /// Wrap the seal-key bytes under a fresh biometric-gated Keystore key. Prompts for a
    /// fingerprint (the wrapping key itself requires auth per use). Returns the blob to
    /// persist.
    pub fn enroll(seal_key: &[u8]) -> Result<Vec<u8>, String> {
        with_gate(|env, class, activity| {
            let plain = env
                .byte_array_from_slice(seal_key)
                .map_err(|e| format!("plain arr: {e}"))?;
            env.call_static_method(
                class,
                "beginEnroll",
                "(Landroid/app/Activity;[B)V",
                &[JValue::Object(activity), JValue::Object(&plain)],
            )
            .map_err(|e| format!("beginEnroll: {e}"))?;
            wait_result(env, class)
        })
    }

    /// Unwrap a blob produced by [`enroll`]. Prompts for a fingerprint.
    pub fn unwrap(blob: &[u8]) -> Result<Vec<u8>, String> {
        with_gate(|env, class, activity| {
            let arr = env
                .byte_array_from_slice(blob)
                .map_err(|e| format!("blob arr: {e}"))?;
            env.call_static_method(
                class,
                "beginUnwrap",
                "(Landroid/app/Activity;[B)V",
                &[JValue::Object(activity), JValue::Object(&arr)],
            )
            .map_err(|e| format!("beginUnwrap: {e}"))?;
            wait_result(env, class)
        })
    }
}

pub use imp::{availability, enroll, presence_check, unwrap};

/// All JNI work happens on a blocking thread (prompt waits can take a minute); commands
/// call these `spawn_blocking` wrappers so the async runtime never stalls.
pub async fn availability_async() -> OsAuth {
    tauri::async_runtime::spawn_blocking(availability)
        .await
        .unwrap_or(OsAuth::None)
}

pub async fn presence_check_async() -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(presence_check)
        .await
        .map_err(|e| e.to_string())?
}

pub async fn enroll_async(seal_key: Vec<u8>) -> Result<Vec<u8>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let out = enroll(&seal_key);
        // Best-effort scrub of the plaintext copy this closure owned.
        drop(zeroize::Zeroizing::new(seal_key));
        out
    })
    .await
    .map_err(|e| e.to_string())?
}

pub async fn unwrap_async(blob: Vec<u8>) -> Result<Vec<u8>, String> {
    tauri::async_runtime::spawn_blocking(move || unwrap(&blob))
        .await
        .map_err(|e| e.to_string())?
}
