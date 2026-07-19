//! Device-link hardware attestation — the Rust side of `HwAttest.kt` (injected by
//! `scripts/harden-android.sh`). Android only: asks the Keystore for an ephemeral
//! attestation chain over the link-request challenge; every other platform (and any
//! Android failure) yields `None`, and the link request simply carries no attestation —
//! it is advisory, never a gate. Verification lives in `client_core::attest` and runs
//! on the PRIMARY, which need not be an Android device.

#[cfg(not(target_os = "android"))]
pub fn chain(_challenge: &[u8]) -> Option<Vec<String>> {
    None
}

/// Certificate chain (base64 DER, leaf first) attesting an ephemeral Keystore key bound
/// to `challenge`, or `None` when the device can't attest.
#[cfg(target_os = "android")]
pub fn chain(challenge: &[u8]) -> Option<Vec<String>> {
    use jni::objects::{JClass, JObject, JValue};

    const CLASS: &str = "app.sona.messenger.HwAttest";
    let run = || -> Result<String, String> {
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
            .new_string(CLASS)
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
                format!("HwAttest not found (re-run harden-android.sh): {e}")
            })?;
        let class = JClass::from(class);
        let arr = env
            .byte_array_from_slice(challenge)
            .map_err(|e| format!("challenge array: {e}"))?;
        let json = env
            .call_static_method(
                &class,
                "chainJson",
                "([B)Ljava/lang/String;",
                &[JValue::Object(&arr)],
            )
            .and_then(|v| v.l())
            .map_err(|e| {
                let _ = env.exception_clear();
                format!("chainJson: {e}")
            })?;
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return Err("chainJson raised".into());
        }
        env.get_string((&json).into())
            .map(String::from)
            .map_err(|e| format!("chain string: {e}"))
    };
    match run() {
        Ok(json) => {
            let chain: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
            // Keystore attestation always chains leaf→intermediate(s)→root; a bare
            // "chain" of one certificate is a keystore that couldn't attest.
            if chain.len() >= 2 {
                Some(chain)
            } else {
                None
            }
        }
        Err(e) => {
            eprintln!("[hw-attest] unavailable: {e}");
            None
        }
    }
}
