//! In-app updates: manual "check for updates" against the operator's update channel.
//!
//! Trust model: the channel base URL and a minisign (ed25519) public key are baked in
//! at build time (`SONA_UPDATE_BASE` / `SONA_UPDATE_PUBKEY`, exported by build.sh from
//! the operator's gitignored `.env.update`). The relay TLS layer is transport only —
//! every decision is made against the minisign signature, so a compromised host can
//! serve outages, never forged updates. Builds without the env vars have updates
//! disabled entirely (the settings row says so).
//!
//! Per platform the *apply* step differs:
//! * Linux — the deb enrolls an apt repo (see build.sh); applying is one pkexec'd
//!   `apt-get install --only-upgrade`. apt re-verifies the archive's GPG signature.
//! * Windows — download the NSIS installer, verify minisign, spawn it PASSIVE
//!   (`/P /R`: progress-bar-only upgrade in place, auto-relaunch) and exit. Never the
//!   interactive installer — its maintenance flow exposes an uninstall page whose
//!   "remove app data" option wipes the vault.
//! * Android — download the APK, verify minisign, stream it into a PackageInstaller
//!   session (UpdateBridge.kt; content-URI installs break on some ROMs). The OS
//!   enforces same-signer + higher versionCode before touching the installed app;
//!   app data survives by construction.
//!
//! Downgrade safety: a manifest advertising a version ≤ ours is reported as
//! "up to date" and can never trigger an install — a replayed old manifest is inert.
//! The manifest is re-fetched and re-verified inside `update_install`, so a check/
//! install pair can't be split across two different (partially swapped) server states.

use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Compile-time channel config; `None` (dev builds, forks without a channel) disables.
const UPDATE_BASE: Option<&str> = option_env!("SONA_UPDATE_BASE");
const UPDATE_PUBKEY: Option<&str> = option_env!("SONA_UPDATE_PUBKEY");
/// Optional trustless mirror consulted when the primary host is unreachable — e.g. a
/// GitHub `…/releases/latest/download` base holding the same signed files.
const UPDATE_FALLBACK: Option<&str> = option_env!("SONA_UPDATE_FALLBACK");

/// Body caps: a hostile mirror must not balloon memory. Manifests are ~1 KB; installers
/// are a few MB (desktop) to tens of MB (APK with bundled webview assets).
const MANIFEST_MAX: usize = 64 * 1024;
#[cfg(any(target_os = "android", target_os = "windows"))]
const ARTIFACT_MAX: usize = 256 * 1024 * 1024;

#[derive(Deserialize)]
struct Manifest {
    version: String,
    #[serde(default)]
    notes: Option<String>,
    // Read only on Windows/Android (Linux applies through apt); deserialized everywhere.
    #[cfg_attr(
        not(any(target_os = "android", target_os = "windows")),
        allow(dead_code)
    )]
    #[serde(default)]
    platforms: std::collections::HashMap<String, PlatformEntry>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(
    not(any(target_os = "android", target_os = "windows")),
    allow(dead_code)
)]
struct PlatformEntry {
    url: String,
    #[serde(default)]
    sha256: Option<String>,
    /// Full contents of the artifact's `.minisig` file. Required for exe/apk installs.
    #[serde(default)]
    minisig: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateInfo {
    /// False when this build has no update channel baked in.
    pub configured: bool,
    pub current: String,
    pub latest: Option<String>,
    pub notes: Option<String>,
    pub available: bool,
    /// How an install would be applied on this platform: "apt" | "installer" | "apk".
    pub method: &'static str,
}

fn method() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "apk"
    }
    #[cfg(target_os = "windows")]
    {
        "installer"
    }
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        "apt"
    }
}

#[cfg(any(target_os = "android", target_os = "windows"))]
fn platform_key() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "android-arm64"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-x86_64"
    }
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        "linux-deb"
    }
}

/// Strict `major.minor.patch` parse; anything else compares as "no version".
fn parse_v(s: &str) -> Option<(u64, u64, u64)> {
    let mut it = s.trim().splitn(3, '.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    Some((a, b, c))
}

/// Manifest locations in preference order: the operator's own host first, then the
/// optional mirror (a GitHub `releases/latest/download` URL). Every byte from either
/// is minisign-verified against the baked pubkey, so the mirror is fully trustless —
/// it can only serve outages or the truth.
fn manifest_bases() -> Vec<String> {
    let mut v = Vec::new();
    if let Some(b) = UPDATE_BASE {
        v.push(format!("{}/updates", b.trim_end_matches('/')));
    }
    if let Some(b) = UPDATE_FALLBACK {
        v.push(b.trim_end_matches('/').to_string());
    }
    v
}

/// Fetch `manifest.json` + `manifest.json.minisig`, verify, parse. All trust lives here.
async fn fetch_manifest(proxy: Option<&str>) -> Result<Manifest, String> {
    let pubkey = UPDATE_PUBKEY.ok_or("this build has no update signing key configured")?;
    let bases = manifest_bases();
    if bases.is_empty() {
        return Err("this build has no update channel configured".into());
    }
    let mut last_err = String::new();
    for base in &bases {
        let fetched: Result<(Vec<u8>, Vec<u8>), String> = async {
            let m =
                client_core::http_get_bytes(&format!("{base}/manifest.json"), proxy, MANIFEST_MAX)
                    .await?;
            let s = client_core::http_get_bytes(
                &format!("{base}/manifest.json.minisig"),
                proxy,
                MANIFEST_MAX,
            )
            .await?;
            Ok((m, s))
        }
        .await;
        match fetched {
            Ok((manifest, sig)) => {
                // A bad signature is NOT a reason to try the mirror: it means this
                // source is compromised or corrupt, and the mirror carries the same
                // files — fail loudly instead of shopping for a copy that "works".
                verify_minisign(pubkey, &manifest, std::str::from_utf8(&sig).unwrap_or(""))?;
                return serde_json::from_slice(&manifest)
                    .map_err(|e| format!("manifest parse: {e}"));
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn verify_minisign(pubkey_b64: &str, data: &[u8], sig_text: &str) -> Result<(), String> {
    let pk = minisign_verify::PublicKey::from_base64(pubkey_b64.trim())
        .map_err(|e| format!("update pubkey: {e}"))?;
    let sig =
        minisign_verify::Signature::decode(sig_text).map_err(|e| format!("signature: {e}"))?;
    pk.verify(data, &sig, false)
        .map_err(|_| "SIGNATURE VERIFICATION FAILED — refusing update".to_string())
}

/// Stage event for the settings UI's progress modal: `{stage, pct}`; `pct` is present
/// only while downloading with a known length.
fn emit_stage(stage: &str, pct: Option<u64>) {
    crate::eng().emit(
        "update_state",
        serde_json::json!({ "stage": stage, "pct": pct }),
    );
}

/// Download an artifact and verify it against its manifest entry (minisign mandatory,
/// sha256 as an extra pin when present). Returns the verified bytes. Emits
/// `downloading` progress along the way.
#[cfg(any(target_os = "android", target_os = "windows"))]
async fn fetch_artifact(entry: &PlatformEntry, proxy: Option<&str>) -> Result<Vec<u8>, String> {
    let pubkey = UPDATE_PUBKEY.ok_or("no update signing key")?;
    let sig = entry
        .minisig
        .as_deref()
        .ok_or("manifest entry has no signature — refusing")?;
    let on = |got: u64, total: Option<u64>| {
        emit_stage(
            "downloading",
            total.filter(|t| *t > 0).map(|t| got * 100 / t),
        );
    };
    // The manifest's URL points at the primary host; if that fetch fails and a mirror
    // is baked in, retry there by asset name. Verification below treats both equally.
    let bytes = match client_core::http_get_bytes_progress(&entry.url, proxy, ARTIFACT_MAX, on)
        .await
    {
        Ok(b) => b,
        Err(primary_err) => match (UPDATE_FALLBACK, entry.url.rsplit('/').next()) {
            (Some(mirror), Some(name)) if !name.is_empty() => client_core::http_get_bytes_progress(
                &format!("{}/{name}", mirror.trim_end_matches('/')),
                proxy,
                ARTIFACT_MAX,
                on,
            )
            .await
            .map_err(|mirror_err| format!("{primary_err}; mirror: {mirror_err}"))?,
            _ => return Err(primary_err),
        },
    };
    emit_stage("verifying", None);
    verify_minisign(pubkey, &bytes, sig)?;
    if let Some(want) = entry.sha256.as_deref() {
        use sha2::Digest as _;
        let got = hex::encode(sha2::Sha256::digest(&bytes));
        if !got.eq_ignore_ascii_case(want.trim()) {
            return Err("sha256 mismatch — refusing update".into());
        }
    }
    Ok(bytes)
}

async fn proxy_of(state: &tauri::State<'_, AppState>) -> Option<String> {
    state.inner.lock().await.prefs.socks_proxy.clone()
}

fn current_version(app: &tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

#[tauri::command]
pub async fn update_check(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<UpdateInfo, String> {
    let current = current_version(&app);
    if UPDATE_BASE.is_none() || UPDATE_PUBKEY.is_none() {
        return Ok(UpdateInfo {
            configured: false,
            current,
            latest: None,
            notes: None,
            available: false,
            method: method(),
        });
    }
    let proxy = proxy_of(&state).await;
    let m = fetch_manifest(proxy.as_deref()).await?;
    let newer = match (parse_v(&m.version), parse_v(&current)) {
        (Some(remote), Some(local)) => remote > local,
        _ => false,
    };
    Ok(UpdateInfo {
        configured: true,
        current,
        latest: Some(m.version),
        notes: m.notes,
        available: newer,
        method: method(),
    })
}

/// Apply the update for this platform. Re-fetches and re-verifies the manifest so the
/// decision can't ride on stale state from an earlier `update_check`.
#[tauri::command]
pub async fn update_install(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let current = current_version(&app);
    let proxy = proxy_of(&state).await;
    let m = fetch_manifest(proxy.as_deref()).await?;
    match (parse_v(&m.version), parse_v(&current)) {
        (Some(remote), Some(local)) if remote > local => {}
        _ => return Err("already up to date".into()),
    }

    // Linux: apt does download + GPG verification + atomic replace itself; the running
    // process keeps its old inode and the user restarts whenever convenient.
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        let _ = m; // apt owns artifact fetch + verification on this platform
        emit_stage("installing", None);
        let out = tokio::task::spawn_blocking(|| {
            std::process::Command::new("pkexec")
                .args([
                    "sh",
                    "-c",
                    "apt-get update && apt-get install -y --only-upgrade sona",
                ])
                .output()
        })
        .await
        .map_err(|e| format!("spawn: {e}"))?
        .map_err(|e| format!("pkexec not available ({e}) — run: sudo apt update && sudo apt install --only-upgrade sona"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "apt upgrade failed: {} — run manually: sudo apt update && sudo apt install --only-upgrade sona",
                err.trim()
            ));
        }
        return Ok("updated — restart Sona to switch to the new version".into());
    }

    // Windows: verified installer to a temp file, hand off, exit so it can replace us.
    #[cfg(target_os = "windows")]
    {
        let entry = m
            .platforms
            .get(platform_key())
            .cloned()
            .ok_or("manifest has no Windows artifact")?;
        let bytes = fetch_artifact(&entry, proxy.as_deref()).await?;
        let path = std::env::temp_dir().join(format!("sona-update-{}.exe", m.version));
        tokio::fs::write(&path, &bytes)
            .await
            .map_err(|e| format!("write installer: {e}"))?;
        emit_stage("installing", None);
        // /P /R: PASSIVE upgrade (progress bar only, closes the running app, replaces
        // in place, auto-relaunches the new version) — NEVER the interactive installer:
        // its maintenance flow let a user reach the uninstall page, whose "remove app
        // data" option wipes the vault and forces a relink. Data must survive updates.
        std::process::Command::new(&path)
            .args(["/P", "/R"])
            .spawn()
            .map_err(|e| format!("launch installer: {e}"))?;
        app.exit(0);
        return Ok("installer started".into());
    }

    // Android: verified APK to app cache, then the platform package installer takes
    // over (its same-signer + versionCode-monotonic rules are enforced by the OS).
    #[cfg(target_os = "android")]
    {
        if !android_can_install() {
            return Err("needs-install-permission".into());
        }
        let entry = m
            .platforms
            .get(platform_key())
            .cloned()
            .ok_or("manifest has no Android artifact")?;
        let bytes = fetch_artifact(&entry, proxy.as_deref()).await?;
        use tauri::Manager as _;
        let dir = app
            .path()
            .app_cache_dir()
            .map_err(|e| format!("cache dir: {e}"))?
            .join("updates");
        // Fresh staging dir: stale APKs from earlier attempts are dead weight and the
        // installer must only ever see the file we just verified.
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| format!("mkdir: {e}"))?;
        let path = dir.join(format!("sona-update-{}.apk", m.version));
        tokio::fs::write(&path, &bytes)
            .await
            .map_err(|e| format!("write apk: {e}"))?;
        emit_stage("installing", None);
        android_install_apk(path.to_str().ok_or("bad path")?)?;
        return Ok("installer started".into());
    }
}

/// Android bounce-out to the "install unknown apps" system toggle for this app.
#[tauri::command]
pub async fn update_open_install_settings() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        return with_update_bridge(|env, class, activity| {
            use jni::objects::JValue;
            env.call_static_method(
                class,
                "openInstallSettings",
                "(Landroid/app/Activity;)V",
                &[JValue::Object(activity)],
            )
            .map(|_| ())
            .map_err(|e| format!("openInstallSettings: {e}"))
        });
    }
    #[cfg(not(target_os = "android"))]
    Ok(())
}

// ── Android JNI plumbing (UpdateBridge.kt, installed by harden-android.sh) ──────────

#[cfg(target_os = "android")]
const UPDATE_BRIDGE_CLASS: &str = "app.sona.messenger.UpdateBridge";

/// Same classloader dance as `android_media::with_bridge`: `FindClass` on a non-main
/// thread only sees system classes, so resolve through the activity's loader.
#[cfg(target_os = "android")]
fn with_update_bridge(
    f: impl for<'a> FnOnce(
        &mut jni::JNIEnv<'a>,
        &jni::objects::JClass<'a>,
        &jni::objects::JObject<'a>,
    ) -> Result<(), String>,
) -> Result<(), String> {
    use jni::objects::{JClass, JObject, JValue};
    let ctx = ndk_context::android_context();
    let vm =
        unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| format!("JavaVM: {e}"))?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach: {e}"))?;
    let activity = unsafe { JObject::from_raw(crate::android_media::context_obj().cast()) };
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
        .new_string(UPDATE_BRIDGE_CLASS)
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
            format!("UpdateBridge not found (regenerate with harden-android.sh): {e}")
        })?;
    let class = JClass::from(class);
    let out = f(&mut env, &class, &activity);
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        return Err("UpdateBridge call raised a Java exception".into());
    }
    out
}

#[cfg(target_os = "android")]
fn android_can_install() -> bool {
    let mut ok = false;
    let r = with_update_bridge(|env, class, activity| {
        use jni::objects::JValue;
        ok = env
            .call_static_method(
                class,
                "canRequestInstalls",
                "(Landroid/app/Activity;)Z",
                &[JValue::Object(activity)],
            )
            .and_then(|v| v.z())
            .map_err(|e| format!("canRequestInstalls: {e}"))?;
        Ok(())
    });
    r.is_ok() && ok
}

#[cfg(target_os = "android")]
fn android_install_apk(path: &str) -> Result<(), String> {
    with_update_bridge(|env, class, activity| {
        use jni::objects::JValue;
        let jpath = env.new_string(path).map_err(|e| format!("path: {e}"))?;
        env.call_static_method(
            class,
            "installApk",
            "(Landroid/app/Activity;Ljava/lang/String;)V",
            &[JValue::Object(activity), JValue::Object(&jpath)],
        )
        .map(|_| ())
        .map_err(|e| format!("installApk: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::parse_v;

    #[test]
    fn version_ordering() {
        assert!(parse_v("0.1.2") > parse_v("0.1.1"));
        assert!(parse_v("0.2.0") > parse_v("0.1.99"));
        assert!(parse_v("1.0.0") > parse_v("0.99.99"));
        assert_eq!(parse_v("0.1.1"), parse_v(" 0.1.1 "));
        assert_eq!(parse_v("junk"), None);
        assert_eq!(parse_v("1.2"), None);
    }

    #[test]
    fn downgrade_or_equal_is_not_available() {
        // update_check treats "remote > local" strictly; equal and older must be false.
        assert!(parse_v("0.1.1") <= parse_v("0.1.1"));
        assert!(parse_v("0.1.0") <= parse_v("0.1.1"));
    }
}
