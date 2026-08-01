//! Android media capture bridge — the Rust side of `MediaBridge.kt` (injected into the
//! generated Android project by `scripts/harden-android.sh`).
//!
//! Direction of data:
//! * Kotlin → Rust: camera frames (tight I420 from Camera2), screen frames (packed
//!   RGBA from the MediaProjection virtual display — converted/decimated here), and
//!   48 kHz stereo PCM16 from AudioPlaybackCapture. Pushed through the `native*` JNI
//!   exports into latest-frame slots / a small audio queue that the engine's sources
//!   ([`crate::media_shell::SlotSource`], [`crate::media_shell::SystemAudioSource`])
//!   drain on their poll cadence.
//! * Rust → Kotlin: start/stop calls when the user toggles a track (`set_*_capture`),
//!   resolved through the activity's classloader exactly like [`crate::bio`].
//!
//! Privacy notes that make this shape deliberate:
//! * Capture runs **only** between explicit start/stop calls — no idle camera.
//! * Screen share requires the OS consent dialog + a visible foreground-service
//!   notification, and Sona's own FLAG_SECURE window shows up black in the share.

use std::collections::VecDeque;
use std::sync::Mutex;

use client_core::media::{video, SCREEN_AUDIO_SAMPLES};
use jni::objects::{JByteArray, JClass, JObject, JValue};
use jni::sys::{jboolean, jint};
use jni::JNIEnv;

const BRIDGE_CLASS: &str = "app.sona.messenger.MediaBridge";

/// Latest camera / screen frame from Kotlin, drained by the engine's video sources.
static CAMERA_SLOT: Mutex<Option<video::Frame>> = Mutex::new(None);
static SCREEN_SLOT: Mutex<Option<video::Frame>> = Mutex::new(None);
/// Small system-audio queue (20 ms stereo frames). Bounded: stale audio is dropped —
/// latency beats completeness for a live share.
static SYS_AUDIO: Mutex<VecDeque<[i16; SCREEN_AUDIO_SAMPLES]>> = Mutex::new(VecDeque::new());
/// Carries partial reads across `nativeSystemAudio` calls (chunks are arbitrary).
static SYS_AUDIO_PENDING: Mutex<Vec<i16>> = Mutex::new(Vec::new());
const SYS_AUDIO_QUEUE_FRAMES: usize = 8;

/// Voice-call mic queue (20 ms mono 48 kHz frames from the VOICE_COMMUNICATION
/// AudioRecord — hardware AEC/NS/AGC already applied). Replaces cpal input on Android;
/// drained by `audio.rs`. Bounded like the system-audio queue: drop oldest on overflow.
static VOICE_AUDIO: Mutex<VecDeque<[i16; VOICE_SAMPLES]>> = Mutex::new(VecDeque::new());
/// Defensive re-chunking across pushes (Kotlin sends exact frames; don't rely on it).
static VOICE_PENDING: Mutex<Vec<i16>> = Mutex::new(Vec::new());
const VOICE_QUEUE_FRAMES: usize = 8;
/// One 20 ms mono frame at 48 kHz (= 960 samples), same framing as the call engine.
const VOICE_SAMPLES: usize = client_core::call::SAMPLES_PER_FRAME;
/// Playout queue toward the Kotlin VOICE_COMMUNICATION AudioTrack (mixed voice + peer
/// screen audio from `audio.rs`). Bounded like the mic queue: drop oldest on overflow —
/// latency beats backlog on a live call.
static VOICE_PLAYOUT: Mutex<VecDeque<[i16; VOICE_SAMPLES]>> = Mutex::new(VecDeque::new());
const VOICE_PLAYOUT_QUEUE_FRAMES: usize = 6;

/// Engine-side drain for the camera/screen slots.
pub fn take_frame(camera: bool) -> Option<video::Frame> {
    let slot = if camera { &CAMERA_SLOT } else { &SCREEN_SLOT };
    slot.lock().ok()?.take()
}

/// Engine-side drain for system audio; `false` = nothing buffered (engine sends silence).
pub fn read_system_audio(buf: &mut [i16; SCREEN_AUDIO_SAMPLES]) -> bool {
    match SYS_AUDIO.lock().ok().and_then(|mut q| q.pop_front()) {
        Some(frame) => {
            *buf = frame;
            true
        }
        None => false,
    }
}

/// Drain one echo-cancelled voice-mic frame; `false` = nothing buffered yet.
pub fn read_voice_frame(buf: &mut [i16; VOICE_SAMPLES]) -> bool {
    match VOICE_AUDIO.lock().ok().and_then(|mut q| q.pop_front()) {
        Some(frame) => {
            *buf = frame;
            true
        }
        None => false,
    }
}

/// Queue one mixed 20 ms playout frame for the Kotlin AudioTrack thread.
pub fn push_playout_frame(frame: &[i16; VOICE_SAMPLES]) {
    if let Ok(mut q) = VOICE_PLAYOUT.lock() {
        if q.len() >= VOICE_PLAYOUT_QUEUE_FRAMES {
            q.pop_front(); // overflow: drop the oldest, keep latency bounded
        }
        q.push_back(*frame);
    }
}

// ── JNI exports (called from MediaBridge.kt) ────────────────────────────────────────

/// Whether ndk-context already holds a context.
static NDK_CONTEXT_SET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The live Activity (raw global-ref jobject), when one is resumed/created. Separate
/// slot from `ndk_context` (which holds the APPLICATION context so Keystore, service
/// control, and notifications keep working with no activity at all — docs/NOTIFICATIONS.md §4.3);
/// only the flows that genuinely need an Activity read this: BiometricPrompt,
/// MediaProjection consent, camera/mic permission prompts.
static ACTIVITY_SLOT: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Install `obj` (app context or activity) into ndk-context. `replace` forces a swap
/// (app-context install wins over a leftover activity from the old init path).
pub(crate) fn install_ndk_context(env: &JNIEnv, obj: &JObject, replace: bool) {
    let Ok(vm) = env.get_java_vm() else {
        crate::diag!("[init] no JavaVM");
        return;
    };
    let Ok(global) = env.new_global_ref(obj) else {
        crate::diag!("[init] global ref failed");
        return;
    };
    let ptr = global.as_obj().as_raw();
    // The context must outlive the process — leak the ref deliberately (once per
    // install; a few bytes).
    std::mem::forget(global);
    unsafe {
        if NDK_CONTEXT_SET.swap(true, std::sync::atomic::Ordering::SeqCst) {
            if !replace {
                return;
            }
            ndk_context::release_android_context();
        }
        ndk_context::initialize_android_context(vm.get_java_vm_pointer().cast(), ptr.cast());
    }
    crate::diag!("[init] ndk-context initialized");
}

/// Store (or clear, with null) the live Activity. Old refs are deliberately leaked —
/// one global ref per activity re-creation, same trade as the context install.
pub(crate) fn set_activity(env: &JNIEnv, activity: &JObject) {
    let ptr = if activity.is_null() {
        std::ptr::null_mut()
    } else {
        match env.new_global_ref(activity) {
            Ok(global) => {
                let p = global.as_obj().as_raw();
                std::mem::forget(global);
                p.cast()
            }
            Err(_) => return,
        }
    };
    ACTIVITY_SLOT.store(ptr, std::sync::atomic::Ordering::SeqCst);
}

/// The raw jobject to use as the Java `this` for bridge calls: the live Activity when
/// one exists, else the application context (fine for everything except prompts).
pub(crate) fn context_obj() -> *mut std::ffi::c_void {
    let act = ACTIVITY_SLOT.load(std::sync::atomic::Ordering::SeqCst);
    if !act.is_null() {
        return act;
    }
    ndk_context::android_context().context()
}

/// The live Activity alone; `None` when the app is headless/backgrounded. For flows
/// that must show UI (BiometricPrompt, consent dialogs).
pub(crate) fn activity_obj() -> Option<*mut std::ffi::c_void> {
    let act = ACTIVITY_SLOT.load(std::sync::atomic::Ordering::SeqCst);
    (!act.is_null()).then_some(act)
}

/// Called from MainActivity.onCreate (injected by harden-android.sh), right after the
/// native library is loaded. Current tao/wry never initialize `ndk-context`, but the
/// biometric gate and the Keystore device-key binding read it — without this call the
/// first JNI user panics with "android context was not initialized" (found on-device:
/// account creation hung forever). On activity re-creation (rotation, theme change)
/// the old pointer would go stale, so re-initialize with the fresh activity.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_MediaBridge_nativeInitAndroidContext(
    env: JNIEnv,
    _class: JClass,
    activity: JObject,
) {
    // Legacy shim (pre-context-split templates): make sure SOME context exists in
    // ndk-context — never replacing the app context `SonaApp` installed — and record
    // the activity in its slot. New templates call `nativeSetActivity` instead.
    install_ndk_context(&env, &activity, false);
    set_activity(&env, &activity);
}

/// MainActivity lifecycle: onCreate/onResume pass the activity, onDestroy passes null.
/// Keeps the activity slot fresh for prompt-needing flows while `ndk_context` stays on
/// the application context (headless-safe).
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_MediaBridge_nativeSetActivity(
    env: JNIEnv,
    _class: JClass,
    activity: JObject,
) {
    set_activity(&env, &activity);
}

/// One video frame from Kotlin. `rgba == true`: packed RGBA (screen path) — convert
/// and decimate here; otherwise tight planar I420 (camera path). `rot` = degrees
/// clockwise to rotate so the frame is upright (0 for screen frames).
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_MediaBridge_nativeVideoFrame(
    env: JNIEnv,
    _class: JClass,
    track: jint,
    width: jint,
    height: jint,
    rgba: jboolean,
    rot: jint,
    data: JByteArray,
) {
    let (Ok(w), Ok(h)) = (usize::try_from(width), usize::try_from(height)) else {
        return;
    };
    let Ok(bytes) = env.convert_byte_array(&data) else {
        return;
    };
    let rot = match rot {
        90 | 180 | 270 => rot as u32,
        _ => 0,
    };
    let frame = if rgba != 0 {
        let d = crate::media_shell::decim_for(w, 1280);
        crate::media_shell::packed_to_i420(&bytes, w, h, 4, (0, 1, 2), d)
    } else {
        let f = video::Frame {
            width: w,
            height: h,
            i420: bytes,
        };
        f.valid().then_some(f)
    }
    .map(|f| crate::media_shell::rotate_i420(f, rot));
    let Some(frame) = frame else { return };
    let slot = match track {
        1 => &CAMERA_SLOT,
        2 => &SCREEN_SLOT,
        _ => return,
    };
    if let Ok(mut s) = slot.lock() {
        *s = Some(frame);
    }
}

/// System-audio PCM from Kotlin: 48 kHz stereo PCM16 little-endian, arbitrary length.
/// Re-chunked into the engine's 20 ms frames.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_MediaBridge_nativeSystemAudio(
    env: JNIEnv,
    _class: JClass,
    pcm: JByteArray,
) {
    let Ok(bytes) = env.convert_byte_array(&pcm) else {
        return;
    };
    let Ok(mut pending) = SYS_AUDIO_PENDING.lock() else {
        return;
    };
    pending.extend(
        bytes
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]])),
    );
    let Ok(mut queue) = SYS_AUDIO.lock() else {
        return;
    };
    while pending.len() >= SCREEN_AUDIO_SAMPLES {
        let mut frame = [0i16; SCREEN_AUDIO_SAMPLES];
        frame.copy_from_slice(&pending[..SCREEN_AUDIO_SAMPLES]);
        pending.drain(..SCREEN_AUDIO_SAMPLES);
        if queue.len() >= SYS_AUDIO_QUEUE_FRAMES {
            queue.pop_front(); // overflow: drop the oldest, keep latency bounded
        }
        queue.push_back(frame);
    }
}

/// Voice-mic PCM from Kotlin: 48 kHz MONO PCM16 little-endian (hardware AEC applied).
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_MediaBridge_nativeVoiceAudio(
    env: JNIEnv,
    _class: JClass,
    pcm: JByteArray,
) {
    let Ok(bytes) = env.convert_byte_array(&pcm) else {
        return;
    };
    let Ok(mut pending) = VOICE_PENDING.lock() else {
        return;
    };
    pending.extend(
        bytes
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]])),
    );
    let Ok(mut queue) = VOICE_AUDIO.lock() else {
        return;
    };
    while pending.len() >= VOICE_SAMPLES {
        let mut frame = [0i16; VOICE_SAMPLES];
        frame.copy_from_slice(&pending[..VOICE_SAMPLES]);
        pending.drain(..VOICE_SAMPLES);
        if queue.len() >= VOICE_QUEUE_FRAMES {
            queue.pop_front(); // overflow: drop the oldest, keep latency bounded
        }
        queue.push_back(frame);
    }
}

/// The Kotlin AudioTrack thread pulls one 20 ms playout frame into `out` (1920 bytes,
/// 48 kHz mono PCM16 little-endian). Returns the bytes written, or 0 when nothing is
/// buffered — the track writes silence for that step instead.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_MediaBridge_nativeVoicePlayoutFrame(
    env: JNIEnv,
    _class: JClass,
    out: JByteArray,
) -> jint {
    let Some(frame) = VOICE_PLAYOUT.lock().ok().and_then(|mut q| q.pop_front()) else {
        return 0;
    };
    let mut bytes = [0i8; VOICE_SAMPLES * 2];
    for (i, s) in frame.iter().enumerate() {
        let [lo, hi] = s.to_le_bytes();
        bytes[2 * i] = lo as i8;
        bytes[2 * i + 1] = hi as i8;
    }
    match env.set_byte_array_region(&out, 0, &bytes) {
        Ok(()) => (VOICE_SAMPLES * 2) as jint,
        Err(_) => 0,
    }
}

// ── Rust → Kotlin control calls ─────────────────────────────────────────────────────

/// Resolve `MediaBridge` through the activity's classloader (as in `bio.rs`:
/// `FindClass` on a non-main thread only sees system classes).
fn with_bridge(
    f: impl for<'a> FnOnce(&mut JNIEnv<'a>, &JClass<'a>, &JObject<'a>) -> Result<(), String>,
) -> Result<(), String> {
    let ctx = ndk_context::android_context();
    let vm =
        unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| format!("JavaVM: {e}"))?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach: {e}"))?;
    // Prefer the live Activity (permission prompts / consent dialogs need one); fall
    // back to the app context so classloading keeps working headless.
    let activity = unsafe { JObject::from_raw(context_obj().cast()) };
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
            format!("MediaBridge not found (regenerate with harden-android.sh): {e}")
        })?;
    let class = JClass::from(class);
    let out = f(&mut env, &class, &activity);
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        return Err("MediaBridge call raised a Java exception".into());
    }
    out
}

fn call_with_activity(method: &str) -> Result<(), String> {
    with_bridge(|env, class, activity| {
        env.call_static_method(
            class,
            method,
            "(Landroid/app/Activity;)V",
            &[JValue::Object(activity)],
        )
        .map(|_| ())
        .map_err(|e| format!("{method}: {e}"))
    })
}

fn call_no_args(method: &str) -> Result<(), String> {
    with_bridge(|env, class, _| {
        env.call_static_method(class, method, "()V", &[])
            .map(|_| ())
            .map_err(|e| format!("{method}: {e}"))
    })
}

/// Prompt for RECORD_AUDIO if it isn't granted yet (no-op otherwise). Native cpal
/// capture for calls can't raise the runtime prompt itself — call this before opening
/// the mic so first use asks instead of failing with a bare "permission denied".
pub fn ensure_mic_permission() {
    if let Err(e) = call_with_activity("ensureMic") {
        crate::diag!("[media] mic permission bridge: {e}");
    }
}

/// Start/stop the Camera2 pipeline (prompts for the CAMERA permission on first use).
pub fn set_camera_capture(on: bool) {
    let r = if on {
        call_with_activity("startCamera")
    } else {
        if let Ok(mut s) = CAMERA_SLOT.lock() {
            *s = None;
        }
        call_no_args("stopCamera")
    };
    if let Err(e) = r {
        crate::diag!("[media] camera bridge: {e}");
    }
}

/// Start/stop screen share (OS consent dialog + foreground service on start).
pub fn set_screen_capture(on: bool) {
    let r = call_with_activity(if on { "startScreen" } else { "stopScreen" });
    if !on {
        if let Ok(mut s) = SCREEN_SLOT.lock() {
            *s = None;
        }
    }
    if let Err(e) = r {
        crate::diag!("[media] screen bridge: {e}");
    }
}

/// Toggle AudioPlaybackCapture alongside an active projection.
pub fn set_screen_audio_capture(on: bool) {
    let r = call_no_args(if on {
        "startScreenAudio"
    } else {
        "stopScreenAudio"
    });
    if let Err(e) = r {
        crate::diag!("[media] screen-audio bridge: {e}");
    }
}

/// Start/stop the echo-cancelled voice-call mic (VOICE_COMMUNICATION AudioRecord +
/// platform AEC/NS/AGC + MODE_IN_COMMUNICATION routing). Replaces cpal input in calls.
pub fn set_voice_capture(on: bool) {
    let r = call_with_activity(if on { "startVoiceMic" } else { "stopVoiceMic" });
    if !on {
        if let Ok(mut q) = VOICE_AUDIO.lock() {
            q.clear();
        }
        if let Ok(mut p) = VOICE_PENDING.lock() {
            p.clear();
        }
    }
    if let Err(e) = r {
        crate::diag!("[media] voice-mic bridge: {e}");
    }
}

/// Start/stop the voice-call playout sink (USAGE_VOICE_COMMUNICATION AudioTrack).
/// Replaces cpal output in calls — a MEDIA-usage stream is muted/ducked by many OEM
/// ROMs while in MODE_IN_COMMUNICATION and never feeds the AEC its reference.
pub fn set_voice_playout(on: bool) {
    let r = call_no_args(if on {
        "startVoicePlayout"
    } else {
        "stopVoicePlayout"
    });
    if !on {
        if let Ok(mut q) = VOICE_PLAYOUT.lock() {
            q.clear();
        }
    }
    if let Err(e) = r {
        crate::diag!("[media] voice-playout bridge: {e}");
    }
}

/// Toggle the platform NoiseSuppressor on the live voice mic (and the wanted state for
/// future calls). Android's counterpart of the desktop RNNoise gate.
pub fn set_voice_noise_suppression(on: bool) {
    let r = with_bridge(|env, class, _| {
        env.call_static_method(
            class,
            "setVoiceNoiseSuppression",
            "(Z)V",
            &[JValue::Bool(on as jboolean)],
        )
        .map(|_| ())
        .map_err(|e| format!("setVoiceNoiseSuppression: {e}"))
    });
    if let Err(e) = r {
        crate::diag!("[media] voice-ns bridge: {e}");
    }
}

/// Route call audio to the loudspeaker (`true`) or back to the earpiece (`false`).
/// Hand route ownership to Core-Telecom (or take it back when the call ends). While
/// Telecom owns it, `MediaBridge` keeps capture/playout and the platform AEC/NS but stops
/// driving `setCommunicationDevice`/SCO — two writers is how call audio ends up on the
/// wrong device (`internal/CALL_PLAN.md` §7.4).
pub fn set_telecom_owns_route(owned: bool) {
    let r = with_bridge(|env, class, _ctx| {
        env.call_static_method(
            class,
            "setTelecomOwnsRoute",
            "(Z)V",
            &[JValue::Bool(owned as jboolean)],
        )
        .map(|_| ())
        .map_err(|e| format!("setTelecomOwnsRoute: {e}"))
    });
    if let Err(e) = r {
        crate::diag!("[media] telecom route ownership: {e}");
    }
}

pub fn set_speakerphone(on: bool) {
    let r = with_bridge(|env, class, activity| {
        env.call_static_method(
            class,
            "setSpeakerphone",
            "(Landroid/app/Activity;Z)V",
            &[JValue::Object(activity), JValue::Bool(on as jboolean)],
        )
        .map(|_| ())
        .map_err(|e| format!("setSpeakerphone: {e}"))
    });
    if let Err(e) = r {
        crate::diag!("[media] speakerphone bridge: {e}");
    }
}

/// Current call-audio routing options as JSON:
/// `{"bt": <headset connected>, "bt_name": <product name>, "route": "earpiece|speaker|bluetooth|wired"}`.
pub fn audio_routes() -> Option<String> {
    let mut out = None;
    let r = with_bridge(|env, class, ctx| {
        let v = env
            .call_static_method(
                class,
                "audioRoutesJson",
                "(Landroid/content/Context;)Ljava/lang/String;",
                &[JValue::Object(ctx)],
            )
            .and_then(|v| v.l())
            .map_err(|e| format!("audioRoutesJson: {e}"))?;
        let s: String = env.get_string(&v.into()).map_err(|e| e.to_string())?.into();
        out = Some(s);
        Ok(())
    });
    if let Err(e) = r {
        crate::diag!("[media] audio-routes bridge: {e}");
    }
    out
}

/// Route call audio explicitly ("earpiece" | "speaker" | "bluetooth"); returns the
/// fresh routes JSON so the UI reflects what actually happened, not what was asked.
pub fn set_audio_route(route: &str) -> Option<String> {
    let mut out = None;
    let r = with_bridge(|env, class, ctx| {
        let jroute = env.new_string(route).map_err(|e| e.to_string())?;
        let v = env
            .call_static_method(
                class,
                "setAudioRoute",
                "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(ctx), JValue::Object(&jroute)],
            )
            .and_then(|v| v.l())
            .map_err(|e| format!("setAudioRoute: {e}"))?;
        let s: String = env.get_string(&v.into()).map_err(|e| e.to_string())?.into();
        out = Some(s);
        Ok(())
    });
    if let Err(e) = r {
        crate::diag!("[media] audio-route bridge: {e}");
    }
    out
}

/// Call tones ("ringback" | "ring" | "end" | "stop") — the webview's own audio is
/// silent in MODE_IN_COMMUNICATION, so these live in Kotlin. "ring" plays the user's
/// system ringtone (in-app incoming overlay); the rest are voice-call-stream tones.
pub fn call_tone(kind: &str) {
    let r = with_bridge(|env, class, ctx| {
        let jkind = env.new_string(kind).map_err(|e| e.to_string())?;
        env.call_static_method(
            class,
            "callTone",
            "(Landroid/content/Context;Ljava/lang/String;)V",
            &[JValue::Object(ctx), JValue::Object(&jkind)],
        )
        .map(|_| ())
        .map_err(|e| format!("callTone: {e}"))
    });
    if let Err(e) = r {
        crate::diag!("[media] call-tone bridge: {e}");
    }
}

/// Kotlin's AudioDeviceCallback: a call-audio route changed (headset plugged /
/// unplugged, auto-switch). Forward to the webview so the in-call button adapts live.
#[no_mangle]
pub extern "system" fn Java_app_sona_messenger_MediaBridge_nativeAudioRoute(
    mut env: JNIEnv,
    _class: JClass,
    json: jni::objects::JString,
) {
    let Ok(s) = env.get_string(&json) else {
        return;
    };
    let s: String = s.into();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
        crate::eng().emit("audio_route", v);
    }
}

/// Background the app the way Android's home button does: `Activity.moveTaskToBack`.
/// Used by the double-back-to-exit gesture — the task leaves the screen but the
/// process (and the delivery engine) keeps running, unlike a swipe-kill.
pub fn move_task_to_back() {
    let Some(act) = activity_obj() else {
        return; // headless: nothing on screen to background
    };
    let ctx = ndk_context::android_context();
    let Ok(vm) = (unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }) else {
        return;
    };
    let Ok(mut env) = vm.attach_current_thread() else {
        return;
    };
    let obj = unsafe { JObject::from_raw(act.cast()) };
    if let Err(e) = env.call_method(&obj, "moveTaskToBack", "(Z)Z", &[JValue::Bool(1)]) {
        crate::diag!("[nav] moveTaskToBack: {e}");
        let _ = env.exception_clear();
    }
}

/// Whether call audio currently routes to the loudspeaker.
pub fn speakerphone_on() -> bool {
    let mut on = false;
    let r = with_bridge(|env, class, activity| {
        on = env
            .call_static_method(
                class,
                "isSpeakerphoneOn",
                "(Landroid/app/Activity;)Z",
                &[JValue::Object(activity)],
            )
            .and_then(|v| v.z())
            .map_err(|e| format!("isSpeakerphoneOn: {e}"))?;
        Ok(())
    });
    if let Err(e) = r {
        crate::diag!("[media] speakerphone bridge: {e}");
    }
    on
}
