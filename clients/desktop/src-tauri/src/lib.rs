//! Tauri glue for Sona desktop/Android.
//!
//! This layer is deliberately thin: every command forwards to the headless, tested
//! [`client_core`] SDK. No security logic lives here — keep it that way so the audited
//! surface stays in `client-core` / `crypto-core` / `kt-log`. What *does* live here is the
//! non-secret app plumbing a GUI needs: where the sealed vault / encrypted history / relay
//! config sit on disk, and a live subscription that streams inbound messages to the UI.
//!
//! Persistence (all under the platform app-data dir):
//! * `config.json`  — relay URL + pinned KT key. Not secret; it's the trust anchor config.
//! * `vault.bin`    — the sealed account vault (device-bound when a key store is present).
//! * `history.bin`  — chat history, encrypted at rest under the account `data_key`.
//!
//! NOTE: building this crate requires the platform webview (e.g. `libwebkit2gtk-4.1` on
//! Linux) and the Tauri CLI. It is not built by the plain `cargo test` used for
//! `client-core`. See `clients/README.md`.

use std::path::PathBuf;
use std::sync::Arc;

use client_core::devicekey::DeviceKeyProvider;
use client_core::multidevice::{
    self, self_sync_jitter_secs, LinkRequest, RevocationCheck, RosterAudit,
};
use client_core::{
    contact_for, identity_hash_for, Client, Contact, ContactOutcome, DeliveryStatus, Direction,
    Group, GroupMember, History, InboundEvent, StoredMessage,
};
use crypto_core::{
    check_password, create_account_with_username_bound, quick, unlock_bound, unlock_with_seal_key,
    vault::SealKey, Account, DEVICE_KEY_LEN,
};
use serde::{Deserialize, Serialize};
use tauri::Manager;
use tokio::sync::Mutex;

#[cfg(target_os = "android")]
mod android_media;
mod audio;
mod bio;
mod call;
mod cmd;
mod delivery_service;
pub(crate) mod engine;
mod hw_attest;
#[cfg(target_os = "android")]
mod jni_entry;
mod media_shell;
mod notif;
pub(crate) mod notifier;
mod push;
mod runtime;
mod state;
mod update;
mod views;
pub(crate) use call::cmd::*;
pub(crate) use call::engine::*;
pub(crate) use call::group::*;
pub(crate) use call::signal::*;
pub(crate) use cmd::chat::*;
pub(crate) use cmd::files::*;
pub(crate) use cmd::groups::*;
pub(crate) use cmd::security::*;
pub(crate) use cmd::setup::*;
pub(crate) use notif::*;
pub(crate) use push::*;
pub(crate) use runtime::*;
pub(crate) use state::{
    detect_capabilities, device_key, device_key_or_create, eng, AppState, CallCtl, GroupCallCtl,
    PendingGroupOffer, PendingOffer, PendingReconnect, Prefs, RelayConfig, Session,
    LEG_REOFFER_DELAY_MS, MAX_GROUP_CALL_MEMBERS, MAX_LEG_REOFFERS, MAX_PIN_ATTEMPTS,
    PRESENCE_WINDOW_SECS, RECONNECT_GRACE_MS, RECONNECT_WINDOW_SECS,
};
pub(crate) use views::*;

// ---------------------------------------------------------------------------------------
// View structs — flat, serializable shapes for the UI. No behavior.
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------------------

/// How long after sending a message may still be edited.
const EDIT_WINDOW_SECS: u64 = 300;

// ---------------------------------------------------------------------------------------
// Attachments: send a file, fetch one inline (images), save one to disk.
// ---------------------------------------------------------------------------------------

/// Cap accepted by the relay for one blob; enforced client-side too for a clear error.
const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

// ─────────────────────────── GIFs (relay privacy proxy) ───────────────────────────

/// Group flavor of [`send_attachment_inner`]: encrypt + upload the blob ONCE (no lock
/// held), then fan the reference out — multi-device: to every device of every member
/// plus our own other devices (shared msg_id); legacy relay: pairwise per member.
/// Recorded like a group text (sender = our primary key; rendering derives "mine").
async fn send_group_attachment(
    state: &tauri::State<'_, AppState>,
    group_id: &str,
    filename: String,
    data: Vec<u8>,
    voice_secs: Option<u32>,
    caption: Option<String>,
    peaks: Vec<u8>,
) -> Result<MsgView, String> {
    let client = {
        let s = state.inner.lock().await;
        let g = s.history.group(group_id).ok_or("no such group")?;
        cmd::groups::ensure_in_group(g)?;
        s.client.clone().ok_or("not configured")?
    };

    // Slow part (encrypt-to-blob + upload) with no lock held.
    let mut attachment = client
        .upload_attachment(&filename, &data)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(secs) = voice_secs {
        attachment.voice = true;
        attachment.duration_secs = secs;
    }
    attachment.caption = caption.clone();
    attachment.peaks = peaks;
    let view_peaks = attachment.peaks.clone();

    let mut s = state.inner.lock().await;
    let g = s.history.group(group_id).ok_or("no such group")?;
    let group = group_from_record(group_id, g);
    let my_key = s
        .account
        .as_ref()
        .map(|a| a.ratchet_ref().identity_key())
        .unwrap_or_default();
    // File our own copy under the account PRIMARY key so it renders as ours on every
    // one of our devices (same rule as group texts).
    let sender_key = s
        .history
        .self_primary_key()
        .map(str::to_string)
        .unwrap_or_else(|| my_key.clone());
    let (msg_id, sent_at) = if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_mut().ok_or("locked")?;
        client
            .send_group_file_multi(
                account,
                &mut sess.history,
                &group,
                attachment.clone(),
                false,
            )
            .await
            .map_err(|e| e.to_string())?
    } else {
        let expire = Some(s.history.group_timer(group_id).unwrap_or(0));
        let account = s.account.as_mut().ok_or("locked")?;
        client
            .send_group_file(account, &group, attachment.clone(), expire, false)
            .await
            .map_err(|e| e.to_string())?;
        (
            format!(
                "g{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ),
            attachment.ts,
        )
    };
    s.history
        .record_group_attachment(group_id, &sender_key, &msg_id, attachment, sent_at, None);
    s.history.mark_group_seen(group_id);
    let delete_at = s
        .history
        .group(group_id)
        .and_then(|g| g.messages.iter().find(|m| m.msg_id == msg_id))
        .and_then(|m| m.delete_at);
    let view = MsgView {
        msg_id,
        direction: "outgoing",
        body: filename,
        sent_at,
        delete_at,
        attachment: true,
        voice: voice_secs.is_some(),
        duration_secs: voice_secs.unwrap_or(0),
        status: "sent",
        edited: false,
        reply_to_id: None,
        reply_preview: None,
        reactions: Vec::new(),
        caption,
        peaks: view_peaks,
        system: false,
        unread: false,
        pinned: false,
        forwarded: false,
    };
    s.persist()?;
    Ok(view)
}

/// Human label for a disappearing-messages duration, for a system-event chip.
fn timer_label(secs: Option<u64>) -> String {
    match secs {
        None => "Disappearing messages off".to_string(),
        Some(s) => {
            let (n, unit) = if s % 604800 == 0 && s >= 604800 {
                (s / 604800, "week")
            } else if s % 86400 == 0 && s >= 86400 {
                (s / 86400, "day")
            } else if s % 3600 == 0 && s >= 3600 {
                (s / 3600, "hour")
            } else if s % 60 == 0 && s >= 60 {
                (s / 60, "minute")
            } else {
                (s, "second")
            };
            let plural = if n == 1 { "" } else { "s" };
            format!("Disappearing messages: {n} {unit}{plural}")
        }
    }
}

/// Current unix time in seconds (file naming, not security).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// "3d 4h" / "2h 10m" / "45m" — rough, for user-facing wait messages.
fn human_duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{}m", m.max(1))
    }
}

/// The attachment reference for a message, cloned out of history under the lock.
async fn attachment_ref(
    state: &tauri::State<'_, AppState>,
    peer: &str,
    msg_id: &str,
) -> Result<(Arc<Client>, client_core::AttachmentRef), String> {
    let s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    // `peer` is a 1:1 identity key or a group id — check both timelines.
    let att = s
        .history
        .messages(peer)
        .iter()
        .find(|m| m.msg_id == msg_id)
        .and_then(|m| m.attachment.clone())
        .or_else(|| {
            s.history
                .group(peer)
                .and_then(|g| g.messages.iter().find(|m| m.msg_id == msg_id))
                .and_then(|m| m.attachment.clone())
        })
        .ok_or("no such attachment")?;
    Ok((client, att))
}

// ---------------------------------------------------------------------------------------
// Local chat preferences (pin/mute/nickname/block) + chat deletion. All local prefs live
// inside the encrypted history; nothing here is transmitted (except delete-for-both).
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Groups.
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Multi-device: linking + device management.
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Security: quick unlock (PIN / biometric / auto), auto-lock, PIN reminders, and the
// username/password change ceremony. Design notes in crypto_core::quick and docs/.
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Voice calls. Signaling rides the ratchet (CallOffer/Answer/End); media is the
// client-core engine over the relay's blind rooms; audio is cpal (audio.rs). Design
// rationale lives in client-core/src/call.rs and crates/server/src/call.rs.
// ---------------------------------------------------------------------------------------

/// How long an unanswered ring lasts, both directions.
const RING_TIMEOUT_SECS: u64 = 45;

// ---------------------------------------------------------------------------------------
// Group calls. A full mesh of the 1:1 blind pair rooms — one room + one fresh key per
// participant pair, tickets only ever inside that pair's ratchet session. The relay is
// untouched and cannot tell a group-call leg from a 1:1 voice call. Voice-only by
// design (mesh upload scales with group size); rationale in client-core/src/groupcall.rs.
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Live delivery: one persistent authenticated WebSocket, pushing events in real time.
// ---------------------------------------------------------------------------------------

/// How often the disappearing-messages reaper checks for expired messages. The UI hides
/// an expired bubble at the exact second client-side; this tick only bounds how long the
/// expired plaintext stays inside the sealed history file (and how stale a chat-list
/// preview can get).
const REAPER_TICK_SECS: u64 = 5;

// ---------------------------------------------------------------------------------------
// Delivery modes, push registration, and headless entry points (docs/NOTIFICATIONS.md Pillar C).
// ---------------------------------------------------------------------------------------

/// Linux/WebKitGTK: wry neither enables media streams nor answers WebKit's permission
/// requests, so `getUserMedia` silently fails. Enable the setting and allow user-media
/// capture requests from our own (only) page: audio for voice messages, video for the
/// QR link-code scanner. Everything else (geolocation, notifications, …) stays denied.
/// Android grants this through the generated WebChromeClient + the manifest permission;
/// Windows has its own `PermissionRequested` handler below.
#[cfg(target_os = "linux")]
fn allow_microphone(app: &tauri::AppHandle) {
    use tauri::Manager as _;
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let _ = window.with_webview(|pw| {
        use webkit2gtk::glib::object::Cast as _;
        use webkit2gtk::{
            PermissionRequestExt as _, SettingsExt as _, UserMediaPermissionRequestExt as _,
            WebViewExt as _,
        };
        let wv = pw.inner();
        if let Some(settings) = webkit2gtk::WebViewExt::settings(&wv) {
            settings.set_enable_media_stream(true);
        }
        wv.connect_permission_request(|_, request| {
            if let Some(media) =
                request.dynamic_cast_ref::<webkit2gtk::UserMediaPermissionRequest>()
            {
                if media.is_for_audio_device() || media.is_for_video_device() {
                    media.allow();
                } else {
                    media.deny();
                }
            } else {
                request.deny(); // everything else (geolocation, notifications, …)
            }
            true
        });
    });
}

/// Windows/WebView2: answer `PermissionRequested` for microphone + camera on our own
/// (only) page — parity with the WebKitGTK handler above; without it WebView2 pops its
/// own per-profile prompt. wry's built-in handler only auto-allows clipboard; extra
/// handlers coexist, and any other permission kind keeps the default (prompt) path.
#[cfg(target_os = "windows")]
fn allow_microphone(app: &tauri::AppHandle) {
    use tauri::Manager as _;
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let _ = window.with_webview(|pw| {
        use webview2_com::Microsoft::Web::WebView2::Win32::{
            COREWEBVIEW2_PERMISSION_KIND, COREWEBVIEW2_PERMISSION_KIND_CAMERA,
            COREWEBVIEW2_PERMISSION_KIND_MICROPHONE, COREWEBVIEW2_PERMISSION_STATE_ALLOW,
        };
        use webview2_com::PermissionRequestedEventHandler;
        unsafe {
            let Ok(webview) = pw.controller().CoreWebView2() else {
                return;
            };
            let mut token = 0i64;
            let _ = webview.add_PermissionRequested(
                &PermissionRequestedEventHandler::create(Box::new(|_, args| {
                    if let Some(args) = args {
                        let mut kind = COREWEBVIEW2_PERMISSION_KIND::default();
                        args.PermissionKind(&mut kind)?;
                        if kind == COREWEBVIEW2_PERMISSION_KIND_MICROPHONE
                            || kind == COREWEBVIEW2_PERMISSION_KIND_CAMERA
                        {
                            args.SetState(COREWEBVIEW2_PERMISSION_STATE_ALLOW)?;
                        }
                    }
                    Ok(())
                })),
                &mut token,
            );
        }
    });
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn allow_microphone(_app: &tauri::AppHandle) {}

/// Android drops a process's stdout/stderr on the floor, which makes every `eprintln`
/// diagnostic in the Rust tree invisible in release builds. Bridge them to logcat
/// (tag `SonaRust`) so on-device failures are debuggable at all.
#[cfg(target_os = "android")]
fn redirect_stdio_to_logcat() {
    unsafe extern "C" {
        fn __android_log_write(prio: i32, tag: *const u8, text: *const u8) -> i32;
    }
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return;
        }
        libc::dup2(fds[1], libc::STDOUT_FILENO);
        libc::dup2(fds[1], libc::STDERR_FILENO);
        let read_fd = fds[0];
        std::thread::Builder::new()
            .name("stdio-logcat".into())
            .spawn(move || {
                use std::io::BufRead;
                use std::os::fd::FromRawFd;
                let file = std::fs::File::from_raw_fd(read_fd);
                for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
                    let mut msg = line.into_bytes();
                    msg.push(0);
                    // 4 = ANDROID_LOG_INFO
                    __android_log_write(4, c"SonaRust".as_ptr().cast(), msg.as_ptr());
                }
            })
            .ok();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "android")]
    redirect_stdio_to_logcat();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::default())
        .on_window_event(|window, event| {
            match event {
                // Desktop-authoritative focus. On Android the activity lifecycle
                // (`nativeActivityState`) is authoritative instead — tao's Focused
                // events stop arriving once the activity dies.
                #[cfg(not(target_os = "android"))]
                tauri::WindowEvent::Focused(f) => {
                    let _ = window;
                    engine::global().set_focused(*f);
                }
                // Desktop: closing the window hides to the tray — the process (and with
                // it the delivery socket + notifications) stays alive. Quit lives in
                // the tray menu. Android never emits this event.
                #[cfg(not(target_os = "android"))]
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    let _ = window.hide();
                    // Hiding does not reliably fire Focused(false) on every WM; force
                    // it so notifications are not suppressed while in the tray.
                    engine::global().set_focused(false);
                    api.prevent_close();
                }
                _ => {}
            }
        })
        .setup(|app| {
            // Desktop tray: the way back in after close-to-tray, and the real quit.
            #[cfg(not(target_os = "android"))]
            {
                use tauri::menu::{Menu, MenuItem};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
                fn show_main(app: &tauri::AppHandle) {
                    if let Some(w) = app.webview_windows().values().next() {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                }
                let open = MenuItem::with_id(app, "open", "Open Sona", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "quit", "Quit Sona", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&open, &quit])?;
                let mut tray = TrayIconBuilder::with_id("main")
                    .tooltip("Sona")
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, e| match e.id.as_ref() {
                        "open" => show_main(app),
                        "quit" => app.exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            show_main(tray.app_handle());
                        }
                    });
                if let Some(icon) = app.default_window_icon() {
                    tray = tray.icon(icon.clone());
                }
                tray.build(app)?;
            }
            // Attach the UI to the (possibly already running — Android sticky
            // restart) delivery engine, then seed the data dir + persisted
            // config/prefs. `init_data_dir` is idempotent: whichever entry point ran
            // first (this setup, or a headless JNI start) already did the work.
            let dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            allow_microphone(app.handle());
            engine::global().attach_ui(app.handle().clone());
            engine::global().init_data_dir(dir);
            std::result::Result::Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            update::update_check,
            update::update_install,
            update::update_open_install_settings,
            cmd::setup::app_status,
            cmd::setup::password_strength,
            cmd::setup::fetch_kt_pubkey,
            cmd::setup::configure,
            cmd::setup::socks_proxy,
            cmd::setup::set_socks_proxy,
            cmd::setup::relay_invite,
            cmd::setup::registration_needs_invite,
            cmd::setup::create_account,
            cmd::setup::unlock,
            cmd::setup::lock,
            cmd::chat::conversations,
            cmd::search::search_messages,
            cmd::chat::thread,
            cmd::chat::open_chat,
            cmd::chat::accept_key_change,
            cmd::chat::mark_verified,
            cmd::chat::mark_seen,
            cmd::chat::send,
            cmd::files::send_file,
            cmd::files::send_voice,
            cmd::files::fetch_attachment,
            cmd::files::save_attachment,
            cmd::contacts::set_pinned,
            cmd::contacts::set_muted,
            cmd::contacts::set_nickname,
            cmd::contacts::my_avatar,
            cmd::contacts::set_my_avatar,
            cmd::contacts::set_blocked,
            cmd::contacts::set_archived,
            cmd::contacts::set_unread,
            cmd::contacts::clear_unread_on_open,
            cmd::requests::message_requests,
            cmd::requests::request_badge,
            cmd::requests::accept_msg_request,
            cmd::requests::decline_msg_request,
            cmd::requests::mark_requests_seen,
            cmd::requests::msg_request_prefs,
            cmd::requests::set_msg_request_prefs,
            cmd::chat::react,
            cmd::chat::react_group,
            cmd::chat::set_typing,
            cmd::chat::set_group_typing,
            cmd::security::privacy_prefs,
            cmd::security::set_privacy,
            cmd::chat::set_open_chat,
            call::cmd::call_set_speaker,
            call::cmd::call_audio_routes,
            call::cmd::call_set_route,
            call::cmd::call_tone,
            call::cmd::call_set_noise_suppression,
            cmd::files::gif_available,
            cmd::files::gif_search,
            cmd::files::gif_trending,
            cmd::files::gif_preview,
            cmd::files::send_gif,
            cmd::contacts::delete_chat,
            cmd::groups::create_group,
            cmd::groups::add_to_group,
            cmd::groups::group_thread,
            cmd::groups::set_group_avatar,
            cmd::groups::send_group_msg,
            cmd::groups::mark_group_seen,
            cmd::groups::delete_group,
            cmd::groups::my_groups,
            cmd::groups::edit_group_message,
            cmd::groups::delete_group_message,
            cmd::groups::delete_group_message_everyone,
            cmd::groups::rename_group,
            cmd::groups::remove_group_member,
            cmd::groups::transfer_group_admin,
            cmd::groups::leave_group,
            cmd::groups::set_group_pinned,
            cmd::groups::set_group_archived,
            cmd::groups::set_group_unread,
            cmd::groups::clear_group_unread_on_open,
            cmd::notes::send_note,
            cmd::notes::set_note_disappearing,
            cmd::requests::send_chat_request,
            cmd::pins::set_msg_pinned,
            cmd::pins::set_group_msg_pinned,
            cmd::forward::forward_message,
            cmd::chat::edit_message,
            cmd::chat::delete_message,
            cmd::chat::delete_message_everyone,
            cmd::chat::set_group_muted,
            cmd::chat::set_disappearing,
            cmd::chat::set_group_disappearing,
            cmd::devices::audit_own_key,
            cmd::devices::link_start,
            cmd::devices::attest_verdict,
            cmd::devices::authorize_device,
            cmd::devices::complete_link_cmd,
            cmd::devices::request_resync,
            cmd::devices::poll_resync_cmd,
            cmd::devices::fulfill_resync_cmd,
            cmd::devices::list_devices,
            cmd::devices::revoke_device,
            cmd::devices::audit_devices,
            cmd::devices::transfer_primary,
            cmd::devices::accept_primary_cmd,
            cmd::devices::check_transfer_cmd,
            cmd::devices::poll_now,
            cmd::security::security_status,
            cmd::security::pin_strength,
            cmd::security::verify_password,
            cmd::security::set_pin,
            cmd::security::disable_pin,
            cmd::security::unlock_pin,
            cmd::security::verify_pin,
            cmd::security::set_auto_unlock,
            cmd::security::try_auto_unlock,
            cmd::security::set_bio_unlock,
            cmd::security::unlock_bio,
            cmd::security::os_presence_check,
            cmd::security::change_password,
            cmd::security::change_username,
            cmd::security::delete_account,
            cmd::security::set_lock_after,
            cmd::security::set_pin_reminder,
            cmd::security::note_app_open,
            cmd::delivery::delivery_status,
            cmd::delivery::set_delivery_mode,
            cmd::delivery::take_pending_intent,
            cmd::delivery::test_notification,
            cmd::delivery::test_ring,
            cmd::delivery::delivery_fixit,
            cmd::delivery::up_distributors,
            cmd::delivery::up_select,
            cmd::delivery::up_clear,
            cmd::files::clipboard_image,
            cmd::delivery::app_background,
            call::cmd::call_status,
            call::cmd::call_start,
            call::cmd::call_accept,
            call::cmd::call_decline,
            call::cmd::call_hangup,
            call::cmd::call_set_muted,
            call::cmd::call_set_camera,
            call::cmd::call_set_screen,
            call::cmd::call_set_screen_audio,
            call::cmd::call_media_channel,
            call::group::group_call_start,
            call::group::group_call_accept,
            call::group::group_call_decline,
            call::group::group_call_hangup,
            call::group::group_call_set_muted,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sona");
}
