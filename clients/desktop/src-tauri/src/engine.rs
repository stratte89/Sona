//! The headless delivery engine (docs/NOTIFICATIONS.md Pillar A).
//!
//! Delivery, decryption, and notification *decisions* live on a process-global engine
//! with its own tokio runtime, started by ANY entry point — Tauri setup (normal
//! launch), the Android `DeliveryService` (sticky/boot restart), or a push receiver
//! (wake-drain). The UI *attaches* to a running engine; it never owns delivery. This is
//! what fixes RC-1 (the sticky-restart Kotlin shell used to come back without any Rust)
//! and RC-2 (notifications used to die with the Activity-bound plugin).
//!
//! The engine deliberately holds no crypto logic of its own: the delivery loops in
//! `lib.rs` keep their exact cancel-safe frame handling, poison acks, and
//! revoked-claim verification — they just spawn on `engine.rt` and talk to the UI/OS
//! through the engine instead of a `tauri::AppHandle`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Mutex as StdMutex, OnceLock, RwLock};

use tauri::Emitter as _;
use tokio::sync::Mutex;

use crate::notifier::{self, ConnState, NotifLine};
use crate::{media_shell, Session};

/// How many MessagingStyle lines the engine buffers per chat.
const MAX_NOTIF_LINES: usize = 8;
/// Dedup ring for the drain-vs-socket handoff window: the ack protocol prevents
/// redelivery in steady state, this is cheap insurance against a duplicate
/// *notification* when a push drain and a reviving socket race.
const SEEN_IDS_CAP: usize = 256;
/// How often a deferred background auto-lock re-checks whether the call it is waiting on
/// has ended. Short enough that the vault closes promptly after a call, long enough that
/// a long call costs a handful of lock acquisitions rather than a poll loop.
const IN_CALL_LOCK_RECHECK_SECS: u64 = 30;

pub struct Engine {
    /// Engine-owned runtime — never Tauri's, so delivery survives without a UI.
    rt: tokio::runtime::Runtime,
    /// THE session. Tauri's `AppState` borrows this same Arc.
    pub session: std::sync::Arc<Mutex<Session>>,
    /// Live media IPC channel to the webview (decoded peer video frames). Engine-owned
    /// so the silent call-resume path works headless; harmless with no UI bound.
    pub media_ui: media_shell::UiChannel,
    /// Attached UI event sink. `None` when headless; every emit no-ops then (the UI
    /// re-fetches state on attach — `main.js` re-renders from `sync`/`conn` on load).
    ui: RwLock<Option<tauri::AppHandle>>,
    /// Live focus. Starts FALSE (RC-5): a headless start must never suppress
    /// notifications; the UI/activity flips it on attach/resume.
    pub focused: AtomicBool,
    /// The conversation the UI has open (peer key or group id) — suppression rule.
    pub open_chat: StdMutex<Option<String>>,
    conn_state: StdMutex<ConnState>,
    /// Network-change nudge: reconnect backoffs cut short when connectivity returns.
    net_nudge: tokio::sync::Notify,
    /// Per-chat MessagingStyle line buffers (replayed on each post).
    notif_lines: StdMutex<HashMap<String, Vec<NotifLine>>>,
    /// Recently-notified msg ids (dedup ring; see [`SEEN_IDS_CAP`]).
    seen_ids: StdMutex<(VecDeque<String>, HashSet<String>)>,
    /// The natively-ringing call (call_id / group call_instance), if any.
    ring: StdMutex<Option<String>>,
    /// Presentation handles handed to the platform and not yet taken back. A handle that
    /// outlives its call is a system call nothing will ever disconnect.
    system_calls: StdMutex<HashSet<String>>,
    /// Latest FCM registration token pushed up from Kotlin (`nativeSetPushToken`).
    push_token: StdMutex<Option<String>>,
    /// Live UnifiedPush endpoint URL from the chosen distributor
    /// (`nativeSetUpEndpoint`; empty push = cleared). Preferred over the FCM token
    /// when both exist — the user explicitly picked a Google-free broker.
    up_endpoint: StdMutex<Option<String>>,
    /// Routing extras from a notification tap that arrived before the webview could
    /// listen (cold start). The UI collects it with `take_pending_intent` on load.
    pending_intent: StdMutex<Option<serde_json::Value>>,
    /// Monotonic unfocus generation — cancels a scheduled background auto-lock when
    /// focus returns before the deadline.
    unfocus_epoch: StdMutex<u64>,
    /// Active push-triggered drain loops; when the last finishes, the shortService is
    /// released.
    drains: StdMutex<usize>,
}

static ENGINE: OnceLock<Engine> = OnceLock::new();

/// The process-global engine (created on first use).
pub fn global() -> &'static Engine {
    ENGINE.get_or_init(|| Engine {
        rt: tokio::runtime::Builder::new_multi_thread()
            // Four, because a call in progress needs four things running at once and
            // three of them are allowed to block their worker: the session loop (voice,
            // on a hard 20 ms cadence), the video encode task, the video decode task
            // (~10 ms per 1080p frame, and 20 of those a second), and the reliable-send
            // task. On two workers a share could park both of them in codec work and the
            // voice tick simply did not get scheduled — the same "everything went choppy"
            // symptom as the wire-level stall, arriving by a different route. Idle
            // workers cost a parked thread each, which is nothing next to that.
            .worker_threads(4)
            .enable_all()
            .thread_name("sona-engine")
            .build()
            .expect("engine runtime builds"),
        session: std::sync::Arc::default(),
        media_ui: media_shell::UiChannel::default(),
        ui: RwLock::new(None),
        focused: AtomicBool::new(false),
        open_chat: StdMutex::new(None),
        conn_state: StdMutex::new(ConnState::Off),
        net_nudge: tokio::sync::Notify::new(),
        notif_lines: StdMutex::new(HashMap::new()),
        seen_ids: StdMutex::new((VecDeque::new(), HashSet::new())),
        ring: StdMutex::new(None),
        system_calls: StdMutex::new(HashSet::new()),
        push_token: StdMutex::new(None),
        up_endpoint: StdMutex::new(None),
        pending_intent: StdMutex::new(None),
        unfocus_epoch: StdMutex::new(0),
        drains: StdMutex::new(0),
    })
}

impl Engine {
    // ── Tasks ─────────────────────────────────────────────────────────────────────

    pub fn spawn<F>(&self, fut: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.rt.spawn(fut)
    }

    pub fn spawn_blocking<F, R>(&self, f: F) -> tokio::task::JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.rt.spawn_blocking(f)
    }

    /// Block the current (non-async) thread on a future, on the engine runtime.
    /// For sync entry points only: Tauri `setup` and JNI calls.
    pub fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
    }

    // ── UI attachment ─────────────────────────────────────────────────────────────

    pub fn attach_ui(&self, app: tauri::AppHandle) {
        *self.ui.write().unwrap() = Some(app);
    }

    pub fn ui_handle(&self) -> Option<tauri::AppHandle> {
        self.ui.read().unwrap().clone()
    }

    /// Emit a UI event. No-op when headless (the UI restores state on attach).
    pub fn emit<S: serde::Serialize + Clone>(&self, event: &str, payload: S) {
        if let Some(app) = self.ui_handle() {
            let _ = app.emit(event, payload);
        }
    }

    /// Seed the session's data dir + persisted config/prefs. Idempotent — the first
    /// entry point (Tauri setup OR a headless JNI start) wins, later calls no-op.
    pub fn init_data_dir(&self, dir: std::path::PathBuf) {
        self.block_on(async {
            let mut s = self.session.lock().await;
            if !s.data_dir.as_os_str().is_empty() {
                return;
            }
            // Before the first diagnostic line, and idempotent. A headless wake never goes
            // through `run()`, which is where this used to be installed, so without it the
            // whole capsule-path diagnostic (E-9) writes to a stdout Android has closed.
            #[cfg(target_os = "android")]
            crate::redirect_stdio_to_logcat();
            // 0700: the directory holding the vault, history, and quick-unlock blobs
            // must not be listable by other local users either (SP-15).
            let _ = crate::privfile::create_dir_private(&dir);
            // Diagnostics get a file from here on. This is the first moment there is
            // anywhere to put one, and on Windows it is the only way the lines ever reach
            // a human: those builds have no console, so stderr goes nowhere no matter what
            // it is redirected to.
            crate::diag::init(&dir);
            s.data_dir = dir;
            // Upgrade path (SP-15): files an older build created 0644 keep that mode
            // until something rewrites them, and some — the call-control secret, the
            // screening index — are written once and then only read. Tighten what is
            // already on disk, once, at the first moment the paths are known.
            for path in [
                s.vault_path(),
                s.history_path(),
                s.prefs_path(),
                s.config_path(),
                s.call_key_path(),
                s.call_store_path(),
                s.call_screen_path(),
                s.quick_pin_path(),
                s.quick_auto_path(),
                s.quick_bio_path(),
            ] {
                if path.exists() {
                    crate::privfile::harden_existing(&path);
                }
            }
            if let Ok(b) = std::fs::read(s.prefs_path()) {
                if let Ok(p) = serde_json::from_slice(&b) {
                    s.prefs = p;
                }
            }
            if let Ok(b) = std::fs::read(s.config_path()) {
                if let Ok(cfg) = serde_json::from_slice::<crate::RelayConfig>(&b) {
                    s.client = Some(std::sync::Arc::new(
                        client_core::Client::with_access_token(
                            cfg.base_url.clone(),
                            cfg.ws_url.clone(),
                            cfg.pinned_kt_key.clone(),
                            cfg.access_token.clone(),
                        )
                        .with_proxy(s.prefs.socks_proxy.clone()),
                    ));
                    s.config = Some(cfg);
                }
            }
        });
    }

    // ── Focus / connection state ──────────────────────────────────────────────────

    pub fn set_focused(&self, focused: bool) {
        self.focused.store(focused, Relaxed);
        // Auto-lock is a SECURITY setting, and the webview's own idle timer freezes
        // when the app is backgrounded (docs/NOTIFICATIONS.md §7.3) — so the engine enforces the
        // backgrounded half: unfocused for `lock_after_secs` ⇒ lock. The UI timer
        // still covers idle-while-on-screen.
        let epoch = {
            let mut e = self.unfocus_epoch.lock().unwrap();
            *e += 1;
            *e
        };
        if focused {
            return; // bumping the epoch above cancelled any scheduled lock
        }
        let engine: &'static Engine = global();
        self.spawn(async move {
            let after = {
                let s = engine.session.lock().await;
                match (s.account.is_some(), s.prefs.lock_after_secs) {
                    (true, Some(secs)) if secs > 0 => secs,
                    _ => return,
                }
            };
            tokio::time::sleep(std::time::Duration::from_secs(after)).await;
            if *engine.unfocus_epoch.lock().unwrap() != epoch || engine.is_focused() {
                return; // focus came back (or flapped) — not idle-in-background
            }
            // A call in progress is not an idle app (`internal/CALL_PLAN.md` §8). Locking takes the
            // session keys out of memory and the call's with them, and a phone in a call is
            // *supposed* to have its screen off — which is exactly the state this timer
            // reads as idle. Wait it out and lock when the call ends; an explicit lock from
            // the user still hangs up, because that one was asked for.
            //
            // "In a call" is `call_slot_free`, not just a connected one: `do_lock` also
            // cancels a ring, an answer waiting on the caller's winner acknowledgement, and
            // a reconnect. A ring that lands inside the auto-lock window is exactly the
            // case this timer must not destroy, and it is the likeliest one — the phone is
            // unfocused because it is asleep, which is when calls arrive.
            while {
                let s = engine.session.lock().await;
                s.account.is_some() && !crate::call_slot_free(&s)
            } {
                tokio::time::sleep(std::time::Duration::from_secs(IN_CALL_LOCK_RECHECK_SECS)).await;
                if *engine.unfocus_epoch.lock().unwrap() != epoch || engine.is_focused() {
                    return;
                }
            }
            // `do_lock` owns the connection state now: only it knows whether the process
            // hold was kept for a wake transport (E-2). Overriding it here would put the
            // auto-lock back on the "locked means unreachable" path the manual lock just
            // came off.
            crate::do_lock(&engine.session).await;
            // Tell a (possibly frozen) UI; it re-checks app_status on resume anyway.
            engine.emit("locked", ());
        });
    }

    pub fn is_focused(&self) -> bool {
        self.focused.load(Relaxed)
    }

    /// Is the app window genuinely in front of the user right now? Drives notification and
    /// incoming-call-ring suppression — we go silent only when the user can actually SEE
    /// the app. Android: the cached activity-focus flag is authoritative (tao focus events
    /// stop arriving once the activity dies). Desktop: consult the LIVE window — focused
    /// AND visible AND not minimized — because the cached `focused` flag can go stale (some
    /// window managers, notably Windows, don't fire `Focused(false)` on minimize), which
    /// would otherwise silence every notification and every ring while the app sits
    /// minimized. Falls back to the cached flag when there is no window yet.
    pub fn on_screen(&self) -> bool {
        // MUST stay non-blocking and lock-free. This runs on the DELIVERY loop
        // (notification suppression, and the incoming-call ring while the session lock is
        // held). An earlier revision queried the live window instead — `is_focused()` and
        // friends dispatch a message to the UI event loop and block on its reply. When
        // that loop is not pumping promptly, which is exactly what a minimized window on
        // Windows produces, the delivery loop wedges: nothing gets drained, no delivery
        // receipts go out, no notification is ever posted, and the sender sits on one
        // tick. The cached flag is maintained from real window events on the main thread
        // (focus changes, close-to-tray, minimize) and is always cheap to read.
        self.focused.load(Relaxed)
    }

    /// Delivery-loop connection transitions (main mailbox only): Connected ↔
    /// Reconnecting. Lock/unlock/mode transitions set `Locked`/`Off` explicitly via
    /// [`set_conn_state`](Self::set_conn_state); a late loop event must not overwrite
    /// those, so this only moves between the two live states.
    pub fn conn(&self, main: bool, up: bool) {
        if !main {
            return;
        }
        self.emit("conn", up);
        let mut state = self.conn_state.lock().unwrap();
        if matches!(*state, ConnState::Connected | ConnState::Reconnecting) {
            let next = if up {
                ConnState::Connected
            } else {
                ConnState::Reconnecting
            };
            if *state != next {
                *state = next;
                notifier::set_service_status(next);
            }
        }
    }

    /// Explicit state transition (unlock → Reconnecting-until-connected, lock →
    /// Locked/Off, mode P → Off). Always wins over in-flight loop events.
    pub fn set_conn_state(&self, next: ConnState) {
        let mut state = self.conn_state.lock().unwrap();
        if *state != next {
            *state = next;
            notifier::set_service_status(next);
        }
    }

    pub fn conn_state(&self) -> ConnState {
        *self.conn_state.lock().unwrap()
    }

    /// Connectivity returned (ConnectivityManager callback): cut every reconnect
    /// backoff short so delivery loops retry immediately. Android-only caller
    /// (`jni_entry`); desktop relies on the watchdog alone.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn nudge_network(&self) {
        self.net_nudge.notify_waiters();
    }

    /// Wait out a backoff delay, returning early on a network-change nudge.
    pub async fn backoff_sleep(&self, delay: std::time::Duration) {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = self.net_nudge.notified() => {}
        }
    }

    // ── Message notifications ─────────────────────────────────────────────────────

    /// Should a notification for `chat_key` be suppressed? Mobile: only when the app
    /// is focused AND that exact chat is on screen. Desktop: whenever focused (the
    /// chat list already shows the unread).
    pub fn suppress_notif(&self, chat_key: &str) -> bool {
        if cfg!(target_os = "android") {
            let focused = self.focused.load(Relaxed);
            let same = self
                .open_chat
                .lock()
                .ok()
                .map(|g| g.as_deref() == Some(chat_key))
                .unwrap_or(false);
            focused && same
        } else {
            let _ = chat_key;
            // The chat list already shows the unread when the app is on screen.
            self.on_screen()
        }
    }

    /// Post (or refresh) a chat notification: dedup by msg id, append to the chat's
    /// line buffer, hand the buffer to the platform pipeline.
    pub fn notify_message(&self, plan: &crate::NotifPlan) {
        {
            let mut seen = self.seen_ids.lock().unwrap();
            if !plan.msg_id.is_empty() {
                if seen.1.contains(&plan.msg_id) {
                    return; // drain-vs-socket duplicate
                }
                seen.0.push_back(plan.msg_id.clone());
                seen.1.insert(plan.msg_id.clone());
                if seen.0.len() > SEEN_IDS_CAP {
                    if let Some(old) = seen.0.pop_front() {
                        seen.1.remove(&old);
                    }
                }
            }
        }
        let lines = {
            let mut buffers = self.notif_lines.lock().unwrap();
            let buf = buffers.entry(plan.chat_key.clone()).or_default();
            buf.push(NotifLine {
                title: plan.title.clone(),
                body: plan.body.clone(),
                when: crate::now_secs() * 1000,
            });
            if buf.len() > MAX_NOTIF_LINES {
                let drop = buf.len() - MAX_NOTIF_LINES;
                buf.drain(..drop);
            }
            buf.clone()
        };
        notifier::show_message(&plan.chat_key, &lines);
    }

    /// Append a line to a chat's shade notification and re-post it — the inline-reply
    /// confirmation path ("You: …" after a successful send, or an error entry). The
    /// repost is also what clears the RemoteInput spinner, so this must run on every
    /// reply outcome; a chat with no live buffer (already cleared) posts fresh.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn append_chat_line(&self, chat_key: &str, title: &str, body: &str) {
        let lines = {
            let mut buffers = self.notif_lines.lock().unwrap();
            let buf = buffers.entry(chat_key.to_string()).or_default();
            buf.push(NotifLine {
                title: title.to_string(),
                body: body.to_string(),
                when: crate::now_secs() * 1000,
            });
            if buf.len() > MAX_NOTIF_LINES {
                let drop = buf.len() - MAX_NOTIF_LINES;
                buf.drain(..drop);
            }
            buf.clone()
        };
        notifier::show_message(chat_key, &lines);
    }

    /// Drop a chat's shade notification (user opened the chat, or its content
    /// expired). Buffer cleared so a later message starts fresh.
    pub fn clear_chat_notif(&self, chat_key: &str) {
        let had = self.notif_lines.lock().unwrap().remove(chat_key).is_some();
        if had {
            notifier::cancel_chat(chat_key);
        }
    }

    /// The reaper removed expired messages from these chats: pull them out of the
    /// shade too, so expired content never outlives its timer there. (Cancel, not
    /// rebuild: the buffer may hold expired lines and erring toward removal is the
    /// only safe direction for disappearing messages.)
    pub fn on_reaped(&self, chats: &[String]) {
        for c in chats {
            self.clear_chat_notif(c);
        }
    }

    // ── Call ring ─────────────────────────────────────────────────────────────────

    /// Start the native ring for `ring_id` — the call's opaque presentation handle, never
    /// a media room id. `title` must already be privacy-leveled by the caller.
    ///
    /// The notification is *presentation*: Core-Telecom owns the call itself (see
    /// [`start_system_call`](Self::start_system_call)), which is why the two are separate
    /// calls — the system call exists even when the app is on screen and no notification
    /// is posted.
    pub fn show_ring(&self, ring_id: &str, title: &str, is_group: bool) {
        *self.ring.lock().unwrap() = Some(ring_id.to_string());
        notifier::show_call(ring_id, title, is_group);
    }

    /// The **locked-vault** ring: one content-free notification, posted under
    /// [`notifier::LOCKED_CALL_RING`] rather than a per-call handle, because a locked
    /// device may not say which call is ringing.
    ///
    /// It goes through the engine for one reason: [`cancel_ring`](Self::cancel_ring) only
    /// takes down the ring it believes is showing, so a ring posted behind the engine's
    /// back cannot be cancelled by it. That is exactly what left a locked phone ringing at
    /// a call already answered elsewhere — the terminal capsule arrived, was verified, and
    /// the cancel it triggered was refused by a guard that had never been told about the
    /// ring.
    pub fn show_locked_ring(&self) {
        *self.ring.lock().unwrap() = Some(notifier::LOCKED_CALL_RING.to_string());
        notifier::show_generic(notifier::Generic::LockedCall);
    }

    /// A call is happening that this device **cannot act on** (`internal/CALL_PLAN.md` §3.1, E-1).
    ///
    /// The locked path used to raise [`show_locked_ring`](Self::show_locked_ring) here as
    /// well, on the reasoning that the user must learn a call is happening. That part is
    /// right — it is L-11's decision and silence would be worse. What was wrong is the
    /// surface: an `INSISTENT|NO_DISMISS` ringtone with an Answer that resolves to
    /// `AnswerPlan::Nothing` and a Decline with no capsule to aim at. The tester's session
    /// ended with a phone ringing at a call it could not answer, decline, or silence, until
    /// the device rebooted itself.
    ///
    /// So this is deliberately not a ring, and deliberately not recorded in `self.ring`:
    /// there is no ring to cancel, `ring_active()` must stay false so the *next* call's
    /// in-app ringtone is not silenced by it, and the notification is dismissible by the
    /// user like any other.
    pub fn show_unactionable_call(&self) {
        notifier::show_generic(notifier::Generic::UnactionableCall);
    }

    /// The vault opened: the locked-state generics are superseded by real, leveled
    /// notifications. Clears the engine's ring bookkeeping with them, so a stale
    /// `LOCKED_CALL_RING` cannot keep [`ring_active`](Self::ring_active) true and silence
    /// the in-app ringtone of the next call.
    pub fn clear_generics(&self) {
        let mut ring = self.ring.lock().unwrap();
        if ring.as_deref() == Some(notifier::LOCKED_CALL_RING) {
            *ring = None;
        }
        drop(ring);
        notifier::clear_generics();
    }

    /// Hand the call to the platform: Core-Telecom becomes the authority for its
    /// lifecycle and audio route (`internal/CALL_PLAN.md` §7.3). Off Android this is a no-op and
    /// the shell keeps its own ring, unchanged.
    pub fn start_system_call(&self, ring_id: &str, title: &str, video: bool, incoming: bool) {
        // Tracked whether or not the platform took it: on a target with no Telecom the set
        // is what proves the shell balances its own bookkeeping, and on Android an
        // untracked handle is a handle nothing will ever disconnect.
        self.system_calls
            .lock()
            .unwrap()
            .insert(ring_id.to_string());
        let added = if incoming {
            crate::telecom::add_incoming(ring_id, title, video)
        } else {
            crate::telecom::add_outgoing(ring_id, title, video)
        };
        // Only hand the route over if Telecom actually took the call: a refusal must
        // leave the existing AudioManager routing in charge rather than nobody.
        #[cfg(target_os = "android")]
        if added {
            crate::android_media::set_telecom_owns_route(true);
        }
        let _ = added;
    }

    /// Media is flowing: the system call is now active (audio focus, route, in-call UI).
    pub fn system_call_active(&self, ring_id: &str) {
        crate::telecom::set_active(ring_id);
        // The answer's process hold has done its job — Telecom owns a live call now, which
        // is a stronger claim on the process than a ring service ever was. Without this the
        // *direct* answer path (unlocked device, no pending unlock, so `clear_unlock_prompt`
        // never runs) would sit on the hold and its "Answering…" notification for the full
        // backstop window while a call was already up (E-5).
        notifier::release_call_hold();
    }

    /// End the system call with an honest [`crate::telecom::cause`], separately from the
    /// notification — a call that never rang here still has to be taken down in Telecom.
    ///
    /// Every path that drops a call must reach this or [`cancel_ring`](Self::cancel_ring),
    /// or the platform keeps a call the shell has forgotten: the ongoing-call chip stays
    /// up, audio focus is never released, `MediaBridge` never gets its route back, and the
    /// next `addCall` meets an occupied slot. Idempotent — ending an unknown handle is a
    /// no-op, so a doubled call costs nothing.
    pub fn end_system_call(&self, ring_id: &str, cause: i32) {
        let remaining = {
            let mut calls = self.system_calls.lock().unwrap();
            if !calls.remove(ring_id) {
                return;
            }
            calls.len()
        };
        crate::telecom::disconnect(ring_id, cause);
        // Hand the route back only when the platform holds no call of ours at all.
        // Reconciliation ends orphaned handles while a live call is up, and giving
        // `MediaBridge` the route back mid-call is the fight §7.4 forbids, in the other
        // direction.
        #[cfg(target_os = "android")]
        if remaining == 0 {
            crate::android_media::set_telecom_owns_route(false);
        }
        let _ = remaining;
    }

    /// The presentation handles the shell believes the platform is holding. The shell's
    /// own bookkeeping, not Telecom's — [`crate::telecom::active_calls`] is the platform's
    /// answer, and reconciliation compares the two.
    pub fn system_calls(&self) -> Vec<String> {
        self.system_calls.lock().unwrap().iter().cloned().collect()
    }

    /// Answer: clear the ring *presentation* and tell Telecom this call was accepted —
    /// without disconnecting it, which is what [`cancel_ring`](Self::cancel_ring) does.
    /// The system call stays up and becomes active once media connects.
    ///
    /// The cancel is **unconditional**, and cancels the exact id the answering surface
    /// named rather than "the ring this process thinks is showing". After a locked wake
    /// Android freezes or kills the process: the notification survives, `self.ring` does
    /// not, and the ring carries `FLAG_INSISTENT` — so a guarded cancel left the system
    /// looping the ringtone for the whole ring window, straight through the unlock. The
    /// notification id may belong to a ring this process never posted; that is the case.
    pub fn accept_ring(&self, ring_id: &str, video: bool) {
        // `accept_call`, not `cancel_call`: an answer is not a missed call — so nothing is
        // posted in its place — and it is not the end of the ring's *process hold* either.
        // What follows an answer on a locked phone is a wait of up to
        // `UNLOCK_TO_ANSWER_SECS` with no socket, and the foreground service that carried
        // the ring is what carries the process through it (E-5).
        notifier::accept_call(ring_id);
        {
            let mut ring = self.ring.lock().unwrap();
            // The *bookkeeping* stays guarded: a stale handle must not wipe the record of a
            // ring that really is showing (A-12's cancel depends on that record).
            if ring.as_deref() == Some(ring_id) {
                *ring = None;
            }
        }
        crate::telecom::answer(ring_id, video);
    }

    /// Stop the native ring for `ring_id`. Empty `missed_title` = silent cancel
    /// (answered here / handled elsewhere); non-empty = also post a missed-call entry.
    /// Also releases the headset-button session — this runs even when no native
    /// notification was posted (in-app ring), because the button session exists for both.
    ///
    /// The cancel is **unconditional**, for exactly the reason
    /// [`accept_ring`](Self::accept_ring) is: the notification and this process do not
    /// share a lifetime. A push-woken ring is posted inside a `shortService` window that
    /// ends seconds later, and Android then freezes or kills the process — while the
    /// notification, its `FLAG_INSISTENT` ringtone, and its 45-second timeout all survive
    /// in `system_server`. Every remote terminal (answered elsewhere, declined elsewhere,
    /// the caller hanging up) therefore lands on a process whose `self.ring` is empty, and
    /// a guarded cancel there is a cancel that never happens: the phone rings out the full
    /// window at a call that ended seconds after it started. Restart reconciliation
    /// (`call/store.rs`) rang the same bell — its whole job is to cancel a ring left on
    /// screen by a process that died, and the guard refused every one of them by
    /// construction.
    ///
    /// Cancelling an id nothing is showing is free (`NotificationManager.cancel` on an
    /// unknown id is a no-op), so the cost of being wrong here is nothing, and the cost of
    /// being guarded was the flagship bug.
    pub fn cancel_ring(&self, ring_id: &str, missed_title: &str) {
        // The system call goes with the ring. A non-empty missed title is exactly the
        // "rang out / cancelled before answer" case; everything else is a local end.
        self.end_system_call(
            ring_id,
            if missed_title.is_empty() {
                crate::telecom::cause::LOCAL
            } else {
                crate::telecom::cause::MISSED
            },
        );
        notifier::cancel_call(ring_id, missed_title);
        // The *bookkeeping* stays guarded: a stale handle must not wipe the record of a
        // ring that really is showing, which is what `ring_active` reads to keep the
        // in-app ringtone and the native one from sounding at once.
        let mut ring = self.ring.lock().unwrap();
        if ring.as_deref() == Some(ring_id) {
            *ring = None;
        }
    }

    /// Whether a native ring notification is currently sounding (any call). The
    /// in-app ringtone checks this so the two never sound at once.
    pub fn ring_active(&self) -> bool {
        self.ring.lock().unwrap().is_some()
    }

    // ── Push token / drain bookkeeping ────────────────────────────────────────────

    pub fn set_push_token(&self, token: String) {
        *self.push_token.lock().unwrap() = Some(token);
    }

    pub fn push_token(&self) -> Option<String> {
        self.push_token.lock().unwrap().clone()
    }

    /// UnifiedPush endpoint lifecycle (Android; `None` elsewhere/when unset).
    pub fn set_up_endpoint(&self, endpoint: Option<String>) {
        *self.up_endpoint.lock().unwrap() = endpoint.filter(|e| !e.is_empty());
    }

    pub fn up_endpoint(&self) -> Option<String> {
        self.up_endpoint.lock().unwrap().clone()
    }

    /// Buffer notification-tap routing extras (cold start races the webview's event
    /// listeners; a live webview also gets the `navigate` event directly).
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn set_pending_intent(&self, v: serde_json::Value) {
        *self.pending_intent.lock().unwrap() = Some(v);
    }

    pub fn take_pending_intent(&self) -> Option<serde_json::Value> {
        self.pending_intent.lock().unwrap().take()
    }

    /// A drain loop started (push wake). Pairs with [`drain_done`](Self::drain_done).
    pub fn drain_started(&self) {
        *self.drains.lock().unwrap() += 1;
    }

    /// A drain loop finished; when the last one does, release the shortService.
    pub fn drain_done(&self) {
        let mut n = self.drains.lock().unwrap();
        *n = n.saturating_sub(1);
        if *n == 0 {
            notifier::drain_finished();
        }
    }

    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn drains_active(&self) -> bool {
        *self.drains.lock().unwrap() > 0
    }
}

// ── Reconnect backoff ─────────────────────────────────────────────────────────────

/// Exponential reconnect backoff: 1 → 2 → 4 → … → 60 s with ±30 % jitter (a relay
/// restart must not get a thundering herd), reset to immediate on success. The
/// network-change nudge cuts the *sleep* short (see [`Engine::backoff_sleep`]);
/// callers `reset()` after a successful subscribe.
pub struct Backoff {
    attempt: u32,
}

impl Backoff {
    pub fn new() -> Self {
        Backoff { attempt: 0 }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Next delay, advancing the attempt counter. Jitter is ±30 % from a cheap
    /// time-seeded xorshift — it spreads a thundering herd; it needs no crypto
    /// quality (this crate deliberately has no direct `rand` dependency).
    pub fn next_delay(&mut self) -> std::time::Duration {
        let base = 1u64 << self.attempt.min(6); // 1,2,4,…,60 (capped below)
        let base = base.min(60);
        self.attempt = self.attempt.saturating_add(1);
        let mut x = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 | 1)
            .unwrap_or(0x9e37_79b9);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        // Map into [0.7, 1.3]: 0.7 + (x % 601)/1000.
        let jitter_milli = 700 + (x % 601);
        std::time::Duration::from_millis(base * jitter_milli)
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Backoff;

    // The backoff must grow exponentially toward the 60 s cap, always inside the
    // ±30 % jitter envelope, and reset cleanly.
    #[test]
    fn backoff_grows_jitters_and_resets() {
        let mut b = Backoff::new();
        for expected_base in [1u64, 2, 4, 8, 16, 32, 60, 60, 60] {
            let d = b.next_delay().as_millis() as u64;
            let lo = expected_base * 700;
            let hi = expected_base * 1300;
            assert!(
                (lo..=hi).contains(&d),
                "delay {d}ms outside [{lo},{hi}] for base {expected_base}s"
            );
        }
        b.reset();
        let d = b.next_delay().as_millis() as u64;
        assert!(
            (700..=1300).contains(&d),
            "reset must return to ~1s, got {d}ms"
        );
    }
}
