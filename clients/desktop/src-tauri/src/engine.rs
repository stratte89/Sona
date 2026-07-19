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
    /// The call whose ring window holds the headset-button MediaSession (started for
    /// EVERY ring, native or in-app — a tap on the earbuds must answer either way).
    buttons: StdMutex<Option<String>>,
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
            .worker_threads(2)
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
        buttons: StdMutex::new(None),
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
            let _ = std::fs::create_dir_all(&dir);
            s.data_dir = dir;
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
            crate::do_lock(&engine.session).await;
            engine.set_conn_state(ConnState::Off);
            // Tell a (possibly frozen) UI; it re-checks app_status on resume anyway.
            engine.emit("locked", ());
        });
    }

    pub fn is_focused(&self) -> bool {
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
        let focused = self.focused.load(Relaxed);
        if cfg!(target_os = "android") {
            let same = self
                .open_chat
                .lock()
                .ok()
                .map(|g| g.as_deref() == Some(chat_key))
                .unwrap_or(false);
            focused && same
        } else {
            focused
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

    /// Start the native ring for `ring_id` (call_id, or group call_instance).
    /// `title` must already be privacy-leveled by the caller.
    pub fn show_ring(&self, ring_id: &str, title: &str, is_group: bool) {
        *self.ring.lock().unwrap() = Some(ring_id.to_string());
        notifier::show_call(ring_id, title, is_group);
    }

    /// Headset-button MediaSession for the ring window: a tap answers, stop/end
    /// declines. Started at every incoming offer (independent of whether the ring is
    /// native or in-app); stopped by [`cancel_ring`](Self::cancel_ring), which every
    /// ring-clearing path already calls.
    pub fn call_buttons_start(&self, ring_id: &str) {
        *self.buttons.lock().unwrap() = Some(ring_id.to_string());
        notifier::call_buttons_start(ring_id);
    }

    /// Stop the native ring for `ring_id` if it is the one showing. Empty
    /// `missed_title` = silent cancel (answered here / handled elsewhere); non-empty =
    /// also post a missed-call entry. Also releases the headset-button session — this
    /// runs even when no native notification was posted (in-app ring), because the
    /// button session exists for both.
    pub fn cancel_ring(&self, ring_id: &str, missed_title: &str) {
        {
            let mut buttons = self.buttons.lock().unwrap();
            if buttons.as_deref() == Some(ring_id) {
                *buttons = None;
                notifier::call_buttons_stop();
            }
        }
        let mut ring = self.ring.lock().unwrap();
        if ring.as_deref() == Some(ring_id) {
            *ring = None;
            notifier::cancel_call(ring_id, missed_title);
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
