use crate::*;

/// (Re-)apply the push half of the current delivery mode. Modes `cp`/`p` register the
/// FCM endpoint for this device's mailbox (idempotent upsert; re-run on unlock and on
/// token rotation); mode `c` unregisters. Crash-safe ordering for mode transitions is
/// the caller's job (`set_delivery_mode`): register-before-stop / start-before-
/// unregister — never a gap with neither transport live.
pub(crate) async fn do_push_registration(inner: &Arc<Mutex<Session>>) {
    let mut s = inner.lock().await;
    let mode = s.prefs.delivery_mode.clone();
    let Some(client) = s.client.clone() else {
        return;
    };
    let (mailbox, unlocked) = {
        let Some(account) = s.account.as_ref() else {
            return; // registration is challenge-signed; retried on next unlock
        };
        let mailbox = if s.history.is_primary_device() {
            account.identity_hash().as_str().to_string()
        } else {
            match client.device_mailbox(account.account_id(), &s.history.self_device_id()) {
                Ok(h) => h,
                Err(_) => return,
            }
        };
        (mailbox, true)
    };
    let _ = unlocked;
    if mode == "c" {
        // Connection-only: drop any registered endpoint (start-before-unregister — the
        // FGS was already started by the caller).
        if s.prefs.push_endpoint.is_some() {
            let ok = {
                let account = s.account.as_ref().expect("checked above");
                client.unregister_push_as(account, &mailbox).await.is_ok()
            };
            if ok {
                s.prefs.push_endpoint = None;
                let _ = s.save_prefs();
            }
        }
        return;
    }
    // cp / p need a wake transport. UnifiedPush (user-chosen distributor, §6.7) wins
    // over the system FCM token whenever both exist — the user explicitly picked a
    // Google-free broker; FCM stays as the silent fallback on stock devices with no
    // distributor installed. With neither, kick an async token fetch (it lands via
    // `nativeSetPushToken`, which re-runs this function; a distributor endpoint lands
    // via `nativeSetUpEndpoint`, same effect) and drop any stale relay registration —
    // a wake POSTed at a dead endpoint is silent loss dressed up as coverage.
    let endpoint = match eng()
        .up_endpoint()
        .or_else(|| eng().push_token().map(|t| format!("fcm:{t}")))
    {
        Some(e) => e,
        None => {
            if s.prefs.push_endpoint.is_some() {
                let ok = {
                    let account = s.account.as_ref().expect("checked above");
                    client.unregister_push_as(account, &mailbox).await.is_ok()
                };
                if ok {
                    s.prefs.push_endpoint = None;
                    let _ = s.save_prefs();
                }
            }
            notifier::request_push_token();
            return;
        }
    };
    if s.prefs.push_endpoint.as_deref() == Some(endpoint.as_str()) {
        return; // already registered with this exact endpoint
    }
    let ok = {
        let account = s.account.as_ref().expect("checked above");
        client
            .register_push_as(account, &mailbox, &endpoint)
            .await
            .is_ok()
    };
    if ok {
        s.prefs.push_endpoint = Some(endpoint);
        let _ = s.save_prefs();
    }
}

pub(crate) fn spawn_push_registration(inner: &Arc<Mutex<Session>>) {
    let inner = inner.clone();
    eng().spawn(async move {
        do_push_registration(&inner).await;
    });
}

/// The wake transports this device and its relay actually have, as probed by
/// [`maybe_auto_delivery_mode`]. Kept separate from the probing so the policy itself is
/// pure and testable — it decides whether calls ring a sleeping phone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WakeTransports {
    /// Google Play services is installed AND Firebase initialized against it.
    pub(crate) play: bool,
    /// A UnifiedPush distributor has handed us a live endpoint (or one is selected and
    /// its endpoint is still landing).
    pub(crate) up_live: bool,
    /// The relay can send FCM wakes.
    pub(crate) relay_fcm: bool,
    /// The relay can POST webhook (UnifiedPush-shaped) wakes.
    pub(crate) relay_webhook: bool,
}

/// Can a content-free wake actually reach this device? Both halves are required: a
/// transport on the phone *and* a relay that can drive it. Anything less is a fallback
/// that exists only on paper — a wake POSTed nowhere is silent loss dressed up as
/// coverage.
pub(crate) fn push_fallback_usable(t: WakeTransports) -> bool {
    (t.play && t.relay_fcm) || (t.up_live && (t.relay_webhook || t.relay_fcm))
}

/// The delivery-mode DEFAULT for a user who never touched the setting (`internal/CALL_PLAN.md`
/// §9): **connection + push fallback** wherever a wake transport is usable, and the
/// **connection alone** everywhere else. Never `"p"` — push-only is an explicit choice,
/// because a phone whose only transport is a best-effort wake cannot be relied on to
/// ring, and the incoming-call reliability this project exists for is exactly what that
/// costs. The connection stays up in both targets, so a push token appearing never takes
/// a healthy connection down.
pub(crate) fn auto_delivery_target(t: WakeTransports) -> &'static str {
    if push_fallback_usable(t) {
        "cp"
    } else {
        "c"
    }
}

/// Resolve and apply [`auto_delivery_target`] for users who never picked a mode. Runs
/// after every unlock and whenever a push transport appears or disappears; an explicit
/// choice in settings (`delivery_mode_set`) turns this off forever.
pub(crate) async fn maybe_auto_delivery_mode(inner: &Arc<Mutex<Session>>) {
    let (user_set, mode, client, unlocked) = {
        let s = inner.lock().await;
        (
            s.prefs.delivery_mode_set,
            s.prefs.delivery_mode.clone(),
            s.client.clone(),
            s.account.is_some(),
        )
    };
    if user_set || !unlocked {
        return;
    }
    let Some(client) = client else { return };
    // Device-side transports (Android only — desktop has no push and keeps "c").
    let Some(h) =
        notifier::health_json().and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
    else {
        return;
    };
    let play = h["play_services"].as_bool().unwrap_or(false);
    let up_live = eng().up_endpoint().is_some()
        || !h["up_distributor"].as_str().unwrap_or_default().is_empty();
    let caps = client.server_capabilities().await.unwrap_or_default();
    let relay_fcm = caps.iter().any(|c| c == client_core::CAP_PUSH_FCM);
    let relay_webhook = caps.iter().any(|c| c == client_core::CAP_PUSH_WEBHOOK);
    // De-Googled phone, relay can wake, exactly ONE distributor installed and none
    // selected: adopt it — there is nothing to choose between, and without an endpoint
    // the push fallback can never become part of the default. The endpoint lands async
    // (`nativeSetUpEndpoint` → on_new_up_endpoint), which re-runs this function.
    // Anything else falls through: a phone with no distributor at all must still be
    // moved OFF a stale push-only default, or it is left with no transport at all.
    if !play && !up_live && relay_webhook {
        let dists = notifier::up_distributors()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
        if let Some([only]) = dists.as_ref().and_then(|d| d.as_array()).map(Vec::as_slice) {
            if let Some(pkg) = only["pkg"].as_str() {
                notifier::up_register(pkg);
                return;
            }
        }
    }
    let target = auto_delivery_target(WakeTransports {
        play,
        up_live,
        relay_fcm,
        relay_webhook,
    });
    if mode == target {
        return;
    }
    {
        let mut s = inner.lock().await;
        // Re-check under the lock — a settings tap may have raced the probes above.
        if s.prefs.delivery_mode_set || s.account.is_none() {
            return;
        }
        s.prefs.delivery_mode = target.into();
        let _ = s.save_prefs();
    }
    // Both auto targets keep the live connection — `cp` adds a fallback beside it, `c`
    // is the connection alone — so the FGS comes up first either way and the push
    // registration reconciles after (`cp` registers, `c` unregisters). A push token
    // appearing must never take a healthy connection down (`internal/CALL_PLAN.md` §9), and a
    // wake transport vanishing must leave the connection carrying everything.
    delivery_service::set_background_delivery(true);
    if !matches!(eng().conn_state(), notifier::ConnState::Connected) {
        eng().set_conn_state(notifier::ConnState::Reconnecting);
    }
    do_push_registration(inner).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E-1: a ring wake that produced no call state must not become a ring.
    ///
    /// This is the branch the second device matrix turned on. The locked drain finding
    /// nothing used to raise the same insistent generic ring as a drain that found a live
    /// capsule — but with nothing behind it, `answer_plan` returns `AnswerPlan::Nothing`
    /// and `decline_locked` has no capsule to aim at, so both buttons are dead and
    /// `FLAG_INSISTENT` keeps the ringtone looping regardless. The tester's phone rang at a
    /// call it could not answer, decline or silence until the device rebooted itself.
    ///
    /// `internal/CALL_PLAN.md` §3.1: the user must still learn a call is happening (L-11), and that
    /// is what `Unactionable` is for — it is simply not allowed to be a ring.
    #[test]
    fn a_ring_wake_with_no_call_state_is_not_a_ring() {
        let nothing_found = LockedWake::default();
        assert_eq!(
            locked_call_surface(&nothing_found, PushWakeClass::CallRing),
            LockedCallSurface::Unactionable,
            "a ring wake whose drain found nothing must degrade, never ring"
        );
        // The same empty drain on a *control* wake invents nothing at all: a terminal for a
        // call this device never rang for must not put a call on screen.
        assert_eq!(
            locked_call_surface(&nothing_found, PushWakeClass::CallControl),
            LockedCallSurface::Nothing
        );

        // A capsule that really does name a live ring still rings, on either wake class —
        // this fix must not cost the case the capsule layer exists for.
        let ringing = LockedWake {
            ringing: true,
            terminated: false,
        };
        for class in [PushWakeClass::CallRing, PushWakeClass::CallControl] {
            assert_eq!(
                locked_call_surface(&ringing, class),
                LockedCallSurface::Ring
            );
        }

        // A terminal takes the ring down, on either class.
        let terminated = LockedWake {
            ringing: false,
            terminated: true,
        };
        for class in [PushWakeClass::CallRing, PushWakeClass::CallControl] {
            assert_eq!(
                locked_call_surface(&terminated, class),
                LockedCallSurface::Terminal
            );
        }

        // Both at once is two different calls, and the live one is the one the user is
        // being called on right now.
        let both = LockedWake {
            ringing: true,
            terminated: true,
        };
        assert_eq!(
            locked_call_surface(&both, PushWakeClass::CallRing),
            LockedCallSurface::Ring,
            "a live ring outranks a terminal for some other call"
        );
    }

    /// The Phase-6 default itself: a usable wake transport buys a FALLBACK beside the
    /// connection, never a replacement for it.
    #[test]
    fn auto_default_is_connection_plus_push_never_push_only() {
        let stock = WakeTransports {
            play: true,
            relay_fcm: true,
            ..Default::default()
        };
        let degoogled = WakeTransports {
            up_live: true,
            relay_webhook: true,
            ..Default::default()
        };
        for t in [stock, degoogled] {
            assert!(push_fallback_usable(t));
            assert_eq!(auto_delivery_target(t), "cp");
        }
    }

    /// Half a transport is no transport: the connection has to carry everything, and
    /// the mode must say so rather than silently behaving as push-only.
    #[test]
    fn no_usable_wake_path_stays_on_the_connection() {
        let cases = [
            // Nothing at all (desktop-shaped, or a de-Googled phone with no distributor).
            WakeTransports::default(),
            // Play services present, relay cannot drive FCM.
            WakeTransports {
                play: true,
                relay_webhook: true,
                ..Default::default()
            },
            // Relay can wake, but nothing on the phone is listening.
            WakeTransports {
                relay_fcm: true,
                relay_webhook: true,
                ..Default::default()
            },
            // A distributor was chosen but the relay has no wake path at all.
            WakeTransports {
                up_live: true,
                ..Default::default()
            },
        ];
        for t in cases {
            assert!(!push_fallback_usable(t), "{t:?} must not count as usable");
            assert_eq!(auto_delivery_target(t), "c", "{t:?}");
        }
    }

    /// A de-Googled phone's distributor rides the relay's FCM path too when that is the
    /// only wake path the relay offers — the wake body is the same constant either way.
    #[test]
    fn unified_push_accepts_either_relay_wake_path() {
        assert!(push_fallback_usable(WakeTransports {
            up_live: true,
            relay_fcm: true,
            ..Default::default()
        }));
    }
}

/// Kotlin delivered a (possibly rotated) FCM registration token (`onNewToken`, or the
/// fetch kicked by [`do_push_registration`]). Store it and re-run registration.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn on_new_push_token(token: String) {
    eng().set_push_token(token);
    let inner = eng().session.clone();
    eng().spawn(async move {
        do_push_registration(&inner).await;
        maybe_auto_delivery_mode(&inner).await; // a wake transport just appeared
    });
}

/// The UnifiedPush distributor delivered (or revoked — empty string) an endpoint URL.
/// Reconcile the relay registration either way: a fresh URL registers (UnifiedPush
/// outranks FCM), a revoked one falls back to the token or unregisters.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn on_new_up_endpoint(endpoint: String) {
    eng().set_up_endpoint(Some(endpoint));
    let inner = eng().session.clone();
    eng().spawn(async move {
        do_push_registration(&inner).await;
        maybe_auto_delivery_mode(&inner).await; // a wake transport appeared (or was revoked)
    });
}

/// Headless persistent start (Android): the sticky-restart shell, the boot receiver,
/// or a wake in connection mode. Tries the silent auto-unlock; on success the full
/// delivery stack comes up exactly as after an interactive unlock. Without
/// auto-unlock the FGS text says so — the one thing it must never do is lie (§4.5).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) async fn headless_start(inner: &Arc<Mutex<Session>>) {
    let mut s = inner.lock().await;
    if s.account.is_some() {
        if s.stop.is_none() {
            // Unlocked but no loops (e.g. a drain finished earlier): start them.
            spawn_subscriber(inner, &mut s);
            spawn_push_registration(inner);
        }
        return;
    }
    match attempt_auto_unlock(&mut s) {
        Some(account) => {
            if finish_unlock(inner, &mut s, account).await.is_err() {
                eng().set_conn_state(notifier::ConnState::Locked);
            }
        }
        None => {
            // PIN/password-only (or before the first device unlock after boot):
            // headless decrypt is impossible BY DESIGN. Say so truthfully.
            eng().set_conn_state(notifier::ConnState::Locked);
        }
    }
}

/// What a **locked** call wake should put on screen once the capsule drain has run.
///
/// Extracted from `headless_wake` so the decision is testable on its own: it is the exact
/// point E-1 got wrong, and it depends only on what the drain found and which wake class
/// arrived — never on a session, a relay, or a device.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockedCallSurface {
    /// A capsule names a live ring for this device: the real, answerable generic ring.
    Ring,
    /// A terminal arrived: take down whatever is showing.
    Terminal,
    /// A call is happening and this device cannot act on it. Dismissible notice, never a
    /// ring (`internal/CALL_PLAN.md` §3.1).
    Unactionable,
    /// A silent control wake that resolved to nothing to show.
    Nothing,
}

/// Decide it. `wake.ringing` wins over `wake.terminated`: a drain that found both a live
/// ring and a terminal is a drain that found two different calls, and the live one is the
/// one the user is being called on right now.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn locked_call_surface(
    wake: &LockedWake,
    wake_class: PushWakeClass,
) -> LockedCallSurface {
    if wake.ringing {
        LockedCallSurface::Ring
    } else if wake.terminated {
        LockedCallSurface::Terminal
    } else if wake_class == PushWakeClass::CallRing {
        // A ring wake that produced no call state. Something is happening — the relay only
        // sends this class for a fresh offer — but nothing here can answer or decline it.
        LockedCallSurface::Unactionable
    } else {
        // A CallControl wake with nothing to apply: a terminal for a call this device never
        // rang for, or one already handled. Showing anything would be inventing a call.
        LockedCallSurface::Nothing
    }
}

/// Coarse, content-free push class passed across JNI.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PushWakeClass {
    Message,
    CallRing,
    CallControl,
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
impl PushWakeClass {
    pub(crate) fn from_jni(value: i32) -> Self {
        match value {
            1 => Self::CallRing,
            2 => Self::CallControl,
            _ => Self::Message,
        }
    }
}

/// Push-wake entry (Android, modes P/C+P): drain the mailbox in a short burst, or
/// degrade honestly when the vault can't be opened headless (§7.4).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) async fn headless_wake(inner: &Arc<Mutex<Session>>, wake_class: PushWakeClass) {
    let mut s = inner.lock().await;
    let call_wake = matches!(
        wake_class,
        PushWakeClass::CallRing | PushWakeClass::CallControl
    );
    // A call wake carries the capsule layer too — an incoming ring's second copy, or the
    // terminal that must stop a ring this device already posted. While the vault is open,
    // drain it alongside the main mailbox; the locked case is handled below, where what it
    // finds decides what goes on screen.
    if call_wake && s.account.is_some() {
        if let (Some(client), true) = (s.client.clone(), s.call_key.is_some()) {
            let inner = inner.clone();
            eng().spawn(async move {
                drain_call_capsules(&inner, &client).await;
            });
        }
    }
    // Live subscriber already draining this mailbox (C+P with a healthy socket — the
    // relay only wakes when it saw no subscriber, so this is a rare race): done.
    if s.account.is_some() && s.stop.is_some() {
        notifier::drain_finished();
        return;
    }
    if s.account.is_none() {
        match attempt_auto_unlock(&mut s) {
            Some(account) => {
                if s.prefs.delivery_mode == "p" {
                    // Drain lifetime: install the account only; loops below.
                    if install_unlocked_account(&mut s, account).await.is_err() {
                        notifier::drain_finished();
                        return;
                    }
                    // The capability probe ran inside install; multi-device forwards
                    // work in the drain exactly as on the socket.
                } else {
                    // Mode C/C+P: a wake means the persistent stack is down — bring
                    // the whole thing back up, then release the shortService.
                    let _ = finish_unlock(inner, &mut s, account).await;
                    notifier::drain_finished();
                    return;
                }
            }
            None => {
                // Locked, no auto-unlock: content-free generic per wake class — never
                // silent loss, never a decrypt (§7.4). A message wake can say no more
                // than that; a call wake, though, has the call-only subsystem: the
                // capsule layer opens with the call-control key alone, so this device can
                // tell a live ring from one that is already over.
                if wake_class == PushWakeClass::Message {
                    notifier::show_generic(notifier::Generic::MaybeMessages);
                    notifier::drain_finished();
                    return;
                }
                let client = s.client.clone();
                drop(s);
                let wake = match client {
                    Some(client) => drain_call_capsules_locked(inner, &client).await,
                    None => LockedWake::default(),
                };
                match locked_call_surface(&wake, wake_class) {
                    LockedCallSurface::Ring => {
                        // A capsule says a call really is ringing this device now. Posted
                        // through the engine, so the engine can take it down again — and
                        // recorded under the id it is actually posted under, not the ring
                        // handle, so a restart cancels a notification that exists.
                        eng().show_locked_ring();
                        mark_locked_rings_presented(inner).await;
                    }
                    LockedCallSurface::Terminal => {
                        // Answered elsewhere, declined, or cancelled: take the generic ring
                        // down instead of leaving the phone ringing at a call that is over.
                        // This is the locked half of the bug the whole project exists for.
                        eng().cancel_ring(notifier::LOCKED_CALL_RING, "");
                    }
                    LockedCallSurface::Unactionable => {
                        // Nothing to read: no call-control identity yet, no capsule that
                        // survived screening, a mailbox this device may not screen at all
                        // (E-13), the relay unreachable, or credential-encrypted storage
                        // still locked after a reboot (E-8).
                        //
                        // The user is still told — L-11 settled that, and silence is worse.
                        // But this is NOT a ring: with no call state behind it an Answer
                        // resolves to `AnswerPlan::Nothing` and a Decline has no capsule to
                        // aim at, which is exactly the dead, unsilenceable ring E-1 is
                        // about (`internal/CALL_PLAN.md` §3.1).
                        eng().show_unactionable_call();
                    }
                    LockedCallSurface::Nothing => {}
                }
                notifier::drain_finished();
                return;
            }
        }
    } else if s.prefs.delivery_mode != "p" {
        // Unlocked, loops dead, connection mode: full restart is the right shape.
        spawn_subscriber(inner, &mut s);
        spawn_push_registration(inner);
        notifier::drain_finished();
        return;
    }
    // ── Drain mode proper (mode P, unlocked): one bounded burst over the main
    // mailbox, plus a one-shot outbox drain. Same pipeline as the live socket —
    // decrypt, poison acks, notif decisions, ring — different lifetime. ──
    let Some(client) = s.client.clone() else {
        notifier::drain_finished();
        return;
    };
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    if let Some(old) = s.stop.replace(stop_tx) {
        let _ = old.send(true);
    }
    let main_hash = if s.history.is_primary_device() {
        None
    } else if let Some(account) = s.account.as_ref() {
        client
            .device_mailbox(account.account_id(), &s.history.self_device_id())
            .ok()
    } else {
        None
    };
    let loop_handle = spawn_delivery_loop(
        inner.clone(),
        client.clone(),
        stop_rx,
        main_hash,
        None,
        true,
    );
    {
        let inner = inner.clone();
        let client = client.clone();
        eng().spawn(async move {
            drain_outbox(&inner, &client).await;
        });
    }
    // Once the drain loop task ends, no receiver holds the watch channel any more —
    // clear the session's stop handle (unless a real unlock replaced it meanwhile,
    // whose channel has live receivers) so the next wake starts a fresh drain
    // instead of mistaking the dead handle for a live subscriber.
    let inner2 = inner.clone();
    drop(s);
    eng().spawn(async move {
        let _ = loop_handle.await;
        let mut s = inner2.lock().await;
        if s.stop.as_ref().is_some_and(|tx| tx.is_closed()) {
            s.stop = None;
        }
    });
}

/// A user-facing notification action arrived from the OS shade (Android). Validated
/// against live state in Rust — an unknown call id is a no-op, so a spoofed/stale
/// action can't decline someone else's ring.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) async fn notif_action(inner: &Arc<Mutex<Session>>, json: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return;
    };
    match v["action"].as_str() {
        // The shade's Answer. Same entry point as Core-Telecom's own answer callback, so
        // there is exactly one answer path: it decides whether this device may answer now
        // or must open the vault first.
        Some("answer_call") => {
            let ring = v["call_id"].as_str().unwrap_or_default().to_string();
            if !ring.is_empty() {
                answered(inner, &ring).await;
            }
        }
        Some("decline_call") => {
            let call_id = v["call_id"].as_str().unwrap_or_default();
            let mut s = inner.lock().await;
            // Locked: the ring the user is declining is the generic one, and the only
            // state describing it is the call-control store. Decline on the layer that
            // can — the scoped identity — instead of silently dismissing a notification
            // and leaving the caller (and our siblings) ringing (`internal/CALL_PLAN.md` §3.4).
            if s.account.is_none() {
                let client = s.client.clone();
                drop(s);
                if let Some(client) = client {
                    // The id the notification was posted under, so a decline ends the ring
                    // the user actually dismissed.
                    decline_locked(inner, &client, call_id).await;
                }
                return;
            }
            // 1:1 ring?
            if s.incoming
                .as_ref()
                .is_some_and(|o| o.ring_handle == call_id)
            {
                let offer = s.incoming.take().expect("checked");
                eng().cancel_ring(&offer.ring_handle, "");
                let Some(client) = s.client.clone() else {
                    return;
                };
                let _ = send_call_terminal_to_device(
                    &client,
                    &mut s,
                    &offer.peer_key,
                    &offer.caller_reply_to_mailbox,
                    &offer.call_instance_id,
                    &offer.offer_id,
                    client_core::callstate::CallTerminalReason::DeclinedHere,
                );
                ring_terminal_selfsync(
                    &client,
                    &mut s,
                    &offer.call_instance_id,
                    &offer.offer_id,
                    client_core::callstate::CallTerminalReason::DeclinedElsewhere,
                );
                log_call_event(&mut s, &offer.peer_key, "📞 Declined call");
                eng().emit("call", serde_json::json!({ "kind": "missed" }));
            } else if s
                .group_incoming
                .as_ref()
                .is_some_and(|o| o.ring_handle == call_id)
            {
                let offer = s.group_incoming.take().expect("checked");
                eng().cancel_ring(&offer.ring_handle, "");
                let Some(client) = s.client.clone() else {
                    return;
                };
                let actor_device_id = s.history.self_device_id();
                let expires_at =
                    now_secs().saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
                let envelopes = {
                    let sess = &mut *s;
                    let mut envelopes = Vec::new();
                    if let Some(account) = sess.account.as_mut() {
                        for (peer_key, (username, _, _)) in &offer.offers {
                            let contact = contact_for(username, peer_key);
                            if let Ok(envelope) = client.prepare_group_call_terminal_v2(
                                account,
                                &contact,
                                &offer.group_id,
                                &offer.call_instance,
                                &offer.ring_id,
                                client_core::callstate::CallTerminalReason::DeclinedHere,
                                &actor_device_id,
                                &offer.coordinator.username,
                                &offer.coordinator.identity_key,
                                &offer.coordinator.device_id,
                                expires_at,
                            ) {
                                envelopes.push(envelope);
                            }
                        }
                    }
                    envelopes
                };
                let _ = post_call_controls(&client, &mut s, &envelopes);
                ring_terminal_selfsync(
                    &client,
                    &mut s,
                    &offer.call_instance,
                    &offer.ring_id,
                    client_core::callstate::CallTerminalReason::DeclinedElsewhere,
                );
                log_group_call_event(&mut s, &offer.group_id, "📞 Declined group call");
                eng().emit("group_call", serde_json::json!({ "kind": "missed" }));
            }
        }
        // Mark-read / inline-reply exist only on REAL (decrypted) message
        // notifications — the locked-state generics never carry these actions,
        // because acting on an unknown message is meaningless. The vault can still
        // lock between posting and the tap, so both arms re-check and degrade
        // honestly instead of silently dropping the user's input.
        Some("mark_read") => {
            let chat = v["chat"].as_str().unwrap_or_default().to_string();
            if chat.is_empty() {
                return;
            }
            let mut s = inner.lock().await;
            if s.account.is_none() {
                return; // locked: can't mark anything; the notification stays honest
            }
            if s.history.group(&chat).is_some() {
                s.history.mark_group_seen(&chat);
                let _ = s.persist();
            } else {
                // 1:1: chat key is the peer identity key; the receipt path needs the
                // username too. An unknown key (contact since deleted) is a no-op.
                // Accepted contacts only: `username_for_peer` skips pending requests,
                // whose row is keyed by identity key and whose claimed name is
                // unverified (SP-02). A stranger gets no read receipt.
                let Some(username) = s.history.username_for_peer(&chat) else {
                    return;
                };
                drop(s);
                if mark_seen_inner(inner, username, chat.clone())
                    .await
                    .is_err()
                {
                    return; // receipt failed: leave the notification standing
                }
            }
            eng().clear_chat_notif(&chat);
            eng().emit("sync", ());
        }
        Some("reply") => {
            let chat = v["chat"].as_str().unwrap_or_default().to_string();
            let text = v["text"].as_str().unwrap_or_default().trim().to_string();
            if chat.is_empty() || text.is_empty() {
                return;
            }
            // Every outcome MUST repost the notification — that is what clears the
            // RemoteInput spinner in the shade.
            let target = {
                let s = inner.lock().await;
                if s.account.is_none() {
                    None // locked between post and tap
                } else if s.history.group(&chat).is_some() {
                    Some((None, true))
                } else {
                    // Accepted contacts only — a notification-reply must not be
                    // addressed to a pending stranger's claimed name (SP-02).
                    s.history.username_for_peer(&chat).map(|u| (Some(u), false))
                }
            };
            let outcome = match target {
                None => Err("Unlock Sona to send — reply not sent".to_string()),
                Some((_, true)) => send_group_inner(inner, chat.clone(), text.clone(), None)
                    .await
                    .map_err(|e| format!("Reply failed: {e}")),
                Some((Some(username), false)) => send_inner(inner, username, text.clone(), None)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("Reply failed: {e}")),
                Some((None, false)) => Err("Reply failed: unknown contact".to_string()),
            };
            match outcome {
                Ok(()) => {
                    eng().append_chat_line(&chat, "You", &text);
                    eng().emit("sync", ());
                }
                Err(msg) => eng().append_chat_line(&chat, "Sona", &msg),
            }
        }
        _ => {}
    }
}
