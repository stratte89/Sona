//! What the **system** does to a call, and what the shell does about it.
//!
//! Core-Telecom is the authority for the platform side of a call: it decides that the
//! user answered (from the lock screen, a watch, a headset button, the car), that the
//! call was disconnected, that a cellular call is taking the audio, and which endpoint the
//! audio is on (`internal/CALL_PLAN.md` §7.3). Those arrive here as events keyed by the call's
//! opaque presentation handle.
//!
//! The protocol still belongs to the shell: an answer from Telecom starts the ordinary
//! answer-claim path, and media begins only once the caller acknowledges this device as
//! the winner. Nothing here waits inside a platform callback — the Kotlin side reports and
//! returns, and this runs afterwards on the engine's runtime.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use crate::*;

/// The `android.telecom.DisconnectCause` an authenticated terminal outcome deserves.
///
/// The system call log is a user-visible record, so it gets the truth: a call answered on
/// the laptop is not one this phone rejected, and a caller who hung up is not a local
/// hangup. Every path that drops a call ends its system call with this.
pub(crate) fn disconnect_cause(reason: client_core::callstate::CallTerminalReason) -> i32 {
    use client_core::callstate::CallTerminalReason as R;
    match reason {
        R::AnsweredHere => telecom::cause::LOCAL,
        R::AnsweredElsewhere => telecom::cause::ANSWERED_ELSEWHERE,
        R::DeclinedHere => telecom::cause::REJECTED,
        R::DeclinedElsewhere => telecom::cause::ANSWERED_ELSEWHERE,
        R::CallerCancelled => telecom::cause::REMOTE,
        R::Expired => telecom::cause::MISSED,
        R::Busy => telecom::cause::BUSY,
        R::TransportError => telecom::cause::ERROR,
    }
}

/// One Core-Telecom event, as JSON from `TelecomBridge.kt`.
pub(crate) async fn handle_telecom_event(inner: &Arc<Mutex<Session>>, json: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return;
    };
    let ring = value["ring"].as_str().unwrap_or_default().to_string();
    if ring.is_empty() {
        return;
    }
    match value["event"].as_str().unwrap_or_default() {
        // The user answered on some surface Telecom owns.
        "answer" => answered(inner, &ring).await,
        // Telecom ended the call: the shade's Decline, a hang-up from a headset or watch,
        // or the platform taking the call away.
        "disconnect" => disconnected(inner, &ring).await,
        // Another call took the audio (a cellular call). Mute rather than tear down: the
        // call is still ours, and `active` brings it back.
        "inactive" => set_muted(inner, &ring, true).await,
        "active" => set_muted(inner, &ring, false).await,
        // Telecom decided the route. It is the authority; the in-call button mirrors it,
        // through the same `audio_route` event a headset plug/unplug already uses.
        "endpoint" => route_changed(value["route"].as_str().unwrap_or("unknown")),
        // A control failed. Only a *lifecycle* failure is terminal: a call the system
        // refused to add, or an answer it would not accept, is not a call, and pretending
        // otherwise leaves a ring nothing can end.
        //
        // A refused route request is not that. Telecom owns route selection (§7.4), so
        // "no" is a legitimate answer — a Bluetooth endpoint that disappeared between the
        // tap and the request, most often — and hanging the call up because the speaker
        // button did not take would be the wrong response to it. Report the route the
        // platform actually has instead.
        "error" => match value["op"].as_str().unwrap_or_default() {
            "add" | "answer" => disconnected(inner, &ring).await,
            "route" => route_changed("unknown"),
            _ => {}
        },
        _ => {}
    }
}

/// Telecom says this device answered. Route it through the ordinary accept path — the
/// same one the in-app button uses — so the answer claim, the winner acknowledgement, and
/// the media start are unchanged. Telecom stays in `CONNECTING` until
/// [`Engine::system_call_active`] says otherwise.
pub(crate) async fn answered(inner: &Arc<Mutex<Session>>, ring: &str) {
    // The platform's answer is accepted immediately — the ringtone stops and the call
    // shows as connecting — but *acting* on it may need the vault first (§3.3).
    let plan = {
        let mut s = inner.lock().await;
        answer_plan(&mut s, ring)
    };
    match plan {
        AnswerPlan::Direct => {
            if call_accept_inner(inner).await.is_err() {
                eng().end_system_call(ring, telecom::cause::ERROR);
            }
        }
        AnswerPlan::Group => {
            if group_call_accept_inner(inner).await.is_err() {
                eng().end_system_call(ring, telecom::cause::ERROR);
            }
        }
        AnswerPlan::Unlock {
            deadline,
            call_instance_id,
            needs_presence,
        } => {
            // The user pressed Answer: the ringtone stops now, whatever happens next. On a
            // locked phone that ring is one insistent notification, and leaving it sounding
            // through the unlock would be the phone ignoring the button.
            eng().accept_ring(ring, false);
            // No claim, no microphone, no media room until the vault opens. Siblings keep
            // ringing meanwhile — this device has not won anything yet.
            //
            // "Require app unlock to answer" is what decides whether a device that *can*
            // open itself silently is allowed to: with the setting on (the default), an
            // answer always costs a human unlock, even where auto-unlock is configured.
            let may_auto = {
                let s = inner.lock().await;
                !s.prefs.require_unlock_to_answer
            };
            if may_auto && silent_unlock(inner).await {
                resume_pending_unlock(inner).await;
                return;
            }
            open_unlock_surface();
            // The vault is open and cannot be the human check, so ask for one outright.
            // Asynchronous by construction: the platform callback has already returned.
            if needs_presence {
                spawn_presence_prompt(
                    inner.clone(),
                    call_instance_id.clone(),
                    ring.to_string(),
                    deadline,
                );
            }
            spawn_unlock_deadline(inner.clone(), call_instance_id, ring.to_string(), deadline);
        }
        AnswerPlan::Nothing => {
            // Nothing answers to that handle any more (it expired, or another device won).
            // Take the system call down rather than leaving it connecting forever.
            eng().end_system_call(ring, telecom::cause::LOCAL);
        }
    }
}

/// Telecom ended the call. Map it onto the same paths the UI buttons use: decline while
/// ringing, hang up when live.
async fn disconnected(inner: &Arc<Mutex<Session>>, ring: &str) {
    let (incoming, group_incoming, live, group_live, claiming, group_claiming) = {
        let s = inner.lock().await;
        (
            s.incoming.as_ref().is_some_and(|o| o.ring_handle == ring),
            s.group_incoming
                .as_ref()
                .is_some_and(|o| o.ring_handle == ring),
            s.call.as_ref().is_some_and(|c| c.ring_handle == ring),
            s.group_call.as_ref().is_some_and(|c| c.ring_handle == ring),
            s.claiming
                .as_ref()
                .is_some_and(|p| p.offer.ring_handle == ring),
            s.group_claiming
                .as_ref()
                .is_some_and(|p| p.offer.ring_handle == ring),
        )
    };
    if incoming {
        let _ = call_decline_inner(inner).await;
    } else if group_incoming {
        let _ = group_call_decline_inner(inner).await;
    // A call still waiting on the caller's winner acknowledgement is ended by the same
    // button as a live one — the hangup paths own that state now, so ending from the
    // system UI is not a dead end.
    } else if live || claiming {
        let _ = call_hangup_inner(inner).await;
    } else if group_live || group_claiming {
        let _ = group_call_hangup_inner(inner).await;
    }
}

/// A held call keeps its session but sends silence: the mic is muted while another call
/// owns the audio, and unmuted when Telecom hands it back. Deliberately not a teardown —
/// a cellular call ending must leave the Sona call where it was.
async fn set_muted(inner: &Arc<Mutex<Session>>, ring: &str, muted: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    let s = inner.lock().await;
    if let Some(call) = s.call.as_ref().filter(|c| c.ring_handle == ring) {
        call.toggles.muted.store(muted, Relaxed);
    } else if let Some(group) = s.group_call.as_ref().filter(|c| c.ring_handle == ring) {
        group.muted.store(muted, Relaxed);
    }
}

/// Republish the routing picture after Telecom moved the call. The Kotlin bridge already
/// knows the new endpoint, so the JSON it builds — headset presence, its name, the live
/// route — is the honest one; the UI never has to guess from the request it made.
fn route_changed(route: &str) {
    #[cfg(target_os = "android")]
    {
        if let Some(json) = android_media::audio_routes() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
                eng().emit("audio_route", value);
                return;
            }
        }
    }
    eng().emit(
        "audio_route",
        serde_json::json!({ "bt": route == "bluetooth", "bt_name": "", "route": route }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::callstate::CallTerminalReason as R;

    /// The invariant A-2 broke: a presentation handle must never outlive its call. The
    /// engine tracks what it handed the platform, so "the shell forgot to disconnect"
    /// stops being invisible — on Android an untracked handle is a system call nothing
    /// can ever end, holding audio focus and refusing the next `addCall`.
    #[test]
    fn a_system_call_never_outlives_the_call_that_created_it() {
        let ring = client_core::callstate::random_call_id();
        eng().start_system_call(&ring, "Peer", false, true);
        assert!(eng().system_calls().contains(&ring));

        // Answering does NOT end it — the call is still up, and this is exactly the
        // distinction that made the leak: `accept_ring` clears the notification only.
        eng().accept_ring(&ring, false);
        assert!(eng().system_calls().contains(&ring));

        eng().end_system_call(&ring, telecom::cause::LOCAL);
        assert!(!eng().system_calls().contains(&ring));
        // Idempotent: a doubled end (a terminal racing a local hangup) costs nothing.
        eng().end_system_call(&ring, telecom::cause::LOCAL);
        assert!(!eng().system_calls().contains(&ring));
    }

    /// `cancel_ring` is the other half of the same bookkeeping, so a ring that is simply
    /// declined or times out leaves nothing behind either.
    #[test]
    fn cancelling_a_ring_takes_its_system_call_with_it() {
        let ring = client_core::callstate::random_call_id();
        eng().start_system_call(&ring, "Peer", false, true);
        eng().cancel_ring(&ring, "Missed call");
        assert!(!eng().system_calls().contains(&ring));
    }

    /// The other half of A-18, and the one it missed: a ring must come **down** in a cold
    /// process too, not only be answerable in one.
    ///
    /// This is the flagship failure the user reported from three different directions —
    /// answered on the laptop, declined elsewhere, the caller hanging up — and one guard
    /// caused all three. A push-woken ring is posted inside a `shortService` window that
    /// ends seconds later; Android then freezes or kills the app while the notification,
    /// its `FLAG_INSISTENT` ringtone and its 45-second timeout live on in `system_server`.
    /// Every terminal therefore arrives at a process whose in-memory `ring` is empty, and
    /// `cancel_ring` used to cancel the notification only when that memory matched. So the
    /// phone rang out the whole window at a call that had already ended — and restart
    /// reconciliation, whose only job is to clear a ring left behind by a dead process,
    /// could never clear a single one.
    #[test]
    fn a_terminal_in_a_cold_process_still_stops_the_ringtone() {
        // An id this engine has never posted: exactly what a process that did not show the
        // ring knows about it, recovered from the sealed store or named by the capsule.
        // (The engine is a process-wide singleton shared by every test in this binary, so
        // the assertion is on this id alone — never on "is any ring showing".)
        let presented = client_core::callstate::random_call_id();

        eng().cancel_ring(&presented, "");

        assert!(
            notifier::cancelled::contains(&presented),
            "the notification looping the ringtone must be cancelled by id, whatever this \
             process remembers about it"
        );
    }

    /// A-3's user-visible half: a call waiting on the caller's winner acknowledgement must
    /// be endable. Before this, `call_hangup` returned `Ok(())` without touching
    /// `claiming`, so the call slot stayed reserved and the device could neither place nor
    /// receive another call until the vault locked.
    #[tokio::test]
    async fn hanging_up_while_claiming_frees_the_call_slot() {
        let ring = client_core::callstate::random_call_id();
        let inner: Arc<Mutex<Session>> = Arc::default();
        eng().start_system_call(&ring, "Peer", false, true);
        {
            let mut s = inner.lock().await;
            s.claiming = Some(PendingClaim {
                offer: PendingOffer {
                    call_instance_id: client_core::callstate::random_call_id(),
                    offer_id: client_core::callstate::random_call_id(),
                    ring_handle: ring.clone(),
                    call_id: "room".into(),
                    key_b64: String::new(),
                    username: "bob".into(),
                    peer_key: "bob-key".into(),
                    caller_device_id: "0".into(),
                    caller_reply_to_mailbox: "b".repeat(64),
                    expires_at: now_secs() + 60,
                    caps: Vec::new(),
                },
                claim_nonce: client_core::callstate::random_call_id(),
                answering_device_id: "0".into(),
            });
            assert!(!call_slot_free(&s));
        }
        // No client in this session, so the terminal cannot go out — the slot must still
        // be freed and the system call still taken down.
        let _ = call_hangup_inner(&inner).await;
        let s = inner.lock().await;
        assert!(s.claiming.is_none());
        assert!(call_slot_free(&s));
        assert!(!eng().system_calls().contains(&ring));
    }

    /// A-17: the same invariant on the paths a dropped mobile leg actually reaches.
    ///
    /// A **connected** call keeps its system call up across the silent resume on purpose, so
    /// the resume's give-up paths are the ones that owe the ending — and none of them did it.
    /// The consequence is A-2's exactly: audio focus never released, the route left with
    /// Telecom, and the next `addCall` meeting an occupied slot, so **the next call never
    /// rings**. Both states that can be holding the handle are pinned here, because they are
    /// removed in different places and the media pump covers neither.
    #[tokio::test]
    async fn giving_up_on_a_resume_takes_the_system_call_with_it() {
        let inner: Arc<Mutex<Session>> = Arc::default();

        // 1. Waiting for a resume that never arrives (relay unreachable, or the peer's
        //    re-offer never comes): the handle lives on `s.reconnect`.
        let ring = client_core::callstate::random_call_id();
        let old_call_id = "old-room".to_string();
        eng().start_system_call(&ring, "bob", false, false);
        {
            let mut s = inner.lock().await;
            s.reconnect = Some(PendingReconnect {
                call_instance_id: client_core::callstate::random_call_id(),
                offer_id: client_core::callstate::random_call_id(),
                ring_handle: ring.clone(),
                old_call_id: old_call_id.clone(),
                peer_username: "bob".into(),
                peer_key: String::new(), // no chip: this session has no history to write to
                peer_device_key: "bob-device".into(),
                peer_reply_to_mailbox: "b".repeat(64),
                caller: true,
                peer_media2: true,
                connected_at: now_secs() - 30,
            });
        }
        assert!(give_up_reconnect(
            &mut *inner.lock().await,
            &old_call_id,
            telecom::cause::REMOTE
        ));
        assert!(
            !eng().system_calls().contains(&ring),
            "a resume nobody came back for must not leave a call in Telecom"
        );
        assert!(inner.lock().await.reconnect.is_none());
        // A second give-up for the same leg is a no-op, not a double end: a peer terminal
        // racing the deadline reaches both.
        assert!(!give_up_reconnect(
            &mut *inner.lock().await,
            &old_call_id,
            telecom::cause::REMOTE
        ));

        // 2. The resumed session came up and never connected: the handle has moved to
        //    `s.call`, and the media pump cannot end it because this take is what removes it.
        let resumed = client_core::callstate::random_call_id();
        eng().start_system_call(&resumed, "bob", false, false);
        {
            let mut s = inner.lock().await;
            s.call = Some(a_call(&resumed, "new-room"));
        }
        assert!(give_up_resumed_call(&mut *inner.lock().await, "new-room"));
        assert!(
            !eng().system_calls().contains(&resumed),
            "a resumed session that never connected must not leave a call in Telecom"
        );
        assert!(inner.lock().await.call.is_none());
    }

    /// A live 1:1 call, as the give-up paths see it.
    fn a_call(ring_handle: &str, call_id: &str) -> CallCtl {
        use std::sync::atomic::{AtomicBool, AtomicU64};
        CallCtl {
            call_instance_id: client_core::callstate::random_call_id(),
            offer_id: client_core::callstate::random_call_id(),
            ring_handle: ring_handle.to_string(),
            call_id: call_id.to_string(),
            peer_username: "bob".into(),
            peer_key: String::new(), // no chip: this session has no history to write to
            peer_device_key: "bob-device".into(),
            peer_reply_to_mailbox: "b".repeat(64),
            caller: true,
            toggles: client_core::media::MediaToggles::default(),
            connected: Arc::new(AtomicBool::new(false)),
            connected_at: Arc::new(AtomicU64::new(0)),
            peer_media2: Arc::new(AtomicBool::new(true)),
            video_ready: Arc::new(AtomicBool::new(false)),
            peer_camera: Arc::new(AtomicBool::new(false)),
            peer_screen: Arc::new(AtomicBool::new(false)),
            transport: "ws",
            answer_arbiter: None,
            ring_fanout: 1,
            busy_devices: std::collections::HashSet::new(),
            stop: tokio::sync::watch::channel(false).0,
        }
    }

    /// A-13: Answer on a **locked** phone must actually hold the call for the unlock.
    ///
    /// The locked ring is one generic notification posted under `LOCKED_CALL_RING`, so
    /// that is the id its Answer action carries — a `presented_as`, never a ring handle.
    /// `answer_plan` matched handles only, found nothing, and returned `Nothing`: the
    /// prominent green button on the lock screen did nothing at all, with no error, in the
    /// default configuration. Answering must arm the pending unlock for the exact call,
    /// stop the ringtone, and keep the ring's own handle for what comes after it.
    #[tokio::test]
    async fn answering_the_generic_locked_ring_holds_the_exact_call_for_the_unlock() {
        use client_core::callstore::PendingRing;

        let inner: Arc<Mutex<Session>> = Arc::default();
        let call = client_core::callstate::random_call_id();
        let ring_handle = client_core::callstate::random_call_id();
        {
            let mut s = inner.lock().await;
            // What a locked wake leaves behind: a pending ring, and the id the one generic
            // notification actually went out under.
            s.call_store.device_id = "a".repeat(32);
            s.call_store.rings.push_back(PendingRing {
                call_instance_id: call.clone(),
                offer_id: client_core::callstate::random_call_id(),
                ring_handle: ring_handle.clone(),
                from: "bob".into(),
                display_name: "bob".into(),
                video: false,
                group: false,
                caller_device_id: "0".into(),
                reply_to_mailbox: "b".repeat(64),
                reply_call_mailbox: String::new(),
                reply_call_key: String::new(),
                created_at: now_secs(),
                ring_expires_at: now_secs() + client_core::callstate::CALL_RING_TIMEOUT_SECS,
                presented_as: Some(notifier::LOCKED_CALL_RING.to_string()),
            });
        }
        eng().show_locked_ring();

        answered(&inner, notifier::LOCKED_CALL_RING).await;

        let s = inner.lock().await;
        let pending = s
            .pending_unlock
            .as_ref()
            .expect("the answer must be held against the call that is ringing");
        assert_eq!(pending.call_instance_id, call);
        assert_eq!(
            pending.ring_handle, ring_handle,
            "the ring's own handle, so the encrypted offer's adoption names the same thing"
        );
        assert!(
            !eng().ring_active(),
            "pressing Answer stops the ringtone, whatever happens next"
        );
    }

    /// The test keyguard is a process-global device state, so the tests that set it run one
    /// at a time rather than racing each other's answer decisions.
    fn keyguard_serial() -> &'static Mutex<()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(Mutex::default)
    }

    /// An inbound 1:1 ring, as `answer_plan` sees it.
    fn ringing(ring: &str) -> PendingOffer {
        PendingOffer {
            call_instance_id: client_core::callstate::random_call_id(),
            offer_id: client_core::callstate::random_call_id(),
            ring_handle: ring.to_string(),
            call_id: "room".into(),
            key_b64: String::new(),
            username: "bob".into(),
            peer_key: "bob-key".into(),
            caller_device_id: "0".into(),
            caller_reply_to_mailbox: "b".repeat(64),
            expires_at: now_secs() + 60,
            caps: Vec::new(),
        }
    }

    fn an_account() -> Account {
        crypto_core::create_account_with_username("alice", "Alice-Password-123!")
            .unwrap()
            .0
    }

    /// A-19: "Require app unlock to answer calls" has to cost something when the **device**
    /// is locked, not when the vault happens to be.
    ///
    /// `answer_plan` decided on `s.account.is_some()` alone. `lock_after_secs` defaults to
    /// `None`, so on a default install the vault stays open from the user's last unlock —
    /// meaning the setting was inert in the *default* configuration, and a phone sitting at
    /// its keyguard would send the answer claim and open the microphone for whoever picked
    /// it up. The setting's own promise is about the lock screen; the vault is a different
    /// state.
    ///
    /// Both halves are pinned here, and the second is the one that matters: the fix's
    /// obvious form answers *instantly* and looks like it works, because with the vault open
    /// every readiness test `resume_pending_unlock` makes is already satisfied the moment the
    /// state is armed.
    #[tokio::test]
    async fn an_answer_over_the_keyguard_costs_a_human_check_even_with_the_vault_open() {
        let _serial = keyguard_serial().lock().await;
        let inner: Arc<Mutex<Session>> = Arc::default();
        let ring = client_core::callstate::random_call_id();
        let call = {
            let mut s = inner.lock().await;
            s.account = Some(an_account());
            s.prefs.require_unlock_to_answer = true;
            let offer = ringing(&ring);
            let call = offer.call_instance_id.clone();
            s.incoming = Some(offer);
            call
        };

        // No keyguard: the ordinary answer must be exactly as it was. (Same guard for the
        // in-app button, which never reaches `answer_plan` at all.)
        notifier::keyguard::set(false);
        assert!(
            matches!(
                answer_plan(&mut *inner.lock().await, &ring),
                AnswerPlan::Direct
            ),
            "an unlocked phone answers straight away — this setting must not tax that"
        );

        // Keyguard up, vault open: the answer is held, and nothing is claimed.
        notifier::keyguard::set(true);
        let plan = answer_plan(&mut *inner.lock().await, &ring);
        assert!(
            matches!(
                plan,
                AnswerPlan::Unlock {
                    needs_presence: true,
                    ..
                }
            ),
            "the keyguard is the state the setting names, whatever the vault is doing"
        );
        {
            let s = inner.lock().await;
            assert!(
                s.claiming.is_none(),
                "no claim before a human is vouched for"
            );
            assert!(s.last_presence_ok.is_none(), "a stale pass must not count");
            assert_eq!(
                s.pending_unlock
                    .as_ref()
                    .map(|p| p.call_instance_id.clone()),
                Some(call.clone())
            );
        }

        // The silent no-op: the vault is open and the offer is here, so every *other*
        // condition to answer is met. Without the explicit gate this resumes immediately.
        assert!(
            !resume_pending_unlock(&inner).await,
            "an answer must not complete on readiness alone"
        );
        assert!(
            inner.lock().await.pending_unlock.is_some(),
            "the answer is still being held, not dropped — the prompt is still up"
        );

        // A human checked, since the button was pressed: the gate releases. (The accept
        // itself then fails for want of a client; what is asserted is that the presence gate
        // is no longer what holds it.)
        inner.lock().await.last_presence_ok = Some(std::time::Instant::now());
        let _ = resume_pending_unlock(&inner).await;
        assert!(
            inner.lock().await.pending_unlock.is_none(),
            "a fresh presence pass releases the answer"
        );
        notifier::keyguard::set(false);
    }

    /// §3.4, which A-19 must not touch: unlock is required to **answer**, never to refuse.
    /// A phone the user cannot prove themselves on must still be able to decline — the
    /// caller (and this account's other devices) have to hear it.
    #[tokio::test]
    async fn declining_over_the_keyguard_is_never_gated() {
        let _serial = keyguard_serial().lock().await;
        notifier::keyguard::set(true);
        let inner: Arc<Mutex<Session>> = Arc::default();
        let ring = client_core::callstate::random_call_id();
        {
            let mut s = inner.lock().await;
            s.account = Some(an_account());
            s.prefs.require_unlock_to_answer = true;
            s.incoming = Some(ringing(&ring));
        }
        eng().start_system_call(&ring, "bob", false, true);

        // Telecom's Decline, from the lock screen, with the gate at its strictest.
        disconnected(&inner, &ring).await;

        let s = inner.lock().await;
        assert!(s.incoming.is_none(), "the ring is refused, not held");
        assert!(
            s.pending_unlock.is_none(),
            "a decline never waits for anyone"
        );
        assert!(!eng().system_calls().contains(&ring));
        drop(s);
        notifier::keyguard::set(false);
    }

    /// A-18: Answer must take the ring notification down even when the process that
    /// posted it is gone.
    ///
    /// A locked wake posts an insistent ring and Android then freezes or kills the
    /// process. Pressing Answer starts a fresh one: A-13 taught it to find the call in the
    /// sealed store, but `accept_ring` cancelled the notification only when its *in-memory*
    /// `ring` matched — and that memory died with the process. So the system looped the
    /// channel ringtone for the whole 45-second window, straight through the unlock, on the
    /// exact path Phase 5 exists for.
    #[tokio::test]
    async fn answering_in_a_cold_process_still_stops_the_ringtone() {
        use client_core::callstore::PendingRing;

        let inner: Arc<Mutex<Session>> = Arc::default();
        let call = client_core::callstate::random_call_id();
        // A cold process, by construction: the store carries the id the notification went
        // out under, and it is one this engine has never heard of — which is exactly what a
        // process that did not post the ring knows about it.
        let presented = client_core::callstate::random_call_id();
        {
            let mut s = inner.lock().await;
            s.call_store.device_id = "a".repeat(32);
            s.call_store.rings.push_back(PendingRing {
                call_instance_id: call.clone(),
                offer_id: client_core::callstate::random_call_id(),
                ring_handle: client_core::callstate::random_call_id(),
                from: "bob".into(),
                display_name: "bob".into(),
                video: false,
                group: false,
                caller_device_id: "0".into(),
                reply_to_mailbox: "b".repeat(64),
                reply_call_mailbox: String::new(),
                reply_call_key: String::new(),
                created_at: now_secs(),
                ring_expires_at: now_secs() + client_core::callstate::CALL_RING_TIMEOUT_SECS,
                presented_as: Some(presented.clone()),
            });
        }
        assert!(!eng().system_calls().contains(&presented));

        answered(&inner, &presented).await;

        assert!(
            notifier::cancelled::contains(&presented),
            "the notification that is looping the ringtone must be cancelled by id, \
             whatever this process remembers about it"
        );
    }

    /// A refused **route** request must not end the call (A-6). Telecom owns route
    /// selection, so "no" is a legitimate answer to the speaker button — most often a
    /// Bluetooth endpoint that vanished between the tap and the request — and the call is
    /// unaffected. Only a lifecycle failure (`add`, `answer`) is terminal.
    #[tokio::test]
    async fn a_refused_route_request_does_not_end_the_call() {
        let ring = client_core::callstate::random_call_id();
        let inner: Arc<Mutex<Session>> = Arc::default();
        eng().start_system_call(&ring, "Peer", false, true);
        {
            let mut s = inner.lock().await;
            s.incoming = Some(PendingOffer {
                call_instance_id: client_core::callstate::random_call_id(),
                offer_id: client_core::callstate::random_call_id(),
                ring_handle: ring.clone(),
                call_id: "room".into(),
                key_b64: String::new(),
                username: "bob".into(),
                peer_key: "bob-key".into(),
                caller_device_id: "0".into(),
                caller_reply_to_mailbox: "b".repeat(64),
                expires_at: now_secs() + 60,
                caps: Vec::new(),
            });
        }
        let error = |op: &str| {
            serde_json::json!({ "ring": ring, "event": "error", "op": op, "reason": "X" })
                .to_string()
        };
        handle_telecom_event(&inner, &error("route")).await;
        assert!(
            inner.lock().await.incoming.is_some(),
            "a route Telecom would not take is not a call that failed"
        );
        // An `add` failure is: the system never accepted the call, so there is nothing to
        // keep ringing for.
        handle_telecom_event(&inner, &error("add")).await;
        assert!(inner.lock().await.incoming.is_none());
    }

    /// The platform's call log is user-visible: a call answered on the laptop is not one
    /// this phone rejected, and a caller who hung up is not a local hangup.
    #[test]
    fn every_terminal_reason_maps_to_an_honest_disconnect_cause() {
        assert_eq!(
            disconnect_cause(R::AnsweredElsewhere),
            telecom::cause::ANSWERED_ELSEWHERE
        );
        assert_eq!(
            disconnect_cause(R::DeclinedElsewhere),
            telecom::cause::ANSWERED_ELSEWHERE
        );
        assert_eq!(disconnect_cause(R::DeclinedHere), telecom::cause::REJECTED);
        assert_eq!(disconnect_cause(R::CallerCancelled), telecom::cause::REMOTE);
        assert_eq!(disconnect_cause(R::Expired), telecom::cause::MISSED);
        assert_eq!(disconnect_cause(R::Busy), telecom::cause::BUSY);
        assert_eq!(disconnect_cause(R::TransportError), telecom::cause::ERROR);
        assert_eq!(disconnect_cause(R::AnsweredHere), telecom::cause::LOCAL);
    }
}
