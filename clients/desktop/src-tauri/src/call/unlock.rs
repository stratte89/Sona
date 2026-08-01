//! Answering a call this device may not act on yet, and the human check that releases it.
//!
//! Two different states can hold an answer back, and confusing them is what made
//! "Require app unlock to answer calls" inert in the default configuration:
//!
//! * the **vault** is locked, so there is no session to send a claim with (`internal/CALL_PLAN.md`
//!   §3.3) — opening it is itself the human check;
//! * the **device** is locked, so whoever is holding the phone is not known to be the
//!   owner. The vault is usually open in this state (`lock_after_secs` defaults to `None`),
//!   which is exactly why it cannot be what is asked about.
//!
//! Both arm the same [`PendingUnlock`], correlated to one exact call and bounded by
//! [`UNLOCK_TO_ANSWER_SECS`], and neither ever blocks the platform's answer callback (§8):
//! Telecom's answer is accepted immediately, the ringtone stops, and everything here runs
//! afterwards on the engine's runtime. Unlock is required to answer, never to decline
//! (§3.4) — nothing in this file is reachable from a decline path.

use crate::*;

pub(crate) enum AnswerPlan {
    Direct,
    Group,
    /// Wait for the vault — or for a human check — then answer this exact call. Carries the
    /// absolute deadline and the logical call, which is what identifies the attempt from
    /// here on — the id the platform named is a *presentation*, and the two are not always
    /// the same string.
    Unlock {
        deadline: u64,
        call_instance_id: String,
        /// The vault is not the thing being waited on: it is open (or opens itself), and
        /// the keyguard is what gated this answer, so a person has to be asked for.
        needs_presence: bool,
    },
    Nothing,
}

/// Decide what an answer for `ring` means right now, and record the pending-unlock state
/// under the same lock so two answers cannot both arm it.
///
/// `ring` is whatever the surface that answered names the call: a Telecom presentation
/// handle, or — on a locked phone — the id the generic ring notification was **posted
/// under**, which is one shared id for every pending ring, because a locked device may not
/// say which call is ringing. Matching only handles is what made Answer a dead button in
/// exactly the configuration Phase 5 exists for.
pub(crate) fn answer_plan(s: &mut Session, ring: &str) -> AnswerPlan {
    // The process that put the ring on screen may be gone; the store outlives it.
    load_locked_call_store(s);
    let direct = s
        .incoming
        .as_ref()
        .filter(|o| o.ring_handle == ring)
        .map(|o| {
            (
                o.call_instance_id.clone(),
                o.offer_id.clone(),
                false,
                o.ring_handle.clone(),
            )
        });
    let group = s
        .group_incoming
        .as_ref()
        .filter(|o| o.ring_handle == ring)
        .map(|o| {
            (
                o.call_instance.clone(),
                o.ring_id.clone(),
                true,
                o.ring_handle.clone(),
            )
        });
    // A capsule ring: the encrypted offer has not arrived (or cannot, while locked). It
    // still names the exact call, which is all the pending-unlock state needs. Matched by
    // the id it was presented under as well as by its own handle — the locked ring only
    // ever has the former.
    let capsule = s
        .call_store
        .rings
        .iter()
        .find(|r| r.ring_handle == ring || r.presented_as.as_deref() == Some(ring))
        .map(|r| {
            (
                r.call_instance_id.clone(),
                r.offer_id.clone(),
                r.group,
                r.ring_handle.clone(),
            )
        });
    let Some((call_instance_id, offer_id, is_group, ring_handle)) = direct.or(group).or(capsule)
    else {
        return AnswerPlan::Nothing;
    };
    // §3.3 in the state it is actually about. The setting's own promise is that "a call
    // answered from the lock screen would otherwise be a call answered by whoever is holding
    // the phone" — that is the **device** being locked, and the vault is a different state.
    // With `lock_after_secs` defaulting to `None` the vault stays open from the user's last
    // unlock, so a gate that read `account.is_some()` cost nothing at all in the default
    // configuration: keyguard, claim sent, microphone live, by whoever picked the phone up.
    //
    // Both answer surfaces that reach here are lock-screen-reachable (Telecom's own answer
    // action and the `CallStyle` notification's). The in-app button does not come through
    // `answer_plan` at all, so an answer taken inside the app is unaffected — which is the
    // point: the check costs something exactly where a human check is what is missing.
    let keyguard = s.prefs.require_unlock_to_answer && crate::notifier::device_locked();
    // Unlocked and allowed: answer now, exactly as the in-app button does.
    if s.account.is_some() && !keyguard {
        return if is_group {
            AnswerPlan::Group
        } else {
            AnswerPlan::Direct
        };
    }
    // Whether opening the vault can *be* the human check. It cannot when the vault is
    // already open, and it cannot when auto-unlock would open it with no one present — in
    // both cases the gate has to be explicit or `resume_pending_unlock` fires instantly and
    // the whole thing is decoration.
    let needs_presence = keyguard && (s.account.is_some() || s.prefs.auto_unlock);
    // Fresh, or nothing: a presence check performed two minutes ago for something else must
    // not answer this call by itself. Clearing costs an in-flight account ceremony its
    // step 2, which is the safe direction.
    if needs_presence {
        s.last_presence_ok = None;
    }
    let deadline = now_secs().saturating_add(UNLOCK_TO_ANSWER_SECS);
    let _ = s.calls().registry.transition(
        &call_instance_id,
        &offer_id,
        client_core::callstate::CallPhase::AnswerPendingUnlock,
        now_secs(),
    );
    s.pending_unlock = Some(PendingUnlock {
        call_instance_id: call_instance_id.clone(),
        // The ring's **own** handle, not the id it was presented under: once the encrypted
        // offer lands it adopts this handle, so everything after the unlock — the system
        // call, its teardown — names the same thing.
        ring_handle,
        group: is_group,
        needs_presence,
        wants_credential: false,
        expires_at: deadline,
    });
    save_call_store(s);
    AnswerPlan::Unlock {
        deadline,
        call_instance_id,
        needs_presence,
    }
}

/// Open the vault without a human, where the device is configured for it. Only reachable
/// with "Require app unlock to answer" off — the setting exists precisely to forbid this.
pub(crate) async fn silent_unlock(inner: &Arc<Mutex<Session>>) -> bool {
    let mut s = inner.lock().await;
    let Some(account) = attempt_auto_unlock(&mut s) else {
        return false;
    };
    finish_unlock(inner, &mut s, account).await.is_ok()
}

/// Bring the app forward so the user can unlock. The unlock surface itself is the app's
/// existing one (biometric, PIN, or password, whichever this device has) — no separate
/// credential path is introduced for calls.
pub(crate) fn open_unlock_surface() {
    #[cfg(target_os = "android")]
    notifier::open_app_for_unlock();
}

/// The whole attempt is bounded: a phone answered from a pocket and never unlocked must
/// not leave Telecom connecting forever. Timing out disconnects **only this device's**
/// system call — no decline goes on the wire, because a sibling may still answer (§3.3).
pub(crate) fn spawn_unlock_deadline(
    inner: Arc<Mutex<Session>>,
    call_instance_id: String,
    presented_as: String,
    deadline: u64,
) {
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            deadline.saturating_sub(now_secs()),
        ))
        .await;
        abandon_pending_unlock(&inner, &call_instance_id, &presented_as).await;
    });
}

/// Give up on an answer this device may not act on: drop the state, take the prompt and
/// the ring down, and end **only this device's** system call. Nothing goes on the wire —
/// the caller and our siblings are still free to resolve the call between them (§3.3).
///
/// Shared by the deadline and by a presence check the user cancelled, because those two
/// differ only in how long the phone waited first.
async fn abandon_pending_unlock(
    inner: &Arc<Mutex<Session>>,
    call_instance_id: &str,
    presented_as: &str,
) {
    let mut s = inner.lock().await;
    // Keyed by the logical call, not by a presentation id: the ring may have been
    // adopted by the encrypted offer meanwhile, which changes what it is shown as and
    // never changes which call it is.
    let Some(pending) = s
        .pending_unlock
        .take_if(|pending| pending.call_instance_id == call_instance_id)
    else {
        return;
    };
    drop(s);
    notifier::clear_unlock_prompt();
    eng().cancel_ring(presented_as, "");
    eng().cancel_ring(&pending.ring_handle, "");
}

/// Is this exact answer still waiting to be acted on? (Asked between the two awaits of the
/// OS prompt, which only Android has.)
#[cfg(target_os = "android")]
async fn still_pending(inner: &Arc<Mutex<Session>>, call_instance_id: &str) -> bool {
    inner
        .lock()
        .await
        .pending_unlock
        .as_ref()
        .is_some_and(|p| p.call_instance_id == call_instance_id && p.expires_at > now_secs())
}

/// Whether the OS vouched for a human recently enough to answer on it. The same window the
/// account ceremonies use — and `answer_plan` clears the stamp when it arms, so "recently"
/// can only mean "since the user pressed Answer".
fn presence_is_fresh(s: &Session) -> bool {
    matches!(s.last_presence_ok, Some(t) if t.elapsed().as_secs() < PRESENCE_WINDOW_SECS)
}

/// Ask the OS to vouch for whoever is holding the phone, then finish the answer.
///
/// Android-only, like the setting itself (§8): nothing off Android arms `needs_presence`.
/// Asynchronous by construction — the platform callback returned long before this runs, and
/// the same [`UNLOCK_TO_ANSWER_SECS`] deadline bounds the whole attempt.
#[cfg(target_os = "android")]
pub(crate) fn spawn_presence_prompt(
    inner: Arc<Mutex<Session>>,
    call_instance_id: String,
    presented_as: String,
    deadline: u64,
) {
    eng().spawn(async move {
        // `BiometricPrompt` needs an Activity and `open_unlock_surface` has only just asked
        // for one — over the keyguard, through A-11's full-screen intent, which takes a
        // moment. Waiting is bounded by the answer's own deadline, whose task owns the
        // teardown if it wins.
        while crate::android_media::activity_obj().is_none() {
            if now_secs() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        if !still_pending(&inner, &call_instance_id).await {
            return;
        }
        match crate::bio::presence_check_async().await {
            // The OS vouched. Stamped the way the account ceremonies stamp it, so one
            // definition of "a human is here" serves both.
            Ok(true) => {
                inner.lock().await.last_presence_ok = Some(std::time::Instant::now());
                resume_pending_unlock(&inner).await;
            }
            // Neither a strong biometric nor a device credential is enrolled, so the OS has
            // nothing to ask on our behalf. Fall back to Sona's own knowledge factor —
            // never to "allow".
            Ok(false) => request_app_credential(&inner, &call_instance_id).await,
            // Cancelled, or the hardware failed. End this device's attempt now rather than
            // leaving Telecom connecting and a prompt on the screen for the full window.
            Err(_) => abandon_pending_unlock(&inner, &call_instance_id, &presented_as).await,
        }
    });
}

#[cfg(not(target_os = "android"))]
pub(crate) fn spawn_presence_prompt(
    _inner: Arc<Mutex<Session>>,
    _call_instance_id: String,
    _presented_as: String,
    _deadline: u64,
) {
}

/// The OS cannot vouch for anyone on this device, so ask for Sona's own password or unlock
/// PIN instead ([`answer_with_app_credential`] verifies it).
///
/// Recorded on the pending state as well as emitted: the webview may not exist yet — the
/// app was brought forward a moment ago — and one that appears later reads the same fact
/// out of `call_status`, so a cold start cannot lose the request.
#[cfg(target_os = "android")]
async fn request_app_credential(inner: &Arc<Mutex<Session>>, call_instance_id: &str) {
    {
        let mut s = inner.lock().await;
        let Some(pending) = s
            .pending_unlock
            .as_mut()
            .filter(|p| p.call_instance_id == call_instance_id)
        else {
            return;
        };
        pending.wants_credential = true;
    }
    eng().emit("call", serde_json::json!({ "kind": "unlock_credential" }));
}

/// A ring for `call_instance_id` just landed: if this device is holding an answer for
/// exactly that call, finish it. Cheap and exact — no timers, no "answer whatever is
/// ringing" window.
pub(crate) fn resume_unlock_for(inner: &Arc<Mutex<Session>>, s: &Session, call_instance_id: &str) {
    if s.pending_unlock
        .as_ref()
        .is_some_and(|pending| pending.call_instance_id == call_instance_id)
    {
        let inner = inner.clone();
        eng().spawn(async move {
            resume_pending_unlock(&inner).await;
        });
    }
}

/// The vault opened (or an offer arrived) while an answer was pending: finish it, if it is
/// still the same call and still live. Returns whether an answer was actually sent.
pub(crate) async fn resume_pending_unlock(inner: &Arc<Mutex<Session>>) -> bool {
    let pending = {
        let mut s = inner.lock().await;
        if s.account.is_none() {
            return false;
        }
        let Some(pending) = s.pending_unlock.take_if(|p| p.expires_at > now_secs()) else {
            // Expired (or none): drop it rather than answering late.
            if s.pending_unlock.take().is_some() {
                notifier::clear_unlock_prompt();
            }
            return false;
        };
        // A terminal that landed while we waited wins: the call is over, and answering it
        // now would be answering a call nobody is on.
        if s.call_store
            .registry
            .terminal_reason(&pending.call_instance_id)
            .is_some()
        {
            notifier::clear_unlock_prompt();
            eng().end_system_call(&pending.ring_handle, telecom::cause::LOCAL);
            return false;
        }
        // A-19's whole substance. Everything else about this state is already ready — the
        // vault is open, the offer is here — which is exactly the trap: without an explicit
        // gate the answer completes the instant it is armed and the setting is decoration.
        // No claim, no microphone, until a human has been vouched for since the button was
        // pressed. The prompt stays up; the deadline still bounds the wait.
        if pending.needs_presence && !presence_is_fresh(&s) {
            s.pending_unlock = Some(pending);
            return false;
        }
        // The offer that carries the media capability may still be in flight; the ring
        // that arrives will call back here.
        let ready = if pending.group {
            s.group_incoming
                .as_ref()
                .is_some_and(|o| o.call_instance == pending.call_instance_id)
        } else {
            s.incoming
                .as_ref()
                .is_some_and(|o| o.call_instance_id == pending.call_instance_id)
        };
        if !ready {
            s.pending_unlock = Some(pending);
            return false;
        }
        // Taken up, one way or another: the prompt has done its job.
        notifier::clear_unlock_prompt();
        pending
    };
    let answered = if pending.group {
        group_call_accept_inner(inner).await
    } else {
        call_accept_inner(inner).await
    };
    if answered.is_err() {
        eng().end_system_call(&pending.ring_handle, telecom::cause::ERROR);
    }
    answered.is_ok()
}

/// The fallback human check for an answer taken over the keyguard (A-19), for a device
/// where the OS has neither a strong biometric nor a device credential enrolled and so
/// cannot vouch for anyone. Sona's own knowledge factor stands in — never a bare "allow".
///
/// Same verification as every quick-unlock enable: the vault password, or the unlock PIN
/// when one is set (whose failures count against the same attempt limit as the lock
/// screen). Refused unless an answer is actually waiting on a human check, so this is never
/// a way to stamp a presence pass for something else.
#[tauri::command]
pub async fn answer_with_app_credential(
    state: tauri::State<'_, AppState>,
    password: Option<String>,
    pin: Option<String>,
) -> Result<(), String> {
    {
        let mut s = state.inner.lock().await;
        let waiting = s
            .pending_unlock
            .as_ref()
            .is_some_and(|p| p.needs_presence && p.expires_at > now_secs());
        if !waiting {
            return Err("no call is waiting to be answered".into());
        }
        authorize_quick_enable(&mut s, password.as_deref(), pin.as_deref())?;
        s.last_presence_ok = Some(std::time::Instant::now());
    }
    resume_pending_unlock(&state.inner).await;
    Ok(())
}
