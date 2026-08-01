//! Off-lock call routing: everything a call needs from the network *before* the
//! session mutex is taken.
//!
//! Call signaling is prepared while `Session` is held — sealing advances ratchets, and
//! the registry/pending state must move with it. So the network half is done here first:
//! the peer's KT-verified device roster is refreshed and every missing device session is
//! opened, with the lock released across each request. Preparation then runs against the
//! pinned roster and established sessions alone (see
//! `Client::extra_signal_envelopes`), and never waits on the relay.

use crate::*;

/// Is `client` still the session's live client? A relogin/unlock replaces it, and work
/// started under the previous account must not write into the new one.
pub(crate) fn is_current(s: &Session, client: &Arc<Client>) -> bool {
    s.client
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, client))
}

/// Refresh one account's verified device roster and open any missing device session,
/// without ever holding `Session` across a network wait.
///
/// Best effort by design: an offline relay, a rolled-back roster, or an unreachable
/// bundle leaves the existing pin and sessions in place, and the call still fans out over
/// what is already pinned and established. It never widens delivery to an unverified key
/// — `fetch_account_devices` verifies the KT binding, STH and inclusion proof, and
/// `install_device_sessions` refuses a bundle whose identity key is not the roster's.
pub(crate) async fn warm_call_routes(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    username: &str,
) {
    warm_device_routes(inner, client, username).await;
    // Same shape for the second delivery layer: each device's published call-control key,
    // fetched off-lock so a capsule can be sealed inside the lock without a round trip.
    //
    // Outside the multi-device gate above, deliberately (A-26). Nothing about the capsule
    // layer is multi-device — it is about a *locked* callee — and this was the only caller,
    // so against a relay that does not advertise the capability `s.call_bindings` was never
    // populated, `capsule_targets` was always empty, and no capsule was ever sent: a locked
    // phone fell back to the unverified generic ring and never got the terminal that stops
    // it. Trust is unchanged: `warm_call_bindings` still returns early without a pinned
    // KT-verified roster, and every binding is still re-checked against the live pin.
    warm_call_bindings(inner, client, username).await;
}

/// The multi-device half: the peer's KT-verified device roster and the sessions to reach
/// each of its devices. Genuinely multi-device work, so it keeps the gate.
async fn warm_device_routes(inner: &Arc<Mutex<Session>>, client: &Arc<Client>, username: &str) {
    {
        let s = inner.lock().await;
        if !s.multi_device || s.account.is_none() {
            return;
        }
        if !is_current(&s, client) {
            return;
        }
    }
    let Ok((resolved, update)) = client.fetch_account_devices(username).await else {
        return;
    };
    let missing = {
        let mut s = inner.lock().await;
        if !is_current(&s, client) {
            return;
        }
        if s.history.apply_roster_update(username, &update).is_err() {
            return; // rollback attempt: keep the pin we already trust, fan out over it
        }
        let Some(account) = s.account.as_ref() else {
            return;
        };
        let mine = account.account_id() == username;
        let missing = client.missing_device_sessions(account, username, &resolved);
        if mine {
            s.history.set_self_primary_key(&resolved.primary_key);
        }
        let _ = s.persist();
        // A freshly verified roster changes which of that caller's devices may ring this
        // one while locked.
        refresh_call_screen(&mut s);
        missing
    };
    if !missing.is_empty() {
        let fetched = client.fetch_device_bundles(&missing).await;
        if !fetched.is_empty() {
            let mut s = inner.lock().await;
            if !is_current(&s, client) {
                return;
            }
            if let Some(account) = s.account.as_mut() {
                if client.install_device_sessions(account, &fetched) > 0 {
                    let _ = s.persist();
                }
            }
        }
    }
}

/// Warm the peer's routes and our own siblings' at once — the two fan-outs a call needs
/// (rings to the callee's devices, terminal self-sync to ours).
pub(crate) async fn warm_call_routes_with_self(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    username: &str,
) {
    let me = {
        let s = inner.lock().await;
        s.account.as_ref().map(|a| a.account_id().to_string())
    };
    match me {
        Some(me) if me != username => {
            // Sequential, not concurrent: both halves take the same lock between their
            // requests, and the account is borrowed mutably to install sessions.
            warm_call_routes(inner, client, username).await;
            warm_call_routes(inner, client, &me).await;
        }
        _ => warm_call_routes(inner, client, username).await,
    }
}

/// [`resolve_send_contact`] for the call paths: same KT rules, but the discovery round
/// trip happens with the session lock released.
///
/// The fast path (pinned key + live session, which is what
/// [`warm_call_routes`] leaves behind) never touches the network at all.
pub(crate) async fn resolve_call_contact(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    username: &str,
) -> Result<Contact, String> {
    let (known, my_key) = {
        let mut s = inner.lock().await;
        if s.history.revoked() {
            return Err("this device was unlinked from the account — relink to continue".into());
        }
        let known = s.history.pinned_contact_key(username).map(str::to_string);
        let account = s.account.as_mut().ok_or("locked")?;
        ensure_not_self(account, username, known.as_deref())?;
        let my_key = account.ratchet_ref().identity_key();
        if let Some(key) = known.as_deref() {
            if account.ratchet_ref().has_session(key) {
                return Ok(contact_for(username, key));
            }
        }
        (known, my_key)
    };
    // No session yet: KT discovery off-lock, then establish under the lock. A key change
    // routes to the verify flow exactly as a send would.
    let discovered = client
        .discover_as(&my_key, username)
        .await
        .map_err(|e| e.to_string())?;
    if known.is_some_and(|key| key != discovered.identity_key) {
        return Err("KEY_CHANGED".into());
    }
    if discovered.identity_key == my_key {
        return Err("that's your own account — you can't message yourself".into());
    }
    let mut s = inner.lock().await;
    if !is_current(&s, client) {
        return Err("not configured".into());
    }
    let account = s.account.as_mut().ok_or("locked")?;
    let contact = client
        .start_session(account, &discovered)
        .map_err(|e| e.to_string())?;
    s.persist()?;
    Ok(contact)
}

/// The session is free for a new call: nothing live, ringing, claiming, reconnecting, or
/// being set up right now.
pub(crate) fn call_slot_free(s: &Session) -> bool {
    s.call.is_none()
        && s.incoming.is_none()
        && s.claiming.is_none()
        && s.reconnect.is_none()
        && s.group_call.is_none()
        && s.group_incoming.is_none()
        && s.group_claiming.is_none()
        && !s.call_setup
}

/// Hold the one call slot across the lock-free phases of starting a call, so a second
/// start (or an inbound offer) sees the account as busy instead of racing into it.
pub(crate) struct CallSlot {
    inner: Arc<Mutex<Session>>,
}

impl CallSlot {
    /// Reserve the slot, or report why the account is busy.
    pub(crate) async fn reserve(inner: &Arc<Mutex<Session>>) -> Result<Self, String> {
        let mut s = inner.lock().await;
        if !call_slot_free(&s) {
            return Err("already in a call".into());
        }
        s.call_setup = true;
        Ok(CallSlot {
            inner: inner.clone(),
        })
    }

    /// Release the reservation. Every exit path of a start must reach this — an
    /// async `Drop` cannot take the lock, so it is explicit.
    pub(crate) async fn release(self) {
        let mut s = self.inner.lock().await;
        s.call_setup = false;
        // The claim buffer lives exactly as long as the setup does (E-6). A claim that could
        // not be applied — the start failed, the call ended while the room was coming up —
        // must not survive into the next call, where its ids would match nothing anyway.
        // On the success path `replay_buffered_claims` has already taken it — so anything
        // still here is a claim that will never be answered, and the callee behind it is
        // sitting on "establishing secure connection…" waiting for a winner nobody will
        // send. Worth a line: it names the callee's symptom from the only side that can see
        // the cause.
        if let Some(dropped) = s
            .outgoing_setup
            .take()
            .filter(|setup| !setup.claims.is_empty())
        {
            crate::diag!(
                "[call] call setup released holding {} unanswered claim(s) — the device(s) \
                 that answered will wait out their signal TTL",
                dropped.claims.len()
            );
        }
    }
}

/// Verify the client and session are still usable, and that a terminal control did not
/// land on this call while the lock was released.
///
/// Every exit here is reported. This is the **only** silent way out of `call_start_inner`
/// after the offers have gone out, and it cost a whole test round: the caller placed a call,
/// bailed through here five seconds later, told nobody, and left one device ringing and
/// another stuck on "establishing secure connection…" while its claim was refused against a
/// session holding no call. From the caller's log the sole trace was the refusal — the abort
/// that caused it wrote nothing at all.
pub(crate) fn call_still_live(
    s: &Session,
    client: &Arc<Client>,
    call_instance_id: &str,
) -> Result<(), String> {
    if !is_current(s, client) {
        crate::diag!("[call] outgoing call ABANDONED: session or client replaced mid-start");
        return Err("not configured".into());
    }
    if s.account.is_none() {
        crate::diag!("[call] outgoing call ABANDONED: the vault locked mid-start");
        return Err("locked".into());
    }
    if let Some(reason) = s.call_store.registry.terminal_reason(call_instance_id) {
        // A terminal landed on a call this device is still placing. Naming the reason is the
        // point: it says *who* ended it — a callee's decline or busy reads differently from
        // an expiry or our own cancel, and the answer decides whether the other devices we
        // rang should have been told.
        crate::diag!(
            "[call] outgoing call ABANDONED: a terminal ({reason:?}) landed on it while it \
             was still starting — every device already rung is still ringing, and any claim \
             from them will be refused"
        );
        return Err(format!("call already ended ({reason:?})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::history::RosterDevice;

    /// E-1's root fix: a device that only ever RECEIVES calls must still pin the rosters it
    /// needs to screen one.
    ///
    /// The screening index is built entirely from `history.pinned_roster(...)`, and until
    /// this a roster was pinned by exactly one call site — `warm_device_routes`, reached only
    /// when this device *places* a call. So a receive-only device had an empty index, every
    /// capsule was refused as unplaceable, and the locked ring had no call state behind it.
    /// Confirmed on a device 2026-07-31: one outgoing call was the entire difference between
    /// a dead notification and a real, answerable ring.
    #[tokio::test]
    async fn the_screening_warm_prefers_accounts_with_no_roster_at_all() {
        let mut s = Session {
            account: Some(
                crypto_core::create_account_with_username("alice", "Alice-Password-123!")
                    .unwrap()
                    .0,
            ),
            ..Session::default()
        };
        // Our own account is always a candidate — a sibling's "answered elsewhere" capsule is
        // the one a locked phone most needs to verify, and it is never a contact.
        assert_eq!(screen_warm_targets(&s), vec!["alice".to_string()]);

        // A contact whose roster IS pinned still needs refreshing, but it screens today, so
        // it must not push an unpinned one out of a bounded warm.
        s.history
            .pin_roster(
                "bob",
                0,
                0,
                "bob-primary",
                vec![RosterDevice {
                    device_id: "0".into(),
                    identity_key: "bob-primary".into(),
                    signing_key: "bob-signing".into(),
                }],
            )
            .unwrap();
        s.history.pin_contact("bob", "bob-primary", false);
        s.history.pin_contact("carol", "carol-primary", false);
        let targets = screen_warm_targets(&s);
        assert_eq!(
            targets.iter().position(|t| t == "bob"),
            Some(targets.len() - 1),
            "the already-pinned account goes last: a missing roster is what breaks screening"
        );
        assert!(targets.contains(&"carol".to_string()));
        assert!(targets.contains(&"alice".to_string()));

        // Bounded, so one unlock cannot become a burst of relay round trips.
        for i in 0..40 {
            s.history
                .pin_contact(&format!("peer{i}"), &format!("k{i}"), false);
        }
        assert_eq!(screen_warm_targets(&s).len(), MAX_SCREEN_WARM_PER_UNLOCK);
    }

    /// A-26: the capsule layer must warm against a relay that advertises no multi-device
    /// surface at all.
    ///
    /// `warm_call_routes` returned early on `!s.multi_device`, and it was the **only** caller
    /// of `warm_call_bindings`. So `s.call_bindings` was never populated, `capsule_targets`
    /// was always empty, and no capsule was ever sent — a locked phone fell back to the
    /// unverified generic ring (L-11's fallback) and never got the terminal that stops it.
    /// Nothing about the capsule layer is multi-device; it is about a *locked* callee.
    ///
    /// The relay here is unreachable, so every call-key fetch fails. That is the point: the
    /// warm still records the (empty) result for the account, which is what proves it ran.
    #[tokio::test]
    async fn the_capsule_layer_warms_against_a_single_device_relay() {
        let client = Arc::new(Client::new("http://127.0.0.1:1", "ws://127.0.0.1:1", ""));
        let inner: Arc<Mutex<Session>> = Arc::default();
        {
            let mut s = inner.lock().await;
            s.client = Some(client.clone());
            s.multi_device = false; // the relay does not advertise the capability
            s.account = Some(
                crypto_core::create_account_with_username("alice", "Alice-Password-123!")
                    .unwrap()
                    .0,
            );
            // A pinned, KT-verified roster is what a call key is trusted against, and that
            // requirement is deliberately unchanged — the fix is about not skipping the warm,
            // never about relaxing it.
            s.history
                .pin_roster(
                    "bob",
                    0,
                    0,
                    "bob-primary",
                    vec![RosterDevice {
                        device_id: "0".into(),
                        identity_key: "bob-primary".into(),
                        signing_key: "bob-signing".into(),
                    }],
                )
                .unwrap();
        }

        warm_call_routes(&inner, &client, "bob").await;

        assert!(
            inner.lock().await.call_bindings.contains_key("bob"),
            "the binding warm has to run whatever the relay's multi-device capability says"
        );
    }
}

/// Most accounts warmed for the screening index in one unlock.
///
/// Each is a relay round trip, and the pin it produces is persistent — so a device with many
/// contacts fills its index in over a few unlocks rather than making one unlock expensive.
/// Small on purpose: the accounts that matter are the ones that call you, and they reach the
/// front of the queue on the first unlock after they do.
const MAX_SCREEN_WARM_PER_UNLOCK: usize = 8;

/// Pin the KT rosters a **locked** device needs in order to screen an incoming call, then
/// rebuild the screening index from them (E-1).
///
/// This is the fix for the defect that produced the whole original bug report. The screening
/// index is built entirely out of `history.pinned_roster(...)`, and until now a roster was
/// pinned by exactly one call site — `warm_device_routes`, reached only when this device
/// *places* a call. So a device that only ever **received** calls never pinned anything,
/// its index was empty, `screening_ready` was false, every capsule was refused as
/// unplaceable, and the locked ring had no call state behind it. Confirmed on a device
/// 2026-07-31: one outgoing call was the entire difference between a dead notification and
/// a real, answerable ring.
///
/// Deliberately cheap and deliberately partial:
///
/// * accounts with **no pin at all** go first — those are the ones that break screening
///   outright, as opposed to a pin that is merely stale;
/// * blocked accounts and unaccepted message requests are skipped, exactly as
///   `ScreenIndex::build` skips them, so this never warms a caller who may not ring anyway;
/// * our own account is always a candidate, because a sibling's "answered elsewhere"
///   capsule is the one a locked phone most needs to verify and it is never a contact;
/// * bounded per unlock, and best effort throughout — an unreachable relay leaves the
///   existing pins exactly where they were.
///
/// Runs off the session lock: every network wait happens inside `warm_call_routes`, which
/// takes the lock only for the local steps.
pub(crate) async fn warm_call_screen(inner: &Arc<Mutex<Session>>, client: &Arc<Client>) {
    let targets = {
        let s = inner.lock().await;
        if !is_current(&s, client) {
            return;
        }
        screen_warm_targets(&s)
    };
    if targets.is_empty() {
        return;
    }
    for username in &targets {
        warm_call_routes(inner, client, username).await;
    }
    // Rebuilt from whatever actually landed. `warm_device_routes` also refreshes the index
    // per account it pins, so this is belt and braces — and it is what makes the outcome
    // correct when every fetch failed and nothing called `refresh_call_screen` at all.
    let mut s = inner.lock().await;
    if is_current(&s, client) {
        refresh_call_screen(&mut s);
        crate::diag!(
            "[capsule] screening index warmed for {} account(s); entries now {}",
            targets.len(),
            screen_entry_count(&s)
        );
    }
}

/// Which accounts this unlock should pin rosters for, in the order they should be tried.
///
/// Unpinned first, because a **missing** roster is what makes screening impossible while a
/// stale one still screens. Blocked accounts and unaccepted message requests are excluded
/// for the same reason `ScreenIndex::build` excludes them — warming a caller who may not
/// ring this device buys nothing. Our own account is always a candidate: a sibling's
/// "answered elsewhere" capsule is the one a locked phone most needs to verify, and it is
/// never a contact.
pub(crate) fn screen_warm_targets(s: &Session) -> Vec<String> {
    let Some(account) = s.account.as_ref() else {
        return Vec::new();
    };
    let me = account.account_id().to_string();
    let (mut unpinned, mut pinned): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for name in std::iter::once(me).chain(
        s.history
            .contacts()
            .into_iter()
            .filter(|(_, pin)| !pin.blocked && pin.request.is_none())
            .map(|(username, _)| username),
    ) {
        if s.history.pinned_roster(&name).is_some() {
            pinned.push(name);
        } else {
            unpinned.push(name);
        }
    }
    unpinned.append(&mut pinned);
    unpinned.truncate(MAX_SCREEN_WARM_PER_UNLOCK);
    unpinned
}

/// How many callers the freshly written index can place, for the diagnostic above.
fn screen_entry_count(s: &Session) -> usize {
    let Some(device_key) = device_key() else {
        return 0;
    };
    let store_key = *crypto_core::callkey::call_store_key(&device_key);
    std::fs::read(s.call_screen_path())
        .ok()
        .and_then(|blob| client_core::callscreen::ScreenIndex::open(&store_key, &blob))
        .map(|index| index.entries.len())
        .unwrap_or(0)
}
