//! The call-control store **while the chat vault is locked** — the whole reason a separate
//! call-only subsystem exists (`internal/CALL_PLAN.md` §3.4, §4.2).
//!
//! Nothing here touches the vault. The account hash and device id come from the sealed
//! store, the mailbox is authenticated with the call-control key alone, and each capsule is
//! verified against the approved-caller screening index rather than the roster. What that
//! buys is bounded and deliberate: this device can record ordering state, park a pending
//! ring, take a ring down, and decline. Answering still needs the encrypted offer, which
//! still needs the vault.
//!
//! Two rules here were each written by a call that failed in the field, and both are about
//! *not* destroying evidence:
//!
//! * [`screening_ready`] — draining acks, and an ack deletes at the relay, so a device that
//!   can screen nobody must not open the mailbox at all (E-13);
//! * the drain gate in [`drain_call_capsules_locked`] — one drain at a time process-wide,
//!   because two concurrent ones invalidate each other's single-use nonce challenge and the
//!   relay rejects both (E-18).
//!
//! [`super::store`] owns the same store with the vault open.

use crate::*;
use client_core::callstore::CallStore;
use crypto_core::callkey;
/// How much of a mailbox hash may appear in a diagnostic line.
///
/// Enough to correlate two log lines with each other and with a relay-side query during a
/// device session; far too little to identify anyone. Diagnostics are off unless the user
/// asked for them (`--debug` / `SONA_DEBUG`), and even then the capsule path logs counts,
/// truncated hashes and reasons — never a call id, a username, or key material.
pub(crate) fn mailbox_tag(hash: &str) -> &str {
    &hash[..hash.len().min(8)]
}

/// May a locked drain take mail out of the call-control mailbox at all? (E-13)
///
/// The drain acknowledges every envelope it takes, and an ack deletes it at the relay. That
/// makes "should I fetch" a different question from "should I accept this capsule", and the
/// two were conflated: with no screening index the drain fetched, acked, refused everything
/// as unplaceable, and left a ring with no call state behind it — having destroyed the only
/// copy of the offer, so no later drain and no unlock could recover it.
///
/// An index that opens but is **empty** is treated the same as one that will not open. Both
/// mean the same thing operationally — this device can place nobody — and an empty index is
/// a legitimate state (no pinned contacts yet, or a rebuild that has not happened), which is
/// exactly when destroying an incoming call is least excusable.
///
/// `internal/CALL_PLAN.md` §4.4: "fail closed" means refuse the call, not destroy the evidence.
pub(crate) fn screening_ready(screen: Option<&client_core::callscreen::ScreenIndex>) -> bool {
    screen.is_some_and(|screen| !screen.entries.is_empty())
}

/// Put this device's sealed call-control store in memory **while the vault is locked**,
/// if it is not there already.
///
/// A locked wake loads the store, presents a ring, and returns — and Android may freeze or
/// kill the process the moment it does. The Answer or Decline the user presses afterwards
/// can therefore arrive in a process that has never seen the store, and a session field
/// that is empty because nothing loaded it is indistinguishable from one that is empty
/// because there is no ring. That ambiguity is what made both actions silent no-ops.
///
/// Unlocked, this does nothing: [`load_call_store`] owns the store then, and it is the
/// only path that may bind it to an account.
pub(crate) fn load_locked_call_store(s: &mut Session) -> bool {
    if s.account.is_some() {
        return false;
    }
    if !s.call_store.device_id.is_empty() {
        return true; // already loaded by this process' drain
    }
    let Some(device_key) = device_key() else {
        return false;
    };
    let store_key = *callkey::call_store_key(&device_key);
    let Some(store) = std::fs::read(s.call_store_path())
        .ok()
        .and_then(|blob| CallStore::open(&store_key, &blob))
    else {
        return false;
    };
    s.call_store = store;
    s.call_store_dirty
        .store(false, std::sync::atomic::Ordering::SeqCst);
    true
}

/// What a locked-vault capsule drain found, so the wake path can be honest about what it
/// puts on screen.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LockedWake {
    /// A live ring is pending for this device.
    pub(crate) ringing: bool,
    /// A call this device may have been ringing for has ended.
    pub(crate) terminated: bool,
}

/// Drain the call-control mailbox with the **chat vault locked**.
///
/// This is what the call-only subsystem exists for. Nothing here touches the vault: the
/// account hash and device id come from the sealed store, the mailbox is authenticated
/// with the call-control key alone, and each capsule is verified against the approved-
/// caller screening index — a caller the index cannot place has no key here, so it is
/// refused and acked away rather than ringing this phone.
///
/// Everything it can do is bounded by what a capsule carries: record ordering state, park
/// a pending ring, and take a ring down. Answering still needs the encrypted offer, which
/// still needs the vault.
pub(crate) async fn drain_call_capsules_locked(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
) -> LockedWake {
    // E-18. One drain of this mailbox at a time, process-wide.
    //
    // The subscription is authenticated with a single-use nonce challenge, so two drains
    // running at once do not merely duplicate work — they *invalidate each other* and the
    // relay rejects both. Measured 2026-08-01: one answered-elsewhere produced two
    // `CallControl` wakes 61 ms apart, both drains came back
    // `authentication rejected by server`, the terminal was never read, and the phone rang
    // on to its 43-second backstop at a call already answered on the desktop. Three drains
    // 600 ms apart in the same session all succeeded, which is what made it look
    // intermittent.
    //
    // Serialised rather than skipped: a second wake exists because a second message
    // arrived, and the first drain may already have fetched before it landed. Waiting costs
    // one short queue and reads everything; skipping would leave that message until the
    // next wake, which for a terminal means a phone still ringing.
    static DRAIN_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _drain_guard = DRAIN_GATE.lock().await;
    let Some(device_key) = device_key() else {
        crate::diag!("[capsule] locked drain: no device key store — cannot open any call state");
        return LockedWake::default();
    };
    let store_key = *callkey::call_store_key(&device_key);
    let (call_key, account_hash, device_id, screen) = {
        let mut s = inner.lock().await;
        if !is_current(&s, client) || s.account.is_some() {
            // Not a fault: the vault opened, and the ordinary drain owns the mailbox now.
            return LockedWake::default();
        }
        let Some(store) = std::fs::read(s.call_store_path())
            .ok()
            .and_then(|blob| CallStore::open(&store_key, &blob))
        else {
            // Not the direct-boot case, despite appearances: no Sona component is
            // `directBootAware`, so if this code is running the user has unlocked the device
            // at least once since boot and credential-encrypted storage is readable (E-8).
            // So this means the store was never written, or the device key it is sealed
            // under has rotated.
            crate::diag!(
                "[capsule] locked drain: call store unreadable (never written, or the \
                 device key rotated) — no mailbox to drain"
            );
            return LockedWake::default();
        };
        let Some(call_key) = std::fs::read(s.call_key_path())
            .ok()
            .and_then(|blob| callkey::open_call_secret(&store_key, &blob))
        else {
            crate::diag!("[capsule] locked drain: no call-control identity on this device");
            return LockedWake::default();
        };
        // E-13. Draining **acks**, and acking **destroys**: the relay drops a message the
        // moment it is acknowledged. So the question to ask before opening the mailbox is
        // not "can this capsule be screened" — none has been fetched yet — but "can this
        // device screen *anything at all*". If it cannot, taking the mail out of the box
        // only annihilates it, and the annihilation is permanent and self-perpetuating: the
        // offer capsule that would have rung properly after the next unlock is already gone.
        //
        // `unwrap_or_default()` used to yield an **empty** index here, which refuses every
        // caller. That is what made a missing screening file destroy every incoming call
        // rather than merely fail to screen one.
        let screen = std::fs::read(s.call_screen_path())
            .ok()
            .and_then(|blob| client_core::callscreen::ScreenIndex::open(&store_key, &blob));
        if !screening_ready(screen.as_ref()) {
            crate::diag!(
                "[capsule] locked drain: no usable screening index — NOT draining, so the \
                 capsules survive for the next drain (they would otherwise be acked away \
                 and lost for good)"
            );
            return LockedWake::default();
        }
        let screen = screen.expect("screening_ready implies Some");
        let (account_hash, device_id) = (store.account_hash.clone(), store.device_id.clone());
        s.call_store = store;
        s.call_store_dirty
            .store(false, std::sync::atomic::Ordering::SeqCst);
        (Arc::new(call_key), account_hash, device_id, screen)
    };
    // Locked, so the only signer we can place is a roster key from the screening index:
    // there is no verified `CallKeyBinding` cache without the vault, and guessing one is
    // exactly what fail-closed forbids. A capsule signed by a peer's *call* key is
    // therefore refused here and re-read after unlock, which is the safe direction.
    let approved = move |capsule: &client_core::callcapsule::CallCapsule| {
        (capsule.signer == client_core::callcapsule::CapsuleSigner::Roster)
            .then(|| screen.signing_key(&store_key, &capsule.from, &capsule.caller_device_id))
            .flatten()
    };
    let mailbox = client_core::call_mailbox_for(&account_hash, &device_id).unwrap_or_default();
    let drained = client
        .drain_verified_capsules_by_hash(&call_key, &account_hash, &device_id, now_secs(), approved)
        .await;
    let (capsules, stats) = match drained {
        Ok(drained) => drained,
        Err(error) => {
            // The subscription itself failed: the relay was unreachable, or it refused this
            // device's call-key signature on the mailbox. Distinguishing those two is the
            // whole reason this carries the error.
            crate::diag!(
                "[capsule] locked drain: mailbox {} fetch failed: {error}",
                mailbox_tag(&mailbox)
            );
            return LockedWake::default();
        }
    };
    crate::diag!(
        "[capsule] locked drain: mailbox {} fetched={} decoded={} accepted={} \
         refused_unplaceable={} refused_signature={}",
        mailbox_tag(&mailbox),
        stats.fetched,
        stats.decoded,
        stats.accepted(),
        stats.refused_unplaceable,
        stats.refused_signature
    );
    if stats.dropped_everything() {
        // The failure this whole round exists for: the mailbox had capsules, they were
        // acknowledged to the relay, and not one of them survived screening. The ring that
        // follows will have no call state behind it.
        crate::diag!(
            "[capsule] locked drain: DROPPED ALL {} fetched capsules — any ring raised now \
             has no call state behind it",
            stats.fetched
        );
    }
    let mut s = inner.lock().await;
    if !is_current(&s, client) || s.account.is_some() {
        // The vault opened while the drain was in flight. Everything just fetched is
        // already acknowledged to the relay and is about to be discarded (E-13).
        if !capsules.is_empty() {
            crate::diag!(
                "[capsule] locked drain: vault opened mid-drain — discarding {} \
                 already-acked capsules",
                capsules.len()
            );
        }
        return LockedWake::default();
    }
    let mut wake = LockedWake::default();
    for capsule in &capsules {
        wake.terminated |= capsule.kind == client_core::callcapsule::CapsuleKind::Terminal;
        apply_capsule(&mut s, capsule);
    }
    // Only a ring whose own window is still open. Rings survive past `ring_expires_at` by
    // the crash grace so a restart can cancel what it left on screen — treating one of
    // those as "ringing" would re-post the generic ring for a call that is already over.
    let now = now_secs();
    wake.ringing = s
        .call_store
        .rings
        .iter()
        .any(|ring| ring.ring_expires_at > now);
    wake
}

/// Note that the generic locked ring is on screen, for every pending ring it stands for.
///
/// The locked presentation is one notification under [`notifier::LOCKED_CALL_RING`],
/// not a per-ring handle, so that is the id reconciliation has to cancel — recording the
/// handle instead would leave a restart cancelling something that was never posted.
pub(crate) async fn mark_locked_rings_presented(inner: &Arc<Mutex<Session>>) {
    let mut s = inner.lock().await;
    let calls: Vec<String> = s
        .call_store
        .rings
        .iter()
        .map(|ring| ring.call_instance_id.clone())
        .collect();
    if calls.is_empty() {
        return;
    }
    with_call_store(&mut s, |store| {
        for call in &calls {
            store.mark_presented(call, notifier::LOCKED_CALL_RING);
        }
    });
}

/// Decline a ring **with the chat vault locked** (`internal/CALL_PLAN.md` §3.4).
///
/// This is the one thing the call-only identity is allowed to say on the wire. A locked
/// device has no roster key — it is in the vault — so it signs with its call-control key
/// and marks the capsule [`CapsuleSigner::CallKey`]; `CallCapsule::well_formed` refuses
/// that signer on anything but a decline or a busy, so the scoped identity can end a ring
/// and never start one (§4.2).
///
/// It needs no account name and no relay lookup: the mailbox and public key it replies to
/// came inside the authenticated offer capsule it is answering. A caller that published
/// no call key leaves those fields empty, and then the decline is local only — the ring
/// still stops here, and the caller finds out at its own ring timeout.
///
/// Queued in the store's outbox first, so a decline survives the process that sent it:
/// Android may freeze this app the moment the notification is dismissed.
///
/// `presented_as` is the id the notification the user dismissed was posted under. A locked
/// device shows one generic ring for everything it is holding, so that usually means every
/// pending ring — but "usually" is not "always", and declining a ring the user did not
/// touch is not this function's to do.
pub(crate) async fn decline_locked(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    presented_as: &str,
) {
    use client_core::callcapsule::{CallCapsule, CapsuleKind, CapsulePlan, CapsuleSigner};
    use client_core::callstate::CallTerminalReason;

    let Some(device_key) = device_key() else {
        return;
    };
    let store_key = *callkey::call_store_key(&device_key);
    let queued = {
        let mut s = inner.lock().await;
        if !is_current(&s, client) || s.account.is_some() {
            return; // unlocked: the ordinary decline path owns this
        }
        // The process that showed the ring may already be gone; the store is on disk.
        if !load_locked_call_store(&mut s) {
            return;
        }
        let Some(call_key) = std::fs::read(s.call_key_path())
            .ok()
            .and_then(|blob| callkey::open_call_secret(&store_key, &blob))
        else {
            return;
        };
        let (account_hash, my_device_id) = (
            s.call_store.account_hash.clone(),
            s.call_store.device_id.clone(),
        );
        let username = s.call_store.username.clone();
        if username.is_empty() {
            return; // written by a build that did not record it: nothing to sign as
        }
        let my_call_mailbox =
            client_core::call_mailbox_for(&account_hash, &my_device_id).unwrap_or_default();
        let my_call_key = call_key.public_b64();
        let now = now_secs();
        let retention = call_retention_secs(&s);
        let rings: Vec<_> = s
            .call_store
            .rings
            .iter()
            .filter(|ring| {
                presented_as.is_empty() || ring.presented_as.as_deref() == Some(presented_as)
            })
            .cloned()
            .collect();
        let mut queued = false;
        for ring in rings {
            // Stop presenting it here first, and tombstone it, so the ring goes down even
            // when there is nobody to tell.
            let expires_at = now.saturating_add(client_core::callstate::CALL_SIGNAL_TTL_SECS);
            with_call_store(&mut s, |store| {
                store.record_terminal(
                    &ring.call_instance_id,
                    &ring.offer_id,
                    CallTerminalReason::DeclinedHere,
                    now,
                    retention,
                )
            });
            if ring.reply_call_mailbox.is_empty() || ring.reply_call_key.is_empty() {
                continue; // caller published no call key: local decline only
            }
            let capsule = CallCapsule::new(
                CapsulePlan {
                    kind: CapsuleKind::Terminal,
                    call_instance_id: ring.call_instance_id.clone(),
                    offer_id: ring.offer_id.clone(),
                    // Who is declining: us. The caller checks this against the roster it
                    // rang, and the binding it already holds for this device.
                    from: username.clone(),
                    caller_identity_key: String::new(),
                    caller_device_id: my_device_id.clone(),
                    to_device_id: ring.caller_device_id.clone(),
                    video: false,
                    group: ring.group,
                    display_name: String::new(),
                    created_at: now,
                    ring_expires_at: expires_at,
                    expires_at,
                    reply_to_mailbox: my_call_mailbox.clone(),
                    reply_call_mailbox: my_call_mailbox.clone(),
                    reply_call_key: my_call_key.clone(),
                    signer: CapsuleSigner::CallKey,
                    reason: Some(CallTerminalReason::DeclinedHere),
                },
                |payload| call_key.sign(payload),
            );
            if !capsule.well_formed() {
                continue;
            }
            queued |= with_call_store(&mut s, |store| {
                store.queue_decline(
                    &ring.reply_call_mailbox,
                    &ring.reply_call_key,
                    capsule.encode(),
                    expires_at,
                    now,
                )
            });
        }
        queued
    };
    if queued {
        drain_capsule_outbox(inner, client).await;
    }
}

/// Post whatever the store's capsule outbox holds, with the session lock released, and
/// keep only what did not get through. Bounded by the store's own retry budget.
pub(crate) async fn drain_capsule_outbox(inner: &Arc<Mutex<Session>>, client: &Arc<Client>) {
    let due = {
        let mut s = inner.lock().await;
        if !is_current(&s, client) {
            return;
        }
        with_call_store(&mut s, |store| store.take_due(now_secs()))
    };
    if due.is_empty() {
        return;
    }
    let mut delivered = Vec::new();
    for (id, entry) in due {
        if client
            .post_call_capsule_to(
                &entry.call_mailbox,
                &entry.call_key,
                &entry.plaintext,
                entry.expires_at,
            )
            .await
            .is_ok()
        {
            delivered.push(id);
        }
    }
    let mut s = inner.lock().await;
    if is_current(&s, client) && !delivered.is_empty() {
        with_call_store(&mut s, |store| store.delivered(&delivered));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E-13: a device that can screen nobody must not open the mailbox.
    ///
    /// The drain acks every envelope it takes and an ack deletes it at the relay, so
    /// fetching without a usable screening index does not "fail to screen one call" — it
    /// destroys every incoming call permanently, including the offer that would have rung
    /// correctly after the next unlock. That is what made E-1 self-perpetuating.
    ///
    /// An index that opens but is empty is deliberately treated as no index at all: both
    /// mean this device can place nobody, and an empty one is a *legitimate* state (no
    /// pinned contacts yet, or a rebuild that has not run), which is precisely when
    /// annihilating an incoming call is least excusable.
    #[test]
    fn a_device_that_can_screen_nobody_must_not_drain_the_mailbox() {
        use client_core::callscreen::{ScreenEntry, ScreenIndex};

        assert!(
            !screening_ready(None),
            "no screening index at all: fetching would ack the capsules away unscreened"
        );
        assert!(
            !screening_ready(Some(&ScreenIndex::default())),
            "an index that opens but places nobody is not a licence to destroy the mailbox"
        );
        let usable = ScreenIndex {
            entries: vec![ScreenEntry {
                caller: "caller-hash".into(),
                devices: vec![("0".into(), "signing-key".into())],
            }],
        };
        assert!(
            screening_ready(Some(&usable)),
            "one placeable caller is enough to make draining meaningful"
        );
    }
}
