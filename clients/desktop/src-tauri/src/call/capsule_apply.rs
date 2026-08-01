//! Who a capsule entitles to do what, and what converging one with existing call state
//! means.
//!
//! [`super::capsule`] fetches; this decides. The split is the one the delivery layer keeps
//! everywhere else: a verified signature says only "someone this device would let ring it
//! sent this", which is not the same question as "may this sender end *this* call" — and
//! treating the two as one let any non-blocked contact who could name a `call_instance_id`
//! take its ring down.
//!
//! Two entitlement checks, then the convergence:
//!
//! * [`capsule_signing_keys`] — the key a signature must verify under, taken only from
//!   pinned, KT-verified state, so an unpinned or blocked caller has no key at all;
//! * [`capsule_terminal_allowed`] — whether that verified signer may end this particular
//!   call, which is the encrypted layer's own rule on a layer with less to check with;
//! * [`apply_capsule`] / [`adopt_capsule_ring`] — what survives, converged onto the one
//!   registry record both delivery layers key.
//!
//! [`group_terminal_capsule_worth_sending`] lives here too, deliberately: it is the
//! sending-side mirror of the group rule, and if the two ever drift the symptom is a phone
//! left ringing while nothing fails loudly.

use crate::*;
use client_core::callcapsule::{CallCapsule, CapsuleKind};

/// The key a capsule's signature must verify under, from **pinned, KT-verified** state.
/// A blocked caller, an unpinned account, or a device that is not on that account's
/// verified roster gets `None` — which refuses the capsule.
///
/// Two key sets, because a capsule names which one signed it: the device's roster key,
/// and — for a device that was **locked** when it replied, and so had no roster key to
/// sign with — the call-control key its verified [`CallKeyBinding`] publishes. Both are
/// rooted in the same KT-verified roster; the call-control key's narrower reach is
/// enforced by `CallCapsule::well_formed`, which only lets it end a ring.
pub(crate) fn capsule_signing_keys(s: &Session) -> impl Fn(&CallCapsule) -> Option<String> {
    use client_core::callcapsule::CapsuleSigner;
    let mut roster_keys: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    let mut call_keys: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    let me = s.account.as_ref().map(|account| account.account_id());
    // Our own siblings first: a self-sync terminal from another of our devices is what
    // stops this one ringing when someone else answered.
    for username in me.into_iter().map(str::to_string).chain(
        s.history
            .contacts()
            .into_iter()
            .filter(|(_, pin)| !pin.blocked && pin.request.is_none())
            .map(|(username, _)| username),
    ) {
        let Some(pin) = s.history.pinned_roster(&username) else {
            continue;
        };
        for device in &pin.devices {
            if !device.signing_key.is_empty() {
                roster_keys.insert(
                    (username.clone(), device.device_id.clone()),
                    device.signing_key.clone(),
                );
            }
        }
        // The bindings warmed for this account, already verified against that same pin.
        if let Some(cached) = s.call_bindings.get(&username) {
            for (device_id, binding) in &cached.devices {
                if !binding.call_signing_key.is_empty() {
                    call_keys.insert(
                        (username.clone(), device_id.clone()),
                        binding.call_signing_key.clone(),
                    );
                }
            }
        }
    }
    move |capsule: &CallCapsule| {
        let who = (
            capsule.from.to_string(),
            capsule.caller_device_id.to_string(),
        );
        match capsule.signer {
            CapsuleSigner::Roster => roster_keys.get(&who).cloned(),
            CapsuleSigner::CallKey => call_keys.get(&who).cloned(),
        }
    }
}

/// May this capsule's signer end **this** call on this device?
///
/// A verified signature says only "a caller this device would let ring it sent this". That
/// is not the same question, and treating it as the same one let any non-blocked contact
/// who could name a `call_instance_id` tombstone that call and take its ring down. The
/// encrypted paths never conflated the two: `CallTerminalV2` checks the sender against the
/// call's peer, and `GroupCallTerminalV2` separates a coordinator's cancellation — which
/// ends the logical call — from an ordinary member's leave, which does not.
///
/// The rules here are those rules, on the layer that has less to check with:
///
/// * **our own devices** may say anything about our own call. That is the self-sync
///   terminal, and it is the one that stops this phone ringing for a call answered on the
///   desktop.
/// * **a peer** may only announce outcomes that are its side's to announce. "Answered
///   elsewhere" is a word about *our* devices; a peer saying it is a peer editing our call
///   log.
/// * **a group** terminal ends the logical call only from the ring's coordinator, and only
///   with a reason that ends one. A member declining leaves its own leg — the capsule layer
///   holds no per-leg state, so for it that is simply nothing.
/// * a **1:1** terminal from a caller we cannot place is still accepted, because
///   `call_instance_id` is 128 random bits that only the parties to that call ever see:
///   naming it *is* the proof of participation. This is what keeps terminal-before-offer
///   working, which is the race this project exists for.
///
/// Residual, and deliberate: a group member can still race a forged `caller_cancelled`
/// against the coordinator's own offer capsule, in the window before this device has any
/// state for that ring. Closing that needs group membership, which lives in the vault —
/// exactly what a locked device does not have.
fn capsule_terminal_allowed(
    s: &Session,
    capsule: &CallCapsule,
    reason: client_core::callstate::CallTerminalReason,
) -> bool {
    use client_core::callstate::CallTerminalReason as R;

    // Who we are: the account when the vault is open, and the name the sealed store
    // carries when it is not — the same one a locked decline signs as.
    let me = s
        .account
        .as_ref()
        .map(|account| account.account_id().to_string())
        .unwrap_or_else(|| s.call_store.username.clone());
    if !me.is_empty() && capsule.from == me {
        return true;
    }
    if !matches!(
        reason,
        R::CallerCancelled | R::Expired | R::TransportError | R::DeclinedHere | R::Busy
    ) {
        return false;
    }
    // Who announced the ring we are holding for this call, if we are holding one.
    let announcer = s
        .call_store
        .ring(&capsule.call_instance_id)
        .map(|ring| (ring.from.clone(), ring.caller_device_id.clone()));
    let from_announcer = announcer.as_ref().is_some_and(|(from, device_id)| {
        *from == capsule.from && *device_id == capsule.caller_device_id
    });

    if capsule.group {
        if !matches!(reason, R::CallerCancelled | R::Expired | R::TransportError) {
            return false;
        }
        let coordinator = [
            s.group_call
                .as_ref()
                .map(|call| (&call.call_instance, &call.coordinator)),
            s.group_incoming
                .as_ref()
                .map(|offer| (&offer.call_instance, &offer.coordinator)),
            s.group_claiming
                .as_ref()
                .map(|pending| (&pending.offer.call_instance, &pending.offer.coordinator)),
        ]
        .into_iter()
        .flatten()
        .find(|(call_instance, _)| **call_instance == capsule.call_instance_id)
        .map(|(_, coordinator)| coordinator);
        return match coordinator {
            Some(coordinator) => {
                coordinator.username == capsule.from
                    && coordinator.device_id == capsule.caller_device_id
            }
            // A pending capsule ring but no live group state: the coordinator's offer fan
            // is what announced it, so that is who may end it.
            None if announcer.is_some() => from_announcer,
            // Nothing here for this call at all — a terminal before its offer. There is no
            // ring to take down, so all this can do is write the tombstone that stops a
            // late offer from ringing.
            None => true,
        };
    }
    let peer = [
        s.call
            .as_ref()
            .map(|call| (&call.call_instance_id, &call.peer_username)),
        s.incoming
            .as_ref()
            .map(|offer| (&offer.call_instance_id, &offer.username)),
        s.claiming
            .as_ref()
            .map(|pending| (&pending.offer.call_instance_id, &pending.offer.username)),
        s.reconnect
            .as_ref()
            .map(|rc| (&rc.call_instance_id, &rc.peer_username)),
    ]
    .into_iter()
    .flatten()
    .find(|(call_instance_id, _)| **call_instance_id == capsule.call_instance_id)
    .map(|(_, username)| username.clone());
    match (peer, announcer) {
        (Some(username), _) => username == capsule.from,
        (None, Some(_)) => from_announcer,
        (None, None) => true,
    }
}

/// The mirror of [`capsule_terminal_allowed`]'s **group** rule, on the sending side: is a
/// group terminal worth putting on the capsule layer at all?
///
/// `send_group_call_terminal_everywhere` minted a capsule for every other member on *any*
/// leave, including a plain decline (A-5's fix, and correct for the encrypted fan, which
/// carries per-leg semantics the capsule layer deliberately does not have). A-14 then made
/// every receiver refuse a non-coordinator group terminal — also correct — which left the
/// traffic itself pure waste: N−1 silent high-priority wakes per decline, N(N−1) if everyone
/// declines, each spending the recipient's `CONTROL_WAKE_BURST` budget and waking a frozen
/// process on a locked phone (A-25).
///
/// It lives here, beside the rule it mirrors, for one reason: if the send condition and the
/// accept condition ever drift, the symptom is a phone left ringing and **nothing fails
/// loudly**. Keeping both on one screen is the cheapest guard against that.
///
/// The coordinator's own terminal must still fan to every member device — without it a
/// member's locked phone adopts the group ring and never learns it ended, which is the entire
/// reason the capsule fan exists here. Only a non-coordinator's leave skips.
pub(crate) fn group_terminal_capsule_worth_sending(
    s: &Session,
    coordinator: &GroupCoordinator,
    reason: client_core::callstate::CallTerminalReason,
) -> bool {
    use client_core::callstate::CallTerminalReason as R;
    super::auth::local_group_coordinator(s, coordinator)
        && matches!(reason, R::CallerCancelled | R::Expired | R::TransportError)
}

/// Converge one verified capsule with the call state this device already has, and record
/// the result in the persistent call-control store.
///
/// Offers converge silently: the capsule carries no media capability, so it cannot be
/// answered on its own, and a ring raised from one would be a ring the user cannot pick
/// up. The store keeps it as a pending ring so the encrypted offer adopts it — one ring —
/// and so a restart knows what this device was showing.
///
/// Terminals do the real work: the tombstone they write suppresses a late encrypted offer
/// (the terminal-before-offer race) and survives the process, and a live ring for that
/// logical call stops.
pub(crate) fn apply_capsule(s: &mut Session, capsule: &CallCapsule) {
    let retention = call_retention_secs(s);
    match capsule.kind {
        CapsuleKind::Offer => {
            // Already ringing/claiming/live for this call: one ring, whichever layer
            // announced it. The registry refuses the rest on its own terms — a tombstoned
            // call, a duplicate, an expired deadline.
            let live = [
                s.incoming.as_ref().map(|o| &o.call_instance_id),
                s.claiming.as_ref().map(|c| &c.offer.call_instance_id),
                s.call.as_ref().map(|c| &c.call_instance_id),
            ]
            .into_iter()
            .flatten()
            .any(|id| id == &capsule.call_instance_id);
            if live {
                return;
            }
            with_call_store(s, |store| {
                store.record_offer(capsule, now_secs(), retention);
            });
        }
        CapsuleKind::Terminal => {
            let Some(reason) = capsule.reason else {
                return;
            };
            // A verified signature is not an entitlement to end *this* call.
            if !capsule_terminal_allowed(s, capsule, reason) {
                return;
            }
            let ended = with_call_store(s, |store| {
                store
                    .record_terminal(
                        &capsule.call_instance_id,
                        &capsule.offer_id,
                        reason,
                        now_secs(),
                        retention,
                    )
                    .1
            });
            // Whatever this device was presenting for that call comes down — under
            // **both** ids, because they are not always the same one. A ring restored into
            // Telecom is showing under its `ring_handle`; the generic locked-vault ring is
            // showing under `presented_as`, one shared id for every pending ring, because a
            // locked device may not name the call. Cancelling only the handle is what left
            // a locked phone ringing at a call answered on the desktop. `cancel_ring` is
            // idempotent and ignores an id nothing is showing, so naming both costs
            // nothing.
            if let Some(ring) = ended {
                if let Some(presented_as) = ring.presented_as.as_deref() {
                    eng().cancel_ring(presented_as, "");
                }
                eng().cancel_ring(&ring.ring_handle, "");
            }
            // …and any live call state for it, through the same cascade the encrypted
            // terminal uses. This is the path a **locked** peer's decline arrives on:
            // it has no other way to reach us, so treating a capsule terminal as
            // ring-only would leave the caller ringing at a call already refused.
            end_local_call_state(s, &capsule.call_instance_id, reason);
        }
    }
}

/// Take over a pending capsule ring for the same logical call **and the same registry
/// record**. The encrypted offer owns the ring from here on: it is the only layer that
/// carries a media capability, so it is the only one that can produce an answerable ring.
///
/// A capsule naming a different `offer_id` for this logical call is not this ring — it is
/// left where it is, and the registry refuses it on its own terms.
pub(crate) fn adopt_capsule_ring(
    s: &mut Session,
    call_instance_id: &str,
    offer_id: &str,
) -> Option<String> {
    let matches = s
        .call_store
        .ring(call_instance_id)
        .is_some_and(|ring| ring.offer_id == offer_id);
    matches
        .then(|| with_call_store(s, |store| store.take_ring(call_instance_id)))
        .flatten()
        .map(|ring| ring.ring_handle)
}
#[cfg(test)]
mod tests {
    use super::*;
    use client_core::callcapsule::CapsulePlan;
    use client_core::callstate::{
        random_call_id, CallTerminalReason, OfferDecision, CALL_RING_TIMEOUT_SECS,
        CALL_SIGNAL_TTL_SECS,
    };

    /// The name a test session answers to, so a capsule minted `from` it is a **sibling's**
    /// self-sync terminal rather than a peer's. `apply_capsule` reads it from the sealed
    /// store when the vault is locked, which is the state these tests model.
    const ME: &str = "me";

    fn as_me(s: &mut Session) {
        s.call_store.username = ME.to_string();
    }

    fn capsule(
        kind: CapsuleKind,
        call: &str,
        offer: &str,
        reason: Option<CallTerminalReason>,
    ) -> CallCapsule {
        group_capsule(kind, call, offer, reason, false)
    }

    /// A terminal from one of our own devices — what a desktop sends its siblings when it
    /// answers, and the only sender entitled to say `answered_elsewhere`.
    fn from_sibling(
        kind: CapsuleKind,
        call: &str,
        offer: &str,
        reason: Option<CallTerminalReason>,
    ) -> CallCapsule {
        signed(ME, kind, call, offer, reason, false)
    }

    fn group_capsule(
        kind: CapsuleKind,
        call: &str,
        offer: &str,
        reason: Option<CallTerminalReason>,
        group: bool,
    ) -> CallCapsule {
        signed("bob", kind, call, offer, reason, group)
    }

    fn signed(
        from: &str,
        kind: CapsuleKind,
        call: &str,
        offer: &str,
        reason: Option<CallTerminalReason>,
        group: bool,
    ) -> CallCapsule {
        let account = crypto_core::create_account_with_username(from, "Test-Password-123!")
            .unwrap()
            .0;
        let now = now_secs();
        CallCapsule::new(
            CapsulePlan {
                kind,
                call_instance_id: call.to_string(),
                offer_id: offer.to_string(),
                from: from.to_string(),
                caller_identity_key: account.ratchet_ref().identity_key(),
                caller_device_id: "0".into(),
                to_device_id: "a".repeat(32),
                video: false,
                group,
                display_name: from.to_string(),
                created_at: now,
                ring_expires_at: now + CALL_RING_TIMEOUT_SECS,
                expires_at: now + CALL_SIGNAL_TTL_SECS,
                reply_to_mailbox: "b".repeat(64),
                reply_call_mailbox: "c".repeat(64),
                reply_call_key: "their-call-key".into(),
                signer: client_core::callcapsule::CapsuleSigner::Roster,
                reason,
            },
            |payload| account.ratchet_ref().sign(payload),
        )
    }

    /// The capsule layer arriving first must not consume the ring: the encrypted offer
    /// still rings (it is the only layer carrying a media capability), and it adopts the
    /// pending capsule ring instead of starting a second one.
    #[test]
    fn a_capsule_offer_converges_with_the_encrypted_offer_on_one_ring() {
        let mut s = Session::default();
        let (call, offer) = (random_call_id(), random_call_id());
        apply_capsule(&mut s, &capsule(CapsuleKind::Offer, &call, &offer, None));
        assert_eq!(
            s.call_store.ring(&call).map(|ring| ring.offer_id.clone()),
            Some(offer.clone())
        );
        // A duplicate capsule for the same call changes nothing.
        apply_capsule(&mut s, &capsule(CapsuleKind::Offer, &call, &offer, None));
        assert_eq!(
            s.call_store.ring(&call).map(|ring| ring.offer_id.clone()),
            Some(offer.clone())
        );
        // A capsule naming a different record for the same logical call is not this
        // pending ring, and cannot take it over.
        assert!(adopt_capsule_ring(&mut s, &call, &random_call_id()).is_none());
        // Both layers key one registry record, so the encrypted offer reads as a
        // duplicate — which is exactly the signal that it is this same ring arriving on
        // the layer that can be answered, and it takes the pending ring over.
        let now = now_secs();
        assert_eq!(
            s.calls().registry.receive_offer(
                &call,
                &offer,
                now,
                now + CALL_RING_TIMEOUT_SECS,
                now,
                0
            ),
            OfferDecision::Duplicate
        );
        assert!(adopt_capsule_ring(&mut s, &call, &offer).is_some());
        assert!(s.call_store.ring(&call).is_none());
    }

    /// A group ring is keyed by its `ring_id` — not by the per-member `offer_id`, of
    /// which one logical group ring has several — so that is the id its capsules carry
    /// and the id the encrypted group offer adopts on. Getting this wrong would not fail
    /// loudly: every member's offer would find no ring to take over, and a locked phone
    /// would ring once per member.
    #[test]
    fn a_group_capsule_converges_on_the_ring_id() {
        let mut s = Session::default();
        let (call, ring_id) = (random_call_id(), random_call_id());
        apply_capsule(
            &mut s,
            &group_capsule(CapsuleKind::Offer, &call, &ring_id, None, true),
        );
        assert_eq!(
            s.call_store.ring(&call).map(|ring| ring.offer_id.clone()),
            Some(ring_id.clone())
        );
        // A member's own per-leg offer id is not the ring: it must not take it over.
        assert!(adopt_capsule_ring(&mut s, &call, &random_call_id()).is_none());
        let now = now_secs();
        assert_eq!(
            s.calls().registry.receive_offer(
                &call,
                &ring_id,
                now,
                now + CALL_RING_TIMEOUT_SECS,
                now,
                0
            ),
            OfferDecision::Duplicate
        );
        assert!(adopt_capsule_ring(&mut s, &call, &ring_id).is_some());
        assert!(s.call_store.ring(&call).is_none());
    }

    /// The terminal-before-offer race, over the capsule layer: the tombstone it writes is
    /// what stops a late encrypted offer from ringing for the full timeout.
    #[test]
    fn a_terminal_capsule_tombstones_a_call_whose_offer_has_not_arrived() {
        let mut s = Session::default();
        as_me(&mut s);
        let (call, offer) = (random_call_id(), random_call_id());
        apply_capsule(
            &mut s,
            &capsule(
                CapsuleKind::Terminal,
                &call,
                &offer,
                Some(CallTerminalReason::CallerCancelled),
            ),
        );
        assert_eq!(
            s.calls().registry.terminal_reason(&call),
            Some(CallTerminalReason::CallerCancelled)
        );
        let now = now_secs();
        assert_eq!(
            s.calls().registry.receive_offer(
                &call,
                &offer,
                now,
                now + CALL_RING_TIMEOUT_SECS,
                now,
                0
            ),
            OfferDecision::Suppressed(CallTerminalReason::CallerCancelled)
        );
        // …and a capsule offer that arrives after it never rings either.
        apply_capsule(&mut s, &capsule(CapsuleKind::Offer, &call, &offer, None));
        assert!(s.call_store.ring(&call).is_none());
    }

    /// A-12: the terminal has to cancel the ring the phone is **actually showing**.
    ///
    /// On a locked device that is one generic notification under `LOCKED_CALL_RING`, not
    /// the capsule's random ring handle — `presented_as` records which, and nothing read
    /// it. So the whole locked chain worked (the sibling's capsule verified, the tombstone
    /// landed, `LockedWake::terminated` went true) and the phone rang out anyway. Both
    /// halves are pinned here: the engine must know about a ring it is expected to cancel,
    /// and the cancel must name the id the ring was posted under.
    #[test]
    fn a_terminal_capsule_cancels_the_id_the_locked_ring_was_posted_under() {
        let mut s = Session::default();
        as_me(&mut s);
        let (call, offer) = (random_call_id(), random_call_id());
        apply_capsule(&mut s, &capsule(CapsuleKind::Offer, &call, &offer, None));
        // What a locked wake does: one generic ring, recorded under the id it went out
        // with rather than under the handle nothing was posted with.
        eng().show_locked_ring();
        with_call_store(&mut s, |store| {
            store.mark_presented(&call, notifier::LOCKED_CALL_RING)
        });
        assert!(eng().ring_active(), "the locked ring is showing");

        apply_capsule(
            &mut s,
            &from_sibling(
                CapsuleKind::Terminal,
                &call,
                &offer,
                Some(CallTerminalReason::AnsweredElsewhere),
            ),
        );
        assert!(
            !eng().ring_active(),
            "answering elsewhere must stop the ring this phone is actually showing"
        );
    }

    /// A-25: what is minted and what is accepted must be **one** condition.
    ///
    /// `send_group_call_terminal_everywhere` minted a capsule for every other member on any
    /// leave, including a plain decline; A-14 then made every receiver refuse a
    /// non-coordinator group terminal. Both were right on their own, and together they meant
    /// N−1 silent high-priority wakes per decline that every recipient discarded — each one
    /// spending that phone's control-wake budget and thawing a frozen process for nothing.
    ///
    /// So this compares the two predicates directly, reason by reason. If they drift the
    /// symptom is a phone left ringing and nothing fails loudly, which is why they live
    /// beside each other and why this is asserted rather than reasoned about.
    #[test]
    fn a_group_terminal_is_minted_exactly_when_a_receiver_would_accept_it() {
        use client_core::callstate::CallTerminalReason as R;

        const EVERY_REASON: [R; 8] = [
            R::AnsweredHere,
            R::AnsweredElsewhere,
            R::DeclinedHere,
            R::DeclinedElsewhere,
            R::CallerCancelled,
            R::Expired,
            R::Busy,
            R::TransportError,
        ];

        // A member holding the group ring "bob" (device 0) announced by capsule.
        let mut receiver = Session::default();
        as_me(&mut receiver);
        let (call, ring_id) = (random_call_id(), random_call_id());
        apply_capsule(
            &mut receiver,
            &group_capsule(CapsuleKind::Offer, &call, &ring_id, None, true),
        );
        assert!(receiver.call_store.ring(&call).is_some());

        // The coordinator's own device, which is what the receiver checks the sender against.
        let account = crypto_core::create_account_with_username("bob", "Test-Password-123!")
            .unwrap()
            .0;
        let coordinator = GroupCoordinator {
            username: "bob".into(),
            identity_key: account.ratchet_ref().identity_key(),
            device_id: Session::default().history.self_device_id(),
            reply_to_mailbox: "b".repeat(64),
        };
        let sender = Session {
            account: Some(account),
            ..Default::default()
        };
        assert_eq!(sender.history.self_device_id(), coordinator.device_id);

        for reason in EVERY_REASON {
            let accepted = capsule_terminal_allowed(
                &receiver,
                &group_capsule(CapsuleKind::Terminal, &call, &ring_id, Some(reason), true),
                reason,
            );
            assert_eq!(
                group_terminal_capsule_worth_sending(&sender, &coordinator, reason),
                accepted,
                "{reason:?}: the coordinator mints a group terminal capsule exactly when a \
                 member would act on it"
            );
        }

        // And a member who is not the coordinator mints nothing at all, whatever the reason:
        // that is the N−1 wakes per decline this removes.
        let member = Session {
            account: Some(
                crypto_core::create_account_with_username("carol", "Test-Password-123!")
                    .unwrap()
                    .0,
            ),
            ..Default::default()
        };
        for reason in EVERY_REASON {
            assert!(
                !group_terminal_capsule_worth_sending(&member, &coordinator, reason),
                "{reason:?}: a non-coordinator's leave has no capsule to send"
            );
        }
    }

    /// A-14: a verified signature is not an entitlement to end *this* call.
    ///
    /// `send_group_call_terminal_everywhere` mints a capsule for every member on **any**
    /// leave, including a plain decline. With no role check, one member declining
    /// tombstoned the whole logical call on every other member's device and cancelled their
    /// ring — on a locked phone, the only layer they have — and then suppressed the
    /// encrypted offer behind it. The encrypted path has always distinguished a
    /// coordinator's cancellation from a member's leave; so must this one.
    #[test]
    fn a_group_members_decline_does_not_end_the_ring_for_everyone_else() {
        let mut s = Session::default();
        as_me(&mut s);
        let (call, ring_id) = (random_call_id(), random_call_id());
        apply_capsule(
            &mut s,
            &group_capsule(CapsuleKind::Offer, &call, &ring_id, None, true),
        );
        assert!(s.call_store.ring(&call).is_some(), "the group ring is up");

        // Carol is in the group and knows the call id, because she was rung too.
        let carol = signed(
            "carol",
            CapsuleKind::Terminal,
            &call,
            &ring_id,
            Some(CallTerminalReason::DeclinedHere),
            true,
        );
        apply_capsule(&mut s, &carol);
        assert!(
            s.call_store.ring(&call).is_some(),
            "one member declining is not the call ending"
        );
        assert_eq!(
            s.calls().registry.terminal_reason(&call),
            None,
            "and it must not tombstone the call the rest are still being offered"
        );

        // The coordinator — who announced this ring — still ends it for everyone.
        apply_capsule(
            &mut s,
            &group_capsule(
                CapsuleKind::Terminal,
                &call,
                &ring_id,
                Some(CallTerminalReason::CallerCancelled),
                true,
            ),
        );
        assert!(s.call_store.ring(&call).is_none());
        assert_eq!(
            s.calls().registry.terminal_reason(&call),
            Some(CallTerminalReason::CallerCancelled)
        );
    }

    /// The 1:1 half of the same rule: "answered elsewhere" is a word about *our* devices,
    /// so a peer saying it is a peer editing our call log. A peer's own outcomes still
    /// apply — and still apply before the offer arrives, because `call_instance_id` is 128
    /// random bits only the parties to that call ever see.
    #[test]
    fn a_peer_may_announce_its_own_outcome_and_not_ours() {
        let mut s = Session::default();
        as_me(&mut s);
        let (call, offer) = (random_call_id(), random_call_id());
        apply_capsule(&mut s, &capsule(CapsuleKind::Offer, &call, &offer, None));
        apply_capsule(
            &mut s,
            &capsule(
                CapsuleKind::Terminal,
                &call,
                &offer,
                Some(CallTerminalReason::AnsweredElsewhere),
            ),
        );
        assert!(
            s.call_store.ring(&call).is_some(),
            "a peer does not get to say another of our devices answered"
        );
        apply_capsule(
            &mut s,
            &capsule(
                CapsuleKind::Terminal,
                &call,
                &offer,
                Some(CallTerminalReason::CallerCancelled),
            ),
        );
        assert!(s.call_store.ring(&call).is_none(), "hanging up is its own");
    }

    /// A capsule from an account we have not pinned — or one we blocked — has no signing
    /// key here, which is what refuses it before any state is touched.
    #[test]
    fn screening_supplies_no_key_for_an_unknown_or_blocked_caller() {
        let mut s = Session::default();
        s.history.pin_contact("mallory", "mallory-key", true);
        s.history
            .with_contact_mut("mallory", |pin| pin.blocked = true);
        let approved = capsule_signing_keys(&s);
        let from_mallory = capsule(
            CapsuleKind::Offer,
            &random_call_id(),
            &random_call_id(),
            None,
        );
        assert!(approved(&from_mallory).is_none());
    }
}
