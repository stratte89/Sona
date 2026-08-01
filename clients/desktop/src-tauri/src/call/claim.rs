//! The **caller's** side of the answer race: taking `CallAnswerClaimedV2` from each callee
//! device that picked up, and turning the claims into exactly one winner (`internal/CALL_PLAN.md`
//! §3.5).
//!
//! Ringing every device on an account means several may answer, and the arbiter — not the
//! order the claims happen to arrive in — decides which one gets the call. Everything here
//! is idempotent, because the same claim reaches it twice in the worst case: once when it
//! lands, and once when the buffer is replayed after the caller's own media room comes up
//! (E-6). [`super::signal`] owns the rest of the encrypted signalling; this is only the
//! stretch between a claim arriving and a winner going back out.

use super::auth::{same_peer, verified_sender_device};
use crate::*;

/// One `CallAnswerClaimedV2`, applied to the outbound call it names (§3.5).
///
/// Reached twice for the same claim in the worst case: once when it arrives, and once when
/// it is replayed after the media room comes up (E-6). Everything it decides is idempotent
/// under that — the arbiter answers `Duplicate` for a nonce it has already seen, and a
/// duplicate re-sends the same winner acknowledgement, which is what a caller owes a callee
/// whose first copy was lost anyway.
pub(crate) async fn apply_answer_claim(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    incoming: BufferedClaim,
) {
    let BufferedClaim {
        sender_identity_key,
        call_instance_id,
        offer_id,
        claim_nonce,
        answering_device_id,
        reply_to_mailbox,
        caps,
        expires_at,
    } = incoming;
    let mut s = inner.lock().await;
    if !client_core::callstate::valid_control_expiry(expires_at, now_secs()) {
        // Almost always a clock disagreement between the two devices rather than a stale
        // claim: the callee stamps `expires_at` from *its* clock and this is checked
        // against ours (E-14).
        crate::diag!(
            "[call] claim REFUSED: expiry {expires_at} invalid against local now {} \
             (clock skew between the devices?)",
            now_secs()
        );
        return;
    }
    let Some(call) = s.call.as_ref().filter(|call| {
        call.caller && call.call_instance_id == call_instance_id && call.offer_id == offer_id
    }) else {
        // E-6. `s.call` is installed at the *end* of `spawn_call`, after the mic open and
        // the room join, and the offers went out before any of that. A claim landing in
        // between used to be dropped here with no retry: no winner was ever sent, the callee
        // sat on "establishing secure connection…" until the signal TTL, and the caller went
        // on showing "ringing…". Being a race is why it was intermittent.
        //
        // Buffer it verbatim and replay it once the room is up, so every check below is
        // still made, against real call state, exactly once. Buffering is not deciding:
        // nothing here picks a winner or trusts a field.
        if let Some(setup) = s.outgoing_setup.as_mut().filter(|setup| {
            setup.call_instance_id == call_instance_id && setup.offer_id == offer_id
        }) {
            let buffered = setup.claims.len() < MAX_BUFFERED_CLAIMS;
            if buffered {
                setup.claims.push(BufferedClaim {
                    sender_identity_key,
                    call_instance_id,
                    offer_id,
                    claim_nonce,
                    answering_device_id,
                    reply_to_mailbox,
                    caps,
                    expires_at,
                });
            }
            crate::diag!(
                "[call] claim arrived before the room was up — {} (E-6)",
                if buffered {
                    "buffered for replay"
                } else {
                    "DROPPED, buffer full"
                }
            );
        } else {
            // No live call and no setup naming this call: the claim is for something this
            // device is not doing. Stale, or aimed at a call that already ended.
            crate::diag!(
                "[call] claim DROPPED: no outgoing call or setup matches it \
                 (has_call={}, has_setup={})",
                s.call.is_some(),
                s.outgoing_setup.is_some()
            );
        }
        return;
    };
    // E-14. Each check reported separately, because a dropped claim is the difference
    // between a call connecting and a callee sitting on "establishing secure connection…"
    // until the signal TTL — and all three used to fail into one silent `return`, on the
    // caller, where the callee can never see it either.
    let peer_ok = same_peer(&s.history, &sender_identity_key, &call.peer_key);
    let device_ok = verified_sender_device(
        &s.history,
        &call.peer_username,
        &sender_identity_key,
        &answering_device_id,
    );
    let derived_mailbox = client
        .device_mailbox(&call.peer_username, &answering_device_id)
        .ok();
    let mailbox_ok = derived_mailbox.as_deref() == Some(reply_to_mailbox.as_str());
    if !peer_ok || !device_ok || !mailbox_ok {
        crate::diag!(
            "[call] claim REFUSED from device {} — same_peer={peer_ok} \
             verified_device={device_ok} mailbox_matches={mailbox_ok} \
             (roster_pinned={}, expected_mailbox={}, claim_mailbox={})",
            crate::call::store_locked::mailbox_tag(&answering_device_id),
            s.history.pinned_roster(&call.peer_username).is_some(),
            derived_mailbox
                .as_deref()
                .map(crate::call::store_locked::mailbox_tag)
                .unwrap_or("<none>"),
            crate::call::store_locked::mailbox_tag(&reply_to_mailbox),
        );
        return;
    }
    let claim = client_core::callstate::AnswerClaim {
        call_instance_id: call_instance_id.clone(),
        offer_id: offer_id.clone(),
        claim_nonce,
        answering_device_id,
        reply_to_mailbox,
    };
    let (decision, peer_username, winner_identity_key) = {
        let call = s.call.as_mut().expect("checked above");
        let decision = call
            .answer_arbiter
            .as_mut()
            .expect("caller owns an arbiter")
            .claim(&claim);
        if matches!(decision, client_core::callstate::ClaimDecision::Winner(_)) {
            call.peer_media2.store(
                client_core::media::peer_supports_media2(&caps),
                std::sync::atomic::Ordering::Relaxed,
            );
            call.peer_device_key = sender_identity_key.clone();
            call.peer_reply_to_mailbox = claim.reply_to_mailbox.clone();
        }
        (
            decision,
            call.peer_username.clone(),
            call.peer_device_key.clone(),
        )
    };
    let winner = match decision {
        client_core::callstate::ClaimDecision::Winner(ref winner) => {
            let _ = s.calls().registry.transition(
                &call_instance_id,
                &offer_id,
                client_core::callstate::CallPhase::Winner,
                now_secs(),
            );
            winner.clone()
        }
        client_core::callstate::ClaimDecision::Duplicate(ref winner)
        | client_core::callstate::ClaimDecision::Lost(ref winner) => winner.clone(),
        client_core::callstate::ClaimDecision::Invalid => {
            // The arbiter refused it outright — wrong call/offer for this arbiter, or a
            // malformed claim. The callee waits out its whole signal TTL for a winner that
            // is never coming, so this must not be silent (E-14).
            crate::diag!("[call] claim REFUSED by the answer arbiter as Invalid");
            return;
        }
    };
    crate::diag!(
        "[call] claim accepted ({decision:?}) — sending winner to device {}",
        crate::call::store_locked::mailbox_tag(&winner.answering_device_id)
    );
    let _ = send_call_winner_everywhere(
        client,
        &mut s,
        &peer_username,
        &winner_identity_key,
        &call_instance_id,
        &offer_id,
        &winner.claim_nonce,
        &winner.answering_device_id,
        &winner.reply_to_mailbox,
    );
}

/// Replay the claims that arrived while the media room was coming up (E-6).
///
/// Called once, immediately after `spawn_call` installs `s.call`, and it always clears the
/// setup — a claim that cannot be applied now (expired, for a call that has since ended)
/// must not be held for the next call.
pub(crate) async fn replay_buffered_claims(inner: &Arc<Mutex<Session>>, client: &Arc<Client>) {
    let claims = {
        let mut s = inner.lock().await;
        match s.outgoing_setup.take() {
            Some(setup) => setup.claims,
            None => return,
        }
    };
    for claim in claims {
        apply_answer_claim(inner, client, claim).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_claim(call: &str, offer: &str, nonce: &str) -> BufferedClaim {
        BufferedClaim {
            sender_identity_key: "bob-key".into(),
            call_instance_id: call.into(),
            offer_id: offer.into(),
            claim_nonce: nonce.into(),
            answering_device_id: "0".into(),
            reply_to_mailbox: "b".repeat(64),
            caps: Vec::new(),
            expires_at: now_secs() + client_core::callstate::CALL_SIGNAL_TTL_SECS,
        }
    }

    /// E-6: a claim that beats the caller's own media room must not be thrown away.
    ///
    /// `call_start_inner` posts the offers, and only then runs `spawn_call` — a mic open and
    /// a room join, which the code itself calls the slower part — installing `s.call` at the
    /// end of it. The claim handler required `s.call` and silently returned otherwise, with
    /// no retry anywhere, so a callee that answered promptly got no winner: it sat on
    /// "establishing secure connection…" until the signal TTL while the caller went on
    /// showing "ringing…". Reported from both Linux and Android, intermittently, which is
    /// what a race looks like from the outside.
    ///
    /// The buffer is not a decision — nothing here picks a winner or trusts a field. It
    /// only preserves what the arbiter will be given once there is call state to check it
    /// against.
    #[tokio::test]
    async fn a_claim_that_beats_the_room_is_buffered_rather_than_dropped() {
        let client = Arc::new(Client::new("http://127.0.0.1:1", "ws://127.0.0.1:1", ""));
        let inner: Arc<Mutex<Session>> = Arc::default();
        let call = client_core::callstate::random_call_id();
        let offer = client_core::callstate::random_call_id();
        {
            let mut s = inner.lock().await;
            s.client = Some(client.clone());
            // Exactly the window the offers go out in: reserved, no `s.call` yet.
            s.outgoing_setup = Some(OutgoingSetup {
                call_instance_id: call.clone(),
                offer_id: offer.clone(),
                claims: Vec::new(),
            });
        }

        apply_answer_claim(&inner, &client, a_claim(&call, &offer, "n1")).await;
        assert_eq!(
            inner
                .lock()
                .await
                .outgoing_setup
                .as_ref()
                .unwrap()
                .claims
                .len(),
            1,
            "the claim must survive the window instead of being dropped on the floor"
        );

        // A claim for some other call is not ours to hold.
        apply_answer_claim(
            &inner,
            &client,
            a_claim(&client_core::callstate::random_call_id(), &offer, "n2"),
        )
        .await;
        assert_eq!(
            inner
                .lock()
                .await
                .outgoing_setup
                .as_ref()
                .unwrap()
                .claims
                .len(),
            1,
            "only claims naming this exact call and offer are buffered"
        );

        // Bounded: a peer that floods claims while the room comes up cannot grow this.
        for i in 0..(MAX_BUFFERED_CLAIMS * 2) {
            apply_answer_claim(&inner, &client, a_claim(&call, &offer, &format!("f{i}"))).await;
        }
        assert_eq!(
            inner
                .lock()
                .await
                .outgoing_setup
                .as_ref()
                .unwrap()
                .claims
                .len(),
            MAX_BUFFERED_CLAIMS
        );

        // Replay always clears the setup, so nothing is carried into the next call. (With
        // no `s.call` installed here the claims cannot be applied — the point being asserted
        // is that they do not linger.)
        replay_buffered_claims(&inner, &client).await;
        assert!(inner.lock().await.outgoing_setup.is_none());
    }

    /// The buffer belongs to the setup, so locking mid-start drops it with everything else.
    #[tokio::test]
    async fn locking_during_a_call_start_drops_the_claim_buffer() {
        let inner: Arc<Mutex<Session>> = Arc::default();
        {
            let mut s = inner.lock().await;
            s.outgoing_setup = Some(OutgoingSetup {
                call_instance_id: client_core::callstate::random_call_id(),
                offer_id: client_core::callstate::random_call_id(),
                claims: vec![a_claim("c", "o", "n")],
            });
        }
        crate::do_lock(&inner).await;
        assert!(inner.lock().await.outgoing_setup.is_none());
    }
}
