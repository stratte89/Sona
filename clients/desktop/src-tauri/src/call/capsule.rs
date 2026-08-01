//! The **second delivery layer** for an incoming call, wired into the shell: minimal
//! call-control capsules sealed to each recipient device's call-control key.
//!
//! A capsule rides *beside* the ordinary encrypted offer, never instead of it. Both name
//! the same `call_instance_id` and the same `offer_id`, so the two layers converge on one
//! [`CallRegistry`](client_core::callstate::CallRegistry) record — one ring — and a
//! terminal that arrives on either layer ends the call on both.
//!
//! This module is the **fetching** half of receiving: draining this device's call-control
//! mailbox with the vault open, polling it while a call rings out, and relaying a locked
//! callee's refusal onward. What may then be acted on, by whom, and how it converges with
//! the call state the encrypted layer keeps is [`super::capsule_apply`]; the same drain
//! with the vault **locked** is [`super::store_locked`]. [`super::capsule_send`] is the
//! sending half — warming keys, minting, sealing, posting.
//!
//! What it deliberately does not own: presenting a ring from a capsule alone. A capsule
//! carries no media capability, so a ring raised from one cannot be answered until the
//! encrypted offer arrives — which on Android is the Core-Telecom + unlock-to-answer work
//! (`internal/CALL_PLAN.md` §7, §8). Until then a capsule offer converges silently and a capsule
//! terminal does the reliability work: it cancels a live ring and tombstones a late offer.

use crate::*;
use client_core::callcapsule::{CallCapsule, CapsuleKind};

/// Drain this device's call-control mailbox and converge what it holds with call state.
///
/// Runs with the session lock released across the drain itself. The signing key each
/// capsule is checked against comes from the pinned KT-verified roster, so a caller we
/// cannot place — or one that is blocked — is refused and simply acked away.
pub(crate) async fn drain_call_capsules(inner: &Arc<Mutex<Session>>, client: &Arc<Client>) {
    let (call_key, username, device_id) = {
        let s = inner.lock().await;
        if !is_current(&s, client) || s.history.revoked() {
            return;
        }
        let (Some(call_key), Some(account)) = (s.call_key.as_ref(), s.account.as_ref()) else {
            if s.account.is_some() {
                crate::diag!("[capsule] drain: no call-control identity on this device");
            }
            return; // no call-control identity, or locked: the store owns that path
        };
        (
            call_key.clone(),
            account.account_id().to_string(),
            s.history.self_device_id(),
        )
    };
    let approved = {
        let s = inner.lock().await;
        capsule_signing_keys(&s)
    };
    let drained = client
        .drain_verified_capsules(&call_key, &username, &device_id, now_secs(), approved)
        .await;
    let (capsules, stats) = match drained {
        Ok(drained) => drained,
        Err(error) => {
            crate::diag!("[capsule] drain: mailbox fetch failed: {error}");
            return;
        }
    };
    if stats.fetched > 0 {
        crate::diag!(
            "[capsule] drain: fetched={} decoded={} accepted={} refused_unplaceable={} \
             refused_signature={}",
            stats.fetched,
            stats.decoded,
            stats.accepted(),
            stats.refused_unplaceable,
            stats.refused_signature
        );
    }
    if stats.dropped_everything() {
        crate::diag!(
            "[capsule] drain: DROPPED ALL {} fetched capsules — screening placed none of \
             their signers",
            stats.fetched
        );
    }
    if capsules.is_empty() {
        return;
    }
    let mut s = inner.lock().await;
    if !is_current(&s, client) {
        crate::diag!(
            "[capsule] drain: session replaced mid-drain — discarding {} already-acked capsules",
            capsules.len()
        );
        return;
    }
    for capsule in &capsules {
        // E-19. A **locked** callee can only tell the caller. Noted before the capsule is
        // applied, because applying it takes `s.call` away.
        let relay = caller_relay_for(&s, capsule);
        apply_capsule(&mut s, capsule);
        if let Some((peer_username, peer_key, offer_id)) = relay {
            send_call_terminal_everywhere(
                &client,
                &mut s,
                &peer_username,
                &peer_key,
                &capsule.call_instance_id,
                &offer_id,
                client_core::callstate::CallTerminalReason::DeclinedElsewhere,
            );
        }
    }
    let _ = s.persist();
}

/// Does this capsule oblige us, as the **caller**, to cancel the rest of our own ring
/// fan-out? (E-19)
///
/// A callee that declines while locked signs with its call-control key, and that key may
/// only address the one mailbox the offer capsule named — the caller's. It cannot reach the
/// callee's *other* devices: sealing a capsule to a sibling needs that sibling's published
/// call key, and a locked device holds only the screening index, which stores signing keys
/// for verification and no encryption keys at all. Its roster is in the vault.
///
/// So the caller has to finish the job. It rang every one of those devices and holds the
/// verified roster, and it already does exactly this when *it* hangs up — that path calls
/// `send_call_terminal_everywhere` and stops every device, which is why a caller hangup
/// cancels both and a locked decline used to cancel only one. Measured 2026-08-01: the
/// caller's call ended and the callee's desktop rang on to its own timeout.
///
/// `DeclinedElsewhere`, not `DeclinedHere`: the devices being told did not decline anything,
/// another of their siblings did — which is exactly what that reason means everywhere else.
fn caller_relay_for(s: &Session, capsule: &CallCapsule) -> Option<(String, String, String)> {
    if capsule.kind != CapsuleKind::Terminal {
        return None;
    }
    // Only a callee-side refusal. An "answered elsewhere" is a *sibling* of ours and is
    // already fanned by `ring_terminal_selfsync`; a caller-cancelled is our own doing.
    if !matches!(
        capsule.reason,
        Some(client_core::callstate::CallTerminalReason::DeclinedHere)
            | Some(client_core::callstate::CallTerminalReason::Busy)
    ) {
        return None;
    }
    let call = s
        .call
        .as_ref()
        .filter(|call| call.caller && call.call_instance_id == capsule.call_instance_id)?;
    Some((
        call.peer_username.clone(),
        call.peer_key.clone(),
        call.offer_id.clone(),
    ))
}

/// How often a caller re-reads its call-control mailbox while a call is ringing out.
///
/// The main delivery socket subscribes to the *message* mailbox; the call-control one is a
/// separate, short-lived connection. A callee whose vault is locked can only answer on
/// that layer (§3.4), so during the ring window — and only then — the caller polls it.
/// Outside a ringing call the ordinary unlock and push-wake drains are enough.
const RINGING_CAPSULE_POLL_SECS: u64 = 5;

/// Collect capsule replies while `call_instance_id` is ringing out.
///
/// Stops as soon as the call is no longer ringing out (answered, ended, or gone) and never
/// runs past the signal deadline. Best effort: a failed drain is one poll missed, and the
/// caller's own ring timeout still bounds the call.
pub(crate) fn spawn_ringing_capsule_poll(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    call_instance_id: String,
    until: u64,
) {
    let inner = inner.clone();
    let client = client.clone();
    eng().spawn(async move {
        while now_secs() < until {
            tokio::time::sleep(std::time::Duration::from_secs(RINGING_CAPSULE_POLL_SECS)).await;
            {
                let s = inner.lock().await;
                if !is_current(&s, &client) || s.call_key.is_none() {
                    return;
                }
                let ringing = s.call.as_ref().is_some_and(|call| {
                    call.call_instance_id == call_instance_id
                        && !call.connected.load(std::sync::atomic::Ordering::Relaxed)
                }) || s.group_call.as_ref().is_some_and(|call| {
                    call.call_instance == call_instance_id
                        && call.connected.lock().unwrap().is_empty()
                });
                if !ringing {
                    return;
                }
            }
            drain_call_capsules(&inner, &client).await;
        }
    });
}
