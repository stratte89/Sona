use super::*;

/// Why a message did or did not earn a push wake (E-10).
///
/// The relay used to make this decision and then forget it instantly: `fire_wake` is
/// fire-and-forget and only a `DeadToken` reaction is visible, by way of a push row
/// disappearing. So "the phone never rang" was unattributable from either end — a device
/// cannot report a wake it never received, and the relay said nothing about having tried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WakeDecision {
    /// A wake is going out to this endpoint.
    Claimed(String),
    /// This class never wakes anyone (receipts, typing, reactions, unrelated self-sync).
    ClassSilent,
    /// A live subscriber already holds this mailbox, so there is nothing to wake.
    SubscriberLive,
    /// The recipient has no push registration at all.
    Unregistered,
    /// Refused by the per-class budget: `wake_debounce_secs`, `call_wake_min_secs`, or the
    /// `CallControl` token bucket.
    Budgeted,
}

impl WakeDecision {
    fn tag(&self) -> &'static str {
        match self {
            WakeDecision::Claimed(_) => "claimed",
            WakeDecision::ClassSilent => "skipped=class-silent",
            WakeDecision::SubscriberLive => "skipped=subscriber-live",
            WakeDecision::Unregistered => "skipped=unregistered",
            WakeDecision::Budgeted => "refused=budget",
        }
    }
}

/// Is wake logging switched on? (`WAKE_LOG=1`)
///
/// **Off by default, and deliberately.** This is a blind relay: it carries ciphertext it
/// cannot read, and its journal must not quietly become a delivery-metadata archive
/// recording who was woken and when. That is exactly the retention `internal/CALL_PLAN.md` §4.5
/// requires honesty about. The operator of a relay debugging their own device can turn it
/// on; nobody's traffic is described without someone choosing it.
///
/// Even switched on it stays content-free: a truncated recipient hash, the wake class, and
/// the decision. Never a payload, a size, or a sender.
pub(crate) fn wake_log_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("WAKE_LOG").is_ok_and(|v| v != "0" && !v.is_empty()))
}

/// Lines per second, so a flood cannot turn the journal into the DoS.
const WAKE_LOG_PER_SEC: u32 = 20;

/// Spend a log slot for this second, reporting how many were suppressed when the second
/// rolls over — a silent cap would be its own dishonesty.
fn wake_log_slot(t: u64) -> Option<u32> {
    use std::sync::Mutex;
    static WINDOW: Mutex<(u64, u32)> = Mutex::new((0, 0));
    let mut w = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    if w.0 != t {
        let suppressed = w.1.saturating_sub(WAKE_LOG_PER_SEC);
        *w = (t, 1);
        return Some(suppressed);
    }
    w.1 = w.1.saturating_add(1);
    (w.1 <= WAKE_LOG_PER_SEC).then_some(0)
}

/// One content-free line per wake decision.
pub(crate) fn log_wake(
    recipient: &IdentityHash,
    class: WakeClass,
    decision: &WakeDecision,
    t: u64,
) {
    if !wake_log_enabled() {
        return;
    }
    let Some(suppressed) = wake_log_slot(t) else {
        return;
    };
    let hash = recipient.as_str();
    let short = &hash[..hash.len().min(8)];
    if suppressed > 0 {
        println!("[wake] {suppressed} line(s) suppressed by the per-second cap");
    }
    println!("[wake] {short} class={class:?} {}", decision.tag());
}

pub(crate) async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut env): Json<Envelope>,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let t = now();
    // Enforce the server-side TTL ceiling before the message is stored anywhere, so both
    // the in-memory queue and the durable DB agree on a bounded expiry (M-3). A client
    // that sends `expires_at: None` gets the default ceiling, not an immortal message.
    env.expires_at = Some(crate::store::clamp_expiry(t, env.expires_at));

    // Collect any live delivery channels for the recipient while holding the lock,
    // then release it before doing the (async) sends. If the recipient is offline and
    // has a push subscription, claim a per-class (debounced) wake slot under the same
    // lock — see `claim_wake`.
    let wake_class = env.wake;
    let recipient = env.to.clone();
    let (live_senders, wake) = {
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&key, t) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
        let to = env.to.clone();
        match inner.store.enqueue(env.clone(), t) {
            Ok(true) => {}
            // Idempotent: the relay already holds this exact message (an at-least-once
            // retry after a lost ACK) or it arrived already-expired. Success, but there
            // is nothing new to persist, deliver live, or wake for — the first arrival
            // did all that. Returning 200 here is what stops the sender showing "Not
            // sent" for a message the recipient already received.
            Ok(false) => return StatusCode::ACCEPTED.into_response(),
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        }
        // Persist the queued message (envelope encrypted at rest) for offline durability.
        if let Some(db) = &inner.db {
            let _ = db.insert_message(&env, env.expires_at);
        }
        let live = inner.live.get(to.as_str()).cloned().unwrap_or_default();
        // Each outcome is named rather than collapsed into `Option` (E-10): "nobody is
        // registered", "a subscriber is already here", and "the budget refused it" are three
        // different answers to "why did the phone not ring", and they were indistinguishable.
        let wake = if wake_class == WakeClass::None {
            WakeDecision::ClassSilent
        } else if !live.is_empty() {
            WakeDecision::SubscriberLive
        } else {
            match inner.push.get_mut(to.as_str()) {
                None => WakeDecision::Unregistered,
                Some(sub) => match claim_wake(sub, wake_class, t, &state.config) {
                    Some(endpoint) => WakeDecision::Claimed(endpoint),
                    None => WakeDecision::Budgeted,
                },
            }
        };
        (live, wake)
    };
    log_wake(&recipient, wake_class, &wake, t);

    // Best-effort live push. If the recipient is offline this is simply empty and the
    // message waits in the store until they connect.
    if !live_senders.is_empty() {
        if let Ok(frame) = serde_json::to_string(&ServerFrame::Message { envelope: env }) {
            for s in live_senders {
                let _ = s.send(frame.clone());
            }
        }
    }

    // Content-free wake for an offline recipient: constant per-class body,
    // fire-and-forget. The response never waits on the push provider.
    if let WakeDecision::Claimed(endpoint) = wake {
        fire_wake(&state, recipient, endpoint, wake_class);
    }
    StatusCode::ACCEPTED.into_response()
}

/// Control wakes allowed back to back, before the refill rate applies.
///
/// One answered call produces a handful — the winner, the terminal to the caller, the
/// sibling self-terminals — usually inside the same second, and dropping any of them can
/// leave a phone ringing. Eight covers that with room to spare and still bounds a sender
/// that simply keeps posting.
pub(crate) const CONTROL_WAKE_BURST: u32 = 8;

/// Spend one call-control wake against this recipient's bucket, refilling it first.
///
/// A plain min-interval was the wrong shape: a real call's controls arrive together, and a
/// second-resolution throttle merges exactly the burst that must not be merged. A bucket
/// separates the two cases — a call's worth of controls passes at once, a stream does not.
fn control_budget(sub: &mut PushSub, t: u64, config: &Config) -> bool {
    let interval = config.control_wake_min_secs.max(1);
    let repaid = t.saturating_sub(sub.last_wake_control) / interval;
    sub.control_wake_debt = sub
        .control_wake_debt
        .saturating_sub(repaid.min(u64::from(u32::MAX)) as u32);
    if sub.control_wake_debt >= CONTROL_WAKE_BURST {
        return false;
    }
    sub.control_wake_debt += 1;
    sub.last_wake_control = t;
    true
}

/// Decide whether this envelope earns a wake for `sub`, stamping the per-class
/// timestamp when it does. Pure per-subscription policy:
/// * `None`   — never wake (receipts, typing, self-sync traffic).
/// * `Normal` — debounced by `wake_debounce_secs` (a burst rides one wake).
/// * `Call`   — bypasses the message debounce; own tiny min-interval
///   (`call_wake_min_secs`) so offer spam can't become a battery DoS.
/// * `CallControl` — a token bucket of its own ([`control_budget`]), so a cancellation is
///   never swallowed by a ring-offer's debounce, one call's controls all get through, and
///   a flood is still bounded.
pub(crate) fn claim_wake(
    sub: &mut PushSub,
    class: WakeClass,
    t: u64,
    config: &Config,
) -> Option<String> {
    let due = match class {
        WakeClass::None => false,
        WakeClass::Normal => t.saturating_sub(sub.last_wake_normal) >= config.wake_debounce_secs,
        WakeClass::Call => t.saturating_sub(sub.last_wake_call) >= config.call_wake_min_secs,
        WakeClass::CallControl => control_budget(sub, t, config),
    };
    if !due {
        return None;
    }
    match class {
        WakeClass::Normal => sub.last_wake_normal = t,
        WakeClass::Call => sub.last_wake_call = t,
        WakeClass::CallControl => {} // spent inside `control_budget`
        WakeClass::None => unreachable!("None is never due"),
    }
    Some(sub.endpoint.clone())
}

/// What the transport did with a wake the relay claimed and sent (E-10).
pub(crate) fn log_wake_outcome(
    recipient: &IdentityHash,
    class: WakeClass,
    outcome: crate::push::WakeOutcome,
) {
    if !wake_log_enabled() {
        return;
    }
    let Some(_) = wake_log_slot(now()) else {
        return;
    };
    let hash = recipient.as_str();
    let short = &hash[..hash.len().min(8)];
    let tag = match outcome {
        crate::push::WakeOutcome::Sent => "sent",
        crate::push::WakeOutcome::DeadToken => "dead-token (push row dropped)",
        crate::push::WakeOutcome::Transient => "transport-failed (dropped)",
    };
    println!("[wake] {short} class={class:?} {tag}");
}

/// Dispatch one wake to its transport: `fcm:<token>` endpoints go through the FCM
/// adapter (which self-heals dead tokens by dropping the push row); anything else is
/// the webhook POST with the constant per-class body. Fire-and-forget either way.
pub(crate) fn fire_wake(
    state: &AppState,
    recipient: IdentityHash,
    endpoint: String,
    class: WakeClass,
) {
    if let Some(token) = endpoint.strip_prefix("fcm:") {
        let Some(fcm) = state.fcm.clone() else {
            return; // registration was gated on config, so this can't happen in practice
        };
        let token = token.to_string();
        let state = state.clone();
        let endpoint_full = endpoint.clone();
        tokio::spawn(async move {
            let outcome = fcm.wake(&token, class).await;
            // The transport's answer, which nothing recorded before (E-10). A wake the
            // relay claimed, sent, and had refused or dropped by FCM looked exactly like a
            // wake that arrived — from here *and* from the device, which cannot report
            // something it never received.
            log_wake_outcome(&recipient, class, outcome);
            if outcome == crate::push::WakeOutcome::DeadToken {
                let mut inner = state.inner.lock().unwrap();
                // Remove only if the row still holds this exact token (the device may
                // have re-registered a fresh one meanwhile).
                let stale = inner
                    .push
                    .get(recipient.as_str())
                    .is_some_and(|s| s.endpoint == endpoint_full);
                if stale {
                    inner.push.remove(recipient.as_str());
                    if let Some(db) = &inner.db {
                        let _ = db.delete_push(recipient.as_str());
                    }
                }
            }
        });
    } else {
        let body = class.wake_body();
        tokio::spawn(async move {
            let sent = crate::http::push::push_client()
                .post(endpoint)
                .body(body)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            // A UnifiedPush distributor that refuses or is unreachable was silent too
            // (E-10) — and on a de-Googled phone this is the *only* wake transport, so it
            // is the one whose failures matter most.
            log_wake_outcome(
                &recipient,
                class,
                if sent {
                    crate::push::WakeOutcome::Sent
                } else {
                    crate::push::WakeOutcome::Transient
                },
            );
        });
    }
}

#[cfg(test)]
mod wake_log_tests {
    use super::*;

    /// E-10: the per-second cap must say what it swallowed.
    ///
    /// A log that silently drops lines under load is its own dishonesty — the operator
    /// reading it cannot tell "nothing happened" from "too much happened", which is the
    /// exact confusion this whole facility exists to remove.
    #[test]
    fn the_wake_log_cap_reports_what_it_suppressed() {
        // A second of its own, so the shared window cannot be disturbed by another test.
        let t = 4_000_000_000;
        assert_eq!(
            wake_log_slot(t),
            Some(0),
            "the first line of a new second always gets through"
        );
        for _ in 1..WAKE_LOG_PER_SEC {
            assert_eq!(wake_log_slot(t), Some(0));
        }
        assert_eq!(wake_log_slot(t), None, "past the cap, lines are dropped");
        assert_eq!(wake_log_slot(t), None);
        // Rolling over reports the two that were dropped, and starts counting again.
        assert_eq!(wake_log_slot(t + 1), Some(2));
    }

    /// Each outcome is its own answer to "why did the phone not ring". Collapsing any two
    /// of them is what made the last device round unreadable.
    #[test]
    fn every_wake_decision_is_distinguishable() {
        let tags = [
            WakeDecision::Claimed(String::new()).tag(),
            WakeDecision::ClassSilent.tag(),
            WakeDecision::SubscriberLive.tag(),
            WakeDecision::Unregistered.tag(),
            WakeDecision::Budgeted.tag(),
        ];
        let unique: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len());
    }

    /// Off unless the operator asks for it: a blind relay's journal must not become a
    /// delivery-metadata archive by default (`internal/CALL_PLAN.md` §4.5).
    #[test]
    fn wake_logging_is_opt_in() {
        if std::env::var("WAKE_LOG").is_err() {
            assert!(!wake_log_enabled());
        }
    }
}
