use super::*;

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
    let (live_senders, wake_endpoint) = {
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&key, t) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
        let to = env.to.clone();
        match inner.store.enqueue(env.clone(), t) {
            Ok(()) => {}
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        }
        // Persist the queued message (envelope encrypted at rest) for offline durability.
        if let Some(db) = &inner.db {
            let _ = db.insert_message(&env, env.expires_at);
        }
        let live = inner.live.get(to.as_str()).cloned().unwrap_or_default();
        let wake = if live.is_empty() {
            inner
                .push
                .get_mut(to.as_str())
                .and_then(|sub| claim_wake(sub, wake_class, t, &state.config))
        } else {
            None
        };
        (live, wake)
    };

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
    if let Some(endpoint) = wake_endpoint {
        fire_wake(&state, recipient, endpoint, wake_class);
    }
    StatusCode::ACCEPTED.into_response()
}

/// Decide whether this envelope earns a wake for `sub`, stamping the per-class
/// timestamp when it does. Pure per-subscription policy:
/// * `None`   — never wake (receipts, typing, self-sync traffic).
/// * `Normal` — debounced by `wake_debounce_secs` (a burst rides one wake).
/// * `Call`   — bypasses the message debounce; own tiny min-interval
///   (`call_wake_min_secs`) so offer spam can't become a battery DoS.
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
    };
    if !due {
        return None;
    }
    match class {
        WakeClass::Normal => sub.last_wake_normal = t,
        WakeClass::Call => sub.last_wake_call = t,
        WakeClass::None => unreachable!("None is never due"),
    }
    Some(sub.endpoint.clone())
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
            if fcm.wake(&token, class).await == crate::push::WakeOutcome::DeadToken {
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
        let body = match class {
            WakeClass::Call => WAKE_BODY_CALL,
            _ => WAKE_BODY,
        };
        tokio::spawn(async move {
            let _ = crate::http::push::push_client()
                .post(endpoint)
                .body(body)
                .send()
                .await;
        });
    }
}
