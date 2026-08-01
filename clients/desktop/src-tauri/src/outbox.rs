use crate::*;

fn schedule_call_outbox_retry(client: Arc<Client>, due_at: u64) {
    let inner = eng().session.clone();
    eng().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            due_at.saturating_sub(now_secs()),
        ))
        .await;
        drain_call_outbox(&inner, &client).await;
    });
}

/// Queue call controls before their first network attempt, then remove only relay-
/// accepted copies. Failures remain encrypted in the short-lived bounded outbox and are
/// retried on their backoff deadline.
pub(crate) fn post_call_controls(
    client: &Arc<Client>,
    s: &mut Session,
    envelopes: &[client_core::Envelope],
) -> Vec<Result<(), String>> {
    if envelopes.is_empty() {
        return Vec::new();
    }
    let now = now_secs();
    let queued = s.history.call_outbox_push(envelopes, now);
    if let Err(error) = s.persist() {
        return (0..envelopes.len()).map(|_| Err(error.clone())).collect();
    }
    // The first attempt uses the same unlocked drain as every retry. Callers commonly
    // hold `Session` while constructing control state; scheduling instead of posting
    // here guarantees HTTP never extends that critical section.
    schedule_call_outbox_retry(client.clone(), now);
    queued
        .into_iter()
        .map(|queued| {
            if queued {
                Ok(())
            } else {
                Err("call control was rejected by the durable outbox".into())
            }
        })
        .collect()
}

/// Retry due call controls without holding the session mutex over relay posts.
pub(crate) async fn drain_call_outbox(inner: &Arc<Mutex<Session>>, client: &Arc<Client>) {
    let due = {
        let mut s = inner.lock().await;
        if !s
            .client
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, client))
        {
            return;
        }
        if s.history.call_outbox_reap(now_secs()) > 0 {
            let _ = s.persist();
        }
        s.history.call_outbox_due(now_secs())
    };
    if due.is_empty() {
        return;
    }
    let posted = client.post_envelopes_concurrent(&due).await;
    let attempted: Vec<_> = due
        .into_iter()
        .zip(posted.iter().map(Result::is_ok))
        .collect();
    let next_due = {
        let mut s = inner.lock().await;
        s.history.call_outbox_settle(&attempted, now_secs());
        let next_due = s.history.call_outbox_next_due(now_secs());
        let _ = s.persist();
        next_due
    };
    if let Some(due_at) = next_due {
        schedule_call_outbox_retry(client.clone(), due_at);
    }
}
