//! The blind message store: holds opaque ciphertext for offline recipients, keyed
//! only by [`IdentityHash`]. No crypto, no plaintext, no sender index.
//!
//! Invariants (all fail-closed):
//! * Reject any envelope that is not zero-knowledge clean (carries a raw identifier).
//! * Route only by recipient hash; never store or index by sender.
//! * Cap per-mailbox depth so one recipient cannot be used to exhaust storage.
//! * Drop expired messages on access (TTL ceiling).

use std::collections::HashMap;

use protocol_types::{Envelope, IdentityHash};

/// Max undelivered messages held per recipient mailbox — a **backstop on count**, not
/// the primary bound; [`MAX_MAILBOX_BYTES`] is. Over either limit the mailbox evicts its
/// oldest arrivals rather than refusing new mail (see [`MessageStore::enqueue`]).
///
/// It used to be 100 with a hard refusal on top, which turned every mailbox into a
/// per-user resource with a public address and 100 units of headroom (SP-03): `POST
/// /v1/messages` is unauthenticated by design (sealed sender) and the mailbox hash is
/// computable from the username, so ~100 junk envelopes — about two minutes from one IP
/// under the 60/min limiter — made every legitimate sender see a hard `400` and the
/// victim's contacts see "Not sent", for up to the 30-day TTL if the victim's phone
/// stayed off.
pub const MAX_MAILBOX_DEPTH: usize = 2_000;

/// Max total ciphertext held per recipient mailbox. This is the real bound: filling it
/// costs the attacker real bandwidth instead of 100 tiny requests, and going over it
/// degrades the *oldest* mail rather than blocking new mail.
///
/// Sized far above any legitimate backlog. Envelopes carry ciphertext only —
/// attachments live in blob storage — and the REST body limit is 64 KiB, so a real
/// offline backlog is hundreds of KiB at the very most.
pub const MAX_MAILBOX_BYTES: usize = 4 * 1024 * 1024;

/// Server-side maximum message time-to-live. Every stored envelope is clamped to at most
/// `now + MAX_MESSAGE_TTL_SECS`, and a message with no client-set expiry defaults to it.
/// This guarantees mailboxes drain even if a client sets `expires_at: None`, so undelivered
/// state can't accumulate forever (M-3). 30 days is generous for offline delivery.
pub const MAX_MESSAGE_TTL_SECS: u64 = 30 * 24 * 3600;

/// Hard cap on the number of distinct recipient mailboxes held in memory. Per-mailbox
/// depth is already capped; this bounds the *count* so a flood to millions of random
/// recipient hashes can't exhaust memory (M-3). Large enough not to bite real deployments.
pub const MAX_MAILBOXES: usize = 500_000;

/// Clamp a message's absolute expiry to the server ceiling. `None` (client set no expiry)
/// becomes the default ceiling; anything later than the ceiling is pulled back to it.
pub fn clamp_expiry(now: u64, requested: Option<u64>) -> u64 {
    let ceiling = now.saturating_add(MAX_MESSAGE_TTL_SECS);
    match requested {
        Some(exp) => exp.min(ceiling),
        None => ceiling,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayError {
    #[error("rejected: envelope carries a raw identifier (zero-knowledge violation)")]
    ZkViolation,
    /// One envelope on its own does not fit a mailbox's whole byte budget. Not reachable
    /// by a flood — eviction handles those — so this stays an honest client error.
    #[error("rejected: message is too large for a mailbox")]
    MailboxFull,
    #[error("rejected: relay is at capacity")]
    StoreFull,
}

/// What one envelope costs against a mailbox's byte budget: the ciphertext plus a fixed
/// allowance for the routing fields and per-entry overhead. Approximate on purpose — the
/// budget is a resource bound, not an accounting ledger, and re-serializing every
/// envelope to measure it exactly would cost more than it is worth.
fn envelope_bytes(env: &Envelope) -> usize {
    env.ciphertext.len() + env.msg_id.len() + 256
}

/// The outcome of a successful [`MessageStore::enqueue`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stored {
    /// `true` = newly stored; `false` = nothing new (an already-expired message, or an
    /// idempotent duplicate the relay already holds).
    pub stored: bool,
    /// Ids evicted from the mailbox to make room, oldest first. The caller must delete
    /// these from durable storage too, or a restart would reload what was evicted.
    pub evicted: Vec<String>,
}

/// In-memory blind message store. Keyed only by recipient hash.
#[derive(Default)]
pub struct MessageStore {
    mailboxes: HashMap<String, Vec<Envelope>>,
}

impl MessageStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept an envelope for later delivery. `now` is unix-seconds (injected so the
    /// logic is testable without a clock). Enforces every relay invariant, fail-closed.
    ///
    /// [`Stored::stored`] is `false` for an already-expired message or an **idempotent
    /// duplicate** the relay already holds. Delivery is at-least-once: a client whose ACK
    /// was lost retries the same `msg_id`, and a message the recipient already received
    /// must return success, not an error — otherwise the sender shows "Not sent" for a
    /// message that went through. The caller skips the live push, the wake, and the DB
    /// write in that case.
    ///
    /// **Over-capacity evicts instead of refusing (SP-03).** A full mailbox used to hard-
    /// refuse, which handed anyone who could spell a username a delivery-denial primitive:
    /// sealed sender means the relay cannot attribute the flood to anyone, so the only
    /// thing it can change is the resource shape. Now the mailbox is bounded by bytes
    /// (plus a count backstop) and sheds its **oldest arrivals** to make room. Oldest-first
    /// is the one eviction order that helps: a flood is old by the time the message it was
    /// meant to block arrives, and time-critical traffic (call offers, terminals) is always
    /// the newest thing in the mailbox. It is not free — a determined flood can still push
    /// a genuine queued message out — but "expensive and lossy" beats "cheap and total",
    /// and honest senders keep getting `202` and real delivery instead of a hard failure.
    pub fn enqueue(&mut self, mut env: Envelope, now: u64) -> Result<Stored, RelayError> {
        if !env.is_zk_clean() {
            return Err(RelayError::ZkViolation);
        }
        // Defensive TTL ceiling (also enforced at the HTTP boundary): no message may
        // outlive `now + MAX_MESSAGE_TTL_SECS`, and a missing expiry gets the default.
        env.expires_at = Some(clamp_expiry(now, env.expires_at));
        // An already-expired message is silently dropped — nothing to store, and it
        // is not the sender's error that the recipient was slow to come online.
        if matches!(env.expires_at, Some(exp) if exp <= now) {
            return Ok(Stored::default());
        }
        let cost = envelope_bytes(&env);
        // One message that cannot fit an empty mailbox is a client bug, not a flood.
        if cost > MAX_MAILBOX_BYTES {
            return Err(RelayError::MailboxFull);
        }

        // Bound the number of distinct mailboxes: a brand-new recipient hash is refused
        // once the relay is at capacity (existing mailboxes still accept up to their depth).
        let key = env.to.as_str().to_string();
        if !self.mailboxes.contains_key(&key) && self.mailboxes.len() >= MAX_MAILBOXES {
            return Err(RelayError::StoreFull);
        }
        let mailbox = self.mailboxes.entry(key).or_default();
        // Already holding this exact message: idempotent success (a retry after a lost
        // ACK), NOT a rejection. Re-storing would double-deliver; erroring would strand
        // a delivered message as "Not sent" on the sender. Checked before any eviction so
        // a retry can never cost the mailbox a message.
        if mailbox.iter().any(|m| m.msg_id == env.msg_id) {
            return Ok(Stored::default());
        }
        // Shed oldest-first until the newcomer fits. Expired entries go first and for
        // free — they were already dead, they just had not been swept yet.
        mailbox.retain(|m| !matches!(m.expires_at, Some(exp) if exp <= now));
        let mut held: usize = mailbox.iter().map(envelope_bytes).sum();
        let mut evicted = Vec::new();
        while (held + cost > MAX_MAILBOX_BYTES || mailbox.len() >= MAX_MAILBOX_DEPTH)
            && !mailbox.is_empty()
        {
            let old = mailbox.remove(0);
            held -= envelope_bytes(&old);
            evicted.push(old.msg_id);
        }
        mailbox.push(env);
        Ok(Stored {
            stored: true,
            evicted,
        })
    }

    /// Drop every expired message and any mailbox left empty. Called by the relay's
    /// periodic reaper so delivered/expired state doesn't linger in memory (M-3).
    pub fn prune(&mut self, now: u64) {
        self.mailboxes.retain(|_, mailbox| {
            mailbox.retain(|m| !matches!(m.expires_at, Some(exp) if exp <= now));
            !mailbox.is_empty()
        });
    }

    /// Fetch all currently-valid messages for a recipient, pruning anything expired.
    /// Does NOT delete delivered messages — the client sends explicit delivery receipts
    /// (acks) so a dropped connection never loses a message.
    pub fn fetch(&mut self, to: &IdentityHash, now: u64) -> Vec<Envelope> {
        let key = to.as_str().to_string();
        let Some(mailbox) = self.mailboxes.get_mut(&key) else {
            return Vec::new();
        };
        mailbox.retain(|m| !matches!(m.expires_at, Some(exp) if exp <= now));
        mailbox.clone()
    }

    /// Remove a delivered message by id (called on a client delivery receipt).
    pub fn ack(&mut self, to: &IdentityHash, msg_id: &str) {
        if let Some(mailbox) = self.mailboxes.get_mut(to.as_str()) {
            mailbox.retain(|m| m.msg_id != msg_id);
        }
    }

    pub fn depth(&self, to: &IdentityHash) -> usize {
        self.mailboxes.get(to.as_str()).map_or(0, |m| m.len())
    }

    /// Drop a whole mailbox (account deletion). Undelivered ciphertext for a deleted
    /// account has no recipient anymore — keeping it would only preserve traffic
    /// metadata at rest.
    pub fn purge(&mut self, to: &str) {
        self.mailboxes.remove(to);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{PayloadKind, WakeClass};

    fn env_for(to: &str, msg_id: &str, expires_at: Option<u64>) -> Envelope {
        Envelope {
            to: IdentityHash::from_identifier(to),
            ciphertext: "Y2lwaGVy".into(),
            kind: PayloadKind::Message,
            msg_id: msg_id.into(),
            expires_at,
            wake: Default::default(),
            raw_identifier: None,
        }
    }

    fn call_env(to: &str, msg_id: &str, expires_at: Option<u64>, wake: WakeClass) -> Envelope {
        Envelope {
            wake,
            ..env_for(to, msg_id, expires_at)
        }
    }

    #[test]
    fn enqueue_and_fetch_round_trip() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        store.enqueue(env_for("bob", "m1", None), 1000).unwrap();
        let msgs = store.fetch(&bob, 1000);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg_id, "m1");
    }

    #[test]
    fn zk_violation_is_rejected() {
        let mut store = MessageStore::new();
        let mut bad = env_for("bob", "m1", None);
        bad.raw_identifier = Some("bob-real-uuid".into());
        assert_eq!(store.enqueue(bad, 1000), Err(RelayError::ZkViolation));
    }

    #[test]
    fn duplicate_msg_id_is_idempotent() {
        let mut store = MessageStore::new();
        // First store is "newly stored"; a re-post of the same id is idempotent success
        // (Ok(false) = already held), NOT an error — an at-least-once retry of a message
        // the recipient already received must not surface to the sender as "Not sent".
        assert!(
            store
                .enqueue(env_for("bob", "m1", None), 1000)
                .unwrap()
                .stored
        );
        assert!(
            !store
                .enqueue(env_for("bob", "m1", None), 1000)
                .unwrap()
                .stored
        );
        // And it did not double-store.
        assert_eq!(
            store
                .fetch(&IdentityHash::from_identifier("bob"), 1000)
                .len(),
            1
        );
    }

    /// SP-03: a full mailbox must EVICT, never refuse. The count backstop and the byte
    /// budget both shed oldest-first, and the newcomer always lands — the whole point is
    /// that no amount of junk can make a mailbox reject a legitimate sender.
    #[test]
    fn an_over_full_mailbox_evicts_its_oldest_instead_of_refusing() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        for i in 0..MAX_MAILBOX_DEPTH {
            store
                .enqueue(env_for("bob", &format!("m{i}"), None), 1000)
                .unwrap();
        }
        let out = store
            .enqueue(env_for("bob", "legit", None), 1000)
            .expect("must not refuse");
        assert!(out.stored);
        assert_eq!(out.evicted, vec!["m0".to_string()], "oldest arrival goes");
        assert_eq!(store.depth(&bob), MAX_MAILBOX_DEPTH);
        let held = store.fetch(&bob, 1000);
        assert!(held.iter().any(|m| m.msg_id == "legit"));
        assert!(!held.iter().any(|m| m.msg_id == "m0"));
    }

    /// The byte budget is the real bound: a flood of large envelopes hits it long before
    /// the count backstop, and still cannot block delivery.
    #[test]
    fn the_byte_budget_evicts_before_the_count_backstop() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        let big = |id: &str| Envelope {
            ciphertext: "A".repeat(512 * 1024),
            ..env_for("bob", id, None)
        };
        let junk = 16;
        let shed: usize = (0..junk)
            .map(|i| {
                store
                    .enqueue(big(&format!("junk{i}")), 1000)
                    .unwrap()
                    .evicted
                    .len()
            })
            .sum();
        assert!(
            shed > 0,
            "the byte budget must bind long before the count cap"
        );
        assert!(store.depth(&bob) < junk);
        assert!(
            store.depth(&bob) < MAX_MAILBOX_DEPTH,
            "count cap was never reached — bytes did the work"
        );
        // And a normal-sized message still lands, which is the whole point.
        assert!(
            store
                .enqueue(env_for("bob", "legit", None), 1000)
                .unwrap()
                .stored
        );
        assert!(store.fetch(&bob, 1000).iter().any(|m| m.msg_id == "legit"));
    }

    /// Eviction must never cost a mailbox a message on an at-least-once retry: the
    /// duplicate check runs first, so a retry is idempotent success and evicts nothing.
    #[test]
    fn an_idempotent_retry_into_a_full_mailbox_evicts_nothing() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        for i in 0..MAX_MAILBOX_DEPTH {
            store
                .enqueue(env_for("bob", &format!("m{i}"), None), 1000)
                .unwrap();
        }
        let out = store.enqueue(env_for("bob", "m7", None), 1000).unwrap();
        assert!(!out.stored);
        assert!(out.evicted.is_empty());
        assert_eq!(store.depth(&bob), MAX_MAILBOX_DEPTH);
    }

    /// A single envelope larger than a whole mailbox budget is an honest client error,
    /// not a flood — this is the only path left that refuses.
    #[test]
    fn one_oversized_envelope_is_still_refused() {
        let mut store = MessageStore::new();
        let huge = Envelope {
            ciphertext: "A".repeat(MAX_MAILBOX_BYTES + 1),
            ..env_for("bob", "huge", None)
        };
        assert_eq!(store.enqueue(huge, 1000), Err(RelayError::MailboxFull));
    }

    #[test]
    fn expired_messages_are_pruned_on_fetch() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        store
            .enqueue(env_for("bob", "live", Some(2000)), 1000)
            .unwrap();
        store
            .enqueue(env_for("bob", "alsolive", None), 1000)
            .unwrap();
        let msgs = store.fetch(&bob, 2500);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg_id, "alsolive");
    }

    #[test]
    fn none_expiry_is_clamped_to_the_ttl_ceiling() {
        // A client that sets expires_at:None must not create an immortal message (M-3):
        // it lands with the default ceiling and prunes once past it.
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        store.enqueue(env_for("bob", "m1", None), 1000).unwrap();
        let stored = store.fetch(&bob, 1000);
        assert_eq!(stored[0].expires_at, Some(1000 + MAX_MESSAGE_TTL_SECS));
        // Past the ceiling it is gone.
        assert!(store
            .fetch(&bob, 1000 + MAX_MESSAGE_TTL_SECS + 1)
            .is_empty());
    }

    #[test]
    fn oversized_expiry_is_pulled_back_to_the_ceiling() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        // Requested far past the ceiling → clamped.
        store
            .enqueue(env_for("bob", "m1", Some(u64::MAX)), 1000)
            .unwrap();
        assert_eq!(
            store.fetch(&bob, 1000)[0].expires_at,
            Some(1000 + MAX_MESSAGE_TTL_SECS)
        );
    }

    /// Call signaling sets a call-scale expiry (~65 s). The relay must keep it exactly:
    /// clamping is a ceiling, never an extension, or a stale ring/terminal could be
    /// served to a device that reconnects minutes later.
    #[test]
    fn a_call_scale_expiry_is_kept_exactly_and_never_extended() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        let deadline = 1000 + 65;
        store
            .enqueue(
                call_env("bob", "offer", Some(deadline), WakeClass::Call),
                1000,
            )
            .unwrap();
        assert_eq!(store.fetch(&bob, 1000)[0].expires_at, Some(deadline));
        // One second past its own deadline the offer is gone, long before the generic
        // 30-day ceiling — a late reconnect can never be rung by it.
        assert!(store.fetch(&bob, deadline + 1).is_empty());
        assert_eq!(store.depth(&bob), 0);
    }

    /// A duplicate control (an at-least-once outbox retry) is idempotent success, and
    /// must not push the original's deadline out.
    #[test]
    fn a_duplicate_control_neither_double_stores_nor_extends_the_deadline() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        store
            .enqueue(
                call_env("bob", "terminal", Some(1065), WakeClass::CallControl),
                1000,
            )
            .unwrap();
        // Same msg_id, a much later expiry: accepted (the sender's ACK may have been
        // lost) but nothing changes.
        assert_eq!(
            store.enqueue(
                call_env("bob", "terminal", Some(9999), WakeClass::CallControl),
                1010,
            ),
            Ok(Stored::default())
        );
        assert_eq!(store.depth(&bob), 1);
        assert_eq!(store.fetch(&bob, 1010)[0].expires_at, Some(1065));
    }

    /// A control that arrives after its own deadline is accepted (the sender must not
    /// show a failure for a call that is over anyway) and stored nowhere.
    #[test]
    fn an_already_expired_control_is_accepted_but_never_stored() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        assert_eq!(
            store.enqueue(
                call_env("bob", "late", Some(999), WakeClass::CallControl),
                1000,
            ),
            Ok(Stored::default())
        );
        assert_eq!(store.depth(&bob), 0);
    }

    #[test]
    fn prune_drops_expired_and_empty_mailboxes() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        store
            .enqueue(env_for("bob", "gone", Some(2000)), 1000)
            .unwrap();
        store.prune(2500);
        assert_eq!(store.depth(&bob), 0);
        assert!(store.mailboxes.is_empty()); // empty mailbox reaped, not just emptied
    }

    #[test]
    fn ack_removes_delivered_message() {
        let mut store = MessageStore::new();
        let bob = IdentityHash::from_identifier("bob");
        store.enqueue(env_for("bob", "m1", None), 1000).unwrap();
        store.ack(&bob, "m1");
        assert_eq!(store.depth(&bob), 0);
    }
}
