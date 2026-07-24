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

/// Max undelivered messages held per recipient mailbox. Beyond this, new messages
/// for that mailbox are rejected — bounds storage and blunts a flood against one user.
pub const MAX_MAILBOX_DEPTH: usize = 100;

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
    #[error("rejected: recipient mailbox is full")]
    MailboxFull,
    #[error("rejected: relay is at capacity")]
    StoreFull,
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
    /// `Ok(true)` = newly stored; `Ok(false)` = nothing new to store (an already-expired
    /// message, or an **idempotent duplicate** the relay already holds). Delivery is
    /// at-least-once: a client whose ACK was lost retries the same `msg_id`, and a message
    /// the recipient already received must return success, not an error — otherwise the
    /// sender shows "Not sent" for a message that went through. The caller skips the live
    /// push, the wake, and the DB write when this is `false`.
    pub fn enqueue(&mut self, mut env: Envelope, now: u64) -> Result<bool, RelayError> {
        if !env.is_zk_clean() {
            return Err(RelayError::ZkViolation);
        }
        // Defensive TTL ceiling (also enforced at the HTTP boundary): no message may
        // outlive `now + MAX_MESSAGE_TTL_SECS`, and a missing expiry gets the default.
        env.expires_at = Some(clamp_expiry(now, env.expires_at));
        // An already-expired message is silently dropped — nothing to store, and it
        // is not the sender's error that the recipient was slow to come online.
        if matches!(env.expires_at, Some(exp) if exp <= now) {
            return Ok(false);
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
        // a delivered message as "Not sent" on the sender.
        if mailbox.iter().any(|m| m.msg_id == env.msg_id) {
            return Ok(false);
        }
        if mailbox.len() >= MAX_MAILBOX_DEPTH {
            return Err(RelayError::MailboxFull);
        }
        mailbox.push(env);
        Ok(true)
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
    use protocol_types::PayloadKind;

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
        assert_eq!(store.enqueue(env_for("bob", "m1", None), 1000), Ok(true));
        assert_eq!(store.enqueue(env_for("bob", "m1", None), 1000), Ok(false));
        // And it did not double-store.
        assert_eq!(
            store
                .fetch(&IdentityHash::from_identifier("bob"), 1000)
                .len(),
            1
        );
    }

    #[test]
    fn mailbox_depth_is_capped() {
        let mut store = MessageStore::new();
        for i in 0..MAX_MAILBOX_DEPTH {
            store
                .enqueue(env_for("bob", &format!("m{i}"), None), 1000)
                .unwrap();
        }
        assert_eq!(
            store.enqueue(env_for("bob", "overflow", None), 1000),
            Err(RelayError::MailboxFull)
        );
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
