//! The **call-control store**: the small amount of state the call subsystem must survive
//! a process death with, sealed under the call-only store key rather than the vault.
//!
//! A ring that only exists in process memory is a ring that becomes a lie the moment
//! Android kills the app: the notification stays up while nothing knows which call it
//! belongs to, and a terminal that arrives afterwards has nothing to cancel. This module
//! is what makes the call subsystem restartable — and, because it carries the account
//! context the mailbox is derived from, what lets a device whose chat vault is **locked**
//! find its own call-control mailbox at all.
//!
//! What it holds (`internal/CALL_PLAN.md` §6.1):
//!
//! * pending rings — the presentable part of a capsule, never its media capability
//!   (a capsule has none);
//! * the ordering state and terminal tombstones, as the same
//!   [`CallRegistry`](crate::callstate::CallRegistry) the live paths use, so there is no
//!   second state machine to disagree with the first;
//! * a bounded outbox of sealed capsules, so a decline sent while locked survives the
//!   process that sent it.
//!
//! What it must never hold: message history, media room ids, media keys, or recorded
//! media. Asserted by a test over the encoded form.
//!
//! Every bound is checked on open, before anything is allocated from a size the file
//! chose, and a blob that does not open at all yields an empty store — losing ordering
//! state, never ringing on unauthenticated data.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::callcapsule::{CallCapsule, CapsuleKind};
use crate::callstate::{
    valid_call_id, valid_device_id, CallRegistry, CallTerminalReason, OfferDecision,
    TerminalDecision, MAX_CALL_RECORDS,
};

/// Most rings held at once. One call slot is the product rule; the rest of the headroom
/// is for a phone that woke to a backlog of capsules for calls that have since ended.
pub const MAX_PENDING_RINGS: usize = 8;
/// Most capsules queued for delivery at once.
pub const MAX_OUTBOX: usize = 32;
/// Attempts per outbox entry, including the first — the same budget the vault-resident
/// control outbox uses.
pub const MAX_OUTBOX_ATTEMPTS: u32 = 6;
/// Backoff between attempts, in seconds.
pub const OUTBOX_BACKOFF_SECS: [u64; 5] = [1, 2, 4, 8, 16];
/// Largest store this build will even attempt to open.
pub const MAX_STORE_BYTES: usize = 256 * 1024;
/// How long past its ring deadline a pending ring is kept, so a process that died mid-ring
/// can reconcile and cancel what it left on screen instead of orphaning it.
pub const CRASH_GRACE_SECS: u64 = 30;

/// A ring this device is presenting, or was presenting when it died.
///
/// Everything here comes from a verified capsule and is presentation/routing only. There
/// is deliberately no media room id and no media key: answering needs the encrypted
/// offer, which lives behind the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRing {
    pub call_instance_id: String,
    /// The registry record this ring is keyed under — shared with the encrypted offer.
    pub offer_id: String,
    /// This device's single-use presentation handle.
    pub ring_handle: String,
    pub from: String,
    pub display_name: String,
    pub video: bool,
    pub group: bool,
    pub caller_device_id: String,
    /// Exact route for this device's reply controls.
    pub reply_to_mailbox: String,
    /// The caller device's call-control mailbox and public call key, taken from the
    /// authenticated capsule. This is what lets a **locked** device answer at all: it
    /// needs neither the caller's account name nor a relay lookup it could not verify.
    /// Empty when that caller published no call-control key — the decline is then local.
    #[serde(default)]
    pub reply_call_mailbox: String,
    #[serde(default)]
    pub reply_call_key: String,
    pub created_at: u64,
    pub ring_expires_at: u64,
    /// The id this ring was actually **posted under**, once it has been shown — the
    /// presentation handle for a Telecom call, or the generic locked-ring id when the
    /// vault was closed. `None` means it never reached the screen, and reconciliation has
    /// nothing to take down. Storing the id rather than a bool is what makes the
    /// cancellation land on the notification that actually exists.
    #[serde(default)]
    pub presented_as: Option<String>,
}

impl PendingRing {
    /// The presentable part of a verified offer capsule.
    pub fn from_capsule(capsule: &CallCapsule) -> Self {
        PendingRing {
            call_instance_id: capsule.call_instance_id.clone(),
            offer_id: capsule.offer_id.clone(),
            ring_handle: capsule.ring_handle.clone(),
            from: capsule.from.clone(),
            display_name: capsule.display_name.clone(),
            video: capsule.video,
            group: capsule.group,
            caller_device_id: capsule.caller_device_id.clone(),
            reply_to_mailbox: capsule.reply_to_mailbox.clone(),
            reply_call_mailbox: checked_reply_route(capsule),
            reply_call_key: capsule.reply_call_key.clone(),
            created_at: capsule.created_at,
            ring_expires_at: capsule.ring_expires_at,
            presented_as: None,
        }
    }

    fn well_formed(&self) -> bool {
        valid_call_id(&self.call_instance_id)
            && valid_call_id(&self.offer_id)
            && valid_call_id(&self.ring_handle)
            && valid_device_id(&self.caller_device_id)
            && !self.from.is_empty()
            && self.from.len() <= 64
            && self.display_name.len() <= crate::callcapsule::MAX_DISPLAY_NAME
            && self.reply_to_mailbox.len() == 64
            && self.ring_expires_at > self.created_at
    }
}

/// The capsule's reply route, but only if it is the route the caller could legitimately
/// have named (A-22).
///
/// `reply_call_mailbox` is covered by the caller's signature, so it is authentic — but it was
/// never checked to be *the caller's own* mailbox, and it is **derivable** from fields this
/// capsule already authenticates. Unchecked, an approved contact could aim a locked phone's
/// decline at a third party's call-control mailbox: a one-hop reflector, signed by us, that
/// spends that party's `CallControl` wake budget and plants a tombstone for a
/// `call_instance_id` of the attacker's choosing.
///
/// Derived from the capsule's own authenticated fields and nothing else, because a locked
/// device has no session state to check against — which is exactly why the field was trusted
/// in the first place.
///
/// **Fails open on the ring, closed on the reply.** A mismatch yields an empty route, which
/// the decline path already handles as "caller published no call key": the ring is still
/// shown, it still stops locally, and the caller finds out at its own ring timeout. Refusing
/// the whole capsule would stop the ring being shown at all — a worse outcome than the leak
/// being closed. `reply_call_key` is still carried: it is not derivable, and sealing to a
/// wrong key only makes the decline unreadable. It can no longer be *aimed*.
///
/// Deliberately **not** in [`CallCapsule::well_formed`]: that predicate also runs on the
/// sending side, so a derivation that ever disagreed with the mint by a character would
/// silently stop this device sending capsules at all, and the locked layer would quietly
/// vanish. Here it can only ever refuse a reply route.
fn checked_reply_route(capsule: &CallCapsule) -> String {
    let account_hash = crate::IdentityHash::from_identifier(&capsule.from);
    match crate::call_mailbox_for(account_hash.as_str(), &capsule.caller_device_id) {
        Some(derived) if derived == capsule.reply_call_mailbox => derived,
        _ => String::new(),
    }
}

/// A capsule addressed directly at a call-control mailbox.
///
/// Deliberately not `CapsuleDelivery`: that names an account and carries a fetched
/// binding, and a **locked** device has neither. Both fields here came out of the signed
/// offer capsule this is replying to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsulePost {
    pub call_mailbox: String,
    pub call_key: String,
    pub plaintext: Vec<u8>,
    pub expires_at: u64,
}

/// One sealed capsule waiting to go out, with its retry budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// Random id, so a caller can report exactly which entries were delivered.
    pub id: String,
    pub post: CapsulePost,
    pub attempts: u32,
    pub next_attempt_at: u64,
}

/// What a restart owes the platform: rings to put back, and rings to take down.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Still valid and non-terminal — safe to present again.
    pub present: Vec<PendingRing>,
    /// Handles whose call ended or expired while we were gone. Never ring; if the system
    /// still shows one, take it down.
    pub cancel: Vec<String>,
}

/// The sealed-at-rest call-control store.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CallStore {
    /// The account this store belongs to, as its username hash — the one piece of account
    /// context a locked device needs to derive its own call-control mailbox.
    pub account_hash: String,
    /// The account name, which a decline sent from a locked device has to carry so the
    /// caller can place the signer. No worse than what the store already holds — a pending
    /// ring names the *caller* — and the whole file is sealed under the device key.
    #[serde(default)]
    pub username: String,
    pub device_id: String,
    pub rings: VecDeque<PendingRing>,
    /// Ordering, duplicate suppression, and terminal tombstones.
    pub registry: CallRegistry,
    pub outbox: VecDeque<OutboxEntry>,
}

impl CallStore {
    pub fn new(account_hash: &str, device_id: &str) -> Self {
        CallStore {
            account_hash: account_hash.to_string(),
            device_id: device_id.to_string(),
            ..Default::default()
        }
    }

    /// Is this store the one this account and device should be using? A relink, an
    /// account switch, or a primary transfer re-ids the device, and the previous store's
    /// rings and tombstones are not ours to act on.
    pub fn belongs_to(&self, account_hash: &str, device_id: &str) -> bool {
        self.account_hash == account_hash && self.device_id == device_id
    }

    /// Open a sealed store. `None` on a wrong device key, a truncated/half-written file,
    /// tampering, or any bound the file exceeds.
    pub fn open(store_key: &[u8; 32], blob: &[u8]) -> Option<Self> {
        if blob.len() > MAX_STORE_BYTES {
            return None;
        }
        let plain = crypto_core::callkey::open_call_store(store_key, blob)?;
        let store: CallStore = serde_json::from_slice(&plain).ok()?;
        store.validated()
    }

    pub fn seal(&self, store_key: &[u8; 32]) -> Vec<u8> {
        let plain = serde_json::to_vec(self).unwrap_or_default();
        crypto_core::callkey::seal_call_store(store_key, &plain)
    }

    /// Every bound and shape, checked before this store is used for anything.
    fn validated(self) -> Option<Self> {
        let bounded = self.rings.len() <= MAX_PENDING_RINGS
            && self.outbox.len() <= MAX_OUTBOX
            && self.registry.records().len() <= MAX_CALL_RECORDS
            && self.account_hash.len() <= 64
            && self.username.len() <= 64
            && valid_device_id(&self.device_id)
            && self.rings.iter().all(PendingRing::well_formed)
            && self.outbox.iter().all(|entry| {
                valid_call_id(&entry.id)
                    && entry.attempts <= MAX_OUTBOX_ATTEMPTS
                    && entry.post.plaintext.len() <= crypto_core::callkey::MAX_CAPSULE_BYTES
                    && entry.post.call_mailbox.len() == 64
                    && entry
                        .post
                        .call_mailbox
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                    && !entry.post.call_key.is_empty()
                    && entry.post.call_key.len() <= 64
            });
        bounded.then_some(self)
    }

    /// Apply a verified capsule. Returns the registry's decision, so the caller presents a
    /// ring only for [`OfferDecision::Ring`] — never merely because a row exists.
    pub fn record_offer(
        &mut self,
        capsule: &CallCapsule,
        now: u64,
        retention_secs: u64,
    ) -> OfferDecision {
        if capsule.kind != CapsuleKind::Offer {
            return OfferDecision::Invalid;
        }
        let decision = self.registry.receive_offer(
            &capsule.call_instance_id,
            &capsule.offer_id,
            capsule.created_at,
            capsule.ring_expires_at,
            now,
            retention_secs,
        );
        if decision == OfferDecision::Ring {
            while self.rings.len() >= MAX_PENDING_RINGS {
                self.rings.pop_front();
            }
            self.rings.push_back(PendingRing::from_capsule(capsule));
        }
        decision
    }

    /// Record a final outcome and drop the ring it ends.
    ///
    /// The whole [`PendingRing`] comes back, not just its handle: what the platform is
    /// showing may be the handle (a system call) **or**
    /// [`presented_as`](PendingRing::presented_as) (the generic locked-vault ring, posted
    /// under one shared id because a locked device may not name the call). Cancelling only
    /// the handle takes down nothing on a locked phone, which is how a terminal capsule
    /// came to be verified, recorded — and then to leave the ring sounding anyway.
    pub fn record_terminal(
        &mut self,
        call_instance_id: &str,
        offer_id: &str,
        reason: CallTerminalReason,
        now: u64,
        retention_secs: u64,
    ) -> (TerminalDecision, Option<PendingRing>) {
        let decision =
            self.registry
                .record_terminal(call_instance_id, offer_id, reason, now, retention_secs);
        let ended = matches!(
            decision,
            TerminalDecision::Applied(_) | TerminalDecision::Duplicate(_)
        );
        let ring = ended.then(|| self.take_ring(call_instance_id)).flatten();
        (decision, ring)
    }

    /// Note that a ring reached the screen, under the id it was actually posted with.
    ///
    /// That id is not always the ring handle: a locked device shows the generic ring under
    /// [`crate::callstore::LOCKED_RING_ID`]-shaped ids of the shell's choosing, and
    /// cancelling the handle instead would take down nothing.
    pub fn mark_presented(&mut self, call_instance_id: &str, presented_as: &str) {
        if let Some(ring) = self
            .rings
            .iter_mut()
            .find(|ring| ring.call_instance_id == call_instance_id)
        {
            ring.presented_as = Some(presented_as.to_string());
        }
    }

    pub fn take_ring(&mut self, call_instance_id: &str) -> Option<PendingRing> {
        let index = self
            .rings
            .iter()
            .position(|ring| ring.call_instance_id == call_instance_id)?;
        self.rings.remove(index)
    }

    pub fn ring(&self, call_instance_id: &str) -> Option<&PendingRing> {
        self.rings
            .iter()
            .find(|ring| ring.call_instance_id == call_instance_id)
    }

    /// What this process owes the platform after a restart (`internal/CALL_PLAN.md` §6.4).
    ///
    /// A ring is re-presentable only while it is inside its own window and its call has no
    /// terminal tombstone. Anything else is cancellation: an expired ring, a ring whose
    /// call ended while we were gone, and a ring that outlived even the crash grace.
    pub fn reconcile(&mut self, now: u64, retention_secs: u64) -> Reconciliation {
        let mut out = Reconciliation::default();
        let expired = self.registry.expire(now, retention_secs);
        let mut keep = VecDeque::new();
        while let Some(ring) = self.rings.pop_front() {
            let terminal = self
                .registry
                .terminal_reason(&ring.call_instance_id)
                .is_some()
                || expired.contains(&ring.call_instance_id);
            if terminal || ring.ring_expires_at <= now {
                // Only worth cancelling what was actually shown; a ring that never made it
                // to the screen leaves nothing behind.
                if let Some(presented_as) = ring
                    .presented_as
                    .filter(|_| ring.ring_expires_at.saturating_add(CRASH_GRACE_SECS) > now)
                {
                    out.cancel.push(presented_as);
                }
                continue;
            }
            out.present.push(ring.clone());
            keep.push_back(ring);
        }
        self.rings = keep;
        self.reap_outbox(now);
        out
    }

    /// Queue a decline for delivery. Bounded; the oldest entry is dropped at capacity, and
    /// an already-expired or malformed capsule is not queued at all.
    ///
    /// The outbox is what makes a decline sent from a locked phone survive the process
    /// that sent it — Android may freeze the app the moment the notification is dismissed.
    pub fn queue_decline(
        &mut self,
        call_mailbox: &str,
        call_key: &str,
        plaintext: Vec<u8>,
        expires_at: u64,
        now: u64,
    ) -> bool {
        let post = CapsulePost {
            call_mailbox: call_mailbox.to_string(),
            call_key: call_key.to_string(),
            plaintext,
            expires_at,
        };
        if expires_at <= now
            || post.plaintext.len() > crypto_core::callkey::MAX_CAPSULE_BYTES
            || post.call_mailbox.len() != 64
            || !post.call_mailbox.bytes().all(|b| b.is_ascii_hexdigit())
            || post.call_key.is_empty()
            || post.call_key.len() > 64
        {
            return false;
        }
        while self.outbox.len() >= MAX_OUTBOX {
            self.outbox.pop_front();
        }
        self.outbox.push_back(OutboxEntry {
            id: crate::callstate::random_call_id(),
            post,
            attempts: 0,
            next_attempt_at: now,
        });
        true
    }

    /// Entries whose attempt is due, charged one attempt each and rescheduled. The caller
    /// posts them off-lock and reports the delivered ids to [`Self::delivered`]; anything
    /// it does not report is retried until its budget or its expiry runs out.
    pub fn take_due(&mut self, now: u64) -> Vec<(String, CapsulePost)> {
        self.reap_outbox(now);
        let mut due = Vec::new();
        for entry in self.outbox.iter_mut() {
            if entry.next_attempt_at > now {
                continue;
            }
            let backoff = OUTBOX_BACKOFF_SECS
                .get(entry.attempts as usize)
                .copied()
                .unwrap_or(0);
            entry.attempts = entry.attempts.saturating_add(1);
            entry.next_attempt_at = now.saturating_add(backoff);
            due.push((entry.id.clone(), entry.post.clone()));
        }
        due
    }

    pub fn delivered(&mut self, ids: &[String]) {
        self.outbox.retain(|entry| !ids.contains(&entry.id));
    }

    /// Drop entries that are out of attempts or past their call-scale expiry.
    fn reap_outbox(&mut self, now: u64) {
        self.outbox
            .retain(|entry| entry.attempts < MAX_OUTBOX_ATTEMPTS && entry.post.expires_at > now);
    }

    /// Expire what has aged out, on every open, after every terminal transition,
    /// whenever the retention setting changes, and on a periodic tick — a shortened
    /// window applies to the tombstones already stored, not only to the next call.
    ///
    /// Returns whether anything actually changed, so a periodic sweep over a store with
    /// nothing to expire costs no re-seal and no write.
    pub fn cleanup(&mut self, now: u64, retention_secs: u64) -> bool {
        // Snapshot BEFORE anything runs: `expire` purges as part of its own work, so a
        // count taken after it would miss exactly the tombstones this sweep dropped.
        let before = (
            self.registry.records().len(),
            self.rings.len(),
            self.outbox.len(),
        );
        let expired = self.registry.expire(now, retention_secs);
        self.registry.retain_within(now, retention_secs);
        self.rings
            .retain(|ring| ring.ring_expires_at.saturating_add(CRASH_GRACE_SECS) > now);
        self.reap_outbox(now);
        !expired.is_empty()
            || before
                != (
                    self.registry.records().len(),
                    self.rings.len(),
                    self.outbox.len(),
                )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callcapsule::{CapsulePlan, CapsuleSigner, MAX_DISPLAY_NAME};
    use crate::callstate::{random_call_id, CALL_RING_TIMEOUT_SECS, CALL_SIGNAL_TTL_SECS};

    const NOW: u64 = 1_800_000_000;

    fn store_key() -> [u8; 32] {
        *crypto_core::callkey::call_store_key(&[7u8; crypto_core::DEVICE_KEY_LEN])
    }

    fn capsule(
        kind: CapsuleKind,
        call: &str,
        offer: &str,
        reason: Option<CallTerminalReason>,
    ) -> CallCapsule {
        let account = crypto_core::create_account_with_username("bob", "Bob-Password-123!")
            .unwrap()
            .0;
        CallCapsule::new(
            CapsulePlan {
                kind,
                call_instance_id: call.to_string(),
                offer_id: offer.to_string(),
                from: "bob".into(),
                caller_identity_key: account.ratchet_ref().identity_key(),
                caller_device_id: "0".into(),
                to_device_id: "a".repeat(32),
                video: false,
                group: false,
                display_name: "bob".into(),
                created_at: NOW,
                ring_expires_at: NOW + CALL_RING_TIMEOUT_SECS,
                expires_at: NOW + CALL_SIGNAL_TTL_SECS,
                reply_to_mailbox: "b".repeat(64),
                reply_call_mailbox: "c".repeat(64),
                reply_call_key: String::new(),
                signer: CapsuleSigner::Roster,
                reason,
            },
            |payload| account.ratchet_ref().sign(payload),
        )
    }

    /// A-22: a reply route that is not the caller's own is dropped, and only the route.
    ///
    /// The field is signed, so it is authentic — but nothing proved it named the *caller's*
    /// call-control mailbox, and it is derivable from what the capsule already authenticates.
    /// Unchecked, an approved contact could point a locked phone's decline at a third party:
    /// a one-hop reflector, signed by us, spending that party's control-wake budget and
    /// tombstoning a call id of the attacker's choosing.
    ///
    /// The direction of failure is the other half of this: the **ring must still be shown**.
    /// Refusing the capsule outright would turn a closed leak into a missed call.
    #[test]
    fn a_reply_route_the_caller_could_not_own_is_dropped_and_the_ring_is_still_rung() {
        let (call, offer) = (random_call_id(), random_call_id());
        // The helper's `"c".repeat(64)` is exactly the reflector shape: a well-formed mailbox
        // that "bob"/device "0" could not have derived.
        let foreign = capsule(CapsuleKind::Offer, &call, &offer, None);
        assert_eq!(foreign.reply_call_mailbox, "c".repeat(64));

        let mut store = CallStore::default();
        assert_eq!(store.record_offer(&foreign, NOW, 0), OfferDecision::Ring);
        let ring = store.ring(&call).expect("the ring is still shown");
        assert!(
            ring.reply_call_mailbox.is_empty(),
            "a decline must not be postable to a mailbox the caller could not own"
        );

        // The route the caller *can* name — derived the same way the sender mints it —
        // survives untouched, or the locked decline would never reach anyone.
        let mut honest = capsule(CapsuleKind::Offer, &call, &offer, None);
        honest.reply_call_mailbox = crate::call_mailbox_for(
            crate::IdentityHash::from_identifier(&honest.from).as_str(),
            &honest.caller_device_id,
        )
        .expect("derivable");
        assert_eq!(
            PendingRing::from_capsule(&honest).reply_call_mailbox,
            honest.reply_call_mailbox
        );
    }

    fn queue(store: &mut CallStore, expires_at: u64, now: u64) -> bool {
        store.queue_decline(
            &"a".repeat(64),
            "their-call-key",
            b"sealed capsule".to_vec(),
            expires_at,
            now,
        )
    }

    fn stored() -> CallStore {
        CallStore::new("account-hash", &"a".repeat(32))
    }

    /// The store survives the process it was written by, and only for the device that
    /// wrote it.
    #[test]
    fn a_sealed_store_round_trips_and_is_refused_to_another_device_key() {
        let mut store = stored();
        let (call, offer) = (random_call_id(), random_call_id());
        store.record_offer(&capsule(CapsuleKind::Offer, &call, &offer, None), NOW, 0);
        let blob = store.seal(&store_key());
        assert_eq!(CallStore::open(&store_key(), &blob).unwrap(), store);

        let other = *crypto_core::callkey::call_store_key(&[9u8; crypto_core::DEVICE_KEY_LEN]);
        assert!(CallStore::open(&other, &blob).is_none());
        // A half-written file is refused rather than half-trusted.
        assert!(CallStore::open(&store_key(), &blob[..blob.len() / 2]).is_none());
        // …and so is a record sealed as something else under the same key.
        let screen = crypto_core::callkey::seal_screen_index(&store_key(), b"{}");
        assert!(CallStore::open(&store_key(), &screen).is_none());
    }

    /// A pending ring is presentation state, not a capability: nothing in it can join a
    /// call, and the store never holds message history.
    #[test]
    fn the_store_holds_no_media_capability() {
        let mut store = stored();
        let (call, offer) = (random_call_id(), random_call_id());
        store.record_offer(&capsule(CapsuleKind::Offer, &call, &offer, None), NOW, 0);
        let json = String::from_utf8(serde_json::to_vec(&store).unwrap()).unwrap();
        for forbidden in ["call_id", "key_b64", "room", "media_key", "messages"] {
            assert!(
                !json.contains(forbidden),
                "store must not carry {forbidden}"
            );
        }
    }

    /// Crash recovery: a ring inside its window comes back, a ring whose call ended (or
    /// whose window closed) is taken down, and neither ever rings from an old row alone.
    #[test]
    fn reconciliation_restores_live_rings_and_cancels_dead_ones() {
        let mut store = stored();
        let live = (random_call_id(), random_call_id());
        let ended = (random_call_id(), random_call_id());
        let stale = (random_call_id(), random_call_id());
        for (call, offer) in [&live, &ended, &stale] {
            assert_eq!(
                store.record_offer(&capsule(CapsuleKind::Offer, call, offer, None), NOW, 0),
                OfferDecision::Ring
            );
            let handle = store.ring(call).unwrap().ring_handle.clone();
            store.mark_presented(call, &handle);
        }
        let ended_handle = store.ring(&ended.0).unwrap().ring_handle.clone();
        store.record_terminal(
            &ended.0,
            &ended.1,
            CallTerminalReason::AnsweredElsewhere,
            NOW + 1,
            0,
        );
        // The terminal already took its ring down; reconciliation must not resurrect it.
        assert!(store.ring(&ended.0).is_none());

        // Two seconds into the ring window: only the live and stale rings remain, and both
        // are still presentable.
        let out = store.reconcile(NOW + 2, 0);
        assert_eq!(out.present.len(), 2);
        assert!(out.cancel.is_empty());
        assert!(!out
            .present
            .iter()
            .any(|ring| ring.ring_handle == ended_handle));

        // Past the ring deadline: both expire, and what was on screen is cancelled.
        let out = store.reconcile(NOW + CALL_RING_TIMEOUT_SECS + 1, 0);
        assert!(out.present.is_empty());
        assert_eq!(out.cancel.len(), 2);
        assert!(store.rings.is_empty());
        // Long past it, there is nothing left to cancel either.
        assert_eq!(
            store.reconcile(NOW + CALL_RING_TIMEOUT_SECS + CRASH_GRACE_SECS + 1, 0),
            Reconciliation::default()
        );
    }

    /// A late offer for a call that already ended never becomes a ring, however it is
    /// replayed — the tombstone outlives the capsule.
    #[test]
    fn a_terminal_tombstone_suppresses_a_late_offer_across_a_restart() {
        let mut store = stored();
        let (call, offer) = (random_call_id(), random_call_id());
        store.record_terminal(&call, &offer, CallTerminalReason::CallerCancelled, NOW, 0);
        let reopened = CallStore::open(&store_key(), &store.seal(&store_key())).unwrap();
        let mut store = reopened;
        assert_eq!(
            store.record_offer(
                &capsule(CapsuleKind::Offer, &call, &offer, None),
                NOW + 1,
                0
            ),
            OfferDecision::Suppressed(CallTerminalReason::CallerCancelled)
        );
        assert!(store.rings.is_empty());
    }

    /// The outbox is what makes a decline sent while locked survive the process that sent
    /// it: bounded, retried on a fixed budget, and never retried past its call-scale life.
    #[test]
    fn the_outbox_retries_on_a_bounded_budget_and_expires_honestly() {
        let mut store = stored();
        assert!(queue(&mut store, NOW + CALL_SIGNAL_TTL_SECS, NOW));
        assert!(
            !queue(&mut store, NOW, NOW),
            "an already-expired capsule is never queued"
        );
        assert!(
            !store.queue_decline("short", "k", b"x".to_vec(), NOW + 60, NOW),
            "a malformed reply route is never queued"
        );

        let due = store.take_due(NOW);
        assert_eq!(due.len(), 1);
        assert!(
            store.take_due(NOW).is_empty(),
            "backoff holds the next attempt"
        );
        store.delivered(&[due[0].0.clone()]);
        assert!(store.outbox.is_empty());

        // Nothing delivered: the budget runs out rather than retrying forever.
        queue(&mut store, NOW + CALL_SIGNAL_TTL_SECS, NOW);
        let mut attempts = 0;
        for tick in 0..CALL_SIGNAL_TTL_SECS {
            attempts += store.take_due(NOW + tick).len();
        }
        assert_eq!(attempts, MAX_OUTBOX_ATTEMPTS as usize);
        assert!(store.outbox.is_empty());
    }

    /// Lowering the retention setting applies to what is already stored — but never below
    /// the window a late offer needs, or a restart would ring for a call that ended.
    #[test]
    fn shortening_retention_prunes_history_but_keeps_the_anti_replay_window() {
        use crate::callstate::MIN_TOMBSTONE_SECS;
        let mut store = stored();
        let (call, offer) = (random_call_id(), random_call_id());
        store.record_terminal(
            &call,
            &offer,
            CallTerminalReason::DeclinedElsewhere,
            NOW,
            30 * 24 * 3600,
        );
        // The user switches to "until the call ends": the 30-day tombstone is cut back
        // immediately…
        assert!(!store.cleanup(NOW + 1, 0), "nothing removed yet");
        assert_eq!(
            store.registry.terminal_reason(&call),
            Some(CallTerminalReason::DeclinedElsewhere),
            "…but not below the ordering window"
        );
        assert!(
            store.cleanup(NOW + MIN_TOMBSTONE_SECS, 0),
            "the sweep that drops the tombstone must report the change, or the periodic \
             pass would never write it back"
        );
        assert_eq!(store.registry.terminal_reason(&call), None);
        assert!(
            !store.cleanup(NOW + MIN_TOMBSTONE_SECS, 0),
            "a sweep with nothing to do must not dirty the store"
        );
    }

    /// Bounds are enforced on open, before anything is sized from what the file claims.
    #[test]
    fn an_oversized_or_malformed_store_is_refused_on_open() {
        let mut fat = stored();
        for _ in 0..MAX_PENDING_RINGS + 4 {
            let mut ring = PendingRing::from_capsule(&capsule(
                CapsuleKind::Offer,
                &random_call_id(),
                &random_call_id(),
                None,
            ));
            ring.presented_as = Some("shown".into());
            fat.rings.push_back(ring);
        }
        assert!(CallStore::open(&store_key(), &fat.seal(&store_key())).is_none());

        let mut malformed = stored();
        let mut ring = PendingRing::from_capsule(&capsule(
            CapsuleKind::Offer,
            &random_call_id(),
            &random_call_id(),
            None,
        ));
        ring.display_name = "x".repeat(MAX_DISPLAY_NAME + 1);
        malformed.rings.push_back(ring);
        assert!(CallStore::open(&store_key(), &malformed.seal(&store_key())).is_none());

        let mut wrong_device = stored();
        wrong_device.device_id = "not-a-device-id".into();
        assert!(CallStore::open(&store_key(), &wrong_device.seal(&store_key())).is_none());
        assert!(CallStore::open(&store_key(), &vec![0u8; MAX_STORE_BYTES + 1]).is_none());
    }

    /// A store written by another account or another device id is not ours to act on.
    #[test]
    fn a_store_from_another_account_or_device_is_not_adopted() {
        let store = stored();
        assert!(store.belongs_to("account-hash", &"a".repeat(32)));
        assert!(!store.belongs_to("другой", &"a".repeat(32)));
        assert!(!store.belongs_to("account-hash", &"b".repeat(32)));
    }
}
