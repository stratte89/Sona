//! Deterministic call-signaling state.
//!
//! Transport delivery is at-least-once and device fan-out is concurrent, so call
//! controls can be duplicated and arrive in any order. This module is deliberately
//! independent of networking, media, and UI: callers feed it authenticated signaling
//! events and get one monotonic decision back.

use std::collections::VecDeque;

use rand::RngCore;
use serde::{Deserialize, Serialize};

/// One incoming ring lasts this long on every platform.
pub const CALL_RING_TIMEOUT_SECS: u64 = 45;
/// Call signaling stays queued slightly longer than the visible ring so terminal
/// controls can catch a device waking at the edge of the ring window.
pub const CALL_SIGNAL_TTL_SECS: u64 = 60;
/// Sender/recipient wall clocks may differ by a few seconds. A deadline beyond the
/// signal TTL plus this allowance is malformed and must not create a longer ring.
pub const CALL_CLOCK_SKEW_SECS: u64 = 5;
/// Correctness tombstones must outlive every valid queued offer even when the user
/// chooses immediate historical cleanup.
pub const MIN_TOMBSTONE_SECS: u64 = CALL_SIGNAL_TTL_SECS + CALL_CLOCK_SKEW_SECS;
/// Hard bound for pending and terminal call-control state.
pub const MAX_CALL_RECORDS: usize = 512;
/// A logical call can rotate media offers while reconnecting. Keep enough accepted
/// generations for a delayed terminal from a just-closed media leg to end the call.
pub const MAX_PRIOR_OFFERS: usize = 128;

/// A random 128-bit lowercase-hex signaling identifier.
pub fn random_call_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_lower(&bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Strict shape check for logical call, offer, ring, and claim IDs.
pub fn valid_call_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validate an offer deadline without trusting the sender to lengthen the ring.
pub fn valid_offer_deadline(created_at: u64, expires_at: u64) -> bool {
    expires_at > created_at
        && expires_at.saturating_sub(created_at)
            <= CALL_RING_TIMEOUT_SECS.saturating_add(CALL_CLOCK_SKEW_SECS)
}

/// Validate the outer/full-signal deadline independently from the shorter ring window.
pub fn valid_signal_deadline(created_at: u64, expires_at: u64) -> bool {
    expires_at > created_at
        && expires_at.saturating_sub(created_at)
            <= CALL_SIGNAL_TTL_SECS.saturating_add(CALL_CLOCK_SKEW_SECS)
}

/// Validate a received control whose sender creation time is not carried separately.
pub fn valid_control_expiry(expires_at: u64, now: u64) -> bool {
    expires_at > now.saturating_sub(CALL_CLOCK_SKEW_SECS)
        && expires_at <= now.saturating_add(CALL_SIGNAL_TTL_SECS + CALL_CLOCK_SKEW_SECS)
}

/// Primary device ID or a random lowercase-hex linked-device ID.
pub fn valid_device_id(device_id: &str) -> bool {
    device_id == protocol_types::PRIMARY_DEVICE_ID || valid_call_id(device_id)
}

/// Explicit terminal outcome. These values are carried on the wire and shown accurately
/// by shells instead of mapping every terminal event to "answered elsewhere."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallTerminalReason {
    AnsweredHere,
    AnsweredElsewhere,
    DeclinedHere,
    DeclinedElsewhere,
    CallerCancelled,
    Expired,
    Busy,
    TransportError,
}

/// Monotonic non-terminal state. Ordering is intentional and used by
/// [`CallRegistry::transition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallPhase {
    Offered,
    Ringing,
    AnswerPendingUnlock,
    Claiming,
    Winner,
    Active,
}

/// Persistable non-secret signaling record. Media room IDs and keys never enter this
/// structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRecord {
    pub call_instance_id: String,
    pub offer_id: String,
    pub prior_offer_ids: VecDeque<String>,
    pub expires_at: u64,
    pub updated_at: u64,
    pub state: CallRecordState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CallRecordState {
    Live {
        phase: CallPhase,
    },
    Terminal {
        reason: CallTerminalReason,
        retain_until: u64,
    },
}

/// Result of receiving an authenticated offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferDecision {
    Ring,
    Duplicate,
    Suppressed(CallTerminalReason),
    Expired,
    Invalid,
    Capacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeDecision {
    Accepted,
    Duplicate,
    Stale,
    Suppressed(CallTerminalReason),
    Expired,
    Invalid,
    Missing,
}

/// Result of applying a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionDecision {
    Applied,
    Duplicate,
    Regressive,
    Prerequisite,
    Terminal(CallTerminalReason),
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalDecision {
    Applied(CallTerminalReason),
    Duplicate(CallTerminalReason),
    Conflict,
    Invalid,
    Capacity,
}

/// Bounded, persistable call state. Entries stay in arrival order so capacity eviction
/// is deterministic across process restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRegistry {
    records: VecDeque<CallRecord>,
}

impl CallRegistry {
    pub fn records(&self) -> &VecDeque<CallRecord> {
        &self.records
    }

    /// Apply an offer without extending its original deadline on duplicates.
    pub fn receive_offer(
        &mut self,
        call_instance_id: &str,
        offer_id: &str,
        created_at: u64,
        expires_at: u64,
        now: u64,
        retention_secs: u64,
    ) -> OfferDecision {
        self.purge(now);
        if !valid_call_id(call_instance_id)
            || !valid_call_id(offer_id)
            || !valid_offer_deadline(created_at, expires_at)
            || created_at > now.saturating_add(CALL_CLOCK_SKEW_SECS)
            || expires_at > now.saturating_add(CALL_RING_TIMEOUT_SECS + CALL_CLOCK_SKEW_SECS)
        {
            return OfferDecision::Invalid;
        }
        if let Some(record) = self
            .records
            .iter()
            .find(|record| record.call_instance_id == call_instance_id)
        {
            return match record.state {
                CallRecordState::Terminal { reason, .. }
                    if record.offer_id == offer_id
                        || record.prior_offer_ids.iter().any(|prior| prior == offer_id) =>
                {
                    OfferDecision::Suppressed(reason)
                }
                CallRecordState::Terminal { .. } => OfferDecision::Invalid,
                CallRecordState::Live { .. } if record.offer_id == offer_id => {
                    OfferDecision::Duplicate
                }
                // A second initial offer ID for one logical call is malformed. Resume
                // signaling has a separate explicit path and never rings.
                CallRecordState::Live { .. } => OfferDecision::Invalid,
            };
        }
        if expires_at <= now {
            let _ = self.record_terminal(
                call_instance_id,
                offer_id,
                CallTerminalReason::Expired,
                now,
                retention_secs,
            );
            return OfferDecision::Expired;
        }
        if !self.make_room(now) {
            return OfferDecision::Capacity;
        }
        self.records.push_back(CallRecord {
            call_instance_id: call_instance_id.to_string(),
            offer_id: offer_id.to_string(),
            prior_offer_ids: VecDeque::new(),
            expires_at,
            updated_at: now,
            state: CallRecordState::Live {
                phase: CallPhase::Ringing,
            },
        });
        OfferDecision::Ring
    }

    /// Adopt a fresh offer/media capability for an already-live logical call without
    /// ever ringing. Terminal calls cannot be revived.
    pub fn receive_resume(
        &mut self,
        call_instance_id: &str,
        offer_id: &str,
        created_at: u64,
        expires_at: u64,
        now: u64,
    ) -> ResumeDecision {
        self.purge(now);
        if !valid_call_id(call_instance_id)
            || !valid_call_id(offer_id)
            || !valid_signal_deadline(created_at, expires_at)
            || !valid_control_expiry(expires_at, now)
        {
            return ResumeDecision::Invalid;
        }
        if expires_at <= now {
            return ResumeDecision::Expired;
        }
        let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.call_instance_id == call_instance_id)
        else {
            return ResumeDecision::Missing;
        };
        match record.state {
            CallRecordState::Terminal { reason, .. } => ResumeDecision::Suppressed(reason),
            CallRecordState::Live { .. } if record.offer_id == offer_id => {
                ResumeDecision::Duplicate
            }
            CallRecordState::Live { .. }
                if record.prior_offer_ids.iter().any(|prior| prior == offer_id) =>
            {
                ResumeDecision::Stale
            }
            CallRecordState::Live { .. } => {
                while record.prior_offer_ids.len() >= MAX_PRIOR_OFFERS {
                    record.prior_offer_ids.pop_front();
                }
                record.prior_offer_ids.push_back(record.offer_id.clone());
                record.offer_id = offer_id.to_string();
                record.expires_at = expires_at;
                record.updated_at = now;
                ResumeDecision::Accepted
            }
        }
    }

    /// Advance a live record. Equal transitions are idempotent; backwards transitions
    /// and every transition after terminal state are refused.
    pub fn transition(
        &mut self,
        call_instance_id: &str,
        offer_id: &str,
        phase: CallPhase,
        now: u64,
    ) -> TransitionDecision {
        let Some(record) = self.records.iter_mut().find(|record| {
            record.call_instance_id == call_instance_id && record.offer_id == offer_id
        }) else {
            return TransitionDecision::Missing;
        };
        match record.state {
            CallRecordState::Terminal { reason, .. } => TransitionDecision::Terminal(reason),
            CallRecordState::Live { phase: current } if phase == current => {
                TransitionDecision::Duplicate
            }
            CallRecordState::Live { phase: current } if phase < current => {
                TransitionDecision::Regressive
            }
            CallRecordState::Live { phase: current }
                if phase == CallPhase::Active && current != CallPhase::Winner =>
            {
                TransitionDecision::Prerequisite
            }
            CallRecordState::Live { .. } => {
                record.state = CallRecordState::Live { phase };
                record.updated_at = now;
                TransitionDecision::Applied
            }
        }
    }

    /// Terminal state is accepted even before an offer. The first authenticated
    /// terminal outcome wins and its retention is never extended by duplicates.
    pub fn record_terminal(
        &mut self,
        call_instance_id: &str,
        offer_id: &str,
        reason: CallTerminalReason,
        now: u64,
        retention_secs: u64,
    ) -> TerminalDecision {
        self.purge(now);
        if !valid_call_id(call_instance_id) || !valid_call_id(offer_id) {
            return TerminalDecision::Invalid;
        }
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.call_instance_id == call_instance_id)
        {
            if record.offer_id != offer_id
                && !record.prior_offer_ids.iter().any(|prior| prior == offer_id)
            {
                return TerminalDecision::Conflict;
            }
            if let CallRecordState::Terminal {
                reason: existing, ..
            } = record.state
            {
                return TerminalDecision::Duplicate(existing);
            }
            record.updated_at = now;
            record.state = CallRecordState::Terminal {
                reason,
                retain_until: tombstone_deadline(now, retention_secs),
            };
            return TerminalDecision::Applied(reason);
        }
        if !self.make_room(now) {
            return TerminalDecision::Capacity;
        }
        self.records.push_back(CallRecord {
            call_instance_id: call_instance_id.to_string(),
            offer_id: offer_id.to_string(),
            prior_offer_ids: VecDeque::new(),
            expires_at: now,
            updated_at: now,
            state: CallRecordState::Terminal {
                reason,
                retain_until: tombstone_deadline(now, retention_secs),
            },
        });
        TerminalDecision::Applied(reason)
    }

    pub fn terminal_reason(&self, call_instance_id: &str) -> Option<CallTerminalReason> {
        self.records
            .iter()
            .find(|record| record.call_instance_id == call_instance_id)
            .and_then(|record| match record.state {
                CallRecordState::Terminal { reason, .. } => Some(reason),
                CallRecordState::Live { .. } => None,
            })
    }

    /// Expire live offers and remove tombstones whose correctness/user-retention window
    /// elapsed.
    pub fn expire(&mut self, now: u64, retention_secs: u64) -> Vec<String> {
        let mut expired = Vec::new();
        for record in &mut self.records {
            let expirable = matches!(
                record.state,
                CallRecordState::Live {
                    phase: CallPhase::Offered
                        | CallPhase::Ringing
                        | CallPhase::AnswerPendingUnlock
                        | CallPhase::Claiming
                }
            );
            if expirable && record.expires_at <= now {
                expired.push(record.call_instance_id.clone());
                record.updated_at = now;
                record.state = CallRecordState::Terminal {
                    reason: CallTerminalReason::Expired,
                    retain_until: tombstone_deadline(now, retention_secs),
                };
            }
        }
        self.purge(now);
        expired
    }

    /// Re-apply a (possibly shortened) retention to tombstones that already exist, then
    /// purge. Lowering the user's retention setting has to take effect on what is already
    /// stored, not only on what happens next — and a tombstone can only get *shorter* this
    /// way, never longer, with [`MIN_TOMBSTONE_SECS`] still the floor underneath it.
    pub fn retain_within(&mut self, now: u64, retention_secs: u64) {
        for record in &mut self.records {
            if let CallRecordState::Terminal { retain_until, .. } = &mut record.state {
                *retain_until =
                    (*retain_until).min(tombstone_deadline(record.updated_at, retention_secs));
            }
        }
        self.purge(now);
    }

    pub fn purge(&mut self, now: u64) {
        self.records.retain(|record| {
            !matches!(
                record.state,
                CallRecordState::Terminal { retain_until, .. } if retain_until <= now
            )
        });
    }

    fn make_room(&mut self, now: u64) -> bool {
        self.purge(now);
        while self.records.len() >= MAX_CALL_RECORDS {
            let Some(index) = self
                .records
                .iter()
                .position(|record| matches!(record.state, CallRecordState::Terminal { .. }))
            else {
                return false;
            };
            self.records.remove(index);
        }
        true
    }
}

fn tombstone_deadline(now: u64, retention_secs: u64) -> u64 {
    now.saturating_add(retention_secs.max(MIN_TOMBSTONE_SECS))
}

/// One answer attempt. It contains routing/authentication identifiers only, never media
/// capability material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerClaim {
    pub call_instance_id: String,
    pub offer_id: String,
    pub claim_nonce: String,
    pub answering_device_id: String,
    pub reply_to_mailbox: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerWinner {
    pub claim_nonce: String,
    pub answering_device_id: String,
    pub reply_to_mailbox: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimDecision {
    Winner(AnswerWinner),
    Duplicate(AnswerWinner),
    Lost(AnswerWinner),
    Invalid,
}

/// Caller-side first-answer arbiter. The first valid claim wins permanently.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerArbiter {
    call_instance_id: String,
    offer_id: String,
    winner: Option<AnswerWinner>,
}

impl AnswerArbiter {
    pub fn new(call_instance_id: String, offer_id: String) -> Self {
        Self {
            call_instance_id,
            offer_id,
            winner: None,
        }
    }

    pub fn winner(&self) -> Option<&AnswerWinner> {
        self.winner.as_ref()
    }

    pub fn claim(&mut self, claim: &AnswerClaim) -> ClaimDecision {
        if claim.call_instance_id != self.call_instance_id
            || claim.offer_id != self.offer_id
            || !valid_call_id(&claim.claim_nonce)
            || !valid_device_id(&claim.answering_device_id)
            || claim.reply_to_mailbox.len() != 64
            || !claim
                .reply_to_mailbox
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return ClaimDecision::Invalid;
        }
        if let Some(winner) = self.winner.clone() {
            if winner.claim_nonce == claim.claim_nonce
                && winner.answering_device_id == claim.answering_device_id
                && winner.reply_to_mailbox == claim.reply_to_mailbox
            {
                return ClaimDecision::Duplicate(winner);
            }
            return ClaimDecision::Lost(winner);
        }
        let winner = AnswerWinner {
            claim_nonce: claim.claim_nonce.clone(),
            answering_device_id: claim.answering_device_id.clone(),
            reply_to_mailbox: claim.reply_to_mailbox.clone(),
        };
        self.winner = Some(winner.clone());
        ClaimDecision::Winner(winner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> String {
        format!("{byte:02x}").repeat(16)
    }

    #[test]
    fn identifiers_and_deadlines_are_strict() {
        assert!(valid_call_id(&id(1)));
        assert!(!valid_call_id(&id(0xab).to_uppercase()));
        assert!(!valid_call_id("short"));
        assert!(valid_offer_deadline(100, 145));
        assert!(valid_offer_deadline(100, 150));
        assert!(!valid_offer_deadline(100, 151));
        assert!(!valid_offer_deadline(100, 100));
        assert!(valid_signal_deadline(100, 160));
        assert!(valid_signal_deadline(100, 165));
        assert!(!valid_signal_deadline(100, 166));
        assert!(valid_control_expiry(160, 100));
        assert!(!valid_control_expiry(200, 100));
        assert!(valid_device_id("0"));
        assert!(valid_device_id(&id(9)));
        assert!(!valid_device_id("desktop"));
        assert_ne!(random_call_id(), random_call_id());
    }

    #[test]
    fn terminal_before_offer_suppresses_the_late_ring() {
        let mut calls = CallRegistry::default();
        let call = id(1);
        let offer = id(2);
        calls.record_terminal(
            &call,
            &offer,
            CallTerminalReason::AnsweredElsewhere,
            120,
            7 * 24 * 3600,
        );
        assert_eq!(
            calls.receive_offer(&call, &offer, 100, 145, 121, 7 * 24 * 3600),
            OfferDecision::Suppressed(CallTerminalReason::AnsweredElsewhere)
        );
    }

    #[test]
    fn every_terminal_reason_converges_across_delivery_orders_and_duplicates() {
        let reasons = [
            CallTerminalReason::AnsweredHere,
            CallTerminalReason::AnsweredElsewhere,
            CallTerminalReason::DeclinedHere,
            CallTerminalReason::DeclinedElsewhere,
            CallTerminalReason::CallerCancelled,
            CallTerminalReason::Expired,
            CallTerminalReason::Busy,
            CallTerminalReason::TransportError,
        ];
        for (index, reason) in reasons.into_iter().enumerate() {
            let call = format!("{:032x}", index + 100);
            let offer = id(2);

            let mut terminal_first = CallRegistry::default();
            terminal_first.record_terminal(&call, &offer, reason, 110, 0);
            terminal_first.record_terminal(&call, &offer, reason, 111, 0);
            assert_eq!(
                terminal_first.receive_offer(&call, &offer, 100, 145, 112, 0),
                OfferDecision::Suppressed(reason)
            );

            let mut offer_first = CallRegistry::default();
            assert_eq!(
                offer_first.receive_offer(&call, &offer, 100, 145, 101, 0),
                OfferDecision::Ring
            );
            assert_eq!(
                offer_first.receive_offer(&call, &offer, 100, 145, 102, 0),
                OfferDecision::Duplicate
            );
            offer_first.record_terminal(&call, &offer, reason, 110, 0);
            assert_eq!(offer_first.terminal_reason(&call), Some(reason));
            assert_eq!(
                offer_first.transition(&call, &offer, CallPhase::Active, 111),
                TransitionDecision::Terminal(reason)
            );
        }
    }

    #[test]
    fn duplicate_offer_never_extends_the_original_deadline() {
        let mut calls = CallRegistry::default();
        let call = id(1);
        let offer = id(2);
        assert_eq!(
            calls.receive_offer(&call, &offer, 100, 145, 101, 0),
            OfferDecision::Ring
        );
        assert_eq!(
            calls.receive_offer(&call, &offer, 120, 165, 121, 0),
            OfferDecision::Duplicate
        );
        assert_eq!(calls.records()[0].expires_at, 145);
    }

    #[test]
    fn resume_rotates_offer_id_without_ringing_or_reviving_terminal_state() {
        let mut calls = CallRegistry::default();
        let call = id(1);
        let initial = id(2);
        let resumed = id(3);
        calls.receive_offer(&call, &initial, 100, 145, 101, 0);
        calls.transition(&call, &initial, CallPhase::Winner, 109);
        calls.transition(&call, &initial, CallPhase::Active, 110);
        assert_eq!(
            calls.receive_resume(&call, &resumed, 120, 180, 121),
            ResumeDecision::Accepted
        );
        assert_eq!(calls.records()[0].offer_id, resumed);
        assert_eq!(
            calls.receive_resume(&call, &id(3), 120, 180, 122),
            ResumeDecision::Duplicate
        );
        assert_eq!(
            calls.receive_resume(&call, &initial, 120, 180, 122),
            ResumeDecision::Stale
        );
        calls.record_terminal(&call, &id(3), CallTerminalReason::CallerCancelled, 123, 0);
        assert_eq!(
            calls.receive_resume(&call, &id(4), 124, 184, 125),
            ResumeDecision::Suppressed(CallTerminalReason::CallerCancelled)
        );
    }

    #[test]
    fn delayed_terminal_from_an_accepted_pre_resume_offer_ends_the_logical_call() {
        let mut calls = CallRegistry::default();
        let call = id(1);
        let initial = id(2);
        let resumed = id(3);
        calls.receive_offer(&call, &initial, 100, 145, 101, 0);
        calls.transition(&call, &initial, CallPhase::Winner, 109);
        calls.transition(&call, &initial, CallPhase::Active, 110);
        assert_eq!(
            calls.receive_resume(&call, &resumed, 120, 180, 121),
            ResumeDecision::Accepted
        );
        assert_eq!(
            calls.record_terminal(&call, &initial, CallTerminalReason::CallerCancelled, 122, 0,),
            TerminalDecision::Applied(CallTerminalReason::CallerCancelled)
        );
        assert_eq!(
            calls.terminal_reason(&call),
            Some(CallTerminalReason::CallerCancelled)
        );
    }

    #[test]
    fn stale_and_malformed_offers_never_ring() {
        let mut calls = CallRegistry::default();
        assert_eq!(
            calls.receive_offer(&id(1), &id(2), 100, 145, 146, 0),
            OfferDecision::Expired
        );
        assert_eq!(
            calls.receive_offer(&id(3), &id(4), 100, 1000, 101, 0),
            OfferDecision::Invalid
        );
        assert_eq!(
            calls.receive_offer(&id(5), &id(6), 1_000, 1_045, 100, 0),
            OfferDecision::Invalid,
            "a sender cannot make us ring on a far-future clock"
        );
    }

    #[test]
    fn transitions_are_monotonic_and_terminal_is_final() {
        let mut calls = CallRegistry::default();
        let call = id(1);
        let offer = id(2);
        assert_eq!(
            calls.receive_offer(&call, &offer, 100, 145, 101, 0),
            OfferDecision::Ring
        );
        assert_eq!(
            calls.transition(&call, &offer, CallPhase::AnswerPendingUnlock, 102),
            TransitionDecision::Applied
        );
        assert_eq!(
            calls.transition(&call, &offer, CallPhase::Ringing, 103),
            TransitionDecision::Regressive
        );
        assert_eq!(
            calls.transition(&call, &offer, CallPhase::Active, 103),
            TransitionDecision::Prerequisite,
            "media cannot make a call active before caller acknowledgement"
        );
        assert_eq!(
            calls.transition(&call, &offer, CallPhase::Winner, 103),
            TransitionDecision::Applied
        );
        assert_eq!(
            calls.transition(&call, &offer, CallPhase::Active, 104),
            TransitionDecision::Applied
        );
        calls.record_terminal(&call, &offer, CallTerminalReason::CallerCancelled, 104, 0);
        assert_eq!(
            calls.transition(&call, &offer, CallPhase::Active, 105),
            TransitionDecision::Terminal(CallTerminalReason::CallerCancelled)
        );
        assert_eq!(
            calls.record_terminal(
                &call,
                &offer,
                CallTerminalReason::AnsweredElsewhere,
                106,
                999,
            ),
            TerminalDecision::Duplicate(CallTerminalReason::CallerCancelled),
            "a duplicate/conflicting terminal cannot rewrite history"
        );
        assert_eq!(
            calls.record_terminal(&call, &id(9), CallTerminalReason::AnsweredElsewhere, 107, 0,),
            TerminalDecision::Conflict,
            "a terminal for another offer cannot end this call"
        );
    }

    #[test]
    fn immediate_retention_keeps_the_mandatory_ordering_window() {
        let mut calls = CallRegistry::default();
        let call = id(1);
        let offer = id(2);
        calls.record_terminal(&call, &offer, CallTerminalReason::DeclinedElsewhere, 100, 0);
        calls.purge(100 + MIN_TOMBSTONE_SECS - 1);
        assert_eq!(
            calls.terminal_reason(&call),
            Some(CallTerminalReason::DeclinedElsewhere)
        );
        calls.purge(100 + MIN_TOMBSTONE_SECS);
        assert_eq!(calls.terminal_reason(&call), None);
    }

    #[test]
    fn first_valid_answer_claim_wins_and_retries_are_idempotent() {
        let call = id(1);
        let offer = id(2);
        let first = AnswerClaim {
            call_instance_id: call.clone(),
            offer_id: offer.clone(),
            claim_nonce: id(3),
            answering_device_id: id(5),
            reply_to_mailbox: "a".repeat(64),
        };
        let second = AnswerClaim {
            claim_nonce: id(4),
            answering_device_id: id(6),
            reply_to_mailbox: "b".repeat(64),
            ..first.clone()
        };
        let mut arbiter = AnswerArbiter::new(call, offer);
        assert!(matches!(
            arbiter.claim(&first),
            ClaimDecision::Winner(AnswerWinner { ref answering_device_id, .. })
                if answering_device_id == &id(5)
        ));
        assert!(matches!(
            arbiter.claim(&first),
            ClaimDecision::Duplicate(AnswerWinner { ref answering_device_id, .. })
                if answering_device_id == &id(5)
        ));
        assert!(matches!(
            arbiter.claim(&second),
            ClaimDecision::Lost(AnswerWinner { ref answering_device_id, .. })
                if answering_device_id == &id(5)
        ));
    }

    #[test]
    fn invalid_claim_cannot_win() {
        let mut arbiter = AnswerArbiter::new(id(1), id(2));
        let wrong_call = AnswerClaim {
            call_instance_id: id(9),
            offer_id: id(2),
            claim_nonce: id(3),
            answering_device_id: id(5),
            reply_to_mailbox: "a".repeat(64),
        };
        assert_eq!(arbiter.claim(&wrong_call), ClaimDecision::Invalid);
        let wrong_offer = AnswerClaim {
            call_instance_id: id(1),
            offer_id: id(9),
            ..wrong_call
        };
        assert_eq!(arbiter.claim(&wrong_offer), ClaimDecision::Invalid);
        assert!(arbiter.winner().is_none());
    }

    #[test]
    fn registry_is_bounded_without_evicting_live_calls() {
        let mut calls = CallRegistry::default();
        for n in 0..MAX_CALL_RECORDS {
            let call = format!("{n:032x}");
            calls.receive_offer(&call, &id(2), 100, 145, 101, 0);
        }
        assert_eq!(calls.records().len(), MAX_CALL_RECORDS);
        assert_eq!(
            calls.receive_offer(&id(250), &id(3), 100, 145, 101, 0),
            OfferDecision::Capacity
        );
        calls.record_terminal(
            &format!("{:032x}", 0),
            &id(2),
            CallTerminalReason::Expired,
            102,
            0,
        );
        assert_eq!(
            calls.receive_offer(&id(250), &id(3), 100, 145, 103, 0),
            OfferDecision::Ring
        );
        assert_eq!(calls.records().len(), MAX_CALL_RECORDS);
    }
}

#[cfg(test)]
#[path = "callstate_permutation_tests.rs"]
mod permutation_tests;
