//! The **minimal call-control capsule**: the smallest thing that can make a locked
//! device ring, and stop it ringing.
//!
//! A capsule is the second of the two layers an incoming call travels on
//! (`internal/CALL_PLAN.md` §4.3). The first is the ordinary encrypted offer, which carries the
//! media ticket and only opens after the vault does. This one is sealed to the device's
//! call-control key, so a phone with a closed vault can present, correlate, cancel, and
//! decline a ring — and nothing more.
//!
//! What it deliberately does **not** carry: a media room id, a media key, message
//! content, contacts, or any reusable account capability. A capsule that leaked in full
//! would let its holder learn that a call was offered and to which device — not join it,
//! not read anything, not act as the account.
//!
//! Authenticity is the caller's device signature over every field, verified against a
//! key the recipient already trusts: the KT-verified roster once unlocked, and the
//! approved-caller screening index while locked. Freshness is the absolute deadlines
//! plus a per-capsule nonce; ordering and duplicate suppression are
//! [`crate::callstate`]'s job, keyed by the same `call_instance_id` the encrypted offer
//! carries — which is what makes the two layers converge on one ring instead of two.

use serde::{Deserialize, Serialize};

use crate::callstate::{
    random_call_id, valid_call_id, valid_control_expiry, valid_device_id, valid_offer_deadline,
    valid_signal_deadline, CallTerminalReason,
};

/// Wire version of the capsule format. A capsule that does not carry exactly this is
/// refused rather than guessed at — there is no legacy client to be compatible with.
pub const CAPSULE_VERSION: u8 = 1;

/// Longest display name a capsule may carry. Long enough for a real name, short enough
/// that the capsule stays small and a hostile sender cannot use the ring UI as a canvas.
pub const MAX_DISPLAY_NAME: usize = 64;

/// What this capsule is asking the device to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleKind {
    /// Start presenting a ring for `call_instance_id`.
    Offer,
    /// Stop presenting it, with the reason the UI must show honestly.
    Terminal,
}

/// Which of the sending device's keys signed this capsule.
///
/// A device with an open vault signs with its **roster** key, the same authority as every
/// other device-signed record. A device whose vault is **locked** has no roster key — it
/// is sealed in the vault — and can only sign with its scoped call-control key
/// (`internal/CALL_PLAN.md` §3.4: "explicit decline … uses only the scoped call-control identity").
///
/// The two are not interchangeable, and [`CallCapsule::well_formed`] enforces the
/// difference: a call-control key may sign a capsule that **ends** a ring and never one
/// that starts one. That is the whole reach of the call-only identity — it can refuse a
/// call, it can never place one (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleSigner {
    /// The sending device's KT-verified roster Ed25519 key.
    Roster,
    /// The sending device's published call-control Ed25519 key, bound to it by a
    /// [`kt_log::CallKeyBinding`] the recipient verifies against the same roster.
    CallKey,
}

/// The sealed contents of a call-control capsule.
///
/// Every field is covered by [`signing_payload`](CallCapsule::signing_payload), so the
/// relay — which stores the sealed bytes — cannot alter which device is being rung, for
/// which call, until when, or by whom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallCapsule {
    /// Format version; must equal [`CAPSULE_VERSION`].
    pub v: u8,
    pub kind: CapsuleKind,
    /// The logical call — the same id the encrypted offer carries, so a device that
    /// receives both rings once.
    pub call_instance_id: String,
    /// The id this ring is keyed under in [`crate::callstate::CallRegistry`]: the 1:1
    /// `offer_id`, or a group ring's `ring_id`. It is the same value the encrypted offer
    /// carries, which is what lets the two layers converge on one registry record — and
    /// what lets a locked device send a decline/terminal the caller will accept.
    pub offer_id: String,
    /// Random, single-use identifier for **this device's** presentation of the ring. It
    /// is the only correlator that may be exposed outside end-to-end encryption, and it
    /// grants nothing.
    pub ring_handle: String,
    /// The caller's account name — display and screening. Never a contact list.
    pub from: String,
    /// The caller device's identity key and id: the verification material a recipient
    /// checks against its pinned roster (unlocked) or screening index (locked).
    pub caller_identity_key: String,
    pub caller_device_id: String,
    /// The device this capsule is for. Bound in so a capsule cannot be replayed at a
    /// sibling device.
    pub to_device_id: String,
    /// Media shape, for the ring UI only: whether video was offered, and whether this is
    /// a group call.
    pub video: bool,
    pub group: bool,
    /// Display name honoring the recipient's notification privacy level. Empty means the
    /// ring says only "Sona call" — which is also what a locked device shows when it
    /// cannot yet verify who is calling.
    pub display_name: String,
    pub created_at: u64,
    /// When the ring stops on its own.
    pub ring_expires_at: u64,
    /// When the capsule itself is stale (call-scale, never the generic message TTL).
    pub expires_at: u64,
    /// Exact route for this device's reply controls (decline/busy), so an answer never
    /// wakes the caller's other devices.
    pub reply_to_mailbox: String,
    /// The sending device's **call-control** mailbox and public call key, so a recipient
    /// whose vault is locked can reply on the layer it can actually use. Both arrive
    /// inside an authenticated payload, which is what lets a locked device seal a decline
    /// without trusting the relay to hand it the right key.
    #[serde(default)]
    pub reply_call_mailbox: String,
    #[serde(default)]
    pub reply_call_key: String,
    /// Which of the sender's keys signed this (see [`CapsuleSigner`]).
    pub signer: CapsuleSigner,
    /// Terminal reason; `None` on an offer.
    pub reason: Option<CallTerminalReason>,
    /// Per-capsule anti-replay nonce.
    pub nonce: String,
    /// Ed25519 (base64) by the caller device's roster signing key over
    /// [`signing_payload`](Self::signing_payload).
    pub signature: String,
}

/// Everything needed to mint a capsule except the signature.
#[derive(Debug, Clone)]
pub struct CapsulePlan {
    pub kind: CapsuleKind,
    pub call_instance_id: String,
    pub offer_id: String,
    pub from: String,
    pub caller_identity_key: String,
    pub caller_device_id: String,
    pub to_device_id: String,
    pub video: bool,
    pub group: bool,
    pub display_name: String,
    pub created_at: u64,
    pub ring_expires_at: u64,
    pub expires_at: u64,
    pub reply_to_mailbox: String,
    pub reply_call_mailbox: String,
    pub reply_call_key: String,
    pub signer: CapsuleSigner,
    pub reason: Option<CallTerminalReason>,
}

impl CallCapsule {
    /// The exact bytes the caller device signs. Length-prefixed and domain-separated, so
    /// no two field layouts can produce the same payload.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        v.extend_from_slice(b"sona-call-capsule-v1");
        v.push(self.v);
        v.push(match self.kind {
            CapsuleKind::Offer => 0,
            CapsuleKind::Terminal => 1,
        });
        v.push(match self.signer {
            CapsuleSigner::Roster => 0,
            CapsuleSigner::CallKey => 1,
        });
        for field in [
            self.call_instance_id.as_bytes(),
            self.offer_id.as_bytes(),
            self.ring_handle.as_bytes(),
            self.from.as_bytes(),
            self.caller_identity_key.as_bytes(),
            self.caller_device_id.as_bytes(),
            self.to_device_id.as_bytes(),
            self.display_name.as_bytes(),
            self.reply_to_mailbox.as_bytes(),
            self.reply_call_mailbox.as_bytes(),
            self.reply_call_key.as_bytes(),
            self.nonce.as_bytes(),
        ] {
            v.extend_from_slice(&(field.len() as u64).to_be_bytes());
            v.extend_from_slice(field);
        }
        v.push(self.video as u8);
        v.push(self.group as u8);
        v.extend_from_slice(&self.created_at.to_be_bytes());
        v.extend_from_slice(&self.ring_expires_at.to_be_bytes());
        v.extend_from_slice(&self.expires_at.to_be_bytes());
        v.push(match self.reason {
            None => 0xff,
            Some(reason) => reason as u8,
        });
        v
    }

    /// Mint and sign a capsule for one device. `sign` must sign with the private half of
    /// `caller_identity` device's roster signing key.
    pub fn new(plan: CapsulePlan, sign: impl FnOnce(&[u8]) -> String) -> Self {
        let mut capsule = CallCapsule {
            v: CAPSULE_VERSION,
            kind: plan.kind,
            call_instance_id: plan.call_instance_id,
            offer_id: plan.offer_id,
            ring_handle: random_call_id(),
            from: plan.from,
            caller_identity_key: plan.caller_identity_key,
            caller_device_id: plan.caller_device_id,
            to_device_id: plan.to_device_id,
            video: plan.video,
            group: plan.group,
            display_name: plan.display_name,
            created_at: plan.created_at,
            ring_expires_at: plan.ring_expires_at,
            expires_at: plan.expires_at,
            reply_to_mailbox: plan.reply_to_mailbox,
            reply_call_mailbox: plan.reply_call_mailbox,
            reply_call_key: plan.reply_call_key,
            signer: plan.signer,
            reason: plan.reason,
            nonce: random_call_id(),
            signature: String::new(),
        };
        capsule.signature = sign(&capsule.signing_payload());
        capsule
    }

    /// Serialize for sealing. Bounded by construction — every field is length-checked by
    /// [`well_formed`](Self::well_formed) before it is signed or accepted.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parse a decrypted capsule. `None` for anything malformed; nothing is allocated
    /// from a size the sender chose.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > crypto_core::callkey::MAX_CAPSULE_BYTES {
            return None;
        }
        let capsule: CallCapsule = serde_json::from_slice(bytes).ok()?;
        capsule.well_formed().then_some(capsule)
    }

    /// Structural validity: exact id shapes, bounded strings, sane deadlines, and a
    /// reason exactly when the kind calls for one. Checked before any signature work.
    pub fn well_formed(&self) -> bool {
        self.v == CAPSULE_VERSION
            && valid_call_id(&self.call_instance_id)
            && valid_call_id(&self.offer_id)
            && valid_call_id(&self.ring_handle)
            && valid_call_id(&self.nonce)
            && valid_device_id(&self.caller_device_id)
            && valid_device_id(&self.to_device_id)
            && !self.from.is_empty()
            && self.from.len() <= 64
            // A locked sender cannot name its identity key — that lives in the vault — and
            // does not need to: its signature is checked against a call-control binding
            // keyed by device id, not against an identity key.
            && (!self.caller_identity_key.is_empty() || self.signer == CapsuleSigner::CallKey)
            && self.caller_identity_key.len() <= 64
            && self.display_name.len() <= MAX_DISPLAY_NAME
            && self.reply_to_mailbox.len() == 64
            && self.reply_to_mailbox.bytes().all(|b| b.is_ascii_hexdigit())
            // The reply route for the locked layer is optional (a sender with no
            // call-control identity has none) but never malformed.
            && (self.reply_call_mailbox.is_empty()
                || (self.reply_call_mailbox.len() == 64
                    && self.reply_call_mailbox.bytes().all(|b| b.is_ascii_hexdigit())))
            && self.reply_call_key.len() <= 64
            && !self.signature.is_empty()
            && self.signature.len() <= 128
            && valid_signal_deadline(self.created_at, self.expires_at)
            // A call-only key may end a ring and never start one: that is the entire
            // reach of the scoped identity (`internal/CALL_PLAN.md` §4.2). Without this rule a
            // stolen call key — which lives outside the vault, by design — could make a
            // peer's phone ring.
            && (self.signer == CapsuleSigner::Roster
                || matches!(
                    (self.kind, self.reason),
                    (
                        CapsuleKind::Terminal,
                        Some(CallTerminalReason::DeclinedHere | CallTerminalReason::Busy)
                    )
                ))
            && match self.kind {
                // An offer must name a ring window it cannot stretch.
                CapsuleKind::Offer => {
                    self.reason.is_none()
                        && valid_offer_deadline(self.created_at, self.ring_expires_at)
                }
                // A terminal carries no ring window of its own.
                CapsuleKind::Terminal => self.reason.is_some(),
            }
    }

    /// Is this capsule for us, fresh, and really from the device it names?
    ///
    /// Fail-closed and in this order: shape, addressing, freshness, then the signature
    /// under `expected_signing_key` — the key the caller's KT-verified roster (or the
    /// approved-caller screening index) gives for `caller_device_id`. A caller we cannot
    /// place has no key here, so its capsule is simply refused.
    ///
    /// The caller of this function picks *which* key by reading [`Self::signer`]: the
    /// roster key, or the call-control key the device's verified
    /// [`kt_log::CallKeyBinding`] publishes. Both are rooted in the same KT-verified
    /// roster; only their reach differs, and [`Self::well_formed`] is what bounds it.
    pub fn verify(&self, my_device_id: &str, expected_signing_key: &str, now: u64) -> bool {
        self.well_formed()
            && self.to_device_id == my_device_id
            && valid_control_expiry(self.expires_at, now)
            && !expected_signing_key.is_empty()
            && verify_signature(
                expected_signing_key,
                &self.signing_payload(),
                &self.signature,
            )
    }
}

/// Ed25519 verification over the same base64 conventions — and the same fail-closed
/// behavior — as every other device-signed record.
fn verify_signature(signing_key_b64: &str, message: &[u8], signature_b64: &str) -> bool {
    kt_log::verify_ed25519(signing_key_b64, message, signature_b64)
}

#[cfg(test)]
mod tests {
    /// SP-20 (the half that cannot be a libFuzzer target from `fuzz/`): the JSON parse a
    /// **locked** device runs on relay-supplied bytes.
    ///
    /// `crypto_core::CallKey::open_capsule` — the AEAD/header parser ahead of this — is
    /// covered by the `call_capsule` fuzz target. What follows the decrypt is
    /// `serde_json::from_slice::<CallCapsule>` plus `well_formed`, and that lives here in
    /// `client-core`, which the standalone fuzz package cannot depend on without dragging
    /// libopus/OpenH264 (cmake + a C toolchain) into the fuzz CI job for one target.
    /// So the same shape is driven deterministically instead: structured mutations of a
    /// real capsule, which is where a deserializer actually breaks — not uniform noise,
    /// which almost never reaches past the first byte.
    ///
    /// Invariant: no input panics, and nothing malformed is ever `well_formed`.
    #[test]
    fn the_locked_device_capsule_parser_never_panics_on_relay_bytes() {
        let seed = minted().0.encode();

        // A cheap deterministic PRNG — no dev-dependency, and a failure is reproducible.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..4000 {
            let mut buf = seed.clone();
            match next() % 5 {
                // Flip a byte.
                0 => {
                    let i = (next() as usize) % buf.len();
                    buf[i] ^= (next() % 256) as u8;
                }
                // Truncate anywhere, including to nothing.
                1 => buf.truncate((next() as usize) % (buf.len() + 1)),
                // Splice in multibyte UTF-8 and structural JSON characters.
                2 => {
                    let i = (next() as usize) % (buf.len() + 1);
                    let junk: &[u8] = match next() % 4 {
                        0 => "€€€".as_bytes(),
                        1 => b"\"\"\"",
                        2 => b"{[,:]}",
                        _ => &[0xff, 0xfe, 0x00],
                    };
                    buf.splice(i..i, junk.iter().copied());
                }
                // Repeat a slice — deep nesting / huge fields.
                3 => {
                    let chunk: Vec<u8> = buf.iter().take(64).copied().collect();
                    for _ in 0..(next() % 40) {
                        buf.extend_from_slice(&chunk);
                    }
                }
                // Raw bytes with no structure at all.
                _ => buf = (0..(next() % 256)).map(|_| (next() % 256) as u8).collect(),
            }

            // `decode` is the production entry point: size cap, deserialize, and
            // `well_formed`. The only requirement is that it returns, either way — a
            // panic here aborts the locked-device drain.
            if let Some(c) = CallCapsule::decode(&buf) {
                // Anything that survived `decode` is well-formed by construction, and
                // building its signing payload must not panic either.
                assert!(c.well_formed());
                let _ = c.signing_payload();
            }
        }
    }

    use super::*;
    use crate::callstate::{CALL_RING_TIMEOUT_SECS, CALL_SIGNAL_TTL_SECS};

    const NOW: u64 = 1_800_000_000;

    /// A real account, so the tests sign exactly the way a caller device does.
    fn caller() -> crypto_core::Account {
        crypto_core::create_account_with_username("alice", "Alice-Password-123!")
            .unwrap()
            .0
    }

    fn plan() -> CapsulePlan {
        CapsulePlan {
            kind: CapsuleKind::Offer,
            call_instance_id: random_call_id(),
            offer_id: random_call_id(),
            from: "alice".into(),
            caller_identity_key: "caller-identity-key".into(),
            caller_device_id: "0".into(),
            to_device_id: "a".repeat(32),
            video: true,
            group: false,
            display_name: "Alice".into(),
            created_at: NOW,
            ring_expires_at: NOW + CALL_RING_TIMEOUT_SECS,
            expires_at: NOW + CALL_SIGNAL_TTL_SECS,
            reply_to_mailbox: "b".repeat(64),
            reply_call_mailbox: "c".repeat(64),
            reply_call_key: String::new(),
            signer: CapsuleSigner::Roster,
            reason: None,
        }
    }

    fn sign_with(account: &crypto_core::Account) -> impl FnOnce(&[u8]) -> String + '_ {
        move |payload| account.ratchet_ref().sign(payload)
    }

    fn minted() -> (CallCapsule, String) {
        let account = caller();
        let capsule = CallCapsule::new(plan(), sign_with(&account));
        (capsule, account.ratchet_ref().signing_key())
    }

    #[test]
    fn a_signed_capsule_round_trips_and_verifies_for_its_device() {
        let (capsule, signing_key) = minted();
        let bytes = capsule.encode();
        let decoded = CallCapsule::decode(&bytes).unwrap();
        assert_eq!(decoded, capsule);
        assert!(decoded.verify(&"a".repeat(32), &signing_key, NOW));
        // …and not for a sibling device, however valid the signature.
        assert!(!decoded.verify(&"c".repeat(32), &signing_key, NOW));
    }

    #[test]
    fn the_capsule_carries_no_media_capability() {
        let (capsule, _) = minted();
        let json = String::from_utf8(capsule.encode()).unwrap();
        for forbidden in ["call_id", "key_b64", "room", "media_key"] {
            assert!(
                !json.contains(forbidden),
                "capsule must not carry {forbidden}"
            );
        }
        // Two capsules for the same call share no correlatable ring handle or nonce.
        let (second, _) = minted();
        assert_ne!(capsule.ring_handle, second.ring_handle);
        assert_ne!(capsule.nonce, second.nonce);
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let (capsule, signing_key) = minted();
        type Tamper = Box<dyn Fn(&mut CallCapsule)>;
        let tampered: Vec<Tamper> = vec![
            Box::new(|c| c.call_instance_id = random_call_id()),
            Box::new(|c| c.offer_id = random_call_id()),
            Box::new(|c| c.ring_handle = random_call_id()),
            Box::new(|c| c.from = "mallory".into()),
            Box::new(|c| c.caller_identity_key = "another-key".into()),
            Box::new(|c| c.caller_device_id = "b".repeat(32)),
            Box::new(|c| c.to_device_id = "c".repeat(32)),
            Box::new(|c| c.video = false),
            Box::new(|c| c.group = true),
            Box::new(|c| c.display_name = "Bank".into()),
            Box::new(|c| c.created_at += 1),
            Box::new(|c| c.ring_expires_at += 1),
            Box::new(|c| c.expires_at += 1),
            Box::new(|c| c.reply_to_mailbox = "c".repeat(64)),
            Box::new(|c| c.nonce = random_call_id()),
        ];
        for (index, mutate) in tampered.iter().enumerate() {
            let mut broken = capsule.clone();
            mutate(&mut broken);
            assert!(
                !broken.verify(&broken.to_device_id.clone(), &signing_key, NOW),
                "field {index} must be authenticated"
            );
        }
    }

    /// The reach of the call-only identity, in one rule: it may end a ring and never
    /// start one. A call key lives outside the vault by design, so if it could sign an
    /// offer, a stolen one could make a peer's phone ring.
    #[test]
    fn a_call_key_may_decline_a_ring_and_never_raise_one() {
        let key = caller();
        let declined = CallCapsule::new(
            CapsulePlan {
                kind: CapsuleKind::Terminal,
                signer: CapsuleSigner::CallKey,
                reason: Some(CallTerminalReason::DeclinedHere),
                ..plan()
            },
            sign_with(&key),
        );
        assert!(declined.well_formed());
        let busy = CallCapsule::new(
            CapsulePlan {
                kind: CapsuleKind::Terminal,
                signer: CapsuleSigner::CallKey,
                reason: Some(CallTerminalReason::Busy),
                ..plan()
            },
            sign_with(&key),
        );
        assert!(busy.well_formed());

        // An offer signed by a call key is refused outright…
        let ringer = CallCapsule::new(
            CapsulePlan {
                signer: CapsuleSigner::CallKey,
                ..plan()
            },
            sign_with(&key),
        );
        assert!(!ringer.well_formed());
        assert!(CallCapsule::decode(&ringer.encode()).is_none());
        // …and so is every terminal reason that is not this device refusing the call:
        // only the device that owns the ring may say it was answered or cancelled.
        for reason in [
            CallTerminalReason::AnsweredElsewhere,
            CallTerminalReason::CallerCancelled,
            CallTerminalReason::AnsweredHere,
            CallTerminalReason::Expired,
        ] {
            let overreach = CallCapsule::new(
                CapsulePlan {
                    kind: CapsuleKind::Terminal,
                    signer: CapsuleSigner::CallKey,
                    reason: Some(reason),
                    ..plan()
                },
                sign_with(&key),
            );
            assert!(
                !overreach.well_formed(),
                "{reason:?} is not a call key's to send"
            );
        }
    }

    /// The reply route a locked device answers on is authenticated like everything else:
    /// a relay that swapped it could point a decline at a mailbox of its own choosing.
    #[test]
    fn the_locked_reply_route_is_covered_by_the_signature() {
        let (capsule, signing_key) = minted();
        for mutate in [
            |c: &mut CallCapsule| c.reply_call_mailbox = "d".repeat(64),
            |c: &mut CallCapsule| c.reply_call_key = "another-call-key".into(),
            |c: &mut CallCapsule| c.signer = CapsuleSigner::CallKey,
        ] {
            let mut broken = capsule.clone();
            mutate(&mut broken);
            assert!(!broken.verify(&broken.to_device_id.clone(), &signing_key, NOW));
        }
        // Absent is fine (the sender has no call-control identity); malformed is not.
        let key = caller();
        let none = CallCapsule::new(
            CapsulePlan {
                reply_call_mailbox: String::new(),
                reply_call_key: String::new(),
                ..plan()
            },
            sign_with(&key),
        );
        assert!(none.well_formed());
        let bad = CallCapsule::new(
            CapsulePlan {
                reply_call_mailbox: "not-a-mailbox".into(),
                ..plan()
            },
            sign_with(&key),
        );
        assert!(!bad.well_formed());
    }

    #[test]
    fn an_unknown_version_or_wrong_signer_is_refused() {
        let (mut capsule, signing_key) = minted();
        let other = crypto_core::create_account_with_username("mallory", "Mallory-Password-9!")
            .unwrap()
            .0
            .ratchet_ref()
            .signing_key();
        assert!(!capsule.verify(&"a".repeat(32), &other, NOW));
        assert!(!capsule.verify(&"a".repeat(32), "", NOW));
        capsule.v = 2;
        assert!(!capsule.well_formed());
        assert!(!capsule.verify(&"a".repeat(32), &signing_key, NOW));
        assert!(CallCapsule::decode(&capsule.encode()).is_none());
    }

    #[test]
    fn a_stale_or_over_long_capsule_never_rings() {
        let (capsule, signing_key) = minted();
        // Valid up to its expiry, plus the documented clock-skew allowance; past that it
        // is refused however good the signature is.
        assert!(capsule.verify(&"a".repeat(32), &signing_key, capsule.expires_at - 1));
        assert!(!capsule.verify(
            &"a".repeat(32),
            &signing_key,
            capsule.expires_at + crate::callstate::CALL_CLOCK_SKEW_SECS + 1
        ));
        // A sender cannot mint a longer ring than the shared constant allows.
        let key = caller();
        let greedy = CallCapsule::new(
            CapsulePlan {
                ring_expires_at: NOW + CALL_RING_TIMEOUT_SECS * 10,
                expires_at: NOW + CALL_SIGNAL_TTL_SECS * 10,
                ..plan()
            },
            sign_with(&key),
        );
        assert!(!greedy.well_formed());
    }

    #[test]
    fn a_terminal_capsule_needs_a_reason_and_an_offer_must_not_have_one() {
        let key = caller();
        let terminal = CallCapsule::new(
            CapsulePlan {
                kind: CapsuleKind::Terminal,
                reason: Some(CallTerminalReason::CallerCancelled),
                ..plan()
            },
            sign_with(&key),
        );
        assert!(terminal.well_formed());
        assert!(terminal.verify(&"a".repeat(32), &key.ratchet_ref().signing_key(), NOW));

        let reasonless = CallCapsule::new(
            CapsulePlan {
                kind: CapsuleKind::Terminal,
                reason: None,
                ..plan()
            },
            sign_with(&key),
        );
        assert!(!reasonless.well_formed());

        let confused = CallCapsule::new(
            CapsulePlan {
                reason: Some(CallTerminalReason::Expired),
                ..plan()
            },
            sign_with(&key),
        );
        assert!(!confused.well_formed(), "an offer carries no reason");
    }

    /// The two delivery layers name the same registry record, so a device that gets both
    /// rings once — and a locked device's decline is one the caller will accept.
    #[test]
    fn a_capsule_and_the_encrypted_offer_converge_on_one_registry_record() {
        use crate::callstate::{CallRegistry, CallTerminalReason, OfferDecision, TerminalDecision};
        let (capsule, _) = minted();
        let mut registry = CallRegistry::default();
        assert_eq!(
            registry.receive_offer(
                &capsule.call_instance_id,
                &capsule.offer_id,
                NOW,
                capsule.ring_expires_at,
                NOW,
                0
            ),
            OfferDecision::Ring
        );
        // The encrypted offer carries the same pair: a duplicate, never a second ring.
        assert_eq!(
            registry.receive_offer(
                &capsule.call_instance_id,
                &capsule.offer_id,
                NOW,
                capsule.ring_expires_at,
                NOW,
                0
            ),
            OfferDecision::Duplicate
        );
        assert_eq!(
            registry.record_terminal(
                &capsule.call_instance_id,
                &capsule.offer_id,
                CallTerminalReason::DeclinedHere,
                NOW,
                0
            ),
            TerminalDecision::Applied(CallTerminalReason::DeclinedHere)
        );
    }

    #[test]
    fn malformed_shapes_and_oversized_blobs_are_refused_before_any_work() {
        let key = caller();
        let bad_ids = [
            CapsulePlan {
                call_instance_id: "short".into(),
                ..plan()
            },
            CapsulePlan {
                offer_id: "short".into(),
                ..plan()
            },
            CapsulePlan {
                to_device_id: "NOT-HEX".into(),
                ..plan()
            },
            CapsulePlan {
                reply_to_mailbox: "zz".into(),
                ..plan()
            },
            CapsulePlan {
                display_name: "x".repeat(MAX_DISPLAY_NAME + 1),
                ..plan()
            },
            CapsulePlan {
                from: String::new(),
                ..plan()
            },
        ];
        for plan in bad_ids {
            assert!(!CallCapsule::new(plan, sign_with(&key)).well_formed());
        }
        assert!(CallCapsule::decode(b"not json").is_none());
        assert!(
            CallCapsule::decode(&vec![b'x'; crypto_core::callkey::MAX_CAPSULE_BYTES + 1]).is_none()
        );
    }
}
