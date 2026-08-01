//! Binding a device's **call-control key** to that device, verifiably.
//!
//! The call-control key ([`crypto_core::CallKey`]) is what a caller seals a minimal
//! incoming-call capsule to, so a locked Android phone can ring, cancel, and decline
//! without opening its chat vault. The question this module answers is the only one that
//! matters for that: *is this call key really the one that device published?*
//!
//! The trust chain reuses what already exists, and adds no new authority:
//!
//! ```text
//! KT log ──> account binding ──> roster (account-signed) ──> device record
//!                                                              │ signing_key
//!                                                              ▼
//!                                                        CallKeyBinding
//! ```
//!
//! A binding is signed by the **device's own** Ed25519 roster key, over a payload that
//! names the account (username hash) and the device id — so a binding cannot be moved to
//! another device or replayed into another account, and the relay (which stores and
//! serves it) cannot mint one. Verification is always against a roster the caller already
//! KT-verified; a device that has been removed from the roster has no verifiable binding
//! left, which is how call-control revocation happens for free.
//!
//! `created_at` is monotonic per device: a newer binding replaces an older one (key
//! rotation, app reinstall), and a **replayed older** binding must be refused so a relay
//! cannot roll a device back to a call key whose secret has since been destroyed.

use serde::{Deserialize, Serialize};

use crate::b64d;
use crate::entry::verify_ed25519;
use crate::roster::{push_field, KtRosterEntry};

const CALL_KEY_DOMAIN: &[u8] = b"sona-call-key-v1";

/// A Curve25519 public key is exactly 32 bytes. Bounds the field before anything larger
/// is decoded from it.
const CALL_KEY_LEN: usize = 32;

/// A device's published call-control key, signed by that device's roster key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallKeyBinding {
    /// The device this key belongs to — must be present in the account's roster.
    pub device_id: String,
    /// The device's Curve25519 call-control public key (base64) — what capsules are
    /// sealed to.
    pub call_key: String,
    /// The device's Ed25519 call-control key (base64) — what proves control of its
    /// call-control mailbox to the relay while the account vault is locked.
    #[serde(default)]
    pub call_signing_key: String,
    /// Unix seconds when the key was minted. Monotonic per device.
    pub created_at: u64,
    /// Ed25519 signature (base64) by the device's roster `signing_key` over
    /// [`signing_payload`](Self::signing_payload).
    pub signature: String,
}

impl CallKeyBinding {
    /// The exact bytes covered by the signature. Binds the account and the device, so a
    /// binding is useless anywhere but where it was minted.
    pub fn signing_payload(&self, username_hash: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(CALL_KEY_DOMAIN);
        push_field(&mut v, username_hash.as_bytes());
        push_field(&mut v, self.device_id.as_bytes());
        push_field(&mut v, self.call_key.as_bytes());
        push_field(&mut v, self.call_signing_key.as_bytes());
        v.extend_from_slice(&self.created_at.to_be_bytes());
        v
    }

    /// Build a binding signed by the device's own roster key. `sign` must produce a
    /// base64 Ed25519 signature under the `signing_key` in that device's roster record.
    pub fn new(
        username_hash: &str,
        device_id: String,
        call_key: String,
        call_signing_key: String,
        created_at: u64,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut binding = CallKeyBinding {
            device_id,
            call_key,
            call_signing_key,
            created_at,
            signature: String::new(),
        };
        binding.signature = sign(&binding.signing_payload(username_hash));
        binding
    }

    /// Shape check before any signature work: a well-formed device id and a call key of
    /// exactly the right base64 length.
    pub fn well_formed(&self) -> bool {
        self.call_key.len() <= 64
            && b64d(&self.call_key).is_some_and(|key| key.len() == CALL_KEY_LEN)
            && self.call_signing_key.len() <= 64
            && b64d(&self.call_signing_key).is_some_and(|key| key.len() == CALL_KEY_LEN)
            && (self.device_id == crate::PRIMARY_DEVICE_ID
                || (self.device_id.len() == 32
                    && self
                        .device_id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())))
    }

    /// Verify this binding against an already **KT-verified** roster for `username_hash`.
    ///
    /// Fail-closed: the roster must be for that account, must contain the named device,
    /// and the signature must verify under that device's roster signing key. Nothing here
    /// trusts the relay that served the binding.
    pub fn verify(&self, username_hash: &str, roster: &KtRosterEntry) -> bool {
        if !self.well_formed() || roster.username_hash != username_hash {
            return false;
        }
        let Some(device) = roster
            .devices
            .iter()
            .find(|device| device.device_id == self.device_id)
        else {
            return false;
        };
        verify_ed25519(
            &device.signing_key,
            &self.signing_payload(username_hash),
            &self.signature,
        )
    }

    /// Does `self` supersede `previous`? A binding may only move forward in time, so a
    /// replayed older key cannot displace the one the device is actually listening with.
    pub fn supersedes(&self, previous: &CallKeyBinding) -> bool {
        self.device_id == previous.device_id && self.created_at > previous.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b64e;
    use crate::roster::DeviceRecord;
    use ed25519_dalek::{Signer, SigningKey};

    fn uhash() -> String {
        "a".repeat(64)
    }

    fn device(id: &str) -> (SigningKey, DeviceRecord) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sk = SigningKey::from_bytes(&{
            let mut seed = sk.to_bytes();
            seed[0] = id.as_bytes()[0];
            seed
        });
        let signing_key = b64e(sk.verifying_key().as_bytes());
        let record = DeviceRecord::new(
            &uhash(),
            id.to_string(),
            b64e(&[1u8; 32]),
            signing_key,
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        (sk, record)
    }

    fn roster_of(devices: Vec<DeviceRecord>) -> KtRosterEntry {
        KtRosterEntry {
            seq: 0,
            username_hash: uhash(),
            devices,
            timestamp: 100,
            signature: String::new(), // account signature is checked elsewhere
        }
    }

    fn binding_for(sk: &SigningKey, device_id: &str, created_at: u64) -> CallKeyBinding {
        CallKeyBinding::new(
            &uhash(),
            device_id.to_string(),
            b64e(&[9u8; 32]),
            b64e(&[8u8; 32]),
            created_at,
            |p| b64e(&sk.sign(p).to_bytes()),
        )
    }

    #[test]
    fn a_device_signed_binding_verifies_against_its_roster() {
        let (sk, record) = device(&"b".repeat(32));
        let roster = roster_of(vec![record]);
        let binding = binding_for(&sk, &"b".repeat(32), 500);
        assert!(binding.verify(&uhash(), &roster));
    }

    #[test]
    fn a_binding_for_a_device_outside_the_roster_is_refused() {
        let (sk, record) = device(&"b".repeat(32));
        let roster = roster_of(vec![record]);
        // Same key, different device id: revoked device, or a relay pointing the call
        // key at a device that is not on the roster.
        let elsewhere = binding_for(&sk, &"c".repeat(32), 500);
        assert!(!elsewhere.verify(&uhash(), &roster));
    }

    #[test]
    fn another_devices_signature_cannot_bind_this_device() {
        let (_owner_sk, owner) = device(&"b".repeat(32));
        let (other_sk, other) = device(&"c".repeat(32));
        let roster = roster_of(vec![owner, other]);
        // `other` signs a binding claiming the owner's device id.
        let forged = binding_for(&other_sk, &"b".repeat(32), 500);
        assert!(!forged.verify(&uhash(), &roster));
    }

    #[test]
    fn a_binding_cannot_be_replayed_into_another_account() {
        let (sk, record) = device(&"b".repeat(32));
        let roster = roster_of(vec![record]);
        let binding = binding_for(&sk, &"b".repeat(32), 500);
        // Same bytes, different account: the username hash is inside the signature.
        let mut other_account = roster.clone();
        other_account.username_hash = "d".repeat(64);
        assert!(!binding.verify(&"d".repeat(64), &other_account));
    }

    #[test]
    fn a_tampered_call_key_breaks_the_signature() {
        let (sk, record) = device(&"b".repeat(32));
        let roster = roster_of(vec![record]);
        let mut binding = binding_for(&sk, &"b".repeat(32), 500);
        binding.call_key = b64e(&[4u8; 32]);
        assert!(!binding.verify(&uhash(), &roster));
    }

    #[test]
    fn swapping_the_mailbox_signing_key_breaks_the_signature() {
        // Both halves are covered: a relay cannot keep the capsule key and substitute a
        // mailbox key it controls (which would let it drain the device's capsules).
        let (sk, record) = device(&"b".repeat(32));
        let roster = roster_of(vec![record]);
        let mut binding = binding_for(&sk, &"b".repeat(32), 500);
        binding.call_signing_key = b64e(&[3u8; 32]);
        assert!(!binding.verify(&uhash(), &roster));
    }

    #[test]
    fn malformed_shapes_are_refused_before_signature_work() {
        let (sk, record) = device(&"b".repeat(32));
        let roster = roster_of(vec![record]);
        let mut short_key = binding_for(&sk, &"b".repeat(32), 500);
        short_key.call_key = "too-short".into();
        assert!(!short_key.well_formed());
        assert!(!short_key.verify(&uhash(), &roster));
        let mut bad_id = binding_for(&sk, &"b".repeat(32), 500);
        bad_id.device_id = "NOT-HEX".into();
        assert!(!bad_id.well_formed());
    }

    #[test]
    fn only_a_newer_binding_supersedes_the_stored_one() {
        let (sk, _) = device(&"b".repeat(32));
        let current = binding_for(&sk, &"b".repeat(32), 500);
        let newer = binding_for(&sk, &"b".repeat(32), 501);
        let older = binding_for(&sk, &"b".repeat(32), 499);
        assert!(newer.supersedes(&current));
        assert!(!older.supersedes(&current)); // rollback attempt
        assert!(!current.supersedes(&current)); // exact replay
        let other_device = binding_for(&sk, &"c".repeat(32), 900);
        assert!(!other_device.supersedes(&current));
    }
}
