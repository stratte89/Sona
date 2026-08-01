//! Multi-device: the signed **device roster** for an account, recorded in the same
//! append-only Key Transparency log as the username→key bindings.
//!
//! A roster is the account's authoritative list of devices. Two signatures make it
//! trustworthy without trusting the server:
//!
//! * **The roster is signed by the account key** — the Ed25519 `signing_key` currently
//!   bound to the username in the KT log (held by the *primary* device). The server
//!   cannot mint, extend, or shrink a roster: it does not hold that private key. A rogue
//!   device can only be injected by publishing a roster the account key signed — which
//!   lands in the public log as permanent evidence.
//! * **Each device record carries a proof-of-possession** — the device's own Ed25519 key
//!   signs its record, so an account cannot be tricked into enrolling a public key whose
//!   private half the enrollee does not control, and a record cannot be transplanted to
//!   another account (the username hash is bound into the signed payload).
//!
//! Roster epochs are strictly sequential per account (`seq` 0, 1, 2, …) and every epoch
//! is a new leaf in the append-only log — adding *or removing* a device is permanently
//! recorded and auditable, exactly like a key rotation.
//!
//! The **primary device** is the record with [`PRIMARY_DEVICE_ID`]; its keys must equal
//! the account keys in the current [`KtEntry`], and its mailbox is the legacy account
//! mailbox — which is what keeps every existing single-device account (and every old
//! client that has never heard of rosters) working unchanged.

use serde::{Deserialize, Serialize};

use crate::entry::{verify_ed25519, KtEntry};

/// The reserved device id of the primary device. Its keys are the account keys and its
/// mailbox is the legacy account mailbox (`SHA-256(username)`).
pub const PRIMARY_DEVICE_ID: &str = "0";

/// Maximum devices per account. Bounds roster size (and the fan-out amplification a
/// single account can demand from senders and the relay).
pub const MAX_DEVICES: usize = 8;

const DEVICE_DOMAIN: &[u8] = b"sona-kt-device-v1";
const ROSTER_DOMAIN: &[u8] = b"sona-kt-roster-v1";
/// Distinct leaf prefix so a roster leaf can never be confused with a binding leaf
/// (whose bytes start with the `sona-kt-entry-v1` domain).
const ROSTER_LEAF_PREFIX: &[u8] = b"sona-kt-leaf-roster-v1|";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterError {
    #[error("roster signature is not by the account's current signing key")]
    BadRosterSignature,
    #[error("device record proof-of-possession signature is invalid")]
    BadDeviceSignature,
    #[error("roster is structurally invalid: {0}")]
    Malformed(String),
    #[error("roster does not match the account's current KT binding: {0}")]
    BindingMismatch(String),
}

/// One device in a roster: its public keys, when it was added, and its
/// proof-of-possession signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// [`PRIMARY_DEVICE_ID`] for the primary device; otherwise 32 lowercase hex chars
    /// (128 random bits, minted by the device itself).
    pub device_id: String,
    /// The device's Curve25519 Olm identity key (base64) — what peers encrypt to.
    pub identity_key: String,
    /// The device's Ed25519 key (base64) — signs this record and the device's
    /// WebSocket login challenges.
    pub signing_key: String,
    /// Unix seconds when the device was enrolled.
    pub added_at: u64,
    /// Ed25519 signature (base64) by `signing_key` over
    /// [`signing_payload`](Self::signing_payload) — proof the enrollee holds the
    /// private key, bound to this account.
    pub signature: String,
}

impl DeviceRecord {
    /// The exact bytes covered by the proof-of-possession signature. Binds the account
    /// (username hash) so a record cannot be replayed into another account's roster.
    pub fn signing_payload(&self, username_hash: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(DEVICE_DOMAIN);
        push_field(&mut v, username_hash.as_bytes());
        push_field(&mut v, self.device_id.as_bytes());
        push_field(&mut v, self.identity_key.as_bytes());
        push_field(&mut v, self.signing_key.as_bytes());
        v.extend_from_slice(&self.added_at.to_be_bytes());
        v
    }

    /// Build a record signed by the device's own key. `sign` must produce a base64
    /// Ed25519 signature with the private key matching `signing_key`.
    pub fn new(
        username_hash: &str,
        device_id: String,
        identity_key: String,
        signing_key: String,
        added_at: u64,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut r = DeviceRecord {
            device_id,
            identity_key,
            signing_key,
            added_at,
            signature: String::new(),
        };
        r.signature = sign(&r.signing_payload(username_hash));
        r
    }

    /// Verify the proof-of-possession signature for this record under `username_hash`.
    pub fn verify(&self, username_hash: &str) -> bool {
        verify_ed25519(
            &self.signing_key,
            &self.signing_payload(username_hash),
            &self.signature,
        )
    }

    /// Structural validity of the device id: the reserved primary id, or 32 lowercase
    /// hex characters.
    pub fn device_id_well_formed(&self) -> bool {
        self.device_id == PRIMARY_DEVICE_ID
            || (self.device_id.len() == 32
                && self
                    .device_id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
    }
}

/// One roster epoch: the complete device list for an account at a point in time,
/// signed by the account key. Appended to the KT log as its own leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtRosterEntry {
    /// Roster epoch for this account: 0 for the first roster, then incrementing by 1
    /// on every change (add, remove, or refresh after an account-key rotation).
    pub seq: u64,
    /// SHA-256 of the username — the same log address as the account's [`KtEntry`] chain.
    pub username_hash: String,
    /// The complete device list (1..=[`MAX_DEVICES`], exactly one primary).
    pub devices: Vec<DeviceRecord>,
    /// Unix seconds when this epoch was minted.
    pub timestamp: u64,
    /// Ed25519 signature (base64) by the account's **current** KT-bound signing key
    /// over [`signing_payload`](Self::signing_payload).
    pub signature: String,
}

impl KtRosterEntry {
    /// The exact bytes covered by [`signature`](Self::signature). Domain-separated;
    /// every device record (including its own signature) is bound in, so no record can
    /// be added, dropped, or reordered without breaking the account signature.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(ROSTER_DOMAIN);
        v.extend_from_slice(&self.seq.to_be_bytes());
        push_field(&mut v, self.username_hash.as_bytes());
        v.extend_from_slice(&(self.devices.len() as u64).to_be_bytes());
        for d in &self.devices {
            push_field(&mut v, d.device_id.as_bytes());
            push_field(&mut v, d.identity_key.as_bytes());
            push_field(&mut v, d.signing_key.as_bytes());
            v.extend_from_slice(&d.added_at.to_be_bytes());
            push_field(&mut v, d.signature.as_bytes());
        }
        v.extend_from_slice(&self.timestamp.to_be_bytes());
        v
    }

    /// The bytes stored as the Merkle leaf. Prefixed with a roster-specific domain so a
    /// roster leaf and a binding leaf can never collide or be confused.
    pub fn leaf_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ROSTER_LEAF_PREFIX.len() + 256);
        v.extend_from_slice(ROSTER_LEAF_PREFIX);
        v.extend_from_slice(&self.signing_payload());
        v.extend_from_slice(b"|sig|");
        v.extend_from_slice(self.signature.as_bytes());
        v
    }

    /// Build and sign a roster epoch. `sign_with_account` must sign with the private
    /// key matching the account's current KT-bound signing key.
    pub fn new(
        seq: u64,
        username_hash: String,
        devices: Vec<DeviceRecord>,
        timestamp: u64,
        sign_with_account: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut r = KtRosterEntry {
            seq,
            username_hash,
            devices,
            timestamp,
            signature: String::new(),
        };
        r.signature = sign_with_account(&r.signing_payload());
        r
    }

    /// Full semantic validation against the account's **current, already-verified**
    /// [`KtEntry`]. Run by the server before appending, and by clients after proving
    /// inclusion. Fail-closed on every check:
    ///
    /// * roster is for the entry's username;
    /// * 1..=[`MAX_DEVICES`] devices, well-formed and unique device ids;
    /// * exactly one primary record, whose keys equal the account keys in `current`
    ///   (a roster signed before a key rotation fails here — the account must publish
    ///   a fresh epoch after rotating, and until then clients fall back to
    ///   single-device delivery to the KT-bound key);
    /// * every device record's proof-of-possession verifies;
    /// * the roster signature verifies under `current.signing_key`.
    pub fn validate_against(&self, current: &KtEntry) -> Result<(), RosterError> {
        if self.username_hash != current.username_hash {
            return Err(RosterError::BindingMismatch("username differs".into()));
        }
        if self.devices.is_empty() || self.devices.len() > MAX_DEVICES {
            return Err(RosterError::Malformed(format!(
                "device count must be 1..={MAX_DEVICES}"
            )));
        }
        let mut primaries = 0usize;
        for (i, d) in self.devices.iter().enumerate() {
            if !d.device_id_well_formed() {
                return Err(RosterError::Malformed(format!(
                    "device {i} has a malformed id"
                )));
            }
            if self.devices[..i].iter().any(|p| p.device_id == d.device_id) {
                return Err(RosterError::Malformed(format!(
                    "duplicate device id {}",
                    d.device_id
                )));
            }
            if d.device_id == PRIMARY_DEVICE_ID {
                primaries += 1;
                if d.identity_key != current.identity_key || d.signing_key != current.signing_key {
                    return Err(RosterError::BindingMismatch(
                        "primary device keys do not match the KT-bound account keys".into(),
                    ));
                }
            }
            if !d.verify(&self.username_hash) {
                return Err(RosterError::BadDeviceSignature);
            }
        }
        if primaries != 1 {
            return Err(RosterError::Malformed(
                "roster must contain exactly one primary device".into(),
            ));
        }
        if !verify_ed25519(
            &current.signing_key,
            &self.signing_payload(),
            &self.signature,
        ) {
            return Err(RosterError::BadRosterSignature);
        }
        Ok(())
    }
}

/// Length-prefixed field append (same convention as `entry.rs`).
pub(crate) fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b64e;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = b64e(sk.verifying_key().as_bytes());
        (sk, vk)
    }

    fn uhash() -> String {
        "a".repeat(64)
    }

    /// Account claim + a matching primary device record.
    fn account_with_primary() -> (SigningKey, KtEntry, DeviceRecord) {
        let (sk, vk) = keypair();
        let entry = KtEntry::new_claim(uhash(), "acct-idk".into(), vk.clone(), 100, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        let primary = DeviceRecord::new(
            &uhash(),
            PRIMARY_DEVICE_ID.into(),
            "acct-idk".into(),
            vk,
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        (sk, entry, primary)
    }

    fn linked_device(username_hash: &str, id: &str) -> DeviceRecord {
        let (dsk, dvk) = keypair();
        DeviceRecord::new(username_hash, id.into(), "dev-idk".into(), dvk, 200, |p| {
            b64e(&dsk.sign(p).to_bytes())
        })
    }

    #[test]
    fn valid_roster_passes_validation() {
        let (sk, entry, primary) = account_with_primary();
        let dev = linked_device(&uhash(), &"b".repeat(32));
        let roster = KtRosterEntry::new(0, uhash(), vec![primary, dev], 300, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert_eq!(roster.validate_against(&entry), Ok(()));
    }

    #[test]
    fn roster_signed_by_stranger_is_rejected() {
        let (_sk, entry, primary) = account_with_primary();
        let (stranger, _) = keypair();
        let roster = KtRosterEntry::new(0, uhash(), vec![primary], 300, |p| {
            b64e(&stranger.sign(p).to_bytes())
        });
        assert_eq!(
            roster.validate_against(&entry),
            Err(RosterError::BadRosterSignature)
        );
    }

    #[test]
    fn device_record_without_key_possession_is_rejected() {
        let (sk, entry, primary) = account_with_primary();
        // Enrollee claims a public key but signs with a different (attacker) key.
        let (_victim_sk, victim_vk) = keypair();
        let (attacker_sk, _) = keypair();
        let forged = DeviceRecord::new(
            &uhash(),
            "c".repeat(32),
            "dev-idk".into(),
            victim_vk,
            200,
            |p| b64e(&attacker_sk.sign(p).to_bytes()),
        );
        let roster = KtRosterEntry::new(0, uhash(), vec![primary, forged], 300, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert_eq!(
            roster.validate_against(&entry),
            Err(RosterError::BadDeviceSignature)
        );
    }

    #[test]
    fn device_record_cannot_be_transplanted_to_another_account() {
        // A record signed for account A must not verify inside account B's roster.
        let dev = linked_device(&uhash(), &"d".repeat(32));
        assert!(dev.verify(&uhash()));
        assert!(!dev.verify(&"b".repeat(64)));
    }

    #[test]
    fn primary_keys_must_match_the_kt_binding() {
        let (sk, entry, _primary) = account_with_primary();
        // Primary record carries different keys than the KT entry.
        let (psk, pvk) = keypair();
        let wrong_primary = DeviceRecord::new(
            &uhash(),
            PRIMARY_DEVICE_ID.into(),
            "other-idk".into(),
            pvk,
            100,
            |p| b64e(&psk.sign(p).to_bytes()),
        );
        let roster = KtRosterEntry::new(0, uhash(), vec![wrong_primary], 300, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(matches!(
            roster.validate_against(&entry),
            Err(RosterError::BindingMismatch(_))
        ));
    }

    #[test]
    fn structural_rules_enforced() {
        let (sk, entry, primary) = account_with_primary();
        let sign = |p: &[u8]| b64e(&sk.sign(p).to_bytes());

        // No devices.
        let empty = KtRosterEntry::new(0, uhash(), vec![], 300, sign);
        assert!(matches!(
            empty.validate_against(&entry),
            Err(RosterError::Malformed(_))
        ));

        // No primary.
        let dev = linked_device(&uhash(), &"e".repeat(32));
        let no_primary = KtRosterEntry::new(0, uhash(), vec![dev.clone()], 300, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(matches!(
            no_primary.validate_against(&entry),
            Err(RosterError::Malformed(_))
        ));

        // Duplicate device id.
        let dup = KtRosterEntry::new(
            0,
            uhash(),
            vec![primary.clone(), dev.clone(), dev.clone()],
            300,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        assert!(matches!(
            dup.validate_against(&entry),
            Err(RosterError::Malformed(_))
        ));

        // Malformed device id (uppercase hex).
        let bad_id = linked_device(&uhash(), &"F".repeat(32));
        let bad = KtRosterEntry::new(0, uhash(), vec![primary.clone(), bad_id], 300, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(matches!(
            bad.validate_against(&entry),
            Err(RosterError::Malformed(_))
        ));

        // Too many devices.
        let mut many = vec![primary];
        for i in 0..MAX_DEVICES {
            many.push(linked_device(&uhash(), &format!("{i:032x}")));
        }
        let over = KtRosterEntry::new(0, uhash(), many, 300, |p| b64e(&sk.sign(p).to_bytes()));
        assert!(matches!(
            over.validate_against(&entry),
            Err(RosterError::Malformed(_))
        ));
    }

    #[test]
    fn tampering_with_the_device_list_breaks_the_roster_signature() {
        let (sk, entry, primary) = account_with_primary();
        let mut roster = KtRosterEntry::new(0, uhash(), vec![primary], 300, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        // Server tries to inject a (validly self-signed) rogue device post-hoc.
        roster
            .devices
            .push(linked_device(&uhash(), &"9".repeat(32)));
        assert_eq!(
            roster.validate_against(&entry),
            Err(RosterError::BadRosterSignature)
        );
    }

    #[test]
    fn leaf_bytes_are_domain_separated_from_binding_leaves() {
        let (sk, _entry, primary) = account_with_primary();
        let roster = KtRosterEntry::new(0, uhash(), vec![primary], 300, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(roster.leaf_bytes().starts_with(b"sona-kt-leaf-roster-v1|"));
    }
}
