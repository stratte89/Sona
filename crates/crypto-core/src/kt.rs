//! Client-side Key Transparency: mint our own log entries, verify a contact's published
//! key against the log before trusting it, and compute out-of-band safety numbers.
//!
//! Together these close the first-contact MITM gap: the server can only ever serve a
//! contact's *logged* key (or be caught), and two people can compare a short safety
//! number over any trusted channel to confirm the binding with zero trust in the server.

use kt_log::{
    verify_inclusion_b64, verify_sth_b64, DeviceRecord, KtEntry, KtRosterEntry, SignedTreeHead,
};
use sha2::{Digest, Sha512};

use crate::Account;

impl Account {
    /// Mint a first-claim Key Transparency entry for this identity, signed with our Olm
    /// Ed25519 key. Uploaded at registration; the server appends it to the log.
    pub fn kt_claim_entry(&self, timestamp: u64) -> KtEntry {
        let username_hash = self.identity_hash().as_str().to_string();
        KtEntry::new_claim(
            username_hash,
            self.engine.identity_key(),
            self.engine.signing_key(),
            timestamp,
            |payload| self.engine.sign(payload),
        )
    }

    /// Mint the proof-of-possession device record for **this** device, to be enrolled in
    /// the roster of the account addressed by `username_hash`. On the primary device,
    /// pass [`kt_log::PRIMARY_DEVICE_ID`] and the account's own hash; on a device being
    /// linked, pass the fresh random device id and the *account's* hash (which the
    /// linking flow supplies — a linked device's own `identity_hash()` is irrelevant).
    pub fn device_record(
        &self,
        username_hash: &str,
        device_id: &str,
        timestamp: u64,
    ) -> DeviceRecord {
        DeviceRecord::new(
            username_hash,
            device_id.to_string(),
            self.engine.identity_key(),
            self.engine.signing_key(),
            timestamp,
            |payload| self.engine.sign(payload),
        )
    }

    /// Sign a device-roster epoch with this account's (= primary device's) signing key.
    /// Only valid when called on the account whose signing key is currently KT-bound to
    /// the username — the log refuses rosters signed by anyone else.
    pub fn kt_roster_entry(
        &self,
        seq: u64,
        devices: Vec<DeviceRecord>,
        timestamp: u64,
    ) -> KtRosterEntry {
        KtRosterEntry::new(
            seq,
            self.identity_hash().as_str().to_string(),
            devices,
            timestamp,
            |payload| self.engine.sign(payload),
        )
    }
}

/// Outcome of checking a fetched bundle against the Key Transparency log.
#[derive(Debug, PartialEq, Eq)]
pub enum KtCheck {
    /// The bundle's identity key is the one published in the log for this username.
    Verified,
    /// The tree head was not signed by the pinned key — do not trust this server.
    BadTreeHead,
    /// The entry is not actually in the log (forged/absent proof).
    NotInLog,
    /// The proof was for a different username than expected.
    WrongUsername,
    /// The logged key and the offered bundle key disagree — possible substitution.
    KeyMismatch,
}

/// Verify that `bundle_identity_key` for `expected_username_hash` is exactly what the
/// Key Transparency log says, trusting only `pinned_kt_pubkey` (shipped out-of-band).
///
/// This is the gate a client runs before starting a session with a new contact.
#[allow(clippy::too_many_arguments)]
pub fn verify_contact_binding(
    pinned_kt_pubkey: &str,
    expected_username_hash: &str,
    bundle_identity_key: &str,
    entry: &KtEntry,
    index: u64,
    inclusion_proof_b64: &str,
    sth: &SignedTreeHead,
) -> KtCheck {
    if !verify_sth_b64(pinned_kt_pubkey, sth) {
        return KtCheck::BadTreeHead;
    }
    if !verify_inclusion_b64(sth, entry, index, inclusion_proof_b64) {
        return KtCheck::NotInLog;
    }
    if entry.username_hash != expected_username_hash {
        return KtCheck::WrongUsername;
    }
    if entry.identity_key != bundle_identity_key {
        return KtCheck::KeyMismatch;
    }
    KtCheck::Verified
}

/// A 60-digit safety number derived from both identity keys — the value two people read
/// to each other (or scan) to confirm, with zero trust in the server, that they share
/// the right keys. Symmetric: both sides compute the same number.
pub fn safety_number(my_identity_key_b64: &str, their_identity_key_b64: &str) -> String {
    // Sort so both parties hash in the same order regardless of who is "me".
    let mut keys = [my_identity_key_b64, their_identity_key_b64];
    keys.sort_unstable();
    let mut h = Sha512::new();
    h.update(b"sona-safety-number-v1");
    h.update(keys[0].as_bytes());
    h.update(keys[1].as_bytes());
    let digest = h.finalize(); // 64 bytes

    // 12 groups of 5 digits, each from a 5-byte chunk (60 bytes used).
    let mut groups = Vec::with_capacity(12);
    for chunk in digest.chunks_exact(5).take(12) {
        let mut n: u64 = 0;
        for &b in chunk {
            n = (n << 8) | b as u64;
        }
        groups.push(format!("{:05}", n % 100_000));
    }
    groups.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account;

    #[test]
    fn vodozemac_signed_entry_verifies_in_kt_log() {
        // The critical cross-library check: an entry signed by our Olm (vodozemac)
        // Ed25519 key must verify under kt-log's ed25519-dalek verifier.
        let (alice, _) = create_account("Alice-Password-123!").unwrap();
        let entry = alice.kt_claim_entry(1000);
        assert!(entry.verify_signature());
        assert_eq!(entry.username_hash, alice.identity_hash().as_str());
        assert_eq!(entry.identity_key, alice.ratchet_ref().identity_key());
    }

    #[test]
    fn account_minted_roster_validates_in_kt_log() {
        // Cross-library check: a roster signed with vodozemac keys must append to and
        // validate in the kt-log, including a linked device minted by a second engine.
        use kt_log::{KtLog, PRIMARY_DEVICE_ID};
        let (primary, _) = create_account("Alice-Password-123!").unwrap();
        let (linked, _) = create_account("Linked-Password-456!").unwrap();
        let uhash = primary.identity_hash().as_str().to_string();

        let mut log = KtLog::generate();
        log.append(primary.kt_claim_entry(1000)).unwrap();

        let devices = vec![
            primary.device_record(&uhash, PRIMARY_DEVICE_ID, 1000),
            linked.device_record(&uhash, &"ab".repeat(16), 1001),
        ];
        let roster = primary.kt_roster_entry(0, devices, 1002);
        let idx = log.append_roster(roster).unwrap();
        assert_eq!(log.latest_roster_for(&uhash).unwrap().devices.len(), 2);

        // A roster signed by the linked (non-account) key is refused.
        let rogue = linked.kt_roster_entry(1, vec![], 1003);
        let mut rogue = rogue;
        rogue.username_hash = uhash.clone();
        assert!(log.append_roster(rogue).is_err());
        let _ = idx;
    }

    #[test]
    fn safety_number_is_symmetric_and_key_dependent() {
        let a = "AAAAidentitykeyAAAA";
        let b = "BBBBidentitykeyBBBB";
        assert_eq!(safety_number(a, b), safety_number(b, a)); // order independent
        assert_ne!(safety_number(a, b), safety_number(a, "CCCC")); // changes with key
                                                                   // Shape: 12 space-separated 5-digit groups.
        let sn = safety_number(a, b);
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 12);
        assert!(groups
            .iter()
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn key_mismatch_is_detected() {
        // Build a real log entry, then ask to verify it against a DIFFERENT bundle key.
        use kt_log::KtLog;
        let mut log = KtLog::generate();
        let pinned = log.verifying_key_b64();
        let (alice, _) = create_account("Alice-Password-123!").unwrap();
        let entry = alice.kt_claim_entry(1000);
        let idx = log.append(entry.clone()).unwrap();
        let sth = log.sth(1);
        let (entry, proof) = log.inclusion(idx).unwrap();
        let proof_b64 = kt_log::inclusion_to_b64(&proof);

        // Correct key → Verified.
        assert_eq!(
            verify_contact_binding(
                &pinned,
                alice.identity_hash().as_str(),
                &alice.ratchet_ref().identity_key(),
                &entry,
                idx as u64,
                &proof_b64,
                &sth,
            ),
            KtCheck::Verified
        );

        // Substituted key → KeyMismatch (the attack KT is designed to catch).
        assert_eq!(
            verify_contact_binding(
                &pinned,
                alice.identity_hash().as_str(),
                "attacker-substituted-identity-key",
                &entry,
                idx as u64,
                &proof_b64,
                &sth,
            ),
            KtCheck::KeyMismatch
        );
    }
}
