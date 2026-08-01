//! A Key Transparency log entry: one signed `username → identity_key` binding.
//!
//! The signature is what makes an entry *self-authenticating*, so the server can store
//! and serve entries but can never forge one:
//!
//! * **First claim** (`prev_signing_key == None`): signed by the entry's own
//!   `signing_key`. Establishes the username's initial key (trust-on-first-claim, but
//!   recorded immutably so it can never be silently changed later).
//! * **Rotation** (`prev_signing_key == Some(old)`): signed by the *previous* signing
//!   key. Only the current key-holder can authorize a successor, forming a continuity
//!   chain back to the first claim.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{b64d, b64e};

const ENTRY_DOMAIN: &[u8] = b"sona-kt-entry-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EntryError {
    #[error("entry signature is invalid")]
    BadSignature,
    #[error("entry is structurally invalid: {0}")]
    Malformed(String),
}

/// One immutable binding in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtEntry {
    /// Position in this username's own chain: 0 for the first claim, then incrementing.
    pub seq: u64,
    /// SHA-256 of the username (the public, log-addressable identity).
    pub username_hash: String,
    /// Curve25519 identity key (base64) bound to this username at this point in time.
    pub identity_key: String,
    /// Ed25519 key (base64) that owns this binding (and signs the *next* rotation).
    pub signing_key: String,
    /// The signing key this entry supersedes. `None` for the first claim.
    pub prev_signing_key: Option<String>,
    /// Unix seconds when the entry was minted.
    pub timestamp: u64,
    /// The owner released this username (set on a rename-away). While the latest entry
    /// is a release, the owner may still continue the chain normally (reclaim); once
    /// [`RELEASE_GRACE_SECS`](crate::RELEASE_GRACE_SECS) have passed, anyone may append
    /// a fresh self-signed claim ([`KtEntry::new_reclaim`]) and take the name over.
    #[serde(default)]
    pub released: bool,
    /// Ed25519 signature (base64) over [`signing_payload`](Self::signing_payload).
    pub signature: String,
}

impl KtEntry {
    /// The exact bytes covered by [`signature`](Self::signature). Domain-separated and
    /// binds every field together so no field can be swapped without breaking the sig.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(ENTRY_DOMAIN);
        v.extend_from_slice(&self.seq.to_be_bytes());
        push_field(&mut v, self.username_hash.as_bytes());
        push_field(&mut v, self.identity_key.as_bytes());
        push_field(&mut v, self.signing_key.as_bytes());
        push_field(
            &mut v,
            self.prev_signing_key.as_deref().unwrap_or("").as_bytes(),
        );
        v.extend_from_slice(&self.timestamp.to_be_bytes());
        // Appended only when set, so every pre-release-feature entry (released = false)
        // keeps its original payload bytes and its signature stays valid.
        if self.released {
            v.extend_from_slice(b"|released");
        }
        v
    }

    /// The bytes stored as the Merkle leaf — the full entry including its signature, so
    /// an inclusion proof commits to the signed binding in its entirety.
    pub fn leaf_bytes(&self) -> Vec<u8> {
        let mut v = self.signing_payload();
        v.extend_from_slice(b"|sig|");
        v.extend_from_slice(self.signature.as_bytes());
        v
    }

    /// Build and sign a first-claim entry. `sign` produces a base64 Ed25519 signature
    /// over the given bytes using the private key matching `signing_key`.
    pub fn new_claim(
        username_hash: String,
        identity_key: String,
        signing_key: String,
        timestamp: u64,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut e = KtEntry {
            seq: 0,
            username_hash,
            identity_key,
            signing_key,
            prev_signing_key: None,
            timestamp,
            released: false,
            signature: String::new(),
        };
        e.signature = sign(&e.signing_payload());
        e
    }

    /// Build and sign a rotation entry. `sign_with_prev` must sign with the private key
    /// matching `prev_signing_key` — that is what authorizes the new binding. Set
    /// `released` to mint a **release**: the owner keeps the name (and can reclaim it by
    /// appending any later rotation) until the grace period runs out, after which the
    /// name becomes claimable by anyone via [`new_reclaim`](Self::new_reclaim).
    #[allow(clippy::too_many_arguments)]
    pub fn new_rotation(
        seq: u64,
        username_hash: String,
        new_identity_key: String,
        new_signing_key: String,
        prev_signing_key: String,
        timestamp: u64,
        released: bool,
        sign_with_prev: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut e = KtEntry {
            seq,
            username_hash,
            identity_key: new_identity_key,
            signing_key: new_signing_key,
            prev_signing_key: Some(prev_signing_key),
            timestamp,
            released,
            signature: String::new(),
        };
        e.signature = sign_with_prev(&e.signing_payload());
        e
    }

    /// Build and sign a fresh claim over a **released** name whose grace period has
    /// passed: self-signed like a first claim (the old owner does not authorize it — the
    /// prior release entry plus the elapsed grace do), but at the next chain position so
    /// the takeover is an explicit, auditable event in the name's history.
    pub fn new_reclaim(
        seq: u64,
        username_hash: String,
        identity_key: String,
        signing_key: String,
        timestamp: u64,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut e = KtEntry {
            seq,
            username_hash,
            identity_key,
            signing_key,
            prev_signing_key: None,
            timestamp,
            released: false,
            signature: String::new(),
        };
        e.signature = sign(&e.signing_payload());
        e
    }

    /// Verify the entry's signature under the correct key (own key for a first claim,
    /// previous key for a rotation). Fail-closed on any malformed field.
    pub fn verify_signature(&self) -> bool {
        let signer = self
            .prev_signing_key
            .as_deref()
            .unwrap_or(&self.signing_key);
        verify_ed25519(signer, &self.signing_payload(), &self.signature)
    }
}

/// Length-prefixed field append, so concatenated fields are unambiguous.
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Verify an Ed25519 signature (all base64). Returns `false` on any malformed input.
///
/// Public because device-signed material lives outside this crate too — a call-control
/// capsule is verified against the same roster signing keys, with the same base64
/// conventions and the same fail-closed behavior.
pub fn verify_ed25519(verifying_key_b64: &str, message: &[u8], signature_b64: &str) -> bool {
    let verify = || -> Option<()> {
        let vk_bytes: [u8; 32] = b64d(verifying_key_b64)?.try_into().ok()?;
        let sig_bytes: [u8; 64] = b64d(signature_b64)?.try_into().ok()?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).ok()?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(message, &sig).ok()
    };
    verify().is_some()
}

/// Convenience for callers (and the public key encoder).
pub fn encode_key(bytes: &[u8]) -> String {
    b64e(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk_b64 = b64e(sk.verifying_key().as_bytes());
        (sk, vk_b64)
    }

    #[test]
    fn first_claim_self_signature_verifies() {
        let (sk, vk_b64) = keypair();
        let entry = KtEntry::new_claim("uhash".into(), "idkey".into(), vk_b64, 1000, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(entry.verify_signature());
    }

    #[test]
    fn tampered_identity_key_breaks_signature() {
        let (sk, vk_b64) = keypair();
        let mut entry = KtEntry::new_claim("uhash".into(), "idkey".into(), vk_b64, 1000, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        entry.identity_key = "attacker-key".into(); // swap the bound key
        assert!(!entry.verify_signature());
    }

    #[test]
    fn rotation_must_be_signed_by_previous_key() {
        let (old_sk, old_vk) = keypair();
        let (_new_sk, new_vk) = keypair();
        // Correct: rotation signed by the OLD key authorizes the new binding.
        let good = KtEntry::new_rotation(
            1,
            "uhash".into(),
            "new-idkey".into(),
            new_vk.clone(),
            old_vk.clone(),
            2000,
            false,
            |p| b64e(&old_sk.sign(p).to_bytes()),
        );
        assert!(good.verify_signature());

        // Wrong: rotation signed by some unrelated key must fail.
        let (attacker_sk, _) = keypair();
        let bad = KtEntry::new_rotation(
            1,
            "uhash".into(),
            "new-idkey".into(),
            new_vk,
            old_vk,
            2000,
            false,
            |p| b64e(&attacker_sk.sign(p).to_bytes()),
        );
        assert!(!bad.verify_signature());
    }

    #[test]
    fn garbage_inputs_fail_closed() {
        assert!(!verify_ed25519("nope", b"msg", "nope"));
    }
}
