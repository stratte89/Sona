//! Signed Tree Head (STH): the server's signed commitment to the whole log at a point
//! in time. A client trusts STHs only from the server's pinned Key Transparency public
//! key (distributed out-of-band — for a self-hosted instance, baked into the client).
//!
//! Two clients comparing STHs is how log *equivocation* is caught: a server that signs
//! two different histories at the same size has signed two conflicting heads, which is
//! non-repudiable evidence of misbehavior.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{b64d, b64e};

const STH_DOMAIN: &[u8] = b"sona-kt-sth-v1";

/// A signed commitment to the log: its size and Merkle root at `timestamp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    /// Base64 of the 32-byte Merkle root (RFC 6962 MTH).
    pub root_b64: String,
    pub timestamp: u64,
    /// Base64 Ed25519 signature over the canonical head bytes.
    pub signature_b64: String,
}

fn payload(tree_size: u64, root: &[u8], timestamp: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(STH_DOMAIN);
    v.extend_from_slice(&tree_size.to_be_bytes());
    v.extend_from_slice(root);
    v.extend_from_slice(&timestamp.to_be_bytes());
    v
}

impl SignedTreeHead {
    /// Create and sign a tree head for the given root bytes.
    pub fn create(tree_size: u64, root: &[u8], timestamp: u64, signing_key: &SigningKey) -> Self {
        let sig = signing_key.sign(&payload(tree_size, root, timestamp));
        SignedTreeHead {
            tree_size,
            root_b64: b64e(root),
            timestamp,
            signature_b64: b64e(&sig.to_bytes()),
        }
    }

    /// The 32-byte Merkle root, or `None` if the field is malformed.
    pub fn root_bytes(&self) -> Option<[u8; 32]> {
        b64d(&self.root_b64)?.try_into().ok()
    }

    /// Verify this head was signed by `verifying_key`. Fail-closed on malformed fields.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let check = || -> Option<()> {
            let root = self.root_bytes()?;
            let sig_bytes: [u8; 64] = b64d(&self.signature_b64)?.try_into().ok()?;
            let sig = Signature::from_bytes(&sig_bytes);
            verifying_key
                .verify_strict(&payload(self.tree_size, &root, self.timestamp), &sig)
                .ok()
        };
        check().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sth_verifies_under_its_signer_only() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let root = [9u8; 32];
        let sth = SignedTreeHead::create(5, &root, 1234, &sk);
        assert!(sth.verify(&sk.verifying_key()));
        assert!(!sth.verify(&other.verifying_key())); // wrong key
    }

    #[test]
    fn tampered_size_or_root_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut sth = SignedTreeHead::create(5, &[9u8; 32], 1234, &sk);
        sth.tree_size = 6;
        assert!(!sth.verify(&sk.verifying_key()));

        let mut sth2 = SignedTreeHead::create(5, &[9u8; 32], 1234, &sk);
        sth2.root_b64 = b64e(&[7u8; 32]);
        assert!(!sth2.verify(&sk.verifying_key()));
    }
}
