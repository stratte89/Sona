//! Client-side verification. These functions run on the *recipient's* device and need
//! nothing but the pinned server public key and the proofs the server hands over — they
//! never trust the server's word, only its math and its (non-repudiable) signatures.

use ct_merkle::RootHash;
use ed25519_dalek::VerifyingKey;
use sha2::{digest::Output, Sha256};

use crate::entry::KtEntry;
use crate::head::SignedTreeHead;
use crate::{ConsistencyProof, InclusionProof};

/// Reconstruct a `ct-merkle` root from the bytes committed in a tree head.
fn root_from(sth: &SignedTreeHead) -> Option<RootHash<Sha256>> {
    let bytes = sth.root_bytes()?;
    let out: Output<Sha256> = Output::<Sha256>::from(bytes);
    Some(RootHash::new(out, sth.tree_size))
}

// ── Proof (de)serialization ──────────────────────────────────────────────────
// ct-merkle proofs are opaque byte blobs (no serde derive), so we move them over the
// wire as base64. These helpers are the single encode/decode point.

pub fn inclusion_to_b64(proof: &InclusionProof) -> String {
    crate::b64e(proof.as_bytes())
}

pub fn inclusion_from_b64(s: &str) -> Option<InclusionProof> {
    let bytes = crate::b64d(s)?;
    // ct-merkle's from_bytes PANICS on a length that isn't a whole number of digests —
    // and this string comes from the (untrusted) server. Fail closed instead; a
    // malicious relay must not be able to crash a verifying client. (Found by fuzzing.)
    if bytes.len() % 32 != 0 {
        return None;
    }
    Some(InclusionProof::from_bytes(bytes))
}

pub fn consistency_to_b64(proof: &ConsistencyProof) -> String {
    crate::b64e(proof.as_bytes())
}

pub fn consistency_from_b64(s: &str) -> Option<ConsistencyProof> {
    let bytes = crate::b64d(s)?;
    if bytes.len() % 32 != 0 {
        return None;
    }
    let digests: Vec<Output<Sha256>> = bytes
        .chunks_exact(32)
        .map(|c| Output::<Sha256>::from(<[u8; 32]>::try_from(c).expect("chunk is 32 bytes")))
        .collect();
    Some(ConsistencyProof::from_digests(digests.iter()))
}

/// Is this tree head genuinely signed by the pinned Key Transparency key?
pub fn verify_sth(verifying_key: &VerifyingKey, sth: &SignedTreeHead) -> bool {
    sth.verify(verifying_key)
}

/// Parse a base64 Ed25519 public key (the pinned KT key, as shipped in client config).
pub fn verifying_key_from_b64(b64: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = crate::b64d(b64)?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// [`verify_sth`] taking the pinned key as base64 — lets clients work purely in strings
/// without depending on the ed25519 types directly.
pub fn verify_sth_b64(pinned_key_b64: &str, sth: &SignedTreeHead) -> bool {
    match verifying_key_from_b64(pinned_key_b64) {
        Some(vk) => sth.verify(&vk),
        None => false,
    }
}

/// Does `entry` (a self-authenticating binding) really appear in the log committed by
/// `sth`, at position `index`? Checks both the entry's own signature and the Merkle
/// inclusion proof. The caller must have already verified `sth` with [`verify_sth`].
pub fn verify_inclusion(
    sth: &SignedTreeHead,
    entry: &KtEntry,
    index: u64,
    proof: &InclusionProof,
) -> bool {
    if !entry.verify_signature() {
        return false;
    }
    let Some(root) = root_from(sth) else {
        return false;
    };
    root.verify_inclusion(&entry.leaf_bytes(), index, proof)
        .is_ok()
}

/// Does `roster` really appear in the log committed by `sth`, at position `index`?
/// Merkle inclusion only — the caller must ALSO validate the roster semantically against
/// the account's verified current binding
/// ([`KtRosterEntry::validate_against`](crate::roster::KtRosterEntry::validate_against)),
/// and must have already verified `sth` with [`verify_sth`].
pub fn verify_roster_inclusion(
    sth: &SignedTreeHead,
    roster: &crate::roster::KtRosterEntry,
    index: u64,
    proof: &InclusionProof,
) -> bool {
    let Some(root) = root_from(sth) else {
        return false;
    };
    root.verify_inclusion(&roster.leaf_bytes(), index, proof)
        .is_ok()
}

/// [`verify_roster_inclusion`] taking a base64 proof (as carried on the wire).
pub fn verify_roster_inclusion_b64(
    sth: &SignedTreeHead,
    roster: &crate::roster::KtRosterEntry,
    index: u64,
    proof_b64: &str,
) -> bool {
    match inclusion_from_b64(proof_b64) {
        Some(p) => verify_roster_inclusion(sth, roster, index, &p),
        None => false,
    }
}

/// Is the log committed by `new_sth` an append-only extension of the one committed by
/// `old_sth`? This is what proves the server never rewrote or removed history — the
/// guarantee that a binding a client saw earlier cannot be silently changed.
pub fn verify_consistency(
    old_sth: &SignedTreeHead,
    new_sth: &SignedTreeHead,
    proof: &ConsistencyProof,
) -> bool {
    let (Some(old_root), Some(new_root)) = (root_from(old_sth), root_from(new_sth)) else {
        return false;
    };
    new_root.verify_consistency(&old_root, proof).is_ok()
}

/// [`verify_inclusion`] taking a base64 proof (as carried on the wire).
pub fn verify_inclusion_b64(
    sth: &SignedTreeHead,
    entry: &KtEntry,
    index: u64,
    proof_b64: &str,
) -> bool {
    match inclusion_from_b64(proof_b64) {
        Some(p) => verify_inclusion(sth, entry, index, &p),
        None => false,
    }
}

/// The result of comparing two tree heads during gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipVerdict {
    /// The two heads are on the same append-only history — no lie detected.
    Consistent,
    /// **Proof the server equivocated**: it signed two conflicting histories. Non-repudiable.
    Equivocation,
    /// Sizes differ and no consistency proof was supplied, or one head is newer than the
    /// other party's current view — can't conclude yet (fetch a proof / retry).
    Inconclusive,
    /// A head is not signed by the pinned Key Transparency key — ignore it.
    BadSignature,
}

/// Compare two signed tree heads to detect server equivocation (the split-view attack).
///
/// * Both must be signed by `pinned_key_b64` (else [`GossipVerdict::BadSignature`]).
/// * **Same size, different root** → the server signed two different logs at the same
///   size → [`GossipVerdict::Equivocation`] (non-repudiable proof).
/// * **Different sizes** → they can only be honest if the smaller is a prefix of the
///   larger; supply a consistency proof (smaller→larger) to check. With a valid proof →
///   [`Consistent`]; with an invalid one → [`Equivocation`]; without one → [`Inconclusive`].
pub fn check_heads(
    pinned_key_b64: &str,
    a: &SignedTreeHead,
    b: &SignedTreeHead,
    proof_small_to_large_b64: Option<&str>,
) -> GossipVerdict {
    if !verify_sth_b64(pinned_key_b64, a) || !verify_sth_b64(pinned_key_b64, b) {
        return GossipVerdict::BadSignature;
    }
    if a.tree_size == b.tree_size {
        return if a.root_b64 == b.root_b64 {
            GossipVerdict::Consistent
        } else {
            GossipVerdict::Equivocation
        };
    }
    let (small, large) = if a.tree_size < b.tree_size {
        (a, b)
    } else {
        (b, a)
    };
    match proof_small_to_large_b64 {
        Some(p) if verify_consistency_b64(small, large, p) => GossipVerdict::Consistent,
        Some(_) => GossipVerdict::Equivocation,
        None => GossipVerdict::Inconclusive,
    }
}

/// [`verify_consistency`] taking a base64 proof (as carried on the wire).
pub fn verify_consistency_b64(
    old_sth: &SignedTreeHead,
    new_sth: &SignedTreeHead,
    proof_b64: &str,
) -> bool {
    match consistency_from_b64(proof_b64) {
        Some(p) => verify_consistency(old_sth, new_sth, &p),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b64e;
    use crate::log::KtLog;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn end_to_end_inclusion_with_pinned_key() {
        let mut log = KtLog::generate();
        let pinned = log.verifying_key(); // client pins this out-of-band

        let sk = SigningKey::generate(&mut OsRng);
        let vk = b64e(sk.verifying_key().as_bytes());
        let entry = KtEntry::new_claim("alice".into(), "idk".into(), vk, 100, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        let idx = log.append(entry).unwrap();
        let sth = log.sth(1);

        // Client checks: head is signed by the pinned key, and the entry is included.
        assert!(verify_sth(&pinned, &sth));
        let (entry, proof) = log.inclusion(idx).unwrap();
        assert!(verify_inclusion(&sth, &entry, idx as u64, &proof));

        // A head signed by a different key must be rejected.
        let attacker = SigningKey::generate(&mut OsRng);
        assert!(!verify_sth(&attacker.verifying_key(), &sth));
    }

    #[test]
    fn gossip_detects_equivocation_and_accepts_honest_growth() {
        use crate::consistency_to_b64;
        use crate::log::KtLog;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let claim = |uhash: &str| {
            let sk = SigningKey::generate(&mut OsRng);
            let vk = b64e(sk.verifying_key().as_bytes());
            KtEntry::new_claim(uhash.into(), "id".into(), vk, 1, |p| {
                b64e(&sk.sign(p).to_bytes())
            })
        };

        // One signing key, so both "views" are validly signed by the same server key.
        let seed = KtLog::generate().signing_key_seed_b64();
        let pinned = KtLog::from_seed_b64(&seed).unwrap().verifying_key_b64();

        // Honest single log: size 1 → size 4, with a consistency proof between them.
        let mut log = KtLog::from_seed_b64(&seed).unwrap();
        log.append(claim("alice")).unwrap();
        let sth1 = log.sth(1);
        for u in ["bob", "carol", "dave"] {
            log.append(claim(u)).unwrap();
        }
        let sth4 = log.sth(2);
        let proof = consistency_to_b64(&log.consistency(1).unwrap());
        assert_eq!(
            check_heads(&pinned, &sth1, &sth4, Some(&proof)),
            GossipVerdict::Consistent
        );
        // Different sizes but no proof → can't conclude.
        assert_eq!(
            check_heads(&pinned, &sth1, &sth4, None),
            GossipVerdict::Inconclusive
        );

        // Split view: a SECOND log under the same key with a different first entry has the
        // same size (1) but a different root — provable equivocation.
        let mut fork = KtLog::from_seed_b64(&seed).unwrap();
        fork.append(claim("attacker")).unwrap();
        let fork_sth1 = fork.sth(1);
        assert_ne!(sth1.root_b64, fork_sth1.root_b64);
        assert_eq!(
            check_heads(&pinned, &sth1, &fork_sth1, None),
            GossipVerdict::Equivocation
        );

        // A head signed by a different key is ignored.
        let other_pinned = KtLog::generate().verifying_key_b64();
        assert_eq!(
            check_heads(&other_pinned, &sth1, &sth4, None),
            GossipVerdict::BadSignature
        );
    }

    #[test]
    fn malformed_proof_b64_is_rejected_not_panicking() {
        // Regression (found by fuzzing): a proof whose decoded length is not a whole
        // number of 32-byte digests must return None — ct-merkle's from_bytes panics
        // on it, and the input comes from the untrusted server.
        assert!(inclusion_from_b64("0K8+").is_none()); // decodes to 3 bytes
        assert!(consistency_from_b64("0K8+").is_none());
        assert!(inclusion_from_b64("not base64 !!!").is_none());
        // A whole number of digests still parses.
        assert!(inclusion_from_b64(&b64e(&[0u8; 32])).is_some());
    }

    #[test]
    fn inclusion_against_wrong_head_fails() {
        let mut log = KtLog::generate();
        let sk = SigningKey::generate(&mut OsRng);
        let vk = b64e(sk.verifying_key().as_bytes());
        let idx = log
            .append(KtEntry::new_claim(
                "alice".into(),
                "idk".into(),
                vk,
                100,
                |p| b64e(&sk.sign(p).to_bytes()),
            ))
            .unwrap();
        let (entry, proof) = log.inclusion(idx).unwrap();

        // Append more, take a NEW head, and try to verify the OLD proof against it.
        let sk2 = SigningKey::generate(&mut OsRng);
        let vk2 = b64e(sk2.verifying_key().as_bytes());
        log.append(KtEntry::new_claim(
            "bob".into(),
            "idk2".into(),
            vk2,
            100,
            |p| b64e(&sk2.sign(p).to_bytes()),
        ))
        .unwrap();
        let new_sth = log.sth(2);
        // Proof was for a size-1 tree; against the size-2 head it must not verify.
        assert!(!verify_inclusion(&new_sth, &entry, idx as u64, &proof));
    }
}
