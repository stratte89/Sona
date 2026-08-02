//! The server-side append-only Key Transparency log.
//!
//! Wraps a `ct-merkle` Merkle tree with the Sona entry semantics: every append
//! is validated (signature + continuity chain) before it joins the tree, so the log
//! only ever contains well-formed, self-authenticating bindings. The server signs tree
//! heads with its Key Transparency key.

use std::collections::HashMap;

use ct_merkle::mem_backed_tree::MemoryBackedTree;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Sha256;

use crate::entry::KtEntry;
use crate::head::SignedTreeHead;
use crate::roster::{KtRosterEntry, RosterError};
use crate::{ConsistencyProof, InclusionProof};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppendError {
    #[error("entry signature is invalid")]
    BadSignature,
    #[error("chain continuity broken: {0}")]
    BrokenChain(String),
    #[error("roster rejected: {0}")]
    Roster(#[from] RosterError),
}

/// One leaf of the log: either a username→key binding or a device-roster epoch. Both
/// share the same append-only Merkle tree (so one consistency proof covers everything);
/// they are distinguished by domain-separated leaf bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KtRecord {
    Binding(KtEntry),
    Roster(KtRosterEntry),
}

/// How long a released username stays reserved to its old owner before anyone may claim
/// it (7 days). Enforced against the release entry's **signed** timestamp — the server
/// refuses future-dated entries at submission time, so a claimant cannot shorten the
/// window by post-dating and the rule stays verifiable from the log alone.
pub const RELEASE_GRACE_SECS: u64 = 7 * 86400;

/// The append-only log plus the index needed to answer per-user queries.
pub struct KtLog {
    tree: MemoryBackedTree<Sha256, Vec<u8>>,
    records: Vec<KtRecord>,
    /// username_hash -> binding-leaf indices, in append order (the rotation chain).
    by_user: HashMap<String, Vec<usize>>,
    /// username_hash -> roster-leaf indices, in append order (the roster epochs).
    rosters_by_user: HashMap<String, Vec<usize>>,
    signing_key: SigningKey,
    /// Release grace override ([`RELEASE_GRACE_SECS`] by default; configurable so a test
    /// relay can exercise the reclaim flow without waiting a week).
    release_grace_secs: u64,
}

impl KtLog {
    /// Build a log with a specific Key Transparency signing key (e.g. loaded from disk).
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            tree: MemoryBackedTree::new(),
            records: Vec::new(),
            by_user: HashMap::new(),
            rosters_by_user: HashMap::new(),
            signing_key,
            release_grace_secs: RELEASE_GRACE_SECS,
        }
    }

    /// Override the release grace period (test relays; production keeps the default).
    pub fn set_release_grace_secs(&mut self, secs: u64) {
        self.release_grace_secs = secs;
    }

    /// Generate a fresh signing key (use [`verifying_key`](Self::verifying_key) to pin it
    /// into clients). Convenient for tests and first boot.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self::new(SigningKey::generate(&mut OsRng))
    }

    /// Load a log with a signing key restored from a base64 32-byte seed (as produced by
    /// [`signing_key_seed_b64`](Self::signing_key_seed_b64)). Returns `None` on a bad seed.
    pub fn from_seed_b64(seed_b64: &str) -> Option<Self> {
        let seed: [u8; 32] = crate::b64d(seed_b64)?.try_into().ok()?;
        Some(Self::new(SigningKey::from_bytes(&seed)))
    }

    /// The base64 32-byte signing-key seed, for persisting the KT key across restarts.
    /// Secret — store it like any private key.
    pub fn signing_key_seed_b64(&self) -> String {
        crate::b64e(&self.signing_key.to_bytes())
    }

    /// The public key clients must pin to trust this log's tree heads.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The pinned public key as base64 — the value baked into client config.
    pub fn verifying_key_b64(&self) -> String {
        crate::b64e(self.signing_key.verifying_key().as_bytes())
    }

    pub fn size(&self) -> usize {
        self.records.len()
    }

    /// The binding entry at a given username's chain position, if `index` is a binding.
    fn binding_at(&self, index: usize) -> Option<&KtEntry> {
        match self.records.get(index)? {
            KtRecord::Binding(e) => Some(e),
            KtRecord::Roster(_) => None,
        }
    }

    /// Validate and append an entry. Enforces, fail-closed:
    /// * a valid signature (own key for a first claim, previous key for a rotation);
    /// * correct continuity — a first claim only for a new username, and a rotation that
    ///   names the current key, increments the sequence, and keeps the username fixed;
    /// * a self-signed **reclaim** (`prev_signing_key == None` at `seq > 0`) only over a
    ///   released name whose grace period (measured between signed timestamps) has
    ///   passed. The owner needs no grace: a normal rotation always continues the chain.
    pub fn append(&mut self, entry: KtEntry) -> Result<usize, AppendError> {
        if !entry.verify_signature() {
            return Err(AppendError::BadSignature);
        }
        match self
            .by_user
            .get(&entry.username_hash)
            .and_then(|v| v.last())
        {
            Some(&last_idx) => {
                let last = self
                    .binding_at(last_idx)
                    .expect("by_user indices always point at binding leaves");
                if entry.seq != last.seq + 1 {
                    return Err(AppendError::BrokenChain("sequence not contiguous".into()));
                }
                match entry.prev_signing_key.as_deref() {
                    Some(prev) => {
                        if prev != last.signing_key.as_str() {
                            return Err(AppendError::BrokenChain(
                                "prev_signing_key does not match the current key".into(),
                            ));
                        }
                    }
                    // Takeover of a released name: authorized by the release entry plus
                    // the elapsed grace, not by the old owner's signature.
                    None => {
                        if !last.released {
                            return Err(AppendError::BrokenChain(
                                "username is not released — only its owner can rotate it".into(),
                            ));
                        }
                        if entry.timestamp < last.timestamp.saturating_add(self.release_grace_secs)
                        {
                            return Err(AppendError::BrokenChain(
                                "username is released but still inside its grace period".into(),
                            ));
                        }
                    }
                }
            }
            None => {
                if entry.seq != 0 || entry.prev_signing_key.is_some() {
                    return Err(AppendError::BrokenChain(
                        "first entry for a username must be a seq-0 self-claim".into(),
                    ));
                }
            }
        }

        let index = self.records.len();
        self.tree.push(entry.leaf_bytes());
        self.by_user
            .entry(entry.username_hash.clone())
            .or_default()
            .push(index);
        self.records.push(KtRecord::Binding(entry));
        Ok(index)
    }

    /// Validate and append a device-roster epoch. Enforces, fail-closed:
    /// * the username already has a binding chain (no roster for an unclaimed name);
    /// * the roster validates against the **current** binding — account signature,
    ///   per-device proofs of possession, exactly one primary whose keys match the
    ///   KT-bound account keys (see [`KtRosterEntry::validate_against`]);
    /// * roster epochs are contiguous per username (0, 1, 2, …).
    pub fn append_roster(&mut self, roster: KtRosterEntry) -> Result<usize, AppendError> {
        let current = self
            .by_user
            .get(&roster.username_hash)
            .and_then(|v| v.last())
            .and_then(|&i| self.binding_at(i))
            .ok_or_else(|| {
                AppendError::BrokenChain("no binding exists for this username".into())
            })?;
        if current.released {
            return Err(AppendError::BrokenChain(
                "no roster changes on a released username".into(),
            ));
        }
        roster.validate_against(current)?;

        // Roster epochs are scoped to the name's ownership era: a reclaim (self-signed
        // binding at seq > 0) starts a new owner, whose roster chain restarts at 0 —
        // the previous owner's epochs stay in the log but no longer constrain them.
        let era_start = self
            .by_user
            .get(&roster.username_hash)
            .map(|v| {
                v.iter()
                    .rev()
                    .find(|&&i| {
                        self.binding_at(i)
                            .is_some_and(|e| e.prev_signing_key.is_none())
                    })
                    .copied()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        let expected_seq = self
            .rosters_by_user
            .get(&roster.username_hash)
            .and_then(|v| v.last())
            .filter(|&&i| i > era_start)
            .and_then(|&i| match self.records.get(i) {
                Some(KtRecord::Roster(r)) => Some(r.seq + 1),
                _ => None,
            })
            .unwrap_or(0);
        if roster.seq != expected_seq {
            return Err(AppendError::BrokenChain(format!(
                "roster epoch not contiguous (expected {expected_seq})"
            )));
        }

        let index = self.records.len();
        self.tree.push(roster.leaf_bytes());
        self.rosters_by_user
            .entry(roster.username_hash.clone())
            .or_default()
            .push(index);
        self.records.push(KtRecord::Roster(roster));
        Ok(index)
    }

    /// A signed head committing to the current tree.
    pub fn sth(&self, now: u64) -> SignedTreeHead {
        let root = self.tree.root();
        SignedTreeHead::create(
            root.num_leaves(),
            root.as_bytes().as_slice(),
            now,
            &self.signing_key,
        )
    }

    /// The latest entry index for a username (the head of its rotation chain).
    pub fn latest_index_for(&self, username_hash: &str) -> Option<usize> {
        self.by_user
            .get(username_hash)
            .and_then(|v| v.last())
            .copied()
    }

    /// **Every** leaf index under a username — bindings and roster epochs together, in
    /// log order (SP-13).
    ///
    /// The auditor verifies only that the STH is signed and that growth is
    /// consistency-proof-clean, which catches a *rewritten* log but not a log that grows
    /// correctly while containing a leaf the named account never authorized. Detecting
    /// that needs the leaf set for one account, so the account can check each one against
    /// what it actually signed. Serving it is gated to the owner — see the relay's
    /// `/v1/kt/leaves`, which is challenge-signed precisely because "all leaves for this
    /// username" handed to anyone would be a fresh enumeration oracle.
    pub fn all_indices_for(&self, username_hash: &str) -> Vec<usize> {
        let mut idx: Vec<usize> = self
            .by_user
            .get(username_hash)
            .into_iter()
            .flatten()
            .chain(
                self.rosters_by_user
                    .get(username_hash)
                    .into_iter()
                    .flatten(),
            )
            .copied()
            .collect();
        idx.sort_unstable();
        idx
    }

    /// The record at `index`, whichever kind it is.
    pub fn record(&self, index: usize) -> Option<&KtRecord> {
        self.records.get(index)
    }

    /// The latest roster-epoch index for a username, if it has published one.
    pub fn latest_roster_index_for(&self, username_hash: &str) -> Option<usize> {
        self.rosters_by_user
            .get(username_hash)
            .and_then(|v| v.last())
            .copied()
    }

    /// The latest roster for a username, if any.
    pub fn latest_roster_for(&self, username_hash: &str) -> Option<&KtRosterEntry> {
        match self
            .records
            .get(self.latest_roster_index_for(username_hash)?)
        {
            Some(KtRecord::Roster(r)) => Some(r),
            _ => None,
        }
    }

    pub fn entry(&self, index: usize) -> Option<&KtEntry> {
        self.binding_at(index)
    }

    /// Inclusion proof for the binding entry at `index`, paired with the entry itself.
    /// `None` if the leaf at `index` is not a binding.
    pub fn inclusion(&self, index: usize) -> Option<(KtEntry, InclusionProof)> {
        let entry = self.binding_at(index)?.clone();
        Some((entry, self.tree.prove_inclusion(index)))
    }

    /// Inclusion proof for the roster epoch at `index`, paired with the roster itself.
    /// `None` if the leaf at `index` is not a roster.
    pub fn roster_inclusion(&self, index: usize) -> Option<(KtRosterEntry, InclusionProof)> {
        match self.records.get(index)? {
            KtRecord::Roster(r) => Some((r.clone(), self.tree.prove_inclusion(index))),
            KtRecord::Binding(_) => None,
        }
    }

    /// Consistency proof from a tree of `old_size` leaves to the current tree, proving the
    /// log only grew. `None` unless `1 <= old_size < current_size` — a proof from the empty
    /// tree is undefined (the empty tree is trivially a prefix of any), and equal sizes
    /// need no proof.
    pub fn consistency(&self, old_size: usize) -> Option<ConsistencyProof> {
        if old_size == 0 || old_size >= self.records.len() {
            return None;
        }
        let additions = self.records.len() - old_size;
        Some(self.tree.prove_consistency(additions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{b64e, verify};
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    fn signer() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = b64e(sk.verifying_key().as_bytes());
        (sk, vk)
    }

    fn claim(uhash: &str, sk: &SigningKey, vk: &str) -> KtEntry {
        KtEntry::new_claim(uhash.into(), "id".into(), vk.into(), 100, |p| {
            b64e(&sk.sign(p).to_bytes())
        })
    }

    #[test]
    fn append_first_claim_and_prove_inclusion() {
        let mut log = KtLog::generate();
        let (sk, vk) = signer();
        let idx = log.append(claim("alice", &sk, &vk)).unwrap();
        let sth = log.sth(1);
        let (entry, proof) = log.inclusion(idx).unwrap();
        assert!(verify::verify_inclusion(&sth, &entry, idx as u64, &proof));
    }

    #[test]
    fn rejects_second_claim_for_same_username() {
        let mut log = KtLog::generate();
        let (sk, vk) = signer();
        log.append(claim("alice", &sk, &vk)).unwrap();
        // A different keypair tries to claim the same username afresh (seq 0) — hijack.
        let (sk2, vk2) = signer();
        let err = log.append(claim("alice", &sk2, &vk2)).unwrap_err();
        assert!(matches!(err, AppendError::BrokenChain(_)));
    }

    #[test]
    fn released_name_is_claimable_only_after_grace() {
        let mut log = KtLog::generate();
        log.set_release_grace_secs(1000);
        let (owner, owner_vk) = signer();
        log.append(claim("alice", &owner, &owner_vk)).unwrap();

        // An unreleased name refuses any self-signed takeover outright.
        let (thief, thief_vk) = signer();
        let premature = KtEntry::new_reclaim(
            1,
            "alice".into(),
            "thief-id".into(),
            thief_vk.clone(),
            5000,
            |p| b64e(&thief.sign(p).to_bytes()),
        );
        assert!(matches!(
            log.append(premature),
            Err(AppendError::BrokenChain(_))
        ));

        // Owner releases at t=500.
        let release = KtEntry::new_rotation(
            1,
            "alice".into(),
            "id".into(),
            owner_vk.clone(),
            owner_vk.clone(),
            500,
            true,
            |p| b64e(&owner.sign(p).to_bytes()),
        );
        log.append(release).unwrap();

        // Inside the grace window (t < 1500) a takeover is still refused.
        let early = KtEntry::new_reclaim(
            2,
            "alice".into(),
            "thief-id".into(),
            thief_vk.clone(),
            1499,
            |p| b64e(&thief.sign(p).to_bytes()),
        );
        assert!(matches!(
            log.append(early),
            Err(AppendError::BrokenChain(_))
        ));

        // Past the grace window the takeover appends — an explicit, auditable event.
        let takeover = KtEntry::new_reclaim(
            2,
            "alice".into(),
            "thief-id".into(),
            thief_vk.clone(),
            1500,
            |p| b64e(&thief.sign(p).to_bytes()),
        );
        assert!(log.append(takeover).is_ok());

        // The old owner's chain is severed: their rotation no longer continues it.
        let stale = KtEntry::new_rotation(
            3,
            "alice".into(),
            "id".into(),
            owner_vk.clone(),
            owner_vk.clone(),
            1600,
            false,
            |p| b64e(&owner.sign(p).to_bytes()),
        );
        assert!(matches!(
            log.append(stale),
            Err(AppendError::BrokenChain(_))
        ));
    }

    #[test]
    fn owner_reclaims_own_released_name_during_grace() {
        let mut log = KtLog::generate();
        log.set_release_grace_secs(1000);
        let (owner, owner_vk) = signer();
        log.append(claim("alice", &owner, &owner_vk)).unwrap();
        let release = KtEntry::new_rotation(
            1,
            "alice".into(),
            "id".into(),
            owner_vk.clone(),
            owner_vk.clone(),
            500,
            true,
            |p| b64e(&owner.sign(p).to_bytes()),
        );
        log.append(release).unwrap();

        // A normal rotation (released = false) needs no grace — the owner signs it.
        let unrelease = KtEntry::new_rotation(
            2,
            "alice".into(),
            "id".into(),
            owner_vk.clone(),
            owner_vk.clone(),
            600,
            false,
            |p| b64e(&owner.sign(p).to_bytes()),
        );
        log.append(unrelease).unwrap();

        // The name is no longer released: takeovers fail even long after.
        let (thief, thief_vk) = signer();
        let takeover = KtEntry::new_reclaim(
            3,
            "alice".into(),
            "thief-id".into(),
            thief_vk,
            999_999,
            |p| b64e(&thief.sign(p).to_bytes()),
        );
        assert!(matches!(
            log.append(takeover),
            Err(AppendError::BrokenChain(_))
        ));
    }

    #[test]
    fn roster_chain_restarts_for_a_new_owner_and_halts_while_released() {
        use crate::roster::{DeviceRecord, KtRosterEntry, PRIMARY_DEVICE_ID};

        let mut log = KtLog::generate();
        log.set_release_grace_secs(1000);
        let (sk, vk) = signer();
        let uhash = "a".repeat(64);
        log.append(KtEntry::new_claim(
            uhash.clone(),
            "acct-idk".into(),
            vk.clone(),
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        ))
        .unwrap();

        // Old owner publishes roster epochs 0 and 1.
        let primary = DeviceRecord::new(
            &uhash,
            PRIMARY_DEVICE_ID.into(),
            "acct-idk".into(),
            vk.clone(),
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        let r0 = KtRosterEntry::new(0, uhash.clone(), vec![primary.clone()], 200, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        log.append_roster(r0).unwrap();
        let r1 = KtRosterEntry::new(1, uhash.clone(), vec![primary.clone()], 250, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        log.append_roster(r1).unwrap();

        // Released: no roster changes are accepted (not even from the owner).
        let release = KtEntry::new_rotation(
            1,
            uhash.clone(),
            "acct-idk".into(),
            vk.clone(),
            vk.clone(),
            300,
            true,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        log.append(release).unwrap();
        let frozen = KtRosterEntry::new(2, uhash.clone(), vec![primary], 350, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(matches!(
            log.append_roster(frozen),
            Err(AppendError::BrokenChain(_))
        ));

        // New owner takes over after grace; their roster chain restarts at epoch 0 and
        // must NOT have to continue the old owner's numbering.
        let (nsk, nvk) = signer();
        let takeover = KtEntry::new_reclaim(
            2,
            uhash.clone(),
            "new-acct-idk".into(),
            nvk.clone(),
            2000,
            |p| b64e(&nsk.sign(p).to_bytes()),
        );
        log.append(takeover).unwrap();
        let new_primary = DeviceRecord::new(
            &uhash,
            PRIMARY_DEVICE_ID.into(),
            "new-acct-idk".into(),
            nvk.clone(),
            2000,
            |p| b64e(&nsk.sign(p).to_bytes()),
        );
        let continuation =
            KtRosterEntry::new(2, uhash.clone(), vec![new_primary.clone()], 2100, |p| {
                b64e(&nsk.sign(p).to_bytes())
            });
        assert!(matches!(
            log.append_roster(continuation),
            Err(AppendError::BrokenChain(_))
        ));
        let fresh = KtRosterEntry::new(0, uhash.clone(), vec![new_primary], 2100, |p| {
            b64e(&nsk.sign(p).to_bytes())
        });
        log.append_roster(fresh).unwrap();
        assert_eq!(log.latest_roster_for(&uhash).unwrap().seq, 0);
    }

    #[test]
    fn valid_rotation_is_accepted_invalid_is_rejected() {
        let mut log = KtLog::generate();
        let (old_sk, old_vk) = signer();
        log.append(claim("alice", &old_sk, &old_vk)).unwrap();
        let (_new_sk, new_vk) = signer();

        // Proper rotation: signed by old key, seq 1, prev = old key.
        let good = KtEntry::new_rotation(
            1,
            "alice".into(),
            "id2".into(),
            new_vk.clone(),
            old_vk.clone(),
            200,
            false,
            |p| b64e(&old_sk.sign(p).to_bytes()),
        );
        assert!(log.append(good).is_ok());

        // Rotation by a stranger (not the current key) is refused.
        let (stranger, _) = signer();
        let bad = KtEntry::new_rotation(
            2,
            "alice".into(),
            "id3".into(),
            "whatever".into(),
            new_vk,
            300,
            false,
            |p| b64e(&stranger.sign(p).to_bytes()),
        );
        assert!(log.append(bad).is_err());
    }

    #[test]
    fn roster_append_verify_and_epoch_continuity() {
        use crate::roster::{DeviceRecord, KtRosterEntry, PRIMARY_DEVICE_ID};

        let mut log = KtLog::generate();
        let (sk, vk) = signer();
        let uhash = "a".repeat(64);
        log.append(KtEntry::new_claim(
            uhash.clone(),
            "acct-idk".into(),
            vk.clone(),
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        ))
        .unwrap();

        let primary = DeviceRecord::new(
            &uhash,
            PRIMARY_DEVICE_ID.into(),
            "acct-idk".into(),
            vk.clone(),
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        let (dsk, dvk) = signer();
        let linked = DeviceRecord::new(&uhash, "b".repeat(32), "dev-idk".into(), dvk, 200, |p| {
            b64e(&dsk.sign(p).to_bytes())
        });

        // Roster for an unclaimed username is refused.
        let orphan = KtRosterEntry::new(0, "f".repeat(64), vec![primary.clone()], 250, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(matches!(
            log.append_roster(orphan),
            Err(AppendError::BrokenChain(_))
        ));

        // Epoch 0 with primary + one linked device appends and proves inclusion.
        let r0 = KtRosterEntry::new(
            0,
            uhash.clone(),
            vec![primary.clone(), linked.clone()],
            300,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        let idx = log.append_roster(r0).unwrap();
        assert_eq!(log.latest_roster_for(&uhash).unwrap().devices.len(), 2);
        let sth = log.sth(1);
        let (roster, proof) = log.roster_inclusion(idx).unwrap();
        assert!(verify::verify_roster_inclusion(
            &sth, &roster, idx as u64, &proof
        ));
        // A binding proof cannot be requested for a roster leaf and vice versa.
        assert!(log.inclusion(idx).is_none());
        assert!(log.roster_inclusion(0).is_none());

        // Epoch must be contiguous: another seq-0 (or a skip) is refused.
        let replay = KtRosterEntry::new(0, uhash.clone(), vec![primary.clone()], 400, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(matches!(
            log.append_roster(replay),
            Err(AppendError::BrokenChain(_))
        ));
        let skip = KtRosterEntry::new(2, uhash.clone(), vec![primary.clone()], 400, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        assert!(matches!(
            log.append_roster(skip),
            Err(AppendError::BrokenChain(_))
        ));

        // Epoch 1 removing the linked device (device removal is an appended epoch).
        let r1 = KtRosterEntry::new(1, uhash.clone(), vec![primary], 500, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        log.append_roster(r1).unwrap();
        assert_eq!(log.latest_roster_for(&uhash).unwrap().devices.len(), 1);

        // A roster signed by a stranger is refused (server cannot inject devices).
        let (stranger, _) = signer();
        let (esk, evk) = signer();
        let rogue_dev = DeviceRecord::new(&uhash, "c".repeat(32), "rogue".into(), evk, 600, |p| {
            b64e(&esk.sign(p).to_bytes())
        });
        let latest = log.latest_roster_for(&uhash).unwrap().clone();
        let mut devices = latest.devices.clone();
        devices.push(rogue_dev);
        let rogue = KtRosterEntry::new(2, uhash.clone(), devices, 600, |p| {
            b64e(&stranger.sign(p).to_bytes())
        });
        assert!(matches!(
            log.append_roster(rogue),
            Err(AppendError::Roster(_))
        ));
    }

    #[test]
    fn consistency_holds_across_mixed_binding_and_roster_leaves() {
        use crate::roster::{DeviceRecord, KtRosterEntry, PRIMARY_DEVICE_ID};

        let mut log = KtLog::generate();
        let (sk, vk) = signer();
        let uhash = "a".repeat(64);
        log.append(KtEntry::new_claim(
            uhash.clone(),
            "id".into(),
            vk.clone(),
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        ))
        .unwrap();
        let old_sth = log.sth(1);

        let primary = DeviceRecord::new(
            &uhash,
            PRIMARY_DEVICE_ID.into(),
            "id".into(),
            vk,
            100,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        let roster = KtRosterEntry::new(0, uhash, vec![primary], 200, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        log.append_roster(roster).unwrap();
        let (s2, v2) = signer();
        log.append(claim("bob", &s2, &v2)).unwrap();

        let new_sth = log.sth(2);
        assert_eq!(new_sth.tree_size, 3); // bindings + roster share one tree
        let proof = log.consistency(old_sth.tree_size as usize).unwrap();
        assert!(verify::verify_consistency(&old_sth, &new_sth, &proof));
    }

    #[test]
    fn consistency_proof_holds_across_appends() {
        let mut log = KtLog::generate();
        let (sk, vk) = signer();
        log.append(claim("alice", &sk, &vk)).unwrap();
        let old_sth = log.sth(1);

        // Append more entries for other users.
        for name in ["bob", "carol", "dave"] {
            let (s, v) = signer();
            log.append(claim(name, &s, &v)).unwrap();
        }
        let new_sth = log.sth(2);
        let proof = log.consistency(old_sth.tree_size as usize).unwrap();
        assert!(verify::verify_consistency(&old_sth, &new_sth, &proof));
    }
}
