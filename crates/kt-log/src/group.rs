//! Cryptographic **group-membership epochs** — an admin-authorized, signed,
//! append-only chain that decides who is in a group.
//!
//! ## Why this is separate from the public KT log
//!
//! Username→key bindings ([`KtEntry`](crate::KtEntry)) and device rosters
//! ([`KtRosterEntry`](crate::KtRosterEntry)) are *public*: they go into the append-only
//! transparency tree the whole world can audit. Group membership is **private** — the
//! relay must never learn who is in which group — so a group's roster is NOT published to
//! that tree. It is exchanged peer-to-peer inside the members' end-to-end sessions.
//!
//! What we reuse from KT is the *signing/rotation pattern*, not the log itself:
//!
//! * **Signed, append-only, monotonic epochs.** Each epoch carries `seq` 0,1,2,… and is
//!   Ed25519-signed. A relay can store and relay epochs but can never forge one.
//! * **Continuity chain** (exactly like [`KtEntry`] key rotation via `prev_signing_key`):
//!   epoch 0 is self-signed by the creator's admin key (trust-on-first, recorded
//!   immutably); every later epoch must be signed by the admin key named in the epoch
//!   *before* it. Only the current admin can extend the chain.
//!
//! ## Authority = a KT-bound account key
//!
//! The admin is identified by [`GroupEpoch::admin_key`], the admin's **account Ed25519
//! signing key** — the very key bound to their username in the public KT log. So any
//! member can independently KT-verify that the admin key really belongs to the account it
//! claims (resolve the admin's username → its [`KtEntry`] → compare `signing_key`). Because
//! that key lives on the primary device, admin actions are primary-device-only (the same
//! constraint as a username rename).
//!
//! ## What is admin-gated (and what is not)
//!
//! Only **membership** — adding a member, removing (kicking) a member — and **admin
//! transfer** advance the epoch chain and therefore require the admin's signature. Every
//! other group operation (rename, timer, avatar, pins, messages, and a member removing
//! *themselves* by leaving) stays egalitarian and is gated elsewhere on current-membership,
//! not here.

use serde::{Deserialize, Serialize};

use crate::entry::verify_ed25519;

const EPOCH_DOMAIN: &[u8] = b"sona-group-epoch-v1";

/// Upper bound on members in one epoch. Bounds the signed payload / fan-out size; far
/// above any realistic group and unrelated to the (much smaller) group-*call* cap.
pub const MAX_GROUP_MEMBERS: usize = 256;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum GroupEpochError {
    #[error("group epoch signature is invalid")]
    BadSignature,
    #[error("group epoch is structurally invalid: {0}")]
    Malformed(String),
    #[error("group epoch rollback: pinned seq {pinned}, got {got}")]
    Rollback { pinned: u64, got: u64 },
    #[error("group epoch does not chain from the pinned admin key")]
    BrokenContinuity,
}

/// One member as recorded in an epoch: the account's username and its stable Curve25519
/// account identity key (the same value peers address Olm sessions to). No signing key is
/// stored per member — the admin is located among the members by
/// [`admin_identity_key`](GroupEpoch::admin_identity_key), and the admin *key* is carried
/// separately, so an ordinary member entry needs only what a session already requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMemberEntry {
    pub username: String,
    pub identity_key: String,
}

/// One signed group-membership epoch: the complete member list at a point in time, plus
/// the admin who authorized it and the admin it chains from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEpoch {
    /// The group's stable random id (never changes across epochs).
    pub group_id: String,
    /// Epoch number: 0 for the genesis (creation), then strictly +1 on every change.
    pub seq: u64,
    /// The complete member list for this epoch.
    pub members: Vec<GroupMemberEntry>,
    /// The admin authorized **from this epoch forward** — the Ed25519 account signing key
    /// (base64) that must sign the *next* epoch. For a normal membership change this equals
    /// the previous admin key; for an admin transfer it is the new admin's key.
    pub admin_key: String,
    /// The admin's Curve25519 account identity key (base64). Must be one of the members'
    /// `identity_key`s, so "the admin is a current member" is a purely local check and the
    /// admin↔key binding is auditable against KT via that member's username.
    pub admin_identity_key: String,
    /// The admin key that signs THIS epoch: `None` for the genesis (self-signed by
    /// `admin_key`); `Some(prev)` for every later epoch (signed by the prior admin,
    /// forming the continuity chain — the same pattern as `KtEntry::prev_signing_key`).
    pub prev_admin_key: Option<String>,
    /// Unix seconds when the epoch was minted.
    pub timestamp: u64,
    /// Ed25519 signature (base64) over [`signing_payload`](Self::signing_payload), by the
    /// key in `prev_admin_key` (or by `admin_key` itself for the genesis).
    pub signature: String,
}

impl GroupEpoch {
    /// The exact bytes covered by [`signature`](Self::signature). Domain-separated and
    /// length-prefixed so no field — including any member — can be swapped, added, dropped,
    /// or reordered without breaking the signature.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(EPOCH_DOMAIN);
        push_field(&mut v, self.group_id.as_bytes());
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.extend_from_slice(&(self.members.len() as u64).to_be_bytes());
        for m in &self.members {
            push_field(&mut v, m.username.as_bytes());
            push_field(&mut v, m.identity_key.as_bytes());
        }
        push_field(&mut v, self.admin_key.as_bytes());
        push_field(&mut v, self.admin_identity_key.as_bytes());
        push_field(
            &mut v,
            self.prev_admin_key.as_deref().unwrap_or("").as_bytes(),
        );
        v.extend_from_slice(&self.timestamp.to_be_bytes());
        v
    }

    /// Build and sign the **genesis** epoch (seq 0): self-signed by the creator's admin
    /// key, exactly like a first KT claim. `sign` must sign with the private key matching
    /// `admin_key`. The creator must appear in `members` (see [`validate_structure`]).
    pub fn genesis(
        group_id: String,
        members: Vec<GroupMemberEntry>,
        admin_key: String,
        admin_identity_key: String,
        timestamp: u64,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut e = GroupEpoch {
            group_id,
            seq: 0,
            members,
            admin_key,
            admin_identity_key,
            prev_admin_key: None,
            timestamp,
            signature: String::new(),
        };
        e.signature = sign(&e.signing_payload());
        e
    }

    /// Build and sign a **successor** epoch. `sign_with_prev` must sign with the private
    /// key matching `prev_admin_key` — that is what authorizes the change. Used for both a
    /// membership change (pass the same `admin_key` as `prev_admin_key`) and an admin
    /// transfer (pass the new admin's `admin_key`/`admin_identity_key`, still signed by the
    /// outgoing admin's `prev_admin_key`).
    #[allow(clippy::too_many_arguments)]
    pub fn next(
        seq: u64,
        group_id: String,
        members: Vec<GroupMemberEntry>,
        admin_key: String,
        admin_identity_key: String,
        prev_admin_key: String,
        timestamp: u64,
        sign_with_prev: impl FnOnce(&[u8]) -> String,
    ) -> Self {
        let mut e = GroupEpoch {
            group_id,
            seq,
            members,
            admin_key,
            admin_identity_key,
            prev_admin_key: Some(prev_admin_key),
            timestamp,
            signature: String::new(),
        };
        e.signature = sign_with_prev(&e.signing_payload());
        e
    }

    /// Verify the epoch's signature under the correct key: `prev_admin_key` for a
    /// successor, or `admin_key` itself for the genesis. Fail-closed on any malformed field.
    pub fn verify_signature(&self) -> bool {
        let signer = self.prev_admin_key.as_deref().unwrap_or(&self.admin_key);
        verify_ed25519(signer, &self.signing_payload(), &self.signature)
    }

    /// Structural validity, independent of any chain position or signature:
    ///
    /// * non-empty `group_id`, `admin_key`, `admin_identity_key`;
    /// * 1..=[`MAX_GROUP_MEMBERS`] members, each with non-empty fields and a unique
    ///   `identity_key`;
    /// * the admin is one of the members (`admin_identity_key` ∈ members) — so a member
    ///   made admin by a transfer must actually be in the group;
    /// * genesis (`seq == 0`) is self-signed (`prev_admin_key == None`); every successor
    ///   (`seq > 0`) names a non-empty `prev_admin_key`.
    pub fn validate_structure(&self) -> Result<(), GroupEpochError> {
        if self.group_id.is_empty() {
            return Err(GroupEpochError::Malformed("empty group_id".into()));
        }
        if self.admin_key.is_empty() || self.admin_identity_key.is_empty() {
            return Err(GroupEpochError::Malformed("empty admin key".into()));
        }
        if self.members.is_empty() || self.members.len() > MAX_GROUP_MEMBERS {
            return Err(GroupEpochError::Malformed(format!(
                "member count must be 1..={MAX_GROUP_MEMBERS}"
            )));
        }
        for (i, m) in self.members.iter().enumerate() {
            if m.username.is_empty() || m.identity_key.is_empty() {
                return Err(GroupEpochError::Malformed(format!(
                    "member {i} has an empty field"
                )));
            }
            if self.members[..i]
                .iter()
                .any(|p| p.identity_key == m.identity_key)
            {
                return Err(GroupEpochError::Malformed(format!(
                    "duplicate member identity key at {i}"
                )));
            }
        }
        if !self
            .members
            .iter()
            .any(|m| m.identity_key == self.admin_identity_key)
        {
            return Err(GroupEpochError::Malformed(
                "admin is not one of the members".into(),
            ));
        }
        match (self.seq, self.prev_admin_key.as_deref()) {
            (0, Some(_)) => Err(GroupEpochError::Malformed(
                "genesis epoch must be self-signed (no prev admin)".into(),
            )),
            (0, None) => Ok(()),
            (_, None) => Err(GroupEpochError::Malformed(
                "successor epoch must name a previous admin".into(),
            )),
            (_, Some("")) => Err(GroupEpochError::Malformed("empty prev admin key".into())),
            (_, Some(_)) => Ok(()),
        }
    }

    /// The username of the admin (the member whose `identity_key` is `admin_identity_key`).
    pub fn admin_username(&self) -> Option<&str> {
        self.members
            .iter()
            .find(|m| m.identity_key == self.admin_identity_key)
            .map(|m| m.username.as_str())
    }

    /// Whether an account identity key is a member in this epoch.
    pub fn is_member(&self, identity_key: &str) -> bool {
        self.members.iter().any(|m| m.identity_key == identity_key)
    }

    /// Full validation of THIS epoch as the successor to a pinned `(pinned_seq,
    /// pinned_admin_key)`. Enforces, in order:
    ///
    /// * structure ([`validate_structure`](Self::validate_structure));
    /// * **anti-rollback**: a `seq` ≤ the pinned one is refused (a relay replaying an old
    ///   epoch to resurrect a kicked member is caught here) — the same monotonic guard as
    ///   `History::pin_roster`;
    /// * **continuity**: `prev_admin_key` must equal the pinned admin key;
    /// * **authority**: the signature verifies under that same (pinned) admin key — so only
    ///   the current admin could have produced it.
    ///
    /// A seq **gap** (`seq > pinned_seq + 1`) is allowed as long as continuity and the
    /// signature hold: every epoch carries the FULL member list (state, not a delta), so an
    /// epoch signed by our pinned admin is fully verifiable no matter how many epochs we
    /// missed. This is what lets a kicked member — who is not fanned the intermediate
    /// epochs — be re-added later. A gap that crosses an admin *transfer* still fails
    /// (`prev_admin_key` names an admin we never pinned → [`BrokenContinuity`]
    /// (GroupEpochError::BrokenContinuity)), because such a chain cannot be verified one
    /// unseen link at a time.
    pub fn verify_succession(
        &self,
        pinned_seq: u64,
        pinned_admin_key: &str,
    ) -> Result<(), GroupEpochError> {
        self.validate_structure()?;
        if self.seq <= pinned_seq {
            return Err(GroupEpochError::Rollback {
                pinned: pinned_seq,
                got: self.seq,
            });
        }
        if self.prev_admin_key.as_deref() != Some(pinned_admin_key) {
            return Err(GroupEpochError::BrokenContinuity);
        }
        // The signer is prev_admin_key == pinned_admin_key (just checked), so this proves
        // the CURRENT admin authorized the change — a non-admin's forgery fails here.
        if !self.verify_signature() {
            return Err(GroupEpochError::BadSignature);
        }
        Ok(())
    }

    /// Validate THIS epoch as a fresh baseline with no prior pin — either the genesis of a
    /// group we are creating, or the current epoch of a group we are being invited into
    /// mid-life (trust-on-first-epoch, carried inside an end-to-end-authenticated invite).
    /// Structure + self-consistent signature only; succession is enforced from here on.
    pub fn validate_baseline(&self) -> Result<(), GroupEpochError> {
        self.validate_structure()?;
        if !self.verify_signature() {
            return Err(GroupEpochError::BadSignature);
        }
        Ok(())
    }
}

/// Length-prefixed field append (same convention as `entry.rs` / `roster.rs`).
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
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

    fn member(name: &str, idk: &str) -> GroupMemberEntry {
        GroupMemberEntry {
            username: name.into(),
            identity_key: idk.into(),
        }
    }

    /// A creator with an admin keypair and a matching member entry (idk == admin idk).
    fn creator() -> (SigningKey, String, String, GroupMemberEntry) {
        let (sk, admin_key) = keypair();
        let admin_idk = "creator-idk".to_string();
        let m = member("creator", &admin_idk);
        (sk, admin_key, admin_idk, m)
    }

    #[test]
    fn genesis_self_signature_verifies_and_is_structurally_valid() {
        let (sk, admin_key, admin_idk, me) = creator();
        let e = GroupEpoch::genesis(
            "g1".into(),
            vec![me, member("bob", "bob-idk")],
            admin_key,
            admin_idk,
            1000,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        assert!(e.verify_signature());
        assert_eq!(e.validate_structure(), Ok(()));
        assert_eq!(e.validate_baseline(), Ok(()));
        assert_eq!(e.admin_username(), Some("creator"));
    }

    #[test]
    fn tampering_with_the_member_list_breaks_the_signature() {
        let (sk, admin_key, admin_idk, me) = creator();
        let mut e = GroupEpoch::genesis("g1".into(), vec![me], admin_key, admin_idk, 1000, |p| {
            b64e(&sk.sign(p).to_bytes())
        });
        // Inject a rogue member after signing.
        e.members.push(member("mallory", "mallory-idk"));
        assert!(!e.verify_signature());
        assert_eq!(e.validate_baseline(), Err(GroupEpochError::BadSignature));
    }

    #[test]
    fn genesis_must_be_self_signed_and_admin_must_be_a_member() {
        let (sk, admin_key) = keypair();
        // Admin identity key is NOT among the members → structurally invalid.
        let e = GroupEpoch::genesis(
            "g1".into(),
            vec![member("bob", "bob-idk")],
            admin_key.clone(),
            "creator-idk".into(),
            1000,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        assert!(matches!(
            e.validate_structure(),
            Err(GroupEpochError::Malformed(_))
        ));
    }

    #[test]
    fn membership_change_must_be_signed_by_the_current_admin() {
        let (sk, admin_key, admin_idk, me) = creator();
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            vec![me.clone()],
            admin_key.clone(),
            admin_idk.clone(),
            1000,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        // Admin adds Bob at seq 1 — signed by the admin (== prev).
        let good = GroupEpoch::next(
            1,
            "g1".into(),
            vec![me.clone(), member("bob", "bob-idk")],
            admin_key.clone(),
            admin_idk.clone(),
            admin_key.clone(),
            1001,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        assert_eq!(good.verify_succession(g0.seq, &g0.admin_key), Ok(()));

        // A non-admin member forges an add signed by their OWN key — refused.
        let (mallory_sk, _mallory_key) = keypair();
        let forged = GroupEpoch::next(
            1,
            "g1".into(),
            vec![me, member("mallory", "mallory-idk")],
            admin_key.clone(),
            admin_idk,
            admin_key.clone(), // claims to chain from the real admin…
            1001,
            |p| b64e(&mallory_sk.sign(p).to_bytes()), // …but signs with the wrong key
        );
        assert_eq!(
            forged.verify_succession(g0.seq, &g0.admin_key),
            Err(GroupEpochError::BadSignature)
        );
    }

    #[test]
    fn rollback_is_refused_but_a_same_admin_gap_bridges() {
        let (sk, admin_key, admin_idk, me) = creator();
        // Pretend we've pinned seq 5.
        let replay = GroupEpoch::next(
            3,
            "g1".into(),
            vec![me.clone()],
            admin_key.clone(),
            admin_idk.clone(),
            admin_key.clone(),
            1001,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        assert_eq!(
            replay.verify_succession(5, &admin_key),
            Err(GroupEpochError::Rollback { pinned: 5, got: 3 })
        );
        // A jump past the next slot IS verifiable when it chains from (and is signed by)
        // the same pinned admin — epochs are full state, so missed links don't matter.
        // This is the re-added-after-kick path.
        let gap = GroupEpoch::next(
            7,
            "g1".into(),
            vec![me.clone()],
            admin_key.clone(),
            admin_idk.clone(),
            admin_key.clone(),
            1001,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        assert_eq!(gap.verify_succession(5, &admin_key), Ok(()));
        // But a gap crossing an admin TRANSFER cannot be bridged: the epoch chains from an
        // admin we never pinned.
        let (stranger_sk, stranger_key) = keypair();
        let unbridgeable = GroupEpoch::next(
            7,
            "g1".into(),
            vec![me],
            admin_key.clone(),
            admin_idk,
            stranger_key,
            1001,
            |p| b64e(&stranger_sk.sign(p).to_bytes()),
        );
        assert_eq!(
            unbridgeable.verify_succession(5, &admin_key),
            Err(GroupEpochError::BrokenContinuity)
        );
    }

    #[test]
    fn admin_transfer_moves_authority_to_the_new_admin() {
        let (old_sk, old_key, old_idk, old_m) = creator();
        let (new_sk, new_key) = keypair();
        let new_idk = "bob-idk".to_string();
        let bob = member("bob", &new_idk);
        let members = vec![old_m.clone(), bob.clone()];

        // seq 0: created by old admin.
        let g0 = GroupEpoch::genesis(
            "g1".into(),
            members.clone(),
            old_key.clone(),
            old_idk.clone(),
            1000,
            |p| b64e(&old_sk.sign(p).to_bytes()),
        );
        // seq 1: old admin hands the role to Bob (still signed by the OLD admin).
        let transfer = GroupEpoch::next(
            1,
            "g1".into(),
            members.clone(),
            new_key.clone(),
            new_idk.clone(),
            old_key.clone(),
            1001,
            |p| b64e(&old_sk.sign(p).to_bytes()),
        );
        assert_eq!(transfer.verify_succession(g0.seq, &g0.admin_key), Ok(()));

        // seq 2 by the NEW admin verifies against the transferred key.
        let by_new = GroupEpoch::next(
            2,
            "g1".into(),
            vec![old_m.clone(), bob],
            new_key.clone(),
            new_idk.clone(),
            new_key.clone(),
            1002,
            |p| b64e(&new_sk.sign(p).to_bytes()),
        );
        assert_eq!(
            by_new.verify_succession(transfer.seq, &transfer.admin_key),
            Ok(())
        );

        // The OLD admin has lost authority: an epoch it signs after the transfer is refused
        // (it would have to name the new admin as prev, but it cannot sign for that key).
        // Structurally valid (Bob is still a member + still the admin), so the ONLY thing
        // that fails is the signature — proving the old key no longer carries authority.
        let old_tries_again = GroupEpoch::next(
            2,
            "g1".into(),
            vec![
                old_m,
                member("bob", &new_idk),
                member("charlie", "charlie-idk"),
            ],
            new_key.clone(),
            new_idk,
            new_key.clone(), // must chain from the new admin now…
            1002,
            |p| b64e(&old_sk.sign(p).to_bytes()), // …but the old admin signs it
        );
        assert_eq!(
            old_tries_again.verify_succession(transfer.seq, &transfer.admin_key),
            Err(GroupEpochError::BadSignature)
        );
    }

    #[test]
    fn transfer_target_must_be_a_member() {
        let (old_sk, old_key, _old_idk, old_m) = creator();
        let (_new_sk, new_key) = keypair();
        // New admin identity key is not in the member list → structurally invalid.
        let bad = GroupEpoch::next(
            1,
            "g1".into(),
            vec![old_m],
            new_key,
            "stranger-idk".into(),
            old_key.clone(),
            1001,
            |p| b64e(&old_sk.sign(p).to_bytes()),
        );
        assert!(matches!(
            bad.verify_succession(0, &old_key),
            Err(GroupEpochError::Malformed(_))
        ));
    }

    #[test]
    fn broken_continuity_is_refused() {
        let (sk, admin_key, admin_idk, me) = creator();
        // Correct signature, correct seq, but prev_admin_key names a DIFFERENT admin than
        // the one we pinned → the chain does not connect.
        let (_other_sk, other_key) = keypair();
        let e = GroupEpoch::next(
            1,
            "g1".into(),
            vec![me],
            admin_key.clone(),
            admin_idk,
            other_key.clone(),
            1001,
            |p| b64e(&sk.sign(p).to_bytes()),
        );
        assert_eq!(
            e.verify_succession(0, &admin_key),
            Err(GroupEpochError::BrokenContinuity)
        );
    }

    #[test]
    fn garbage_signature_fails_closed() {
        let (_sk, admin_key, admin_idk, me) = creator();
        let mut e = GroupEpoch::genesis("g1".into(), vec![me], admin_key, admin_idk, 1000, |_| {
            "not-a-signature".into()
        });
        assert!(!e.verify_signature());
        e.signature = String::new();
        assert!(!e.verify_signature());
    }
}
