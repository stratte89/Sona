//! Key Transparency for Sona.
//!
//! ## The problem this solves
//!
//! In any messenger, two people exchange *names*, not keys. Something maps a name to a
//! public key — here, the server's directory. A malicious (or compromised, or coerced)
//! server can answer that lookup with **its own** key and silently sit in the middle.
//! End-to-end encryption alone does not stop this: the ciphertext is perfectly
//! encrypted… to the attacker.
//!
//! ## The fix
//!
//! Publish every `username → identity_key` binding into an **append-only, signed,
//! publicly verifiable log** (RFC 6962 Merkle tree, via the `ct-merkle` crate). Then:
//!
//! * **Entries are self-authenticating.** Each binding is signed by the user's own key;
//!   a key *rotation* is signed by the *previous* key (a continuity chain). The server
//!   cannot forge or silently replace a user's key — it lacks the private key to sign.
//! * **The log cannot be rewritten.** Inclusion proofs show a key really is in the log;
//!   consistency proofs show the log only ever grew (no entry was altered or removed).
//! * **The log cannot equivocate.** Signed Tree Heads are gossiped/compared; a server
//!   that shows different histories to different people is caught.
//!
//! Combined with out-of-band safety numbers (see `crypto-core`), this matches or beats
//! the key-verification story of mainstream messengers.
//!
//! This crate provides the entry/STH types, the server-side [`KtLog`], and the
//! client-side verification functions. The Merkle proof math is delegated entirely to
//! the vetted `ct-merkle` crate — we do not hand-roll consistency-proof verification.

pub mod callbinding;
pub mod entry;
pub mod group;
pub mod head;
pub mod log;
pub mod roster;
pub mod verify;

pub use callbinding::CallKeyBinding;
pub use entry::{verify_ed25519, EntryError, KtEntry};
pub use group::{GroupEpoch, GroupEpochError, GroupMemberEntry, MAX_GROUP_MEMBERS};
pub use head::SignedTreeHead;
pub use log::{AppendError, KtLog, KtRecord, RELEASE_GRACE_SECS};
pub use roster::{DeviceRecord, KtRosterEntry, RosterError, MAX_DEVICES, PRIMARY_DEVICE_ID};
pub use verify::{
    check_heads, consistency_from_b64, consistency_to_b64, inclusion_from_b64, inclusion_to_b64,
    verify_consistency, verify_consistency_b64, verify_inclusion, verify_inclusion_b64,
    verify_roster_inclusion, verify_roster_inclusion_b64, verify_sth, verify_sth_b64,
    verifying_key_from_b64, GossipVerdict,
};

use sha2::Sha256;

/// The hash function backing the Merkle log.
pub type LogHasher = Sha256;
/// Inclusion proof over the log (an item is present).
pub type InclusionProof = ct_merkle::InclusionProof<Sha256>;
/// Consistency proof over the log (the new tree is an append-only extension of the old).
pub type ConsistencyProof = ct_merkle::ConsistencyProof<Sha256>;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

/// Base64 (no padding) — the encoding used everywhere keys/signatures cross our wire.
/// Matches vodozemac's encoding so client-minted (Olm) signatures interoperate.
pub(crate) fn b64e(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

/// Decode base64, tolerating an accidental trailing pad. Returns `None` on garbage —
/// callers fail closed.
pub(crate) fn b64d(s: &str) -> Option<Vec<u8>> {
    STANDARD_NO_PAD.decode(s.trim_end_matches('=')).ok()
}
