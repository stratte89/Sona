//! The **scoped call-control identity**: a per-device Curve25519 key that exists only to
//! open minimal incoming-call capsules while the main vault is locked.
//!
//! Why a second identity at all: an Android phone must be able to show, cancel, and
//! decline a ring with the chat vault closed. Doing that with the account's ratchet
//! identity would mean opening the vault — the thing the lock exists to prevent. So the
//! call subsystem gets its own key with a deliberately tiny reach:
//!
//! * it opens **capsules only** (see [`seal_capsule`] / [`CallKey::open_capsule`]) — it
//!   is never a ratchet session, never signs anything for the account, and cannot decrypt
//!   a chat message, a history blob, or a media ticket;
//! * it carries a second, Ed25519 half whose only job is proving control of the device's
//!   **call-control mailbox** to the relay ([`CallKey::sign`]). A locked device has no
//!   account signing key — that is in the vault — so without this half it could not even
//!   collect the capsule addressed to it. It signs nothing else: it is not in the KT log,
//!   not an account authority, and the relay accepts it only for that one mailbox;
//! * its public half is bound to the device by a signature from the device's *roster*
//!   Ed25519 key ([`kt_log::CallKeyBinding`]), so a peer trusts it only after the KT-
//!   verified roster says that device really published it;
//! * revocation is the roster's: a device removed from the roster has no verifiable
//!   binding any more, and its capsules stop being accepted.
//!
//! ## At rest
//!
//! The secret is sealed under [`call_store_key`] — HKDF of the **device key** (OS keyring
//! on desktop; a non-exportable Keystore/StrongBox-wrapped key on Android), *not* of the
//! password-derived vault key. That is the whole point: the call subsystem must open
//! without the password, and only on this device. A stolen blob without the device key is
//! useless off-device, and the vault is not weakened — the call key can decrypt nothing
//! the vault protects.
//!
//! ## Capsule format
//!
//! `MAGIC "SCC1"(4) || version(1) || ephemeral_pub(32) || nonce(24) || ct`
//!
//! Sender-anonymous by construction (an ephemeral X25519 key per capsule, no sender key
//! on the wire): the relay learns nothing about who is calling, and a locked device that
//! cannot yet check the caller shows a generic ring. Caller authentication rides *inside*
//! the sealed plaintext, where the screening index can check it after opening.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey, Ed25519SecretKey};
use zeroize::Zeroizing;

use crate::DEVICE_KEY_LEN;

const CAPSULE_MAGIC: &[u8; 4] = b"SCC1";
const CAPSULE_VERSION: u8 = 1;
const SECRET_MAGIC: &[u8; 4] = b"SCK1";
const SCREEN_MAGIC: &[u8; 4] = b"SCS1";
const SCREEN_VERSION: u8 = 1;
const STORE_MAGIC: &[u8; 4] = b"SCT1";
const STORE_VERSION: u8 = 1;
const SCREEN_INFO: &[u8] = b"sona-call-screen-v1";
/// Version 2 carries both halves (X25519 || Ed25519 seed). A version-1 blob (X25519
/// only) is deliberately refused rather than upgraded: the caller mints a fresh identity
/// and republishes, which is the same path a rotated device key already takes.
const SECRET_VERSION: u8 = 2;
const SECRET_PLAINTEXT_LEN: usize = 64;
const NONCE_LEN: usize = 24;
const PUBLIC_LEN: usize = 32;
/// Header length of a capsule: magic + version + ephemeral public key.
const CAPSULE_HEADER_LEN: usize = 4 + 1 + PUBLIC_LEN;
const CAPSULE_INFO: &[u8] = b"sona-call-capsule-v1";
const STORE_INFO: &[u8] = b"sona-call-store-v1";

/// Largest capsule this build will even attempt to open. A capsule carries a handful of
/// short fields; anything larger is a malformed or hostile blob and is refused before a
/// single allocation is sized from it.
pub const MAX_CAPSULE_BYTES: usize = 4096;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CallKeyError {
    #[error("call key is not a valid Curve25519 public key")]
    BadPublicKey,
    #[error("call capsule is malformed")]
    Malformed,
    #[error("call capsule payload is too large")]
    TooLarge,
    #[error("Diffie-Hellman with this key is not contributory")]
    NonContributory,
}

/// A device's call-control secret: the X25519 half that opens capsules and the Ed25519
/// half that proves control of its call-control mailbox.
pub struct CallKey {
    secret: Curve25519SecretKey,
    signing: Ed25519SecretKey,
}

impl CallKey {
    /// Mint a fresh call-control identity.
    pub fn generate() -> Self {
        Self {
            secret: Curve25519SecretKey::new(),
            signing: Ed25519SecretKey::new(),
        }
    }

    /// Rebuild from raw secret bytes (e.g. unwrapped from the Android Keystore):
    /// X25519 secret then Ed25519 seed.
    pub fn from_bytes(bytes: &[u8; SECRET_PLAINTEXT_LEN]) -> Self {
        let (curve, ed) = bytes.split_at(32);
        Self {
            secret: Curve25519SecretKey::from_slice(curve.try_into().expect("32 bytes")),
            signing: Ed25519SecretKey::from_slice(ed.try_into().expect("32 bytes")),
        }
    }

    /// The raw secret, for platform key wrapping. Zeroized when the caller drops it.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_PLAINTEXT_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRET_PLAINTEXT_LEN]);
        out[..32].copy_from_slice(self.secret.to_bytes().as_ref());
        out[32..].copy_from_slice(self.signing.to_bytes().as_ref());
        out
    }

    /// The public half a peer seals capsules to — what the roster binding publishes.
    pub fn public_b64(&self) -> String {
        Curve25519PublicKey::from(&self.secret).to_base64()
    }

    /// The public Ed25519 half the relay checks mailbox challenges against.
    pub fn signing_key_b64(&self) -> String {
        self.signing.public_key().to_base64()
    }

    /// Sign a relay challenge for this device's call-control mailbox. The only thing
    /// this key ever signs.
    pub fn sign(&self, message: &[u8]) -> String {
        self.signing.sign(message).to_base64()
    }

    /// Open a capsule sealed to this identity. `None` for anything that is not a valid,
    /// untampered capsule for this key — including a capsule meant for another device.
    pub fn open_capsule(&self, blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() > MAX_CAPSULE_BYTES || blob.len() < CAPSULE_HEADER_LEN + NONCE_LEN {
            return None;
        }
        let (header, rest) = blob.split_at(CAPSULE_HEADER_LEN);
        if &header[..4] != CAPSULE_MAGIC || header[4] != CAPSULE_VERSION {
            return None;
        }
        let ephemeral: [u8; PUBLIC_LEN] = header[5..].try_into().ok()?;
        let ephemeral = Curve25519PublicKey::from(ephemeral);
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        let shared = self.secret.diffie_hellman(&ephemeral)?;
        let recipient = Curve25519PublicKey::from(&self.secret);
        let key = capsule_key(shared.as_bytes(), &ephemeral, &recipient);
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &capsule_aad(header, &recipient),
                },
            )
            .ok()
    }
}

/// Seal `plaintext` to a device's published call key. The capsule carries a fresh
/// ephemeral public key, so two capsules to the same device share no correlatable bytes.
pub fn seal_capsule(
    recipient_call_key_b64: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CallKeyError> {
    if plaintext.len() + CAPSULE_HEADER_LEN + NONCE_LEN + 16 > MAX_CAPSULE_BYTES {
        return Err(CallKeyError::TooLarge);
    }
    let recipient = Curve25519PublicKey::from_base64(recipient_call_key_b64)
        .map_err(|_| CallKeyError::BadPublicKey)?;
    let ephemeral_secret = Curve25519SecretKey::new();
    let ephemeral = Curve25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret
        .diffie_hellman(&recipient)
        .ok_or(CallKeyError::NonContributory)?;
    let key = capsule_key(shared.as_bytes(), &ephemeral, &recipient);

    let mut header = Vec::with_capacity(CAPSULE_HEADER_LEN);
    header.extend_from_slice(CAPSULE_MAGIC);
    header.push(CAPSULE_VERSION);
    header.extend_from_slice(ephemeral.as_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &capsule_aad(&header, &recipient),
            },
        )
        .map_err(|_| CallKeyError::Malformed)?;

    let mut out = header;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Is this a syntactically valid published call key? Cheap gate before trusting a
/// binding fetched from the relay.
pub fn valid_call_key(call_key_b64: &str) -> bool {
    Curve25519PublicKey::from_base64(call_key_b64).is_ok()
}

/// The key that seals the call-only store (identity secret, pending rings, tombstones),
/// derived from the **device key** so the store opens without the account password and
/// only on this device.
pub fn call_store_key(device_key: &[u8; DEVICE_KEY_LEN]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, device_key)
        .expand(STORE_INFO, key.as_mut())
        .expect("32 bytes is a valid HKDF length");
    key
}

/// Seal the call-control secret for storage under [`call_store_key`].
pub fn seal_call_secret(store_key: &[u8; 32], call_key: &CallKey) -> Vec<u8> {
    seal_under(
        store_key,
        SECRET_MAGIC,
        SECRET_VERSION,
        call_key.to_bytes().as_ref(),
    )
}

/// Seal the approved-caller screening index under the same call-only store key. Its own
/// magic is bound as associated data, so one record can never be opened as the other.
pub fn seal_screen_index(store_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    seal_under(store_key, SCREEN_MAGIC, SCREEN_VERSION, plaintext)
}

/// Open a blob produced by [`seal_screen_index`]. `None` on a wrong device key, a
/// truncated file, or tampering — the caller rebuilds the index from verified state.
pub fn open_screen_index(store_key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    open_under(store_key, SCREEN_MAGIC, SCREEN_VERSION, blob)
}

/// Seal the call-control **store** — pending rings, terminal tombstones, and the capsule
/// outbox — under the same call-only store key, with its own magic as associated data so
/// it can never be opened as the identity or the screening index.
pub fn seal_call_store(store_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    seal_under(store_key, STORE_MAGIC, STORE_VERSION, plaintext)
}

/// Open a blob produced by [`seal_call_store`]. `None` on a wrong device key, a truncated
/// or half-written file, or tampering — the caller starts from an empty store, which
/// loses ordering state but never rings on unauthenticated data.
pub fn open_call_store(store_key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    open_under(store_key, STORE_MAGIC, STORE_VERSION, blob)
}

/// The keyed hash under which one caller appears in the screening index. Keyed, so the
/// index on disk is not a readable list of who may call this device.
pub fn screen_hash(store_key: &[u8; 32], username: &str) -> String {
    let mut out = [0u8; 16];
    Hkdf::<Sha256>::new(Some(username.as_bytes()), store_key)
        .expand(SCREEN_INFO, &mut out)
        .expect("16 bytes is a valid HKDF length");
    out.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn seal_under(store_key: &[u8; 32], magic: &[u8; 4], version: u8, plaintext: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(5);
    header.extend_from_slice(magic);
    header.push(version);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(store_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .expect("XChaCha20-Poly1305 encryption does not fail");
    let mut out = header;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open_under(store_key: &[u8; 32], magic: &[u8; 4], version: u8, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 5 + NONCE_LEN {
        return None;
    }
    let (header, rest) = blob.split_at(5);
    if &header[..4] != magic || header[4] != version {
        return None;
    }
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(store_key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: header,
            },
        )
        .ok()
}

/// Open a blob produced by [`seal_call_secret`]. `None` on a wrong device key, a
/// truncated file, or tampering — the caller mints a fresh identity and republishes.
pub fn open_call_secret(store_key: &[u8; 32], blob: &[u8]) -> Option<CallKey> {
    let plain = open_under(store_key, SECRET_MAGIC, SECRET_VERSION, blob)?;
    let bytes: [u8; SECRET_PLAINTEXT_LEN] = plain.as_slice().try_into().ok()?;
    Some(CallKey::from_bytes(&bytes))
}

/// Base64 of a public key, for the small number of callers that hold raw bytes.
pub fn public_key_b64(bytes: &[u8; 32]) -> String {
    STANDARD.encode(bytes)
}

/// Capsule content key: HKDF over the DH secret, salted with both public keys so a
/// capsule can only be opened by the device it names.
fn capsule_key(
    shared: &[u8; 32],
    ephemeral: &Curve25519PublicKey,
    recipient: &Curve25519PublicKey,
) -> Zeroizing<[u8; 32]> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral.as_bytes());
    salt.extend_from_slice(recipient.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(CAPSULE_INFO, key.as_mut())
        .expect("32 bytes is a valid HKDF length");
    key
}

/// AEAD associated data: the wire header plus the recipient key, so neither the version,
/// the ephemeral key, nor the intended recipient can be swapped without failing the tag.
fn capsule_aad(header: &[u8], recipient: &Curve25519PublicKey) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + PUBLIC_LEN);
    aad.extend_from_slice(header);
    aad.extend_from_slice(recipient.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capsule_opens_only_for_the_device_it_names() {
        let phone = CallKey::generate();
        let laptop = CallKey::generate();
        let capsule = seal_capsule(&phone.public_b64(), b"ring handle + deadline").unwrap();
        assert_eq!(
            phone.open_capsule(&capsule).unwrap(),
            b"ring handle + deadline"
        );
        assert!(laptop.open_capsule(&capsule).is_none());
    }

    #[test]
    fn a_capsule_leaks_neither_plaintext_nor_a_sender_key() {
        let phone = CallKey::generate();
        let sender_visible = CallKey::generate();
        let capsule = seal_capsule(&phone.public_b64(), b"caller=alice").unwrap();
        assert!(!capsule.windows(6).any(|w| w == b"caller"));
        // The only public key on the wire is the per-capsule ephemeral one.
        let ephemeral = &capsule[5..5 + PUBLIC_LEN];
        assert_ne!(ephemeral, sender_visible.to_bytes().as_ref());
        // Two capsules to the same device share no ephemeral key.
        let second = seal_capsule(&phone.public_b64(), b"caller=alice").unwrap();
        assert_ne!(&second[5..5 + PUBLIC_LEN], ephemeral);
    }

    #[test]
    fn tampering_with_any_part_of_a_capsule_is_refused() {
        let phone = CallKey::generate();
        let capsule = seal_capsule(&phone.public_b64(), b"payload").unwrap();
        for index in [0, 4, 6, CAPSULE_HEADER_LEN + 1, capsule.len() - 1] {
            let mut broken = capsule.clone();
            broken[index] ^= 0xff;
            assert!(
                phone.open_capsule(&broken).is_none(),
                "byte {index} must be authenticated"
            );
        }
        // Truncation and an empty blob are refused before any allocation.
        assert!(phone.open_capsule(&capsule[..CAPSULE_HEADER_LEN]).is_none());
        assert!(phone.open_capsule(&[]).is_none());
    }

    #[test]
    fn an_oversized_capsule_is_refused_both_ways() {
        let phone = CallKey::generate();
        assert_eq!(
            seal_capsule(&phone.public_b64(), &vec![0u8; MAX_CAPSULE_BYTES]),
            Err(CallKeyError::TooLarge)
        );
        assert!(phone
            .open_capsule(&vec![0u8; MAX_CAPSULE_BYTES + 1])
            .is_none());
    }

    #[test]
    fn a_malformed_call_key_is_rejected_not_guessed() {
        assert_eq!(
            seal_capsule("not-base64!!", b"x"),
            Err(CallKeyError::BadPublicKey)
        );
        assert!(!valid_call_key("short"));
        assert!(valid_call_key(&CallKey::generate().public_b64()));
    }

    #[test]
    fn the_signing_half_is_usable_and_distinct_from_the_capsule_half() {
        let key = CallKey::generate();
        assert_ne!(key.signing_key_b64(), key.public_b64());
        let signature = key.sign(b"relay challenge");
        let verifier = vodozemac::Ed25519PublicKey::from_base64(&key.signing_key_b64()).unwrap();
        let parsed = vodozemac::Ed25519Signature::from_base64(&signature).unwrap();
        assert!(verifier.verify(b"relay challenge", &parsed).is_ok());
        assert!(verifier.verify(b"another challenge", &parsed).is_err());
        // Both halves survive a store round trip.
        let store_key = call_store_key(&[2u8; DEVICE_KEY_LEN]);
        let blob = seal_call_secret(&store_key, &key);
        let reopened = open_call_secret(&store_key, &blob).unwrap();
        assert_eq!(reopened.signing_key_b64(), key.signing_key_b64());
        assert_eq!(reopened.public_b64(), key.public_b64());
    }

    #[test]
    fn a_version_one_blob_is_refused_so_the_caller_mints_a_fresh_identity() {
        // v1 held only the X25519 half; a device with one must re-mint and republish
        // rather than come up with half an identity.
        let store_key = call_store_key(&[5u8; DEVICE_KEY_LEN]);
        let mut v1 = seal_call_secret(&store_key, &CallKey::generate());
        v1[4] = 1;
        assert!(open_call_secret(&store_key, &v1).is_none());
    }

    #[test]
    fn the_stored_secret_round_trips_only_under_its_own_device_key() {
        let device_key = [7u8; DEVICE_KEY_LEN];
        let store_key = call_store_key(&device_key);
        let call_key = CallKey::generate();
        let blob = seal_call_secret(&store_key, &call_key);
        let reopened = open_call_secret(&store_key, &blob).unwrap();
        assert_eq!(reopened.public_b64(), call_key.public_b64());
        // A different device key derives a different store key and opens nothing.
        let other = call_store_key(&[8u8; DEVICE_KEY_LEN]);
        assert_ne!(other.as_ref(), store_key.as_ref());
        assert!(open_call_secret(&other, &blob).is_none());
        // Raw secret bytes never appear in the blob.
        let secret = call_key.to_bytes();
        assert!(!blob.windows(32).any(|w| w == &secret[..32]));
        assert!(!blob.windows(32).any(|w| w == &secret[32..]));
    }

    #[test]
    fn the_screening_index_seals_apart_from_the_identity() {
        let store_key = call_store_key(&[6u8; DEVICE_KEY_LEN]);
        let index = seal_screen_index(&store_key, b"approved callers");
        assert_eq!(
            open_screen_index(&store_key, &index).unwrap(),
            b"approved callers"
        );
        // The two record kinds never open as each other, even under the same key.
        let identity = seal_call_secret(&store_key, &CallKey::generate());
        assert!(open_screen_index(&store_key, &identity).is_none());
        assert!(open_call_secret(&store_key, &index).is_none());
        // Another device key opens neither.
        let other = call_store_key(&[7u8; DEVICE_KEY_LEN]);
        assert!(open_screen_index(&other, &index).is_none());
    }

    #[test]
    fn screen_hashes_are_keyed_stable_and_unlinkable() {
        let store_key = call_store_key(&[1u8; DEVICE_KEY_LEN]);
        let other_device = call_store_key(&[2u8; DEVICE_KEY_LEN]);
        assert_eq!(
            screen_hash(&store_key, "alice"),
            screen_hash(&store_key, "alice")
        );
        assert_ne!(
            screen_hash(&store_key, "alice"),
            screen_hash(&store_key, "bob")
        );
        // Keyed: the same contact hashes differently on another device, so an index on
        // disk is not a readable (or cross-device linkable) list of who may call.
        assert_ne!(
            screen_hash(&store_key, "alice"),
            screen_hash(&other_device, "alice")
        );
        assert!(!screen_hash(&store_key, "alice").contains("alice"));
    }

    #[test]
    fn a_truncated_or_tampered_secret_blob_is_refused() {
        let store_key = call_store_key(&[3u8; DEVICE_KEY_LEN]);
        let blob = seal_call_secret(&store_key, &CallKey::generate());
        assert!(open_call_secret(&store_key, &blob[..4]).is_none());
        let mut broken = blob.clone();
        broken[4] ^= 0xff; // version byte is bound as AAD
        assert!(open_call_secret(&store_key, &broken).is_none());
        let last = blob.len() - 1;
        let mut flipped = blob;
        flipped[last] ^= 0xff;
        assert!(open_call_secret(&store_key, &flipped).is_none());
    }
}
