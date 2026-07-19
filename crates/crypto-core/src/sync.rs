//! Password/PIN-gated **history-sync sealing** for multi-device linking.
//!
//! When a new device is linked, the primary device exports chat history as one opaque
//! blob, uploads it to the relay (`POST /v1/sync`), and the new device downloads and
//! decrypts it after the user enters the **account password (or PIN)**. The relay only
//! ever stores ciphertext.
//!
//! ## Key derivation — why the link secret is mandatory
//!
//! The blob sits **on the relay**, so the relay itself is the offline brute-force
//! adversary to design against. A key derived from the password alone would be as
//! strong as the password; a key derived from a 4–8 character **PIN** alone would be
//! trivially brute-forceable by the relay. So (mirroring the vault-v2 pattern of mixing
//! a keyring device key into the password KDF) the sync key mixes in a mandatory
//! 256-bit **link secret** that travels only over the device-linking channel (QR code /
//! short code shown by one device and scanned by the other) and is **never sent to the
//! relay**:
//!
//! ```text
//! sync_key = HKDF-SHA256( salt,
//!                         Argon2id(password-or-PIN, salt) || link_secret,
//!                         "sona-history-sync-v1" )
//! ```
//!
//! * The relay holds the blob but neither input → cannot brute-force anything.
//! * Someone who intercepts the QR (shoulder-surfer, camera) holds the link secret but
//!   must still supply the password/PIN — which is also what the *user* experiences:
//!   history appears on the new device only after they type it.
//!
//! ## Blob format
//!
//! `MAGIC "SHS1"(4) || version(1) || salt(16) || nonce(24) || ct`, header bound as AAD.
//! The plaintext is padded to coarse buckets before sealing so the blob length reveals
//! only a bucket, not the exact history size.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::vault::VaultError;

const MAGIC: &[u8; 4] = b"SHS1"; // Sona History-Sync blob, v1
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Length of the link secret carried over the device-linking channel (QR/short code).
pub const LINK_SECRET_LEN: usize = 32;

// Same Argon2id cost class as the vault: the KDF mostly slows a guessing loop that has
// somehow obtained the link secret; the 256-bit link secret is what defeats the relay.
const ARGON_MEM_KIB: u32 = 65_536;
const ARGON_TIME: u32 = 3;
const ARGON_LANES: u32 = 1;

/// Padding buckets: 64 KiB granularity so the relay learns only a coarse size class,
/// not the exact history length.
const PAD_BUCKET: usize = 64 * 1024;

/// Generate a fresh link secret (256 bits from the OS RNG). Display/transfer it only
/// over the device-linking channel — never send it to the relay.
pub fn generate_link_secret() -> [u8; LINK_SECRET_LEN] {
    let mut s = [0u8; LINK_SECRET_LEN];
    OsRng.fill_bytes(&mut s);
    s
}

/// The derived history-sync key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SyncKey([u8; KEY_LEN]);

/// Derive the sync key from the user secret (account password or PIN), the link
/// secret, and the blob's salt. One Argon2id run.
fn derive_sync_key(
    user_secret: &str,
    link_secret: &[u8; LINK_SECRET_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<SyncKey, VaultError> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_TIME, ARGON_LANES, Some(KEY_LEN))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = [0u8; KEY_LEN];
    argon
        .hash_password_into(user_secret.as_bytes(), salt, &mut stretched)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;

    let mut ikm = [0u8; KEY_LEN + LINK_SECRET_LEN];
    ikm[..KEY_LEN].copy_from_slice(&stretched);
    ikm[KEY_LEN..].copy_from_slice(link_secret);
    stretched.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; KEY_LEN];
    hk.expand(b"sona-history-sync-v1", &mut key)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    ikm.zeroize();
    Ok(SyncKey(key))
}

/// Pad `plaintext` to the next [`PAD_BUCKET`] boundary with an 8-byte length prefix,
/// so the sealed blob's size reveals only a coarse bucket.
fn pad(plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
    let raw = 8 + plaintext.len();
    let padded = raw.div_ceil(PAD_BUCKET).max(1) * PAD_BUCKET;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(padded, 0);
    Zeroizing::new(out)
}

fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    let len = u64::from_be_bytes(padded.get(..8)?.try_into().ok()?) as usize;
    padded.get(8..8 + len).map(|b| b.to_vec())
}

/// Seal a history export into an opaque relay blob under the account password/PIN and
/// the link secret. A fresh salt and nonce are generated per call.
pub fn seal_history(
    user_secret: &str,
    link_secret: &[u8; LINK_SECRET_LEN],
    history_plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_sync_key(user_secret, link_secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());

    let mut header = Vec::with_capacity(4 + 1 + SALT_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);

    let padded = pad(history_plaintext);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &padded,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Decryption)?;

    let mut blob = header;
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Open a history-sync blob. Wrong password/PIN, wrong link secret, and tampering are
/// all an indistinguishable [`VaultError::Decryption`] (no oracle).
pub fn open_history(
    user_secret: &str,
    link_secret: &[u8; LINK_SECRET_LEN],
    blob: &[u8],
) -> Result<Vec<u8>, VaultError> {
    const HEADER: usize = 4 + 1 + SALT_LEN;
    if blob.len() < HEADER + NONCE_LEN || &blob[0..4] != MAGIC {
        return Err(VaultError::Malformed);
    }
    if blob[4] != VERSION {
        return Err(VaultError::BadVersion);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[5..5 + SALT_LEN]);
    let nonce = &blob[HEADER..HEADER + NONCE_LEN];
    let ct = &blob[HEADER + NONCE_LEN..];

    let key = derive_sync_key(user_secret, link_secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let padded = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ct,
                aad: &blob[0..HEADER],
            },
        )
        .map_err(|_| VaultError::Decryption)?;
    let padded = Zeroizing::new(padded);
    unpad(&padded).ok_or(VaultError::Malformed)
}

/// Seal a small **provisioning** payload (username, history-sync id, etc.) for a device
/// being linked, under the link secret alone. The link secret is already 256 bits of
/// entropy carried over the QR/short-code channel, so no password KDF is needed here (the
/// blob never protects anything the user must *also* type). Format is the v1 blob with a
/// distinct expand label; a fresh salt+nonce per call.
pub fn seal_provisioning(
    link_secret: &[u8; LINK_SECRET_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let mut key = provisioning_key(link_secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();

    let mut header = Vec::with_capacity(4 + 1 + SALT_LEN);
    header.extend_from_slice(b"SPV1"); // Sona ProVisioning blob, v1
    header.push(VERSION);
    header.extend_from_slice(&salt);

    let padded = pad(plaintext);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &padded,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Decryption)?;
    let mut blob = header;
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Open a provisioning blob sealed by [`seal_provisioning`].
pub fn open_provisioning(
    link_secret: &[u8; LINK_SECRET_LEN],
    blob: &[u8],
) -> Result<Vec<u8>, VaultError> {
    const HEADER: usize = 4 + 1 + SALT_LEN;
    if blob.len() < HEADER + NONCE_LEN || &blob[0..4] != b"SPV1" {
        return Err(VaultError::Malformed);
    }
    if blob[4] != VERSION {
        return Err(VaultError::BadVersion);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[5..5 + SALT_LEN]);
    let nonce = &blob[HEADER..HEADER + NONCE_LEN];
    let ct = &blob[HEADER + NONCE_LEN..];

    let mut key = provisioning_key(link_secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();
    let padded = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ct,
                aad: &blob[0..HEADER],
            },
        )
        .map_err(|_| VaultError::Decryption)?;
    let padded = Zeroizing::new(padded);
    unpad(&padded).ok_or(VaultError::Malformed)
}

fn provisioning_key(
    link_secret: &[u8; LINK_SECRET_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<[u8; KEY_LEN], VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), link_secret);
    let mut key = [0u8; KEY_LEN];
    hk.expand(b"sona-provisioning-v1", &mut key)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Encode a link secret for transport in a QR/short code (base64, no padding).
pub fn link_secret_b64(link_secret: &[u8; LINK_SECRET_LEN]) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    STANDARD_NO_PAD.encode(link_secret)
}

/// Decode a link secret from its [`link_secret_b64`] form. `None` on malformed input.
pub fn link_secret_from_b64(s: &str) -> Option<[u8; LINK_SECRET_LEN]> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    STANDARD_NO_PAD.decode(s.trim()).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_round_trip_and_wrong_secret() {
        let ls = generate_link_secret();
        let blob = seal_provisioning(&ls, b"{\"username\":\"alice\"}").unwrap();
        assert_eq!(
            open_provisioning(&ls, &blob).unwrap(),
            b"{\"username\":\"alice\"}"
        );
        let other = generate_link_secret();
        assert!(matches!(
            open_provisioning(&other, &blob),
            Err(VaultError::Decryption)
        ));
    }

    #[test]
    fn link_secret_b64_round_trip() {
        let ls = generate_link_secret();
        let s = link_secret_b64(&ls);
        assert_eq!(link_secret_from_b64(&s).unwrap(), ls);
        assert!(link_secret_from_b64("not base64 %%%").is_none());
        assert!(link_secret_from_b64("YWJj").is_none()); // too short
    }

    #[test]
    fn round_trip_with_pin_and_link_secret() {
        let ls = generate_link_secret();
        let blob = seal_history("2846", &ls, b"the whole chat history").unwrap();
        assert_eq!(
            open_history("2846", &ls, &blob).unwrap(),
            b"the whole chat history"
        );
        // No plaintext leaks into the blob.
        assert!(!blob.windows(4).any(|w| w == b"chat"));
    }

    #[test]
    fn wrong_pin_or_wrong_link_secret_fails_indistinguishably() {
        let ls = generate_link_secret();
        let blob = seal_history("2846", &ls, b"history").unwrap();
        assert!(matches!(
            open_history("2847", &ls, &blob),
            Err(VaultError::Decryption)
        ));
        let other = generate_link_secret();
        assert!(matches!(
            open_history("2846", &other, &blob),
            Err(VaultError::Decryption)
        ));
    }

    #[test]
    fn tampered_or_malformed_blob_is_rejected() {
        let ls = generate_link_secret();
        let mut blob = seal_history("Correct-Horse-Battery-9", &ls, b"h").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(matches!(
            open_history("Correct-Horse-Battery-9", &ls, &blob),
            Err(VaultError::Decryption)
        ));
        assert!(matches!(
            open_history("x", &ls, b"short"),
            Err(VaultError::Malformed)
        ));
    }

    #[test]
    fn blob_length_reveals_only_a_coarse_bucket() {
        let ls = generate_link_secret();
        // Two very different small histories seal to the same bucketed length.
        let a = seal_history("2846", &ls, b"x").unwrap();
        let b = seal_history("2846", &ls, &vec![7u8; 30_000]).unwrap();
        assert_eq!(a.len(), b.len());
        // A history past the bucket boundary lands in the next bucket, not exact size.
        let c = seal_history("2846", &ls, &vec![7u8; 70_000]).unwrap();
        assert!(c.len() > a.len());
        assert_eq!((c.len() - a.len()) % PAD_BUCKET, 0);
    }
}
