//! At-rest vault: encrypts the user's identity key material under a password.
//!
//! Threat model for this module: an attacker with the raw vault bytes (stolen device,
//! seized backup) and unlimited offline time. Defense:
//!
//! * **Argon2id** turns the password into the wrapping key — memory-hard, so offline
//!   brute force is expensive even with GPUs/ASICs.
//! * **XChaCha20-Poly1305** AEAD encrypts the payload with a random 24-byte nonce.
//!   Authenticated, so a wrong password (or any tampering) fails cleanly instead of
//!   returning garbage that downstream code might trust.
//! * Secrets are wrapped in [`zeroize`] types and erased from memory on drop.
//!
//! Two formats coexist, distinguished by the version byte:
//!
//! * **v1 — password-only.** Portable: the blob + password is enough to unlock on any
//!   machine. This is what backups/exports should use.
//! * **v2 — device-bound.** The wrapping key is HKDF-SHA256 over the Argon2id output
//!   *and* a random 32-byte **device key** that the platform client keeps in the OS
//!   keyring (Linux Secret Service / Windows Credential Manager / Android Keystore).
//!   A stolen v2 blob is useless without *both* the password and the device key, so
//!   offline brute force of the password alone no longer works. The device key is
//!   supplied by the caller — fetching it is OS-specific and lives in the client layer
//!   (`client-core::devicekey`).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8; 4] = b"SCV1"; // Sona Vault, format v1
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 uses a 192-bit nonce
const KEY_LEN: usize = 32;

// Argon2id cost parameters. Tuned for ~interactive unlock on a phone while staying
// painful to brute-force offline. Bumping these is a vault-format change (see VERSION).
const ARGON_MEM_KIB: u32 = 65_536; // 64 MiB
const ARGON_TIME: u32 = 3; // iterations
const ARGON_LANES: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("wrong password or corrupted vault")]
    Decryption,
    #[error("vault blob is malformed or truncated")]
    Malformed,
    #[error("unsupported vault format version")]
    BadVersion,
    #[error("vault is device-bound: the OS-keyring device key is required to open it")]
    DeviceKeyRequired,
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

/// Length of the device-binding key (see module docs on the v2 format).
pub const DEVICE_KEY_LEN: usize = 32;

/// A cached wrapping key: the Argon2id-derived key plus the salt/version it belongs to.
///
/// Argon2id is deliberately slow (~hundreds of ms). Running it once per *unlock* is the
/// design; running it once per *message* is not. A `SealKey` lets the caller pay the KDF
/// cost once and then re-seal the vault cheaply after every ratchet advance
/// ([`seal_with_key`]). Holding it is no worse than holding the unlocked payload itself —
/// both live only in the memory of an unlocked session — and it means the *password* does
/// not have to stay in memory at all. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SealKey {
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
    version: u8,
}

impl SealKey {
    /// Serialize as `version(1) || salt(16) || key(32)` for quick-unlock wrapping (see
    /// the `quick` module). These bytes ARE the vault key — callers must only ever store
    /// them encrypted (PIN/device-key/Keystore-wrapped) and zeroize plaintext copies.
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + SALT_LEN + KEY_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.key);
        zeroize::Zeroizing::new(out)
    }

    /// Inverse of [`SealKey::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<SealKey, VaultError> {
        if bytes.len() != 1 + SALT_LEN + KEY_LEN {
            return Err(VaultError::Malformed);
        }
        let version = bytes[0];
        if version != 1 && version != 2 {
            return Err(VaultError::BadVersion);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[1..1 + SALT_LEN]);
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes[1 + SALT_LEN..]);
        Ok(SealKey { key, salt, version })
    }
}

/// Open a vault blob directly with a cached/unwrapped [`SealKey`] — no KDF run. This is
/// the quick-unlock path; a key that does not match the blob (or any tampering) fails as
/// [`VaultError::Decryption`], indistinguishable from a wrong password.
pub fn open_with_seal_key(seal_key: &SealKey, blob: &[u8]) -> Result<VaultPayload, VaultError> {
    const HEADER: usize = 4 + 1 + SALT_LEN + NONCE_LEN;
    if blob.len() < HEADER || &blob[0..4] != MAGIC {
        return Err(VaultError::Malformed);
    }
    let nonce = &blob[5 + SALT_LEN..HEADER];
    let ciphertext = &blob[HEADER..];
    let cipher = XChaCha20Poly1305::new((&seal_key.key).into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::Decryption)?;
    serde_json::from_slice(&plaintext).map_err(|_| VaultError::Malformed)
}

/// Derive a fresh [`SealKey`] (new random salt) from a password — v1 when `device_key`
/// is `None`, v2 when it is supplied. One Argon2id run.
pub fn derive_seal_key(
    password: &str,
    device_key: Option<&[u8; DEVICE_KEY_LEN]>,
) -> Result<SealKey, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let (version, key) = match device_key {
        None => (1, derive_key(password, &salt)?),
        Some(dk) => (2, derive_key_v2(password, dk, &salt)?),
    };
    Ok(SealKey { key, salt, version })
}

/// Re-seal a payload under a previously derived [`SealKey`] — no KDF run. The salt and
/// version are the ones the key was derived for; only the nonce is fresh per call
/// (XChaCha20's 192-bit random nonce makes key reuse across seals safe).
pub fn seal_with_key(seal_key: &SealKey, payload: &VaultPayload) -> Result<Vec<u8>, VaultError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = XChaCha20Poly1305::new((&seal_key.key).into());
    let plaintext = serde_json::to_vec(payload).map_err(|_| VaultError::Malformed)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| VaultError::Decryption)?;
    let mut blob = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.push(seal_key.version);
    blob.extend_from_slice(&seal_key.salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// The secret material a vault protects.
///
/// `secret_state` is opaque to the vault — it's the serialized Double Ratchet state
/// (the Olm account + every per-contact session) produced by the `ratchet` module.
/// Keeping it opaque means the vault format never has to change as the ratchet evolves.
///
/// `ZeroizeOnDrop` guarantees these bytes are scrubbed from memory when the struct
/// is dropped — no lingering key material on the heap.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct VaultPayload {
    /// The user's stable account identifier (UUID). Stays inside the vault so it is
    /// portable across reinstalls but never written in the clear.
    pub account_id: String,
    /// Serialized Double Ratchet state (Olm account pickle + session pickles).
    pub secret_state: Vec<u8>,
    /// A stable 32-byte key for encrypting bulk local data (chat history, contacts)
    /// cheaply while the vault is unlocked — without re-running Argon2 on every save.
    /// Generated once at account creation and sealed here.
    #[serde(default)]
    pub data_key: Vec<u8>,
}

impl std::fmt::Debug for VaultPayload {
    // Never print key material, even by accident in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultPayload")
            .field("account_id", &self.account_id)
            .field("secret_state", &"<redacted>")
            .field("data_key", &"<redacted>")
            .finish()
    }
}

/// Derive the 32-byte wrapping key from a password + salt using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], VaultError> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_TIME, ARGON_LANES, Some(KEY_LEN))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Derive the v2 wrapping key: Argon2id(password) and the device key are combined with
/// HKDF-SHA256 (extract with the vault salt, expand with a format label). Both inputs
/// are required — neither the password nor the device key alone yields the key.
fn derive_key_v2(
    password: &str,
    device_key: &[u8; DEVICE_KEY_LEN],
    salt: &[u8],
) -> Result<[u8; KEY_LEN], VaultError> {
    let mut argon = derive_key(password, salt)?;
    let mut ikm = [0u8; KEY_LEN + DEVICE_KEY_LEN];
    ikm[..KEY_LEN].copy_from_slice(&argon);
    ikm[KEY_LEN..].copy_from_slice(device_key);
    argon.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; KEY_LEN];
    hk.expand(b"sona-vault-v2 wrapping key", &mut key)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    ikm.zeroize();
    Ok(key)
}

/// Encrypt a payload into a self-describing vault blob:
/// `MAGIC(4) || version(1) || salt(16) || nonce(24) || ciphertext`.
///
/// With `device_key: None` this produces a portable **v1** (password-only) blob; with
/// `Some(..)` a device-bound **v2** blob (see module docs). A fresh random salt and
/// nonce are generated on every call, so re-saving the same payload never produces the
/// same bytes.
pub fn seal_with(
    password: &str,
    device_key: Option<&[u8; DEVICE_KEY_LEN]>,
    payload: &VaultPayload,
) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let (version, mut key) = match device_key {
        None => (1, derive_key(password, &salt)?),
        Some(dk) => (2, derive_key_v2(password, dk, &salt)?),
    };
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();

    let plaintext = serde_json::to_vec(payload).map_err(|_| VaultError::Malformed)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| VaultError::Decryption)?;

    let mut blob = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.push(version);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Portable (v1, password-only) seal. Equivalent to `seal_with(password, None, ..)`.
pub fn seal(password: &str, payload: &VaultPayload) -> Result<Vec<u8>, VaultError> {
    seal_with(password, None, payload)
}

/// Decrypt a vault blob produced by [`seal_with`], handling both formats:
///
/// * **v1** opens with the password alone (a supplied device key is ignored, which is
///   what lets a v1 vault be opened and re-sealed as v2 during migration).
/// * **v2** requires the device key; without one this returns
///   [`VaultError::DeviceKeyRequired`] *before* touching the KDF, so the caller can
///   distinguish "fetch the device key" from "wrong password".
///
/// Returns [`VaultError::Decryption`] on a wrong password, wrong device key, or any
/// tampering — the AEAD tag makes them indistinguishable, which is what we want (no
/// oracle telling an attacker which input was wrong).
pub fn open_with(
    password: &str,
    device_key: Option<&[u8; DEVICE_KEY_LEN]>,
    blob: &[u8],
) -> Result<VaultPayload, VaultError> {
    open_keeping_key(password, device_key, blob).map(|(payload, _)| payload)
}

/// Like [`open_with`], but also returns the derived wrapping key as a [`SealKey`] so the
/// caller can re-seal after every ratchet advance without re-running Argon2. The returned
/// key matches the blob's format (a v1 blob yields a v1 key, etc.).
pub fn open_keeping_key(
    password: &str,
    device_key: Option<&[u8; DEVICE_KEY_LEN]>,
    blob: &[u8],
) -> Result<(VaultPayload, SealKey), VaultError> {
    const HEADER: usize = 4 + 1 + SALT_LEN + NONCE_LEN;
    if blob.len() < HEADER {
        return Err(VaultError::Malformed);
    }
    if &blob[0..4] != MAGIC {
        return Err(VaultError::Malformed);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[5..5 + SALT_LEN]);
    let nonce = &blob[5 + SALT_LEN..HEADER];
    let ciphertext = &blob[HEADER..];

    let version = blob[4];
    let key = match version {
        1 => derive_key(password, &salt)?,
        2 => match device_key {
            Some(dk) => derive_key_v2(password, dk, &salt)?,
            None => return Err(VaultError::DeviceKeyRequired),
        },
        _ => return Err(VaultError::BadVersion),
    };
    let cipher = XChaCha20Poly1305::new((&key).into());

    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::Decryption)?;
    let payload = serde_json::from_slice(&plaintext).map_err(|_| VaultError::Malformed)?;
    Ok((payload, SealKey { key, salt, version }))
}

/// Password-only open. Equivalent to `open_with(password, None, ..)`; a v2 blob yields
/// [`VaultError::DeviceKeyRequired`].
pub fn open(password: &str, blob: &[u8]) -> Result<VaultPayload, VaultError> {
    open_with(password, None, blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultPayload {
        VaultPayload {
            account_id: "11111111-2222-3333-4444-555555555555".into(),
            secret_state: vec![7u8; 32],
            data_key: vec![9u8; 32],
        }
    }

    #[test]
    fn round_trip_recovers_payload() {
        let blob = seal("Correct-Horse-Battery-9", &sample()).unwrap();
        let out = open("Correct-Horse-Battery-9", &blob).unwrap();
        assert_eq!(out.secret_state, vec![7u8; 32]);
        assert_eq!(out.account_id, "11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let blob = seal("Correct-Horse-Battery-9", &sample()).unwrap();
        match open("wrong-password", &blob) {
            Err(VaultError::Decryption) => {}
            other => panic!("expected Decryption error, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut blob = seal("Correct-Horse-Battery-9", &sample()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // flip a bit in the ciphertext/tag
        assert!(matches!(
            open("Correct-Horse-Battery-9", &blob),
            Err(VaultError::Decryption)
        ));
    }

    #[test]
    fn reseal_is_non_deterministic() {
        // Fresh salt + nonce each time → identical payloads produce different blobs.
        let a = seal("pw-pw-pw-pw-12", &sample()).unwrap();
        let b = seal("pw-pw-pw-pw-12", &sample()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn device_bound_round_trip() {
        let dk = [42u8; DEVICE_KEY_LEN];
        let blob = seal_with("Correct-Horse-Battery-9", Some(&dk), &sample()).unwrap();
        assert_eq!(blob[4], 2, "device-bound vaults are format v2");
        let out = open_with("Correct-Horse-Battery-9", Some(&dk), &blob).unwrap();
        assert_eq!(out.secret_state, vec![7u8; 32]);
    }

    #[test]
    fn device_bound_vault_needs_the_device_key() {
        let dk = [42u8; DEVICE_KEY_LEN];
        let blob = seal_with("Correct-Horse-Battery-9", Some(&dk), &sample()).unwrap();
        // No device key → a distinct, actionable error (not a generic decrypt failure).
        assert!(matches!(
            open_with("Correct-Horse-Battery-9", None, &blob),
            Err(VaultError::DeviceKeyRequired)
        ));
        assert!(matches!(
            open("Correct-Horse-Battery-9", &blob),
            Err(VaultError::DeviceKeyRequired)
        ));
        // Wrong device key → indistinguishable from a wrong password.
        let wrong = [43u8; DEVICE_KEY_LEN];
        assert!(matches!(
            open_with("Correct-Horse-Battery-9", Some(&wrong), &blob),
            Err(VaultError::Decryption)
        ));
    }

    #[test]
    fn v1_to_v2_migration() {
        // A portable v1 vault opens even when a device key is supplied (ignored), so a
        // client can unlock the old blob and immediately re-seal it device-bound.
        let dk = [7u8; DEVICE_KEY_LEN];
        let v1 = seal("Correct-Horse-Battery-9", &sample()).unwrap();
        let payload = open_with("Correct-Horse-Battery-9", Some(&dk), &v1).unwrap();
        let v2 = seal_with("Correct-Horse-Battery-9", Some(&dk), &payload).unwrap();
        let out = open_with("Correct-Horse-Battery-9", Some(&dk), &v2).unwrap();
        assert_eq!(out.account_id, payload.account_id);
    }

    #[test]
    fn cached_seal_key_reseals_without_kdf_and_stays_compatible() {
        // v1: open keeping the key, re-seal with it, and the plain password still opens it.
        let blob = seal("Correct-Horse-Battery-9", &sample()).unwrap();
        let (payload, key) = open_keeping_key("Correct-Horse-Battery-9", None, &blob).unwrap();
        let resealed = seal_with_key(&key, &payload).unwrap();
        assert_eq!(resealed[4], 1);
        let out = open("Correct-Horse-Battery-9", &resealed).unwrap();
        assert_eq!(out.account_id, payload.account_id);

        // v2: same, and the re-sealed blob still requires the device key.
        let dk = [42u8; DEVICE_KEY_LEN];
        let blob2 = seal_with("Correct-Horse-Battery-9", Some(&dk), &sample()).unwrap();
        let (payload2, key2) =
            open_keeping_key("Correct-Horse-Battery-9", Some(&dk), &blob2).unwrap();
        let resealed2 = seal_with_key(&key2, &payload2).unwrap();
        assert_eq!(resealed2[4], 2);
        assert!(matches!(
            open("Correct-Horse-Battery-9", &resealed2),
            Err(VaultError::DeviceKeyRequired)
        ));
        assert!(open_with("Correct-Horse-Battery-9", Some(&dk), &resealed2).is_ok());

        // A freshly derived key seals blobs the password opens.
        let fresh = derive_seal_key("Correct-Horse-Battery-9", Some(&dk)).unwrap();
        let sealed = seal_with_key(&fresh, &sample()).unwrap();
        assert_eq!(sealed[4], 2);
        assert!(open_with("Correct-Horse-Battery-9", Some(&dk), &sealed).is_ok());
    }

    #[test]
    fn malformed_blob_is_rejected() {
        assert!(matches!(
            open("x", b"too-short"),
            Err(VaultError::Malformed)
        ));
        assert!(matches!(
            open("x", &[0u8; 64]),
            Err(VaultError::Malformed) // bad magic
        ));
    }
}
